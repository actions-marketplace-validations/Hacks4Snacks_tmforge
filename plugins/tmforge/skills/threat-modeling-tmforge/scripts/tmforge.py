#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import secrets
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from collections.abc import Generator
from contextlib import ExitStack, contextmanager
from functools import cache
from pathlib import Path
from types import ModuleType
from typing import IO, cast
from urllib.parse import SplitResult, urlsplit

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
RELEASES = "https://github.com/Hacks4Snacks/tmforge/releases/download"
DOWNLOAD_HOSTS = {
    "github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
}
MAX_METADATA_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_BINARY_BYTES = 512 * 1024 * 1024
COPYFILE_XATTR = 1 << 2
COPYFILE_DATA = 1 << 3
JSON = dict[str, object]


def json_object(value: object) -> JSON:
    """Require an object before interpreting release or cache metadata."""
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return cast(JSON, value)


def plugin_version() -> str:
    """Select the matching immutable CLI release from the installed plugin manifest."""
    manifest = json_object(
        json.loads((PLUGIN_ROOT / "plugin.json").read_text(encoding="utf-8"))
    )
    version = manifest.get("version")
    if (
        manifest.get("name") != "tmforge"
        or not isinstance(version, str)
        or not re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?", version
        )
    ):
        raise ValueError(
            "Install the complete tmforge plugin with a release version; 'latest' is not a pin"
        )
    return version


def runtime_id(system: str | None = None, machine: str | None = None) -> str:
    """Map the current host to one of the six published self-contained binaries."""
    system = system or platform.system()
    machine = (machine or platform.machine()).lower()
    operating_system = {"Darwin": "osx", "Linux": "linux", "Windows": "win"}.get(system)
    architecture = {
        "x86_64": "x64",
        "amd64": "x64",
        "arm64": "arm64",
        "aarch64": "arm64",
    }.get(machine)
    if operating_system is None or architecture is None:
        raise ValueError(
            f"No published tmforge binary for {system}/{machine}; supply your own CLI"
        )
    if system == "Linux" and platform.libc_ver()[0].lower() == "musl":
        raise ValueError(
            "Published Linux binaries require glibc; supply your own CLI on musl"
        )
    return f"{operating_system}-{architecture}"


def cache_root(explicit: Path | None = None) -> Path:
    """Use a private user cache; never write dependencies into the plugin or PATH."""
    if explicit is not None:
        root = explicit.expanduser()
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Caches" / "tmforge" / "copilot"
    elif sys.platform == "win32":
        root = (
            Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
            / "tmforge"
            / "copilot"
        )
    else:
        root = (
            Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
            / "tmforge"
            / "copilot"
        )
    root = root.absolute()
    for directory in [*reversed(root.parents), root]:
        try:
            validate_cache_entry(directory, private=directory == root)
        except FileNotFoundError:
            break
    root = Path(os.path.abspath(root))
    if root.is_relative_to(PLUGIN_ROOT.resolve()):
        raise ValueError("The binary cache must be outside the installed plugin")
    return root


@cache
def windows_permissions_module() -> ModuleType:
    script = (
        Path(__file__).resolve().parents[2]
        / "threat-modeling/scripts/windows_permissions.py"
    )
    spec = importlib.util.spec_from_file_location("tmforge_windows_permissions", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def windows_cache_permissions(path: Path, private: bool) -> None:
    windows_permissions_module().windows_permissions(path, private)


def validate_windows_cache_acl(
    owner: str,
    current_user: str,
    entries: list[tuple[int, int, int, str]],
    private: bool,
) -> None:
    windows_permissions_module().validate_windows_acl(
        owner, current_user, entries, private
    )


def validate_cache_entry(
    path: Path,
    private: bool,
    directory: bool = True,
    info: os.stat_result | None = None,
) -> None:
    if info is None:
        info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(
        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
    ):
        raise ValueError(f"Cache paths must not be symlinks or reparse points: {path}")
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or (not directory and info.st_nlink != 1):
        raise ValueError(
            f"Cache paths must be directories or single-link regular files: {path}"
        )
    if os.name == "nt":
        windows_cache_permissions(path, private)
    elif os.name == "posix":
        owners = {os.geteuid()} if private else {0, os.geteuid()}
        allowed_shared_parent = (
            not private and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        )
        forbidden = 0o077 if private else 0o022
        if info.st_uid not in owners or (
            info.st_mode & forbidden and not allowed_shared_parent
        ):
            raise ValueError(
                f"Unsafe cache ownership or permissions: {path}; use a new private cache directory and reinstall"
            )
    else:
        raise ValueError("Cannot verify cache permissions on this operating system")


def validate_cache_directories(
    root: Path, version: str, rid: str, create: bool = False
) -> bool:
    target = root / version / rid
    for directory in [*reversed(target.parents), target]:
        private = directory == root or directory.is_relative_to(root)
        try:
            validate_cache_entry(directory, private)
        except FileNotFoundError:
            if not create:
                return False
            try:
                directory.mkdir(mode=0o700)
            except FileExistsError:
                pass
            validate_cache_entry(directory, private)
    return True


def binary_path(root: Path, version: str, rid: str) -> Path:
    """Keep each version and architecture separate and reject redirected cache paths."""
    executable = "tmforge.exe" if rid.startswith("win-") else "tmforge"
    path = root / version / rid / executable
    if not path.parent.resolve().is_relative_to(root.resolve()):
        raise ValueError("Binary cache path escapes its configured root")
    return path


def stream_sha256(stream: IO[bytes]) -> str:
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(block)
    return digest.hexdigest()


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return stream_sha256(stream)


@contextmanager
def windows_cache_handle(
    path: Path, directory: bool = False
) -> Generator[int, None, None]:
    """Hold a non-reparse entry without permitting replacement or file writes."""
    if sys.platform != "win32":
        raise ValueError("Windows cache handles require Windows")
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.CreateFileW(
        str(path),
        0x81 if directory else 0x80000000,
        3 if directory else 1,
        None,
        3,
        0x02200000,
        None,
    )
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    descriptor = None
    try:
        attributes = (wintypes.DWORD * 2)()
        if not kernel.GetFileInformationByHandleEx(
            handle, 9, ctypes.byref(attributes), ctypes.sizeof(attributes)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if attributes[0] & 0x400 or bool(attributes[0] & 0x10) != directory:
            raise ValueError(
                f"Cache paths must not be symlinks or reparse points: {path}"
            )
        if directory:
            yield handle
        else:
            descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            yield descriptor
    finally:
        if descriptor is None:
            kernel.CloseHandle(handle)
        else:
            os.close(descriptor)


@contextmanager
def cache_directory(
    path: Path, root: Path, create: bool = False
) -> Generator[int | None, None, None]:
    """Pin cache directory components while the binary and receipt are in use."""
    with ExitStack() as stack:
        if os.name == "nt":
            for directory in [*reversed(path.parents), path]:
                if create and not directory.exists():
                    try:
                        directory.mkdir(mode=0o700)
                    except FileExistsError:
                        pass
                stack.enter_context(windows_cache_handle(directory, directory=True))
                validate_cache_entry(
                    directory,
                    private=directory == root or directory.is_relative_to(root),
                )
            yield None
            return
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptor = os.open(path.anchor, flags)
        try:
            directory = Path(path.anchor)
            validate_cache_entry(directory, private=False, info=os.fstat(descriptor))
            for component in path.parts[1:]:
                try:
                    child = os.open(component, flags, dir_fd=descriptor)
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                    child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                directory /= component
                validate_cache_entry(
                    directory,
                    private=directory == root or directory.is_relative_to(root),
                    info=os.fstat(descriptor),
                )
            yield descriptor
        finally:
            os.close(descriptor)


@contextmanager
def cache_file(
    path: Path, directory: int | None, private: bool = True
) -> Generator[IO[bytes], None, None]:
    with ExitStack() as stack:
        if os.name == "nt":
            descriptor = stack.enter_context(windows_cache_handle(path))
            stream = stack.enter_context(os.fdopen(descriptor, "rb", closefd=False))
        else:
            descriptor = os.open(
                path.name if directory is not None else path,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=directory,
            )
            stream = stack.enter_context(os.fdopen(descriptor, "rb"))
        validate_cache_entry(
            path, private=private, directory=False, info=os.fstat(descriptor)
        )
        yield stream


@contextmanager
def cache_output(path: Path, directory: int | None) -> Generator[IO[bytes], None, None]:
    descriptor = os.open(
        path.name if directory is not None else path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0),
        0o600,
        dir_fd=directory,
    )
    with os.fdopen(descriptor, "wb") as stream:
        validate_cache_entry(
            path, private=True, directory=False, info=os.fstat(descriptor)
        )
        yield stream


@contextmanager
def installation_directory(
    parent: Path, directory: int | None
) -> Generator[tuple[Path, int | None], None, None]:
    name = ".install-" + secrets.token_hex(16)
    path = parent / name
    entry = name if directory is not None else path
    os.mkdir(entry, mode=0o700, dir_fd=directory)
    identity = None
    try:
        with ExitStack() as stack:
            if directory is None:
                stack.enter_context(windows_cache_handle(path, directory=True))
                staged = None
                info = path.lstat()
            else:
                staged = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
                )
                stack.callback(os.close, staged)
                info = os.fstat(staged)
            validate_cache_entry(path, private=True, info=info)
            identity = (info.st_dev, info.st_ino)
            try:
                yield path, staged
            finally:
                for child in os.listdir(staged if staged is not None else path):
                    os.unlink(
                        child if staged is not None else path / child, dir_fd=staged
                    )
    finally:
        if identity is not None:
            current = os.stat(entry, dir_fd=directory, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != identity:
                raise ValueError("Installation directory changed during cleanup")
            os.rmdir(entry, dir_fd=directory)


@contextmanager
def verified_cache(
    root: Path, version: str, rid: str
) -> Generator[tuple[Path, IO[bytes], str] | None, None, None]:
    """Keep verified cache handles alive until their consumer is finished."""
    root = cache_root(root)
    if not validate_cache_directories(root, version, rid):
        yield None
        return
    binary = binary_path(root, version, rid)
    receipt = binary.parent / "receipt.json"
    if (
        binary.is_symlink()
        or receipt.is_symlink()
        or not binary.is_file()
        or not receipt.is_file()
    ):
        yield None
        return
    validate_cache_entry(binary, private=True, directory=False)
    validate_cache_entry(receipt, private=True, directory=False)
    with cache_directory(binary.parent, root) as directory, ExitStack() as stack:
        try:
            executable = stack.enter_context(cache_file(binary, directory))
            metadata = stack.enter_context(cache_file(receipt, directory))
        except FileNotFoundError:
            yield None
            return
        info = os.fstat(executable.fileno())
        if (
            not 0 < info.st_size <= MAX_BINARY_BYTES
            or os.fstat(metadata.fileno()).st_size > MAX_METADATA_BYTES
        ):
            yield None
            return
        try:
            content = metadata.read(MAX_METADATA_BYTES + 1)
            data = (
                json_object(json.loads(content))
                if len(content) <= MAX_METADATA_BYTES
                else {}
            )
        except (OSError, ValueError):
            yield None
            return
        expected_hash = data.get("binarySha256")
        metadata_hash = data.get("releaseMetadataSha256")
        archive_hash = data.get("archiveSha256")
        extension = "zip" if rid.startswith("win-") else "tar.gz"
        source = f"{RELEASES}/v{version}/tmforge-{version}-{rid}.{extension}"
        if (
            data.get("version") != version
            or data.get("rid") != rid
            or data.get("source") != source
            or not isinstance(metadata_hash, str)
            or not re.fullmatch(r"[0-9a-f]{64}", metadata_hash)
            or not isinstance(archive_hash, str)
            or not re.fullmatch(r"[0-9a-f]{64}", archive_hash)
            or expected_hash != stream_sha256(executable)
            or (os.name != "nt" and not info.st_mode & stat.S_IXUSR)
        ):
            yield None
            return
        executable.seek(0)
        yield binary, executable, cast(str, expected_hash)


def cached_binary(root: Path, version: str, rid: str) -> Path | None:
    with verified_cache(root, version, rid) as verified:
        return verified[0] if verified is not None else None


def macos_copy_quarantine(source: int, destination: int) -> None:
    """Preserve existing quarantine metadata without inventing or removing it."""
    if sys.platform != "darwin":
        raise ValueError("macOS quarantine metadata requires macOS")
    import ctypes
    import errno

    library = ctypes.CDLL(None, use_errno=True)
    attribute_args = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_int,
    )
    library.fgetxattr.argtypes = attribute_args
    library.fgetxattr.restype = ctypes.c_ssize_t
    library.fsetxattr.argtypes = attribute_args
    library.fsetxattr.restype = ctypes.c_int
    attribute = b"com.apple.quarantine"
    size = library.fgetxattr(source, attribute, None, 0, 0, 0)
    if size >= 0:
        value = ctypes.create_string_buffer(size)
        if library.fgetxattr(source, attribute, value, size, 0, 0) != size:
            raise ValueError("Source quarantine metadata changed while copying")
        if library.fsetxattr(destination, attribute, value, size, 0, 0) != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
    elif ctypes.get_errno() != errno.ENOATTR:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


@contextmanager
def macos_execution_copy(
    source: IO[bytes], expected_hash: str
) -> Generator[Path, None, None]:
    """Stage held bytes with their extended attributes, including quarantine."""
    if sys.platform != "darwin":
        raise ValueError("macOS execution copies require macOS")
    import ctypes

    library = ctypes.CDLL(None, use_errno=True)
    library.fcopyfile.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    library.fcopyfile.restype = ctypes.c_int
    with tempfile.TemporaryDirectory(prefix="tmforge-exec-") as directory:
        private = cache_root(Path(directory).resolve())
        executable = private / "tmforge"
        descriptor = os.open(
            executable, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700
        )
        try:
            source.seek(0)
            if (
                library.fcopyfile(
                    source.fileno(), descriptor, None, COPYFILE_XATTR | COPYFILE_DATA
                )
                != 0
            ):
                code = ctypes.get_errno()
                raise OSError(code, os.strerror(code))
            macos_copy_quarantine(source.fileno(), descriptor)
            os.fchmod(descriptor, 0o500)
            os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            with os.fdopen(os.dup(descriptor), "rb") as staged:
                if stream_sha256(staged) != expected_hash:
                    raise ValueError(
                        "Execution copy SHA-256 mismatch; cached bytes changed"
                    )
        finally:
            os.close(descriptor)
        yield executable


def execute_verified(
    verified: tuple[Path, IO[bytes], str], arguments: list[str]
) -> int:
    binary, stream, expected_hash = verified
    if sys.platform == "win32":
        return subprocess.run([str(binary), *arguments], check=False).returncode
    if sys.platform.startswith("linux"):
        descriptor = stream.fileno()
        return subprocess.run(
            [str(binary), *arguments],
            executable=f"/proc/self/fd/{descriptor}",
            pass_fds=(descriptor,),
            check=False,
        ).returncode
    if sys.platform == "darwin":
        with macos_execution_copy(stream, expected_hash) as executable:
            return subprocess.run([str(executable), *arguments], check=False).returncode
    raise ValueError("Cannot bind verified execution on this operating system")


def copy_limited(source: IO[bytes], destination: IO[bytes], limit: int) -> int:
    """Bound actual bytes, not just a possibly untrusted length declaration."""
    count = 0
    while block := source.read(min(1024 * 1024, limit - count + 1)):
        count += len(block)
        if count > limit:
            raise ValueError(f"Download or executable exceeds the {limit}-byte limit")
        destination.write(block)
    return count


def download(
    url: str, destination: Path, limit: int, directory: int | None = None
) -> None:
    """Fetch public release data over verified TLS; no credentials or telemetry."""
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in DOWNLOAD_HOSTS:
        raise ValueError("Downloads must use an HTTPS GitHub release URL")
    request = urllib.request.Request(
        url, headers={"User-Agent": "tmforge-copilot-plugin"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        final: SplitResult = urlsplit(str(response.geturl()))
        if final.scheme != "https" or final.hostname not in DOWNLOAD_HOSTS:
            raise ValueError(
                "Release download redirected outside the HTTPS GitHub asset hosts"
            )
        with cache_output(destination, directory) as output:
            copy_limited(response, output, limit)


def release_asset(metadata: JSON, version: str, rid: str) -> tuple[str, str, int]:
    """Accept only the expected asset from the pinned release metadata."""
    if metadata.get("version") != version or metadata.get("tag") != f"v{version}":
        raise ValueError("Release metadata does not match the plugin version")
    extension = "zip" if rid.startswith("win-") else "tar.gz"
    filename = f"tmforge-{version}-{rid}.{extension}"
    artifacts = metadata.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("Release metadata has no artifact list")
    matches: list[JSON] = []
    for value in cast(list[object], artifacts):
        item = json_object(value)
        if item.get("rid") == rid and item.get("file") == filename:
            matches.append(item)
    if len(matches) != 1:
        raise ValueError(f"Release metadata must describe exactly one {filename}")
    digest, size = matches[0].get("sha256"), matches[0].get("size")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("Release metadata has no valid SHA-256 checksum")
    if type(size) is not int or not 0 < size <= MAX_ARCHIVE_BYTES:
        raise ValueError(
            "Release archive size is invalid or exceeds the download limit"
        )
    return filename, digest, size


def unpack_binary(
    archive: Path,
    member_name: str,
    destination: Path,
    directory: int | None = None,
    archive_stream: IO[bytes] | None = None,
) -> None:
    """Copy only the expected regular executable; never extract archive paths."""
    with ExitStack() as stack:
        if archive_stream is None:
            archive_stream = stack.enter_context(
                cache_file(archive, directory, private=False)
            )
        archive_stream.seek(0)
        if archive.suffix == ".zip":
            package = stack.enter_context(zipfile.ZipFile(archive_stream))
            members = [
                member
                for member in package.infolist()
                if member.filename == member_name
            ]
            if len(members) != 1:
                raise ValueError("Archive must contain exactly one expected executable")
            member = members[0]
            mode = stat.S_IFMT(member.external_attr >> 16)
            if (
                member.is_dir()
                or mode not in {0, stat.S_IFREG}
                or not 0 < member.file_size <= MAX_BINARY_BYTES
            ):
                raise ValueError("Expected executable must be a bounded regular file")
            source = stack.enter_context(package.open(member))
            size = member.file_size
        else:
            tar_package = stack.enter_context(
                tarfile.open(fileobj=archive_stream, mode="r:gz")
            )
            tar_members = [
                member for member in tar_package if member.name == member_name
            ]
            if len(tar_members) != 1:
                raise ValueError("Archive must contain exactly one expected executable")
            tar_member = tar_members[0]
            if not tar_member.isfile() or not 0 < tar_member.size <= MAX_BINARY_BYTES:
                raise ValueError("Expected executable must be a bounded regular file")
            extracted = tar_package.extractfile(tar_member)
            if extracted is None:
                raise ValueError("Expected executable has no readable content")
            source = stack.enter_context(extracted)
            size = tar_member.size
        with cache_output(destination, directory) as output:
            if copy_limited(source, output, size) != size:
                raise ValueError("Executable size does not match the archive header")
            if sys.platform == "darwin":
                macos_copy_quarantine(archive_stream.fileno(), output.fileno())
            if os.name == "posix":
                os.fchmod(output.fileno(), 0o700)


def install(root: Path, version: str, rid: str) -> Path:
    """Provision only after the caller explicitly requests --install."""
    root = cache_root(root)
    cached = cached_binary(root, version, rid)
    if cached is not None:
        return cached
    binary = binary_path(root, version, rid)
    base_url = f"{RELEASES}/v{version}"
    with (
        cache_directory(binary.parent, root, create=True) as directory,
        installation_directory(binary.parent, directory) as (temporary, staged),
    ):
        metadata_path = temporary / "release-metadata.json"
        download(
            f"{base_url}/release-metadata.json",
            metadata_path,
            MAX_METADATA_BYTES,
            directory=staged,
        )
        with cache_file(metadata_path, staged) as metadata_stream:
            content = metadata_stream.read(MAX_METADATA_BYTES + 1)
        if len(content) > MAX_METADATA_BYTES:
            raise ValueError("Release metadata exceeds the size limit")
        metadata_hash = hashlib.sha256(content).hexdigest()
        metadata = json_object(json.loads(content))
        filename, expected_hash, expected_size = release_asset(metadata, version, rid)
        archive = temporary / filename
        download(f"{base_url}/{filename}", archive, expected_size, directory=staged)
        staged_binary = temporary / binary.name
        with cache_file(archive, staged) as archive_stream:
            if (
                os.fstat(archive_stream.fileno()).st_size != expected_size
                or stream_sha256(archive_stream) != expected_hash
            ):
                raise ValueError(
                    "Release archive size or SHA-256 mismatch; binary was not installed"
                )
            unpack_binary(
                archive,
                f"tmforge-{version}-{rid}/{binary.name}",
                staged_binary,
                directory=staged,
                archive_stream=archive_stream,
            )
        with cache_file(staged_binary, staged) as executable:
            binary_hash = stream_sha256(executable)
        receipt = temporary / "receipt.json"
        with cache_output(receipt, staged) as output:
            output.write(
                (
                    json.dumps(
                        {
                            "version": version,
                            "rid": rid,
                            "archiveSha256": expected_hash,
                            "releaseMetadataSha256": metadata_hash,
                            "binarySha256": binary_hash,
                            "source": f"{base_url}/{filename}",
                        },
                        indent=2,
                    )
                    + "\n"
                ).encode("utf-8")
            )
        for source, destination in (
            (staged_binary, binary),
            (receipt, binary.parent / receipt.name),
        ):
            os.replace(
                source.name if staged is not None else source,
                destination.name if directory is not None else destination,
                src_dir_fd=staged,
                dst_dir_fd=directory,
            )
        with cache_directory(binary.parent, root) as current:
            if directory is not None and current is not None:
                original_info, current_info = os.fstat(directory), os.fstat(current)
                if (original_info.st_dev, original_info.st_ino) != (
                    current_info.st_dev,
                    current_info.st_ino,
                ):
                    raise ValueError("Cache directory changed during installation")
    return binary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="Pass CLI arguments after --, for example: -- open model.tm7 --json",
    )
    parser.add_argument(
        "--cache-dir", type=Path, help="Override the user cache (outside the plugin)"
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--status",
        action="store_true",
        help="Report cached binary state as JSON; never download",
    )
    action.add_argument(
        "--install",
        action="store_true",
        help="Approve downloading the pinned release for this host",
    )
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    forwarded = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
    if (args.status or args.install) and forwarded:
        parser.error("--status and --install cannot be combined with CLI arguments")
    try:
        version, rid = plugin_version(), runtime_id()
        root = cache_root(args.cache_dir)
        if args.install:
            print(install(root, version, rid))
            return 0
        if args.status:
            binary = cached_binary(root, version, rid)
            print(
                json.dumps(
                    {
                        "version": version,
                        "rid": rid,
                        "installed": binary is not None,
                        "binary": str(binary_path(root, version, rid)),
                    },
                    indent=2,
                )
            )
            return 0
        with verified_cache(root, version, rid) as verified:
            if verified is None:
                command = [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--cache-dir",
                    str(root),
                    "--install",
                ]
                raise ValueError(
                    "Pinned tmforge binary is missing or invalid. After approval, run: "
                    + shlex.join(command)
                )
            return execute_verified(verified, forwarded)
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f"tmforge plugin: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
