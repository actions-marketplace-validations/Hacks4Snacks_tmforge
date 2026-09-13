#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import IO, cast
from urllib.parse import SplitResult, urlsplit

PLUGIN_ROOT = Path(__file__).resolve().parents[3]
RELEASES = "https://github.com/Hacks4Snacks/tmforge/releases/download"
DOWNLOAD_HOSTS = {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
MAX_METADATA_BYTES = 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_BINARY_BYTES = 512 * 1024 * 1024
JSON = dict[str, object]


def json_object(value: object) -> JSON:
    """Require an object before interpreting release or cache metadata."""
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return cast(JSON, value)


def plugin_version() -> str:
    """Resolve the pin from the installed plugin, not the analyzed worktree."""
    manifest = json_object(json.loads((PLUGIN_ROOT / "plugin.json").read_text(encoding="utf-8")))
    version = manifest.get("version")
    if manifest.get("name") != "tmforge" or not isinstance(version, str) or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?", version
    ):
        raise ValueError("Install the complete tmforge plugin with a release version; 'latest' is not a pin")
    return version


def runtime_id(system: str | None = None, machine: str | None = None) -> str:
    """Map the current host to one of the six published self-contained binaries."""
    system = system or platform.system()
    machine = (machine or platform.machine()).lower()
    operating_system = {"Darwin": "osx", "Linux": "linux", "Windows": "win"}.get(system)
    architecture = {"x86_64": "x64", "amd64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(machine)
    if operating_system is None or architecture is None:
        raise ValueError(f"No published tmforge binary for {system}/{machine}; supply your own CLI")
    if system == "Linux" and platform.libc_ver()[0].lower() == "musl":
        raise ValueError("Published Linux binaries require glibc; supply your own CLI on musl")
    return f"{operating_system}-{architecture}"


def cache_root(explicit: Path | None = None) -> Path:
    """Use a private user cache; never write dependencies into the plugin or PATH."""
    if explicit is not None:
        root = explicit.expanduser().resolve()
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Caches" / "tmforge" / "copilot"
    elif sys.platform == "win32":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "tmforge" / "copilot"
    else:
        root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "tmforge" / "copilot"
    root = root.resolve()
    if root.is_relative_to(PLUGIN_ROOT):
        raise ValueError("The binary cache must be outside the installed plugin")
    return root


def binary_path(root: Path, version: str, rid: str) -> Path:
    """Keep each version and architecture separate and reject redirected cache paths."""
    executable = "tmforge.exe" if rid.startswith("win-") else "tmforge"
    path = root / version / rid / executable
    if not path.parent.resolve().is_relative_to(root.resolve()):
        raise ValueError("Binary cache path escapes its configured root")
    return path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def cached_binary(root: Path, version: str, rid: str) -> Path | None:
    """Do not execute incomplete or modified cache entries, even when offline."""
    binary = binary_path(root, version, rid)
    receipt = binary.parent / "receipt.json"
    if binary.is_symlink() or receipt.is_symlink() or not binary.is_file() or not receipt.is_file():
        return None
    if not 0 < binary.stat().st_size <= MAX_BINARY_BYTES or receipt.stat().st_size > MAX_METADATA_BYTES:
        return None
    try:
        data = json_object(json.loads(receipt.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return None
    if data.get("version") != version or data.get("rid") != rid or data.get("binarySha256") != sha256(binary):
        return None
    if os.name != "nt" and not os.access(binary, os.X_OK):
        return None
    return binary


def copy_limited(source: IO[bytes], destination: IO[bytes], limit: int) -> int:
    """Bound actual bytes, not just a possibly untrusted length declaration."""
    count = 0
    while block := source.read(min(1024 * 1024, limit - count + 1)):
        count += len(block)
        if count > limit:
            raise ValueError(f"Download or executable exceeds the {limit}-byte limit")
        destination.write(block)
    return count


def download(url: str, destination: Path, limit: int) -> None:
    """Fetch public release data over verified TLS; no credentials or telemetry."""
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in DOWNLOAD_HOSTS:
        raise ValueError("Downloads must use an HTTPS GitHub release URL")
    request = urllib.request.Request(url, headers={"User-Agent": "tmforge-copilot-plugin"})
    with urllib.request.urlopen(request, timeout=60) as response:
        final: SplitResult = urlsplit(str(response.geturl()))
        if final.scheme != "https" or final.hostname not in DOWNLOAD_HOSTS:
            raise ValueError("Release download redirected outside the HTTPS GitHub asset hosts")
        with destination.open("wb") as output:
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
        raise ValueError("Release archive size is invalid or exceeds the download limit")
    return filename, digest, size


def unpack_binary(archive: Path, member_name: str, destination: Path) -> None:
    """Copy only the expected regular executable; never extract archive paths."""
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as package:
            members = [member for member in package.infolist() if member.filename == member_name]
            if len(members) != 1:
                raise ValueError("Archive must contain exactly one expected executable")
            member = members[0]
            mode = stat.S_IFMT(member.external_attr >> 16)
            if member.is_dir() or mode not in {0, stat.S_IFREG} or not 0 < member.file_size <= MAX_BINARY_BYTES:
                raise ValueError("Expected executable must be a bounded regular file")
            with package.open(member) as source, destination.open("wb") as output:
                count = copy_limited(source, output, member.file_size)
            if count != member.file_size:
                raise ValueError("Executable size does not match the archive header")
    else:
        with tarfile.open(archive, "r:gz") as package:
            members = [member for member in package if member.name == member_name]
            if len(members) != 1:
                raise ValueError("Archive must contain exactly one expected executable")
            member = members[0]
            if not member.isfile() or not 0 < member.size <= MAX_BINARY_BYTES:
                raise ValueError("Expected executable must be a bounded regular file")
            source = package.extractfile(member)
            if source is None:
                raise ValueError("Expected executable has no readable content")
            with source, destination.open("wb") as output:
                count = copy_limited(source, output, member.size)
            if count != member.size:
                raise ValueError("Executable size does not match the archive header")
    destination.chmod(0o755)


def install(root: Path, version: str, rid: str) -> Path:
    """Provision only after the caller explicitly requests --install."""
    cached = cached_binary(root, version, rid)
    if cached is not None:
        return cached
    binary = binary_path(root, version, rid)
    binary.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    base_url = f"{RELEASES}/v{version}"
    with tempfile.TemporaryDirectory(prefix=".install-", dir=binary.parent) as directory:
        temporary = Path(directory)
        metadata_path = temporary / "release-metadata.json"
        download(f"{base_url}/release-metadata.json", metadata_path, MAX_METADATA_BYTES)
        metadata = json_object(json.loads(metadata_path.read_text(encoding="utf-8")))
        filename, expected_hash, expected_size = release_asset(metadata, version, rid)
        archive = temporary / filename
        download(f"{base_url}/{filename}", archive, expected_size)
        if archive.stat().st_size != expected_size or sha256(archive) != expected_hash:
            raise ValueError("Release archive size or SHA-256 mismatch; binary was not installed")
        staged_binary = temporary / binary.name
        unpack_binary(archive, f"tmforge-{version}-{rid}/{binary.name}", staged_binary)
        receipt = temporary / "receipt.json"
        receipt.write_text(json.dumps({
            "version": version, "rid": rid, "archiveSha256": expected_hash,
            "binarySha256": sha256(staged_binary), "source": f"{base_url}/{filename}",
        }, indent=2) + "\n", encoding="utf-8")
        os.replace(staged_binary, binary)
        os.replace(receipt, binary.parent / receipt.name)
    return binary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, epilog="Pass CLI arguments after --, for example: -- open model.tm7 --json")
    parser.add_argument("--cache-dir", type=Path, help="Override the user cache (outside the plugin)")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--status", action="store_true", help="Report cached binary state as JSON; never download")
    action.add_argument("--install", action="store_true", help="Approve downloading the pinned release for this host")
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
        binary = cached_binary(root, version, rid)
        if args.status:
            print(json.dumps({"version": version, "rid": rid, "installed": binary is not None,
                              "binary": str(binary_path(root, version, rid))}, indent=2))
            return 0
        if binary is None:
            command = [sys.executable, str(Path(__file__).resolve()), "--cache-dir", str(root), "--install"]
            raise ValueError("Pinned tmforge binary is missing or invalid. After approval, run: " + shlex.join(command))
        # Preserve the caller's working directory, stdout, stderr, and CLI exit code.
        return subprocess.run([str(binary), *forwarded], check=False).returncode
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f"tmforge plugin: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
