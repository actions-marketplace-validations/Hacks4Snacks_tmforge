#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
from contextlib import ExitStack, contextmanager
from functools import cache
from pathlib import Path, PurePosixPath, PureWindowsPath
from types import ModuleType
from typing import Generator, cast

from generate_suppressions import (
    artifact_stream,
    output_directory,
    system_path,
    validate_output_entry,
)

SCRIPTS = Path(__file__).resolve().parent
SCRIPTS_DIR = SCRIPTS
PACKAGE_VALIDATOR = SCRIPTS / "validate_package.py"
RENDERER = SCRIPTS / "render_analysis.py"
EXAMPLE = SCRIPTS.parent / "assets" / "analysis.example.json"
STATE_DIR = Path.home() / ".copilot-threat-model-validation"
SKIP_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    ".vscode-test",
    ".vscode-test-web",
    "__pycache__",
    "node_modules",
    "vendor",
    "venv",
}

JsonObject = dict[str, object]
PACKAGE_DOCUMENTS = ("analysis.json", "data-flow.md", "threat-model.md")


def resolve_root(explicit_root: Path | None) -> Path:
    """Use the selected directory or the caller's Git worktree, never this script."""
    if explicit_root is not None:
        root = explicit_root.expanduser().resolve()
    else:
        try:
            result = subprocess.run(
                ["git", "-C", str(Path.cwd()), "rev-parse", "--show-toplevel"],
                capture_output=True,
                check=False,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(
                "Cannot discover the current Git worktree; pass --root explicitly."
            ) from exc
        if result.returncode != 0 or not result.stdout.strip():
            raise ValueError(
                "Not in a Git worktree; pass --root for the directory to analyze."
            )
        root = Path(result.stdout.strip()).resolve()
    if not root.is_dir():
        raise ValueError(f"Analyzed root is not a directory: {root}")
    return root


def as_object(value: object) -> JsonObject | None:
    """Narrow a JSON value to an object."""
    return cast(JsonObject, value) if isinstance(value, dict) else None


def state_path(root: Path, state_directory: Path = STATE_DIR) -> Path:
    """Return the baseline path for this repository checkout."""
    key = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:16]
    return state_directory / f"{key}.json"


def validate_private_state(
    info: os.stat_result, directory: bool, private: bool = True
) -> None:
    reparse = getattr(info, "st_file_attributes", 0) & getattr(
        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
    )
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if reparse or not expected_type(info.st_mode):
        raise ValueError(
            "validation state must use regular files and directories, not links"
        )
    if not directory and info.st_nlink != 1:
        raise ValueError("validation state must not be hard-linked")
    if os.name == "posix":
        owners = {os.geteuid()} if private else {0, os.geteuid()}
        forbidden = 0o077 if private else 0o022
        shared_parent = not private and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        if info.st_uid not in owners or (
            stat.S_IMODE(info.st_mode) & forbidden and not shared_parent
        ):
            raise ValueError(
                "validation state must be owned by the current user and private (0700 directories, 0600 files); ancestors must have trusted owners and no untrusted write access"
            )


@cache
def windows_permissions_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "state_windows_permissions", SCRIPTS / "windows_permissions.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def windows_state_permissions(path: Path, private: bool = True) -> None:
    windows_permissions_module().windows_permissions(path, private)


@contextmanager
def windows_state_directory(path: Path, create: bool) -> Generator[None, None, None]:
    with ExitStack() as handles:
        for directory in [*reversed(path.absolute().parents), path.absolute()]:
            try:
                info = directory.lstat()
            except FileNotFoundError:
                if not create:
                    raise
                directory.mkdir(mode=0o700)
                info = directory.lstat()
            handles.enter_context(
                windows_permissions_module().windows_directory_handle(directory)
            )
            reparse = getattr(info, "st_file_attributes", 0) & getattr(
                stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
            )
            if reparse or not stat.S_ISDIR(info.st_mode):
                raise ValueError(
                    "validation state must use directories, not links or reparse points"
                )
            windows_state_permissions(directory, private=directory == path.absolute())
        yield


@contextmanager
def private_state_directory(
    path: Path, create: bool = False
) -> Generator[int | None, None, None]:
    if sys.platform == "win32":
        with windows_state_directory(path, create):
            yield None
        return
    descriptor = None
    try:
        if os.name == "posix":
            absolute = system_path(path)
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            descriptor = os.open(absolute.anchor, flags)
            validate_private_state(
                os.fstat(descriptor), directory=True, private=len(absolute.parts) == 1
            )
            for index, name in enumerate(absolute.parts[1:], start=1):
                private = index == len(absolute.parts) - 1
                try:
                    info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(name, mode=0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                    info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                validate_private_state(info, directory=True, private=private)
                child = os.open(name, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                validate_private_state(
                    os.fstat(descriptor), directory=True, private=private
                )
        else:
            validate_private_state(path.lstat(), directory=True)
        yield descriptor
    finally:
        if descriptor is not None:
            os.close(descriptor)


def read_state(path: Path) -> object:
    with private_state_directory(path.parent) as directory:
        location = path.name if directory is not None else path
        info = os.stat(location, dir_fd=directory, follow_symlinks=False)
        validate_private_state(info, directory=False)
        if sys.platform == "win32":
            windows_state_permissions(path)
        flags = (
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(location, flags, dir_fd=directory)
        with os.fdopen(descriptor, "r", encoding="utf-8") as source:
            opened = os.fstat(source.fileno())
            validate_private_state(opened, directory=False)
            if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError("validation state changed while opening")
            return json.load(source)


def write_state(path: Path, document: JsonObject) -> None:
    with private_state_directory(path.parent, create=True) as directory:
        location = path.name if directory is not None else path
        try:
            info = os.stat(location, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            validate_private_state(info, directory=False)
            if sys.platform == "win32":
                windows_state_permissions(path)
        name = f".{path.name}.{secrets.token_hex(16)}.tmp"
        temporary = name if directory is not None else path.parent / name
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(document, output, sort_keys=True)
            if sys.platform == "win32":
                windows_state_permissions(path.parent / name)
            os.replace(temporary, location, src_dir_fd=directory, dst_dir_fd=directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass


def remove_state(path: Path) -> None:
    with private_state_directory(path.parent) as directory:
        location = path.name if directory is not None else path
        try:
            os.unlink(location, dir_fd=directory)
        except FileNotFoundError:
            pass


def file_digest(path: Path) -> str:
    """Hash a regular artifact, failing closed on unsafe or unreadable paths."""
    digest = hashlib.sha256()
    with artifact_stream(path) as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def walk_error(error: OSError) -> None:
    raise error


raise_walk_error = walk_error


def checked_directories(root: Path):
    with output_directory(root):
        pass
    for directory, children, filenames in os.walk(root, onerror=walk_error):
        children[:] = sorted(name for name in children if name not in SKIP_DIRECTORIES)
        path = Path(directory)
        with output_directory(path) as descriptor:
            for name in children:
                location = name if descriptor is not None else path / name
                validate_output_entry(
                    os.stat(location, dir_fd=descriptor, follow_symlinks=False),
                    directory=True,
                )
        yield path, sorted(filenames)


def package_files(package_directory: Path) -> list[Path]:
    """Return deterministic package files covered by the unified verifier."""
    paths: list[Path] = []
    for directory, filenames in checked_directories(package_directory):
        with output_directory(directory) as descriptor:
            for name in filenames:
                if name.endswith((".tm7", ".tm.json", ".tm.suppressions.json")) or (
                    directory == package_directory
                    and (
                        name in PACKAGE_DOCUMENTS or name.endswith(".tm.evidence.json")
                    )
                ):
                    path = directory / name
                    location = name if descriptor is not None else path
                    validate_output_entry(
                        os.stat(location, dir_fd=descriptor, follow_symlinks=False)
                    )
                    paths.append(path)
    return sorted(
        paths, key=lambda path: path.relative_to(package_directory).as_posix()
    )


def package_digest(package_directory: Path) -> str:
    """Hash package paths and bytes so companion-only changes are detected."""
    digest = hashlib.sha256()
    for path in package_files(package_directory):
        relative_path = path.relative_to(package_directory).as_posix()
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_digest(path).encode("ascii", errors="backslashreplace"))
        digest.update(b"\0")
    return digest.hexdigest()


def snapshot_packages(root: Path, *, require_ledger: bool = False) -> dict[str, str]:
    """Return hashes for retained packages under the repository root."""
    snapshot: dict[str, str] = {}
    package_directories: set[Path] = set()
    for package_directory, filenames in checked_directories(root):
        if require_ledger and "analysis.json" not in filenames:
            continue
        has_package_documents = any(
            name in PACKAGE_DOCUMENTS or name.endswith(".tm.evidence.json")
            for name in filenames
        )
        has_models = any(
            name.endswith((".tm7", ".tm.json", ".tm.suppressions.json"))
            for name in filenames
        )
        if not has_package_documents and (
            not has_models
            or any(
                parent in package_directories for parent in package_directory.parents
            )
        ):
            continue
        package_directories.add(package_directory)
        relative_path = package_directory.relative_to(root).as_posix()
        snapshot[relative_path] = package_digest(package_directory)
    return dict(sorted(snapshot.items()))


def changed_packages(before: dict[str, str], after: dict[str, str]) -> list[str]:
    """Return new or modified retained packages."""
    return sorted(path for path, digest in after.items() if before.get(path) != digest)


def validate_paths(
    root: Path,
    relative_paths: list[str],
    tmforge: str | None = None,
    timeout: int = 300,
) -> list[str]:
    """Run the unified package verifier and return concise failures."""
    if not PACKAGE_VALIDATOR.is_file():
        return [f"package verifier not found: {PACKAGE_VALIDATOR}"]
    if timeout < 1:
        raise ValueError("--timeout must be at least 1 second")

    failures: list[str] = []
    for relative_path in relative_paths:
        path = root / relative_path
        try:
            artifacts = package_files(path)
        except (OSError, ValueError) as exc:
            failures.append(
                f"{relative_path}: unsafe or unreadable package artifacts: {exc}"
            )
            continue
        command = [
            sys.executable,
            str(PACKAGE_VALIDATOR),
            str(path),
            "--json",
            "--timeout",
            str(timeout),
        ]
        if tmforge:
            command.extend(["--tmforge", tmforge])
        models = sum(artifact.name.endswith(".tm7") for artifact in artifacts)
        sidecars = sum(
            artifact.name.endswith(".tm.suppressions.json") for artifact in artifacts
        )
        deadline = 30 + timeout * (1 + models * (9 + sidecars))
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                check=False,
                text=True,
                timeout=deadline,
                cwd=root,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            failures.append(f"{relative_path}: validator failed to run: {exc}")
            continue
        if result.returncode == 0:
            continue
        detail = (result.stderr or result.stdout or "validation failed").strip()
        failures.append(f"{relative_path}: {detail[:2000]}")
    return failures


def report_failures(failures: list[str]) -> None:
    """Print actionable validation failures."""
    print(
        "Threat-model package validation failed. Fix the changed package(s) and "
        "rerun the unified verifier:",
        file=sys.stderr,
    )
    for failure in failures:
        print(f"- {failure}", file=sys.stderr)


def snapshot(root: Path, state_directory: Path = STATE_DIR) -> int:
    """Persist the current retained-ledger baseline."""
    files = snapshot_packages(root)
    state: JsonObject = {"root": str(root), "files": files}
    write_state(state_path(root, state_directory), state)
    print(f"Baseline captured for {len(files)} package(s).")
    return 0


def baseline_files(value: object, root: Path) -> dict[str, str]:
    """Validate persisted state without coercing missing or corrupt data."""
    state = as_object(value)
    if state is None or set(state) != {"root", "files"}:
        raise ValueError("invalid baseline state: expected root and files")
    if state["root"] != str(root):
        raise ValueError("baseline belongs to a different target root")
    files = as_object(state["files"])
    if files is None:
        raise ValueError("invalid baseline state: files must be an object")
    result: dict[str, str] = {}
    for name, digest in files.items():
        relative = PurePosixPath(name)
        if (
            relative.is_absolute()
            or relative.as_posix() != name
            or ".." in relative.parts
            or "\\" in name
            or "\0" in name
            or PureWindowsPath(name).drive
        ):
            raise ValueError(f"invalid baseline package path: {name!r}")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError(f"invalid baseline SHA-256 digest for {name!r}")
        result[name] = digest
    return result


def read_baseline(path: Path, root: Path) -> dict[str, str]:
    return baseline_files(read_state(path), root)


def verify(
    root: Path,
    check_all: bool,
    keep: bool,
    state_directory: Path = STATE_DIR,
    tmforge: str | None = None,
    timeout: int = 300,
) -> int:
    """Validate packages changed since the baseline, or every package."""
    after = snapshot_packages(root, require_ledger=check_all)
    path = state_path(root, state_directory)

    if check_all:
        targets = sorted(after)
    else:
        try:
            before = read_baseline(path, root)
        except FileNotFoundError:
            print(
                "No baseline found; run 'snapshot' first or pass --all.",
                file=sys.stderr,
            )
            return 1
        targets = changed_packages(before, after)
        for relative_path in before.keys() - after.keys():
            relative = Path(relative_path)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("baseline package path escapes the reviewed root")
            package = root / relative
            if package.exists() and package_files(package):
                targets.append(relative_path)
        targets.sort()

    if not targets:
        if not keep and not check_all:
            remove_state(path)
        print("No changed threat-model packages to validate.")
        return 0

    failures = validate_paths(root, targets, tmforge, timeout)
    if failures:
        report_failures(failures)
        return 1

    if not keep and not check_all:
        remove_state(path)
    print(f"Validated {len(targets)} threat-model package(s).")
    return 0


def self_test() -> int:
    """Verify package change detection and rejection of invalid or stale content."""
    example = SCRIPTS.parent / "assets" / "analysis.example.json"
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory).resolve()
        ledger = root / "analysis.json"

        def write_verify_fixture() -> None:
            document = json.loads(example.read_text(encoding="utf-8"))
            document["scope"]["mode"] = "verify"
            document["scope"]["ownershipDecision"] = {
                "action": "verify-only",
                "modelReference": "existing-model.tm7",
                "rationale": "Self-test validates change detection only.",
            }
            ledger.write_text(json.dumps(document), encoding="utf-8")

        write_verify_fixture()
        render_result = subprocess.run(
            [sys.executable, str(RENDERER), str(ledger)],
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )
        if render_result.returncode != 0:
            raise AssertionError(f"fixture rendering failed: {render_result.stderr}")
        before = snapshot_packages(root)
        if changed_packages(before, snapshot_packages(root)):
            raise AssertionError("unchanged package was reported as changed")

        for rename in (False, True):
            renamed = ledger.with_name("analysis-renamed.json")
            if rename:
                ledger.rename(renamed)
            else:
                ledger.unlink()
            changed = changed_packages(before, snapshot_packages(root))
            if changed != ["."]:
                raise AssertionError("missing canonical ledger was not detected")
            failures = validate_paths(root, changed)
            if not failures or "missing canonical ledger" not in failures[0]:
                raise AssertionError("package without a canonical ledger was accepted")
            if rename:
                renamed.rename(ledger)
            else:
                write_verify_fixture()

        sidecar = root / "threat-model.tm.evidence.json"
        sidecar.write_text(json.dumps({"state": "draft"}), encoding="utf-8")
        added = snapshot_packages(root)
        if changed_packages(before, added) != ["."]:
            raise AssertionError("lifecycle sidecar addition was not detected")
        if changed_packages(added, snapshot_packages(root)):
            raise AssertionError("unchanged lifecycle sidecar was reported as changed")
        sidecar.write_text(json.dumps({"state": "invalid-state"}), encoding="utf-8")
        edited = snapshot_packages(root)
        changed = changed_packages(added, edited)
        if changed != ["."]:
            raise AssertionError("lifecycle sidecar edit was not detected")
        failures = validate_paths(root, changed)
        if not failures or "lifecycle.parity" not in failures[0]:
            raise AssertionError("invalid lifecycle sidecar was not rejected")
        sidecar.unlink()
        if changed_packages(edited, snapshot_packages(root)) != ["."]:
            raise AssertionError("lifecycle sidecar removal was not detected")

        document = json.loads(ledger.read_text(encoding="utf-8"))
        document["threats"][0]["score"] = 25
        ledger.write_text(json.dumps(document), encoding="utf-8")
        changed = changed_packages(before, snapshot_packages(root))
        if changed != ["."]:
            raise AssertionError(f"expected one changed package, got {changed}")
        failures = validate_paths(root, changed)
        if not failures or "score must equal" not in failures[0]:
            raise AssertionError("invalid score was not rejected")

        write_verify_fixture()
        rerender_result = subprocess.run(
            [sys.executable, str(RENDERER), str(ledger)],
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )
        if rerender_result.returncode != 0:
            raise AssertionError(
                f"fixture rerendering failed: {rerender_result.stderr}"
            )
        before = snapshot_packages(root)
        threat_model = root / "threat-model.md"
        threat_model.write_text(
            threat_model.read_text(encoding="utf-8") + "stale\n", encoding="utf-8"
        )
        changed = changed_packages(before, snapshot_packages(root))
        if changed != ["."]:
            raise AssertionError(f"document-only change was not detected: {changed}")
        failures = validate_paths(root, changed)
        if not failures or "stale generated document" not in failures[0]:
            raise AssertionError("stale generated document was not rejected")

    print("OK: threat-model package-validation self-test passed")
    return 0


def main() -> int:
    """Dispatch a verifier command."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    snapshot_parser = sub.add_parser(
        "snapshot", help="Capture the pre-edit package baseline."
    )
    verify_parser = sub.add_parser(
        "verify", help="Validate packages changed since the baseline."
    )
    for command_parser in (snapshot_parser, verify_parser):
        command_parser.add_argument(
            "--root",
            type=Path,
            help="Reviewed directory; defaults to the current Git worktree.",
        )
        command_parser.add_argument(
            "--state-dir",
            type=Path,
            default=STATE_DIR,
            help="Baseline directory; use a separate directory for concurrent sessions.",
        )
    verify_parser.add_argument(
        "--tmforge",
        help="tmforge executable or wrapper command passed to the package verifier.",
    )
    verify_parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Timeout in seconds for each tmforge command; the package deadline scales with its model and suppression counts.",
    )
    verify_parser.add_argument(
        "--all",
        action="store_true",
        dest="check_all",
        help="Validate every directory with analysis.json, ignoring the baseline and standalone model artifacts.",
    )
    verify_parser.add_argument(
        "--keep",
        action="store_true",
        help="Retain the baseline after a successful run.",
    )
    sub.add_parser("self-test", help="Verify change detection and rejection logic.")
    args = parser.parse_args()
    if args.command == "verify" and args.timeout < 1:
        parser.error("--timeout must be at least 1 second")

    try:
        if args.command == "self-test":
            return self_test()
        root = resolve_root(args.root)
        state_directory = args.state_dir.expanduser().absolute()
        if args.command == "snapshot":
            return snapshot(root, state_directory)
        return verify(
            root, args.check_all, args.keep, state_directory, args.tmforge, args.timeout
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"threat-model validation error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
