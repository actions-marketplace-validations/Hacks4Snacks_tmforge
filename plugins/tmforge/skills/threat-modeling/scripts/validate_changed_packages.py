#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import cast

SCRIPTS_DIR = Path(__file__).resolve().parent
PACKAGE_VALIDATOR = SCRIPTS_DIR / "validate_package.py"
RENDERER = SCRIPTS_DIR / "render_analysis.py"
EXAMPLE = SCRIPTS_DIR.parent / "assets" / "analysis.example.json"
STATE_DIR = Path(tempfile.gettempdir()) / "copilot-threat-model-validation"
SKIP_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "node_modules",
    "vendor",
    "venv",
}

JsonObject = dict[str, object]


def as_object(value: object) -> JsonObject | None:
    """Narrow a JSON value to an object."""
    return cast(JsonObject, value) if isinstance(value, dict) else None


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


def state_path(root: Path, state_directory: Path = STATE_DIR) -> Path:
    """Return the baseline path for this repository checkout."""
    key = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:16]
    return state_directory / f"{key}.json"


def raise_walk_error(error: OSError) -> None:
    """An unreadable subtree must not look like an unchanged or empty repository."""
    raise error


def file_digest(path: Path) -> str:
    """Hash one package file, preserving read errors as changed state."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        return f"unreadable:{type(exc).__name__}:{exc}"


def package_files(package_directory: Path) -> list[Path]:
    """Return deterministic package files covered by the unified verifier."""
    paths: list[Path] = []
    for directory, children, filenames in os.walk(
        package_directory, onerror=raise_walk_error
    ):
        children[:] = sorted(name for name in children if name not in SKIP_DIRECTORIES)
        current = Path(directory)
        for name in filenames:
            if name.endswith((".tm7", ".tm.json")) or (
                current == package_directory
                and name in {"analysis.json", "data-flow.md", "threat-model.md"}
            ):
                paths.append(current / name)
    return sorted(
        set(paths), key=lambda path: path.relative_to(package_directory).as_posix()
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


def snapshot_packages(root: Path) -> dict[str, str]:
    """Return hashes for retained packages under the repository root."""
    snapshot: dict[str, str] = {}
    for directory, child_directories, filenames in os.walk(root, onerror=raise_walk_error):
        child_directories[:] = sorted(
            name for name in child_directories if name not in SKIP_DIRECTORIES
        )
        if "analysis.json" not in filenames:
            continue
        package_directory = Path(directory)
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

    failures: list[str] = []
    for relative_path in relative_paths:
        path = root / relative_path
        command = [sys.executable, "-B", str(PACKAGE_VALIDATOR), str(path), "--json"]
        if tmforge is not None:
            command.extend(["--tmforge", tmforge])
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                check=False,
                text=True,
                timeout=timeout,
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
    state_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    files = snapshot_packages(root)
    state: JsonObject = {
        "root": str(root),
        "files": files,
    }
    descriptor, temporary_name = tempfile.mkstemp(dir=state_directory, suffix=".tmp")
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(state, stream, sort_keys=True)
        os.replace(temporary_path, state_path(root, state_directory))
    finally:
        temporary_path.unlink(missing_ok=True)
    print(f"Baseline captured for {len(files)} package(s).")
    return 0


def read_baseline(path: Path, root: Path) -> dict[str, str]:
    """Reject corrupt or foreign state rather than silently validating no packages."""
    state = as_object(json.loads(path.read_text(encoding="utf-8")))
    if state is None or state.get("root") != str(root):
        raise ValueError(f"Invalid baseline root in {path}; capture a new snapshot.")
    files = as_object(state.get("files"))
    if files is None:
        raise ValueError(f"Invalid baseline files in {path}; capture a new snapshot.")
    before: dict[str, str] = {}
    for name, digest in files.items():
        relative = Path(name)
        if (
            not name
            or relative.is_absolute()
            or ".." in relative.parts
            or not (root / relative).resolve().is_relative_to(root)
            or not isinstance(digest, str)
        ):
            raise ValueError(f"Invalid baseline entry in {path}; capture a new snapshot.")
        before[name] = digest
    return before


def verify(
    root: Path,
    check_all: bool,
    keep: bool,
    state_directory: Path = STATE_DIR,
    tmforge: str | None = None,
    timeout: int = 300,
) -> int:
    """Validate packages changed since the baseline, or every package."""
    after = snapshot_packages(root)
    path = state_path(root, state_directory)

    if check_all:
        targets = sorted(after)
    elif not path.is_file():
        print(
            "No baseline found; run 'snapshot' first or pass --all.",
            file=sys.stderr,
        )
        return 1
    else:
        before = read_baseline(path, root)
        # Deleting a ledger must not hide an otherwise retained package from the gate.
        missing_ledgers = [
            name for name in before if name not in after and (root / name).is_dir()
        ]
        targets = sorted(set(changed_packages(before, after) + missing_ledgers))

    failures = validate_paths(root, targets, tmforge, timeout) if targets else []
    if failures:
        report_failures(failures)
        return 1

    if not keep and not check_all:
        path.unlink(missing_ok=True)
    if targets:
        print(f"Validated {len(targets)} threat-model package(s).")
    else:
        print("No changed threat-model packages to validate.")
    return 0


def self_test() -> int:
    """Verify package change detection and rejection of invalid or stale content."""
    with tempfile.TemporaryDirectory() as temporary_directory:
        root = Path(temporary_directory)
        ledger = root / "analysis.json"

        def write_verify_fixture() -> None:
            document = json.loads(EXAMPLE.read_text(encoding="utf-8"))
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
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--root", type=Path,
        help="Analyzed directory; defaults to the current Git worktree's top level.",
    )
    common.add_argument(
        "--state-dir", type=Path, default=STATE_DIR,
        help="Snapshot storage outside the plugin; use a unique directory per session.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("snapshot", parents=[common], help="Capture the pre-edit package baseline.")
    verify_parser = sub.add_parser(
        "verify", parents=[common], help="Validate packages changed since the baseline."
    )
    verify_parser.add_argument("--tmforge", help="tmforge executable or wrapper command")
    verify_parser.add_argument(
        "--timeout", type=int, default=300,
        help="Overall timeout in seconds for each package verifier (default: 300).",
    )
    verify_parser.add_argument(
        "--all",
        action="store_true",
        dest="check_all",
        help="Validate every retained package, ignoring the baseline.",
    )
    verify_parser.add_argument(
        "--keep",
        action="store_true",
        help="Retain the baseline after a successful run.",
    )
    sub.add_parser("self-test", help="Verify change detection and rejection logic.")
    args = parser.parse_args()

    try:
        if args.command == "self-test":
            return self_test()
        root = resolve_root(args.root)
        state_directory = args.state_dir.expanduser().resolve()
        if args.command == "snapshot":
            return snapshot(root, state_directory)
        if args.timeout < 1:
            parser.error("--timeout must be at least 1 second")
        return verify(
            root, args.check_all, args.keep, state_directory, args.tmforge, args.timeout
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"threat-model validation error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
