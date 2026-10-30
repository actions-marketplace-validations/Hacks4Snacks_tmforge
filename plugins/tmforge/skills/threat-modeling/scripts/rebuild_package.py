#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager, nullcontext
from pathlib import Path

from generate_suppressions import output_directory, validate_output_entry

SCRIPTS = Path(__file__).resolve().parent
TIMEOUT_SECONDS = 1800


class BoundDirectory:
    def __init__(self, path: Path, descriptor: int | None) -> None:
        self.path = path
        self.descriptor = descriptor
        info = os.fstat(descriptor) if descriptor is not None else path.lstat()
        self.identity = (info.st_dev, info.st_ino)

    def check_identity(self) -> None:
        with output_directory(self.path) as descriptor:
            info = os.fstat(descriptor) if descriptor is not None else self.path.lstat()
            if self.identity != (info.st_dev, info.st_ino):
                raise ValueError(f"rebuild directory changed: {self.path}")

    def entry(self, name: str) -> Path:
        if Path(name).name != name or name in {"", ".", ".."}:
            raise ValueError(f"expected a directory-local name: {name!r}")
        return Path(name) if self.descriptor is not None else self.path / name

    def info(self, name: str) -> os.stat_result:
        return os.stat(self.entry(name), dir_fd=self.descriptor, follow_symlinks=False)

    def read(self, name: str) -> bytes | None:
        try:
            info = self.info(name)
        except FileNotFoundError:
            return None
        validate_output_entry(info)
        flags = (
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(self.entry(name), flags, dir_fd=self.descriptor)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            validate_output_entry(opened)
            if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError(f"rebuild artifact changed while opening: {name}")
            return stream.read()

    def unlink(self, name: str) -> None:
        os.unlink(self.entry(name), dir_fd=self.descriptor)

    def replace_from(self, source: BoundDirectory, name: str) -> None:
        os.replace(
            source.entry(name),
            self.entry(name),
            src_dir_fd=source.descriptor,
            dst_dir_fd=self.descriptor,
        )

    def write(self, name: str, content: bytes, mode: int = 0o600) -> None:
        descriptor = os.open(
            self.entry(name),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            mode,
            dir_fd=self.descriptor,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)

    def clear(self) -> None:
        for name in os.listdir(
            self.descriptor if self.descriptor is not None else self.path
        ):
            info = self.info(name)
            reparse = getattr(info, "st_file_attributes", 0) & 0x400
            if stat.S_ISDIR(info.st_mode) and not reparse:
                with bound_directory(self.path / name, self) as child:
                    child.clear()
                os.rmdir(self.entry(name), dir_fd=self.descriptor)
            elif reparse and stat.S_ISDIR(info.st_mode):
                os.rmdir(self.entry(name), dir_fd=self.descriptor)
            else:
                self.unlink(name)


@contextmanager
def bound_directory(
    path: Path, parent: BoundDirectory | None = None
) -> Iterator[BoundDirectory]:
    with ExitStack() as stack:
        descriptor: int | None
        if parent is not None and parent.descriptor is not None:
            expected = parent.info(path.name)
            validate_output_entry(expected, directory=True)
            descriptor = os.open(
                path.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent.descriptor,
            )
            stack.callback(os.close, descriptor)
            opened = os.fstat(descriptor)
            validate_output_entry(opened, directory=True)
            if (expected.st_dev, expected.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError(f"directory changed while opening: {path}")
        else:
            descriptor = stack.enter_context(output_directory(path))
            if sys.platform == "win32":
                from windows_permissions import windows_directory_handle

                for ancestor in [*reversed(path.absolute().parents), path.absolute()]:
                    stack.enter_context(windows_directory_handle(ancestor))
        yield BoundDirectory(path, descriptor)


@contextmanager
def package_lock(package: Path, parent: BoundDirectory | None = None) -> Iterator[None]:
    with (
        nullcontext(parent) if parent is not None else bound_directory(package.parent)
    ) as directory:
        name = f".{package.name}.rebuild.lock"
        try:
            os.mkdir(directory.entry(name), mode=0o700, dir_fd=directory.descriptor)
        except FileExistsError as exc:
            raise ValueError(
                f"another rebuild holds {directory.path / name}; inspect recovery files before removing a stale lock"
            ) from exc
        try:
            yield
        finally:
            os.rmdir(directory.entry(name), dir_fd=directory.descriptor)


@contextmanager
def temporary_directory(
    parent: BoundDirectory, prefix: str
) -> Iterator[BoundDirectory]:
    name = prefix + secrets.token_hex(16)
    os.mkdir(parent.entry(name), mode=0o700, dir_fd=parent.descriptor)
    path = parent.path / name
    directory = None
    try:
        with bound_directory(path, parent) as directory:
            try:
                yield directory
            finally:
                directory.clear()
    finally:
        if directory is not None:
            remove_directory(parent, directory)


def copy_tree(source: BoundDirectory, destination: BoundDirectory) -> None:
    """Copy without resolving package or descendant paths through links."""
    for name in sorted(
        os.listdir(source.descriptor if source.descriptor is not None else source.path)
    ):
        info = source.info(name)
        validate_output_entry(info, directory=stat.S_ISDIR(info.st_mode))
        if stat.S_ISDIR(info.st_mode):
            os.mkdir(destination.entry(name), mode=0o700, dir_fd=destination.descriptor)
            with bound_directory(source.path / name, source) as child_source:
                if child_source.identity != (info.st_dev, info.st_ino):
                    raise ValueError(f"package directory changed while copying: {name}")
                with bound_directory(
                    destination.path / name, destination
                ) as child_destination:
                    copy_tree(child_source, child_destination)
        else:
            content = source.read(name)
            if content is None:
                raise ValueError(f"package artifact disappeared while copying: {name}")
            destination.write(name, content, stat.S_IMODE(info.st_mode))


def remove_directory(parent: BoundDirectory, directory: BoundDirectory) -> None:
    info = parent.info(directory.path.name)
    if (info.st_dev, info.st_ino) != directory.identity:
        raise ValueError(f"temporary directory was replaced: {directory.path}")
    os.rmdir(parent.entry(directory.path.name), dir_fd=parent.descriptor)


def artifact_bytes(path: Path) -> bytes | None:
    with bound_directory(path.parent) as directory:
        return directory.read(path.name)


def promote_outputs(
    package: Path,
    candidate: Path,
    before: dict[str, bytes | None],
    owned: BoundDirectory | None = None,
    staged: BoundDirectory | None = None,
    parent: BoundDirectory | None = None,
) -> None:
    """Publish under the package lock, retaining recovery files if rollback fails."""
    with ExitStack() as stack:
        owned = owned or stack.enter_context(bound_directory(package))
        staged = staged or stack.enter_context(bound_directory(candidate))
        parent = parent or stack.enter_context(bound_directory(package.parent))
        _promote_outputs(owned, staged, parent, before)


def _promote_outputs(
    owned: BoundDirectory,
    staged: BoundDirectory,
    parent: BoundDirectory,
    before: dict[str, bytes | None],
) -> None:
    changed: dict[str, bytes | None] = {}
    for name, previous in before.items():
        if owned.read(name) != previous:
            raise ValueError(f"owned artifact changed during rebuild: {name}")
        content = staged.read(name)
        if content != previous:
            changed[name] = content
    if not changed:
        return
    recovery_name = f".{owned.path.name}.rollback-{secrets.token_hex(16)}"
    os.mkdir(parent.entry(recovery_name), mode=0o700, dir_fd=parent.descriptor)
    recovery_path = parent.path / recovery_name
    retain_recovery = False
    attempted: list[str] = []
    recovery = None
    try:
        with bound_directory(recovery_path, parent) as recovery:
            for name in changed:
                previous = before[name]
                if previous is not None:
                    recovery.write(
                        name, previous, stat.S_IMODE(owned.info(name).st_mode)
                    )
                    if owned.read(name) != previous:
                        raise ValueError(
                            f"owned artifact changed during rebuild: {name}"
                        )
            try:
                for name in changed:
                    if owned.read(name) != before[name]:
                        raise ValueError(
                            f"owned artifact changed during promotion: {name}"
                        )
                    attempted.append(name)
                    if changed[name] is None:
                        owned.unlink(name)
                    else:
                        owned.replace_from(staged, name)
                owned.check_identity()
                staged.check_identity()
                parent.check_identity()
                for name, previous in before.items():
                    if owned.read(name) != changed.get(name, previous):
                        raise ValueError(
                            f"owned artifact changed during promotion: {name}"
                        )
            except (OSError, ValueError, KeyboardInterrupt) as exc:
                unrestored: list[str] = []
                for name in reversed(attempted):
                    try:
                        current = owned.read(name)
                        if current == before[name]:
                            continue
                        if current != changed[name]:
                            unrestored.append(name)
                        elif before[name] is None:
                            owned.unlink(name)
                        else:
                            owned.replace_from(recovery, name)
                    except (OSError, ValueError):
                        unrestored.append(name)
                if unrestored:
                    retain_recovery = True
                    raise ValueError(
                        f"{exc}; rollback incomplete for {sorted(unrestored)}; original artifacts retained at {recovery_path}"
                    ) from exc
                raise
    finally:
        if recovery is not None and not retain_recovery:
            with bound_directory(recovery_path, parent) as cleanup:
                if cleanup.identity != recovery.identity:
                    raise ValueError(
                        f"recovery directory was replaced: {recovery_path}"
                    )
                cleanup.clear()
            remove_directory(parent, recovery)


def run(
    command: list[str], cwd: Path | None = None, descriptor: int | None = None
) -> tuple[int, str]:
    """Run one bounded subprocess and return its exit code and combined output."""
    try:
        pass_fds: tuple[int, ...] = ()
        if descriptor is not None:
            bootstrap = (
                "import os,sys; descriptor=int(sys.argv[1]); os.fchdir(descriptor); "
                "os.close(descriptor); os.execvp(sys.argv[2], sys.argv[2:])"
            )
            command = [
                sys.executable,
                "-B",
                "-S",
                "-c",
                bootstrap,
                str(descriptor),
                *command,
            ]
            pass_fds = (descriptor,)
            cwd = None
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=TIMEOUT_SECONDS,
            cwd=cwd,
            pass_fds=pass_fds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    return result.returncode, f"{result.stdout}{result.stderr}".strip()


def rebuild(
    args: argparse.Namespace,
    package: Path,
    tmforge: list[str] | None,
    results: list[dict[str, object]],
    failed: str | None,
    directory: BoundDirectory | None = None,
    model_steps: bool = True,
) -> dict[str, object]:
    ledger = package / args.ledger
    model = package / args.model
    manifest = package / args.manifest
    steps: list[tuple[str, list[str] | None, Path | None]] = []

    if args.manifest_command:
        steps.append(("manifest", shlex.split(args.manifest_command), package))

    validate = [sys.executable, str(SCRIPTS / "validate_analysis.py"), ledger.name]
    if args.baseline is not None:
        validate += ["--baseline", str(args.baseline.resolve())]
    steps.append(("ledger", validate, package))

    if model_steps and tmforge is not None:
        steps.append(
            ("apply", [*tmforge, "apply", manifest.name, "--out", model.name], package)
        )
    steps.append(
        (
            "layout",
            (
                [
                    sys.executable,
                    str(SCRIPTS / "check_layout.py"),
                    model.name,
                    "--analysis",
                    ledger.name,
                ]
                if model_steps
                else None
            ),
            package,
        )
    )
    if args.justifications is not None:
        suppressions = [
            sys.executable,
            str(SCRIPTS / "generate_suppressions.py"),
            model.name,
            str(args.justifications.resolve()),
            "--out",
            f"{model.stem}.tm.suppressions.json",
            "--verify",
        ]
        if tmforge is not None:
            suppressions += ["--tmforge", shlex.join(tmforge)]
        steps.append(("suppressions", suppressions if model_steps else None, package))
    steps.append(
        (
            "render",
            [
                sys.executable,
                str(SCRIPTS / "render_analysis.py"),
                ledger.name,
                "--output-dir",
                ".",
            ],
            package,
        )
    )
    verify = [
        sys.executable,
        str(SCRIPTS / "validate_package.py"),
        ".",
        "--json",
    ]
    if tmforge is not None:
        verify += ["--tmforge", shlex.join(tmforge)]
    steps.append(("package", verify, package))

    for name, command, cwd in steps:
        if command is None:
            results.append({"step": name, "status": "skipped"})
            continue
        if failed is not None:
            results.append({"step": name, "status": "not-run"})
            continue
        if directory is not None:
            directory.check_identity()
        if name in {"apply", "layout", "suppressions"}:
            input_name = manifest.name if name == "apply" else model.name
            content = (
                directory.read(input_name)
                if directory is not None
                else artifact_bytes(package / input_name)
            )
            if content is None:
                option = "--manifest" if name == "apply" else "--model"
                results.append(
                    {
                        "step": name,
                        "status": "fail",
                        "detail": f"Required input {input_name!r} is missing; check {option} "
                        "or the preceding generation step. No outputs were promoted.",
                    }
                )
                failed = name
                continue
        manifest_before = None
        ledger_before = None
        if name == "manifest":
            ledger_before = (
                directory.read(ledger.name)
                if directory is not None
                else artifact_bytes(ledger)
            )
            manifest_before = (
                directory.read(manifest.name)
                if directory is not None
                else artifact_bytes(manifest)
            )
        code, output = (
            run(command, cwd, descriptor=directory.descriptor)
            if directory is not None
            else run(command, cwd)
        )
        entry: dict[str, object] = {"step": name}
        if name == "manifest" and code == 0:
            manifest_after = (
                directory.read(manifest.name)
                if directory is not None
                else artifact_bytes(manifest)
            )
            entry["cwd"] = str(package)
            entry["beforeSha256"] = (
                hashlib.sha256(manifest_before).hexdigest()
                if manifest_before is not None
                else None
            )
            entry["afterSha256"] = (
                hashlib.sha256(manifest_after).hexdigest()
                if manifest_after is not None
                else None
            )
            if manifest_after is None:
                code, output = (
                    1,
                    f"Manifest command did not produce {manifest.name!r} in candidate cwd {package}. Use candidate-relative output paths.",
                )
            elif manifest_before == manifest_after:
                entry["changed"] = False
                if not args.allow_unchanged_manifest:
                    code, output = 1, (
                        f"Manifest command left {manifest.name!r} unchanged in candidate cwd {package}. "
                        "Check its output path; use --allow-unchanged-manifest only for an intentional no-op rebuild."
                    )
            else:
                entry["changed"] = True
            ledger_after = (
                directory.read(ledger.name)
                if directory is not None
                else artifact_bytes(ledger)
            )
            if ledger_after != ledger_before:
                code, output = 1, (
                    f"Manifest command changed staged ledger {ledger.name!r}. "
                    "Regenerate the ledger before invoking rebuild_package.py; manifest generation may only consume it."
                )
        status = "pass" if code == 0 else "fail"
        entry["status"] = status
        if status == "fail":
            entry["detail"] = output[-2000:]
            failed = name
        results.append(entry)

    return {
        "valid": failed is None,
        "package": str(package),
        "failedStep": failed,
        "steps": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path, help="package directory")
    parser.add_argument("--ledger", default="analysis.json", help="ledger file name")
    parser.add_argument("--model", help="model file name (default: model.tm7)")
    parser.add_argument(
        "--manifest", help="manifest file name (default: model.tm.json)"
    )
    parser.add_argument(
        "--manifest-command",
        help="argv command run in candidate cwd; update the staged manifest using relative package paths, not the ledger; skipped if absent",
    )
    parser.add_argument(
        "--allow-unchanged-manifest",
        action="store_true",
        help="explicitly allow byte-identical manifest-command output for an intentional no-op rebuild",
    )
    parser.add_argument(
        "--justifications",
        type=Path,
        help="justification map for the suppressions step",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        help="previous ledger revision for the id-stability gate",
    )
    parser.add_argument(
        "--tmforge", help="tmforge invocation, default resolves on PATH"
    )
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    args = parser.parse_args()
    if args.allow_unchanged_manifest and args.manifest_command is None:
        parser.error("--allow-unchanged-manifest requires --manifest-command")
    args.model_requested = args.model is not None or args.manifest is not None
    if args.model is None:
        args.model = "model.tm7"
    if args.manifest is None:
        args.manifest = "model.tm.json"

    package = args.package.absolute()
    for name in (args.ledger, args.model, args.manifest):
        if Path(name).name != name or name in {"", ".", ".."}:
            parser.error(
                "--ledger, --model and --manifest must be package-local file names"
            )

    try:
        tmforge = shlex.split(args.tmforge) if args.tmforge is not None else None
        manifest_command = (
            shlex.split(args.manifest_command)
            if args.manifest_command is not None
            else None
        )
    except ValueError as exc:
        parser.error(str(exc))
    if tmforge == [] or manifest_command == []:
        parser.error("--tmforge and --manifest-command must not be empty when supplied")
    if tmforge is None:
        found = shutil.which("tmforge")
        tmforge = [found] if found else None

    try:
        with (
            bound_directory(package.parent) as parent,
            bound_directory(package, parent) as owned,
        ):
            return run_package(args, owned, parent, tmforge)
    except (OSError, ValueError) as exc:
        print(f"ERROR: unsafe or unreadable package directory: {exc}", file=sys.stderr)
        return 2


def run_package(
    args: argparse.Namespace,
    owned: BoundDirectory,
    parent: BoundDirectory,
    tmforge: list[str] | None,
) -> int:
    package = owned.path
    model = package / args.model
    owned.check_identity()
    parent.check_identity()
    results: list[dict[str, object]] = []
    failed: str | None = None
    try:
        ledger = json.loads(owned.read(args.ledger) or b"{}")
    except (ValueError, UnicodeDecodeError):
        ledger = {}
    scope = ledger.get("scope", {}) if isinstance(ledger, dict) else {}
    model_steps = bool(
        owned.read(args.manifest) is not None
        or owned.read(args.model) is not None
        or args.manifest_command
        or args.justifications is not None
        or args.model_requested
        or (
            isinstance(scope, dict)
            and scope.get("mode") in {"formal-package", "update"}
        )
    )
    if model_steps:
        if tmforge is None:
            code, output = (
                1,
                "tmforge is unavailable; provide an approved CLI with --tmforge before rebuilding model artifacts",
            )
        else:
            code, output = run(
                [*tmforge, "--version"], package, descriptor=owned.descriptor
            )
        prerequisite: dict[str, object] = {
            "step": "tmforge",
            "status": "pass" if code == 0 else "fail",
        }
        if code != 0:
            prerequisite["detail"] = (
                output[-2000:] or "tmforge availability check failed"
            )
            failed = "tmforge"
        results.append(prerequisite)

    if failed is not None:
        report = rebuild(
            args, package, tmforge, results, failed, model_steps=model_steps
        )
    else:
        outputs = (
            args.ledger,
            args.manifest,
            args.model,
            f"{model.stem}.tm.suppressions.json",
            "data-flow.md",
            "threat-model.md",
        )
        try:
            with (
                package_lock(package, parent),
                temporary_directory(
                    parent, prefix=f".{package.name}.rebuild-"
                ) as candidate,
            ):
                copy_tree(owned, candidate)
                before = {name: candidate.read(name) for name in outputs}
                report = rebuild(
                    args,
                    candidate.path,
                    tmforge,
                    results,
                    None,
                    directory=candidate,
                    model_steps=model_steps,
                )
                if report["valid"]:
                    owned.check_identity()
                    parent.check_identity()
                    candidate.check_identity()
                    promote_outputs(
                        package,
                        candidate.path,
                        before,
                        owned=owned,
                        staged=candidate,
                        parent=parent,
                    )
        except (OSError, ValueError, KeyboardInterrupt) as exc:
            results.append(
                {
                    "step": "candidate",
                    "status": "fail",
                    "detail": str(exc) or "rebuild interrupted",
                }
            )
            report = {"valid": False, "failedStep": "candidate", "steps": results}
        report["package"] = str(package)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for entry in results:
            print(f"{entry['status']:>8}  {entry['step']}")
            if entry.get("detail"):
                print(entry["detail"], file=sys.stderr)
        print("VALID" if report["valid"] else f"FAILED at {report['failedStep']}")
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
