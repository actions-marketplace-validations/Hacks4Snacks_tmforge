#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
TIMEOUT_SECONDS = 1800


def run(command: list[str], cwd: Path | None = None) -> tuple[int, str]:
    """Run one bounded subprocess and return its exit code and combined output."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=TIMEOUT_SECONDS,
            cwd=cwd,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    return result.returncode, f"{result.stdout}{result.stderr}".strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path, help="package directory")
    parser.add_argument("--ledger", default="analysis.json", help="ledger file name")
    parser.add_argument("--model", default="threat-model.tm7", help="model file name")
    parser.add_argument(
        "--manifest", default="threat-model.tm.json", help="manifest file name"
    )
    parser.add_argument(
        "--manifest-command",
        help="command that regenerates the manifest from the ledger; skipped if absent",
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

    package = args.package.resolve()
    if not package.is_dir():
        print(f"ERROR: no such package directory: {package}", file=sys.stderr)
        return 2

    ledger = package / args.ledger
    model = package / args.model
    manifest = package / args.manifest
    try:
        tmforge = shlex.split(args.tmforge) if args.tmforge is not None else None
        manifest_command = shlex.split(args.manifest_command) if args.manifest_command is not None else None
    except ValueError as exc:
        parser.error(str(exc))
    if tmforge == [] or manifest_command == []:
        parser.error("--tmforge and --manifest-command must not be empty when supplied")
    if tmforge is None:
        found = shutil.which("tmforge")
        tmforge = [found] if found else None

    steps: list[tuple[str, list[str] | None, Path | None]] = []

    has_manifest = manifest.is_file() or manifest_command is not None
    if has_manifest and tmforge is None:
        print("ERROR: tmforge not found; pass the approved launcher command with --tmforge", file=sys.stderr)
        return 2
    if manifest_command is not None:
        steps.append(("manifest", manifest_command, package))

    validate = [sys.executable, str(SCRIPTS / "validate_analysis.py"), str(ledger)]
    if args.baseline is not None:
        validate += ["--baseline", str(args.baseline)]
    steps.append(("ledger", validate, None))

    if has_manifest and tmforge is not None:
        steps.append(
            ("apply", [*tmforge, "apply", manifest.name, "--out", model.name], package)
        )
    # Plan checks for outputs created by earlier steps, not just pre-existing files.
    has_model = model.is_file() or has_manifest
    if has_model:
        steps.append(
            (
                "layout",
                [
                    sys.executable,
                    str(SCRIPTS / "check_layout.py"),
                    str(model),
                    "--analysis",
                    str(ledger),
                ],
                None,
            )
        )
    if has_model and args.justifications is not None:
        steps.append(
            (
                "suppressions",
                [
                    sys.executable,
                    str(SCRIPTS / "generate_suppressions.py"),
                    model.name,
                    str(args.justifications.resolve()),
                    "--out",
                    f"{model.stem}.tm.suppressions.json",
                    "--verify",
                    *(["--tmforge", shlex.join(tmforge)] if tmforge is not None else []),
                ],
                package,
            )
        )
    steps.append(
        (
            "render",
            [
                sys.executable,
                str(SCRIPTS / "render_analysis.py"),
                str(ledger),
                "--output-dir",
                str(package),
            ],
            None,
        )
    )
    verify = [
        sys.executable,
        str(SCRIPTS / "validate_package.py"),
        str(package),
        "--json",
    ]
    if tmforge is not None:
        verify += ["--tmforge", shlex.join(tmforge)]
    steps.append(("package", verify, None))

    results: list[dict[str, object]] = []
    failed: str | None = None
    for name, command, cwd in steps:
        if command is None:
            results.append({"step": name, "status": "skipped"})
            continue
        if failed is not None:
            results.append({"step": name, "status": "not-run"})
            continue
        code, output = run(command, cwd)
        status = "pass" if code == 0 else "fail"
        entry: dict[str, object] = {"step": name, "status": status}
        if status == "fail":
            entry["detail"] = output[-2000:]
            failed = name
        results.append(entry)

    report = {
        "valid": failed is None,
        "package": str(package),
        "failedStep": failed,
        "steps": results,
    }
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for entry in results:
            print(f"{entry['status']:>8}  {entry['step']}")
            if entry.get("detail"):
                print(entry["detail"], file=sys.stderr)
        print("VALID" if failed is None else f"FAILED at {failed}")
    return 0 if failed is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
