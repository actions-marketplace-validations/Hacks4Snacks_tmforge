#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable, Iterable, Iterator
from contextlib import ExitStack, contextmanager
from functools import partial
from pathlib import Path
from typing import BinaryIO

from windows_permissions import windows_directory_handle

TIMEOUT_SECONDS = 300

# `tmforge analyze` names the flagged object either inside brackets after a short kind
# label, or inline after "The". Both forms end with the stable `ID=<guid>` descriptor.
TARGET = re.compile(
    r"^(?P<model>.+?): (?:[A-Za-z ]*\[(?P<bracketed>[^\[\]]*?ID=[0-9a-fA-F-]{36})\s*\]"
    r"|The (?P<plain>.*?ID=[0-9a-fA-F-]{36}))"
)
HEAD = re.compile(
    r"^(?P<file>.+?): \w+ (?P<rule>TM\d+): ",
)
# Aliases are the ledger ids rendered into the element name by the manifest.
NAMED = re.compile(
    r"^(?:DS|TB|P|F|X|A)\d+(?::\s*|\s+)(?P<name>.+) "
    r"\([^()\r\n]+\) ID=[0-9a-fA-F-]{36}$"
)


def parse_findings(text: str) -> list[dict[str, str]]:
    """Return every analyzer finding as ``{rule, model, target}``."""
    findings: list[dict[str, str]] = []
    for line in text.splitlines():
        head = HEAD.match(line)
        if head is None:
            continue
        target = TARGET.match(line[head.end() :])
        if target is None:
            raise ValueError(f"unparsed analyzer diagnostic: {line}")
        descriptor = target.group("bracketed") or target.group("plain")
        findings.append(
            {
                "rule": head.group("rule"),
                # `model` names the drawing surface, not the file. Using the path here
                # makes tmforge skip the suppression with a TM0001 warning.
                "model": target.group("model"),
                "target": descriptor.strip(),
            }
        )
    return findings


def target_name(descriptor: str) -> str | None:
    """Return the stable element name inside an analyzer target descriptor."""
    matched = NAMED.match(descriptor)
    return None if matched is None else matched.group("name")


def build_document(
    findings: list[dict[str, str]],
    justifications: dict[str, dict[str, str]],
    model_name: str,
) -> tuple[dict[str, object], list[str]]:
    """Return the sidecar document and every finding left unjustified."""
    suppressions: list[dict[str, str]] = []
    missing: list[str] = []
    for finding in findings:
        name = target_name(finding["target"])
        if name is None:
            missing.append(
                f"{finding['rule']}: target name must start with a diagram ID "
                f"('ID: Name' or 'ID Name'): {finding['target']!r}"
            )
            continue
        text = justifications.get(finding["rule"], {}).get(name)
        if not text:
            missing.append(f"{finding['rule']} on {name!r}")
            continue
        suppressions.append(
            {
                "rule": finding["rule"],
                "model": finding["model"],
                "target": finding["target"],
                "justification": text,
            }
        )
    suppressions.sort(key=lambda item: (item["rule"], item["target"]))
    # tmforge resolves `file` relative to the directory holding the suppression file,
    # so the sidecar must sit beside the model and name it without a path.
    document = {"files": [{"file": model_name, "suppressions": suppressions}]}
    return document, sorted(set(missing))


def run_analyze(
    invocation: list[str], model: Path, sidecar: Path | None
) -> tuple[str, str | None]:
    """Run ``tmforge analyze`` from the model directory and return its output."""
    command = [*invocation, "analyze", model.name]
    if sidecar is not None:
        command += ["--suppressionFile", sidecar.name]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=TIMEOUT_SECONDS,
            cwd=model.parent,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "", str(exc)
    # Exit code 2 reports findings rather than a tool failure.
    if result.returncode not in {0, 2}:
        detail = (result.stderr or result.stdout or "no output").strip()
        return "", f"exit {result.returncode}: {detail[:1000]}"
    return f"{result.stdout}\n{result.stderr}", None


def resolve_invocation(raw: str | None) -> list[str] | None:
    """Return the tmforge invocation, or None when it cannot be located."""
    if raw is not None:
        command = shlex.split(raw)
        if not command:
            raise ValueError("--tmforge must not be empty")
        return command
    found = shutil.which("tmforge")
    return [found] if found else None


def verify_sidecar(invocation: list[str], model: Path, sidecar: Path) -> int:
    verify_text, failure = run_analyze(invocation, model, sidecar)
    if failure is not None:
        print(f"ERROR: verification run failed: {failure}", file=sys.stderr)
        return 2
    try:
        remaining = parse_findings(verify_text)
    except ValueError as exc:
        print(f"ERROR: verification failed: {exc}", file=sys.stderr)
        return 2
    skipped = "TM0001" in verify_text
    for finding in remaining:
        print(
            f"ERROR: unanswered after suppression: {finding['rule']} {finding['target']}",
            file=sys.stderr,
        )
    if skipped:
        print(
            "ERROR: tmforge skipped a suppression (TM0001); check that model "
            "names the drawing surface and file names the model",
            file=sys.stderr,
        )
    return 1 if remaining or skipped else 0


def require_distinct_output(output: Path, inputs: Iterable[Path | None]) -> None:
    """Reject outputs that name an input, including existing file aliases."""
    destination = output.resolve()
    for source in inputs:
        if source is not None and (
            destination == source.resolve()
            or (output.exists() and source.exists() and output.samefile(source))
        ):
            raise ValueError(f"output must be distinct from input: {source}")


def validate_output_entry(info: os.stat_result, directory: bool = False) -> None:
    reparse = getattr(info, "st_file_attributes", 0) & getattr(
        stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0
    )
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if reparse or not expected_type(info.st_mode):
        raise ValueError(
            "output paths must use regular files and directories, not symlinks or reparse points"
        )


def system_path(path: Path) -> Path:
    """Expand only macOS's root-owned temporary-directory aliases, not user links."""
    absolute = path.absolute()
    if sys.platform == "darwin" and absolute.parts[1:2] in (("var",), ("tmp",)):
        alias = Path(absolute.anchor) / absolute.parts[1]
        expected = Path("/private") / alias.name
        info = alias.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            and info.st_uid == 0
            and alias.parent / os.readlink(alias) == expected
        ):
            return expected.joinpath(*absolute.parts[2:])
    return absolute


@contextmanager
def output_directory(path: Path, create: bool = False) -> Iterator[int | None]:
    absolute = system_path(path)
    descriptor = None
    handles = ExitStack()
    try:
        if os.name == "posix":
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            descriptor = os.open(absolute.anchor, flags)
            for name in absolute.parts[1:]:
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
                validate_output_entry(info, directory=True)
                child = os.open(name, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                validate_output_entry(os.fstat(descriptor), directory=True)
        else:
            for parent in [*reversed(absolute.parents), absolute]:
                try:
                    info = parent.lstat()
                except FileNotFoundError:
                    if not create:
                        raise
                    parent.mkdir(mode=0o700, exist_ok=True)
                    info = parent.lstat()
                handles.enter_context(windows_directory_handle(parent))
                validate_output_entry(info, directory=True)
        yield descriptor
    finally:
        if descriptor is not None:
            os.close(descriptor)
        handles.close()


@contextmanager
def artifact_stream(path: Path) -> Iterator[BinaryIO]:
    """Open a regular artifact through its original, no-follow parent path."""
    with output_directory(path.parent) as directory:
        location = path.name if directory is not None else path
        info = os.stat(location, dir_fd=directory, follow_symlinks=False)
        validate_output_entry(info)
        flags = (
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(location, flags, dir_fd=directory)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            validate_output_entry(opened)
            if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError(f"artifact changed while opening: {path}")
            yield stream


def write_sidecar(
    path: Path,
    document: dict[str, object],
    verify: Callable[[Path], int] | None = None,
) -> int:
    destination = path.absolute()
    with output_directory(destination.parent) as directory:
        location = destination.name if directory is not None else destination
        try:
            info = os.stat(location, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            validate_output_entry(info)
        name = f".{path.name}.{secrets.token_hex(16)}.tmp.json"
        temporary = name if directory is not None else destination.parent / name
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                output.write(json.dumps(document, indent=2) + "\n")
            if verify is not None:
                code = verify(destination.parent / name)
                if code != 0:
                    return code
            os.replace(temporary, location, src_dir_fd=directory, dst_dir_fd=directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
    return 0


def run_self_test() -> int:
    """Prove both analyzer line shapes parse and an unjustified finding fails."""
    sample = (
        "model.tm7: Warning TM1014: Diagram 1: Data store "
        "[DS1: Snapshot volume (Generic Data Store) "
        "ID=ba30dd09-8f8f-5d2e-aa29-fb85377fb829] stores sensitive data.\n"
        "model.tm7: Warning TM1025: Diagram 1: The DS2: Key Secret "
        "(Generic Data Store) ID=cb30dd09-8f8f-5d2e-aa29-fb85377fb830  declares the "
        "encryption algorithm 'secretbox'.\n"
        "model.tm7: note: unrelated line without a target\n"
    )
    findings = parse_findings(sample)
    assert len(findings) == 2, findings
    assert [item["rule"] for item in findings] == ["TM1014", "TM1025"], findings
    assert all(item["model"] == "Diagram 1" for item in findings), findings
    names = [target_name(item["target"]) for item in findings]
    assert names == ["Snapshot volume", "Key Secret"], names

    document, missing = build_document(findings, {}, "model.tm7")
    assert missing == ["TM1014 on 'Snapshot volume'", "TM1025 on 'Key Secret'"], missing

    unnamed = [{"rule": "TM1014", "model": "Diagram 1", "target": "no alias prefix"}]
    document, missing = build_document(unnamed, {}, "model.tm7")
    assert (
        len(missing) == 1 and "target name must start with a diagram ID" in missing[0]
    ), missing

    justifications = {
        "TM1014": {"Snapshot volume": "Accurate and intended finding."},
        "TM1025": {"Key Secret": "Evidenced posture."},
    }
    document, missing = build_document(findings, justifications, "model.tm7")
    assert missing == [], missing
    entry = document["files"][0]
    assert entry["file"] == "model.tm7", entry
    assert len(entry["suppressions"]) == 2, entry
    assert entry["suppressions"][0]["model"] == "Diagram 1", entry

    print("OK: suppression generator self-test passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model", nargs="?", type=Path, help="path to the .tm7 model")
    parser.add_argument(
        "justifications", nargs="?", type=Path, help="justification map JSON"
    )
    parser.add_argument("--out", type=Path, help="sidecar path; defaults beside model")
    parser.add_argument(
        "--analyzer-output",
        type=Path,
        help="use saved analyzer text instead of running tmforge",
    )
    parser.add_argument(
        "--tmforge", help="tmforge invocation, default resolves on PATH"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="re-run the analyzer with the sidecar and require nothing unanswered",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()
    if args.model is None or args.justifications is None:
        parser.error("model and justifications are required unless --self-test is used")
    if not args.model.is_file():
        print(f"ERROR: no such model: {args.model}", file=sys.stderr)
        return 2

    sidecar = args.out or args.model.with_suffix(".tm.suppressions.json")
    try:
        require_distinct_output(
            sidecar, (args.model, args.justifications, args.analyzer_output)
        )
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    try:
        justifications = json.loads(args.justifications.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {args.justifications}: {exc}", file=sys.stderr)
        return 2
    if not isinstance(justifications, dict):
        print("ERROR: justifications must be a JSON object", file=sys.stderr)
        return 2

    try:
        invocation = resolve_invocation(args.tmforge)
    except ValueError as exc:
        parser.error(str(exc))
    if args.verify and invocation is None:
        print("ERROR: --verify requires tmforge", file=sys.stderr)
        return 2
    if args.analyzer_output is not None:
        text = args.analyzer_output.read_text(encoding="utf-8")
    elif invocation is None:
        print(
            "ERROR: tmforge not found; pass --tmforge or --analyzer-output",
            file=sys.stderr,
        )
        return 2
    else:
        text, failure = run_analyze(invocation, args.model, None)
        if failure is not None:
            print(f"ERROR: tmforge analyze failed: {failure}", file=sys.stderr)
            return 2

    try:
        findings = parse_findings(text)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    document, missing = build_document(findings, justifications, args.model.name)
    if missing:
        for item in missing:
            print(f"ERROR: no justification for {item}", file=sys.stderr)
        print(f"INCOMPLETE: {len(missing)} unjustified finding(s)", file=sys.stderr)
        return 1

    if sidecar.parent.resolve() != args.model.parent.resolve():
        print(
            "ERROR: sidecar must sit beside the model, because tmforge resolves its "
            "file field relative to the suppression file's own directory",
            file=sys.stderr,
        )
        return 2
    try:
        verification = (
            partial(verify_sidecar, invocation, args.model)
            if args.verify and invocation is not None
            else None
        )
        code = write_sidecar(sidecar, document, verification)
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot write sidecar: {exc}", file=sys.stderr)
        return 2
    if code != 0:
        return code

    report: dict[str, object] = {
        "valid": True,
        "model": str(args.model),
        "sidecar": str(sidecar),
        "findings": len(findings),
        "suppressions": len(document["files"][0]["suppressions"]),
    }

    if args.verify:
        report["verified"] = True

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
