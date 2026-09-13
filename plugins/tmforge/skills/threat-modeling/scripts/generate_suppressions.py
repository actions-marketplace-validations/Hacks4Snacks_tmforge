#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

TIMEOUT_SECONDS = 300

# `tmforge analyze` names the flagged object either inside brackets after a short kind
# label, or inline after "The". Both forms end with the stable `ID=<guid>` descriptor.
TARGET = re.compile(
    r"Diagram \d+: (?:[A-Za-z ]*\[(?P<bracketed>[^\[\]]*?ID=[0-9a-fA-F-]{36})\s*\]"
    r"|The (?P<plain>.*?ID=[0-9a-fA-F-]{36}))"
)
HEAD = re.compile(
    r"^(?P<file>\S+): \w+ (?P<rule>TM\d+): (?P<model>Diagram \d+): ",
)
# Aliases are the ledger ids rendered into the element name by the manifest.
NAMED = re.compile(r"^(?:DS|P|F|X|A)\d+: (?P<name>.+?) \(Generic ")


def parse_findings(text: str) -> list[dict[str, str]]:
    """Return every analyzer finding as ``{rule, model, target}``."""
    findings: list[dict[str, str]] = []
    for line in text.splitlines():
        head = HEAD.match(line)
        target = TARGET.search(line)
        if head is None or target is None:
            continue
        descriptor = target.group("bracketed") or target.group("plain")
        findings.append(
            {
                "rule": head.group("rule"),
                # `model` names the drawing surface, not the file. Using the path here
                # makes tmforge skip the suppression with a TM0001 warning.
                "model": head.group("model"),
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
            missing.append(f"{finding['rule']}: unparsed target {finding['target']!r}")
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
    assert missing == ["TM1014: unparsed target 'no alias prefix'"], missing

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

    findings = parse_findings(text)
    document, missing = build_document(findings, justifications, args.model.name)
    if missing:
        for item in missing:
            print(f"ERROR: no justification for {item}", file=sys.stderr)
        print(f"INCOMPLETE: {len(missing)} unjustified finding(s)", file=sys.stderr)
        return 1

    sidecar = args.out or args.model.with_suffix(".tm.suppressions.json")
    if sidecar.parent.resolve() != args.model.parent.resolve():
        print(
            "ERROR: sidecar must sit beside the model, because tmforge resolves its "
            "file field relative to the suppression file's own directory",
            file=sys.stderr,
        )
        return 2
    sidecar.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    report: dict[str, object] = {
        "valid": True,
        "model": str(args.model),
        "sidecar": str(sidecar),
        "findings": len(findings),
        "suppressions": len(document["files"][0]["suppressions"]),
    }

    if args.verify:
        if invocation is None:
            print("ERROR: --verify requires tmforge", file=sys.stderr)
            return 2
        verify_text, failure = run_analyze(invocation, args.model, sidecar)
        if failure is not None:
            print(f"ERROR: verification run failed: {failure}", file=sys.stderr)
            return 2
        remaining = parse_findings(verify_text)
        skipped = "TM0001" in verify_text
        if remaining or skipped:
            for item in remaining:
                print(
                    f"ERROR: unanswered after suppression: {item['rule']} "
                    f"{item['target']}",
                    file=sys.stderr,
                )
            if skipped:
                print(
                    "ERROR: tmforge skipped a suppression (TM0001); check that model "
                    "names the drawing surface and file names the model",
                    file=sys.stderr,
                )
            return 1
        report["verified"] = True

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
