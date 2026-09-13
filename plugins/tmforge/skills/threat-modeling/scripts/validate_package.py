#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import cast
from urllib.parse import unquote

import check_layout
from render_analysis import (
    DOCUMENT_NAMES,
    compare_documents,
    render_documents,
    write_documents,
)
from validate_analysis import (
    JsonObject,
    as_object,
    as_object_list,
    load_document,
    validate_document,
)

Check = dict[str, object]
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def make_check(name: str, status: str, detail: str, **data: object) -> Check:
    """Create one stable machine-readable check result."""
    result: Check = {"name": name, "status": status, "detail": detail}
    result.update(data)
    return result


def resolve_package(path: Path) -> tuple[Path, Path]:
    """Resolve a package directory and its canonical ledger."""
    if path.is_dir():
        return path, path / "analysis.json"
    return path.parent, path


def file_sha256(path: Path) -> str:
    """Return a lowercase SHA-256 digest for one file."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def package_relative(path: Path, package_directory: Path) -> str:
    """Return a stable package-relative path when possible."""
    try:
        return path.resolve().relative_to(package_directory.resolve()).as_posix()
    except ValueError:
        return str(path)


def markdown_errors(path: Path, package_directory: Path) -> list[str]:
    """Validate dependency-free Markdown, Mermaid, and local-link structure."""
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"cannot read {path}: {exc}"]

    errors: list[str] = []
    fence_language: str | None = None
    fence_line = 0
    fence_content: list[str] = []
    mermaid_blocks: list[tuple[int, list[str]]] = []
    heading_count = 0

    for line_number, line in enumerate(content.splitlines(), start=1):
        if line.startswith("# "):
            heading_count += 1
        if not line.startswith("```"):
            if fence_language is not None:
                fence_content.append(line)
            continue
        marker = line[3:].strip()
        if fence_language is None:
            fence_language = marker
            fence_line = line_number
            fence_content = []
        else:
            if marker:
                errors.append(
                    f"line {line_number}: closing code fence must not name a language"
                )
            if fence_language == "mermaid":
                mermaid_blocks.append((fence_line, list(fence_content)))
            fence_language = None
            fence_content = []

    if fence_language is not None:
        errors.append(f"line {fence_line}: unclosed {fence_language or 'code'} fence")
    if heading_count != 1:
        errors.append(f"expected exactly one level-1 heading, found {heading_count}")

    package_root = package_directory.resolve()
    for raw_destination in LINK_RE.findall(content):
        destination = raw_destination.strip().split(maxsplit=1)[0].strip("<>")
        if not destination or destination.startswith(
            ("#", "http://", "https://", "mailto:")
        ):
            continue
        local_path = unquote(destination.split("#", maxsplit=1)[0])
        target = (path.parent / local_path).resolve()
        try:
            target.relative_to(package_root)
        except ValueError:
            errors.append(f"local link escapes package: {destination}")
            continue
        if not target.exists():
            errors.append(f"broken local link: {destination}")

    for line_number, block in mermaid_blocks:
        material = [line.strip() for line in block if line.strip()]
        if not material:
            errors.append(f"line {line_number}: empty Mermaid block")
            continue
        directive = material[0]
        if directive != "sequenceDiagram" and not directive.startswith("flowchart "):
            errors.append(
                f"line {line_number}: unsupported Mermaid directive {directive!r}"
            )
        if directive.startswith("flowchart "):
            subgraphs = sum(1 for line in material[1:] if line.startswith("subgraph "))
            ends = sum(1 for line in material[1:] if line == "end")
            if subgraphs != ends:
                errors.append(
                    f"line {line_number}: Mermaid subgraph/end mismatch "
                    f"({subgraphs} != {ends})"
                )
    return errors


def get_case_insensitive(mapping: JsonObject, name: str) -> object:
    """Read a JSON member without depending on serializer casing."""
    lowered = name.lower()
    for key, value in mapping.items():
        if key.lower() == lowered:
            return value
    return None


def data_object(stdout: str) -> JsonObject:
    """Parse one tmforge JSON envelope and return its data object."""
    value: object = json.loads(stdout)
    root = as_object(value)
    if root is None:
        raise ValueError("JSON output is not an object")
    data = as_object(get_case_insensitive(root, "data"))
    if data is None:
        raise ValueError("JSON output has no data object")
    return data


def run_process(
    command: list[str], allowed_exit_codes: set[int], timeout: int
) -> tuple[str | None, str | None]:
    """Run one bounded subprocess and return stdout or a concise error."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)
    if result.returncode not in allowed_exit_codes:
        detail = (result.stderr or result.stdout or "no output").strip()
        return None, f"exit {result.returncode}: {detail[:1000]}"
    return result.stdout, None


def normalize_guid(value: object) -> str | None:
    """Normalize a populated GUID-like JSON value."""
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if not normalized or normalized == "00000000-0000-0000-0000-000000000000":
        return None
    return normalized


def object_ids(data: JsonObject, collection_name: str = "items") -> set[str]:
    """Extract normalized object IDs from a tmforge data collection."""
    items = as_object_list(get_case_insensitive(data, collection_name)) or []
    return {
        normalized
        for item in items
        if (normalized := normalize_guid(get_case_insensitive(item, "id"))) is not None
    }


def tmforge_model_checks(
    model: Path,
    package_directory: Path,
    invocation: list[str],
    timeout: int,
) -> list[Check]:
    """Run the required read-only tmforge checks for one model artifact."""
    relative_model = package_relative(model, package_directory)
    commands: tuple[tuple[str, list[str], set[int], bool], ...] = (
        ("open", ["open", str(model), "--json"], {0}, True),
        ("boundaries", ["list", "boundaries", str(model), "--json"], {0}, True),
        ("components", ["list", "components", str(model), "--json"], {0}, True),
        ("flows", ["list", "flows", str(model), "--json"], {0}, True),
        ("diagrams", ["list", "diagrams", str(model), "--json"], {0}, True),
        ("render", ["render", str(model), "--plain"], {0}, False),
        ("analyze", ["analyze", str(model), "--json"], {0, 2}, True),
        ("generated-threats", ["threats", str(model), "--json"], {0, 2}, True),
        ("persisted-threats", ["list", "threats", str(model), "--json"], {0}, True),
    )
    checks: list[Check] = []
    outputs: dict[str, JsonObject] = {}
    for name, arguments, allowed_codes, expects_json in commands:
        stdout, failure = run_process(invocation + arguments, allowed_codes, timeout)
        check_name = f"tmforge.{relative_model}.{name}"
        if failure is not None:
            checks.append(make_check(check_name, "fail", failure))
            continue
        if expects_json:
            try:
                outputs[name] = data_object(stdout or "")
            except (ValueError, json.JSONDecodeError) as exc:
                checks.append(make_check(check_name, "fail", f"invalid JSON: {exc}"))
                continue
        checks.append(make_check(check_name, "pass", "command completed"))

    flow_data = outputs.get("flows")
    diagram_data = outputs.get("diagrams")
    persisted_data = outputs.get("persisted-threats")
    if (
        flow_data is not None
        and diagram_data is not None
        and persisted_data is not None
    ):
        flow_ids = object_ids(flow_data)
        diagram_ids = object_ids(diagram_data)
        persisted = as_object_list(get_case_insensitive(persisted_data, "items")) or []
        stale: list[str] = []
        for threat in persisted:
            threat_id = text_value(get_case_insensitive(threat, "id"), "unknown")
            flow_guid = normalize_guid(get_case_insensitive(threat, "flowGuid"))
            diagram_guid = normalize_guid(get_case_insensitive(threat, "diagramGuid"))
            if flow_guid is not None and flow_guid not in flow_ids:
                stale.append(f"{threat_id}: missing flow {flow_guid}")
            if diagram_guid is not None and diagram_guid not in diagram_ids:
                stale.append(f"{threat_id}: missing diagram {diagram_guid}")
        checks.append(
            make_check(
                f"tmforge.{relative_model}.stale-register",
                "fail" if stale else "pass",
                "; ".join(stale) if stale else "persisted references resolve",
                staleEntries=stale,
            )
        )

    generated_data = outputs.get("generated-threats")
    if generated_data is not None and persisted_data is not None:
        generated = (
            as_object_list(get_case_insensitive(generated_data, "threats")) or []
        )
        persisted = as_object_list(get_case_insensitive(persisted_data, "items")) or []
        checks.append(
            make_check(
                f"tmforge.{relative_model}.threat-sets",
                "pass",
                "generated and persisted threat sets are readable",
                generatedCount=len(generated),
                persistedCount=len(persisted),
            )
        )
    return checks


def text_value(value: object, default: str) -> str:
    """Return a non-empty scalar string for diagnostics."""
    if value is None:
        return default
    rendered = str(value).strip()
    return rendered or default


def verify_candidate_final(candidate: Path | None, final: Path | None) -> Check:
    """Verify explicit candidate/final byte equivalence."""
    if candidate is None and final is None:
        return make_check(
            "candidate-final.equivalence",
            "skipped",
            "no candidate/final pair supplied",
        )
    if candidate is None or final is None:
        return make_check(
            "candidate-final.equivalence",
            "fail",
            "--candidate and --final must be supplied together",
        )
    missing = [str(path) for path in (candidate, final) if not path.is_file()]
    if missing:
        return make_check(
            "candidate-final.equivalence",
            "fail",
            f"missing file(s): {', '.join(missing)}",
        )
    candidate_digest = file_sha256(candidate)
    final_digest = file_sha256(final)
    return make_check(
        "candidate-final.equivalence",
        "pass" if candidate_digest == final_digest else "fail",
        (
            "candidate and final bytes match"
            if candidate_digest == final_digest
            else "candidate and final bytes differ"
        ),
        candidateSha256=candidate_digest,
        finalSha256=final_digest,
    )


def inventory(document: JsonObject) -> dict[str, int]:
    """Return canonical package counts from the ledger."""
    names = (
        "evidence",
        "boundaries",
        "elements",
        "flows",
        "assets",
        "threatActors",
        "coverage",
        "threats",
        "assumptions",
    )
    return {name: len(as_object_list(document.get(name)) or []) for name in names}


def layout_check(model: Path, ledger_path: Path | None) -> Check:
    """Fail when the diagram misplaces a shape, warn when it is hard to read.

    Boundary containment is a trust claim readers act on, so an element drawn outside its
    boundary or overlapping one it does not belong to is a defect, not a cosmetic issue.
    Crossings and single-column stacking only degrade legibility, so they warn.
    """
    name = f"layout.{model.name}"
    try:
        report = check_layout.check(model, ledger_path)
    except ET.ParseError as exc:
        # Model validity is already asserted by the tmforge open check; this check has an
        # opinion only when there is a readable diagram to have an opinion about.
        return make_check(
            name, "skipped", f"diagram geometry is not readable XML: {exc}"
        )
    except Exception as exc:  # noqa: BLE001 - surface any other parse failure
        return make_check(name, "fail", f"could not read diagram geometry: {exc}")

    if not report["elements"] and not report["boundaries"]:
        return make_check(name, "skipped", "diagram contains no positioned shapes")

    canvas = cast(JsonObject, report["canvas"])
    detail = (
        f"{report['elements']} elements in {report['boundaries']} boundaries across "
        f"{report['columns']} column(s), {report['crossings']} crossing(s), canvas "
        f"{canvas['width']}x{canvas['height']}"
    )
    failures = cast(list[str], report["failures"])
    warnings = cast(list[str], report["warnings"])
    if failures:
        return make_check(name, "fail", "; ".join(failures), **report)
    if warnings:
        return make_check(name, "warning", "; ".join(warnings), **report)
    return make_check(name, "pass", detail, **report)


def verify_package(
    path: Path,
    tmforge_invocation: list[str] | None = None,
    candidate: Path | None = None,
    final: Path | None = None,
    timeout: int = 60,
) -> JsonObject:
    """Run every available deterministic package check."""
    package_directory, ledger_path = resolve_package(path)
    checks: list[Check] = []
    document: JsonObject | None = None

    if not ledger_path.is_file():
        checks.append(
            make_check(
                "ledger.exists", "fail", f"missing canonical ledger: {ledger_path}"
            )
        )
    else:
        checks.append(make_check("ledger.exists", "pass", str(ledger_path)))
        try:
            document = load_document(ledger_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            checks.append(make_check("ledger.contract", "fail", str(exc)))
        else:
            errors = validate_document(document)
            checks.append(
                make_check(
                    "ledger.contract",
                    "fail" if errors else "pass",
                    "; ".join(errors) if errors else "canonical contract satisfied",
                    errors=errors,
                )
            )

    if document is not None and not validate_document(document):
        expected = render_documents(document, ledger_path.name)
        parity_failures = compare_documents(expected, package_directory)
        checks.append(
            make_check(
                "documents.parity",
                "fail" if parity_failures else "pass",
                (
                    "; ".join(parity_failures)
                    if parity_failures
                    else "generated documents match canonical bytes"
                ),
                errors=parity_failures,
            )
        )
        for name in DOCUMENT_NAMES:
            document_path = package_directory / name
            errors = markdown_errors(document_path, package_directory)
            checks.append(
                make_check(
                    f"documents.{name}.structure",
                    "fail" if errors else "pass",
                    (
                        "; ".join(errors)
                        if errors
                        else "Markdown and Mermaid structure valid"
                    ),
                    errors=errors,
                )
            )
        checks.append(
            make_check(
                "identifiers-and-counts",
                "pass",
                "rendered artifacts derive identifiers and counts from the canonical ledger",
                inventory=inventory(document),
            )
        )
    else:
        checks.append(
            make_check(
                "documents.parity",
                "skipped",
                "ledger contract must pass before rendering checks",
            )
        )

    model_paths = (
        sorted(package_directory.rglob("*.tm7")) if package_directory.is_dir() else []
    )
    scope = as_object(document.get("scope")) if document is not None else None
    mode = scope.get("mode") if scope is not None else None
    if model_paths:
        invocation = tmforge_invocation
        if invocation is None:
            executable = shutil.which("tmforge")
            invocation = [executable] if executable else None
        if invocation is None:
            checks.append(
                make_check(
                    "tmforge.available",
                    "fail",
                    "package contains .tm7 artifacts but tmforge is unavailable",
                )
            )
        else:
            stdout, failure = run_process(invocation + ["--version"], {0}, timeout)
            if failure is not None:
                checks.append(make_check("tmforge.available", "fail", failure))
            else:
                checks.append(
                    make_check(
                        "tmforge.available",
                        "pass",
                        text_value(stdout, "version command completed"),
                    )
                )
                for model in model_paths:
                    checks.extend(
                        tmforge_model_checks(
                            model, package_directory, invocation, timeout
                        )
                    )
        for model in model_paths:
            checks.append(layout_check(model, ledger_path))
    else:
        checks.append(
            make_check(
                "tmforge.artifacts",
                "fail" if mode in {"formal-package", "update"} else "skipped",
                (
                    f"{mode} package requires a retained .tm7 artifact"
                    if mode in {"formal-package", "update"}
                    else "package contains no .tm7 artifact"
                ),
            )
        )

    checks.append(verify_candidate_final(candidate, final))
    failure_count = sum(check.get("status") == "fail" for check in checks)
    warning_count = sum(check.get("status") == "warning" for check in checks)
    result: JsonObject = {
        "valid": failure_count == 0,
        "package": str(package_directory),
        "ledger": str(ledger_path),
        "failureCount": failure_count,
        "warningCount": warning_count,
        "checks": checks,
    }
    if document is not None:
        result["inventory"] = inventory(document)
    return result


def print_human(result: JsonObject) -> None:
    """Print a concise deterministic verification report."""
    checks = as_object_list(result.get("checks")) or []
    labels = {"pass": "PASS", "fail": "FAIL", "warning": "WARN", "skipped": "SKIP"}
    for check in checks:
        status = str(check.get("status"))
        print(
            f"{labels.get(status, status.upper())} "
            f"{check.get('name')}: {check.get('detail')}"
        )
    verdict = "VALID" if result.get("valid") is True else "INVALID"
    print(f"{verdict}: {result.get('package')}")


def run_self_test() -> int:
    """Exercise valid, stale, malformed, and candidate-equivalence paths."""
    fixture = Path(__file__).resolve().parents[1] / "assets" / "analysis.example.json"
    with tempfile.TemporaryDirectory() as temporary_directory:
        package_directory = Path(temporary_directory) / "package"
        package_directory.mkdir()
        ledger = package_directory / "analysis.json"
        ledger.write_bytes(fixture.read_bytes())
        document = load_document(ledger)
        write_documents(render_documents(document), package_directory)

        missing_tm7 = verify_package(package_directory)
        missing_checks = as_object_list(missing_tm7.get("checks")) or []
        if missing_tm7.get("valid") is not False or not any(
            check.get("name") == "tmforge.artifacts" and check.get("status") == "fail"
            for check in missing_checks
        ):
            raise AssertionError("formal package without .tm7 was accepted")

        model = package_directory / "threat-model.tm7"
        model.write_bytes(b"generated tm7 fixture\n")
        fake_tmforge = Path(temporary_directory) / "fake_tmforge.py"
        fake_tmforge.write_text(
            """import json
import sys

arguments = sys.argv[1:]
if arguments == [\"--version\"]:
    print(\"tmforge self-test\")
elif arguments and arguments[0] == \"render\":
    print(\"diagram\")
elif arguments[:2] == [\"list\", \"threats\"]:
    print(json.dumps({\"data\": {\"items\": []}}))
elif arguments and arguments[0] == \"threats\":
    print(json.dumps({\"data\": {\"threats\": []}}))
else:
    print(json.dumps({\"data\": {\"items\": []}}))
""",
            encoding="utf-8",
        )
        valid = verify_package(
            package_directory,
            tmforge_invocation=[sys.executable, str(fake_tmforge)],
        )
        if valid.get("valid") is not True:
            raise AssertionError(f"valid package was rejected: {valid}")

        threat_model = package_directory / "threat-model.md"
        original = threat_model.read_text(encoding="utf-8")
        threat_model.write_text(original + "stale\n", encoding="utf-8")
        stale = verify_package(package_directory)
        stale_checks = as_object_list(stale.get("checks")) or []
        if stale.get("valid") is not False or not any(
            check.get("name") == "documents.parity" and check.get("status") == "fail"
            for check in stale_checks
        ):
            raise AssertionError("stale generated document was not rejected")
        threat_model.write_text(original, encoding="utf-8")

        malformed = package_directory / "malformed.md"
        malformed.write_text("# Bad\n\n```mermaid\nflowchart LR\n", encoding="utf-8")
        errors = markdown_errors(malformed, package_directory)
        if not any("unclosed" in error for error in errors):
            raise AssertionError("unclosed Mermaid fence was not rejected")

        candidate = Path(temporary_directory) / "candidate.bin"
        final = Path(temporary_directory) / "final.bin"
        candidate.write_bytes(b"same")
        final.write_bytes(b"same")
        if verify_candidate_final(candidate, final).get("status") != "pass":
            raise AssertionError("equal candidate/final files were rejected")
        final.write_bytes(b"different")
        if verify_candidate_final(candidate, final).get("status") != "fail":
            raise AssertionError("different candidate/final files were accepted")

    print("OK: package verifier self-test passed")
    return 0


def main() -> int:
    """Validate a package and emit a human or JSON report."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", nargs="?", type=Path)
    parser.add_argument("--tmforge", help="tmforge executable or wrapper command")
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--final", type=Path)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()
    if args.package is None:
        parser.error("package is required unless --self-test is used")
    if args.timeout < 1:
        parser.error("--timeout must be at least 1 second")

    invocation = shlex.split(args.tmforge) if args.tmforge else None
    if invocation == []:
        parser.error("--tmforge must not be empty")
    result = verify_package(
        args.package,
        tmforge_invocation=invocation,
        candidate=args.candidate,
        final=args.final,
        timeout=args.timeout,
    )
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_human(result)
    return 0 if result.get("valid") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
