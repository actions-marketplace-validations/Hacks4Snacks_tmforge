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
from generate_suppressions import artifact_stream
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
    display_id,
    load_document,
    validate_document,
)
from validate_changed_packages import package_files

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
    with artifact_stream(path) as stream:
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
        with artifact_stream(path) as stream:
            content = stream.read().decode("utf-8")
    except (OSError, ValueError) as exc:
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


def native_flow_aliases(
    model: Path, flows: JsonObject, invocation: list[str], timeout: int
) -> tuple[JsonObject, list[str]]:
    """Read stable aliases by native GUID, never infer them from local labels."""
    aliases: JsonObject = {}
    errors: list[str] = []
    items = as_object_list(get_case_insensitive(flows, "items"))
    if items is None:
        return {}, ["native flow inventory is missing or malformed"]
    for flow in items:
        identifier = normalize_guid(get_case_insensitive(flow, "id"))
        if identifier is None:
            errors.append("flow has no native identifier for alias readback")
            continue
        stdout, failure = run_process(
            invocation + ["show", str(model), "--id", identifier, "--json"],
            {0},
            timeout,
        )
        if failure is not None:
            errors.append(f"{identifier}: {failure}")
            continue
        try:
            detail = data_object(stdout or "")
        except ValueError as exc:
            errors.append(f"{identifier}: invalid alias readback: {exc}")
            continue
        properties = as_object(get_case_insensitive(detail, "properties")) or {}
        alias = get_case_insensitive(properties, "Alias")
        if (
            normalize_guid(get_case_insensitive(detail, "id")) != identifier
            or get_case_insensitive(detail, "name")
            != get_case_insensitive(flow, "name")
            or not isinstance(alias, str)
            or not alias.strip()
        ):
            errors.append(f"{identifier}: missing Alias or mismatched native readback")
            continue
        aliases[identifier] = alias
    return aliases, errors


def tmforge_model_checks(
    model: Path,
    package_directory: Path,
    invocation: list[str],
    timeout: int,
    inventories: dict[str, dict[str, JsonObject]] | None = None,
    *,
    flow_display_ids: bool = False,
) -> list[Check]:
    """Run the required read-only tmforge checks for one model artifact."""
    try:
        with artifact_stream(model):
            pass
    except (OSError, ValueError) as exc:
        return [make_check(f"tmforge.{model.name}.path", "fail", str(exc))]
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

    if flow_display_ids:
        aliases, errors = native_flow_aliases(
            model, outputs.get("flows", {}), invocation, timeout
        )
        outputs["flow-aliases"] = aliases
        checks.append(
            make_check(
                f"tmforge.{relative_model}.flow-aliases",
                "fail" if errors else "pass",
                "; ".join(errors) if errors else "stable flow aliases read by GUID",
                errors=errors,
            )
        )
    if inventories is not None:
        inventories[relative_model] = outputs

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


def model_inventory_check(
    document: JsonObject, inventories: dict[str, dict[str, JsonObject]]
) -> Check:
    kinds = {"boundaries": "boundaries", "components": "elements", "flows": "flows"}
    expected = {
        kind: {
            str(item["id"]): item
            for item in as_object_list(document.get(ledger_kind)) or []
        }
        for kind, ledger_kind in kinds.items()
    }
    seen: dict[str, set[str]] = {kind: set() for kind in kinds}
    pages = {
        str(page["id"]): str(page["name"])
        for page in as_object_list(document.get("pages")) or []
    }
    seen_pages: set[str] = set()
    counts = {kind: 0 for kind in kinds}
    errors: list[str] = []
    flow_display_ids = any("displayId" in flow for flow in expected["flows"].values())
    for model, outputs in sorted(inventories.items()):
        collections: dict[str, list[JsonObject]] = {}
        for kind in (*kinds, "diagrams"):
            data = outputs.get(kind, {})
            items = as_object_list(get_case_insensitive(data, "items"))
            count = get_case_insensitive(data, "count")
            if items is None or type(count) is not int or count != len(items):
                errors.append(f"{model}: invalid {kind} inventory or count")
            collections[kind] = items or []
        diagrams = collections["diagrams"]
        headers = [get_case_insensitive(item, "header") for item in diagrams]
        if (
            not diagrams
            or any(not isinstance(header, str) or not header for header in headers)
            or len(set(headers)) != len(headers)
        ):
            errors.append(f"{model}: missing or ambiguous diagram headers")
        if pages:
            for header in headers:
                if header not in pages.values():
                    errors.append(
                        f"{model}: unexpected diagram {header!r}; declare it in ledger pages"
                    )
                elif str(header) in seen_pages:
                    errors.append(f"{model}: duplicate ledger page {header!r}")
                seen_pages.add(str(header))
        component_ids: dict[str, str] = {}
        aliases: dict[str, list[tuple[str, JsonObject]]] = {kind: [] for kind in kinds}
        for kind in kinds:
            counts[kind] += len(collections[kind])
            for item in collections[kind]:
                name = get_case_insensitive(item, "name")
                alias, separator, label = str(name or "").partition(":")
                alias, label = alias.strip(), label.strip()
                label_id = alias
                if kind == "flows" and flow_display_ids:
                    identifier = normalize_guid(get_case_insensitive(item, "id"))
                    alias = str(
                        outputs.get("flow-aliases", {}).get(identifier or "", "")
                    )
                if not separator or alias not in expected[kind]:
                    errors.append(f"{model}: unexpected {kind} alias/name {name!r}")
                else:
                    if alias in seen[kind]:
                        errors.append(f"{model}: duplicate {kind} alias {alias}")
                    if (
                        label != expected[kind][alias].get("name")
                        or label_id != display_id(expected[kind][alias])
                    ):
                        errors.append(f"{model}: {alias} name differs from the ledger")
                    seen[kind].add(alias)
                    if pages:
                        page_owner = expected[kind][alias]
                        if kind == "flows":
                            page_owner = expected["components"].get(
                                str(page_owner.get("sourceId")), {}
                            )
                        expected_header = pages.get(str(page_owner.get("pageId")))
                        if (
                            get_case_insensitive(item, "diagramHeader")
                            != expected_header
                        ):
                            errors.append(
                                f"{model}: {alias} page differs from ledger page {expected_header!r}"
                            )
                identifier = normalize_guid(get_case_insensitive(item, "id"))
                if identifier is None:
                    errors.append(f"{model}: {alias} has no model identifier")
                elif kind == "components":
                    if identifier in component_ids:
                        errors.append(
                            f"{model}: duplicate component identifier {identifier}"
                        )
                    component_ids[identifier] = alias
                if get_case_insensitive(item, "diagramHeader") not in headers:
                    errors.append(f"{model}: {alias} references an unknown diagram")
                aliases[kind].append((alias, item))
        for alias, flow in aliases["flows"]:
            canonical = expected["flows"].get(alias)
            if canonical is None:
                continue
            for field, ledger_field in (
                ("sourceComponentID", "sourceId"),
                ("targetComponentID", "targetId"),
            ):
                endpoint = component_ids.get(
                    normalize_guid(get_case_insensitive(flow, field)) or ""
                )
                if endpoint != canonical.get(ledger_field):
                    errors.append(
                        f"{model}: {alias} {ledger_field} differs from the ledger"
                    )
        for diagram in diagrams:
            header = get_case_insensitive(diagram, "header")
            for kind, field in (
                ("components", "componentCount"),
                ("flows", "connectorCount"),
                ("boundaries", "trustBoundaryCount"),
            ):
                actual = sum(
                    get_case_insensitive(item, "diagramHeader") == header
                    for item in collections[kind]
                )
                if get_case_insensitive(diagram, field) != actual:
                    errors.append(
                        f"{model}: diagram {header!r} {field} disagrees with its inventory"
                    )
    if pages:
        missing_pages = sorted(set(pages.values()) - seen_pages)
        if missing_pages:
            errors.append(f"missing ledger pages: {', '.join(missing_pages)}")
    for kind in kinds:
        missing = sorted(expected[kind].keys() - seen[kind])
        if missing:
            errors.append(f"missing {kind} aliases: {', '.join(missing)}")
        if counts[kind] != len(expected[kind]):
            errors.append(
                f"{kind} count {counts[kind]} differs from ledger count {len(expected[kind])}"
            )
    return make_check(
        "models.parity",
        "fail" if errors else "pass",
        (
            "; ".join(errors)
            if errors
            else "model aliases, names, endpoints, and counts match the ledger"
        ),
        errors=errors,
        modelCounts=counts,
    )


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
    try:
        candidate_digest = file_sha256(candidate)
        final_digest = file_sha256(final)
    except (OSError, ValueError) as exc:
        return make_check("candidate-final.equivalence", "fail", str(exc))
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


def lifecycle_check(document: JsonObject, package_directory: Path) -> Check:
    """Require lifecycle sidecars to agree with the canonical ledger."""
    scope = as_object(document.get("scope")) or {}
    sidecar_paths = sorted(package_directory.glob("*.tm.evidence.json"))
    if not sidecar_paths:
        required = scope.get("mode") == "formal-package"
        return make_check(
            "lifecycle.parity",
            "fail" if required else "skipped",
            (
                "formal-package requires a lifecycle evidence sidecar"
                if required
                else "no lifecycle sidecar present"
            ),
        )
    lifecycle = scope.get("lifecycle")
    baseline = as_object(scope.get("baseline")) or {}
    errors: list[str] = []
    for sidecar_path in sidecar_paths:
        try:
            sidecar = load_document(sidecar_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{sidecar_path.name}: {exc}")
            continue
        if sidecar.get("state") != lifecycle:
            errors.append(
                f"{sidecar_path.name}: state {sidecar.get('state')!r} "
                f"does not match scope.lifecycle {lifecycle!r}"
            )
        if lifecycle == "verified":
            sidecar_baseline = as_object(sidecar.get("baseline")) or {}
            for ledger_key, sidecar_key in (("revision", "sha"), ("date", "date")):
                if sidecar_baseline.get(sidecar_key) != baseline.get(ledger_key):
                    errors.append(
                        f"{sidecar_path.name}: baseline.{sidecar_key} "
                        f"does not match scope.baseline.{ledger_key}"
                    )
    return make_check(
        "lifecycle.parity",
        "fail" if errors else "pass",
        (
            "; ".join(errors)
            if errors
            else "lifecycle sidecars match the canonical ledger"
        ),
        errors=errors,
    )


def suppression_checks(
    package_directory: Path, invocation: list[str] | None, timeout: int
) -> list[Check]:
    checks: list[Check] = []
    try:
        artifacts = package_files(package_directory)
    except (OSError, ValueError) as exc:
        return [make_check("suppressions.paths", "fail", str(exc))]
    for sidecar in (
        path for path in artifacts if path.name.endswith(".tm.suppressions.json")
    ):
        errors: list[str] = []
        models: list[Path] = []
        try:
            if not sidecar.resolve().is_relative_to(package_directory.resolve()):
                raise ValueError("suppression sidecar escapes the package")
            document = load_document(sidecar)
            files = as_object_list(document.get("files"))
            if not files:
                raise ValueError("suppression sidecar requires a nonempty files array")
            for entry in files:
                name = entry.get("file")
                if (
                    not isinstance(name, str)
                    or not name.endswith(".tm7")
                    or any(separator in name for separator in ("/", "\\"))
                ):
                    raise ValueError("suppression file must name a sibling .tm7 model")
                model = sidecar.parent / name
                if not model.is_file() or not model.resolve().is_relative_to(
                    package_directory.resolve()
                ):
                    raise ValueError(
                        f"missing or out-of-package suppression model: {name}"
                    )
                with artifact_stream(model):
                    pass
                if model in models:
                    raise ValueError(f"duplicate suppression model: {name}")
                models.append(model)
                suppressions = as_object_list(entry.get("suppressions"))
                if suppressions is None:
                    raise ValueError(
                        f"{name}: suppressions must be an array of objects"
                    )
                seen: set[tuple[str, str, str]] = set()
                for suppression in suppressions:
                    for field in ("rule", "model", "target", "justification"):
                        value = suppression.get(field)
                        if not isinstance(value, str) or not value.strip():
                            raise ValueError(
                                f"{name}: suppression {field} must be a nonempty string"
                            )
                    if not re.fullmatch(r"TM\d+", str(suppression["rule"])):
                        raise ValueError(f"{name}: invalid suppression rule")
                    key = (
                        str(suppression["rule"]),
                        str(suppression["model"]),
                        str(suppression["target"]),
                    )
                    if key in seen:
                        raise ValueError(f"{name}: duplicate suppression")
                    seen.add(key)
        except (OSError, ValueError) as exc:
            errors.append(str(exc))
        if not errors:
            if invocation is None:
                errors.append("tmforge is required to verify suppression sidecars")
            else:
                for model in models:
                    stdout, failure = run_process(
                        invocation
                        + [
                            "analyze",
                            str(model),
                            "--suppressionFile",
                            str(sidecar),
                            "--json",
                        ],
                        {0},
                        timeout,
                    )
                    if failure is not None:
                        errors.append(f"{model.name}: {failure}")
                    else:
                        try:
                            data_object(stdout or "")
                        except ValueError as exc:
                            errors.append(f"{model.name}: invalid analyzer JSON: {exc}")
        checks.append(
            make_check(
                f"suppressions.{package_relative(sidecar, package_directory)}",
                "fail" if errors else "pass",
                (
                    "; ".join(errors)
                    if errors
                    else "sidecar is well formed and analyzer verification passed"
                ),
                errors=errors,
            )
        )
    return checks


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
    try:
        artifacts = package_files(package_directory)
    except (OSError, ValueError) as exc:
        return {
            "valid": False,
            "package": str(package_directory),
            "ledger": str(ledger_path),
            "failureCount": 1,
            "warningCount": 0,
            "checks": [make_check("artifacts.paths", "fail", str(exc))],
        }

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
        checks.append(lifecycle_check(document, package_directory))
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

    model_paths = [artifact for artifact in artifacts if artifact.name.endswith(".tm7")]
    scope = as_object(document.get("scope")) if document is not None else None
    mode = scope.get("mode") if scope is not None else None
    invocation = tmforge_invocation
    if model_paths:
        inventories: dict[str, dict[str, JsonObject]] = {}
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
                flow_display_ids = any(
                    "displayId" in flow
                    for flow in as_object_list(
                        document.get("flows") if document else None
                    ) or []
                )
                for model in model_paths:
                    checks.extend(
                        tmforge_model_checks(
                            model, package_directory, invocation, timeout, inventories,
                            flow_display_ids=flow_display_ids,
                        )
                    )
        if document is not None and not validate_document(document):
            checks.append(model_inventory_check(document, inventories))
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

    checks.extend(suppression_checks(package_directory, invocation, timeout))
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
        package_directory = Path(temporary_directory).resolve() / "package"
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
from pathlib import Path

arguments = sys.argv[1:]
if arguments == [\"--version\"]:
    print(\"tmforge self-test\")
elif arguments and arguments[0] == \"render\":
    print(\"diagram\")
elif arguments[:2] == [\"list\", \"threats\"]:
    print(json.dumps({\"data\": {\"items\": []}}))
elif arguments and arguments[0] == \"threats\":
    print(json.dumps({\"data\": {\"threats\": []}}))
elif arguments and arguments[0] == \"list\":
    document = json.loads((Path(arguments[2]).parent / \"analysis.json\").read_text())
    kind = arguments[1]
    if kind == \"diagrams\":
        items = [{\"id\": \"diagram-id\", \"header\": \"Diagram 1\",
                  \"componentCount\": len(document[\"elements\"]),
                  \"connectorCount\": len(document[\"flows\"]),
                  \"trustBoundaryCount\": len(document[\"boundaries\"])}]
    else:
        source = document[{\"components\": \"elements\"}.get(kind, kind)]
        items = [{\"id\": item[\"id\"], \"name\": item[\"id\"] + \": \" + item[\"name\"],
                  \"diagramHeader\": \"Diagram 1\",
                  \"sourceComponentID\": item.get(\"sourceId\"),
                  \"targetComponentID\": item.get(\"targetId\")} for item in source]
    print(json.dumps({\"data\": {\"items\": items, \"count\": len(items)}}))
else:
    print(json.dumps({\"data\": {\"items\": []}}))
""",
            encoding="utf-8",
        )
        missing_evidence = verify_package(
            package_directory, tmforge_invocation=[sys.executable, str(fake_tmforge)]
        )
        if (
            missing_evidence.get("valid") is not False
            or lifecycle_check(document, package_directory).get("status") != "fail"
        ):
            raise AssertionError(
                "formal package without lifecycle evidence was accepted"
            )
        sidecar = package_directory / "threat-model.tm.evidence.json"
        sidecar.write_text(json.dumps({"state": "draft"}), encoding="utf-8")
        valid = verify_package(
            package_directory,
            tmforge_invocation=[sys.executable, str(fake_tmforge)],
        )
        if valid.get("valid") is not True:
            raise AssertionError(f"valid package was rejected: {valid}")

        scope = as_object(document.get("scope"))
        assert scope is not None
        baseline = {
            "revision": "a" * 40,
            "date": "2026-09-16",
        }
        sidecar = package_directory / "threat-model.tm.evidence.json"
        for ledger_state, sidecar_state, revision, date, expected_status in (
            ("draft", "draft", "a" * 40, "2026-09-16", "pass"),
            ("draft", "verified", "a" * 40, "2026-09-16", "fail"),
            ("verified", "draft", "a" * 40, "2026-09-16", "fail"),
            ("verified", "verified", "a" * 40, "2026-09-16", "pass"),
            ("verified", "verified", "b" * 40, "2026-09-16", "fail"),
            ("verified", "verified", "a" * 40, "2026-09-15", "fail"),
        ):
            scope["lifecycle"] = ledger_state
            scope["baseline"] = baseline
            ledger.write_text(json.dumps(document), encoding="utf-8")
            write_documents(render_documents(document), package_directory)
            sidecar.write_text(
                json.dumps(
                    {
                        "state": sidecar_state,
                        "baseline": {"sha": revision, "date": date},
                    }
                ),
                encoding="utf-8",
            )
            result = verify_package(
                package_directory,
                tmforge_invocation=[sys.executable, str(fake_tmforge)],
            )
            parity = next(
                check
                for check in as_object_list(result.get("checks")) or []
                if check.get("name") == "lifecycle.parity"
            )
            if parity.get("status") != expected_status or result.get("valid") != (
                expected_status == "pass"
            ):
                raise AssertionError(f"incorrect lifecycle verdict: {result}")

        sidecar.write_text("{invalid", encoding="utf-8")
        if lifecycle_check(document, package_directory).get("status") != "fail":
            raise AssertionError("malformed lifecycle sidecar was accepted")
        for missing in ("revision", "date"):
            scope["baseline"] = {
                key: value for key, value in baseline.items() if key != missing
            }
            if (
                f"scope.baseline: missing required fields: ['{missing}']"
                not in validate_document(document)
            ):
                raise AssertionError(
                    f"verified ledger without baseline.{missing} was accepted"
                )
        sidecar.unlink()
        ledger.write_bytes(fixture.read_bytes())
        document = load_document(ledger)
        write_documents(render_documents(document), package_directory)

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

        candidate = package_directory.parent / "candidate.bin"
        final = package_directory.parent / "final.bin"
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
