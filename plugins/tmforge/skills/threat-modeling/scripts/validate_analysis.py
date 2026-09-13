#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from collections import Counter
from collections.abc import Callable
from datetime import date
from pathlib import Path
from typing import cast

JsonObject = dict[str, object]

CATEGORIES = ("S", "T", "R", "I", "D", "E")
CATEGORY_ORDER = {category: index for index, category in enumerate(CATEGORIES)}
LEVELS = ("critical", "high", "medium", "low")
STATUSES = {"open", "mitigated", "accepted", "transferred", "unknown"}
ORIGINS = {"manual", "generated", "imported"}
TRIAGE_DECISIONS = {
    "confirmed",
    "corrected",
    "deferred",
    "disputed",
    "duplicate",
    "resolved",
}
TRIAGE_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
MODES = {"analyze", "formal-package", "verify", "update"}
LIFECYCLES = {"draft", "verified", "stale", "not-verified", "unvalidated"}
SCOPE_INPUT_KINDS = {
    "user-request",
    "selection",
    "file",
    "directory",
    "component",
    "work-item",
    "issue",
    "pull-request",
    "branch",
    "commit",
    "document",
    "existing-model",
    "other",
}
SCOPE_INPUT_ROLES = {"primary", "supporting", "excluded"}
SCOPE_INPUT_STATUSES = {"resolved", "unavailable"}
OWNERSHIP_ACTIONS = {
    "analysis-only",
    "verify-only",
    "create",
    "update",
    "append",
    "replace",
}
FINDING_TYPES = {
    "design-gap",
    "implementation-defect",
    "operational-gap",
    "unknown",
}
CONTROL_STATUSES = {"implemented", "partial", "unknown"}
BOUNDARY_AXES = {
    "authority",
    "host",
    "network-segment",
    "network-namespace",
    "process-isolation",
}
PLACEMENT_EVIDENCE_KINDS = {"process", "data-store"}
THREAT_ACTOR_CAPABILITIES = {"low", "moderate", "high", "unknown"}
THREAT_ACTOR_ACCESS = {
    "external",
    "authenticated",
    "privileged",
    "internal",
    "supply-chain",
    "physical",
    "compromised-component",
    "unknown",
}
IMPLEMENTATION_EVIDENCE_TYPES = {
    "runtime",
    "deployed-configuration",
    "generated-configuration",
    "source",
    "test",
    "schema",
}
EVIDENCE_TYPES = IMPLEMENTATION_EVIDENCE_TYPES | {
    "contract",
    "procedure",
    "documentation",
    "change-record",
    "assumption",
}
THREAT_ID_RE = re.compile(r"^([A-Z0-9]{1,12})-([STRIDE])-[0-9]{3,}$")
SCOPE_INPUT_ID_RE = re.compile(r"^SI[0-9]{3,}$")
SCOPE_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
ID_PATTERNS = {
    "evidence": re.compile(r"^E[0-9]{3,}$"),
    "boundaries": re.compile(r"^TB[0-9]+$"),
    "elements": re.compile(r"^(A|X|P|DS)[0-9]+$"),
    "flows": re.compile(r"^F[0-9]+$"),
    "assets": re.compile(r"^AS[0-9]+$"),
    "threatActors": re.compile(r"^TA[0-9]+$"),
    "assumptions": re.compile(r"^(A|U)[0-9]{3,}$"),
}


def natural_key(value: str) -> tuple[tuple[int, int | str], ...]:
    """Return a comparable key with numeric substrings ordered numerically."""
    return tuple(
        (0, int(part)) if part.isdigit() else (1, part.lower())
        for part in re.split(r"([0-9]+)", value)
        if part
    )


def risk_level(score: int) -> str:
    """Map a numeric risk score to its controlled level."""
    if score >= 20:
        return "critical"
    if score >= 12:
        return "high"
    if score >= 6:
        return "medium"
    return "low"


def as_object(value: object) -> JsonObject | None:
    """Narrow a JSON value to an object."""
    return cast(JsonObject, value) if isinstance(value, dict) else None


def as_object_list(value: object) -> list[JsonObject] | None:
    """Narrow a JSON value to an array of objects."""
    if not isinstance(value, list):
        return None
    values = cast(list[object], value)
    if any(not isinstance(item, dict) for item in values):
        return None
    return [cast(JsonObject, item) for item in values]


def as_string_list(value: object) -> list[str] | None:
    """Narrow a JSON value to an array of strings."""
    if not isinstance(value, list):
        return None
    values = cast(list[object], value)
    if any(not isinstance(item, str) for item in values):
        return None
    return cast(list[str], values)


def check_placement_evidence(
    element_id: str,
    element: JsonObject,
    evidence: dict[str, JsonObject],
    error: Callable[[str], None],
) -> None:
    """Require evidence for where a running component is deployed.

    Where a component runs decides which boundaries it sits in and therefore which
    flows cross a boundary at all. It is routinely inferred from the repository or
    component name that produced it, which silently places components in the wrong
    cluster, host, or namespace, so it must be evidenced explicitly.
    """
    if element.get("kind") not in PLACEMENT_EVIDENCE_KINDS:
        return
    if element.get("material") is False:
        return
    placement = as_string_list(element.get("placementEvidenceIds"))
    if placement is None or not placement:
        error(
            f"elements.{element_id}: placementEvidenceIds must be a non-empty string "
            f"array naming the evidence that establishes where this component runs"
        )
        return
    unknown_ids = sorted(item for item in placement if item not in evidence)
    if unknown_ids:
        error(f"elements.{element_id}: unknown placement evidence ids {unknown_ids}")
    declared = set(as_string_list(element.get("evidenceIds")) or [])
    missing = sorted(set(placement) - declared)
    if missing:
        error(
            f"elements.{element_id}: placementEvidenceIds {missing} must also appear in "
            f"evidenceIds"
        )


def check_producer_provenance(
    elements: dict[str, JsonObject],
    flows: dict[str, JsonObject],
    error: Callable[[str], None],
) -> None:
    """Require every material store to name its writer or explain the absence.

    A store with no inbound flow is where models acquire invented elements. The
    reasoning is plausible and wrong: something must write this object, no in-scope
    component does, therefore an operator must. That turns an unfinished trace into an
    actor and misstates who is trusted, which identity an attacker must obtain, and
    where the mitigation belongs. Requiring an explicit rationale keeps the judgement
    visible and arguable instead of asserted through a placeholder source.
    """
    written: set[str] = set()
    for flow in flows.values():
        if flow.get("material") is False:
            continue
        target_id = flow.get("targetId")
        if isinstance(target_id, str):
            written.add(target_id)

    for element_id in sorted(elements, key=natural_key):
        element = elements[element_id]
        if element.get("kind") != "data-store" or element.get("material") is not True:
            continue
        rationale = element.get("producerRationale")
        has_rationale = isinstance(rationale, str) and rationale.strip() != ""
        if element_id in written:
            if has_rationale:
                error(
                    f"elements.{element_id}: producerRationale is only for a store with "
                    f"no material inbound flow; this store is written by a modelled flow"
                )
            continue
        if not has_rationale:
            error(
                f"elements.{element_id}: material data store has no material inbound "
                f"flow, so it must record producerRationale naming the excluded "
                f"renderer, external service, or bootstrap step that writes it, or gain "
                f"the missing inbound flow"
            )


def check_coverage_threat_agreement(
    coverage: list[JsonObject],
    threat_index: dict[str, JsonObject],
    error: Callable[[str], None],
) -> None:
    """Reject a cell dismissed as not-applicable that a threat already claims.

    Coverage and threats are edited separately, so adding a threat routinely leaves the
    matching cell asserting that the category does not apply. Both statements then
    validate in isolation while contradicting each other, and the rendered document
    argues against itself. Every conflict is reported together so one pass resolves
    them all rather than one per run.
    """
    claimed: dict[tuple[str, str], list[str]] = {}
    for threat_id in sorted(threat_index, key=natural_key):
        threat = threat_index[threat_id]
        category = threat.get("category")
        if not isinstance(category, str):
            continue
        for target_id in as_string_list(threat.get("targetIds")) or []:
            claimed.setdefault((target_id, category), []).append(threat_id)

    conflicts: list[str] = []
    for cell in coverage:
        if cell.get("disposition") != "not-applicable":
            continue
        target_id = cell.get("targetId")
        category = cell.get("category")
        if not isinstance(target_id, str) or not isinstance(category, str):
            continue
        owners = claimed.get((target_id, category))
        if owners:
            conflicts.append(f"({target_id},{category}) claimed by {owners}")
    if conflicts:
        error(
            "not-applicable coverage contradicted by threats that name the same target "
            f"and category: {conflicts}"
        )


def check_triage(
    threat_id: str,
    threat: JsonObject,
    evidence: dict[str, JsonObject],
    threat_ids: set[str],
    error: Callable[[str], None],
) -> None:
    """Validate the review-disposition trail recorded against one threat.

    Review is where a finding is most easily lost: a reviewer says it is fixed, or
    already covered, or somebody else's, and the assertion closes it. These rules make
    each of those claims carry what a later reader needs to re-check it. `resolved`
    demands evidence and a status that already reflects the fix, so a finding cannot be
    closed on assertion alone. `duplicate` demands the threat it defers to, so the risk
    lands somewhere rather than nowhere. `disputed` demands a reference, so the argument
    stays readable after the pull request that carried it is merged and forgotten.
    """
    if "triage" not in threat:
        return
    entries = as_object_list(threat.get("triage"))
    if entries is None:
        error(f"{threat_id}: triage must be an array of objects")
        return
    if not entries:
        error(f"{threat_id}: triage must be omitted rather than empty")
        return

    order_keys: list[tuple[str, str]] = []
    for index, entry in enumerate(entries):
        owner = f"{threat_id}.triage[{index}]"

        entry_date = entry.get("date")
        if (
            not isinstance(entry_date, str)
            or TRIAGE_DATE_RE.fullmatch(entry_date) is None
        ):
            error(f"{owner}: date must be an ISO calendar date, YYYY-MM-DD")
            entry_date = ""
        else:
            try:
                date.fromisoformat(entry_date)
            except ValueError:
                error(f"{owner}: date {entry_date!r} is not a real calendar date")
                entry_date = ""

        reviewer = entry.get("reviewer")
        if not isinstance(reviewer, str) or not reviewer.strip():
            error(f"{owner}: reviewer must be a non-empty string")
            reviewer = ""
        order_keys.append((entry_date, reviewer))

        rationale = entry.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            error(f"{owner}: rationale must be a non-empty string")

        decision = entry.get("decision")
        if decision not in TRIAGE_DECISIONS:
            error(f"{owner}: invalid decision {decision!r}")

        reference = entry.get("reference")
        has_reference = isinstance(reference, str) and bool(reference.strip())
        if "reference" in entry and not has_reference:
            error(f"{owner}: reference must be a non-empty string when present")

        related_ids = as_string_list(entry.get("relatedThreatIds"))
        if "relatedThreatIds" in entry:
            if not related_ids:
                error(f"{owner}: relatedThreatIds must be a non-empty string array")
                related_ids = []
            else:
                if len(related_ids) != len(set(related_ids)):
                    error(f"{owner}: relatedThreatIds contains duplicates")
                if threat_id in related_ids:
                    error(f"{owner}: relatedThreatIds must not name its own threat")
                unknown_related = sorted(
                    item for item in related_ids if item not in threat_ids
                )
                if unknown_related:
                    error(f"{owner}: unknown threat ids {unknown_related}")
        else:
            related_ids = []

        triage_evidence = as_string_list(entry.get("evidenceIds"))
        if "evidenceIds" in entry:
            if not triage_evidence:
                error(f"{owner}: evidenceIds must be a non-empty string array")
                triage_evidence = []
            else:
                if len(triage_evidence) != len(set(triage_evidence)):
                    error(f"{owner}: evidenceIds contains duplicates")
                missing_evidence = sorted(
                    item for item in triage_evidence if item not in evidence
                )
                if missing_evidence:
                    error(f"{owner}: unknown evidence ids {missing_evidence}")
        else:
            triage_evidence = []

        work_item_ids = as_string_list(entry.get("workItemIds"))
        if "workItemIds" in entry:
            if not work_item_ids:
                error(f"{owner}: workItemIds must be a non-empty string array")
            elif len(work_item_ids) != len(set(work_item_ids)):
                error(f"{owner}: workItemIds contains duplicates")

        if decision == "duplicate" and not related_ids:
            error(f"{owner}: duplicate decision requires relatedThreatIds")
        if decision == "disputed" and not has_reference:
            error(f"{owner}: disputed decision requires a reference")
        if decision == "resolved":
            if not triage_evidence:
                error(
                    f"{owner}: resolved decision requires evidenceIds proving the fix"
                )
            if threat.get("status") not in {"mitigated", "transferred"}:
                error(
                    f"{owner}: resolved decision requires threat status 'mitigated' or "
                    f"'transferred', found {threat.get('status')!r}"
                )

    if order_keys != sorted(order_keys):
        error(f"{threat_id}: triage must be sorted by date then reviewer")


def check_id_stability(
    document: JsonObject,
    baseline: JsonObject,
    error: Callable[[str], None],
) -> None:
    """Compare a rebuilt ledger with its predecessor to catch renumbering.

    ID allocation is positional, so re-deriving IDs from a changed inventory shifts
    every entry after an insertion. Anything keyed by ID then attaches to the wrong
    element while remaining syntactically valid, which is why this is checked rather
    than trusted.
    """
    for section in ("boundaries", "elements", "flows", "assets", "threatActors"):
        current = {
            str(item.get("id")): str(item.get("name"))
            for item in as_object_list(document.get(section)) or []
        }
        previous = {
            str(item.get("id")): str(item.get("name"))
            for item in as_object_list(baseline.get(section)) or []
        }
        moved = sorted(
            f"{item_id}: {previous[item_id]!r} -> {current[item_id]!r}"
            for item_id in previous.keys() & current.keys()
            if previous[item_id] != current[item_id]
        )
        if moved:
            error(f"{section}: ids were reassigned to different entries: {moved}")
        renamed = {name: item_id for item_id, name in previous.items()}
        rehomed = sorted(
            f"{name!r}: {renamed[name]} -> {item_id}"
            for item_id, name in current.items()
            if name in renamed and renamed[name] != item_id
        )
        if rehomed:
            error(f"{section}: existing entries were renumbered: {rehomed}")
        dropped = sorted(previous.keys() - current.keys())
        if dropped:
            error(f"{section}: ids present in the baseline were removed: {dropped}")

    for section in ("threats",):
        current = {
            str(item.get("id")): str(item.get("title"))
            for item in as_object_list(document.get(section)) or []
        }
        previous = {
            str(item.get("id")): str(item.get("title"))
            for item in as_object_list(baseline.get(section)) or []
        }
        dropped = sorted(previous.keys() - current.keys())
        if dropped:
            error(f"{section}: ids present in the baseline were removed: {dropped}")


def check_crossing_consistency(
    flows: dict[str, JsonObject],
    elements: dict[str, JsonObject],
    evidence: dict[str, JsonObject],
    error: Callable[[str], None],
) -> None:
    """Reconcile each flow's crossing claim with the topology that implies it.

    A flow crosses every boundary that contains exactly one of its endpoints, so the
    crossed set is the symmetric difference of the endpoint boundary sets. Overlap on
    one axis does not cancel a crossing on another: a pod-to-pod call inside one
    authority zone still leaves a network namespace.

    A flow may decline a derived crossing only by recording an explicit, evidenced
    ``crossingExemptions`` entry. That keeps a real judgement, such as a Secret reaching
    a container as a projected file rather than over the network, visible and arguable
    instead of asserted silently.
    """
    for flow_id in sorted(flows, key=natural_key):
        flow = flows[flow_id]
        source = elements.get(str(flow.get("sourceId")))
        target = elements.get(str(flow.get("targetId")))
        if source is None or target is None:
            continue
        source_ids = set(as_string_list(source.get("boundaryIds")) or [])
        target_ids = set(as_string_list(target.get("boundaryIds")) or [])
        derived = source_ids ^ target_ids

        exemptions = as_object_list(flow.get("crossingExemptions")) or []
        exempted: set[str] = set()
        for index, exemption in enumerate(exemptions):
            boundary_id = exemption.get("boundaryId")
            rationale = exemption.get("rationale")
            if not isinstance(boundary_id, str) or boundary_id not in derived:
                error(
                    f"flows.{flow_id}.crossingExemptions[{index}]: boundaryId "
                    f"{boundary_id!r} is not a derived crossing for this flow "
                    f"{sorted(derived, key=natural_key)}"
                )
                continue
            if not isinstance(rationale, str) or not rationale.strip():
                error(
                    f"flows.{flow_id}.crossingExemptions[{index}]: rationale must be "
                    f"non-empty"
                )
            evidence_ids = as_string_list(exemption.get("evidenceIds"))
            if not evidence_ids:
                error(
                    f"flows.{flow_id}.crossingExemptions[{index}]: evidenceIds must be "
                    f"a non-empty string array"
                )
            else:
                unknown_ids = sorted(
                    item for item in evidence_ids if item not in evidence
                )
                if unknown_ids:
                    error(
                        f"flows.{flow_id}.crossingExemptions[{index}]: unknown evidence "
                        f"ids {unknown_ids}"
                    )
            exempted.add(boundary_id)

        remaining = derived - exempted
        declared = flow.get("crossesTrustBoundary")
        if remaining and declared is not True:
            error(
                f"flows.{flow_id}: crossesTrustBoundary is {declared!r} but the topology "
                f"places the endpoints in different boundaries "
                f"{sorted(remaining, key=natural_key)}. Set it to true, or record a "
                f"crossingExemptions entry with evidence for each boundary."
            )
        if not derived and declared is True:
            error(
                f"flows.{flow_id}: crossesTrustBoundary is true but both endpoints hold "
                f"identical boundary membership "
                f"{sorted(source_ids, key=natural_key)}"
            )
        if derived and not remaining and declared is True:
            error(
                f"flows.{flow_id}: every derived crossing is exempted, so "
                f"crossesTrustBoundary must be false"
            )


def validate_document(document: object) -> list[str]:
    """Return all deterministic contract violations in a ledger."""
    errors: list[str] = []

    def error(message: str) -> None:
        errors.append(message)

    root = as_object(document)
    if root is None:
        return ["top level must be a JSON object"]

    required = {
        "schemaVersion",
        "scope",
        "evidence",
        "boundaries",
        "elements",
        "flows",
        "assets",
        "threatActors",
        "coverage",
        "threats",
        "assumptions",
        "summary",
    }
    missing = sorted(required - set(root))
    unknown = sorted(set(root) - required)
    if missing:
        error(f"missing top-level fields: {missing}")
    if unknown:
        error(f"unknown top-level fields: {unknown}")
    if root.get("schemaVersion") != 1:
        error("schemaVersion must be 1")

    scope = as_object(root.get("scope"))
    if scope is None:
        error("scope must be an object")
        scope = {}
    scope_name = scope.get("name")
    if not isinstance(scope_name, str) or not scope_name.strip():
        error("scope.name must be a non-empty string")
    scope_slug = scope.get("slug")
    if not isinstance(scope_slug, str) or SCOPE_SLUG_RE.fullmatch(scope_slug) is None:
        error("scope.slug must be lowercase kebab-case")

    mode = scope.get("mode")
    if mode not in MODES:
        error(f"scope.mode must be one of {sorted(MODES)}")
    if scope.get("lifecycle") not in LIFECYCLES:
        error(f"scope.lifecycle must be one of {sorted(LIFECYCLES)}")
    if scope.get("lifecycle") == "verified":
        baseline = as_object(scope.get("baseline"))
        if baseline is None or not baseline.get("revision"):
            error("verified lifecycle requires baseline.revision")
        if baseline is None or not baseline.get("approvedBy"):
            error("verified lifecycle requires baseline.approvedBy")

    exclusions = as_string_list(scope.get("exclusions"))
    if exclusions is None:
        error("scope.exclusions must be a string array")

    scope_inputs = as_object_list(scope.get("inputs"))
    if not scope_inputs:
        error("scope.inputs must be a non-empty array of objects")
        scope_inputs = []
    scope_input_ids: list[str] = []
    seen_scope_input_ids: set[str] = set()
    primary_scope_inputs = 0
    scope_input_evidence: list[tuple[str, list[str]]] = []
    for position, scope_input in enumerate(scope_inputs):
        owner = f"scope.inputs[{position}]"
        input_id = scope_input.get("id")
        if (
            not isinstance(input_id, str)
            or SCOPE_INPUT_ID_RE.fullmatch(input_id) is None
        ):
            error(f"{owner}.id is invalid: {input_id!r}")
        else:
            if input_id in seen_scope_input_ids:
                error(f"duplicate scope input id: {input_id}")
            seen_scope_input_ids.add(input_id)
            scope_input_ids.append(input_id)
            owner = f"scope.inputs.{input_id}"

        kind = scope_input.get("kind")
        role = scope_input.get("role")
        status = scope_input.get("status")
        if kind not in SCOPE_INPUT_KINDS:
            error(f"{owner}: invalid kind {kind!r}")
        if role not in SCOPE_INPUT_ROLES:
            error(f"{owner}: invalid role {role!r}")
        elif role == "primary":
            primary_scope_inputs += 1
        if status not in SCOPE_INPUT_STATUSES:
            error(f"{owner}: invalid status {status!r}")
        for field in ("reference", "rationale"):
            value = scope_input.get(field)
            if not isinstance(value, str) or not value.strip():
                error(f"{owner}: {field} must be non-empty")

        evidence_ids_value = scope_input.get("evidenceIds")
        evidence_ids = (
            as_string_list(evidence_ids_value) if evidence_ids_value is not None else []
        )
        if evidence_ids is None:
            error(f"{owner}: evidenceIds must be a string array")
            evidence_ids = []
        elif len(evidence_ids) != len(set(evidence_ids)):
            error(f"{owner}: evidenceIds contains duplicates")
        if (
            kind != "user-request"
            and role != "excluded"
            and status == "resolved"
            and not evidence_ids
        ):
            error(f"{owner}: resolved non-user scope input requires evidenceIds")
        scope_input_evidence.append((owner, evidence_ids))

    if scope_input_ids != sorted(scope_input_ids, key=natural_key):
        error("scope.inputs must be sorted by natural id order")
    if primary_scope_inputs < 1:
        error("scope.inputs must contain at least one primary input")

    ownership = as_object(scope.get("ownershipDecision"))
    if ownership is None:
        error("scope.ownershipDecision must be an object")
        ownership = {}
    action = ownership.get("action")
    if action not in OWNERSHIP_ACTIONS:
        error(
            f"scope.ownershipDecision.action must be one of {sorted(OWNERSHIP_ACTIONS)}"
        )
    rationale = ownership.get("rationale")
    if not isinstance(rationale, str) or not rationale.strip():
        error("scope.ownershipDecision.rationale must be non-empty")
    model_reference = ownership.get("modelReference")
    if action in {"verify-only", "update", "append", "replace"} and (
        not isinstance(model_reference, str) or not model_reference.strip()
    ):
        error(f"scope.ownershipDecision action {action!r} requires modelReference")
    if mode == "analyze" and action != "analysis-only":
        error("analyze mode requires ownership action 'analysis-only'")
    elif mode == "verify" and action != "verify-only":
        error("verify mode requires ownership action 'verify-only'")
    elif mode in {"formal-package", "update"} and action in {
        "analysis-only",
        "verify-only",
    }:
        error(
            f"{mode} mode requires create, update, append, or replace ownership action"
        )

    collections: dict[str, list[JsonObject]] = {}
    for name in ID_PATTERNS:
        values = as_object_list(root.get(name))
        if values is None:
            error(f"{name} must be an array of objects")
            values = []
        collections[name] = values

    coverage = as_object_list(root.get("coverage"))
    if coverage is None:
        error("coverage must be an array of objects")
        coverage = []
    collections["coverage"] = coverage

    threats = as_object_list(root.get("threats"))
    if threats is None:
        error("threats must be an array of objects")
        threats = []
    collections["threats"] = threats

    def index_collection(name: str) -> dict[str, JsonObject]:
        index: dict[str, JsonObject] = {}
        ids: list[str] = []
        pattern = ID_PATTERNS[name]
        for position, item in enumerate(collections[name]):
            item_id = item.get("id")
            if not isinstance(item_id, str) or pattern.fullmatch(item_id) is None:
                error(f"{name}[{position}].id is invalid: {item_id!r}")
                continue
            if item_id in index:
                error(f"duplicate {name} id: {item_id}")
            index[item_id] = item
            ids.append(item_id)
        if ids != sorted(ids, key=natural_key):
            error(f"{name} must be sorted by natural id order")
        return index

    evidence = index_collection("evidence")
    boundaries = index_collection("boundaries")
    elements = index_collection("elements")
    flows = index_collection("flows")
    assets = index_collection("assets")
    threat_actors = index_collection("threatActors")
    index_collection("assumptions")

    for evidence_id, evidence_item in evidence.items():
        evidence_type = evidence_item.get("type")
        if evidence_type not in EVIDENCE_TYPES:
            error(f"evidence.{evidence_id}: invalid type {evidence_type!r}")

    for owner, evidence_ids in scope_input_evidence:
        missing_ids = sorted(
            evidence_id for evidence_id in evidence_ids if evidence_id not in evidence
        )
        if missing_ids:
            error(f"{owner}: unknown evidence ids {missing_ids}")

    threat_index: dict[str, JsonObject] = {}
    threat_ids: list[str] = []
    for position, threat in enumerate(threats):
        threat_id = threat.get("id")
        if not isinstance(threat_id, str):
            error(f"threats[{position}].id is invalid: {threat_id!r}")
            continue
        match = THREAT_ID_RE.fullmatch(threat_id)
        if match is None:
            error(f"threats[{position}].id is invalid: {threat_id!r}")
            continue
        if threat_id in threat_index:
            error(f"duplicate threat id: {threat_id}")
        threat_index[threat_id] = threat
        threat_ids.append(threat_id)
        if threat.get("area") != match.group(1):
            error(f"{threat_id}: area does not match the id prefix")
        if threat.get("category") != match.group(2):
            error(f"{threat_id}: category does not match the id category")
        if threat.get("origin") not in ORIGINS:
            error(f"{threat_id}: invalid origin {threat.get('origin')!r}")
        if threat.get("findingType") not in FINDING_TYPES:
            error(f"{threat_id}: invalid findingType {threat.get('findingType')!r}")
    if threat_ids != sorted(threat_ids, key=natural_key):
        error("threats must be sorted by natural id order")

    def check_evidence_ids(owner: str, item: JsonObject) -> None:
        evidence_ids = as_string_list(item.get("evidenceIds"))
        if not evidence_ids:
            error(f"{owner}: evidenceIds must be a non-empty string array")
            return
        if len(evidence_ids) != len(set(evidence_ids)):
            error(f"{owner}: evidenceIds contains duplicates")
        missing_ids = sorted(
            evidence_id for evidence_id in evidence_ids if evidence_id not in evidence
        )
        if missing_ids:
            error(f"{owner}: unknown evidence ids {missing_ids}")

    for name, index in (
        ("boundaries", boundaries),
        ("elements", elements),
        ("flows", flows),
        ("assets", assets),
        ("threatActors", threat_actors),
        ("threats", threat_index),
    ):
        for item_id, item in index.items():
            check_evidence_ids(f"{name}.{item_id}", item)

    for boundary_id, boundary in boundaries.items():
        axis = boundary.get("axis")
        if axis not in BOUNDARY_AXES:
            error(
                f"boundaries.{boundary_id}: axis must be one of {sorted(BOUNDARY_AXES)}, "
                f"got {axis!r}. A boundary must declare what kind of trust change it "
                f"represents so membership and nesting stay consistent."
            )
        parent_id = boundary.get("parentId")
        if parent_id is not None and parent_id not in boundaries:
            error(f"boundaries.{boundary_id}: unknown parentId {parent_id!r}")
        if parent_id == boundary_id:
            error(f"boundaries.{boundary_id}: cannot be its own parent")
        # Nesting asserts containment. Containment across different axes is a claim the
        # deployment usually cannot enforce, so only same-axis nesting is permitted.
        if parent_id is not None and parent_id in boundaries and axis in BOUNDARY_AXES:
            parent_axis = boundaries[parent_id].get("axis")
            if parent_axis != axis:
                error(
                    f"boundaries.{boundary_id}: parentId {parent_id!r} has axis "
                    f"{parent_axis!r} but this boundary has axis {axis!r}. Nesting is "
                    f"permitted only within one axis where containment is enforced by a "
                    f"verified control; record the relationship as multiple boundaryIds "
                    f"on the member elements instead."
                )

    boundary_members: dict[str, list[str]] = {bid: [] for bid in boundaries}

    for element_id, element in elements.items():
        boundary_ids = as_string_list(element.get("boundaryIds"))
        if boundary_ids is None:
            error(f"elements.{element_id}: boundaryIds must be a string array")
            continue
        unknown_ids = sorted(item for item in boundary_ids if item not in boundaries)
        if unknown_ids:
            error(f"elements.{element_id}: unknown boundary ids {unknown_ids}")
        for boundary_id in boundary_ids:
            if boundary_id in boundary_members:
                boundary_members[boundary_id].append(element_id)
        check_placement_evidence(element_id, element, evidence, error)

    for boundary_id in sorted(boundary_members, key=natural_key):
        if not boundary_members[boundary_id]:
            error(
                f"boundaries.{boundary_id}: has no member elements. An empty boundary "
                f"renders as an empty region and usually means elements were assigned on "
                f"a different axis than the one this boundary declares."
            )

    for flow_id, flow in flows.items():
        if flow.get("sourceId") not in elements:
            error(f"flows.{flow_id}: unknown sourceId {flow.get('sourceId')!r}")
        if flow.get("targetId") not in elements:
            error(f"flows.{flow_id}: unknown targetId {flow.get('targetId')!r}")
        asset_ids = as_string_list(flow.get("assetIds"))
        if asset_ids is None:
            error(f"flows.{flow_id}: assetIds must be a string array")
            continue
        unknown_ids = sorted(item for item in asset_ids if item not in assets)
        if unknown_ids:
            error(f"flows.{flow_id}: unknown asset ids {unknown_ids}")

    check_crossing_consistency(flows, elements, evidence, error)
    check_producer_provenance(elements, flows, error)

    for actor_id, actor in threat_actors.items():
        for field in ("name", "motivation"):
            value = actor.get(field)
            if not isinstance(value, str) or not value.strip():
                error(f"threatActors.{actor_id}: {field} must be non-empty")
        capability = actor.get("capability")
        if capability not in THREAT_ACTOR_CAPABILITIES:
            error(f"threatActors.{actor_id}: invalid capability {capability!r}")
        access = as_string_list(actor.get("access"))
        if not access:
            error(f"threatActors.{actor_id}: access must be a non-empty string array")
        else:
            if len(access) != len(set(access)):
                error(f"threatActors.{actor_id}: access contains duplicates")
            invalid_access = sorted(set(access) - THREAT_ACTOR_ACCESS)
            if invalid_access:
                error(
                    f"threatActors.{actor_id}: invalid access values {invalid_access}"
                )
        target_asset_ids = as_string_list(actor.get("targetAssetIds"))
        if not target_asset_ids:
            error(
                f"threatActors.{actor_id}: targetAssetIds must be a non-empty "
                "string array"
            )
        else:
            unknown_ids = sorted(
                asset_id for asset_id in target_asset_ids if asset_id not in assets
            )
            if unknown_ids:
                error(f"threatActors.{actor_id}: unknown asset ids {unknown_ids}")

    valid_targets = set(elements) | set(flows)
    for threat_id, threat in threat_index.items():
        target_ids = as_string_list(threat.get("targetIds"))
        if not target_ids:
            error(f"{threat_id}: targetIds must be a non-empty string array")
            target_ids = []
        unknown_targets = sorted(
            item for item in target_ids if item not in valid_targets
        )
        if unknown_targets:
            error(f"{threat_id}: unknown target ids {unknown_targets}")

        asset_ids = as_string_list(threat.get("assetIds"))
        if asset_ids is None:
            error(f"{threat_id}: assetIds must be a string array")
        else:
            unknown_ids = sorted(item for item in asset_ids if item not in assets)
            if unknown_ids:
                error(f"{threat_id}: unknown asset ids {unknown_ids}")

        likelihood = threat.get("likelihood")
        impact = threat.get("impact")
        if not isinstance(likelihood, int) or not 1 <= likelihood <= 5:
            error(f"{threat_id}: likelihood must be an integer from 1 to 5")
        if not isinstance(impact, int) or not 1 <= impact <= 5:
            error(f"{threat_id}: impact must be an integer from 1 to 5")
        if isinstance(likelihood, int) and isinstance(impact, int):
            expected_score = likelihood * impact
            if threat.get("score") != expected_score:
                error(f"{threat_id}: score must equal {expected_score}")
            expected_level = risk_level(expected_score)
            if threat.get("level") != expected_level:
                error(f"{threat_id}: level must be {expected_level!r}")
        if threat.get("status") not in STATUSES:
            error(f"{threat_id}: invalid status {threat.get('status')!r}")
        confidence = threat.get("confidence")
        if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            error(f"{threat_id}: confidence must be between 0 and 1")

        controls = as_object_list(threat.get("currentControls"))
        if controls is None:
            error(f"{threat_id}: currentControls must be an array of objects")
        else:
            for control_index, control in enumerate(controls):
                control_owner = f"{threat_id}.currentControls[{control_index}]"
                check_evidence_ids(control_owner, control)
                description = control.get("description")
                if not isinstance(description, str) or not description.strip():
                    error(f"{control_owner}: description must be non-empty")
                implementation_status = control.get("implementationStatus")
                if implementation_status not in CONTROL_STATUSES:
                    error(
                        f"{control_owner}: invalid implementationStatus "
                        f"{implementation_status!r}"
                    )
                gap = control.get("gap")
                if implementation_status in {"partial", "unknown"} and (
                    not isinstance(gap, str) or not gap.strip()
                ):
                    error(
                        f"{control_owner}: {implementation_status} control requires gap"
                    )
        for field in (
            "mitigation",
            "mitigationOwner",
            "mitigationLocation",
            "verification",
        ):
            value = threat.get(field)
            if not isinstance(value, str) or not value.strip():
                error(f"{threat_id}: {field} must be non-empty")

        if threat.get("findingType") == "implementation-defect":
            threat_evidence_ids = as_string_list(threat.get("evidenceIds")) or []
            evidence_types = {
                evidence[evidence_id].get("type")
                for evidence_id in threat_evidence_ids
                if evidence_id in evidence
            }
            if not evidence_types.intersection(IMPLEMENTATION_EVIDENCE_TYPES):
                error(
                    f"{threat_id}: implementation-defect requires implementation "
                    "or runtime evidence"
                )

        check_triage(threat_id, threat, evidence, set(threat_index), error)

    expected_order = sorted(
        coverage,
        key=lambda item: (
            natural_key(str(item.get("targetId", ""))),
            CATEGORY_ORDER.get(str(item.get("category", "")), len(CATEGORIES)),
        ),
    )
    if coverage != expected_order:
        error("coverage must be sorted by natural target id and STRIDE order")

    required_targets = {
        element_id
        for element_id, element in elements.items()
        if element.get("material") is True
    }
    required_targets.update(
        flow_id
        for flow_id, flow in flows.items()
        if flow.get("material") is True and flow.get("crossesTrustBoundary") is True
    )

    seen_cells: set[tuple[str, str]] = set()
    for position, cell in enumerate(coverage):
        target_id = cell.get("targetId")
        category = cell.get("category")
        owner = f"coverage[{position}]({target_id},{category})"
        if not isinstance(target_id, str):
            error(f"{owner}: targetId must be a string")
            continue
        if not isinstance(category, str) or category not in CATEGORIES:
            error(f"{owner}: invalid category")
            continue
        if target_id not in required_targets:
            error(f"{owner}: target is not a required material coverage target")

        key = (target_id, category)
        if key in seen_cells:
            error(f"{owner}: duplicate coverage cell")
        seen_cells.add(key)
        check_evidence_ids(owner, cell)

        disposition = cell.get("disposition")
        threat_refs = as_string_list(cell.get("threatIds"))
        if threat_refs is None:
            error(f"{owner}: threatIds must be a string array")
            threat_refs = []
        if disposition == "applicable" and not threat_refs:
            error(f"{owner}: applicable coverage requires a threat id")
        elif disposition == "not-applicable" and threat_refs:
            error(f"{owner}: not-applicable coverage cannot reference threats")
        elif disposition not in {"applicable", "not-applicable"}:
            error(f"{owner}: invalid disposition {disposition!r}")
        rationale = cell.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            error(f"{owner}: rationale must be non-empty")

        for threat_ref in threat_refs:
            referenced_threat = threat_index.get(threat_ref)
            if referenced_threat is None:
                error(f"{owner}: unknown threat id {threat_ref!r}")
                continue
            if referenced_threat.get("category") != category:
                error(f"{owner}: {threat_ref} has a different category")
            target_ids = as_string_list(referenced_threat.get("targetIds")) or []
            if target_id not in target_ids:
                error(f"{owner}: {threat_ref} does not include target {target_id}")

    required_cells = {
        (target_id, category)
        for target_id in required_targets
        for category in CATEGORIES
    }
    missing_cells = sorted(
        required_cells - seen_cells,
        key=lambda item: (natural_key(item[0]), CATEGORY_ORDER[item[1]]),
    )
    if missing_cells:
        error(f"missing required coverage cells: {missing_cells}")

    check_coverage_threat_agreement(coverage, threat_index, error)

    counts: Counter[str] = Counter()
    for threat in threat_index.values():
        level = threat.get("level")
        if isinstance(level, str):
            counts[level] += 1
    expected_counts = {level: counts[level] for level in LEVELS}
    summary = as_object(root.get("summary"))
    actual_counts = summary.get("riskCounts") if summary is not None else None
    if actual_counts != expected_counts:
        error(
            f"summary.riskCounts must equal canonical threat counts {expected_counts}"
        )

    return errors


def load_document(path: Path) -> JsonObject:
    """Load one top-level JSON object."""
    value: object = json.loads(path.read_text(encoding="utf-8"))
    document = as_object(value)
    if document is None:
        raise ValueError("top level must be a JSON object")
    return document


def run_self_test() -> int:
    """Exercise one valid fixture and one intentional invariant violation."""
    fixture = Path(__file__).resolve().parents[1] / "assets" / "analysis.example.json"
    document = load_document(fixture)
    valid_errors = validate_document(document)
    if valid_errors:
        print("SELF-TEST FAILED: valid fixture was rejected", file=sys.stderr)
        for message in valid_errors:
            print(f"ERROR: {message}", file=sys.stderr)
        return 1

    invalid = copy.deepcopy(document)
    invalid_threats = as_object_list(invalid.get("threats"))
    if not invalid_threats:
        print("SELF-TEST FAILED: fixture has no threats", file=sys.stderr)
        return 1
    invalid_threats[0]["score"] = 25
    invalid_errors = validate_document(invalid)
    if not any("score must equal" in message for message in invalid_errors):
        print("SELF-TEST FAILED: invalid score was accepted", file=sys.stderr)
        return 1

    invalid_origin = copy.deepcopy(document)
    invalid_origin_threats = as_object_list(invalid_origin.get("threats")) or []
    invalid_origin_threats[0].pop("origin", None)
    invalid_origin_errors = validate_document(invalid_origin)
    if not any("invalid origin" in message for message in invalid_origin_errors):
        print("SELF-TEST FAILED: missing threat origin was accepted", file=sys.stderr)
        return 1

    invalid_scope = copy.deepcopy(document)
    invalid_scope_object = as_object(invalid_scope.get("scope")) or {}
    invalid_scope_inputs = as_object_list(invalid_scope_object.get("inputs")) or []
    for scope_input in invalid_scope_inputs:
        scope_input["role"] = "supporting"
    invalid_scope_errors = validate_document(invalid_scope)
    if not any("at least one primary" in message for message in invalid_scope_errors):
        print("SELF-TEST FAILED: missing primary scope was accepted", file=sys.stderr)
        return 1

    invalid_control = copy.deepcopy(document)
    invalid_control_threats = as_object_list(invalid_control.get("threats")) or []
    invalid_controls = (
        as_object_list(invalid_control_threats[0].get("currentControls"))
        if invalid_control_threats
        else []
    )
    if not invalid_controls:
        print("SELF-TEST FAILED: fixture has no current control", file=sys.stderr)
        return 1
    invalid_controls[0].pop("gap", None)
    invalid_control_errors = validate_document(invalid_control)
    if not any("control requires gap" in message for message in invalid_control_errors):
        print(
            "SELF-TEST FAILED: partial control without gap was accepted",
            file=sys.stderr,
        )
        return 1

    invalid_actor = copy.deepcopy(document)
    invalid_actors = as_object_list(invalid_actor.get("threatActors")) or []
    if not invalid_actors:
        print("SELF-TEST FAILED: fixture has no threat actor", file=sys.stderr)
        return 1
    invalid_actors[0]["targetAssetIds"] = ["AS999"]
    invalid_actor_errors = validate_document(invalid_actor)
    if not any("unknown asset ids" in message for message in invalid_actor_errors):
        print(
            "SELF-TEST FAILED: unknown threat-actor asset was accepted", file=sys.stderr
        )
        return 1

    invalid_triage = copy.deepcopy(document)
    invalid_triage_threats = as_object_list(invalid_triage.get("threats")) or []
    invalid_triage_entries = as_object_list(invalid_triage_threats[0].get("triage"))
    if not invalid_triage_entries:
        print("SELF-TEST FAILED: fixture has no triage entry", file=sys.stderr)
        return 1
    invalid_triage_entries[0]["decision"] = "resolved"
    invalid_triage_errors = validate_document(invalid_triage)
    if not any(
        "resolved decision requires evidenceIds" in message
        for message in invalid_triage_errors
    ):
        print(
            "SELF-TEST FAILED: resolved triage without evidence was accepted",
            file=sys.stderr,
        )
        return 1
    if not any(
        "resolved decision requires threat status" in message
        for message in invalid_triage_errors
    ):
        print(
            "SELF-TEST FAILED: resolved triage on an open threat was accepted",
            file=sys.stderr,
        )
        return 1

    invalid_duplicate = copy.deepcopy(document)
    invalid_duplicate_threats = as_object_list(invalid_duplicate.get("threats")) or []
    invalid_duplicate_entries = (
        as_object_list(invalid_duplicate_threats[0].get("triage")) or []
    )
    invalid_duplicate_entries[0]["decision"] = "duplicate"
    invalid_duplicate_errors = validate_document(invalid_duplicate)
    if not any(
        "duplicate decision requires relatedThreatIds" in message
        for message in invalid_duplicate_errors
    ):
        print(
            "SELF-TEST FAILED: duplicate triage without a related threat was accepted",
            file=sys.stderr,
        )
        return 1

    invalid_self_reference = copy.deepcopy(document)
    invalid_self_threats = as_object_list(invalid_self_reference.get("threats")) or []
    invalid_self_entries = as_object_list(invalid_self_threats[0].get("triage")) or []
    invalid_self_entries[0]["relatedThreatIds"] = [str(invalid_self_threats[0]["id"])]
    invalid_self_errors = validate_document(invalid_self_reference)
    if not any(
        "must not name its own threat" in message for message in invalid_self_errors
    ):
        print(
            "SELF-TEST FAILED: self-referential triage was accepted",
            file=sys.stderr,
        )
        return 1

    invalid_triage_date = copy.deepcopy(document)
    invalid_date_threats = as_object_list(invalid_triage_date.get("threats")) or []
    invalid_date_entries = as_object_list(invalid_date_threats[0].get("triage")) or []
    invalid_date_entries[0]["date"] = "2026-02-30"
    invalid_date_errors = validate_document(invalid_triage_date)
    if not any(
        "is not a real calendar date" in message for message in invalid_date_errors
    ):
        print("SELF-TEST FAILED: impossible triage date was accepted", file=sys.stderr)
        return 1

    invalid_evidence_type = copy.deepcopy(document)
    invalid_evidence_items = as_object_list(invalid_evidence_type.get("evidence")) or []
    invalid_evidence_items[0]["type"] = "design-doc"
    invalid_evidence_errors = validate_document(invalid_evidence_type)
    if not any("invalid type" in message for message in invalid_evidence_errors):
        print(
            "SELF-TEST FAILED: evidence type outside the vocabulary was accepted",
            file=sys.stderr,
        )
        return 1

    invalid_axis = copy.deepcopy(document)
    invalid_axis_boundaries = as_object_list(invalid_axis.get("boundaries")) or []
    invalid_axis_boundaries[0]["axis"] = "trust"
    if not any("axis must be one of" in m for m in validate_document(invalid_axis)):
        print("SELF-TEST FAILED: unknown boundary axis was accepted", file=sys.stderr)
        return 1

    empty_boundary = copy.deepcopy(document)
    for element in as_object_list(empty_boundary.get("elements")) or []:
        element["boundaryIds"] = []
    if not any(
        "has no member elements" in m for m in validate_document(empty_boundary)
    ):
        print("SELF-TEST FAILED: empty boundary was accepted", file=sys.stderr)
        return 1

    missing_placement = copy.deepcopy(document)
    for element in as_object_list(missing_placement.get("elements")) or []:
        element.pop("placementEvidenceIds", None)
    if not any(
        "placementEvidenceIds must be a non-empty" in m
        for m in validate_document(missing_placement)
    ):
        print(
            "SELF-TEST FAILED: process without placement evidence was accepted",
            file=sys.stderr,
        )
        return 1

    stale_crossing = copy.deepcopy(document)
    stale_flows = as_object_list(stale_crossing.get("flows")) or []
    stale_flows[0]["crossesTrustBoundary"] = False
    if not any(
        "places the endpoints in different boundaries" in m
        for m in validate_document(stale_crossing)
    ):
        print(
            "SELF-TEST FAILED: understated boundary crossing was accepted",
            file=sys.stderr,
        )
        return 1

    unbacked_exemption = copy.deepcopy(document)
    unbacked_flows = as_object_list(unbacked_exemption.get("flows")) or []
    unbacked_flows[0]["crossesTrustBoundary"] = False
    unbacked_flows[0]["crossingExemptions"] = [
        {"boundaryId": "TB1", "rationale": "not really"}
    ]
    if not any(
        "evidenceIds must be a non-empty" in m
        for m in validate_document(unbacked_exemption)
    ):
        print(
            "SELF-TEST FAILED: crossing exemption without evidence was accepted",
            file=sys.stderr,
        )
        return 1

    dangling_exemption = copy.deepcopy(document)
    dangling_flows = as_object_list(dangling_exemption.get("flows")) or []
    dangling_flows[0]["crossesTrustBoundary"] = False
    dangling_flows[0]["crossingExemptions"] = [
        {"boundaryId": "TB1", "rationale": "not really", "evidenceIds": ["E999"]}
    ]
    if not any(
        "crossingExemptions[0]: unknown evidence ids" in m
        for m in validate_document(dangling_exemption)
    ):
        print(
            "SELF-TEST FAILED: crossing exemption citing unknown evidence was accepted",
            file=sys.stderr,
        )
        return 1

    print("OK: validator self-test passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ledger", nargs="?", type=Path)
    parser.add_argument(
        "--baseline",
        type=Path,
        help=(
            "previous revision of the same ledger; fails when a rebuild renumbered or "
            "reassigned any existing id"
        ),
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()
    if args.ledger is None:
        parser.error("ledger is required unless --self-test is used")

    try:
        document = load_document(args.ledger)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"INVALID: {args.ledger}: {exc}", file=sys.stderr)
        return 1

    errors = validate_document(document)
    if args.baseline is not None:
        try:
            baseline = load_document(args.baseline)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"INVALID: {args.baseline}: {exc}", file=sys.stderr)
            return 1
        check_id_stability(document, baseline, errors.append)
    if errors:
        for message in errors:
            print(f"ERROR: {message}", file=sys.stderr)
        print(f"INVALID: {len(errors)} error(s)", file=sys.stderr)
        return 1

    threats = as_object_list(document.get("threats")) or []
    summary = as_object(document.get("summary")) or {}
    print(
        json.dumps(
            {
                "valid": True,
                "ledger": str(args.ledger),
                "threatActorCount": len(
                    as_object_list(document.get("threatActors")) or []
                ),
                "threatCount": len(threats),
                "riskCounts": summary.get("riskCounts"),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
