#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import json
import random
import shlex
import subprocess
import sys
import tempfile
from itertools import permutations
from pathlib import Path
from typing import Any

import check_layout
from generate_suppressions import require_distinct_output, write_sidecar
from validate_analysis import as_object_list, display_id, load_document, page_views

ELEMENT_W = 190
ELEMENT_H = 70
PAD = 30  # boundary padding around its elements
COL_GAP = 110  # minimum horizontal gap between columns
ROW_GAP = 34  # vertical gap between elements inside a boundary
GROUP_GAP = 56  # vertical gap between boundaries stacked in one column
ORIGIN_X = 40
ORIGIN_Y = 40

# A flow's name is drawn as one unwrapped line centred on its connector, so the space it
# needs is a function of its text, not of the shapes it joins. At the Microsoft Threat
# Modeling Tool's default font a character is about this wide; a fifty-character name is
# therefore wider than a whole boundary column and will print across whatever it passes
# over unless the gap it spans is opened up to hold it.
LABEL_CHAR_W = 7
LABEL_H = 18
# Never widen a single gap past this. Beyond it the canvas runs into the tool's hard
# coordinate limit and the tool clamps shapes on load, which piles them on top of one
# another — a worse outcome than a label that overhangs. A name that needs more room than
# this has to be shortened instead; check_layout.py reports it.
MAX_COL_GAP = 420

# The tool clamps any shape drawn beyond these coordinates when it loads the file.
MAX_CANVAS_X = 1890
MAX_CANVAS_Y = 2090

# Permuting a group is factorial, so only search groups small enough to stay instant.
MAX_PERMUTATION_GROUP = 6
MAX_REFINEMENT_PASSES = 12


def _groups(elements: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Map each layout group to its member aliases.

    Only the first boundary is representable in a ``.tm7`` drawing surface, so an element
    is grouped by ``boundaryIds[0]``. An element in no boundary becomes its own group so
    it can still be placed and layered.
    """
    members: dict[str, list[str]] = {}
    for element in elements:
        boundary_ids = element.get("boundaryIds") or []
        group = boundary_ids[0] if boundary_ids else "_" + element["id"]
        members.setdefault(group, []).append(element["id"])
    for group in members:
        members[group].sort()
    return members


def _group_of(members: dict[str, list[str]]) -> dict[str, str]:
    return {alias: group for group, aliases in members.items() for alias in aliases}


def derive_columns(
    members: dict[str, list[str]],
    edges: list[tuple[str, str]],
    *,
    rng: random.Random | None = None,
) -> list[list[str]]:
    """Layer groups left to right by following flow direction between them.

    Cycles are broken by dropping back edges in a deterministic depth-first walk, then
    each group is placed one column right of its furthest upstream neighbour. The result
    reads as the direction data actually travels rather than an arbitrary order.
    """
    owner = _group_of(members)
    adjacency: dict[str, set[str]] = {group: set() for group in members}
    for source, target in edges:
        source_group, target_group = owner.get(source), owner.get(target)
        if source_group and target_group and source_group != target_group:
            adjacency[source_group].add(target_group)

    state: dict[str, int] = {group: 0 for group in members}
    acyclic: dict[str, set[str]] = {group: set() for group in members}

    def walk(group: str) -> None:
        state[group] = 1
        neighbours = sorted(adjacency[group])
        if rng is not None:
            rng.shuffle(neighbours)
        for neighbour in neighbours:
            if state[neighbour] == 1:
                continue  # back edge: dropping it breaks the cycle
            acyclic[group].add(neighbour)
            if state[neighbour] == 0:
                walk(neighbour)
        state[group] = 2

    roots = sorted(members)
    if rng is not None:
        rng.shuffle(roots)
    for group in roots:
        if state[group] == 0:
            walk(group)

    layer: dict[str, int] = {group: 0 for group in members}
    for _ in range(len(members)):
        changed = False
        for group in sorted(members):
            for neighbour in sorted(acyclic[group]):
                if layer[neighbour] < layer[group] + 1:
                    layer[neighbour] = layer[group] + 1
                    changed = True
        if not changed:
            break

    columns: dict[int, list[str]] = {}
    for group in sorted(members):
        columns.setdefault(layer[group], []).append(group)
    return [columns[index] for index in sorted(columns)]


def _label_width(flow: dict[str, Any]) -> float:
    """Width of the text a flow is drawn with, in drawing units.

    The diagram label uses the page-local displayId when present, otherwise id.
    """
    identifier = display_id(flow)
    name = str(flow.get("name") or "")
    label = f"{identifier}: {name}" if identifier and name else (identifier or name)
    return len(label) * LABEL_CHAR_W


def column_gaps(
    members: dict[str, list[str]], columns: list[list[str]], flows: list[dict[str, Any]]
) -> list[float]:
    """Width of the gap after each column, widened to hold the labels that span it.

    A flow between neighbouring columns has its name printed at the midpoint between the
    two shapes, so the text clears both of them only when the gap is at least as wide as
    the label less the boundary padding either side. Gaps are capped so wide columns can
    wrap; slot refinement and the native label placer handle remaining obstructions.
    """
    owner = _group_of(members)
    index_of = {
        group: index for index, column in enumerate(columns) for group in column
    }
    gaps = [float(COL_GAP)] * max(0, len(columns) - 1)
    for flow in flows:
        source = index_of.get(owner.get(flow.get("sourceId", ""), ""))
        target = index_of.get(owner.get(flow.get("targetId", ""), ""))
        if source is None or target is None:
            continue
        first, last = sorted((source, target))
        span = last - first
        if span == 0:
            continue
        required = _label_width(flow) - 2 * PAD - (span - 1) * (ELEMENT_W + 2 * PAD)
        per_gap = min(required / span, float(MAX_COL_GAP))
        for gap_index in range(first, last):
            gaps[gap_index] = max(gaps[gap_index], per_gap)
    return gaps


def _column_height(column: list[str], members: dict[str, list[str]]) -> float:
    total = 0.0
    for group in column:
        count = len(members.get(group, []))
        total += count * ELEMENT_H + max(0, count - 1) * ROW_GAP + 2 * PAD
    return total + max(0, len(column) - 1) * GROUP_GAP


def _place(
    order: dict[str, list[str]],
    members: dict[str, list[str]],
    columns: list[list[str]],
    gaps: list[float] | None = None,
) -> dict[str, tuple[float, float, float, float]]:
    """Compute rectangles, wrapping complete columns before the canvas edge."""
    boxes: dict[str, tuple[float, float, float, float]] = {}
    width = ELEMENT_W + 2 * PAD
    rows: list[list[int]] = [[]]
    column_x = float(ORIGIN_X)
    for index in range(len(columns)):
        if rows[-1] and column_x + width > MAX_CANVAS_X:
            rows.append([])
            column_x = float(ORIGIN_X)
        rows[-1].append(index)
        gap = gaps[index] if gaps and index < len(gaps) else float(COL_GAP)
        column_x += width + gap
    row_y = float(ORIGIN_Y)
    for row in rows:
        row_height = max(
            (_column_height(columns[index], members) for index in row), default=0.0
        )
        column_x = float(ORIGIN_X)
        for index in row:
            stack = order.get(f"__col{index}", columns[index])
            heights = [
                len(members[group]) * ELEMENT_H
                + max(0, len(members[group]) - 1) * ROW_GAP
                + 2 * PAD
                for group in stack
            ]
            total = sum(heights) + max(0, len(stack) - 1) * GROUP_GAP
            group_y = row_y + (row_height - total) / 2
            for group, height in zip(stack, heights):
                if not group.startswith("_"):
                    boxes[group] = (column_x, group_y, width, height)
                element_y = group_y + PAD
                for alias in order.get(group, members[group]):
                    boxes[alias] = (
                        column_x + PAD,
                        element_y,
                        float(ELEMENT_W),
                        float(ELEMENT_H),
                    )
                    element_y += ELEMENT_H + ROW_GAP
                group_y += height + GROUP_GAP
            gap = gaps[index] if gaps and index < len(gaps) else float(COL_GAP)
            column_x += width + gap
        row_y += row_height + GROUP_GAP
    return boxes


def _centre(box: tuple[float, float, float, float]) -> tuple[float, float]:
    x, y, width, height = box
    return x + width / 2.0, y + height / 2.0


def label_obstructions(
    elements: list[dict[str, Any]],
    flows: list[dict[str, Any]],
    boxes: dict[str, tuple[float, float, float, float]],
) -> list[str]:
    failures: list[str] = []
    for flow in flows:
        source = boxes.get(flow.get("sourceId", ""))
        target = boxes.get(flow.get("targetId", ""))
        if source is None or target is None:
            continue
        source_x, source_y = _centre(source)
        target_x, target_y = _centre(target)
        half_width = _label_width(flow) / 2
        if half_width == 0:
            continue
        centre_x, centre_y = (source_x + target_x) / 2, (source_y + target_y) / 2
        for element in elements:
            box = boxes.get(element["id"])
            if box is None:
                continue
            left, top, width, height = box
            if (
                centre_x - half_width < left + width
                and left < centre_x + half_width
                and centre_y - LABEL_H / 2 < top + height
                and top < centre_y + LABEL_H / 2
            ):
                failures.append(
                    f"flow {flow.get('id') or flow.get('name')!r} label overlaps {element['id']} in the straight-line layout; "
                    "try seeded restarts, tmforge layout --labels on the candidate, "
                    "or declared page-local views"
                )
    return sorted(set(failures))


def _crosses(
    a: tuple[tuple[float, float], tuple[float, float]],
    b: tuple[tuple[float, float], tuple[float, float]],
) -> bool:
    (x1, y1), (x2, y2) = a
    (x3, y3), (x4, y4) = b
    if len({(x1, y1), (x2, y2), (x3, y3), (x4, y4)}) < 4:
        return False  # segments sharing an endpoint meet at a shape, not a crossing

    def side(ax: float, ay: float, bx: float, by: float, cx: float, cy: float) -> float:
        return (bx - ax) * (cy - ay) - (by - ay) * (cx - ax)

    d1 = side(x3, y3, x4, y4, x1, y1)
    d2 = side(x3, y3, x4, y4, x2, y2)
    d3 = side(x1, y1, x2, y2, x3, y3)
    d4 = side(x1, y1, x2, y2, x4, y4)
    return ((d1 > 0) != (d2 > 0)) and ((d3 > 0) != (d4 > 0))


def _score(
    order: dict[str, list[str]],
    members: dict[str, list[str]],
    columns: list[list[str]],
    edges: list[tuple[str, str]],
    gaps: list[float] | None = None,
    elements: list[dict[str, Any]] | None = None,
    flows: list[dict[str, Any]] | None = None,
) -> tuple[int, int, float]:
    boxes = _place(order, members, columns, gaps)
    segments = [
        (_centre(boxes[source]), _centre(boxes[target]))
        for source, target in edges
        if source in boxes and target in boxes
    ]
    crossings = 0
    length = 0.0
    for index, segment in enumerate(segments):
        (ax, ay), (bx, by) = segment
        length += abs(ax - bx) + abs(ay - by)
        for other in segments[index + 1 :]:
            if _crosses(segment, other):
                crossings += 1
    obstructions = len(label_obstructions(elements or [], flows or [], boxes))
    return obstructions, crossings, round(length, 3)


def _refine(
    order: dict[str, list[str]],
    members: dict[str, list[str]],
    columns: list[list[str]],
    edges: list[tuple[str, str]],
    gaps: list[float] | None = None,
    elements: list[dict[str, Any]] | None = None,
    flows: list[dict[str, Any]] | None = None,
) -> tuple[int, int, float]:
    """Descend to a local optimum by permuting one group at a time, in place."""
    best = _score(order, members, columns, edges, gaps, elements, flows)
    for _ in range(MAX_REFINEMENT_PASSES):
        improved = False
        keys = sorted(key for key in order if not key.startswith("__col"))
        keys += sorted(key for key in order if key.startswith("__col"))
        for key in keys:
            current = order[key]
            if not 2 <= len(current) <= MAX_PERMUTATION_GROUP:
                continue
            for candidate in sorted(permutations(current)):
                if list(candidate) == current:
                    continue
                order[key] = list(candidate)
                score = _score(order, members, columns, edges, gaps, elements, flows)
                if score < best:
                    best, current, improved = score, list(candidate), True
                order[key] = current
        if not improved:
            break
    return best


def compute(
    elements: list[dict[str, Any]],
    flows: list[dict[str, Any]],
    columns: list[list[str]] | None = None,
    restarts: int = 0,
    seed: int = 0,
) -> tuple[dict[str, tuple[float, float, float, float]], tuple[int, float]]:
    """Return ``({alias: (x, y, width, height)}, (crossings, length))``.

    Pass ``columns`` to override the derived layering when a specific narrative order
    reads better than the one implied by flow direction. Complete columns wrap before
    the canvas edge; label-on-shape collisions are minimized before crossings and length.

    Restarts vary cycle-breaking and column assignment as well as within-group order.
    Explicit columns remain fixed. The baseline is always a candidate, so more restarts
    cannot worsen the score for a fixed seed. Repeated output is deterministic but does
    not prove optimality or that remaining crossings are inherent in the topology.
    """
    members = _groups(elements)
    edges = [(flow["sourceId"], flow["targetId"]) for flow in flows]
    automatic_columns = columns is None
    if columns is None:
        columns = derive_columns(members, edges)
    else:
        columns = [
            [group for group in column if group in members] for column in columns
        ]
        placed = {group for column in columns for group in column}
        missing = sorted(set(members) - placed)
        if missing:
            columns = columns + [missing]

    order: dict[str, list[str]] = {
        group: list(aliases) for group, aliases in members.items()
    }
    for index, column in enumerate(columns):
        order[f"__col{index}"] = list(column)

    gaps = column_gaps(members, columns, flows)
    best = _refine(order, members, columns, edges, gaps, elements, flows)
    best_order = {key: list(value) for key, value in order.items()}
    best_columns, best_gaps = columns, gaps

    if restarts > 0:
        rng = random.Random(seed)
        for _ in range(restarts):
            candidate_columns = (
                derive_columns(members, edges, rng=rng)
                if automatic_columns
                else columns
            )
            candidate = {key: list(members[key]) for key in sorted(members)}
            for index, column in enumerate(candidate_columns):
                candidate[f"__col{index}"] = list(column)
            for key in sorted(candidate):
                rng.shuffle(candidate[key])
            candidate_gaps = column_gaps(members, candidate_columns, flows)
            score = _refine(
                candidate,
                members,
                candidate_columns,
                edges,
                candidate_gaps,
                elements,
                flows,
            )
            if score < best:
                best = score
                best_order = {key: list(value) for key, value in candidate.items()}
                best_columns, best_gaps = candidate_columns, candidate_gaps

    return _place(best_order, members, best_columns, best_gaps), (best[1], best[2])


def compute_pages(
    document: dict[str, Any],
    restarts: int = 0,
    seed: int = 0,
    page: str | None = None,
) -> list[dict[str, Any]]:
    """Lay out declared pages independently; a selector accepts an id, name, or index."""
    views = page_views(document)
    if page is not None:
        matches = [
            (metadata, view)
            for index, (metadata, view) in enumerate(views, start=1)
            if (page.isdigit() and int(page) == index)
            or (
                not page.isdigit()
                and page in (metadata.get("id"), metadata.get("name", "Diagram 1"))
            )
        ]
        if len(matches) != 1:
            raise ValueError(
                f"unknown or ambiguous page {page!r}; use a declared page id or one-based index"
            )
        views = matches
    layouts: list[dict[str, Any]] = []
    for metadata, view in views:
        elements = as_object_list(view.get("elements")) or []
        flows = as_object_list(view.get("flows")) or []
        boxes, (crossings, length) = compute(
            elements, flows, restarts=restarts, seed=seed
        )
        width = max((box[0] + box[2] for box in boxes.values()), default=0.0)
        height = max((box[1] + box[3] for box in boxes.values()), default=0.0)
        warnings = label_obstructions(elements, flows, boxes)
        if width > MAX_CANVAS_X or height > MAX_CANVAS_Y:
            warnings.append(
                f"canvas exceeds the tool's limit of {MAX_CANVAS_X}x{MAX_CANVAS_Y} "
                "after column wrapping; the tool clamps out-of-range shapes on load. "
                "Declare page-local views in pages/pageId, or reduce diagram label length; "
                "do not drop model content to fit."
            )
        layouts.append(
            {
                "id": metadata.get("id", ""),
                "name": metadata.get("name", "Diagram 1"),
                "boxes": boxes,
                "width": width,
                "height": height,
                "crossings": crossings,
                "length": length,
                "warnings": warnings,
            }
        )
    return layouts


def manifest_with_layout(
    document: dict[str, Any], manifest: dict[str, Any], layouts: list[dict[str, Any]]
) -> dict[str, Any]:
    """Refresh an existing manifest without dropping controls, stencils, or topology."""
    if manifest.get("schema", "tmforge-manifest") != "tmforge-manifest":
        raise ValueError("--manifest must name a tmforge authoring manifest")
    result = copy.deepcopy(manifest)
    boxes = {alias: box for layout in layouts for alias, box in layout["boxes"].items()}
    for kind in ("boundaries", "elements", "flows"):
        canonical = {item["id"]: item for item in document.get(kind, [])}
        items = result.get(kind, [])
        aliases = [item.get("alias") for item in items]
        if len(aliases) != len(set(aliases)) or set(aliases) != set(canonical):
            raise ValueError(
                f"manifest {kind} aliases must exactly match the ledger; no objects are added or removed by layout"
            )
        for item in items:
            alias = item["alias"]
            source = canonical[alias]
            expected_name = f"{display_id(source)}: {source['name']}"
            if item.get("name") != expected_name:
                raise ValueError(
                    f"manifest {alias} name must be {expected_name!r}; ledger names hold the bare phrase"
                )
            if kind == "flows":
                if (
                    item.get("from") != source["sourceId"]
                    or item.get("to") != source["targetId"]
                ):
                    raise ValueError(
                        f"manifest flow {alias} endpoints differ from the ledger"
                    )
                continue
            if kind == "elements" and item.get("boundary") != next(
                iter(source.get("boundaryIds", [])), None
            ):
                raise ValueError(
                    f"manifest element {alias} boundary differs from the ledger's first boundary"
                )
            if alias not in boxes:
                raise ValueError(
                    f"no generated geometry for {alias}; layout projects the first boundary of each element"
                )
            item.update(
                zip(
                    ("x", "y", "width", "height"),
                    (round(value) for value in boxes[alias]),
                )
            )
            if document.get("pages"):
                item["page"] = source["pageId"]
            elif "page" in item:
                raise ValueError(
                    "declare ledger pages before refreshing a page-assigned manifest"
                )
    if document.get("pages"):
        previous_pages = {page["alias"]: page for page in result.get("pages", [])}
        page_ids = {page["id"] for page in document["pages"]}
        if set(previous_pages) - page_ids:
            raise ValueError(
                "manifest contains pages absent from the ledger; layout will not remove them"
            )
        result["pages"] = [
            {
                **previous_pages.get(page["id"], {}),
                "alias": page["id"],
                "name": page["name"],
            }
            for page in document["pages"]
        ]
    elif result.get("pages"):
        raise ValueError("declare ledger pages before refreshing a multi-page manifest")
    return result


def native_layout_report(
    manifest: dict[str, Any], analysis: Path, invocation: list[str]
) -> dict[str, Any]:
    """Measure a disposable native artifact using the selected CLI, never a global fallback."""
    with tempfile.TemporaryDirectory(prefix="tmforge-layout-") as temporary:
        directory = Path(temporary).resolve()
        source, model = directory / "model.tm.json", directory / "model.tm7"
        write_sidecar(source, manifest)
        try:
            result = subprocess.run(
                [*invocation, "apply", str(source), "--out", str(model)],
                capture_output=True,
                text=True,
                check=False,
                timeout=300,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"native layout evaluation failed: {exc}") from exc
        if result.returncode != 0:
            raise ValueError(
                f"native layout apply failed ({result.returncode}): {(result.stderr or result.stdout).strip()[-2000:]}"
            )
        return check_layout.check(model, analysis)


def native_layout_metrics(report: dict[str, Any]) -> tuple[float, ...]:
    """Compare each page separately so a regression cannot hide behind another page."""
    return tuple(
        float(value)
        for page in report.get("pages", [report])
        for value in (
            len(page["failures"]),
            page["obstructedLabels"],
            page["crossings"],
            page["canvas"]["width"],
            page["canvas"]["height"],
        )
    )


def select_native_layout(
    baseline: dict[str, Any],
    restarted: dict[str, Any],
    analysis: Path,
    invocation: list[str],
) -> tuple[bool, dict[str, Any]]:
    """Accept a restarted artifact only when its measured layout does not regress."""
    baseline_report = native_layout_report(baseline, analysis, invocation)
    restarted_report = (
        native_layout_report(restarted, analysis, invocation)
        if restarted != baseline
        else baseline_report
    )
    baseline_metrics = native_layout_metrics(baseline_report)
    restarted_metrics = native_layout_metrics(restarted_report)
    improved = (
        not restarted_report["failures"]
        and len(baseline_metrics) == len(restarted_metrics)
        and all(
            after <= before
            for before, after in zip(baseline_metrics, restarted_metrics)
        )
        and restarted_metrics != baseline_metrics
    )
    selected = restarted_report if improved else baseline_report
    if selected["failures"]:
        raise ValueError(
            "native layout check failed: " + "; ".join(selected["failures"])
        )
    return improved, {
        "selected": "restarted" if improved else "unseeded",
        "unseeded": {
            "crossings": baseline_report["crossings"],
            "obstructedLabels": baseline_report["obstructedLabels"],
            "canvas": baseline_report["canvas"],
        },
        "restarted": {
            "crossings": restarted_report["crossings"],
            "obstructedLabels": restarted_report["obstructedLabels"],
            "canvas": restarted_report["canvas"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Preview derived layout for a ledger.")
    parser.add_argument("analysis", type=Path, help="path to analysis.json")
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="emit geometry as JSON")
    output.add_argument(
        "--manifest",
        type=Path,
        help="refresh geometry and pages in an existing manifest, preserving its other fields",
    )
    parser.add_argument(
        "--out",
        type=Path,
        help="atomically write the refreshed manifest; otherwise emit it on stdout",
    )
    parser.add_argument(
        "--page", help="lay out one page by id, name, or one-based index"
    )
    parser.add_argument(
        "--strict", action="store_true", help="exit 1 when layout warnings remain"
    )
    parser.add_argument(
        "--restarts",
        type=int,
        default=0,
        help="seeded restarts to escape a local optimum; deterministic for a given seed",
    )
    parser.add_argument(
        "--seed", type=int, default=0, help="seed for --restarts; fixed output per seed"
    )
    parser.add_argument(
        "--tmforge",
        help="explicit CLI command for native layout checks; required for restarted manifest output",
    )
    args = parser.parse_args()
    if args.restarts < 0:
        parser.error("--restarts must not be negative")
    if args.out is not None and args.manifest is None:
        parser.error("--out requires --manifest")
    if args.manifest is not None and args.page is not None:
        parser.error("--manifest refreshes all pages; --page is for layout previews")
    if args.manifest is not None and args.restarts and args.tmforge is None:
        parser.error(
            "--manifest with --restarts requires --tmforge to compare native artifacts"
        )
    if args.tmforge is not None and args.manifest is None:
        parser.error("--tmforge requires --manifest")
    try:
        ledger = load_document(args.analysis)
        layouts = compute_pages(ledger, args.restarts, args.seed, args.page)
        template = load_document(args.manifest) if args.manifest is not None else None
        candidate = (
            manifest_with_layout(ledger, template, layouts)
            if template is not None
            else None
        )
        if args.out is not None:
            require_distinct_output(args.out, (args.analysis,))
        if args.tmforge is not None and template is not None and candidate is not None:
            invocation = shlex.split(args.tmforge)
            if not invocation:
                raise ValueError("--tmforge must not be empty")
            baseline_layouts = (
                compute_pages(ledger, seed=args.seed) if args.restarts else layouts
            )
            baseline = manifest_with_layout(ledger, template, baseline_layouts)
            use_restarted, comparison = select_native_layout(
                baseline, candidate, args.analysis, invocation
            )
            if not use_restarted:
                candidate, layouts = baseline, baseline_layouts
            print(
                "Native layout comparison: " + json.dumps(comparison, sort_keys=True),
                file=sys.stderr,
            )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if candidate is not None:
        if args.out is None:
            print(json.dumps(candidate, indent=2))
    elif args.json:
        result = {"pages": layouts} if ledger.get("pages") else layouts[0]["boxes"]
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        for layout in layouts:
            if ledger.get("pages"):
                print(f"{layout['id']}: {layout['name']}")
            print(
                f"{len(layout['boxes'])} shapes, canvas {layout['width']:.0f}x{layout['height']:.0f}"
            )
            print(
                f"predicted crossings: {layout['crossings']}, total edge length: {layout['length']:.0f}"
            )
    for layout in layouts:
        prefix = f"{layout['id']}: {layout['name']}: " if ledger.get("pages") else ""
        for warning in layout["warnings"]:
            print(f"WARNING: {prefix}{warning}", file=sys.stderr)
    if args.strict and any(layout["warnings"] for layout in layouts):
        return 1
    if candidate is not None and args.out is not None:
        try:
            write_sidecar(args.out, candidate)
        except (OSError, ValueError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        print(f"Wrote layout to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
