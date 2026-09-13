#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
import sys
from itertools import permutations
from pathlib import Path

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


def _groups(elements: list[dict]) -> dict[str, list[str]]:
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
    members: dict[str, list[str]], edges: list[tuple[str, str]]
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
        for neighbour in sorted(adjacency[group]):
            if state[neighbour] == 1:
                continue  # back edge: dropping it breaks the cycle
            acyclic[group].add(neighbour)
            if state[neighbour] == 0:
                walk(neighbour)
        state[group] = 2

    for group in sorted(members):
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


def _label_width(flow: dict) -> float:
    """Width of the text a flow is drawn with, in drawing units.

    The diagram label is the stable id joined to the flow name, which is what the manifest
    writes as the connector's ``name`` and what the tool prints on the connector.
    """
    identifier = str(flow.get("id") or "")
    name = str(flow.get("name") or "")
    label = f"{identifier}: {name}" if identifier and name else (identifier or name)
    return len(label) * LABEL_CHAR_W


def column_gaps(
    members: dict[str, list[str]], columns: list[list[str]], flows: list[dict]
) -> list[float]:
    """Width of the gap after each column, widened to hold the labels that span it.

    A flow between neighbouring columns has its name printed at the midpoint between the
    two shapes, so the text clears both of them only when the gap is at least as wide as
    the label less the boundary padding either side. Sizing the gap from the labels is the
    only way a hand-carried geometry can be legible; the alternative is to shorten the
    names, which is what the cap here forces once a label stops being a label.
    """
    owner = _group_of(members)
    index_of = {group: index for index, column in enumerate(columns) for group in column}
    gaps = [float(COL_GAP)] * max(0, len(columns) - 1)
    for flow in flows:
        source = index_of.get(owner.get(flow.get("sourceId", ""), ""))
        target = index_of.get(owner.get(flow.get("targetId", ""), ""))
        if source is None or target is None:
            continue
        first, last = sorted((source, target))
        if last - first != 1:
            continue  # only a neighbouring pair pins one gap unambiguously
        required = _label_width(flow) - 2 * PAD
        gaps[first] = max(gaps[first], min(required, float(MAX_COL_GAP)))
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
    """Compute rectangles for one candidate ordering."""
    boxes: dict[str, tuple[float, float, float, float]] = {}
    canvas_height = max(
        (_column_height(column, members) for column in columns), default=0.0
    )
    x = float(ORIGIN_X)
    for index, column in enumerate(columns):
        stack = order.get(f"__col{index}", column)
        heights = []
        for group in stack:
            count = len(members.get(group, []))
            heights.append(count * ELEMENT_H + max(0, count - 1) * ROW_GAP + 2 * PAD)
        total = sum(heights) + max(0, len(stack) - 1) * GROUP_GAP
        y = ORIGIN_Y + (canvas_height - total) / 2
        width = ELEMENT_W + 2 * PAD
        for group, height in zip(stack, heights):
            if not group.startswith("_"):
                boxes[group] = (x, y, width, height)
            element_y = y + PAD
            for alias in order.get(group, members.get(group, [])):
                boxes[alias] = (x + PAD, element_y, float(ELEMENT_W), float(ELEMENT_H))
                element_y += ELEMENT_H + ROW_GAP
            y += height + GROUP_GAP
        gap = gaps[index] if gaps and index < len(gaps) else float(COL_GAP)
        x += width + gap
    return boxes


def _centre(box: tuple[float, float, float, float]) -> tuple[float, float]:
    x, y, width, height = box
    return x + width / 2.0, y + height / 2.0


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
) -> tuple[int, float]:
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
    # Crossings dominate; total edge length breaks ties toward tighter routing.
    return crossings, round(length, 3)


def _refine(
    order: dict[str, list[str]],
    members: dict[str, list[str]],
    columns: list[list[str]],
    edges: list[tuple[str, str]],
    gaps: list[float] | None = None,
) -> tuple[int, float]:
    """Descend to a local optimum by permuting one group at a time, in place."""
    best = _score(order, members, columns, edges, gaps)
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
                score = _score(order, members, columns, edges, gaps)
                if score < best:
                    best, current, improved = score, list(candidate), True
                order[key] = current
        if not improved:
            break
    return best


def compute(
    elements: list[dict],
    flows: list[dict],
    columns: list[list[str]] | None = None,
    restarts: int = 0,
    seed: int = 0,
) -> tuple[dict[str, tuple[float, float, float, float]], tuple[int, float]]:
    """Return ``({alias: (x, y, width, height)}, (crossings, length))``.

    Pass ``columns`` to override the derived layering when a specific narrative order
    reads better than the one implied by flow direction.

    Descent from the sorted order reaches a local optimum, and a group larger than
    ``MAX_PERMUTATION_GROUP`` is never permuted at all, so a lower-crossing arrangement
    can remain unreachable. Pass ``restarts`` to descend again from that many seeded
    shuffles and keep the best result. The seed is fixed, so the output stays
    deterministic and a rendered diagram does not churn between runs. Use a small value
    while iterating and a larger one for the delivered artifact; when repeated restarts
    agree, the remaining crossings are evidence of the topology rather than of placement.
    """
    members = _groups(elements)
    edges = [(flow["sourceId"], flow["targetId"]) for flow in flows]
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
    best = _refine(order, members, columns, edges, gaps)
    best_order = {key: list(value) for key, value in order.items()}

    if restarts > 0:
        rng = random.Random(seed)
        keys = sorted(order)
        for _ in range(restarts):
            candidate = {key: list(order[key]) for key in keys}
            for key in keys:
                rng.shuffle(candidate[key])
            score = _refine(candidate, members, columns, edges, gaps)
            if score < best:
                best = score
                best_order = {key: list(value) for key, value in candidate.items()}

    return _place(best_order, members, columns, gaps), best


def main() -> int:
    parser = argparse.ArgumentParser(description="Preview derived layout for a ledger.")
    parser.add_argument("analysis", type=Path, help="path to analysis.json")
    parser.add_argument("--json", action="store_true", help="emit geometry as JSON")
    parser.add_argument(
        "--restarts",
        type=int,
        default=0,
        help="seeded restarts to escape a local optimum; deterministic for a given seed",
    )
    parser.add_argument(
        "--seed", type=int, default=0, help="seed for --restarts; fixed output per seed"
    )
    args = parser.parse_args()

    if not args.analysis.is_file():
        print(f"ERROR: no such ledger: {args.analysis}", file=sys.stderr)
        return 2
    ledger = json.loads(args.analysis.read_text(encoding="utf-8"))
    boxes, (crossings, length) = compute(
        ledger.get("elements", []),
        ledger.get("flows", []),
        restarts=args.restarts,
        seed=args.seed,
    )

    if args.json:
        print(
            json.dumps(
                {alias: list(box) for alias, box in sorted(boxes.items())}, indent=2
            )
        )
        return 0

    width = max((box[0] + box[2] for box in boxes.values()), default=0.0)
    height = max((box[1] + box[3] for box in boxes.values()), default=0.0)
    print(f"{len(boxes)} shapes, canvas {width:.0f}x{height:.0f}")
    print(f"predicted crossings: {crossings}, total edge length: {length:.0f}")
    if width > MAX_CANVAS_X or height > MAX_CANVAS_Y:
        print(
            f"WARNING: canvas exceeds the tool's limit of {MAX_CANVAS_X}x{MAX_CANVAS_Y}; "
            f"the Microsoft Threat Modeling Tool clamps out-of-range shapes on load, which "
            f"piles them on top of each other. Shorten the flow names or split the page.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
