#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ARRAYS = "{http://schemas.microsoft.com/2003/10/Serialization/Arrays}"
MODEL = "{http://schemas.datacontract.org/2004/07/ThreatModeling.Model}"
ABSTRACTS = "{http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts}"
KB = "{http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase}"
XSI_TYPE = "{http://www.w3.org/2001/XMLSchema-instance}type"

BOUNDARY_TYPE = "BorderBoundary"
CONNECTOR_TYPE = "Connector"
SHAPE_TYPES = {"StencilRectangle", "StencilParallelLines", "StencilEllipse"}

# A diagram much taller or wider than this does not fit a review screen.
MAX_ASPECT = 3.0
# Boundary left edges within this many units are treated as the same visual column.
COLUMN_TOLERANCE = 40.0

# A flow's name is printed as one unwrapped line centred on its connector, so its width is
# a function of its text. These match the metrics tmforge places labels with, so what this
# checks is what the tool draws.
LABEL_CHAR_W = 7.0
LABEL_H = 18.0

# The Microsoft Threat Modeling Tool clamps any shape drawn beyond these coordinates when
# it loads the file, which piles clamped shapes on top of each other.
MAX_CANVAS_X = 1890.0
MAX_CANVAS_Y = 2090.0


def _number(node: ET.Element, tag: str) -> float | None:
    found = node.find(ABSTRACTS + tag)
    if found is None or found.text is None:
        found = node.find(MODEL + tag)
    if found is None or found.text is None:
        return None
    try:
        return float(found.text)
    except ValueError:
        return None


def _properties(node: ET.Element) -> tuple[str | None, str | None]:
    """Return the (alias, name) recorded in a shape's property bag."""
    alias: str | None = None
    name: str | None = None
    container = node.find(ABSTRACTS + "Properties")
    if container is None:
        return alias, name
    for prop in container:
        kind = prop.get(XSI_TYPE) or ""
        value_node = prop.find(KB + "Value")
        value = None if value_node is None else value_node.text
        if not value:
            continue
        if kind.endswith("CustomStringDisplayAttribute") and value.startswith("Alias:"):
            alias = value[len("Alias:") :]
        elif kind.endswith("StringDisplayAttribute"):
            name_node = prop.find(KB + "Name")
            if name_node is not None and name_node.text == "Name":
                name = value
    return alias, name


def read_geometry(path: Path) -> dict[str, object]:
    """Extract boundary boxes, element boxes, and connector segments from a ``.tm7``."""
    root = ET.parse(path).getroot()
    boundaries: dict[str, dict[str, object]] = {}
    elements: dict[str, dict[str, object]] = {}
    by_guid: dict[str, tuple[str, str]] = {}
    connectors: list[dict[str, object]] = []

    for entry in root.iter(ARRAYS + "KeyValueOfguidanyType"):
        value = entry.find(ARRAYS + "Value")
        if value is None:
            continue
        kind = value.get(XSI_TYPE) or ""
        guid_node = value.find(ABSTRACTS + "Guid")
        guid = "" if guid_node is None else (guid_node.text or "")
        alias, name = _properties(value)

        if kind == CONNECTOR_TYPE:
            source = value.find(ABSTRACTS + "SourceGuid")
            target = value.find(ABSTRACTS + "TargetGuid")
            connectors.append(
                {
                    "name": name,
                    "sourceGuid": None if source is None else source.text,
                    "targetGuid": None if target is None else target.text,
                    "sourceX": _number(value, "SourceX"),
                    "sourceY": _number(value, "SourceY"),
                    "targetX": _number(value, "TargetX"),
                    "targetY": _number(value, "TargetY"),
                    "handleX": _number(value, "HandleX"),
                    "handleY": _number(value, "HandleY"),
                }
            )
            continue

        if kind != BOUNDARY_TYPE and kind not in SHAPE_TYPES:
            continue

        box = {
            "left": _number(value, "Left"),
            "top": _number(value, "Top"),
            "width": _number(value, "Width"),
            "height": _number(value, "Height"),
        }
        if any(item is None for item in box.values()):
            continue
        record = {"alias": alias, "name": name, "guid": guid, **box}
        key = alias or name or guid
        if kind == BOUNDARY_TYPE:
            boundaries[key] = record
        else:
            elements[key] = record
        if guid:
            by_guid[guid] = ("boundary" if kind == BOUNDARY_TYPE else "element", key)

    return {
        "boundaries": boundaries,
        "elements": elements,
        "connectors": connectors,
        "byGuid": by_guid,
    }


def _rect(box: dict[str, object]) -> tuple[float, float, float, float]:
    left = float(box["left"])  # type: ignore[arg-type]
    top = float(box["top"])  # type: ignore[arg-type]
    width = float(box["width"])  # type: ignore[arg-type]
    height = float(box["height"])  # type: ignore[arg-type]
    return left, top, left + width, top + height


def _contains(outer: dict[str, object], inner: dict[str, object]) -> bool:
    ox1, oy1, ox2, oy2 = _rect(outer)
    ix1, iy1, ix2, iy2 = _rect(inner)
    return ox1 <= ix1 and oy1 <= iy1 and ox2 >= ix2 and oy2 >= iy2


def _overlaps(a: dict[str, object], b: dict[str, object]) -> bool:
    ax1, ay1, ax2, ay2 = _rect(a)
    bx1, by1, bx2, by2 = _rect(b)
    return ax1 < bx2 and bx1 < ax2 and ay1 < by2 and by1 < ay2


def _segments_cross(
    a: tuple[float, float, float, float], b: tuple[float, float, float, float]
) -> bool:
    (x1, y1, x2, y2), (x3, y3, x4, y4) = a, b
    if len({(x1, y1), (x2, y2), (x3, y3), (x4, y4)}) < 4:
        return False

    def side(ax: float, ay: float, bx: float, by: float, cx: float, cy: float) -> float:
        return (bx - ax) * (cy - ay) - (by - ay) * (cx - ax)

    d1 = side(x3, y3, x4, y4, x1, y1)
    d2 = side(x3, y3, x4, y4, x2, y2)
    d3 = side(x1, y1, x2, y2, x3, y3)
    d4 = side(x1, y1, x2, y2, x4, y4)
    return ((d1 > 0) != (d2 > 0)) and ((d3 > 0) != (d4 > 0))


def label_boxes(connectors: list[dict[str, object]]) -> list[tuple[str, dict[str, float]]]:
    """Rectangles the flow names are printed in, as ``(name, box)`` pairs.

    The tool draws the name centred on the midpoint of the connector's quadratic curve —
    ``(source + 2 * handle + target) / 4`` — not on the straight line between the shapes.
    Reading the handle is therefore what makes this agree with what a reviewer sees; a
    handle of zero means unset, which the tool reads back as the endpoint midpoint.
    """
    boxes: list[tuple[str, dict[str, float]]] = []
    for connector in connectors:
        name = connector.get("name")
        coordinates = [
            connector.get(key) for key in ("sourceX", "sourceY", "targetX", "targetY")
        ]
        if not name or any(value is None for value in coordinates):
            continue
        source_x, source_y, target_x, target_y = (float(v) for v in coordinates)  # type: ignore[arg-type]
        # A stored handle of zero means unset, and the tool reads that axis back as the
        # midpoint of the endpoints. Resolve each axis independently, which is what the
        # model does, rather than treating an unset pair as the only unset case.
        handle_x = float(connector.get("handleX") or 0.0) or (source_x + target_x) / 2.0
        handle_y = float(connector.get("handleY") or 0.0) or (source_y + target_y) / 2.0
        centre_x = (source_x + 2 * handle_x + target_x) / 4.0
        centre_y = (source_y + 2 * handle_y + target_y) / 4.0
        width = len(str(name)) * LABEL_CHAR_W
        boxes.append(
            (
                str(name),
                {
                    "left": centre_x - width / 2.0,
                    "top": centre_y - LABEL_H / 2.0,
                    "width": width,
                    "height": LABEL_H,
                },
            )
        )
    return boxes


def _covers(outer: dict[str, object], inner: dict[str, object]) -> bool:
    """Whether ``outer`` hides ``inner`` entirely, leaving nothing of it readable."""
    ox1, oy1, ox2, oy2 = _rect(outer)
    ix1, iy1, ix2, iy2 = _rect(inner)
    return ox1 <= ix1 and oy1 <= iy1 and ox2 >= ix2 and oy2 >= iy2


def check(model_path: Path, analysis_path: Path | None) -> dict[str, object]:
    """Return a machine-readable layout report for one ``.tm7``."""
    geometry = read_geometry(model_path)
    boundaries: dict[str, dict[str, object]] = geometry["boundaries"]  # type: ignore[assignment]
    elements: dict[str, dict[str, object]] = geometry["elements"]  # type: ignore[assignment]
    connectors: list[dict[str, object]] = geometry["connectors"]  # type: ignore[assignment]

    failures: list[str] = []
    warnings: list[str] = []

    home: dict[str, str] = {}
    parents: dict[str, str] = {}
    if analysis_path is not None:
        ledger = json.loads(analysis_path.read_text(encoding="utf-8"))
        for element in ledger.get("elements", []):
            ids = element.get("boundaryIds") or []
            # Only the first boundary is representable in a .tm7 drawing surface.
            if ids:
                home[element["id"]] = ids[0]
        for boundary in ledger.get("boundaries", []):
            if boundary.get("parentId"):
                parents[boundary["id"]] = boundary["parentId"]

    for alias, boundary_id in sorted(home.items()):
        element = elements.get(alias)
        boundary = boundaries.get(boundary_id)
        if element is None or boundary is None:
            continue
        if not _contains(boundary, element):
            failures.append(
                f"element {alias} is drawn outside its boundary {boundary_id}; the "
                f"diagram asserts a trust relationship the ledger does not make"
            )
        for other_id, other in sorted(boundaries.items()):
            if other_id == boundary_id or parents.get(boundary_id) == other_id:
                continue
            if _overlaps(element, other):
                failures.append(
                    f"element {alias} overlaps boundary {other_id} it does not belong to"
                )

    keys = sorted(elements)
    for index, alias in enumerate(keys):
        for other in keys[index + 1 :]:
            if _overlaps(elements[alias], elements[other]):
                failures.append(f"elements {alias} and {other} overlap")

    boundary_keys = sorted(boundaries)
    for index, alias in enumerate(boundary_keys):
        for other in boundary_keys[index + 1 :]:
            if parents.get(alias) == other or parents.get(other) == alias:
                continue
            if _overlaps(boundaries[alias], boundaries[other]):
                failures.append(f"boundaries {alias} and {other} overlap")

    segments: list[tuple[float, float, float, float]] = []
    for connector in connectors:
        values = (
            connector["sourceX"],
            connector["sourceY"],
            connector["targetX"],
            connector["targetY"],
        )
        if any(value is None for value in values):
            continue
        segments.append(tuple(float(value) for value in values))  # type: ignore[arg-type]

    crossings = 0
    for index, segment in enumerate(segments):
        for other in segments[index + 1 :]:
            if _segments_cross(segment, other):
                crossings += 1

    boxes = list(boundaries.values()) + list(elements.values())
    width = height = 0.0
    right = bottom = 0.0
    if boxes:
        left = min(float(box["left"]) for box in boxes)  # type: ignore[arg-type]
        top = min(float(box["top"]) for box in boxes)  # type: ignore[arg-type]
        right = max(_rect(box)[2] for box in boxes)
        bottom = max(_rect(box)[3] for box in boxes)
        width, height = right - left, bottom - top

    labels = label_boxes(connectors)
    buried: list[str] = []
    obstructed: set[str] = set()
    for name, label in labels:
        for alias, element in sorted(elements.items()):
            if _covers(element, label):
                buried.append(f"flow label '{name}' is completely hidden behind {alias}")
            elif _overlaps(element, label):
                obstructed.add(name)
    for index, (name, label) in enumerate(labels):
        for other_name, other in labels[index + 1 :]:
            if _overlaps(label, other):
                obstructed.add(name)
                obstructed.add(other_name)

    failures.extend(sorted(buried))
    if right > MAX_CANVAS_X or bottom > MAX_CANVAS_Y:
        failures.append(
            f"canvas reaches ({right:.0f}, {bottom:.0f}), past the tool's limit of "
            f"({MAX_CANVAS_X:.0f}, {MAX_CANVAS_Y:.0f}); the Microsoft Threat Modeling Tool "
            f"clamps out-of-range shapes on load and piles them on top of each other"
        )

    aspect = (max(width, height) / min(width, height)) if width and height else 0.0

    # Auto-placement stacks every shape at one x-offset. Counting distinct column bands
    # detects that directly, whereas aspect ratio only notices it on large models.
    lefts = sorted(float(box["left"]) for box in boundaries.values())  # type: ignore[arg-type]
    columns = 0
    previous: float | None = None
    for left in lefts:
        if previous is None or left - previous > COLUMN_TOLERANCE:
            columns += 1
            previous = left
    if len(boundaries) > 2 and columns == 1:
        warnings.append(
            f"all {len(boundaries)} boundaries share one column; the diagram was likely "
            f"auto-placed rather than laid out, which produces long crossed connectors"
        )
    if aspect > MAX_ASPECT:
        warnings.append(
            f"canvas aspect ratio {aspect:.2f} exceeds {MAX_ASPECT}; the diagram will "
            f"not fit a review screen at a readable size"
        )
    if crossings:
        warnings.append(
            f"{crossings} connector crossing(s); reduce by reordering elements within "
            f"boundaries, or record why the remaining crossings are inherent"
        )
    if obstructed:
        longest = max((len(name) for name in obstructed), default=0)
        warnings.append(
            f"{len(obstructed)} flow label(s) are printed over a shape or another label "
            f"(longest is {longest} characters); a name is drawn unwrapped, so shorten "
            f"the names, widen the gaps they span, or split the page"
        )

    return {
        "model": str(model_path),
        "boundaries": len(boundaries),
        "elements": len(elements),
        "connectors": len(segments),
        "crossings": crossings,
        "columns": columns,
        "obstructedLabels": len(obstructed),
        "canvas": {
            "width": round(width, 2),
            "height": round(height, 2),
            "aspect": round(aspect, 3),
            "right": round(right, 2),
            "bottom": round(bottom, 2),
        },
        "failures": failures,
        "warnings": warnings,
        "ok": not failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model", type=Path, help="path to the generated .tm7")
    parser.add_argument(
        "--analysis",
        type=Path,
        default=None,
        help="canonical analysis.json, required for boundary containment checks",
    )
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    args = parser.parse_args()

    if not args.model.is_file():
        print(f"ERROR: no such model: {args.model}", file=sys.stderr)
        return 2
    analysis = args.analysis
    if analysis is None:
        sibling = args.model.parent / "analysis.json"
        analysis = sibling if sibling.is_file() else None

    report = check(args.model, analysis)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        canvas = report["canvas"]
        print(
            f"{report['boundaries']} boundaries, {report['elements']} elements, "
            f"{report['connectors']} connectors, {report['crossings']} crossings, "
            f"{report['obstructedLabels']} obstructed labels, "
            f"canvas {canvas['width']:.0f}x{canvas['height']:.0f} "
            f"(aspect {canvas['aspect']:.2f})"
        )
        if analysis is None:
            print("NOTE: no analysis.json; boundary containment was not checked")
        for message in report["warnings"]:
            print(f"WARNING: {message}")
        for message in report["failures"]:
            print(f"FAIL: {message}")
        print("OK: layout check passed" if report["ok"] else "FAILED: layout check")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
