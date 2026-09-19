import { DEFAULT_NODE_SIZE } from './mapping';
import type { LayoutElement } from './engineClient';
import type { DfdEdge, DfdKind, DfdNode } from './types';

/**
 * Auto-layout helpers that make an imported (for example, CLI-authored) model readable without
 * manual clean-up: every shape is grown to fit its label so the name never overruns the boundary,
 * overlapping shapes are pushed apart, each flow is routed through the ports that face its
 * endpoints (instead of React Flow's default top port, which loops lines over their own shapes),
 * and the flow labels are sized from their text and stacked so none cover one another or a shape.
 * All functions are pure and deterministic so a repeated run is a no-op.
 */

/** Label font — mirrors `.dfd-node` (13px / 600) over the app's system font stack, for measurement. */
const LABEL_FONT =
  "600 13px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";

/** Rendered line box of one wrapped label line (13px × 1.2 line-height). */
const LINE_HEIGHT = 16;
/** The icon (plus its margin) stacked above the label inside every shape node. */
const ICON_BLOCK = 26;
/** The small uppercase stencil caption shown above the label for specialized stencils. */
const CAPTION_HEIGHT = 12;
/** Inner padding of `.dfd-node` (≈8px vertical, 12px horizontal) plus a little breathing room. */
const PAD_X = 14;
const PAD_Y = 10;
/** A couple of pixels of slack so DOM wrapping never disagrees with the measured line width. */
const WIDTH_SLACK = 4;

/**
 * The width a label is wrapped to before its shape grows wider, per kind. A process is drawn as an
 * ellipse, so its text column is kept narrower; the boxy store / external shapes can run wider.
 */
const WRAP_TARGET: Record<Exclude<DfdKind, 'boundary'>, number> = {
  process: 150,
  datastore: 210,
  external: 210,
};

/** The most a shape will grow in each dimension, so one very long name can't produce a huge node. */
const MAX_WIDTH = 340;
const MAX_HEIGHT = 240;

/**
 * The smallest a shape is allowed to become when fitting it to its text. These are deliberately
 * tighter than {@link DEFAULT_NODE_SIZE} (the size a freshly dropped stencil gets) so that fitting an
 * imported model to its content stays compact and respects the author's original, denser layout
 * rather than inflating every shape to the palette default.
 */
const MIN_SIZE: Record<Exclude<DfdKind, 'boundary'>, NodeSize> = {
  process: { width: 96, height: 96 },
  datastore: { width: 120, height: 64 },
  external: { width: 120, height: 64 },
};

/**
 * A process is an ellipse: to inscribe a w×h text box its axes must be ≈√2 larger. This factor keeps
 * the wrapped label comfortably inside the ellipse instead of clipping against the curved edge.
 */
const ELLIPSE_FIT = 1.42;

let measureCtx: CanvasRenderingContext2D | null | undefined;

/** A cached 2D context for text measurement, or null where canvas is unavailable (e.g. jsdom tests). */
function context(): CanvasRenderingContext2D | null {
  if (measureCtx === undefined) {
    try {
      measureCtx = document.createElement('canvas').getContext('2d') ?? null;
      if (measureCtx) {
        measureCtx.font = LABEL_FONT;
      }
    } catch {
      measureCtx = null;
    }
  }
  return measureCtx;
}

/** Width (px) of one line of label text. Falls back to a per-character estimate without canvas. */
export function textWidth(text: string): number {
  const ctx = context();
  if (ctx) {
    return ctx.measureText(text).width;
  }
  // ≈7.1px average glyph advance for 13px/600 in the system stack — deterministic for tests.
  return text.length * 7.1;
}

/** Edge-label font — mirrors `.edge-label` (11px / 600); flow labels are measured to size their pills. */
const EDGE_LABEL_FONT =
  "600 11px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";

let edgeMeasureCtx: CanvasRenderingContext2D | null | undefined;

/** A cached 2D context for edge-label measurement at 11px, or null where canvas is unavailable. */
function edgeContext(): CanvasRenderingContext2D | null {
  if (edgeMeasureCtx === undefined) {
    try {
      edgeMeasureCtx = document.createElement('canvas').getContext('2d') ?? null;
      if (edgeMeasureCtx) {
        edgeMeasureCtx.font = EDGE_LABEL_FONT;
      }
    } catch {
      edgeMeasureCtx = null;
    }
  }
  return edgeMeasureCtx;
}

/** Width (px) of a one-line flow label. Falls back to a per-character estimate without canvas. */
export function edgeLabelWidth(text: string): number {
  const ctx = edgeContext();
  if (ctx) {
    return ctx.measureText(text).width;
  }
  // ≈6.0px average glyph advance for 11px/600 in the system stack — deterministic for tests.
  return text.length * 6;
}

/** Boundary-title font — mirrors `.dfd-boundary-label` (12px / 700). */
const BOUNDARY_LABEL_FONT =
  "700 12px -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";

let boundaryMeasureCtx: CanvasRenderingContext2D | null | undefined;

/** A cached 2D context for boundary-title measurement at 12px, or null where canvas is unavailable. */
function boundaryContext(): CanvasRenderingContext2D | null {
  if (boundaryMeasureCtx === undefined) {
    try {
      boundaryMeasureCtx = document.createElement('canvas').getContext('2d') ?? null;
      if (boundaryMeasureCtx) {
        boundaryMeasureCtx.font = BOUNDARY_LABEL_FONT;
      }
    } catch {
      boundaryMeasureCtx = null;
    }
  }
  return boundaryMeasureCtx;
}

/** Width (px) of one line of a trust-boundary title. Falls back to a per-character estimate. */
export function boundaryLabelWidth(text: string): number {
  const ctx = boundaryContext();
  if (ctx) {
    return ctx.measureText(text).width;
  }
  // ≈6.6px average glyph advance for 12px/700 in the system stack — deterministic for tests.
  return text.length * 6.6;
}

/** Greedy word-wrap to a target pixel width; a single word wider than the target is hard-broken. */
/** Greedy word-wrap of `label` to `maxWidth`, measured with the caller's font-specific measurer. */
function wrapWords(label: string, maxWidth: number, measure: (text: string) => number): string[] {
  const words = label.split(/\s+/).filter(Boolean);
  if (words.length === 0) {
    return [''];
  }
  const lines: string[] = [];
  let line = '';
  for (const word of words) {
    const candidate = line ? `${line} ${word}` : word;
    if (line && measure(candidate) > maxWidth) {
      lines.push(line);
      line = word;
    } else {
      line = candidate;
    }
  }
  if (line) {
    lines.push(line);
  }
  return lines;
}

export function wrapLabel(label: string, maxWidth: number): string[] {
  const lines = wrapWords(label, maxWidth, textWidth);
  // Hard-break any line still made of a single over-long token (for example, EncryptionConfiguration).
  return lines.flatMap((l) => (!l.includes(' ') && textWidth(l) > maxWidth ? hardBreak(l, maxWidth) : l));
}

/** Splits a single unbreakable word into chunks that each fit the target width. */
function hardBreak(word: string, maxWidth: number): string[] {
  const parts: string[] = [];
  let chunk = '';
  for (const ch of word) {
    if (chunk && textWidth(chunk + ch) > maxWidth) {
      parts.push(chunk);
      chunk = ch;
    } else {
      chunk += ch;
    }
  }
  if (chunk) {
    parts.push(chunk);
  }
  return parts.length > 0 ? parts : [word];
}

export interface NodeSize {
  width: number;
  height: number;
}

/** Reads a width/height that may be a number or a CSS pixel string, falling back when unset. */
function dim(value: unknown, fallback: number): number {
  const n = typeof value === 'string' ? parseFloat(value) : typeof value === 'number' ? value : NaN;
  return Number.isFinite(n) ? n : fallback;
}

function clamp(value: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, value));
}

/** The smallest on-canvas size that keeps a node's label inside its shape. */
export function fitNodeSize(kind: DfdKind, label: string, hasCaption = false): NodeSize {
  if (kind === 'boundary') {
    return { width: DEFAULT_NODE_SIZE.boundary.width, height: DEFAULT_NODE_SIZE.boundary.height };
  }
  const min = MIN_SIZE[kind];
  const wrapAt = WRAP_TARGET[kind];
  const lines = wrapLabel(label || ' ', wrapAt);
  const longest = Math.max(1, ...lines.map(textWidth));
  const textBoxW = Math.ceil(longest) + WIDTH_SLACK;
  const textBoxH = ICON_BLOCK + (hasCaption ? CAPTION_HEIGHT : 0) + lines.length * LINE_HEIGHT;

  let width: number;
  let height: number;
  if (kind === 'process') {
    width = Math.ceil((textBoxW + PAD_X * 2) * ELLIPSE_FIT);
    height = Math.ceil((textBoxH + PAD_Y * 2) * ELLIPSE_FIT);
  } else {
    width = textBoxW + PAD_X * 2;
    height = textBoxH + PAD_Y * 2;
  }
  return {
    width: clamp(width, min.width, MAX_WIDTH),
    height: clamp(height, min.height, MAX_HEIGHT),
  };
}

/** Merge validated rectangles onto current nodes, retaining selection, properties, and view state. */
export function applyLayoutGeometry(nodes: DfdNode[], elements: LayoutElement[]): DfdNode[] {
  const byId = new Map(elements.map((element) => [element.id, element]));
  if (elements.length !== nodes.length || byId.size !== elements.length || nodes.some((node) => !byId.has(node.id))) {
    throw new Error('The layout response does not match the page. Nothing was changed.');
  }
  return nodes.map((node) => {
    const element = byId.get(node.id)!;
    const current = rectOf(node);
    if (current.x === element.x && current.y === element.y && current.w === element.width && current.h === element.height) {
      return node;
    }
    return {
      ...node,
      position: { x: element.x, y: element.y },
      width: element.width,
      height: element.height,
      style: { ...node.style, width: element.width, height: element.height },
    };
  });
}

/** Presentation-only cleanup, safe on import and offline: no shape or boundary geometry changes. */
export function tidyLabels(nodes: DfdNode[], edges: DfdEdge[]): { nodes: DfdNode[]; edges: DfdEdge[] } {
  return { nodes, edges: deconflictEdgeLabels(nodes, routeEdges(nodes, edges)) };
}

export type FitMode = 'grow' | 'exact';

/**
 * Returns nodes resized so each label fits its shape. `grow` only ever enlarges, so a hand-tuned
 * size is never clipped; `exact` sets the computed fit. The node's centre is preserved, so it stays
 * put relative to its neighbours and any trust boundary it sits in.
 */
export function resizeNodesToFit(nodes: DfdNode[], mode: FitMode = 'exact'): DfdNode[] {
  return nodes.map((n) => {
    const kind = (n.type ?? 'process') as DfdKind;
    if (kind === 'boundary') {
      return n;
    }
    const label = typeof n.data.label === 'string' ? n.data.label : '';
    const fit = fitNodeSize(kind, label, Boolean(n.data.stencilType));
    const curW = dim(n.width ?? n.style?.width, DEFAULT_NODE_SIZE[kind].width);
    const curH = dim(n.height ?? n.style?.height, DEFAULT_NODE_SIZE[kind].height);
    const width = mode === 'grow' ? Math.max(curW, fit.width) : fit.width;
    const height = mode === 'grow' ? Math.max(curH, fit.height) : fit.height;
    if (width === curW && height === curH) {
      return n;
    }
    const position = {
      x: Math.round(n.position.x + (curW - width) / 2),
      y: Math.round(n.position.y + (curH - height) / 2),
    };
    return { ...n, position, width, height, style: { ...n.style, width, height } };
  });
}

/** The four connection ports every shape node exposes, in the order ShapeNode renders them. */
type HandleSide = 't' | 'r' | 'b' | 'l';

function isSide(value: string): value is HandleSide {
  return value === 't' || value === 'r' || value === 'b' || value === 'l';
}

/** The point (flow coords) where a given side's port sits on the edge of a node's rectangle. */
function handlePoint(r: Rect, side: HandleSide): { x: number; y: number } {
  switch (side) {
    case 't':
      return { x: r.x + r.w / 2, y: r.y };
    case 'b':
      return { x: r.x + r.w / 2, y: r.y + r.h };
    case 'l':
      return { x: r.x, y: r.y + r.h / 2 };
    case 'r':
      return { x: r.x + r.w, y: r.y + r.h / 2 };
  }
}

/** The facing (source, target) port sides between two node rectangles, chosen by dominant axis. */
function facingSides(s: Rect, t: Rect): [HandleSide, HandleSide] {
  const dx = t.x + t.w / 2 - (s.x + s.w / 2);
  const dy = t.y + t.h / 2 - (s.y + s.h / 2);
  if (Math.abs(dx) >= Math.abs(dy)) {
    return dx >= 0 ? ['r', 'l'] : ['l', 'r'];
  }
  return dy >= 0 ? ['b', 't'] : ['t', 'b'];
}

/**
 * Assigns each flow the source and target ports that face one another, so a line leaves the side of
 * its source nearest the target and enters the side of its target nearest the source. Without an
 * explicit handle React Flow falls back to a shape's first port (its top), which sends every line
 * looping up and over its own shapes and scatters the midpoint labels far from the flow. Only
 * component-to-component flows are routed; a flow touching a trust boundary (which has no ports) is
 * left for React Flow to place. Handles come purely from geometry, so a repeated run is a no-op.
 */
export function routeEdges(nodes: DfdNode[], edges: DfdEdge[]): DfdEdge[] {
  const rects = new Map<string, Rect>();
  for (const n of nodes) {
    if (n.type !== 'boundary') {
      rects.set(n.id, rectOf(n));
    }
  }
  return edges.map((e) => {
    const s = rects.get(e.source);
    const t = rects.get(e.target);
    if (!s || !t) {
      return e;
    }
    const [sourceHandle, targetHandle] = facingSides(s, t);
    if (e.sourceHandle === sourceHandle && e.targetHandle === targetHandle) {
      return e;
    }
    return { ...e, sourceHandle, targetHandle };
  });
}

/** Text width (px) a long flow label wraps at, so verbose descriptions form a compact multi-line pill. */
const EDGE_WRAP_TARGET = 224;
/** `.edge-label`'s max-width — a pill whose text wraps is laid out at exactly this width. */
const EDGE_MAX_WIDTH = 240;
/** Rendered height (px) of one wrapped line of an 11px/600 flow label (line-height 1.25). */
const EDGE_LINE_H = 14;
/** Horizontal padding (px) added to a label's measured text to get the width of its pill. */
const LABEL_PAD_X = 8;
/** Vertical padding (px), including the pill's halo, added above and below the wrapped lines. */
const LABEL_PAD_Y = 5;
/** Minimum vertical gap (px) kept between a separated label and whatever it was moved off. */
const LABEL_GAP = 6;
/** Iteration cap for the label-overlap relaxation — small diagrams converge well before it. */
const LABEL_ITERS = 60;

/**
 * Geometry of `.dfd-boundary-label`: the title pill is pinned inside the region's top-left corner
 * (2px border + the 10px/6px offsets) and wraps within the width that leaves, at 12px/700 over a
 * 15px line box with 7px/1px padding.
 */
const BOUNDARY_TITLE_LEFT = 12;
const BOUNDARY_TITLE_TOP = 8;
const BOUNDARY_TITLE_PAD_X = 7;
const BOUNDARY_TITLE_PAD_Y = 1;
const BOUNDARY_TITLE_LINE_H = 15;
/** Clear space (px) kept between a boundary's title and the nearest shape below it. */
const BOUNDARY_TITLE_GAP = 10;

/**
 * The on-canvas rectangle a trust boundary's title occupies. The title wraps within the region, so a
 * long name takes several lines and reaches further down into it — which is why a shape parked at the
 * top of a boundary ends up covering the boundary's own name.
 */
export function boundaryTitleRect(region: Rect, label: string): Rect {
  const available = Math.max(1, region.w - BOUNDARY_TITLE_LEFT - 2);
  const content = Math.max(1, available - BOUNDARY_TITLE_PAD_X * 2);
  const lines = wrapWords(label || ' ', content, boundaryLabelWidth);
  return {
    x: region.x + BOUNDARY_TITLE_LEFT,
    y: region.y + BOUNDARY_TITLE_TOP,
    // Shrink-to-fit: the pill takes its one-line width, or the whole remaining width once it wraps.
    w: Math.min(available, Math.ceil(boundaryLabelWidth(label)) + BOUNDARY_TITLE_PAD_X * 2),
    h: lines.length * BOUNDARY_TITLE_LINE_H + BOUNDARY_TITLE_PAD_Y * 2,
  };
}

/** A movable flow label as a box centred on its anchor and shifted to clear overlaps. */
interface LabelBox {
  id: string;
  anchorX: number;
  anchorY: number;
  cx: number;
  cy: number;
  w: number;
  h: number;
}

interface LabelObstacle extends Rect {
  id: string;
}

/** The midpoint of a flow's routed path — its two ports, or the node centres when it is unrouted. */
function labelAnchor(edge: DfdEdge, source: Rect, target: Rect): { x: number; y: number } {
  const sp =
    typeof edge.sourceHandle === 'string' && isSide(edge.sourceHandle)
      ? handlePoint(source, edge.sourceHandle)
      : { x: source.x + source.w / 2, y: source.y + source.h / 2 };
  const tp =
    typeof edge.targetHandle === 'string' && isSide(edge.targetHandle)
      ? handlePoint(target, edge.targetHandle)
      : { x: target.x + target.w / 2, y: target.y + target.h / 2 };
  return { x: (sp.x + tp.x) / 2, y: (sp.y + tp.y) / 2 };
}

/** Overlap of two axis ranges (start + length each), or a value ≤ 0 when they are disjoint. */
function axisOverlap(aStart: number, aLen: number, bStart: number, bLen: number): number {
  return Math.min(aStart + aLen, bStart + bLen) - Math.max(aStart, bStart);
}

/** Greedy word-wrap of a flow label at the edge font, matching the wrapping `.edge-label` renders. */
function wrapEdgeLabel(label: string, maxWidth: number): string[] {
  return wrapWords(label, maxWidth, edgeLabelWidth);
}

/** The on-canvas pill size of a flow label once wrapped, used to detect and clear label overlaps. */
export function edgeLabelBox(text: string): { w: number; h: number } {
  const lines = wrapEdgeLabel(text, EDGE_WRAP_TARGET);
  return {
    // Shrink-to-fit, as CSS lays the pill out: its one-line width, clamped to `.edge-label`'s
    // max-width. A wrapped pill therefore renders at the clamp, not at its longest wrapped line.
    w: Math.min(EDGE_MAX_WIDTH, Math.ceil(edgeLabelWidth(text)) + LABEL_PAD_X * 2),
    h: lines.length * EDGE_LINE_H + LABEL_PAD_Y * 2,
  };
}

function labelRect(label: LabelBox, x = label.cx, y = label.cy): Rect {
  return { x: x - label.w / 2, y: y - label.h / 2, w: label.w, h: label.h };
}

function labelObstacles(nodes: DfdNode[]): LabelObstacle[] {
  return nodes.map((node) => {
    const rect = rectOf(node);
    if (node.type !== 'boundary') {
      return { id: node.id, ...rect };
    }
    const label = typeof node.data.label === 'string' ? node.data.label : '';
    return { id: `title:${node.id}`, ...boundaryTitleRect(rect, label) };
  });
}

function rectsOverlap(a: Rect, b: Rect, gap = 0): boolean {
  return axisOverlap(a.x, a.w, b.x - gap, b.w + gap * 2) > 0
    && axisOverlap(a.y, a.h, b.y - gap, b.h + gap * 2) > 0;
}

/** Candidate offsets around a preferred label centre, ordered nearest-first with vertical bias. */
function labelCandidates(label: LabelBox): { x: number; y: number }[] {
  const stepX = 32;
  const stepY = Math.max(24, Math.ceil(label.h + LABEL_GAP));
  const candidates = [{ x: 0, y: 0 }];
  for (let ring = 1; ring <= 32; ring += 1) {
    const current: { x: number; y: number }[] = [];
    for (let gx = -ring; gx <= ring; gx += 1) {
      current.push({ x: gx * stepX, y: -ring * stepY });
      current.push({ x: gx * stepX, y: ring * stepY });
    }
    for (let gy = -ring + 1; gy < ring; gy += 1) {
      current.push({ x: -ring * stepX, y: gy * stepY });
      current.push({ x: ring * stepX, y: gy * stepY });
    }
    current.sort((a, b) => {
      const ac = Math.hypot(a.x * 1.2, a.y);
      const bc = Math.hypot(b.x * 1.2, b.y);
      return ac - bc || Math.abs(a.x) - Math.abs(b.x) || a.y - b.y || a.x - b.x;
    });
    candidates.push(...current);
  }
  return candidates;
}

/**
 * Returns edges whose labels are nudged vertically so no two auto-placed labels overlap and none
 * sits on top of a component shape. Each label is sized from its measured text, so long flow
 * descriptions that would otherwise cover one another (or a neighbouring shape) are stacked apart,
 * not just the classic request/response pair that shares an exact midpoint. A label the author has
 * already dragged aside (a non-zero offset) is left where it is — and treated as an obstacle the
 * auto-placed labels avoid — and a flow whose label is already clear keeps it on the line. Labels
 * prefer vertical movement but can move horizontally out of dense object corridors. Repeated runs
 * are stable.
 */
export function deconflictEdgeLabels(nodes: DfdNode[], edges: DfdEdge[]): DfdEdge[] {
  const rects = new Map<string, Rect>();
  for (const n of nodes) {
    rects.set(n.id, rectOf(n));
  }

  // Components are fixed obstacles. A boundary's interior legitimately contains labels, but its
  // title strip does not, so reserve only the title rather than the whole region.
  const obstacles = labelObstacles(nodes);
  const movable: LabelBox[] = [];

  for (const e of edges) {
    const s = rects.get(e.source);
    const t = rects.get(e.target);
    if (!s || !t) {
      continue;
    }
    const anchor = labelAnchor(e, s, t);
    const text = typeof e.label === 'string' && e.label ? e.label : 'data flow';
    const box = edgeLabelBox(text);
    const off = e.data?.labelOffset;
    if (off && (off.x !== 0 || off.y !== 0) && !e.data?.autoLabelOffset) {
      // Author-placed: never move it, but keep it as an obstacle the auto-placed labels avoid.
      obstacles.push({
        id: `manual:${e.id}`,
        x: anchor.x + off.x - box.w / 2,
        y: anchor.y + off.y - box.h / 2,
        w: box.w,
        h: box.h,
      });
      continue;
    }
    movable.push({
      id: e.id,
      anchorX: anchor.x,
      anchorY: anchor.y,
      cx: anchor.x,
      cy: anchor.y,
      w: box.w,
      h: box.h,
    });
  }

  // Deterministic order so ties resolve the same way on every run.
  movable.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  // Separate labels symmetrically around their path anchors first, retaining the familiar
  // request/response treatment before object-aware placement.
  for (let iter = 0; iter < LABEL_ITERS / 2; iter += 1) {
    let moved = false;
    for (let i = 0; i < movable.length; i++) {
      for (let j = i + 1; j < movable.length; j++) {
        const a = movable[i];
        const b = movable[j];
        if (axisOverlap(a.cx - a.w / 2, a.w, b.cx - b.w / 2, b.w) <= 0) {
          continue;
        }
        const gap = (a.h + b.h) / 2 + LABEL_GAP - Math.abs(a.cy - b.cy);
        if (gap <= 0) {
          continue;
        }
        // Lower id goes up on a tie, so the split is deterministic.
        const dir = a.cy <= b.cy ? -1 : 1;
        a.cy += (dir * gap) / 2;
        b.cy -= (dir * gap) / 2;
        moved = true;
      }
    }

    if (!moved) {
      break;
    }
  }

  // The old vertical-only relaxation could oscillate between neighboring objects. Place each label
  // into the nearest 2D slot that clears objects, manual labels, and labels already placed.
  const placed: Rect[] = [];
  for (const label of movable) {
    const preferredX = label.cx;
    const preferredY = label.cy;
    let chosen = { x: preferredX, y: preferredY };
    for (const offset of labelCandidates(label)) {
      const x = preferredX + offset.x;
      const y = preferredY + offset.y;
      const candidate = labelRect(label, x, y);
      if (
        obstacles.every((obstacle) => !rectsOverlap(candidate, obstacle, LABEL_GAP))
        && placed.every((other) => !rectsOverlap(candidate, other, LABEL_GAP))
      ) {
        chosen = { x, y };
        break;
      }
    }
    label.cx = chosen.x;
    label.cy = chosen.y;
    placed.push(labelRect(label));
  }

  const offsets = new Map<string, { x: number; y: number }>();
  for (const m of movable) {
    const next = { x: Math.round(m.cx - m.anchorX), y: Math.round(m.cy - m.anchorY) };
    if (next.x !== 0 || next.y !== 0) {
      offsets.set(m.id, next);
    }
  }

  return edges.map((e) => {
    const off = e.data?.labelOffset;
    const manual = Boolean(off && (off.x !== 0 || off.y !== 0) && !e.data?.autoLabelOffset);
    if (manual) {
      return e;
    }
    const next = offsets.get(e.id) ?? { x: 0, y: 0 };
    const cur = off ?? { x: 0, y: 0 };
    if (next.x === 0 && next.y === 0) {
      if (!e.data?.autoLabelOffset && cur.x === 0 && cur.y === 0) {
        return e;
      }
      const data = { ...e.data };
      delete data.labelOffset;
      delete data.autoLabelOffset;
      return { ...e, data };
    }
    if (cur.x === next.x && cur.y === next.y) {
      return e.data?.autoLabelOffset ? e : { ...e, data: { ...e.data, autoLabelOffset: true } };
    }
    return { ...e, data: { ...e.data, labelOffset: next, autoLabelOffset: true } };
  });
}

/** Returns component/title collisions for the label boxes produced by Tidy. */
export function findEdgeLabelObjectOverlaps(
  nodes: DfdNode[],
  edges: DfdEdge[],
): { edgeId: string; obstacleId: string }[] {
  const rects = new Map(nodes.map((node) => [node.id, rectOf(node)]));
  const obstacles = labelObstacles(nodes);
  const overlaps: { edgeId: string; obstacleId: string }[] = [];
  for (const edge of edges) {
    const source = rects.get(edge.source);
    const target = rects.get(edge.target);
    if (!source || !target) {
      continue;
    }
    const anchor = labelAnchor(edge, source, target);
    const offset = edge.data?.labelOffset ?? { x: 0, y: 0 };
    const size = edgeLabelBox(typeof edge.label === 'string' && edge.label ? edge.label : 'data flow');
    const box: Rect = {
      x: anchor.x + offset.x - size.w / 2,
      y: anchor.y + offset.y - size.h / 2,
      w: size.w,
      h: size.h,
    };
    for (const obstacle of obstacles) {
      if (rectsOverlap(box, obstacle)) {
        overlaps.push({ edgeId: edge.id, obstacleId: obstacle.id });
      }
    }
  }
  return overlaps;
}

/**
 * Returns every shape or nested region that covers a trust boundary's title. Tidy clears these, so a
 * non-empty result after a tidy is a regression.
 */
export function findBoundaryTitleOverlaps(nodes: DfdNode[]): { boundaryId: string; nodeId: string }[] {
  const boundaries = nodes.filter((n) => n.type === 'boundary');
  const overlaps: { boundaryId: string; nodeId: string }[] = [];
  for (const boundary of boundaries) {
    const region = rectOf(boundary);
    const label = typeof boundary.data.label === 'string' ? boundary.data.label : '';
    const title = boundaryTitleRect(region, label);
    for (const node of nodes) {
      const rect = rectOf(node);
      // An enclosing region necessarily overlaps the titles of the regions nested inside it.
      if (node.id === boundary.id || containsRect(rect, region)) {
        continue;
      }
      if (rectsOverlap(rect, title)) {
        overlaps.push({ boundaryId: boundary.id, nodeId: node.id });
      }
    }
  }
  return overlaps;
}

/** Desired minimum gap (px) kept between component nodes when they are pushed apart. */
const NODE_GAP = 24;
/** Desired minimum gap (px) inserted when overlapping peer trust boundaries are separated. */
const BOUNDARY_GAP = 24;
/** Padding (px) kept between a boundary's edge and the components it contains when it is grown. */
const BOUNDARY_PAD = 20;
/** Iteration cap for overlap relaxation — diagrams are small, so this converges well before it. */
const SEPARATE_ITERS = 100;

export interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** The bounding rectangle of a node, from its position and (possibly stringified) size. */
export function rectOf(n: DfdNode): Rect {
  const fallback = DEFAULT_NODE_SIZE[(n.type as DfdKind) ?? 'process'] ?? DEFAULT_NODE_SIZE.process;
  return {
    x: n.position.x,
    y: n.position.y,
    w: dim(n.width ?? n.style?.width, fallback.width),
    h: dim(n.height ?? n.style?.height, fallback.height),
  };
}

/** Whether one rectangle fully contains another, including coincident edges. */
function containsRect(outer: Rect, inner: Rect): boolean {
  return inner.x >= outer.x
    && inner.y >= outer.y
    && inner.x + inner.w <= outer.x + outer.w
    && inner.y + inner.h <= outer.y + outer.h;
}

/** Resolves a model Boundary reference against a boundary's id, alias, or label. */
export function resolveBoundary(boundaries: DfdNode[], reference: string | undefined): DfdNode | undefined {
  const expected = reference?.trim().toLowerCase();
  if (!expected) {
    return undefined;
  }
  return boundaries.find((boundary) => {
    const alias = boundary.data.properties?.Alias;
    return [boundary.id, boundary.data.label, alias].some(
      (candidate) => typeof candidate === 'string' && candidate.trim().toLowerCase() === expected,
    );
  });
}

/** Returns an element's explicit Boundary property, when one was authored. */
export function declaredBoundary(node: DfdNode): string | undefined {
  const reference = node.data.properties?.Boundary;
  return typeof reference === 'string' ? reference : undefined;
}

/**
 * Separates overlapping component nodes and peer trust boundaries. Components are assigned by their
 * authored Boundary property first, then by the smallest region containing their centre. A boundary
 * is grown — never shrunk — around its members, and overlapping peers move with all of their members
 * along the axis of least penetration. Fully nested boundaries remain nested and move with their
 * parent, preserving intentional hierarchy and component containment.
 */
export function separateNodes(nodes: DfdNode[]): DfdNode[] {
  const boundaries = nodes.filter((n) => n.type === 'boundary');
  const components = nodes.filter((n) => n.type !== 'boundary');
  const labelOf = new Map(
    boundaries.map((b) => [b.id, typeof b.data.label === 'string' ? b.data.label : ''] as const),
  );

  // Mutable working rectangles for the components, keyed by id.
  const pos = new Map<string, Rect>();
  for (const c of components) {
    pos.set(c.id, rectOf(c));
  }

  // Assign each component to its declared boundary, then fall back to the smallest region containing
  // its centre for models that do not carry authoring metadata (for example, imported .tm7 files).
  const boundaryRects = boundaries.map((b) => ({ id: b.id, r: rectOf(b) }));
  const groupOf = new Map<string, string>();
  for (const c of components) {
    const p = pos.get(c.id)!;
    const cx = p.x + p.w / 2;
    const cy = p.y + p.h / 2;
    const declared = resolveBoundary(boundaries, declaredBoundary(c));
    let owner = declared?.id ?? '';
    if (!owner) {
      let bestArea = Infinity;
      for (const b of boundaryRects) {
        if (cx >= b.r.x && cx <= b.r.x + b.r.w && cy >= b.r.y && cy <= b.r.y + b.r.h && b.r.w * b.r.h < bestArea) {
          bestArea = b.r.w * b.r.h;
          owner = b.id;
        }
      }
    }
    groupOf.set(c.id, owner);
  }

  const groups = new Map<string, string[]>();
  for (const c of components) {
    const g = groupOf.get(c.id)!;
    const arr = groups.get(g);
    if (arr) {
      arr.push(c.id);
    } else {
      groups.set(g, [c.id]);
    }
  }
  for (const ids of groups.values()) {
    ids.sort();
  }

  // Relax overlaps within each group by pushing each overlapping pair apart the short way.
  for (let iter = 0; iter < SEPARATE_ITERS; iter++) {
    let moved = false;
    for (const ids of groups.values()) {
      for (let i = 0; i < ids.length; i++) {
        for (let j = i + 1; j < ids.length; j++) {
          const a = pos.get(ids[i])!;
          const b = pos.get(ids[j])!;
          const dx = b.x + b.w / 2 - (a.x + a.w / 2);
          const dy = b.y + b.h / 2 - (a.y + a.h / 2);
          const px = (a.w + b.w) / 2 + NODE_GAP - Math.abs(dx);
          const py = (a.h + b.h) / 2 + NODE_GAP - Math.abs(dy);
          if (px > 0 && py > 0) {
            if (px < py) {
              const shift = (px / 2) * (dx >= 0 ? 1 : -1);
              a.x -= shift;
              b.x += shift;
            } else {
              const shift = (py / 2) * (dy >= 0 ? 1 : -1);
              a.y -= shift;
              b.y += shift;
            }
            moved = true;
          }
        }
      }
    }
    if (!moved) {
      break;
    }
  }

  const boundaryPos = new Map(boundaryRects.map((b) => [b.id, { ...b.r }]));

  // Build an intentional boundary hierarchy from explicit metadata, or from strict geometric
  // containment when metadata is absent. Partially intersecting boundaries remain peers.
  const parentOf = new Map<string, string | null>();
  for (const boundary of boundaries) {
    const declared = resolveBoundary(boundaries, declaredBoundary(boundary));
    if (declared && declared.id !== boundary.id) {
      parentOf.set(boundary.id, declared.id);
      continue;
    }
    const current = boundaryPos.get(boundary.id)!;
    const currentArea = current.w * current.h;
    const parent = boundaryRects
      .filter((candidate) => candidate.id !== boundary.id
        && candidate.r.w * candidate.r.h > currentArea
        && containsRect(candidate.r, current))
      .sort((a, b) => a.r.w * a.r.h - b.r.w * b.r.h || a.id.localeCompare(b.id))[0];
    parentOf.set(boundary.id, parent?.id ?? null);
  }

  for (const boundary of boundaries) {
    const visited = new Set<string>();
    let current: string | null = boundary.id;
    while (current !== null) {
      if (visited.has(current)) {
        throw new Error('Tidy cannot resolve cyclic boundary membership. No changes were made.');
      }
      visited.add(current);
      current = parentOf.get(current) ?? null;
    }
  }

  const childrenOf = new Map<string | null, string[]>();
  for (const boundary of boundaries) {
    const parent = parentOf.get(boundary.id) ?? null;
    const children = childrenOf.get(parent);
    if (children) {
      children.push(boundary.id);
    } else {
      childrenOf.set(parent, [boundary.id]);
    }
  }
  for (const children of childrenOf.values()) {
    children.sort();
  }

  const membersOf = new Map<string, string[]>();
  for (const component of components) {
    const owner = groupOf.get(component.id)!;
    if (!owner) {
      continue;
    }
    const members = membersOf.get(owner);
    if (members) {
      members.push(component.id);
    } else {
      membersOf.set(owner, [component.id]);
    }
  }

  // Moving a region carries its direct members and every nested region as one layout unit.
  const shiftBoundaryTree = (id: string, dx: number, dy: number): void => {
    const boundary = boundaryPos.get(id)!;
    boundary.x += dx;
    boundary.y += dy;
    for (const memberId of membersOf.get(id) ?? []) {
      const member = pos.get(memberId)!;
      member.x += dx;
      member.y += dy;
    }
    for (const childId of childrenOf.get(id) ?? []) {
      shiftBoundaryTree(childId, dx, dy);
    }
  };

  // Separate one sibling set. Keep the earlier top/left region fixed and move later peers only right
  // or down, which avoids introducing negative coordinates while leaving a visible gap between
  // outlines that overlap or nearly touch.
  const separateBoundarySiblings = (ids: string[]): void => {
    const ordered = [...ids].sort((left, right) => {
      const a = boundaryPos.get(left)!;
      const b = boundaryPos.get(right)!;
      return a.y - b.y || a.x - b.x || left.localeCompare(right);
    });
    for (let iter = 0; iter < SEPARATE_ITERS; iter++) {
      let moved = false;
      for (let i = 0; i < ordered.length; i++) {
        for (let j = i + 1; j < ordered.length; j++) {
          const a = boundaryPos.get(ordered[i])!;
          const b = boundaryPos.get(ordered[j])!;
          if (!rectsOverlap(a, b, BOUNDARY_GAP)) {
            continue;
          }
          const moveRight = a.x + a.w + BOUNDARY_GAP - b.x;
          const moveDown = a.y + a.h + BOUNDARY_GAP - b.y;
          if (moveRight <= moveDown) {
            shiftBoundaryTree(ordered[j], moveRight, 0);
          } else {
            shiftBoundaryTree(ordered[j], 0, moveDown);
          }
          moved = true;
        }
      }
      if (!moved) {
        break;
      }
    }
  };

  // Lay out nested siblings first, then grow their parent around both direct members and children.
  const layoutBoundary = (id: string): void => {
    const children = childrenOf.get(id) ?? [];
    for (const childId of children) {
      layoutBoundary(childId);
    }
    separateBoundarySiblings(children);

    const boundary = boundaryPos.get(id)!;
    let minX = boundary.x;
    let minY = boundary.y;
    let maxX = boundary.x + boundary.w;
    let maxY = boundary.y + boundary.h;
    for (const memberId of membersOf.get(id) ?? []) {
      const member = pos.get(memberId)!;
      minX = Math.min(minX, member.x - BOUNDARY_PAD);
      minY = Math.min(minY, member.y - BOUNDARY_PAD);
      maxX = Math.max(maxX, member.x + member.w + BOUNDARY_PAD);
      maxY = Math.max(maxY, member.y + member.h + BOUNDARY_PAD);
    }
    for (const childId of children) {
      const child = boundaryPos.get(childId)!;
      minX = Math.min(minX, child.x - BOUNDARY_PAD);
      minY = Math.min(minY, child.y - BOUNDARY_PAD);
      maxX = Math.max(maxX, child.x + child.w + BOUNDARY_PAD);
      maxY = Math.max(maxY, child.y + child.h + BOUNDARY_PAD);
    }

    // Reserve the title strip. A boundary's name is pinned inside its own top-left corner and wraps
    // across the region, so anything parked at the top covers it. Open the strip by growing the
    // region upwards rather than by moving shapes, which keeps the author's arrangement intact.
    const title = boundaryTitleRect({ x: minX, y: minY, w: maxX - minX, h: maxY - minY }, labelOf.get(id) ?? '');
    const clearance = BOUNDARY_TITLE_TOP + title.h + BOUNDARY_TITLE_GAP;
    const beneath = [
      ...(membersOf.get(id) ?? []).map((memberId) => pos.get(memberId)!),
      ...children.map((childId) => boundaryPos.get(childId)!),
    ];
    for (const item of beneath) {
      if (axisOverlap(item.x, item.w, title.x, title.w) > 0) {
        minY = Math.min(minY, item.y - clearance);
      }
    }

    boundary.x = minX;
    boundary.y = minY;
    boundary.w = maxX - minX;
    boundary.h = maxY - minY;
  };

  const roots = childrenOf.get(null) ?? [];
  for (const rootId of roots) {
    layoutBoundary(rootId);
  }
  separateBoundarySiblings(roots);

  return nodes.map((n) => {
    if (n.type === 'boundary') {
      const g = boundaryPos.get(n.id)!;
      const cur = rectOf(n);
      const x = Math.round(g.x);
      const y = Math.round(g.y);
      const width = Math.round(g.w);
      const height = Math.round(g.h);
      if (x === cur.x && y === cur.y && width === cur.w && height === cur.h) {
        return n;
      }
      return { ...n, position: { x, y }, width, height, style: { ...n.style, width, height } };
    }
    const p = pos.get(n.id)!;
    const nx = Math.round(p.x);
    const ny = Math.round(p.y);
    if (nx === n.position.x && ny === n.position.y) {
      return n;
    }
    return { ...n, position: { x: nx, y: ny } };
  });
}

/**
 * Tidies a page: fits every shape to its label, separates overlapping shapes (growing any trust
 * boundary to keep wrapping its contents), routes each flow through the ports that face its
 * endpoints, and separates the flow labels so none overlap one another or a shape. `grow` (used when
 * a model is loaded) only enlarges shapes; `exact` (the toolbar action) sets the computed fit.
 */
export function tidyGraph(
  nodes: DfdNode[],
  edges: DfdEdge[],
  mode: FitMode = 'exact',
): { nodes: DfdNode[]; edges: DfdEdge[] } {
  if (nodes.length > 512 || edges.length > 1024
    || nodes.some((node) => node.data.label.length > 4096)
    || edges.some((edge) => typeof edge.label === 'string' && edge.label.length > 4096)) {
    throw new Error('Tidy supports up to 512 shapes, 1024 flows and labels of at most 4096 characters. No changes were made.');
  }
  const separated = separateNodes(resizeNodesToFit(nodes, mode));
  const routed = routeEdges(separated, edges);
  return { nodes: separated, edges: deconflictEdgeLabels(separated, routed) };
}
