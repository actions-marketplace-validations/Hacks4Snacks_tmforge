import { describe, it, expect } from 'vitest';
import {
  applyLayoutGeometry,
  boundaryTitleRect,
  deconflictEdgeLabels,
  edgeLabelBox,
  findBoundaryTitleOverlaps,
  findEdgeLabelObjectOverlaps,
  fitNodeSize,
  resizeNodesToFit,
  routeEdges,
  separateNodes,
  tidyGraph,
  tidyLabels,
  wrapLabel,
} from './autosize';
import { DEFAULT_NODE_SIZE } from './mapping';
import type { DfdEdge, DfdNode } from './types';

describe('shared layout integration', () => {
  function nodes(): DfdNode[] {
    return [
      { id: 'tb', type: 'boundary', position: { x: 0, y: 0 }, width: 400, height: 250, data: { label: 'A long boundary title that will wrap on a narrow region' } },
      { id: 'p', type: 'process', position: { x: 50, y: 50 }, width: 100, height: 60, selected: true, data: { label: 'Gateway', properties: { Boundary: 'tb', Owner: 'security' } } },
    ];
  }

  it('applies only geometry and retains all author and selection state', () => {
    const input = nodes();
    const placed = applyLayoutGeometry(input, [
      { id: 'tb', x: 40, y: 40, width: 240, height: 280 },
      { id: 'p', x: 64, y: 160, width: 160, height: 96 },
    ]);

    expect(placed[1].position).toEqual({ x: 64, y: 160 });
    expect(placed[1].data).toBe(input[1].data);
    expect(placed[1].selected).toBe(true);
    expect(input[1].position).toEqual({ x: 50, y: 50 });
    expect(placed[1].style).toEqual({ width: 160, height: 96 });
  });

  it('refuses missing, duplicate and foreign rectangles instead of partially applying a response', () => {
    const input = nodes();
    const patch = { id: 'p', x: 1, y: 2, width: 100, height: 60 };

    expect(() => applyLayoutGeometry(input, [patch])).toThrow(/does not match/);
    expect(() => applyLayoutGeometry(input, [patch, patch])).toThrow(/does not match/);
    expect(() => applyLayoutGeometry(input, [patch, { ...patch, id: 'foreign' }])).toThrow(/does not match/);
    expect(input).toEqual(nodes());
  });

  it('labels-only cleanup leaves every rectangle untouched, including overlapping trust claims', () => {
    const input = nodes();
    const edges: DfdEdge[] = [{ id: 'f', source: 'p', target: 'p', label: 'loop', data: { properties: { Protocol: 'TLS' } } }];
    const cleaned = tidyLabels(input, edges);

    expect(cleaned.nodes).toBe(input);
    expect(cleaned.edges[0].source).toBe(edges[0].source);
    expect(cleaned.edges[0].target).toBe(edges[0].target);
    expect(cleaned.edges[0].data?.properties).toEqual(edges[0].data?.properties);
  });

  it('refuses cyclic declared boundaries without recursing or changing the input', () => {
    const input = [
      { ...nodes()[0], id: 'a', data: { label: 'A', properties: { Boundary: 'b' } } },
      { ...nodes()[0], id: 'b', data: { label: 'B', properties: { Boundary: 'a' } } },
    ];
    const before = structuredClone(input);

    expect(() => tidyGraph(input, [])).toThrow(/cyclic boundary membership/);
    expect(input).toEqual(before);
  });

  it('bounds cleanup before performing overlap searches or text measurement', () => {
    expect(() => tidyGraph(Array.from({ length: 513 }, () => nodes()[1]), [])).toThrow(/512 shapes/);
    expect(() => tidyGraph([{ ...nodes()[1], data: { label: 'x'.repeat(4097) } }], [])).toThrow(/4096 characters/);
  });
});

describe('wrapLabel', () => {
  it('keeps a short name on a single line', () => {
    expect(wrapLabel('kube-apiserver', 150)).toEqual(['kube-apiserver']);
  });

  it('wraps a multi-word name across lines at the target width', () => {
    const lines = wrapLabel('kube-apiserver (+ encryption provider)', 150);
    expect(lines.length).toBeGreaterThan(1);
    // Every word is preserved in order across the wrapped lines.
    expect(lines.join(' ')).toBe('kube-apiserver (+ encryption provider)');
  });

  it('hard-breaks a single over-long token so it cannot overrun', () => {
    // With the deterministic per-character fallback, a 40-char token exceeds a 120px target.
    const lines = wrapLabel('EncryptionConfigurationLocalKeyEncryptionKey', 120);
    expect(lines.length).toBeGreaterThan(1);
    expect(lines.join('')).toBe('EncryptionConfigurationLocalKeyEncryptionKey');
  });
});

describe('fitNodeSize', () => {
  it('fits a short label to the compact per-kind minimum', () => {
    expect(fitNodeSize('external', 'etcd')).toEqual({ width: 120, height: 64 });
    expect(fitNodeSize('process', 'web')).toEqual({ width: 96, height: 96 });
  });

  it('grows a box shape wide enough for a long single-line name', () => {
    const size = fitNodeSize('external', 'Cluster workload / kubectl (client)');
    expect(size.width).toBeGreaterThan(DEFAULT_NODE_SIZE.external.width);
  });

  it('grows a process wider to fit a name that wraps', () => {
    const size = fitNodeSize('process', 'kube-apiserver (+ encryption provider)');
    expect(size.width).toBeGreaterThan(DEFAULT_NODE_SIZE.process.width);
  });

  it('grows a process taller for a name that wraps to many lines', () => {
    const size = fitNodeSize('process', 'read encrypted secrets from etcd over the local control-plane socket');
    expect(size.height).toBeGreaterThan(DEFAULT_NODE_SIZE.process.height);
  });

  it('never grows a shape beyond the maximum', () => {
    const size = fitNodeSize('datastore', 'x'.repeat(400));
    expect(size.width).toBeLessThanOrEqual(340);
    expect(size.height).toBeLessThanOrEqual(240);
  });

  it('does not resize a trust boundary', () => {
    expect(fitNodeSize('boundary', 'Control-plane node')).toEqual(DEFAULT_NODE_SIZE.boundary);
  });
});

describe('boundaryTitleRect', () => {
  it('pins the title inside the region top-left corner', () => {
    const title = boundaryTitleRect({ x: 100, y: 50, w: 300, h: 200 }, 'TB1');
    expect(title.x).toBe(112);
    expect(title.y).toBe(58);
    expect(title.h).toBe(17); // one 15px line plus the pill's padding
  });

  it('reaches further down a narrow region because the name wraps', () => {
    const wide = boundaryTitleRect({ x: 0, y: 0, w: 400, h: 200 }, 'Undercloud Kubernetes cluster');
    const narrow = boundaryTitleRect({ x: 0, y: 0, w: 130, h: 200 }, 'Undercloud Kubernetes cluster');
    expect(narrow.h).toBeGreaterThan(wide.h);
    // The pill never runs past the region it is drawn in.
    expect(narrow.x + narrow.w).toBeLessThanOrEqual(130);
  });

  it('fills the remaining width once the name wraps, matching how the pill is laid out', () => {
    const long = 'Ironic pod network namespace (dual-homed) [network namespace]';
    const title = boundaryTitleRect({ x: 0, y: 0, w: 300, h: 400 }, long);
    expect(title.h).toBeGreaterThan(17); // it wraps...
    expect(title.w).toBe(300 - 14); // ...so it is laid out at the full remaining width
    // A name that fits on one line only takes the width it needs.
    expect(boundaryTitleRect({ x: 0, y: 0, w: 300, h: 400 }, 'TB5').w).toBeLessThan(80);
  });
});

describe('edgeLabelBox', () => {
  it('is laid out at the pill clamp once the text wraps, not at its longest wrapped line', () => {
    const long = edgeLabelBox('F16: Fetch OS image over the PXE network and verify its checksum');
    expect(long.h).toBeGreaterThan(24); // it wraps...
    expect(long.w).toBe(240); // ...so it renders at `.edge-label`'s max-width
    expect(edgeLabelBox('sync').w).toBeLessThan(80);
  });
});

function node(id: string, type: DfdNode['type'], label: string, x = 0, y = 0, width?: number, height?: number): DfdNode {
  return {
    id,
    type,
    position: { x, y },
    data: { label },
    ...(width || height ? { width, height, style: { width, height } } : {}),
  };
}

describe('resizeNodesToFit', () => {
  it('grow mode enlarges an undersized shape but preserves its centre', () => {
    const n = node('n1', 'external', 'Cluster workload / kubectl (client)', 100, 100, 120, 80);
    const [resized] = resizeNodesToFit([n], 'grow');
    expect(resized.width!).toBeGreaterThan(120);
    // Centre (100 + 120/2 = 160, 100 + 80/2 = 140) is preserved (within a pixel of integer rounding).
    expect(Math.abs(resized.position.x + resized.width! / 2 - 160)).toBeLessThanOrEqual(1);
    expect(Math.abs(resized.position.y + resized.height! / 2 - 140)).toBeLessThanOrEqual(1);
  });

  it('grow mode never shrinks a hand-tuned size', () => {
    const n = node('n1', 'external', 'etcd', 0, 0, 300, 200);
    const [resized] = resizeNodesToFit([n], 'grow');
    expect(resized).toBe(n); // unchanged reference: already larger than the fit
  });

  it('exact mode shrinks an oversized shape to the computed fit', () => {
    const n = node('n1', 'external', 'etcd', 0, 0, 300, 200);
    const [resized] = resizeNodesToFit([n], 'exact');
    expect(resized.width!).toBe(120);
    expect(resized.height!).toBe(64);
  });

  it('leaves trust boundaries untouched', () => {
    const b = node('b1', 'boundary', 'Control-plane node', 0, 0, 260, 180);
    const [resized] = resizeNodesToFit([b], 'exact');
    expect(resized).toBe(b);
  });
});

function edge(id: string, source: string, target: string, labelOffset?: { x: number; y: number }): DfdEdge {
  return { id, source, target, label: id, data: labelOffset ? { labelOffset } : {} };
}

function overlap(a: DfdNode, b: DfdNode): boolean {
  const ar = { x: a.position.x, y: a.position.y, w: a.width ?? 0, h: a.height ?? 0 };
  const br = { x: b.position.x, y: b.position.y, w: b.width ?? 0, h: b.height ?? 0 };
  const ox = Math.min(ar.x + ar.w, br.x + br.w) - Math.max(ar.x, br.x);
  const oy = Math.min(ar.y + ar.h, br.y + br.h) - Math.max(ar.y, br.y);
  return ox > 0 && oy > 0;
}

describe('separateNodes', () => {
  it('pushes two overlapping shapes apart until they no longer overlap', () => {
    const a = node('a', 'process', 'A', 100, 100, 140, 140);
    const b = node('b', 'process', 'B', 160, 120, 140, 140);
    expect(overlap(a, b)).toBe(true);
    const out = separateNodes([a, b]);
    expect(overlap(out[0], out[1])).toBe(false);
  });

  it('leaves well-separated shapes exactly where they are', () => {
    const a = node('a', 'process', 'A', 0, 0, 140, 140);
    const b = node('b', 'process', 'B', 400, 0, 140, 140);
    const out = separateNodes([a, b]);
    expect(out[0]).toBe(a);
    expect(out[1]).toBe(b);
  });

  it('grows a boundary to keep containing shapes pushed against its edge', () => {
    const boundary = node('bnd', 'boundary', 'TB', 0, 0, 200, 120);
    const a = node('a', 'datastore', 'A', 20, 30, 160, 60);
    const b = node('b', 'datastore', 'B', 60, 40, 160, 60);
    const out = separateNodes([boundary, a, b]);
    const rb = out.find((n) => n.id === 'bnd')!;
    const ra = out.find((n) => n.id === 'a')!;
    const rc = out.find((n) => n.id === 'b')!;
    expect(overlap(ra, rc)).toBe(false);
    // The boundary grew (in at least one dimension) to keep wrapping the separated pair...
    expect(rb.width! * rb.height!).toBeGreaterThan(200 * 120);
    // ...and both stores stay fully inside it.
    for (const c of [ra, rc]) {
      expect(c.position.x).toBeGreaterThanOrEqual(rb.position.x);
      expect(c.position.y).toBeGreaterThanOrEqual(rb.position.y);
      expect(c.position.x + c.width!).toBeLessThanOrEqual(rb.position.x + rb.width!);
      expect(c.position.y + c.height!).toBeLessThanOrEqual(rb.position.y + rb.height!);
    }
  });

  it('separates overlapping trust boundaries together with their contents', () => {
    const b1 = node('b1', 'boundary', 'B1', 0, 0, 240, 180);
    const b2 = node('b2', 'boundary', 'B2', 180, 80, 240, 180);
    const a = node('a', 'process', 'A', 40, 40, 96, 96);
    const c = node('c', 'datastore', 'C', 280, 120, 120, 64);
    const out = separateNodes([b1, b2, a, c]);
    const rb1 = out.find((n) => n.id === 'b1')!;
    const rb2 = out.find((n) => n.id === 'b2')!;
    const ra = out.find((n) => n.id === 'a')!;
    const rc = out.find((n) => n.id === 'c')!;

    expect(overlap(rb1, rb2)).toBe(false);
    expect(Math.min(rb1.position.x, rb2.position.x)).toBeGreaterThanOrEqual(0);
    expect(ra.position.x - rb1.position.x).toBe(a.position.x - b1.position.x);
    expect(ra.position.y - rb1.position.y).toBe(a.position.y - b1.position.y);
    expect(rc.position.x - rb2.position.x).toBe(c.position.x - b2.position.x);
    expect(rc.position.y - rb2.position.y).toBe(c.position.y - b2.position.y);
  });

  it('adds clear space between peer boundaries whose outlines nearly touch', () => {
    const upper = node('upper', 'boundary', 'Upper', 0, 0, 240, 180);
    const lower = node('lower', 'boundary', 'Lower', 0, 184, 240, 180);
    const out = separateNodes([upper, lower]);
    const movedUpper = out.find((n) => n.id === 'upper')!;
    const movedLower = out.find((n) => n.id === 'lower')!;

    expect(movedUpper.position).toEqual(upper.position);
    expect(movedLower.position.y - (movedUpper.position.y + movedUpper.height!)).toBeGreaterThanOrEqual(24);
  });

  it('uses explicit boundary aliases before ambiguous geometric containment', () => {
    const b1 = { ...node('b1', 'boundary', 'Outer', 0, 0, 300, 240), data: { label: 'Outer', properties: { Alias: 'TB1' } } };
    const b2 = { ...node('b2', 'boundary', 'Inner', 100, 80, 300, 240), data: { label: 'Inner', properties: { Alias: 'TB2' } } };
    const member = {
      ...node('member', 'process', 'Member', 160, 120, 96, 96),
      data: { label: 'Member', properties: { Boundary: 'TB2' } },
    };
    const out = separateNodes([b1, b2, member]);
    const rb2 = out.find((n) => n.id === 'b2')!;
    const movedMember = out.find((n) => n.id === 'member')!;

    expect(movedMember.position.x - rb2.position.x).toBe(member.position.x - b2.position.x);
    expect(movedMember.position.y - rb2.position.y).toBe(member.position.y - b2.position.y);
  });

  it('preserves intentional nesting instead of separating contained boundaries', () => {
    const outer = node('outer', 'boundary', 'Outer', 0, 0, 500, 400);
    const inner = node('inner', 'boundary', 'Inner', 100, 100, 240, 180);
    const member = node('member', 'process', 'Member', 140, 140, 96, 96);
    const out = separateNodes([outer, inner, member]);

    expect(out.find((n) => n.id === 'outer')).toBe(outer);
    expect(out.find((n) => n.id === 'inner')).toBe(inner);
    expect(out.find((n) => n.id === 'member')).toBe(member);
  });

  it('moves cross-boundary overlaps by their owning region instead of independently', () => {
    // Two boundaries side by side; a node in each, overlapping in x only across the divide. The
    // second boundary must first grow around A, then move as a unit to clear the first boundary.
    const b1 = node('b1', 'boundary', 'B1', 0, 0, 200, 200);
    const b2 = node('b2', 'boundary', 'B2', 210, 0, 200, 200);
    const a = node('a', 'process', 'A', 150, 60, 120, 120); // centre 210 -> in b2
    const c = node('c', 'process', 'C', 40, 60, 120, 120); // centre 100 -> in b1
    const out = separateNodes([b1, b2, a, c]);
    const rb1 = out.find((n) => n.id === 'b1')!;
    const rb2 = out.find((n) => n.id === 'b2')!;
    const ra = out.find((n) => n.id === 'a')!;
    const rc = out.find((n) => n.id === 'c')!;

    expect(overlap(rb1, rb2)).toBe(false);
    for (const [member, boundary] of [[ra, rb2], [rc, rb1]]) {
      expect(member.position.x).toBeGreaterThanOrEqual(boundary.position.x);
      expect(member.position.y).toBeGreaterThanOrEqual(boundary.position.y);
      expect(member.position.x + member.width!).toBeLessThanOrEqual(boundary.position.x + boundary.width!);
      expect(member.position.y + member.height!).toBeLessThanOrEqual(boundary.position.y + boundary.height!);
    }
  });

  it('opens a strip at the top of a boundary so its own title is not covered', () => {
    const boundary = node('tb', 'boundary', 'Undercloud Kubernetes cluster', 0, 0, 300, 200);
    const member = node('m', 'datastore', 'Secret', 20, 10, 120, 64);
    expect(findBoundaryTitleOverlaps([boundary, member])).toEqual([{ boundaryId: 'tb', nodeId: 'm' }]);

    const out = separateNodes([boundary, member]);
    const movedBoundary = out.find((n) => n.id === 'tb')!;
    const movedMember = out.find((n) => n.id === 'm')!;

    expect(findBoundaryTitleOverlaps(out)).toEqual([]);
    // The region grew upwards; the author's shape did not move.
    expect(movedBoundary.position.y).toBeLessThan(boundary.position.y);
    expect(movedMember.position).toEqual(member.position);
    expect(movedMember.position.y + movedMember.height!).toBeLessThanOrEqual(
      movedBoundary.position.y + movedBoundary.height!,
    );
  });

  it('does not reserve a title strip a boundary already has', () => {
    const boundary = node('tb', 'boundary', 'Undercloud Kubernetes cluster', 0, 0, 300, 200);
    const member = node('m', 'datastore', 'Secret', 20, 100, 120, 64);
    expect(findBoundaryTitleOverlaps([boundary, member])).toEqual([]);
    expect(separateNodes([boundary, member]).find((n) => n.id === 'tb')).toBe(boundary);
  });

  it('reserves the same strip on a second run', () => {
    const nodes = [
      node('tb', 'boundary', 'Undercloud Kubernetes cluster', 0, 0, 300, 200),
      node('m', 'datastore', 'Secret', 20, 10, 120, 64),
    ];
    const once = separateNodes(nodes);
    const twice = separateNodes(once);
    expect(twice.find((n) => n.id === 'tb')).toBe(once.find((n) => n.id === 'tb'));
  });

  it('clears a nested region out of its parent title', () => {
    const outer = node('outer', 'boundary', 'Outer region', 0, 0, 600, 500);
    const inner = node('inner', 'boundary', 'Inner', 40, 5, 200, 150);
    expect(findBoundaryTitleOverlaps([outer, inner])).toEqual([{ boundaryId: 'outer', nodeId: 'inner' }]);

    const out = separateNodes([outer, inner]);
    expect(findBoundaryTitleOverlaps(out)).toEqual([]);
    expect(out.find((n) => n.id === 'inner')!.position).toEqual(inner.position);
  });
});

describe('deconflictEdgeLabels', () => {
  const nodes: DfdNode[] = [
    node('a', 'external', 'A', 0, 0, 160, 80),
    node('b', 'process', 'B', 400, 0, 140, 132),
  ];

  it('separates a request/response pair between the same two nodes', () => {
    const edges = [edge('req', 'a', 'b'), edge('res', 'b', 'a')];
    const out = deconflictEdgeLabels(nodes, edges);
    const offsets = out.map((e) => e.data?.labelOffset ?? { x: 0, y: 0 });
    // One label is pushed up, the other down; both stay horizontally on the line, and the pair is
    // separated by at least a label height so they no longer overlap.
    expect(offsets.every((o) => o.x === 0)).toBe(true);
    const ys = offsets.map((o) => o.y).sort((p, q) => p - q);
    expect(ys[0]).toBeLessThan(0);
    expect(ys[0]).toBe(-ys[1]); // symmetric about the shared midpoint
    expect(ys[1] - ys[0]).toBeGreaterThanOrEqual(22);
  });

  it('stacks two wide labels whose pills overlap even when their midpoints differ', () => {
    // Endpoints far to the sides put both midpoints in open space (no shape underneath); the two
    // long labels have anchors 100px apart yet pills far wider, so their boxes still overlap.
    const wide: DfdNode[] = [
      node('a1', 'external', 'A1', 0, 100, 100, 60),
      node('b1', 'process', 'B1', 800, 100, 100, 60),
      node('a2', 'external', 'A2', 100, 100, 100, 60),
      node('b2', 'process', 'B2', 900, 100, 100, 60),
    ];
    const long = 'HTTPS forward heartbeat metrics to the configured endpoint';
    const e1 = { id: 'f1', source: 'a1', target: 'b1', label: long, data: {} } as DfdEdge;
    const e2 = { id: 'f2', source: 'a2', target: 'b2', label: long, data: {} } as DfdEdge;
    const out = deconflictEdgeLabels(wide, [e1, e2]);
    const ys = out.map((e) => e.data?.labelOffset?.y ?? 0);
    expect(out.every((e) => (e.data?.labelOffset?.x ?? 0) === 0)).toBe(true);
    expect(Math.abs(ys[0] - ys[1])).toBeGreaterThanOrEqual(22); // stacked apart, not overlapping
  });

  it('lifts a label off a shape that sits under its flow midpoint', () => {
    const withObstacle: DfdNode[] = [
      node('a', 'external', 'A', 0, 0, 100, 60),
      node('b', 'process', 'B', 600, 0, 100, 60),
      node('c', 'process', 'C', 300, 0, 120, 80), // sits at the a->b midpoint
    ];
    const [out] = deconflictEdgeLabels(withObstacle, [
      { id: 'f', source: 'a', target: 'b', label: 'x', data: {} } as DfdEdge,
    ]);
    const dy = out.data?.labelOffset?.y ?? 0;
    expect(dy).not.toBe(0);
    // The label pill (centre 30 + dy, half-height 11) now clears node C's rectangle (y 0..80).
    const top = 30 + dy - 11;
    const bottom = 30 + dy + 11;
    expect(bottom <= 0 || top >= 80).toBe(true);
  });

  it('leaves a solitary flow label on the line', () => {
    const edges = [edge('only', 'a', 'b')];
    const out = deconflictEdgeLabels(nodes, edges);
    expect(out[0]).toBe(edges[0]); // unchanged reference: no offset needed
  });

  it('respects a label the author has already dragged aside', () => {
    const manual = edge('req', 'a', 'b', { x: 20, y: -40 });
    const out = deconflictEdgeLabels(nodes, [manual, edge('res', 'b', 'a')]);
    expect(out[0].data?.labelOffset).toEqual({ x: 20, y: -40 });
  });

  it('recomputes an automatic offset after object geometry changes', () => {
    const automatic = {
      ...edge('req', 'a', 'b', { x: 0, y: -40 }),
      data: { labelOffset: { x: 0, y: -40 }, autoLabelOffset: true },
    };
    const obstacle = node('c', 'process', 'C', 220, 20, 120, 80);

    const [out] = deconflictEdgeLabels([...nodes, obstacle], [automatic]);

    expect(out.data?.autoLabelOffset).toBe(true);
    expect(out.data?.labelOffset).not.toEqual({ x: 0, y: -40 });
  });

  it('clears a stale automatic offset when the label no longer needs one', () => {
    const automatic = {
      ...edge('only', 'a', 'b', { x: 0, y: 40 }),
      data: { labelOffset: { x: 0, y: 40 }, autoLabelOffset: true },
    };

    const [out] = deconflictEdgeLabels(nodes, [automatic]);

    expect(out.data?.labelOffset).toBeUndefined();
    expect(out.data?.autoLabelOffset).toBeUndefined();
  });

  it('keeps labels clear of a trust-boundary title strip', () => {
    const boundary = node('tb', 'boundary', 'Edge Kubernetes cluster', 200, 20, 320, 220);
    const endpoints = [
      node('left', 'external', 'Left', 0, 0, 100, 60),
      node('right', 'process', 'Right', 600, 0, 100, 60),
    ];

    const [out] = deconflictEdgeLabels([boundary, ...endpoints], [edge('flow', 'left', 'right')]);
    const dy = out.data?.labelOffset?.y ?? 0;
    const labelCenterY = 30 + dy;

    expect(labelCenterY + 11 <= 20 || labelCenterY - 11 >= 48).toBe(true);
  });

  it('finds a two-dimensional slot in a dense object corridor', () => {
    const dense: DfdNode[] = [
      node('left', 'process', 'Left', 0, 100, 140, 132),
      node('right', 'process', 'Right', 600, 100, 140, 132),
      node('middle-top', 'process', 'Middle top', 260, 40, 180, 120),
      node('middle-bottom', 'datastore', 'Middle bottom', 260, 180, 180, 90),
    ];
    const flows: DfdEdge[] = [
      { id: 'f1', source: 'left', target: 'right', label: 'Long request label crossing the dense middle corridor', data: {} },
      { id: 'f2', source: 'right', target: 'left', label: 'Long response label crossing the dense middle corridor', data: {} },
    ];

    const routed = routeEdges(dense, flows);
    const placed = deconflictEdgeLabels(dense, routed);

    expect(findEdgeLabelObjectOverlaps(dense, placed)).toEqual([]);
    expect(placed.every((flow) => flow.data?.autoLabelOffset)).toBe(true);
  });

  it('is stable across repeated runs', () => {
    const edges = [edge('req', 'a', 'b'), edge('res', 'b', 'a')];
    const once = deconflictEdgeLabels(nodes, edges);
    const twice = deconflictEdgeLabels(nodes, once);
    expect(twice.map((e) => e.data?.labelOffset)).toEqual(once.map((e) => e.data?.labelOffset));
  });
});

describe('routeEdges', () => {
  it('routes a rightward flow out of the source right port and into the target left port', () => {
    const nodes = [node('a', 'process', 'A', 0, 0, 100, 100), node('b', 'process', 'B', 400, 0, 100, 100)];
    const [routed] = routeEdges(nodes, [edge('e', 'a', 'b')]);
    expect(routed.sourceHandle).toBe('r');
    expect(routed.targetHandle).toBe('l');
  });

  it('routes a downward flow bottom-to-top', () => {
    const nodes = [node('a', 'process', 'A', 0, 0, 100, 100), node('b', 'process', 'B', 0, 400, 100, 100)];
    const [routed] = routeEdges(nodes, [edge('e', 'a', 'b')]);
    expect(routed.sourceHandle).toBe('b');
    expect(routed.targetHandle).toBe('t');
  });

  it('leaves a flow touching a trust boundary for React Flow to place', () => {
    const nodes = [node('bnd', 'boundary', 'TB', 0, 0, 300, 300), node('b', 'process', 'B', 400, 0, 100, 100)];
    const edges = [edge('e', 'bnd', 'b')];
    const out = routeEdges(nodes, edges);
    expect(out[0]).toBe(edges[0]); // unchanged reference: a boundary has no ports
  });

  it('is a no-op on a second run', () => {
    const nodes = [node('a', 'process', 'A', 0, 0, 100, 100), node('b', 'process', 'B', 400, 0, 100, 100)];
    const once = routeEdges(nodes, [edge('e', 'a', 'b')]);
    const twice = routeEdges(nodes, once);
    expect(twice[0]).toBe(once[0]); // same reference: handles already face their endpoints
  });
});

describe('tidyGraph', () => {
  it('fits shapes and separates overlapping labels in one pass', () => {
    const nodes: DfdNode[] = [
      node('a', 'external', 'Cluster workload / kubectl (client)', 0, 0, 120, 80),
      node('b', 'process', 'kube-apiserver (+ encryption provider)', 400, 0, 100, 100),
    ];
    const edges = [edge('req', 'a', 'b'), edge('res', 'b', 'a')];
    const out = tidyGraph(nodes, edges, 'exact');
    expect(out.nodes[0].width!).toBeGreaterThan(120);
    expect(out.nodes[1].height!).toBeGreaterThan(100);
    expect(out.edges.some((e) => (e.data?.labelOffset?.y ?? 0) !== 0)).toBe(true);
    // Every component-to-component flow is routed through a pair of facing ports.
    expect(out.edges.every((e) => Boolean(e.sourceHandle) && Boolean(e.targetHandle))).toBe(true);
  });

  it('clears both shapes and flow labels off every trust-boundary title', () => {
    const nodes: DfdNode[] = [
      node('tb', 'boundary', 'Undercloud Kubernetes cluster (nc-system namespace)', 0, 0, 320, 400),
      node('a', 'process', 'IPA host-image reverse proxy', 24, 12, 140, 132),
      node('b', 'datastore', 'ironic-api TLS certificate', 24, 240, 160, 80),
    ];
    const edges = [edge('req', 'a', 'b')];
    expect(findBoundaryTitleOverlaps(nodes).length).toBeGreaterThan(0);

    const out = tidyGraph(nodes, edges, 'exact');

    expect(findBoundaryTitleOverlaps(out.nodes)).toEqual([]);
    expect(findEdgeLabelObjectOverlaps(out.nodes, out.edges)).toEqual([]);
  });
});
