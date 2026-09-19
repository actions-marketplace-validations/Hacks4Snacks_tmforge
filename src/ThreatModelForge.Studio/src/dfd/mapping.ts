import { MarkerType } from '@xyflow/react';
import type { DfdEdge, DfdKind, DfdNode, TmForgeElement, TmForgeFlow, TmForgeModel, TmForgeAnalysis } from './types';

function num(value: unknown, fallback: number): number {
  const n = typeof value === 'string' ? parseFloat(value) : typeof value === 'number' ? value : NaN;
  return Number.isFinite(n) ? n : fallback;
}

/**
 * Default on-canvas size (px) per node kind — used when creating a node and when a loaded model has
 * no explicit size. The shape values match each stencil's rendered footprint so existing diagrams
 * look unchanged; every kind is resizable from this starting point.
 */
export const DEFAULT_NODE_SIZE: Record<DfdKind, { width: number; height: number }> = {
  process: { width: 140, height: 132 },
  datastore: { width: 194, height: 81 },
  external: { width: 186, height: 86 },
  boundary: { width: 260, height: 180 },
};

/** React Flow graph -> canonical tmforge-json. */
export function toModel(nodes: DfdNode[], edges: DfdEdge[]): TmForgeModel {
  return {
    schema: 'tmforge-json',
    version: '0.1',
    elements: nodes.map((n) => {
      const kind = (n.type ?? 'process') as DfdKind;
      const size = DEFAULT_NODE_SIZE[kind];
      const el: TmForgeElement = {
        id: n.id,
        kind,
        name: n.data.label,
        x: Math.round(n.position.x),
        y: Math.round(n.position.y),
        width: Math.round(num(n.width ?? n.style?.width, size.width)),
        height: Math.round(num(n.height ?? n.style?.height, size.height)),
      };
      // Carry the stencil identity into the model as a custom property so the engine (and any
      // stencil-aware rule or report) sees it, and it round-trips through tmforge-json.
      const properties = { ...(n.data.properties ?? {}) };
      if (n.data.stencilType) {
        properties.StencilType = n.data.stencilType;
      }
      if (Object.keys(properties).length > 0) {
        el.properties = properties;
      }
      return el;
    }),
    flows: edges.map((e) => {
      const flow: TmForgeFlow = {
        id: e.id,
        source: e.source,
        target: e.target,
        name: typeof e.label === 'string' ? e.label : 'data flow',
      };
      const props = e.data?.properties;
      if (props && Object.keys(props).length > 0) {
        flow.properties = props;
      }
      const offset = e.data?.labelOffset;
      if (!e.data?.autoLabelOffset && offset && (offset.x !== 0 || offset.y !== 0)) {
        flow.labelOffset = { x: Math.round(offset.x), y: Math.round(offset.y) };
      }
      // Persist the ports Tidy routed the flow through so the routing survives a reload.
      if (typeof e.sourceHandle === 'string') {
        flow.sourceHandle = e.sourceHandle;
      }
      if (typeof e.targetHandle === 'string') {
        flow.targetHandle = e.targetHandle;
      }
      return flow;
    }),
  };
}

/** Canonical tmforge-json -> React Flow graph. */
export function fromModel(model: TmForgeModel): { nodes: DfdNode[]; edges: DfdEdge[] } {
  const nodes: DfdNode[] = model.elements.map((el) => {
    // StencilType is surfaced separately as node.data.stencilType; keep it out of the editable
    // custom-property list the Inspector shows (it is re-added on export by toModel).
    const properties = { ...(el.properties ?? {}) };
    const stencilType = properties.StencilType;
    delete properties.StencilType;
    const size = DEFAULT_NODE_SIZE[el.kind];
    const width = el.width ?? size.width;
    const height = el.height ?? size.height;
    return {
      id: el.id,
      type: el.kind,
      position: { x: el.x, y: el.y },
      data: { label: el.name, stencilType, properties },
      // Set the size top-level as well as in style so React Flow knows each node's dimensions on the
      // first render (before it measures the DOM); without this an edge can't resolve its handle
      // positions and stays unrendered until an interaction re-measures — e.g. on a reload restore.
      width,
      height,
      style: { width, height },
      zIndex: el.kind === 'boundary' ? 0 : 1,
    };
  });

  const edges: DfdEdge[] = model.flows.map((f) => {
    const edge: DfdEdge = {
      id: f.id,
      source: f.source,
      target: f.target,
      label: f.name,
      type: 'flow',
      markerEnd: { type: MarkerType.ArrowClosed },
      data: { properties: f.properties ?? {}, labelOffset: f.labelOffset },
    };
    // Only set the ports when the flow carries them (a Tidy-routed model); leaving the keys off an
    // unrouted flow lets React Flow place the line on its default port.
    if (f.sourceHandle) {
      edge.sourceHandle = f.sourceHandle;
    }
    if (f.targetHandle) {
      edge.targetHandle = f.targetHandle;
    }
    return edge;
  });

  return { nodes, edges };
}

/** A single editor page (diagram): a named React Flow graph. */
export interface PageGraph {
  id: string;
  name: string;
  preserveIdentity?: boolean;
  nodes: DfdNode[];
  edges: DfdEdge[];
}

/**
 * Canonical model -> editor pages. A multi-page model (`diagrams`) yields one page per diagram,
 * preserving ids and names; a single-page model yields one page named "Page 1".
 */
export function pagesFromModel(model: TmForgeModel): PageGraph[] {
  if (model.diagrams && model.diagrams.length > 0) {
    return model.diagrams.map((d, i) => {
      const { nodes, edges } = fromModel({
        schema: 'tmforge-json',
        version: '0.1',
        elements: d.elements ?? [],
        flows: d.flows ?? [],
      });
      return { id: d.id || crypto.randomUUID(), name: d.name || `Page ${i + 1}`, preserveIdentity: true, nodes, edges };
    });
  }
  const { nodes, edges } = fromModel(model);
  return [{ id: crypto.randomUUID(), name: 'Page 1', nodes, edges }];
}

/**
 * Editor pages -> canonical model. Mirrors the engine's `TmForgeJsonFormat`: the top-level
 * `elements`/`flows` carry the first page for single-page readers, and `diagrams` is emitted only
 * when there is more than one page or an imported page has an explicit identity. Author-owned
 * metadata, threats and the analysis selection are attached when present.
 */
export function modelFromPages(
  pages: PageGraph[],
  analysis?: TmForgeAnalysis,
  threats?: TmForgeModel['threats'],
  metadata?: TmForgeModel['metadata'],
): TmForgeModel {
  const perPage = pages.map((p) => ({ page: p, graph: toModel(p.nodes, p.edges) }));
  const first = perPage[0]?.graph;
  const model: TmForgeModel = {
    schema: 'tmforge-json',
    version: '0.1',
    elements: first?.elements ?? [],
    flows: first?.flows ?? [],
  };
  if (pages.length > 1 || pages[0]?.preserveIdentity) {
    model.diagrams = perPage.map(({ page, graph }) => ({
      id: page.id,
      name: page.name,
      elements: graph.elements,
      flows: graph.flows,
    }));
  }
  if (analysis) {
    model.analysis = analysis;
  }
  if (threats?.length) {
    model.threats = threats;
  }
  if (metadata) {
    model.metadata = metadata;
  }
  return model;
}
