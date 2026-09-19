import { describe, it, expect } from 'vitest';
import { toModel, fromModel, pagesFromModel, modelFromPages } from './mapping';
import type { DfdEdge, DfdNode } from './types';

const nodes: DfdNode[] = [
  { id: 'n1', type: 'process', position: { x: 10, y: 20 }, data: { label: 'API', properties: { AuthenticationScheme: 'OAuth' } } },
  { id: 'n2', type: 'external', position: { x: 200, y: 20 }, data: { label: 'User', properties: {} } },
];

const edges: DfdEdge[] = [
  { id: 'f1', source: 'n1', target: 'n2', label: 'request', data: { properties: { Protocol: 'HTTPS', Port: '443', Algorithm: 'AES-GCM' } } },
];

describe('mapping — property round-trip (inspector edits reach the engine)', () => {
  it('toModel carries every flow property into the canonical model', () => {
    const model = toModel(nodes, edges);
    expect(model.flows[0].properties).toEqual({ Protocol: 'HTTPS', Port: '443', Algorithm: 'AES-GCM' });
    expect(model.elements[0].properties).toMatchObject({ AuthenticationScheme: 'OAuth' });
  });

  it('fromModel restores flow and element properties onto the graph', () => {
    const { nodes: rn, edges: re } = fromModel(toModel(nodes, edges));
    expect(re[0].data?.properties).toEqual({ Protocol: 'HTTPS', Port: '443', Algorithm: 'AES-GCM' });
    expect(rn[0].data.properties).toMatchObject({ AuthenticationScheme: 'OAuth' });
  });

  it('survives a full pages round-trip', () => {
    const page = { id: 'p1', name: 'Page 1', nodes, edges };
    const model = modelFromPages([page]);
    const pages = pagesFromModel(model);
    expect(pages).toHaveLength(1);
    expect(pages[0].edges[0].data?.properties).toEqual({ Protocol: 'HTTPS', Port: '443', Algorithm: 'AES-GCM' });
  });

  it('preserves an explicitly identified single page and its imported evidence', () => {
    const graph = toModel(nodes, edges);
    const model = {
      ...graph,
      metadata: { owner: 'Reviewer', threatModelName: 'Imported model' },
      diagrams: [{ id: 'imported-page', name: 'Requests', elements: graph.elements, flows: graph.flows }],
      threats: [{ id: 'manual:threat-dragon.original', state: 'Accepted' as const, source: { format: 'threat-dragon', id: 'original' } }],
    };

    const restored = modelFromPages(pagesFromModel(model), undefined, model.threats, model.metadata);

    expect(restored.diagrams?.[0]).toMatchObject({ id: 'imported-page', name: 'Requests' });
    expect(restored.threats).toEqual(model.threats);
    expect(restored.metadata).toEqual(model.metadata);
    expect(modelFromPages(pagesFromModel(graph)).diagrams).toBeUndefined();
  });

  it('omits the properties key entirely for an element with no custom properties', () => {
    const model = toModel(nodes, edges);
    // n2 (User) had an empty properties bag — it should not serialize a properties object.
    expect(model.elements[1].properties).toBeUndefined();
  });

  it('does not serialize a transient Tidy label offset', () => {
    const automatic: DfdEdge = {
      ...edges[0],
      data: { ...edges[0].data, labelOffset: { x: 0, y: 24 }, autoLabelOffset: true },
    };

    expect(toModel(nodes, [automatic]).flows[0].labelOffset).toBeUndefined();
  });
});

describe('mapping — routed ports round-trip (Tidy layout survives a reload)', () => {
  const routed: DfdEdge[] = [
    { id: 'f1', source: 'n1', target: 'n2', label: 'request', sourceHandle: 'r', targetHandle: 'l', data: { properties: {} } },
  ];

  it('toModel persists the source/target ports on the flow', () => {
    const model = toModel(nodes, routed);
    expect(model.flows[0].sourceHandle).toBe('r');
    expect(model.flows[0].targetHandle).toBe('l');
  });

  it('fromModel restores the ports onto the edge', () => {
    const { edges: re } = fromModel(toModel(nodes, routed));
    expect(re[0].sourceHandle).toBe('r');
    expect(re[0].targetHandle).toBe('l');
  });

  it('omits the port keys for an unrouted flow', () => {
    const model = toModel(nodes, edges);
    expect(model.flows[0].sourceHandle).toBeUndefined();
    expect(model.flows[0].targetHandle).toBeUndefined();
  });
});
