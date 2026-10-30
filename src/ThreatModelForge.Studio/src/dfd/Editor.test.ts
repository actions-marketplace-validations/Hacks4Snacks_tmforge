import { describe, it, expect, beforeEach } from 'vitest';
import {
  loadStoredWorkspace,
  emptyWorkspace,
  loadRecentStencilIds,
  loadStringList,
  persistStringList,
  buildFileAccept,
  isAbortError,
  modelNameForManifest,
  buildAnalysis,
  applyCanvasEdgeChanges,
  applyFlags,
  highlightForFocus,
  deleteFromGraph,
  threatIdsForDeletedObjects,
  sameIds,
  initialTheme,
  STORAGE_KEY,
  LEGACY_MODEL_KEY,
  THEME_KEY,
  RECENTS_KEY,
  RECENTS_MAX,
} from './Editor';
import { modelFromPages, type PageGraph } from './mapping';
import type { EdgeChange } from '@xyflow/react';
import type { DfdEdge, DfdNode } from './types';

const processNode: DfdNode = { id: 'n1', type: 'process', position: { x: 10, y: 20 }, data: { label: 'API' } };
const externalNode: DfdNode = { id: 'n2', type: 'external', position: { x: 200, y: 20 }, data: { label: 'User' } };

beforeEach(() => {
  window.localStorage.clear();
});

describe('Threat scope deletion', () => {
  it('matches sparse generated identities and explicit scopes without deleting model-wide decisions', async () => {
    const objectId = '11111111-2222-4333-8444-555555555555';
    const flowId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
    const removed = await threatIdsForDeletedObjects([
      { id: '11111111222243338444555555555555:TM1023' },
      { id: 'AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE:pack/rule' },
      { id: 'foreign-threat-key', elementIds: [objectId] },
      { id: 'manual:scoped', manual: true, elementIds: [flowId] },
      { id: 'manual:model-wide', manual: true },
      { id: 'manual:unrelated', elementIds: ['99999999-2222-4333-8444-555555555555'] },
    ], [objectId, flowId]);
    expect([...removed]).toEqual(['11111111222243338444555555555555:TM1023',
      'AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE:pack/rule', 'foreign-threat-key', 'manual:scoped']);
  });

  it('uses the engine identity for aliases and keeps page and object namespaces distinct', async () => {
    const threats = [{ id: '6b3c361cb7be5f01be4b0cd6e29c6686:TM1021' }, { id: 'manual:scoped', elementIds: ['audit'] }];
    expect([...await threatIdsForDeletedObjects(threats, ['audit'])]).toEqual(threats.map(threat => threat.id));
    expect([...await threatIdsForDeletedObjects([threats[0]], [], 'audit')]).toEqual([]);
    expect([...await threatIdsForDeletedObjects([], ['audit'])]).toEqual([]);
  });
});

describe('Editor — workspace persistence and legacy migration', () => {
  it('returns null when nothing is stored', () => {
    expect(loadStoredWorkspace()).toBeNull();
  });

  it('restores a stored multi-page workspace, preserving page ids, names, and the active page', () => {
    const pageA: PageGraph = { id: 'pa', name: 'Context', nodes: [processNode], edges: [] };
    const pageB: PageGraph = { id: 'pb', name: 'Payments', nodes: [externalNode], edges: [] };
    const model = modelFromPages([pageA, pageB]);
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify({ model, activePageId: 'pb' }));

    const workspace = loadStoredWorkspace();

    expect(workspace).not.toBeNull();
    expect(workspace!.pages.map((p) => p.id)).toEqual(['pa', 'pb']);
    expect(workspace!.pages.map((p) => p.name)).toEqual(['Context', 'Payments']);
    expect(workspace!.activePageId).toBe('pb');
  });

  it('falls back to the first page when the stored active page id is unknown', () => {
    const pageA: PageGraph = { id: 'pa', name: 'Context', nodes: [processNode], edges: [] };
    const pageB: PageGraph = { id: 'pb', name: 'Payments', nodes: [externalNode], edges: [] };
    const model = modelFromPages([pageA, pageB]);
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify({ model, activePageId: 'gone' }));

    const workspace = loadStoredWorkspace();

    expect(workspace!.activePageId).toBe('pa');
  });

  it('carries the analysis selection and threat triage from the stored model', () => {
    const pageA: PageGraph = { id: 'pa', name: 'Context', nodes: [processNode], edges: [] };
    const pageB: PageGraph = { id: 'pb', name: 'Payments', nodes: [externalNode], edges: [] };
    const model = modelFromPages([pageA, pageB], { disabledRuleIds: ['TM1002'] });
    model.threats = [{ id: '{g}:TM1002', state: 'Accepted', justification: 'residual risk' }];
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify({ model, activePageId: 'pa' }));

    const workspace = loadStoredWorkspace();

    expect(workspace!.analysis).toEqual({ disabledRuleIds: ['TM1002'] });
    expect(workspace!.threats).toEqual([{ id: '{g}:TM1002', state: 'Accepted', justification: 'residual risk' }]);
  });

  it('migrates a legacy single-page (v1) model when no v2 workspace is present', () => {
    const model = modelFromPages([{ id: 'x', name: 'Page 1', nodes: [processNode], edges: [] }]);
    window.localStorage.setItem(LEGACY_MODEL_KEY, JSON.stringify(model));

    const workspace = loadStoredWorkspace();

    expect(workspace).not.toBeNull();
    expect(workspace!.pages).toHaveLength(1);
    expect(workspace!.activePageId).toBe(workspace!.pages[0].id);
  });

  it('prefers the v2 workspace over a legacy v1 model when both are present', () => {
    const legacy = modelFromPages([{ id: 'x', name: 'Legacy', nodes: [processNode], edges: [] }]);
    window.localStorage.setItem(LEGACY_MODEL_KEY, JSON.stringify(legacy));
    const v2 = modelFromPages([
      { id: 'pa', name: 'Context', nodes: [processNode], edges: [] },
      { id: 'pb', name: 'Payments', nodes: [externalNode], edges: [] },
    ]);
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify({ model: v2, activePageId: 'pa' }));

    const workspace = loadStoredWorkspace();

    expect(workspace!.pages).toHaveLength(2);
  });

  it('returns null on malformed stored JSON rather than throwing', () => {
    window.localStorage.setItem(STORAGE_KEY, '{ not valid json');
    expect(loadStoredWorkspace()).toBeNull();
  });
});

describe('Editor — emptyWorkspace', () => {
  it('creates a single empty page whose id is the active page', () => {
    const workspace = emptyWorkspace();

    expect(workspace.pages).toHaveLength(1);
    expect(workspace.pages[0].name).toBe('Page 1');
    expect(workspace.pages[0].nodes).toEqual([]);
    expect(workspace.pages[0].edges).toEqual([]);
    expect(workspace.pages[0].id).toBeTruthy();
    expect(workspace.activePageId).toBe(workspace.pages[0].id);
  });
});

describe('Editor — recently used stencils', () => {
  it('returns an empty list when nothing is stored', () => {
    expect(loadRecentStencilIds()).toEqual([]);
  });

  it('returns the stored ids in order', () => {
    window.localStorage.setItem(RECENTS_KEY, JSON.stringify(['a', 'b', 'c']));
    expect(loadRecentStencilIds()).toEqual(['a', 'b', 'c']);
  });

  it('caps the list at the remembered maximum', () => {
    const many = Array.from({ length: RECENTS_MAX + 3 }, (_, i) => `s${i}`);
    window.localStorage.setItem(RECENTS_KEY, JSON.stringify(many));

    const recents = loadRecentStencilIds();

    expect(recents).toHaveLength(RECENTS_MAX);
    expect(recents).toEqual(many.slice(0, RECENTS_MAX));
  });

  it('filters out non-string entries', () => {
    window.localStorage.setItem(RECENTS_KEY, JSON.stringify(['a', 1, null, 'b', {}]));
    expect(loadRecentStencilIds()).toEqual(['a', 'b']);
  });

  it('returns an empty list for a non-array or corrupt value', () => {
    window.localStorage.setItem(RECENTS_KEY, JSON.stringify({ not: 'an array' }));
    expect(loadRecentStencilIds()).toEqual([]);
    window.localStorage.setItem(RECENTS_KEY, 'not json');
    expect(loadRecentStencilIds()).toEqual([]);
  });
});

describe('Editor — persisted string lists (disabled packs, favorites)', () => {
  it('round-trips a list through persist and load', () => {
    persistStringList('tmforge.test.list', ['x', 'y']);
    expect(loadStringList('tmforge.test.list')).toEqual(['x', 'y']);
  });

  it('does not cap the list (unlike recents)', () => {
    const big = Array.from({ length: RECENTS_MAX + 10 }, (_, i) => `v${i}`);
    persistStringList('tmforge.test.list', big);
    expect(loadStringList('tmforge.test.list')).toEqual(big);
  });

  it('filters out non-string entries and tolerates corrupt data', () => {
    window.localStorage.setItem('tmforge.test.list', JSON.stringify(['a', 2, 'b']));
    expect(loadStringList('tmforge.test.list')).toEqual(['a', 'b']);
    window.localStorage.setItem('tmforge.test.list', '{ broken');
    expect(loadStringList('tmforge.test.list')).toEqual([]);
  });
});

describe('Editor — isAbortError', () => {
  it('is true only for a DOMException named AbortError', () => {
    expect(isAbortError(new DOMException('cancelled', 'AbortError'))).toBe(true);
  });

  it('is false for other DOMExceptions and non-exceptions', () => {
    expect(isAbortError(new DOMException('missing', 'NotFoundError'))).toBe(false);
    expect(isAbortError(new Error('AbortError'))).toBe(false);
    expect(isAbortError('AbortError')).toBe(false);
    expect(isAbortError(null)).toBe(false);
  });
});

describe('Editor — file picker filter', () => {
  it('includes .json for the canonical compound tmforge extension', () => {
    const accept = buildFileAccept([
      {
        id: 'tmforge-json',
        displayName: 'Threat Model Forge JSON (.tmforge.json)',
        extensions: ['.tmforge.json'],
        canRead: true,
        canWrite: true,
      },
    ]);

    expect(accept).toBe('.tmforge.json,.json');
  });

  it('deduplicates terminal extensions and ignores write-only formats', () => {
    const accept = buildFileAccept([
      {
        id: 'tmforge-json',
        displayName: 'Threat Model Forge JSON (.tmforge.json)',
        extensions: ['.tmforge.json'],
        canRead: true,
        canWrite: true,
      },
      {
        id: 'json',
        displayName: 'JSON',
        extensions: ['.json'],
        canRead: true,
        canWrite: false,
      },
      {
        id: 'output-only',
        displayName: 'Output only',
        extensions: ['.out'],
        canRead: false,
        canWrite: true,
      },
    ]);

    expect(accept).toBe('.tmforge.json,.json');
  });

  it('uses the startup fallback before format metadata is available', () => {
    expect(buildFileAccept([])).toBe('.json,.tm7,.drawio,.vsdx');
  });
});

describe('Editor — naming a model opened from an authoring manifest', () => {
  // Save falls back to Save As, which offers the bound file name. Keeping the manifest's own name
  // would invite the author to overwrite their reviewable source with the model built from it.
  it('replaces the manifest extension with the model extension', () => {
    expect(modelNameForManifest('threat-model.tm.json')).toBe('threat-model.tmforge.json');
    expect(modelNameForManifest('webshop.manifest.json')).toBe('webshop.tmforge.json');
    expect(modelNameForManifest('model.json')).toBe('model.tmforge.json');
    expect(modelNameForManifest('MODEL.JSON')).toBe('MODEL.tmforge.json');
  });

  it('never produces an empty or extension-less name, whatever the source was called', () => {
    for (const source of ['.json', 'manifest', 'a.b.c.json', '  ']) {
      const named = modelNameForManifest(source);
      expect(named.endsWith('.tmforge.json')).toBe(true);
      expect(named.length).toBeGreaterThan('.tmforge.json'.length);
    }
  });
});

describe('Editor — buildAnalysis', () => {
  it('is undefined when nothing is disabled', () => {
    expect(buildAnalysis([], [])).toBeUndefined();
  });

  it('includes only the toggles that are set', () => {
    expect(buildAnalysis(['availability'], [])).toEqual({ disabledPacks: ['availability'] });
    expect(buildAnalysis([], ['TM1002'])).toEqual({ disabledRuleIds: ['TM1002'] });
    expect(buildAnalysis(['availability'], ['TM1002'])).toEqual({
      disabledPacks: ['availability'],
      disabledRuleIds: ['TM1002'],
    });
  });
});

describe('Editor — applyFlags', () => {
  const nodes: DfdNode[] = [
    { id: 'n1', type: 'process', position: { x: 0, y: 0 }, data: { label: 'A' } },
    { id: 'n2', type: 'external', position: { x: 0, y: 0 }, data: { label: 'B' } },
  ];
  const edges: DfdEdge[] = [{ id: 'e1', source: 'n1', target: 'n2' }];

  it('applies the flagged class to referenced nodes and edges only', () => {
    const result = applyFlags(nodes, edges, new Set(['n1', 'e1']));

    expect(result.nodes[0].className).toBe('flagged');
    expect(result.nodes[1].className).toBeUndefined();
    expect(result.edges[0].className).toBe('flagged');
  });

  it('returns fresh copies and does not mutate the inputs', () => {
    const result = applyFlags(nodes, edges, new Set(['n1', 'e1']));

    expect(result.nodes[0]).not.toBe(nodes[0]);
    expect(result.edges[0]).not.toBe(edges[0]);
    expect(nodes[0].className).toBeUndefined();
    expect(edges[0].className).toBeUndefined();
  });

  it('clears the flagged class when the set is empty', () => {
    const flagged = applyFlags(nodes, edges, new Set(['n1', 'e1']));
    const cleared = applyFlags(flagged.nodes, flagged.edges, new Set());

    expect(cleared.nodes.every((n) => n.className === undefined)).toBe(true);
    expect(cleared.edges.every((e) => e.className === undefined)).toBe(true);
  });

  it('replaces aggregate flags with the elements referenced by one finding', () => {
    const aggregate = applyFlags(nodes, edges, new Set(['n1', 'n2', 'e1']));
    const focused = applyFlags(aggregate.nodes, aggregate.edges, new Set(['n2']));

    expect(focused.nodes[0].className).toBeUndefined();
    expect(focused.nodes[1].className).toBe('flagged');
    expect(focused.edges[0].className).toBeUndefined();
  });
});

describe('Editor — highlightForFocus', () => {
  it('lights up a flow together with both of its endpoints', () => {
    expect(highlightForFocus('e1', { source: 'n1', target: 'n2' })).toEqual(new Set(['e1', 'n1', 'n2']));
  });

  it('lights up an object on its own', () => {
    expect(highlightForFocus('n1')).toEqual(new Set(['n1']));
  });

  it('collapses a self-flow to the two ids involved', () => {
    expect(highlightForFocus('e1', { source: 'n1', target: 'n1' })).toEqual(new Set(['e1', 'n1']));
  });
});

describe('Editor — Tidy edge geometry', () => {
  const route = {
    points: [{ x: 120, y: 40 }, { x: 280, y: 40 }],
    label: { x: 200, y: 40 },
    labelAxis: 'horizontal',
  };

  it('preserves every routed line when controlled replacements omit Studio geometry', () => {
    const current: DfdEdge[] = ['e1', 'e2', 'e3'].map((id, index) => ({
      id,
      source: `n${index}`,
      target: `n${index + 1}`,
      sourceHandle: 'r',
      targetHandle: 'l',
      data: {
        labelOffset: { x: 0, y: index * 18 },
        route,
        autoLabelOffset: true,
        properties: { Protocol: 'HTTPS' },
      },
    }));
    const replacements: EdgeChange<DfdEdge>[] = current.map((edge) => ({
      id: edge.id,
      type: 'replace',
      item: {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        label: 'updated label',
        data: { properties: { Port: '443' } },
      },
    }));

    const result = applyCanvasEdgeChanges(replacements, current);

    expect(result).toHaveLength(3);
    for (let index = 0; index < result.length; index += 1) {
      expect(result[index].sourceHandle).toBe('r');
      expect(result[index].targetHandle).toBe('l');
      expect(result[index].data?.route).toEqual(route);
      expect(result[index].data?.autoLabelOffset).toBe(true);
      expect(result[index].data?.labelOffset).toEqual({ x: 0, y: index * 18 });
      expect(result[index].data?.properties).toEqual({ Port: '443' });
    }
  });

  it('does not carry old handles onto an edge whose endpoint changed', () => {
    const current: DfdEdge[] = [{
      id: 'e1',
      source: 'a',
      target: 'b',
      sourceHandle: 'r',
      targetHandle: 'l',
      data: { labelOffset: { x: 0, y: 18 }, route },
    }];
    const reconnect: EdgeChange<DfdEdge>[] = [{
      id: 'e1',
      type: 'replace',
      item: { id: 'e1', source: 'a', target: 'c', data: {} },
    }];

    const [result] = applyCanvasEdgeChanges(reconnect, current);

    expect(result.sourceHandle).toBeUndefined();
    expect(result.targetHandle).toBeUndefined();
    expect(result.data?.route).toBeUndefined();
    expect(result.data?.labelOffset).toBeUndefined();
  });
});

describe('Editor — initialTheme', () => {
  it('honors a saved theme choice', () => {
    window.localStorage.setItem(THEME_KEY, 'dark');
    expect(initialTheme()).toBe('dark');
    window.localStorage.setItem(THEME_KEY, 'light');
    expect(initialTheme()).toBe('light');
  });

  it('defaults to light when no theme is saved and no OS preference is available', () => {
    window.localStorage.removeItem(THEME_KEY);
    expect(initialTheme()).toBe('light');
  });
});

describe('Editor — deleting a selection', () => {
  const a: DfdNode = { id: 'a', type: 'process', position: { x: 0, y: 0 }, data: { label: 'A' } };
  const b: DfdNode = { id: 'b', type: 'process', position: { x: 0, y: 0 }, data: { label: 'B' } };
  const c: DfdNode = { id: 'c', type: 'datastore', position: { x: 0, y: 0 }, data: { label: 'C' } };
  const ab: DfdEdge = { id: 'ab', source: 'a', target: 'b' };
  const bc: DfdEdge = { id: 'bc', source: 'b', target: 'c' };

  it('deletes every selected element, not just the first', () => {
    const result = deleteFromGraph([a, b, c], [], ['a', 'b'], []);
    expect(result.nodes.map((n) => n.id)).toEqual(['c']);
  });

  it('takes the flows connected to a deleted element with it, at either end', () => {
    const result = deleteFromGraph([a, b, c], [ab, bc], ['b'], []);
    // 'b' is the target of ab and the source of bc; both go.
    expect(result.nodes.map((n) => n.id)).toEqual(['a', 'c']);
    expect(result.edges).toEqual([]);
  });

  it('deletes a selected flow without touching its endpoints', () => {
    const result = deleteFromGraph([a, b, c], [ab, bc], [], ['ab']);
    expect(result.nodes.map((n) => n.id)).toEqual(['a', 'b', 'c']);
    expect(result.edges.map((e) => e.id)).toEqual(['bc']);
  });

  it('handles a selection holding both elements and flows', () => {
    const result = deleteFromGraph([a, b, c], [ab, bc], ['a'], ['bc']);
    expect(result.nodes.map((n) => n.id)).toEqual(['b', 'c']);
    // 'ab' went with 'a' even though only 'bc' was selected.
    expect(result.edges).toEqual([]);
  });

  it('leaves the graph alone when nothing is selected', () => {
    const result = deleteFromGraph([a, b], [ab], [], []);
    expect(result.nodes).toEqual([a, b]);
    expect(result.edges).toEqual([ab]);
  });
});

describe('Editor — sameIds', () => {
  it('recognizes an unchanged selection so the Inspector is not remounted mid-edit', () => {
    expect(sameIds([], [])).toBe(true);
    expect(sameIds(['a', 'b'], ['a', 'b'])).toBe(true);
  });

  it('sees a changed selection', () => {
    expect(sameIds(['a'], ['a', 'b'])).toBe(false);
    expect(sameIds(['a', 'b'], ['b', 'a'])).toBe(false);
    expect(sameIds(['a'], ['b'])).toBe(false);
  });
});
