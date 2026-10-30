import { describe, it, expect, vi, afterEach } from 'vitest';
import { createHttpEngine, looksLikeManifest, offlineEngine, toModel, WasmEngineClient } from './engineClient';
import type { components } from './engine/schema';
import type { TmForgeModel } from './types';

function emptyModel(): TmForgeModel {
  return { schema: 'tmforge-json', version: '0.1', elements: [], flows: [] };
}

describe('OfflineEngineClient — the honest fallback contract', () => {
  it('is labeled as the offline engine', () => {
    expect(offlineEngine.label).toBe('offline (engine unavailable)');
  });

  it('offers only the client-side tmforge-json format', async () => {
    const formats = await offlineEngine.getFormats();

    expect(formats).toHaveLength(1);
    expect(formats[0].id).toBe('tmforge-json');
    expect(formats[0].canRead).toBe(true);
    expect(formats[0].canWrite).toBe(true);
  });

  it('offers the generic fallback stencils and packs', async () => {
    const stencils = await offlineEngine.getStencils();
    const packs = await offlineEngine.getStencilPacks();

    expect(stencils.length).toBeGreaterThan(0);
    expect(stencils.every((s) => typeof s.id === 'string' && s.id.length > 0)).toBe(true);
    expect(packs.length).toBeGreaterThan(0);
  });

  it('has no rule catalog or property schema without the engine', async () => {
    expect(await offlineEngine.getRules()).toEqual([]);
    expect(await offlineEngine.getRulePacks()).toEqual([]);
    expect(await offlineEngine.getPropertySchema()).toEqual([]);
  });

  it('rejects analysis and threat generation with an honest error rather than faking results', async () => {
    await expect(offlineEngine.analyze(emptyModel())).rejects.toThrow(/analysis engine has not loaded/i);
    await expect(offlineEngine.generateThreats(emptyModel())).rejects.toThrow(/analysis engine has not loaded/i);
  });

  it('rejects engine-only operations (report, merge, .tm7 export) with a clear hint', async () => {
    await expect(offlineEngine.report(emptyModel(), 'html')).rejects.toThrow(/require[s]? the .NET engine/i);
    await expect(offlineEngine.merge(null, emptyModel(), emptyModel())).rejects.toThrow(/require[s]? the .NET engine/i);
    await expect(offlineEngine.exportTm7(emptyModel())).rejects.toThrow(/require[s]? the .NET engine/i);
    await expect(offlineEngine.saveTm7(new Uint8Array(), emptyModel())).rejects.toThrow(/requires the .NET engine/i);
  });

  it('rejects opening an authoring manifest rather than re-implementing the builder', async () => {
    // Building a manifest resolves aliases, derives stable ids, places elements inside their
    // boundaries, and validates properties against the schema. A client-side approximation would be a
    // second engine that disagrees with the real one.
    await expect(offlineEngine.applyManifest('{"schema":"tmforge-manifest"}')).rejects.toThrow(
      /require[s]? the .NET engine/i,
    );
  });

  it('refuses unvalidated offline arrangement while directing the user to labels-only cleanup', async () => {
    await expect(offlineEngine.layout(emptyModel(), [])).rejects.toThrow(/requires the .NET engine.*Labels only/i);
  });

  it('converts to tmforge-json client-side but rejects engine-only target formats', async () => {
    const blob = await offlineEngine.convert(emptyModel(), 'tmforge-json');
    expect(blob).toBeInstanceOf(Blob);
    expect(blob.type).toBe('application/json');

    await expect(offlineEngine.convert(emptyModel(), 'drawio')).rejects.toThrow(/require[s]? the .NET engine/i);
  });

  it('detects tmforge-json bytes and returns null for anything else', async () => {
    const json = new TextEncoder().encode('{"schema":"tmforge-json","elements":[]}');
    const detected = await offlineEngine.detect(json);
    expect(detected?.id).toBe('tmforge-json');

    const other = await offlineEngine.detect(new TextEncoder().encode('not a model'));
    expect(other).toBeNull();
  });

  it('round-trips a model through write and read (and readFile from bytes)', async () => {
    const json = await offlineEngine.write(emptyModel());
    expect(typeof json).toBe('string');

    const parsed = await offlineEngine.read(json);
    expect(parsed.schema).toBe('tmforge-json');
    expect(parsed.elements).toEqual([]);

    const fromBytes = await offlineEngine.readFile(new TextEncoder().encode(json));
    expect(fromBytes.schema).toBe('tmforge-json');
  });
});

describe('looksLikeManifest — routing an unidentified document', () => {
  it('recognizes a document that declares the manifest schema', () => {
    expect(looksLikeManifest('{"schema":"tmforge-manifest","version":1,"elements":[]}')).toBe(true);
  });

  it('does not claim other tmforge documents', () => {
    expect(looksLikeManifest('{"schema":"tmforge-json","version":"0.1","elements":[]}')).toBe(false);
    expect(looksLikeManifest('{"schema":"tmforge-rules","version":2}')).toBe(false);
    expect(looksLikeManifest('{"schema":"tmforge-analysis","version":1}')).toBe(false);
  });

  it('does not claim a manifest that declares no envelope', () => {
    // The deliberate asymmetry with the engine's reader, which does accept the concise pre-envelope
    // form once told the document is a manifest. Every manifest field is optional, so a recognizer
    // that accepted an absent envelope would claim any JSON object.
    expect(looksLikeManifest('{"name":"concise","elements":[]}')).toBe(false);
  });

  it('does not throw on documents that are not JSON at all', () => {
    expect(looksLikeManifest('<ThreatModel xmlns="..."/>')).toBe(false);
    expect(looksLikeManifest('PK\u0003\u0004binary')).toBe(false);
    expect(looksLikeManifest('')).toBe(false);
    expect(looksLikeManifest('null')).toBe(false);
    expect(looksLikeManifest('42')).toBe(false);
  });
});

describe('engine model normalization', () => {
  it('retains native note fields and timestamp precision across normalization and offline saves', async () => {
    const note = { id: '7', message: 'Scope\nEvidence <review>', date: '2026-09-30T12:00:00.1234567Z', addedBy: 'Reviewer' };
    const model = toModel({ notes: [note] });
    expect(model.notes).toEqual([{ ...note, id: 7 }]);
    expect((await offlineEngine.read(await offlineEngine.write(model))).notes).toEqual(model.notes);
    expect(toModel({ notes: [] }).notes).toEqual([]);
    expect(toModel({}).notes).toBeUndefined();
  });

  it('normalizes absent native note fields without inventing author or date information', () => {
    expect(toModel({ notes: [{ id: 1, message: null, addedBy: null }] }).notes).toEqual([
      { id: 1, message: undefined, addedBy: undefined, date: '0001-01-01T00:00:00' },
    ]);
  });

  it('restores native canvas labels and ports', () => {
    const model = toModel({ flows: [{ id: 'flow', source: 'a', target: 'b', labelOffset: { x: 32, y: -20 }, sourceHandle: 'r', targetHandle: 'l' }] });
    expect(model.flows[0]).toMatchObject({ labelOffset: { x: 32, y: -20 }, sourceHandle: 'r', targetHandle: 'l' });
  });

  it('preserves imported metadata and threat provenance', () => {
    const dto: components['schemas']['TmForgeModelDto'] = {
      metadata: { owner: 'Author', threatModelName: 'Threat Dragon model', reviewer: 'Reviewer' },
      threats: [{ id: 'manual:threat-dragon.original', manual: true, state: 'Accepted', category: 'Linkability', source: { format: 'threat-dragon', id: 'original', modelType: 'LINDDUN' } }],
    };

    const model = toModel(dto);

    expect(model.metadata).toEqual(dto.metadata);
    expect(model.threats?.[0].source).toEqual(dto.threats?.[0].source);
    expect(model.threats?.[0].category).toBe('Linkability');
  });

  it('preserves every imported page and the expected rule fingerprints before layout', () => {
    const dto: components['schemas']['TmForgeModelDto'] = {
      diagrams: [
        { id: 'first', name: 'First', source: { format: 'threat-dragon', id: '7', modelType: 'LINDDUN' }, elements: [{ id: 'a', kind: 'process', x: 170, y: 130 }], flows: [] },
        { id: 'second', name: 'Second', elements: [{ id: 'b', kind: 'boundary', x: 280, y: 190, width: 700, height: 400 }], flows: [] },
      ],
      analysis: { expectedPacks: [{ id: 'policy', fingerprint: 'sha256:unchanged' }] },
    };

    const model = toModel(dto);

    expect(model.diagrams?.map((page) => page.id)).toEqual(['first', 'second']);
    expect(model.diagrams?.[0].source).toEqual(dto.diagrams?.[0].source);
    expect(model.diagrams?.[1].elements[0]).toMatchObject({ id: 'b', x: 280, y: 190, width: 700, height: 400 });
    expect(model.analysis?.expectedPacks).toEqual(dto.analysis?.expectedPacks);
  });

  it('preserves accepted, priority-edited, and manual threat overlays returned by the engine', () => {
    const dto: components['schemas']['TmForgeModelDto'] = {
      threats: [
        {
          id: 'generated:one',
          state: 'Accepted',
          justification: 'Compensating control.',
          priority: 'Low',
        },
        {
          id: 'manual:two',
          state: 'NeedsInvestigation',
          manual: true,
          category: 'Privacy',
          title: 'Manual privacy threat',
          description: 'Description',
          mitigation: 'Mitigation',
          priority: 'High',
          elementIds: ['source', 'target', 'flow'],
        },
      ],
    };

    expect(toModel(dto).threats).toEqual([
      {
        id: 'generated:one',
        state: 'Accepted',
        justification: 'Compensating control.',
        manual: undefined,
        category: undefined,
        title: undefined,
        description: undefined,
        mitigation: undefined,
        priority: 'Low',
        elementIds: undefined,
      },
      {
        id: 'manual:two',
        state: 'NeedsInvestigation',
        justification: undefined,
        manual: true,
        category: 'Privacy',
        title: 'Manual privacy threat',
        description: 'Description',
        mitigation: 'Mitigation',
        priority: 'High',
        elementIds: ['source', 'target', 'flow'],
      },
    ]);
  });
});

describe('asynchronous engine transport', () => {
  it('carries the latest successful save when preserving an older undo source', async () => {
    const invoke = vi.fn(async () => btoa('<preserved/>'));
    const engine = new WasmEngineClient(invoke);
    await engine.saveTm7(new Uint8Array([1]), emptyModel(), new Uint8Array([2]));
    expect(invoke).toHaveBeenCalledExactlyOnceWith('SaveTm7WithPrevious', 'AQ==', JSON.stringify(emptyModel()), 'Ag==');
  });

  it('surfaces the HTTP native-save refusal instead of hiding it behind a status code', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ detail: 'The native threat register references this object.' }), {
      status: 400, headers: { 'Content-Type': 'application/problem+json' },
    }));
    vi.stubGlobal('fetch', fetchMock);
    try {
      await expect(createHttpEngine().saveTm7(new Uint8Array([1]), emptyModel())).rejects.toThrow('The native threat register references this object.');
      const request = fetchMock.mock.calls[0] as unknown as [Request];
      expect(request[0].url).toContain('/v1/model/save/tm7');
      expect(await request[0].json()).toMatchObject({ contentBase64: 'AQ==', model: emptyModel() });
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('sends original bytes and edits through native save without using conversion', async () => {
    const invoke = vi.fn(async () => btoa('<preserved/>'));
    const engine = new WasmEngineClient(invoke);
    const original = new TextEncoder().encode('<original/>');
    const model = emptyModel();

    const saved = await engine.saveTm7(original, model);

    expect(invoke).toHaveBeenCalledExactlyOnceWith('SaveTm7', btoa('<original/>'), JSON.stringify(model));
    expect(saved.type).toBe('application/xml');
    expect(saved.size).toBe('<preserved/>'.length);
  });

  it('shares decoding for message-based preflight, detection, catalogs and exports', async () => {
    const invoke = vi.fn(async (method: string, ..._args: string[]) => {
      if (method === 'Preflight') return JSON.stringify({ success: true, format: 'tmforge-json', diagnostics: [] });
      if (method === 'Detect') return '';
      if (method === 'ExportTm7') return btoa('<model/>');
      return '[]';
    });
    const engine = new WasmEngineClient(invoke, 'engine (VS Code)');
    expect((await engine.preflight(new Uint8Array(), 'tmforge-json')).success).toBe(true);
    expect(invoke).toHaveBeenCalledWith('Preflight', '', 'tmforge-json', '');
    expect(await engine.detect(new Uint8Array())).toBeNull();
    expect(await engine.getStencils()).toEqual([]);
    expect((await engine.exportTm7({ schema: 'tmforge-json', version: '0.1', elements: [], flows: [] })).size).toBe(8);
    expect(engine.label).toBe('engine (VS Code)');
  });
});

describe('comparison transports', () => {
  afterEach(() => vi.unstubAllGlobals());

  const result = { success: true, findingsAvailable: true, unchangedFindings: 3, changes: [], warnings: [], diagnostics: [] };

  it('uses the same request and result over HTTP and WASM', async () => {
    const baseline = emptyModel();
    const proposed = emptyModel();
    const compare = vi.fn(() => JSON.stringify(result));
    vi.stubGlobal('fetch', vi.fn(async (request: Request) => {
      expect(request.url).toBe('http://localhost/v1/model/compare');
      expect(await request.json()).toEqual({ baseline, proposed });
      return new Response(JSON.stringify(result), { headers: { 'Content-Type': 'application/json' } });
    }));
    const wasm = new WasmEngineClient({ Compare: compare } as unknown as ConstructorParameters<typeof WasmEngineClient>[0]);

    expect(await createHttpEngine('http://localhost').compare(baseline, proposed)).toEqual(result);
    expect(await wasm.compare(baseline, proposed)).toEqual(result);
    expect(compare).toHaveBeenCalledWith(JSON.stringify({ baseline, proposed }));
  });

  it('does not treat missing or failed analysis as an empty successful review', async () => {
    await expect(offlineEngine.compare(emptyModel(), emptyModel())).rejects.toThrow(/requires the .NET engine/);
    const wasm = new WasmEngineClient({ Compare: () => '{}' } as unknown as ConstructorParameters<typeof WasmEngineClient>[0]);
    await expect(wasm.compare(emptyModel(), emptyModel())).rejects.toThrow(/complete comparison/);
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 500 })));
    await expect(createHttpEngine('http://localhost').compare(emptyModel(), emptyModel())).rejects.toThrow(/500/);
  });

  it('keeps successful structural review separate from unavailable findings', async () => {
    const partial = { ...result, findingsAvailable: false, unchangedFindings: 0, diagnostics: [
      { code: 'compare.analysis-unavailable', severity: 'error', path: '$.baseline.analysis', message: 'Unavailable rule pack.' },
    ] };
    const wasm = new WasmEngineClient({ Compare: () => JSON.stringify(partial) } as unknown as ConstructorParameters<typeof WasmEngineClient>[0]);
    expect(await wasm.compare(emptyModel(), emptyModel())).toEqual(partial);
  });

  it('rejects partial, contradictory, or duplicate changes instead of dropping them', async () => {
    const change = { id: 'change', section: 'structure', kind: 'added', title: 'Store', elementKind: 'store', baselineElementIds: [], proposedElementIds: ['store'], properties: [] };
    const payloads = [
      { ...result, changes: [change, change] },
      { ...result, changes: [{ ...change, proposedElementIds: [null] }] },
      { ...result, changes: [{ ...change, properties: [{ to: 'value' }] }] },
      { ...result, findingsAvailable: false, unchangedFindings: 0, changes: [{ ...change, section: 'findings', kind: 'resolved' }] },
      { ...result, success: false, changes: [change] },
    ];
    for (const payload of payloads) {
      const wasm = new WasmEngineClient({ Compare: () => JSON.stringify(payload) } as unknown as ConstructorParameters<typeof WasmEngineClient>[0]);
      await expect(wasm.compare(emptyModel(), emptyModel())).rejects.toThrow(/comparison/);
    }
    const wasm = new WasmEngineClient({ Compare: () => JSON.stringify({ ...result, changes: [change] }) } as unknown as ConstructorParameters<typeof WasmEngineClient>[0]);
    expect((await wasm.compare(emptyModel(), emptyModel())).changes[0].elementKind).toBe('datastore');
  });
});

describe('preflight transports', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('returns identical structured diagnostics over HTTP and WASM', async () => {
    const result = {
      success: false, format: 'tmforge-json', targetFormat: 'drawio',
      diagnostics: [{ code: 'model.unresolved-endpoint', severity: 'error', path: '$.flows[0].target', message: 'Missing target.' }],
    };
    const bytes = new TextEncoder().encode('{"schema":"tmforge-json"}');
    const preflight = vi.fn(() => JSON.stringify(result));
    vi.stubGlobal('fetch', vi.fn(async (request: Request) => {
      expect(request.url).toBe('http://localhost/v1/model/preflight?to=drawio');
      expect(await request.json()).toEqual({ contentBase64: btoa(new TextDecoder().decode(bytes)), formatId: 'tmforge-json' });
      return new Response(JSON.stringify(result), { headers: { 'Content-Type': 'application/json' } });
    }));
    const wasm = new WasmEngineClient({ Preflight: preflight } as unknown as ConstructorParameters<typeof WasmEngineClient>[0]);

    expect(await createHttpEngine('http://localhost').preflight(bytes, 'tmforge-json', 'drawio')).toEqual(result);
    expect(await wasm.preflight(bytes, 'tmforge-json', 'drawio')).toEqual(result);
    expect(preflight).toHaveBeenCalledWith(btoa(new TextDecoder().decode(bytes)), 'tmforge-json', 'drawio');
  });

  it('does not pretend offline or incomplete preflight succeeded', async () => {
    await expect(offlineEngine.preflight(new Uint8Array())).rejects.toThrow(/requires the .NET engine/);
    await expect(offlineEngine.recoverTm7(new Uint8Array())).rejects.toThrow(/requires the .NET engine/);
    const wasm = new WasmEngineClient({ Preflight: () => '{}' } as unknown as ConstructorParameters<typeof WasmEngineClient>[0]);
    await expect(wasm.preflight(new Uint8Array())).rejects.toThrow(/complete preflight/);
  });

  it('carries recovery eligibility and requests recovery only through the explicit operation', async () => {
    const result = { success: false, canRecover: true, format: 'tm7', targetFormat: 'tmforge-json', diagnostics: [
      { code: 'model.unresolved-endpoint', severity: 'error', path: '$.diagrams[2].flows', message: 'Missing endpoint.' },
    ] };
    const bytes = new TextEncoder().encode('native source');
    const recover = vi.fn(() => JSON.stringify(emptyModel()));
    const wasm = new WasmEngineClient({ Preflight: () => JSON.stringify(result), RecoverTm7: recover } as unknown as ConstructorParameters<typeof WasmEngineClient>[0]);
    expect(await wasm.preflight(bytes, 'tm7', 'tmforge-json')).toEqual(result);
    expect(recover).not.toHaveBeenCalled();
    vi.stubGlobal('fetch', vi.fn(async (request: Request) => {
      expect(request.url).toBe('http://localhost/v1/model/recover/tm7');
      expect(await request.json()).toEqual({ contentBase64: btoa('native source') });
      return new Response(JSON.stringify(emptyModel()), { headers: { 'Content-Type': 'application/json' } });
    }));
    expect(await wasm.recoverTm7(bytes)).toEqual(await createHttpEngine('http://localhost').recoverTm7(bytes));
    expect(recover).toHaveBeenCalledExactlyOnceWith(btoa('native source'));
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ detail: 'Duplicate identities cannot be recovered.' }), {
      status: 400, headers: { 'Content-Type': 'application/problem+json' },
    })));
    await expect(createHttpEngine('http://localhost').recoverTm7(bytes)).rejects.toThrow('Duplicate identities cannot be recovered.');
  });
});

describe('layout transports', () => {
  afterEach(() => vi.unstubAllGlobals());

  const geometry = [{ id: 'author-id', x: 40, y: 64, width: 140, height: 100 }];

  it('requests only validation of proposed geometry through HTTP and WASM, never automatic placement', async () => {
    let httpBody: unknown;
    vi.stubGlobal('fetch', vi.fn(async (request: Request) => {
      expect(request.url).toBe('http://localhost/v1/model/layout');
      httpBody = await request.json();
      return new Response(JSON.stringify({ success: true, elements: geometry }), { headers: { 'Content-Type': 'application/json' } });
    }));
    let wasmBody: unknown;
    const wasm = new WasmEngineClient({
      Layout: (json: string) => {
        wasmBody = JSON.parse(json);
        return JSON.stringify({ success: true, elements: geometry });
      },
    } as unknown as ConstructorParameters<typeof WasmEngineClient>[0]);
    const model = emptyModel();
    expect(await createHttpEngine('http://localhost').layout(model, geometry)).toEqual(geometry);
    expect(await wasm.layout(model, geometry)).toEqual(geometry);
    expect(httpBody).toEqual({ model, positions: geometry });
    expect(wasmBody).toEqual(httpBody);
  });

  it.each([
    { success: false, error: 'Layout would change trust-boundary crossings.', elements: geometry },
    { success: true, elements: [{ id: 'a', x: 40, y: 40 }] },
    { success: true, elements: [{ id: 'a', x: 40, y: 40, width: -1, height: 50 }] },
    {},
  ])('rejects refused or incomplete layout results on both transports: %j', async (result) => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(result), { headers: { 'Content-Type': 'application/json' } })));
    const wasm = new WasmEngineClient({ Layout: () => JSON.stringify(result) } as unknown as ConstructorParameters<typeof WasmEngineClient>[0]);

    await expect(createHttpEngine('http://localhost').layout(emptyModel(), geometry)).rejects.toThrow();
    await expect(wasm.layout(emptyModel(), geometry)).rejects.toThrow();
  });

  it('refuses an older engine that ignores Tidy positions and rearranges the model', async () => {
    const rearranged = geometry.map((element) => ({ ...element, x: element.x + 100 }));
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ success: true, elements: rearranged }), { headers: { 'Content-Type': 'application/json' } })));
    const wasm = new WasmEngineClient({ Layout: () => JSON.stringify({ success: true, elements: rearranged }) } as unknown as ConstructorParameters<typeof WasmEngineClient>[0]);

    await expect(createHttpEngine('http://localhost').layout(emptyModel(), geometry)).rejects.toThrow(/did not preserve/);
    await expect(wasm.layout(emptyModel(), geometry)).rejects.toThrow(/did not preserve/);
  });

  it('reports an HTTP failure instead of substituting a client arrangement', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { status: 503, headers: { 'Content-Type': 'application/json' } })));

    await expect(createHttpEngine('http://localhost').layout(emptyModel(), geometry)).rejects.toThrow(/503.*Nothing was changed/);
  });
});
