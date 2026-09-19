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
        { id: 'first', name: 'First', elements: [{ id: 'a', kind: 'process', x: 170, y: 130 }], flows: [] },
        { id: 'second', name: 'Second', elements: [{ id: 'b', kind: 'boundary', x: 280, y: 190, width: 700, height: 400 }], flows: [] },
      ],
      analysis: { expectedPacks: [{ id: 'policy', fingerprint: 'sha256:unchanged' }] },
    };

    const model = toModel(dto);

    expect(model.diagrams?.map((page) => page.id)).toEqual(['first', 'second']);
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
    const wasm = new WasmEngineClient({ Preflight: () => '{}' } as unknown as ConstructorParameters<typeof WasmEngineClient>[0]);
    await expect(wasm.preflight(new Uint8Array())).rejects.toThrow(/complete preflight/);
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
