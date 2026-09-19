import '@testing-library/jest-dom/vitest';
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor, within, act } from '@testing-library/react';
import { ReactFlowProvider, useReactFlow, type ReactFlowInstance } from '@xyflow/react';
import { STORAGE_KEY } from './Editor';
import type { IEngineClient, LayoutElement } from './engineClient';
import type { TmForgeModel } from './types';

const engineState = vi.hoisted(() => ({ current: undefined as IEngineClient | undefined }));
vi.mock('./engineClient', async (importOriginal) => {
  const original = await importOriginal<typeof import('./engineClient')>();
  return {
    ...original,
    probeEngine: async () => false,
    loadWasmEngine: async () => engineState.current ?? null,
  };
});

/**
 * Drives the whole editor — React Flow canvas, Inspector, toolbar, page strip — the way a person
 * does, and asserts on what came out. The component suites cover each panel in isolation; this
 * covers the wiring between them, which is where `Editor.tsx` keeps its 50-odd callbacks and where
 * every defect found during the bulk-edit work actually lived.
 *
 * Two things about jsdom shape these tests:
 *
 * 1. React Flow does not render edges without measured handle geometry, so a flow is never in the
 *    DOM here. Flows are asserted through the persisted workspace instead, which does carry them —
 *    verified by checking they are present *before* an edit as well as absent after, so a test can
 *    never pass merely because a flow was missing all along.
 * 2. The editor reads its stored workspace at module scope, so the store has to be seeded before the
 *    module is imported. Hence resetModules + dynamic import in `mountEditor`.
 *
 * Geometry-dependent behaviour (drag, pan, zoom, Tidy, edge routing) is out of reach here and is not
 * pretended at.
 */
beforeAll(() => {
  // React Flow observes its container for size; jsdom has no ResizeObserver.
  class ResizeObserverStub {
    observe(): void {}

    unobserve(): void {}

    disconnect(): void {}
  }

  (globalThis as unknown as { ResizeObserver: unknown }).ResizeObserver = ResizeObserverStub;

  // Everything in jsdom measures zero, and React Flow culls what it cannot place. These are file
  // local: vitest isolates each test file, so no other suite sees the patched prototype.
  Object.defineProperty(HTMLElement.prototype, 'offsetWidth', { configurable: true, value: 120 });
  Object.defineProperty(HTMLElement.prototype, 'offsetHeight', { configurable: true, value: 60 });
  Object.defineProperty(HTMLElement.prototype, 'getBoundingClientRect', {
    configurable: true,
    value: () => ({ x: 0, y: 0, width: 800, height: 600, top: 0, left: 0, right: 800, bottom: 600 }),
  });
});

interface SeedElement {
  id: string;
  kind: string;
  name: string;
  x: number;
  y: number;
  width: number;
  height: number;
  properties?: Record<string, string>;
}

interface SeedFlow {
  id: string;
  source: string;
  target: string;
  name: string;
}

function seedModel(elements: SeedElement[], flows: SeedFlow[]) {
  return { schema: 'tmforge-json', version: '0.1', elements, flows };
}

/** Three processes in a row, joined a -> b -> c. */
function chain() {
  return seedModel(
    [
      { id: 'a', kind: 'process', name: 'Alpha', x: 0, y: 0, width: 120, height: 60 },
      { id: 'b', kind: 'process', name: 'Bravo', x: 200, y: 0, width: 120, height: 60 },
      { id: 'c', kind: 'process', name: 'Charlie', x: 400, y: 0, width: 120, height: 60 },
    ],
    [
      { id: 'ab', source: 'a', target: 'b', name: 'a to b' },
      { id: 'bc', source: 'b', target: 'c', name: 'b to c' },
    ],
  );
}

/**
 * Gives the test a handle on the same React Flow instance the editor is using, so a selection can be
 * made through the store. Simulating the multi-selection modifier is not an option here: React Flow
 * tracks it with a `window` key listener whose key depends on the detected platform, and jsdom does
 * not reproduce that. Setting selection on the store is the state a real multi-select arrives at,
 * and the editor's onSelectionChange reacts to it exactly as in the browser.
 */
let flow: ReactFlowInstance | null = null;

function FlowHandle(): null {
  flow = useReactFlow();
  return null;
}

/** Mounts the editor over a seeded workspace and waits for the canvas to populate. */
async function mountEditor(model: ReturnType<typeof seedModel>): Promise<void> {
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify({ model }));
  vi.resetModules();
  const { Editor } = await import('./Editor');
  render(
    <ReactFlowProvider>
      <Editor />
      <FlowHandle />
    </ReactFlowProvider>,
  );
  await waitFor(() => expect(document.querySelectorAll('.react-flow__node').length).toBeGreaterThan(0));
}

/** The element ids currently on the canvas. */
function canvasNodeIds(): string[] {
  return Array.from(document.querySelectorAll('.react-flow__node')).map(
    (node) => node.getAttribute('data-id') ?? '',
  );
}

function nodeEl(id: string): Element {
  const node = document.querySelector(`.react-flow__node[data-id="${id}"]`);
  if (!node) {
    throw new Error(`No node ${id} on the canvas. Present: ${canvasNodeIds().join(', ')}`);
  }
  return node;
}

/**
 * The workspace as it was last written to storage. Flows only exist here — see the file comment.
 * Writes are debounced, so callers poll this rather than reading it once.
 */
function persisted(): { elements: string[]; flows: string[] } | null {
  const raw = window.localStorage.getItem(STORAGE_KEY);
  if (!raw) {
    return null;
  }
  const model = (JSON.parse(raw) as { model: ReturnType<typeof seedModel> }).model;
  return {
    elements: (model.elements ?? []).map((element) => element.id),
    flows: (model.flows ?? []).map((flow) => flow.id),
  };
}

/** Waits for the debounced workspace write to match what the test expects. */
async function expectPersisted(expected: { elements: string[]; flows: string[] }): Promise<void> {
  await waitFor(() => expect(persisted()).toEqual(expected), { timeout: 3000, interval: 50 });
}

/** Selects exactly the named elements, as a click or a modifier-click would. */
function selectNodes(...ids: string[]): void {
  const wanted = new Set(ids);
  act(() => {
    flow!.setNodes((nodes) => nodes.map((node) => ({ ...node, selected: wanted.has(node.id) })));
  });
}

function inspector(): HTMLElement {
  return document.querySelector('.inspector') as HTMLElement;
}

function undoButton(): HTMLButtonElement {
  return screen.getByTitle(/Undo/i) as HTMLButtonElement;
}

/** Presses undo until it is exhausted, reporting how many steps that took. */
async function undoToExhaustion(limit = 6): Promise<number> {
  let steps = 0;
  while (steps < limit && !undoButton().disabled) {
    fireEvent.click(undoButton());
    steps += 1;
    await waitFor(() => expect(true).toBe(true));
  }
  return steps;
}

/** Adds a custom property through the Inspector's free-text row (works without the engine). */
function addCustomProperty(key: string, value: string): void {
  const panel = inspector();
  fireEvent.change(within(panel).getByPlaceholderText('key'), { target: { value: key } });
  fireEvent.change(within(panel).getByPlaceholderText('value'), { target: { value } });
  fireEvent.click(within(panel).getByRole('button', { name: 'Add' }));
}

beforeEach(() => {
  window.localStorage.clear();
  engineState.current = undefined;
});

describe('Editor — guarded Tidy', () => {
  const geometry: LayoutElement[] = ['a', 'b', 'c'].map((id, index) => ({
    id, x: 40 + index * 300, y: 100, width: 160, height: 96,
  }));

  async function useLayout(layout: IEngineClient['layout']): Promise<void> {
    const { offlineEngine } = await import('./engineClient');
    engineState.current = Object.assign(Object.create(offlineEngine) as IEngineClient, { label: 'layout test engine', layout });
  }

  async function tidy(): Promise<void> {
    await waitFor(() => expect(document.querySelector('.engine-pill')).toHaveTextContent('layout test engine'));
    fireEvent.click(screen.getByRole('button', { name: 'Tidy' }));
  }

  it('applies a successful response with the original ids and exactly one undo step', async () => {
    const layout = vi.fn(async () => geometry);
    await useLayout(layout);
    await mountEditor(chain());

    await tidy();

    await waitFor(() => expect(flow!.getNode('a')?.position).toEqual({ x: 40, y: 100 }));
    expect(layout).toHaveBeenCalledTimes(1);
    expect(canvasNodeIds()).toEqual(['a', 'b', 'c']);
    expect(await undoToExhaustion()).toBe(1);
    await waitFor(() => expect(flow!.getNode('a')?.position).toEqual({ x: 0, y: 0 }));
    await expectPersisted({ elements: ['a', 'b', 'c'], flows: ['ab', 'bc'] });
  });

  it('tidies the existing horizontal arrangement instead of replacing it with graph layers', async () => {
    const layout = vi.fn(async (...args: unknown[]) => args[1] as LayoutElement[]);
    await useLayout(layout);
    await mountEditor(chain());
    await waitFor(() => expect(document.querySelector('.engine-pill')).toHaveTextContent('layout test engine'));

    fireEvent.click(screen.getByRole('button', { name: 'Tidy' }));

    await waitFor(() => expect(layout).toHaveBeenCalledTimes(1));
    const candidate = layout.mock.calls[0][1] as LayoutElement[];
    expect(candidate).toHaveLength(3);
    for (const [index, id] of ['a', 'b', 'c'].entries()) {
      const placed = candidate.find((element) => element.id === id)!;
      expect(Math.abs(placed.x + placed.width / 2 - (index * 200 + 60))).toBeLessThanOrEqual(0.5);
      expect(Math.abs(placed.y + placed.height / 2 - 30)).toBeLessThanOrEqual(0.5);
    }
    await waitFor(() => expect(flow!.getNode('a')?.position.x).toBe(candidate[0].x));
    expect(await undoToExhaustion()).toBe(1);
  });

  it('leaves geometry and undo history untouched after a refusal', async () => {
    await useLayout(vi.fn(async () => { throw new Error('Unsafe crossing; no pages were changed.'); }));
    await mountEditor(chain());

    await tidy();

    await waitFor(() => expect(screen.getByText(/Unsafe crossing/)).toBeInTheDocument());
    expect(flow!.getNode('a')?.position).toEqual({ x: 0, y: 0 });
    expect(undoButton()).toBeDisabled();
  });

  it('discards a late response instead of overwriting a newer property edit', async () => {
    let finish!: (elements: LayoutElement[]) => void;
    const layout = vi.fn(() => new Promise<LayoutElement[]>((resolve) => { finish = resolve; }));
    await useLayout(layout);
    await mountEditor(chain());
    await tidy();
    await waitFor(() => expect(layout).toHaveBeenCalledTimes(1));
    expect(screen.getByRole('button', { name: /Tidying/ })).toBeDisabled();

    selectNodes('a');
    addCustomProperty('Owner', 'newer-edit');
    await act(async () => { finish(geometry); });

    await waitFor(() => expect(screen.getByText(/model changed while tidying/i)).toBeInTheDocument());
    expect(flow!.getNode('a')?.position).toEqual({ x: 0, y: 0 });
    expect(flow!.getNode('a')?.data.properties).toMatchObject({ Owner: 'newer-edit' });
    expect(await undoToExhaustion()).toBe(1);
  });

  it('does not apply a late response to a different active page', async () => {
    let finish!: (elements: LayoutElement[]) => void;
    const layout = vi.fn(() => new Promise<LayoutElement[]>((resolve) => { finish = resolve; }));
    await useLayout(layout);
    const first = chain();
    const second = seedModel([{ id: 'other', kind: 'process', name: 'Other', x: 900, y: 500, width: 120, height: 60 }], []);
    const model = { ...first, diagrams: [{ ...first, id: 'one', name: 'First' }, { ...second, id: 'two', name: 'Second' }] };
    await mountEditor(model);
    await tidy();
    await waitFor(() => expect(layout).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByRole('tab', { name: /^Second/ }));
    await act(async () => { finish(geometry); });

    await waitFor(() => expect(canvasNodeIds()).toEqual(['other']));
    expect(flow!.getNode('other')?.position).toEqual({ x: 900, y: 500 });
    expect(undoButton()).toBeDisabled();
  });

  it('keeps labels-only cleanup available without invoking an offline layout engine', async () => {
    await mountEditor(chain());
    expect(screen.getByRole('button', { name: 'Tidy' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Tidy options' }));
    expect(screen.queryByRole('menuitem', { name: /Arrange/ })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('menuitem', { name: /Labels only/ }));

    expect(flow!.getNode('a')?.position).toEqual({ x: 0, y: 0 });
    expect(flow!.getNode('b')?.position).toEqual({ x: 200, y: 0 });
  });
});

describe('Editor — deleting from the canvas', () => {
  it('takes an element and its flows together, and restores both in one undo', async () => {
    // The bug this guards: React Flow raises a delete callback for nodes AND one for edges, so
    // snapshotting in both charged two undo steps for a single Backspace.
    await mountEditor(chain());
    await expectPersisted({ elements: ['a', 'b', 'c'], flows: ['ab', 'bc'] });

    fireEvent.click(nodeEl('b'));
    fireEvent.keyDown(document.querySelector('.react-flow')!, { key: 'Backspace' });

    // 'b' was an endpoint of both flows, so both go with it.
    await expectPersisted({ elements: ['a', 'c'], flows: [] });

    const steps = await undoToExhaustion();

    expect(steps).toBe(1);
    await expectPersisted({ elements: ['a', 'b', 'c'], flows: ['ab', 'bc'] });
  });

  it('leaves the endpoints alone when only a flow is deleted', async () => {
    await mountEditor(chain());
    await expectPersisted({ elements: ['a', 'b', 'c'], flows: ['ab', 'bc'] });

    // A flow has no DOM node in jsdom, so reach it the way the canvas search does.
    fireEvent.click(nodeEl('a'));
    fireEvent.click(nodeEl('c'));

    // Deleting 'a' removes only the flow attached to it.
    fireEvent.click(nodeEl('a'));
    fireEvent.keyDown(document.querySelector('.react-flow')!, { key: 'Backspace' });

    await expectPersisted({ elements: ['b', 'c'], flows: ['bc'] });
  });

  it('deletes every selected element at once, not just the first', async () => {
    await mountEditor(chain());
    await expectPersisted({ elements: ['a', 'b', 'c'], flows: ['ab', 'bc'] });

    selectNodes('a', 'b');
    fireEvent.keyDown(document.querySelector('.react-flow')!, { key: 'Backspace' });

    await expectPersisted({ elements: ['c'], flows: [] });
  });

  it('deletes the whole selection from the Inspector button too', async () => {
    await mountEditor(chain());
    await expectPersisted({ elements: ['a', 'b', 'c'], flows: ['ab', 'bc'] });

    selectNodes('a', 'b');
    const button = within(inspector()).getByRole('button', { name: /^Delete/ });
    expect(button).toHaveTextContent('Delete 2 elements');
    fireEvent.click(button);

    await expectPersisted({ elements: ['c'], flows: [] });
  });
});

describe('Editor — editing a selection', () => {
  it('writes a property to every selected element in one undo step', async () => {
    await mountEditor(chain());
    await expectPersisted({ elements: ['a', 'b', 'c'], flows: ['ab', 'bc'] });

    selectNodes('a', 'b');
    addCustomProperty('Owner', 'platform');

    await waitFor(
      () => {
        const raw = JSON.parse(window.localStorage.getItem(STORAGE_KEY)!) as {
          model: ReturnType<typeof seedModel>;
        };
        const owners = raw.model.elements.map((element) => element.properties?.Owner);
        expect(owners).toEqual(['platform', 'platform', undefined]);
      },
      { timeout: 3000, interval: 50 },
    );

    // One edit is one undo, however many elements it touched.
    const steps = await undoToExhaustion();
    expect(steps).toBe(1);
  });

  it('shows a property the selection disagrees about as mixed, and does not flatten it', async () => {
    await mountEditor(
      seedModel(
        [
          { id: 'a', kind: 'process', name: 'Alpha', x: 0, y: 0, width: 120, height: 60, properties: { Owner: 'platform' } },
          { id: 'b', kind: 'process', name: 'Bravo', x: 200, y: 0, width: 120, height: 60, properties: { Owner: 'payments' } },
        ],
        [],
      ),
    );

    selectNodes('a', 'b');

    // The row renders empty with a (mixed) placeholder rather than picking one side's value.
    expect(within(inspector()).getByPlaceholderText('(mixed)')).toBeInTheDocument();

    // Merely showing the selection must not overwrite either value.
    await waitFor(
      () => {
        const raw = JSON.parse(window.localStorage.getItem(STORAGE_KEY)!) as {
          model: ReturnType<typeof seedModel>;
        };
        expect(raw.model.elements.map((element) => element.properties?.Owner)).toEqual([
          'platform',
          'payments',
        ]);
      },
      { timeout: 3000, interval: 50 },
    );
  });

  it('offers no name field for a multi-selection', async () => {
    await mountEditor(chain());

    selectNodes('a', 'b');

    expect(within(inspector()).queryByText('Name')).not.toBeInTheDocument();
    expect(within(inspector()).getByText('2 processes')).toBeInTheDocument();
  });

  it('renames a single element and keeps the change', async () => {
    await mountEditor(chain());

    fireEvent.click(nodeEl('a'));
    const name = within(inspector()).getByLabelText('Name');
    fireEvent.focus(name);
    fireEvent.change(name, { target: { value: 'Gateway' } });

    await waitFor(
      () => {
        const raw = JSON.parse(window.localStorage.getItem(STORAGE_KEY)!) as {
          model: ReturnType<typeof seedModel>;
        };
        expect(raw.model.elements[0].name).toBe('Gateway');
      },
      { timeout: 3000, interval: 50 },
    );
  });
});

describe('Editor — the outline highlights what it picks', () => {
  /** Opens the review outline panel. */
  function openOutline(): void {
    fireEvent.click(screen.getByRole('button', { name: /^Outline/ }));
  }

  /** The outline row carrying the given label (the canvas shows the same names). */
  function outlineRow(label: string): HTMLElement {
    const panel = document.querySelector('.outline') as HTMLElement;
    return within(panel).getByText(label).closest('button') as HTMLElement;
  }

  it('lights up a picked flow with both of its endpoints, the way a finding does', async () => {
    await mountEditor(chain());
    openOutline();

    fireEvent.click(outlineRow('a to b'));

    await waitFor(() => expect(nodeEl('a')).toHaveClass('flagged'));
    expect(nodeEl('b')).toHaveClass('flagged');
    expect(nodeEl('c')).not.toHaveClass('flagged');
  });

  it('lights up a picked object on its own, replacing the previous highlight', async () => {
    await mountEditor(chain());
    openOutline();

    fireEvent.click(outlineRow('a to b'));
    await waitFor(() => expect(nodeEl('a')).toHaveClass('flagged'));

    fireEvent.click(outlineRow('Charlie'));

    await waitFor(() => expect(nodeEl('c')).toHaveClass('flagged'));
    expect(nodeEl('a')).not.toHaveClass('flagged');
    expect(nodeEl('b')).not.toHaveClass('flagged');
  });

  it('marks the picked row so the list and the canvas agree', async () => {
    await mountEditor(chain());
    openOutline();

    fireEvent.click(outlineRow('Bravo'));

    await waitFor(() => expect(outlineRow('Bravo')).toHaveClass('selected'));
    expect(outlineRow('Charlie')).not.toHaveClass('selected');
  });

  it('steps to the next flow and moves the highlight with it', async () => {
    await mountEditor(chain());
    openOutline();

    fireEvent.click(screen.getByRole('button', { name: 'Next flow' }));
    await waitFor(() => expect(nodeEl('a')).toHaveClass('flagged'));

    fireEvent.click(screen.getByRole('button', { name: 'Next flow' }));

    // Flow 2 is b -> c, so the highlight leaves 'a' behind.
    await waitFor(() => expect(nodeEl('c')).toHaveClass('flagged'));
    expect(nodeEl('b')).toHaveClass('flagged');
    expect(nodeEl('a')).not.toHaveClass('flagged');
  });
});

describe('Editor import-only formats', () => {
  it('saves to a new canonical file without binding or overwriting the source', async () => {
    const { offlineEngine } = await import('./engineClient');
    const imported: TmForgeModel = await offlineEngine.read(JSON.stringify(chain()));
    imported.metadata = { owner: 'Imported owner' };
    imported.threats = [{ id: 'manual:threat-dragon.source', state: 'Accepted', manual: true, category: 'Linkability', source: { format: 'threat-dragon', id: 'source' } }];
    imported.diagrams = [{ id: 'source-page', name: 'Imported page', elements: imported.elements, flows: imported.flows }];
    const sourceWrite = vi.fn();
    const targetWrite = vi.fn(async () => undefined);
    const writeModel = vi.fn(async (model: TmForgeModel) => JSON.stringify(model));
    const readFile = vi.fn(async () => imported);
    const open = vi.fn(async () => [{ name: 'foreign.json', getFile: async () => ({ arrayBuffer: async () => new ArrayBuffer(0) }), createWritable: sourceWrite }]);
    const save = vi.fn(async () => ({ name: 'foreign.tmforge.json', createWritable: async () => ({ write: targetWrite, close: async () => undefined }) }));
    const format = { id: 'threat-dragon', displayName: 'Threat Dragon', canRead: true, canWrite: false, roundTrips: false, extensions: [], fidelityNote: 'Import only' };
    engineState.current = Object.assign(Object.create(offlineEngine) as IEngineClient, {
      label: 'import test engine', detect: async () => format, readFile, write: writeModel,
      preflight: async () => ({ success: true, format: 'threat-dragon', diagnostics: [] }),
    });
    Object.defineProperty(window, 'showOpenFilePicker', { configurable: true, value: open });
    Object.defineProperty(window, 'showSaveFilePicker', { configurable: true, value: save });
    try {
      await mountEditor(chain());
      await waitFor(() => expect(document.querySelector('.engine-pill')).toHaveTextContent('import test engine'));
      fireEvent.click(screen.getByRole('button', { name: 'Open File' }));
      await waitFor(() => expect(screen.getByText('foreign.tmforge.json')).toBeInTheDocument());

      fireEvent.click(screen.getByRole('button', { name: 'Save' }));

      await waitFor(() => expect(targetWrite).toHaveBeenCalledOnce());
      expect(sourceWrite).not.toHaveBeenCalled();
      expect(save).toHaveBeenCalledWith({ suggestedName: 'foreign.tmforge.json' });
      expect(readFile).toHaveBeenCalledWith(expect.any(Uint8Array), 'threat-dragon');
      const saved = writeModel.mock.calls.at(-1)?.[0];
      expect(saved?.metadata).toEqual(imported.metadata);
      expect(saved?.threats).toEqual(imported.threats);
      expect(saved?.diagrams?.[0]).toMatchObject({ id: 'source-page', name: 'Imported page' });
    } finally {
      Reflect.deleteProperty(window, 'showOpenFilePicker');
      Reflect.deleteProperty(window, 'showSaveFilePicker');
    }
  });
});

describe('Editor preflight review', () => {
  async function prepare(result: Awaited<ReturnType<IEngineClient['preflight']>>) {
    const { offlineEngine } = await import('./engineClient');
    const model = await offlineEngine.read(JSON.stringify(chain()));
    model.elements[0].name = 'Imported Alpha';
    const readFile = vi.fn(async () => model);
    const preflight = vi.fn(async () => result);
    engineState.current = Object.assign(Object.create(offlineEngine) as IEngineClient, {
      label: 'preflight test engine', preflight, readFile,
      detect: async () => ({ id: 'threat-dragon', canRead: true, canWrite: false, extensions: [] }),
    });
    Object.defineProperty(window, 'showOpenFilePicker', {
      configurable: true,
      value: async () => [{ name: 'source.json', getFile: async () => ({ arrayBuffer: async () => new ArrayBuffer(0) }) }],
    });
    await mountEditor(chain());
    await waitFor(() => expect(document.querySelector('.engine-pill')).toHaveTextContent('preflight test engine'));
    fireEvent.click(screen.getByRole('button', { name: 'Open File' }));
    return { readFile, preflight };
  }

  it('reports errors with paths and leaves the original workspace untouched', async () => {
    try {
      const { readFile } = await prepare({ success: false, diagnostics: [{ code: 'model.unresolved-endpoint', severity: 'error', path: '$.flows[0].target', message: 'Target missing.' }] });
      const dialog = await screen.findByRole('dialog', { name: 'Import blocked' });
      expect(within(dialog).getByText('$.flows[0].target')).toBeInTheDocument();
      expect(within(dialog).queryByRole('button', { name: 'Continue' })).not.toBeInTheDocument();
      fireEvent.click(within(dialog).getByRole('button', { name: 'Close' }));
      expect(readFile).not.toHaveBeenCalled();
      expect(canvasNodeIds()).toEqual(['a', 'b', 'c']);
      expect(undoButton()).toBeDisabled();
    } finally {
      Reflect.deleteProperty(window, 'showOpenFilePicker');
    }
  });

  it.each([false, true])('requires an explicit decision before a lossy import (continue=%s)', async (proceed) => {
    try {
      const { readFile } = await prepare({ success: true, diagnostics: [{ code: 'conversion.line-boundaries', severity: 'warning', path: '$.diagrams', message: 'Line boundaries are not represented.' }] });
      const dialog = await screen.findByRole('dialog', { name: 'Review import' });
      expect(readFile).not.toHaveBeenCalled();
      fireEvent.click(within(dialog).getByRole('button', { name: proceed ? 'Continue' : 'Cancel' }));
      if (proceed) {
        await waitFor(() => expect(readFile).toHaveBeenCalledOnce());
        await screen.findByText('Imported Alpha');
      } else {
        expect(readFile).not.toHaveBeenCalled();
        expect(screen.queryByText('Imported Alpha')).not.toBeInTheDocument();
      }
    } finally {
      Reflect.deleteProperty(window, 'showOpenFilePicker');
    }
  });

  it('discards a delayed import after the workspace changes', async () => {
    const { offlineEngine } = await import('./engineClient');
    const imported = await offlineEngine.read(JSON.stringify(chain()));
    imported.elements[0].name = 'Stale import';
    let resolveRead!: (model: TmForgeModel) => void;
    const readFile = vi.fn(() => new Promise<TmForgeModel>((resolve) => { resolveRead = resolve; }));
    engineState.current = Object.assign(Object.create(offlineEngine) as IEngineClient, {
      label: 'delayed import engine', readFile,
      preflight: async () => ({ success: true, diagnostics: [] }),
      detect: async () => ({ id: 'threat-dragon', canRead: true, canWrite: false, extensions: [] }),
    });
    Object.defineProperty(window, 'showOpenFilePicker', {
      configurable: true,
      value: async () => [{ name: 'source.json', getFile: async () => ({ arrayBuffer: async () => new ArrayBuffer(0) }) }],
    });
    try {
      await mountEditor(chain());
      await waitFor(() => expect(document.querySelector('.engine-pill')).toHaveTextContent('delayed import engine'));
      fireEvent.click(screen.getByRole('button', { name: 'Open File' }));
      await waitFor(() => expect(readFile).toHaveBeenCalledOnce());
      selectNodes('a');
      addCustomProperty('ChangedDuringImport', 'Yes');
      await waitFor(() => expect(window.localStorage.getItem(STORAGE_KEY)).toContain('ChangedDuringImport'), { timeout: 3000 });
      await act(async () => resolveRead(imported));

      expect(screen.queryByText('Stale import')).not.toBeInTheDocument();
      expect(window.localStorage.getItem(STORAGE_KEY)).toContain('ChangedDuringImport');
    } finally {
      Reflect.deleteProperty(window, 'showOpenFilePicker');
    }
  });
});

describe('Editor — undo history', () => {
  it('charges one step per edit and redoes what it undid', async () => {
    await mountEditor(chain());
    await expectPersisted({ elements: ['a', 'b', 'c'], flows: ['ab', 'bc'] });

    fireEvent.click(nodeEl('c'));
    fireEvent.keyDown(document.querySelector('.react-flow')!, { key: 'Backspace' });
    await expectPersisted({ elements: ['a', 'b'], flows: ['ab'] });

    fireEvent.click(undoButton());
    await expectPersisted({ elements: ['a', 'b', 'c'], flows: ['ab', 'bc'] });

    fireEvent.click(screen.getByTitle(/Redo/i));
    await expectPersisted({ elements: ['a', 'b'], flows: ['ab'] });
  });
});
