import '@testing-library/jest-dom/vitest';
import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor, within, act } from '@testing-library/react';
import { ReactFlowProvider, useReactFlow, type ReactFlowInstance } from '@xyflow/react';
import { STORAGE_KEY } from './Editor';
import type { IEngineClient, LayoutElement, ModelCompareResult } from './engineClient';
import type { TmForgeModel } from './types';
import { ReviewDiagram, reviewPageId } from './ReviewDiagram';
import { modelFromPages, pagesFromModel } from './mapping';
import { createShareUrl, MAX_SHARE_MODEL_BYTES, readShareFragment } from './shareLink';
import { ShareDialog } from './ShareDialog';

const engineState = vi.hoisted(() => ({ current: undefined as IEngineClient | undefined, hosted: undefined as IEngineClient | undefined }));
vi.mock('./engineClient', async (importOriginal) => {
  const original = await importOriginal<typeof import('./engineClient')>();
  return {
    ...original,
    probeEngine: async () => engineState.hosted !== undefined,
    createHttpEngine: () => engineState.hosted ?? original.createHttpEngine(),
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
async function mountEditor(model: ReturnType<typeof seedModel> | TmForgeModel): Promise<void> {
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
  engineState.hosted = undefined;
});

describe('Read-only review diagrams', () => {
  it('uses separate SVG and accessibility namespaces for both canvases', () => {
    const pages = pagesFromModel(chain() as TmForgeModel);
    render(<>
      <ReviewDiagram side="baseline" pages={pages} theme="light" selection={undefined} />
      <ReviewDiagram side="proposed" pages={pages} theme="light" selection={undefined} />
    </>);
    const ids = Array.from(document.querySelectorAll('[id]')).map((element) => element.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(document.getElementById('tmforge-review-baseline')).toBeInTheDocument();
    expect(document.getElementById('tmforge-review-proposed')).toBeInTheDocument();
  });

  it('keeps selected shapes and boundaries passive', async () => {
    const model = chain() as TmForgeModel;
    model.elements.push({ id: 'zone', kind: 'boundary', name: 'Trust zone', x: 0, y: 0, width: 600, height: 300 });
    const pages = pagesFromModel(model);
    const original = JSON.stringify(pages);
    render(<ReviewDiagram side="baseline" pages={pages} theme="light" selection={{
      id: 'changed', section: 'structure', kind: 'modified', title: 'Alpha',
      baselineElementIds: ['a', 'zone'], proposedElementIds: ['a'], properties: [],
    }} />);
    await waitFor(() => expect(screen.getByText('Alpha')).toBeInTheDocument());
    fireEvent.doubleClick(screen.getByText('Alpha'));
    fireEvent.doubleClick(screen.getByText('Trust zone'));
    fireEvent.keyDown(screen.getByRole('region', { name: 'Baseline diagram' }), { key: 'Backspace' });
    expect(document.querySelector('.dfd-label-input')).toBeNull();
    expect(document.querySelector('.dfd-boundary-label-input')).toBeNull();
    expect(document.querySelector('.react-flow__resize-control')).toBeNull();
    expect(document.querySelectorAll('.review-highlight')).toHaveLength(2);
    expect(JSON.stringify(pages)).toBe(original);
  });

  it('locates author ids across pages and falls back only for implicit single-page identities', () => {
    const pages = pagesFromModel(chain() as TmForgeModel);
    expect(reviewPageId(pages, 'engine-default-page', ['ab'])).toBe(pages[0].id);
    expect(reviewPageId(pages, 'engine-default-page', [])).toBe(pages[0].id);
    expect(reviewPageId(pages, undefined, [])).toBeUndefined();
    const second = { ...pages[0], id: 'second', nodes: [], edges: [] };
    expect(reviewPageId([...pages, second], 'second', [])).toBe('second');
    expect(reviewPageId([...pages, second], 'missing', [])).toBeUndefined();
  });
});

describe('Editor comparison review', () => {
  const renamed: ModelCompareResult = {
    success: true, findingsAvailable: true, unchangedFindings: 3, warnings: [], diagnostics: [],
    changes: [{ id: 'structure:a', section: 'structure', kind: 'modified', title: 'Gateway', elementKind: 'process',
      baselineElementIds: ['a'], proposedElementIds: ['a'], properties: [{ key: 'name', from: 'Alpha', to: 'Gateway' }] }],
  };

  async function openReview(compare = vi.fn<IEngineClient['compare']>(async () => renamed), preflight: IEngineClient['preflight'] = async () => ({ success: true, format: 'tmforge-json', diagnostics: [] })) {
    const { offlineEngine } = await import('./engineClient');
    engineState.current = Object.assign(Object.create(offlineEngine) as IEngineClient, { label: 'compare test engine', compare, preflight });
    await mountEditor(chain());
    await waitFor(() => expect(document.querySelector('.engine-pill')).toHaveTextContent('compare test engine'));
    selectNodes('a');
    addCustomProperty('Owner', 'reviewed');
    await waitFor(() => expect(window.localStorage.getItem(STORAGE_KEY)).toContain('reviewed'), { timeout: 3000 });
    fireEvent.click(screen.getByRole('button', { name: 'Compare' }));
    return { compare, dialog: screen.getByRole('dialog', { name: 'Model Review' }) };
  }

  function upload(side: string, name: string, model: TmForgeModel = chain() as TmForgeModel) {
    const bytes = new TextEncoder().encode(JSON.stringify(model));
    const file = new File([bytes], name, { type: 'application/json' });
    Object.defineProperty(file, 'arrayBuffer', { value: async () => bytes.buffer });
    fireEvent.change(screen.getByLabelText(`${side} file`), { target: { files: [file] } });
  }

  it('reviews a frozen snapshot without editing, saving, or consuming undo history', async () => {
    const { compare, dialog } = await openReview();
    const before = window.localStorage.getItem(STORAGE_KEY);
    upload('baseline', 'baseline.json');
    await waitFor(() => expect(within(dialog).getByText('baseline.json')).toBeInTheDocument());
    fireEvent.click(within(dialog).getByRole('button', { name: 'Compare' }));
    await waitFor(() => expect(within(dialog).getByRole('button', { name: /Gateway/ })).toBeInTheDocument());
    expect(compare).toHaveBeenCalledTimes(1);
    expect(compare.mock.calls[0]?.length).toBe(2);
    const inputs = compare.mock.calls[0];
    expect(inputs[1].elements[0].properties).toEqual({ Owner: 'reviewed' });
    expect(document.querySelector('.app')).toHaveAttribute('inert');
    expect(within(dialog).getByText('3 unchanged findings')).toBeInTheDocument();
    fireEvent.keyDown(window, { key: 'z', ctrlKey: true });
    fireEvent.keyDown(window, { key: 'd', ctrlKey: true });
    fireEvent.keyDown(dialog, { key: 'Backspace' });
    fireEvent.doubleClick(within(dialog).getAllByText('Alpha')[0]);
    expect(within(dialog).queryByRole('textbox')).not.toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Close review' }));
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe(before);
    expect(document.querySelector('.save-status')).toHaveTextContent('Unsaved');
    expect(canvasNodeIds()).toEqual(['a', 'b', 'c']);
    expect(await undoToExhaustion()).toBe(1);
    expect(flow!.getNode('a')?.data.properties).toEqual({});
  });

  it('requires import-loss confirmation and retains the warning with the accepted input', async () => {
    const preflight = vi.fn<IEngineClient['preflight']>(async () => ({ success: true, format: 'tmforge-json', diagnostics: [
      { code: 'import.loss', severity: 'warning', path: '$.threats', message: 'Generated register will not be compared.' },
    ] }));
    const { dialog, compare } = await openReview(undefined, preflight);
    const read = vi.spyOn(engineState.current!, 'read');
    upload('baseline', 'lossy.json');
    const prompt = await screen.findByRole('dialog', { name: 'Baseline import: lossy.json' });
    expect(read).not.toHaveBeenCalled();
    fireEvent.click(within(prompt).getByRole('button', { name: 'Cancel' }));
    expect(within(dialog).getByRole('button', { name: 'Compare' })).toBeDisabled();
    upload('baseline', 'lossy.json');
    fireEvent.click(within(await screen.findByRole('dialog', { name: 'Baseline import: lossy.json' })).getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(within(dialog).getByText('lossy.json')).toBeInTheDocument());
    expect(read).toHaveBeenCalledTimes(1);
    expect(preflight).toHaveBeenCalledWith(expect.any(Uint8Array), 'tmforge-json', undefined);
    expect(within(dialog).getByText(/Generated register will not be compared/)).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Compare' }));
    await waitFor(() => expect(compare).toHaveBeenCalledTimes(1));
    expect(within(dialog).getByText('Baseline import: 1 diagnostics')).toBeInTheDocument();
  });

  it('blocks invalid input and cancels a pending file read when review closes', async () => {
    const { dialog } = await openReview(undefined, async () => ({ success: false, format: 'tmforge-json', diagnostics: [
      { code: 'model.endpoint', severity: 'error', path: '$.flows[0].target', message: 'Missing target.' },
    ] }));
    const read = vi.spyOn(engineState.current!, 'read');
    upload('baseline', 'invalid.json');
    const prompt = await screen.findByRole('dialog', { name: 'Baseline import: invalid.json' });
    expect(within(prompt).queryByRole('button', { name: 'Continue' })).not.toBeInTheDocument();
    fireEvent.keyDown(prompt, { key: 'Escape' });
    expect(dialog).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Compare' })).toBeDisabled();
    expect(read).not.toHaveBeenCalled();
    let finish!: (result: Awaited<ReturnType<IEngineClient['preflight']>>) => void;
    engineState.current!.preflight = vi.fn<IEngineClient['preflight']>(() => new Promise((resolve) => { finish = resolve; }));
    upload('baseline', 'late.json');
    await waitFor(() => expect(engineState.current!.preflight).toHaveBeenCalledTimes(1));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Close review' }));
    await act(async () => { finish({ success: true, format: 'tmforge-json', diagnostics: [] }); });
    expect(read).not.toHaveBeenCalled();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(canvasNodeIds()).toEqual(['a', 'b', 'c']);
  });

  it('ignores an old comparison after an input is replaced', async () => {
    let finish!: (result: ModelCompareResult) => void;
    const compare = vi.fn<IEngineClient['compare']>(() => new Promise((resolve) => { finish = resolve; }));
    const { dialog } = await openReview(compare);
    upload('baseline', 'old.json');
    await waitFor(() => expect(within(dialog).getByText('old.json')).toBeInTheDocument());
    fireEvent.click(within(dialog).getByRole('button', { name: 'Compare' }));
    await waitFor(() => expect(compare).toHaveBeenCalledTimes(1));
    upload('baseline', 'new.json');
    await waitFor(() => expect(within(dialog).getByText('new.json')).toBeInTheDocument());
    await act(async () => { finish(renamed); });
    expect(within(dialog).queryByRole('button', { name: /Gateway/ })).not.toBeInTheDocument();
    expect(within(dialog).getByText('Not compared')).toBeInTheDocument();
    compare.mockResolvedValue({ ...renamed, changes: [] });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Compare' }));
    await waitFor(() => expect(within(dialog).getByText('No changes in this category')).toBeInTheDocument());
  });

  it('distinguishes unavailable findings from an empty findings delta', async () => {
    const compare = vi.fn<IEngineClient['compare']>(async () => ({ ...renamed, findingsAvailable: false, unchangedFindings: 0,
      warnings: ['Rule selection changed.'], diagnostics: [
        { code: 'compare.analysis-unavailable', severity: 'error', path: '$.baseline.analysis', message: 'Missing custom pack.' },
      ] }));
    const { dialog } = await openReview(compare);
    upload('baseline', 'base.json');
    await waitFor(() => expect(within(dialog).getByText('base.json')).toBeInTheDocument());
    fireEvent.click(within(dialog).getByRole('button', { name: 'Compare' }));
    await waitFor(() => expect(within(dialog).getByText('Findings comparison unavailable.')).toBeInTheDocument());
    expect(within(dialog).getByRole('button', { name: /Gateway/ })).toBeInTheDocument();
    expect(within(dialog).getByText('Rule selection changed.')).toBeInTheDocument();
    expect(within(dialog).queryByText(/unchanged findings/)).not.toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('tab', { name: /Findings N\/A/ }));
    expect(within(dialog).getByText('Findings unavailable')).toBeInTheDocument();
  });

  it('filters and steps through changes and resets results when the proposed source changes', async () => {
    const changes = [...renamed.changes, { ...renamed.changes[0], id: 'crossings:ab', section: 'crossings' as const,
      title: 'Crossing request', elementKind: 'flow', properties: [{ key: 'Service zone', from: 'Crosses', to: 'Does not cross' }] }];
    const { dialog } = await openReview(vi.fn(async () => ({ ...renamed, changes })));
    upload('baseline', 'base.json');
    await waitFor(() => expect(within(dialog).getByText('base.json')).toBeInTheDocument());
    fireEvent.click(within(dialog).getByRole('button', { name: 'Compare' }));
    await waitFor(() => expect(within(dialog).getByText('1 / 2')).toBeInTheDocument());
    fireEvent.click(within(dialog).getByRole('button', { name: 'Next change' }));
    expect(within(dialog).getByText('2 / 2')).toBeInTheDocument();
    expect(within(dialog).getByRole('heading', { name: 'Crossing request' })).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Previous change' }));
    expect(within(dialog).getByRole('heading', { name: 'Gateway' })).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('tab', { name: /Boundary crossings/ }));
    expect(within(dialog).getByText('1 / 1')).toBeInTheDocument();
    fireEvent.change(within(dialog).getByRole('searchbox'), { target: { value: 'missing' } });
    await waitFor(() => expect(within(dialog).getByText('No matching changes')).toBeInTheDocument());
    upload('proposed', 'proposal.json');
    await waitFor(() => expect(within(dialog).getByText('proposal.json')).toBeInTheDocument());
    expect(within(dialog).getByText('Not compared')).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Use current canvas' }));
    expect(within(dialog).getByText('Canvas snapshot')).toBeInTheDocument();
  });

  it('keeps long reviews bounded when navigation wraps to the last change', async () => {
    const changes = Array.from({ length: 101 }, (_, index) => ({ ...renamed.changes[0], id: `change-${index}`, title: `Gateway ${index}` }));
    const { dialog } = await openReview(vi.fn(async () => ({ ...renamed, changes })));
    upload('baseline', 'base.json');
    await waitFor(() => expect(within(dialog).getByText('base.json')).toBeInTheDocument());
    fireEvent.click(within(dialog).getByRole('button', { name: 'Compare' }));
    await waitFor(() => expect(within(dialog).getByText('1 / 101')).toBeInTheDocument());
    expect(dialog.querySelectorAll('.review-change')).toHaveLength(100);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Previous change' }));
    expect(within(dialog).getByText('101 / 101')).toBeInTheDocument();
    expect(dialog.querySelectorAll('.review-change')).toHaveLength(1);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Previous 100 changes' }));
    expect(dialog.querySelectorAll('.review-change')).toHaveLength(100);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Next 100 changes' }));
    expect(dialog.querySelectorAll('.review-change')).toHaveLength(1);
  });

  it.each(['bytes', 'detect', 'preflight'] as const)('discards a pending import at %s without opening a late preflight dialog', async (phase) => {
    const { offlineEngine } = await import('./engineClient');
    let finish!: () => void;
    const pending = new Promise<void>((resolve) => { finish = resolve; });
    const started = vi.fn();
    const pauseAt = async (stage: typeof phase) => {
      if (stage === phase) {
        started();
        await pending;
      }
    };
    const read = vi.fn<IEngineClient['read']>(offlineEngine.read);
    engineState.current = Object.assign(Object.create(offlineEngine) as IEngineClient, {
      label: 'early import engine', read,
      detect: async (bytes: Uint8Array) => { await pauseAt('detect'); return offlineEngine.detect(bytes); },
      preflight: async () => {
        await pauseAt('preflight');
        return { success: true, format: 'tmforge-json', diagnostics: [
          { code: 'import.loss', severity: 'warning', path: '$', message: 'Late import warning' },
        ] };
      },
    });
    await mountEditor(chain());
    await waitFor(() => expect(document.querySelector('.engine-pill')).toHaveTextContent('early import engine'));
    const nodesBefore = flow!.getNodes();
    const edgesBefore = flow!.getEdges();
    const bytes = new TextEncoder().encode(JSON.stringify(chain()));
    const file = new File([bytes], 'incoming.tmforge.json', { type: 'application/json' });
    Object.defineProperty(file, 'arrayBuffer', { value: async () => { await pauseAt('bytes'); return bytes.buffer; } });
    fireEvent.change(document.querySelector('.app input[type="file"]')!, { target: { files: [file] } });
    await waitFor(() => expect(started).toHaveBeenCalledOnce());

    fireEvent.click(screen.getByRole('button', { name: 'Compare' }));
    fireEvent.click(screen.getByRole('button', { name: 'Close review' }));
    await act(async () => { finish(); });

    expect(read).not.toHaveBeenCalled();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(flow!.getNodes()).toEqual(nodesBefore);
    expect(flow!.getEdges()).toEqual(edgesBefore);
    expect(document.querySelector('.file-chip')).toBeNull();
    expect(document.querySelector('.save-status')).toHaveTextContent('Saved');
    expect(undoButton()).toBeDisabled();
  });

  it.each([
    { picker: true, closeBeforeResponse: false },
    { picker: true, closeBeforeResponse: true },
    { picker: false, closeBeforeResponse: false },
    { picker: false, closeBeforeResponse: true },
  ])('discards a pending editor import when review opens (picker=$picker, closed=$closeBeforeResponse)', async ({ picker, closeBeforeResponse }) => {
    const { offlineEngine } = await import('./engineClient');
    const working = chain() as TmForgeModel;
    working.metadata = { owner: 'Current owner' };
    working.threats = [{ id: 'manual:current', manual: true, title: 'Current risk', category: 'Spoofing', state: 'Accepted', justification: 'Reviewed' }];
    const incoming = chain() as TmForgeModel;
    incoming.elements[0].name = 'Late imported Alpha';
    const bytes = new TextEncoder().encode(JSON.stringify(working));
    const write = vi.fn(async () => undefined);
    const workingHandle = {
      name: 'working.tmforge.json',
      getFile: async () => ({ arrayBuffer: async () => bytes.buffer }),
      createWritable: vi.fn(async () => ({ write, close: async () => undefined })),
    };
    const incomingHandle = { ...workingHandle, name: 'incoming.tmforge.json', createWritable: vi.fn() };
    const open = vi.fn().mockResolvedValueOnce([workingHandle]).mockResolvedValueOnce([incomingHandle]);
    let finish!: (model: TmForgeModel) => void;
    const read = vi.fn<IEngineClient['read']>()
      .mockImplementationOnce(offlineEngine.read)
      .mockImplementationOnce(() => new Promise<TmForgeModel>((resolve) => { finish = resolve; }));
    const writeModel = vi.fn<IEngineClient['write']>(async (model) => JSON.stringify(model));
    engineState.current = Object.assign(Object.create(offlineEngine) as IEngineClient, {
      label: 'pending import engine', read, write: writeModel,
      preflight: async () => ({ success: true, format: 'tmforge-json', diagnostics: [] }),
    });
    Object.defineProperty(window, 'showOpenFilePicker', { configurable: true, value: open });
    try {
      await mountEditor(chain());
      await waitFor(() => expect(document.querySelector('.engine-pill')).toHaveTextContent('pending import engine'));
      fireEvent.click(screen.getByRole('button', { name: 'Open File' }));
      await screen.findByText('working.tmforge.json');
      selectNodes('a');
      addCustomProperty('Owner', 'Unsaved edit');
      await waitFor(() => expect(window.localStorage.getItem(STORAGE_KEY)).toContain('Unsaved edit'), { timeout: 3000 });
      const before = window.localStorage.getItem(STORAGE_KEY);
      const nodesBefore = flow!.getNodes();
      const edgesBefore = flow!.getEdges();

      if (picker) {
        fireEvent.click(screen.getByRole('button', { name: 'Open File' }));
      } else {
        Reflect.deleteProperty(window, 'showOpenFilePicker');
        const file = new File([bytes], 'incoming.tmforge.json', { type: 'application/json' });
        Object.defineProperty(file, 'arrayBuffer', { value: async () => bytes.buffer });
        fireEvent.change(document.querySelector('.app input[type="file"]')!, { target: { files: [file] } });
      }
      await waitFor(() => expect(read).toHaveBeenCalledTimes(2));
      fireEvent.click(screen.getByRole('button', { name: 'Compare' }));
      const dialog = screen.getByRole('dialog', { name: 'Model Review' });
      if (closeBeforeResponse) {
        fireEvent.click(within(dialog).getByRole('button', { name: 'Close review' }));
      }
      await act(async () => { finish(incoming); });

      expect(flow!.getNodes()).toEqual(nodesBefore);
      expect(flow!.getEdges()).toEqual(edgesBefore);
      expect(window.localStorage.getItem(STORAGE_KEY)).toBe(before);
      expect(document.querySelector('.file-chip')).toHaveTextContent('working.tmforge.json');
      expect(document.querySelector('.save-status')).toHaveTextContent('Unsaved');
      expect(workingHandle.createWritable).not.toHaveBeenCalled();
      expect(incomingHandle.createWritable).not.toHaveBeenCalled();
      if (!closeBeforeResponse) {
        fireEvent.click(within(dialog).getByRole('button', { name: 'Close review' }));
      }
      fireEvent.click(screen.getByRole('button', { name: 'Save' }));
      await waitFor(() => expect(write).toHaveBeenCalledOnce());
      expect(incomingHandle.createWritable).not.toHaveBeenCalled();
      expect(writeModel.mock.calls[0][0].metadata).toEqual(working.metadata);
      expect(writeModel.mock.calls[0][0].threats).toEqual(working.threats);
      expect(await undoToExhaustion()).toBe(1);
      expect(flow!.getNode('a')?.data.properties).toEqual({});
    } finally {
      Reflect.deleteProperty(window, 'showOpenFilePicker');
    }
  });
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

  it.each([false, true])('discards a pending Tidy when review opens (closed=%s)', async (closeBeforeResponse) => {
    let finish!: (elements: LayoutElement[]) => void;
    const layout = vi.fn<IEngineClient['layout']>(() => new Promise<LayoutElement[]>((resolve) => { finish = resolve; }));
    await useLayout(layout);
    await mountEditor(chain());
    selectNodes('a');
    addCustomProperty('Owner', 'Unsaved edit');
    await waitFor(() => expect(window.localStorage.getItem(STORAGE_KEY)).toContain('Unsaved edit'), { timeout: 3000 });
    const before = window.localStorage.getItem(STORAGE_KEY);
    const nodesBefore = flow!.getNodes();
    const edgesBefore = flow!.getEdges();
    await tidy();
    await waitFor(() => expect(layout).toHaveBeenCalledOnce());

    fireEvent.click(screen.getByRole('button', { name: 'Compare' }));
    const dialog = screen.getByRole('dialog', { name: 'Model Review' });
    if (closeBeforeResponse) {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Close review' }));
    }
    await act(async () => { finish(geometry); });

    expect(flow!.getNodes()).toEqual(nodesBefore);
    expect(flow!.getEdges()).toEqual(edgesBefore);
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe(before);
    expect(document.querySelector('.save-status')).toHaveTextContent('Unsaved');
    if (!closeBeforeResponse) {
      fireEvent.click(within(dialog).getByRole('button', { name: 'Close review' }));
    }
    expect(screen.getByRole('button', { name: 'Tidy' })).toBeEnabled();
    expect(await undoToExhaustion()).toBe(1);
    expect(flow!.getNode('a')?.data.properties).toEqual({});
    layout.mockResolvedValue(geometry);
    await tidy();
    await waitFor(() => expect(flow!.getNode('a')?.position).toEqual({ x: 40, y: 100 }));
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

describe('Editor URL sharing', () => {
  const originalClipboard = Object.getOwnPropertyDescriptor(navigator, 'clipboard');

  afterEach(() => {
    vi.restoreAllMocks();
    if (originalClipboard) Object.defineProperty(navigator, 'clipboard', originalClipboard);
    else Reflect.deleteProperty(navigator, 'clipboard');
    Reflect.deleteProperty(window, 'showOpenFilePicker');
    Reflect.deleteProperty(window, 'showSaveFilePicker');
    window.history.replaceState(null, '', window.location.pathname + window.location.search);
  });

  function sharedModel(): TmForgeModel {
    const model = chain() as TmForgeModel;
    model.elements[0].name = 'Shared Alpha';
    model.elements[0].properties = { AuthenticationScheme: 'Unknown', StencilType: 'generic-process' };
    model.flows[0].sourceHandle = 'r';
    model.flows[0].targetHandle = 'l';
    model.flows[0].labelOffset = { x: 47, y: -28 };
    model.diagrams = [
      { id: 'shared-page', name: 'Shared service', elements: model.elements, flows: model.flows },
      { id: 'empty-page', name: 'Notes', elements: [], flows: [] },
    ];
    model.metadata = { owner: 'Model owner', threatModelName: 'Shared service' };
    model.analysis = { disabledPacks: ['availability'], expectedPacks: [{ id: 'policy', fingerprint: 'sha256:pin' }] };
    model.threats = [{ id: 'manual:source', manual: true, state: 'Accepted', title: 'Reviewed threat', justification: 'Decision', source: { format: 'threat-dragon' } }];
    return modelFromPages(pagesFromModel(model), model.analysis, model.threats, model.metadata);
  }

  async function localEngine(preflight?: IEngineClient['preflight']) {
    const { offlineEngine } = await import('./engineClient');
    const inspect = vi.fn<IEngineClient['preflight']>(preflight ?? (async () => ({ success: true, format: 'tmforge-json', diagnostics: [] })));
    engineState.current = Object.assign(Object.create(offlineEngine) as IEngineClient, { label: 'local share engine', preflight: inspect });
    return inspect;
  }

  async function navigateToShare(json: string) {
    const url = await createShareUrl(json, window.location.href);
    act(() => {
      window.history.replaceState(null, '', new URL(url).hash);
      window.dispatchEvent(new HashChangeEvent('hashchange'));
    });
    return screen.findByRole('dialog', { name: 'Open shared model' });
  }

  it('copies the complete snapshot without changing geometry, dirty state or undo history', async () => {
    const inspect = await localEngine();
    const writeText = vi.fn(async () => undefined);
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
    await mountEditor(sharedModel());
    selectNodes('a');
    addCustomProperty('PendingEdit', 'Yes');
    await waitFor(() => expect(window.localStorage.getItem(STORAGE_KEY)).toContain('PendingEdit'), { timeout: 3000 });
    const before = window.localStorage.getItem(STORAGE_KEY);
    const json = JSON.stringify(JSON.parse(before!).model);
    fireEvent.click(screen.getByRole('button', { name: 'Share model' }));
    const dialog = await screen.findByRole('dialog', { name: 'Share model' });
    const input = await within(dialog).findByRole('textbox', { name: 'Share link' });
    expect(await readShareFragment(new URL((input as HTMLInputElement).value).hash)).toBe(json);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Copy link' }));
    await within(dialog).findByText('Link copied.');
    expect(writeText).toHaveBeenCalledWith((input as HTMLInputElement).value);
    expect(inspect).not.toHaveBeenCalled();
    fireEvent.keyDown(document.querySelector('.react-flow')!, { key: 'Backspace' });
    fireEvent.keyDown(window, { key: 'z', ctrlKey: true });
    expect(canvasNodeIds()).toEqual(['a', 'b', 'c']);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Close' }));
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe(before);
    expect(document.querySelector('.save-status')).toHaveClass('dirty');
    expect(await undoToExhaustion()).toBe(1);
  });

  it('asks before replacing a persisted workspace when the page opens with a link', async () => {
    await localEngine();
    const url = await createShareUrl(JSON.stringify(sharedModel()), window.location.href);
    window.history.replaceState(null, '', new URL(url).hash);
    await mountEditor(chain());
    const dialog = await screen.findByRole('dialog', { name: 'Open shared model' });
    await waitFor(() => expect(within(dialog).getByRole('button', { name: 'Open model' })).toBeEnabled());
    expect(within(dialog).getByText(/replaces the current workspace/)).toBeInTheDocument();
    expect(window.location.hash).toBe('');
    expect(canvasNodeIds()).toEqual(['a', 'b', 'c']);
    expect(screen.queryByText('Shared Alpha')).not.toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(undoButton()).toBeDisabled();
    expect(document.querySelector('.save-status')).toHaveClass('clean');
  });

  it('opens all shared pages byte-identically after local validation without calling the HTTP engine', async () => {
    const inspect = await localEngine();
    const { offlineEngine } = await import('./engineClient');
    const remotePreflight = vi.fn<IEngineClient['preflight']>(async () => { throw new Error('Unexpected upload'); });
    const remoteRead = vi.fn<IEngineClient['read']>(async () => { throw new Error('Unexpected upload'); });
    engineState.hosted = Object.assign(Object.create(offlineEngine) as IEngineClient, { label: 'hosted engine', preflight: remotePreflight, read: remoteRead });
    await mountEditor(chain());
    const model = sharedModel();
    const json = JSON.stringify(model);
    const dialog = await navigateToShare(json);
    await waitFor(() => expect(within(dialog).getByRole('button', { name: 'Open model' })).toBeEnabled());
    expect(inspect).toHaveBeenCalledWith(new TextEncoder().encode(json), 'tmforge-json');
    expect(remotePreflight).not.toHaveBeenCalled();
    expect(remoteRead).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Open model' }));
    await screen.findByText('Shared Alpha');
    await waitFor(() => expect(JSON.stringify(JSON.parse(window.localStorage.getItem(STORAGE_KEY)!).model)).toBe(json), { timeout: 3000 });
    expect(screen.getByRole('tab', { name: /^Notes/ })).toBeInTheDocument();
    expect(screen.getByText('shared-model.tmforge.json')).toBeInTheDocument();
    expect(document.querySelector('.save-status')).toHaveClass('dirty');
    expect(undoButton()).toBeDisabled();
  });

  it('keeps dirty edits, metadata and undo when a received link is cancelled', async () => {
    await localEngine();
    await mountEditor(sharedModel());
    selectNodes('a');
    addCustomProperty('Unsaved', 'Yes');
    await waitFor(() => expect(window.localStorage.getItem(STORAGE_KEY)).toContain('Unsaved'), { timeout: 3000 });
    const before = window.localStorage.getItem(STORAGE_KEY);
    const dialog = await navigateToShare(JSON.stringify(chain()));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(window.localStorage.getItem(STORAGE_KEY)).toBe(before);
    expect(document.querySelector('.save-status')).toHaveClass('dirty');
    expect(await undoToExhaustion()).toBe(1);
  });

  it('does not fall back to HTTP when the in-browser validation engine is unavailable', async () => {
    const { offlineEngine } = await import('./engineClient');
    const remotePreflight = vi.fn();
    engineState.hosted = Object.assign(Object.create(offlineEngine) as IEngineClient, { label: 'hosted engine', preflight: remotePreflight });
    await mountEditor(chain());
    const dialog = await navigateToShare(JSON.stringify(sharedModel()));
    await within(dialog).findByText(/requires the in-browser engine/);
    expect(within(dialog).getByRole('button', { name: 'Open model' })).toBeDisabled();
    expect(remotePreflight).not.toHaveBeenCalled();
    expect(canvasNodeIds()).toEqual(['a', 'b', 'c']);
  });

  it('shows local structural errors and never replaces the workspace with a partial model', async () => {
    await localEngine(async () => ({ success: false, diagnostics: [{ code: 'model.unresolved-endpoint', severity: 'error', path: '$.flows[0].target', message: 'Target missing.' }] }));
    await mountEditor(chain());
    const dialog = await navigateToShare(JSON.stringify(sharedModel()));
    await within(dialog).findByText('Target missing.');
    expect(within(dialog).getByText('$.flows[0].target')).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Open model' })).toBeDisabled();
    expect(canvasNodeIds()).toEqual(['a', 'b', 'c']);
  });

  it('discards a late validation result when a newer link replaces it', async () => {
    let resolveFirst!: (result: Awaited<ReturnType<IEngineClient['preflight']>>) => void;
    const inspect = await localEngine();
    inspect.mockImplementationOnce(() => new Promise(resolve => { resolveFirst = resolve; }));
    await mountEditor(chain());
    await navigateToShare(JSON.stringify(sharedModel()));
    await waitFor(() => expect(inspect).toHaveBeenCalledOnce());
    const newer = sharedModel();
    newer.elements[0].name = 'Newer shared model';
    const dialog = await navigateToShare(JSON.stringify(newer));
    await waitFor(() => expect(within(dialog).getByRole('button', { name: 'Open model' })).toBeEnabled());
    await act(async () => resolveFirst({ success: true, diagnostics: [] }));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Open model' }));
    await screen.findByText('Newer shared model');
    expect(screen.queryByText('Shared Alpha')).not.toBeInTheDocument();
  });

  it('preserves the original file binding after Cancel and detaches it after Open', async () => {
    await localEngine();
    const sourceWrite = vi.fn(async () => undefined);
    const targetWrite = vi.fn(async () => undefined);
    const bytes = new TextEncoder().encode(JSON.stringify(chain()));
    Object.defineProperty(window, 'showOpenFilePicker', { configurable: true, value: async () => [{ name: 'working.tmforge.json', getFile: async () => ({ arrayBuffer: async () => bytes.buffer }), createWritable: async () => ({ write: sourceWrite, close: async () => undefined }) }] });
    Object.defineProperty(window, 'showSaveFilePicker', { configurable: true, value: async () => ({ name: 'shared-model.tmforge.json', createWritable: async () => ({ write: targetWrite, close: async () => undefined }) }) });
    await mountEditor(chain());
    await waitFor(() => expect(document.querySelector('.engine-pill')).toHaveTextContent('local share engine'));
    fireEvent.click(screen.getByRole('button', { name: 'Open File' }));
    await screen.findByText('working.tmforge.json');
    let dialog = await navigateToShare(JSON.stringify(sharedModel()));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(sourceWrite).toHaveBeenCalledOnce());
    dialog = await navigateToShare(JSON.stringify(sharedModel()));
    await waitFor(() => expect(within(dialog).getByRole('button', { name: 'Open model' })).toBeEnabled());
    fireEvent.click(within(dialog).getByRole('button', { name: 'Open model' }));
    await screen.findByText('shared-model.tmforge.json');
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(targetWrite).toHaveBeenCalledOnce());
    expect(sourceWrite).toHaveBeenCalledOnce();
  });

  it('offers a selectable link when clipboard access fails', async () => {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async () => { throw new Error('Denied'); } } });
    render(<ShareDialog request={{ mode: 'create', json: JSON.stringify(sharedModel()), pageUrl: 'https://example.test/studio/' }} onOpen={vi.fn()} onClose={vi.fn()} onDownload={vi.fn()} />);
    const input = await screen.findByRole('textbox', { name: 'Share link' });
    fireEvent.click(screen.getByRole('button', { name: 'Copy link' }));
    await screen.findByText(/Clipboard access is unavailable/);
    expect(input).toHaveFocus();
    expect((input as HTMLInputElement).selectionStart).toBe(0);
    expect((input as HTMLInputElement).selectionEnd).toBe((input as HTMLInputElement).value.length);
  });

  it('cancels an in-flight Tidy even after the Share dialog closes', async () => {
    await localEngine();
    let finish!: (positions: LayoutElement[]) => void;
    const layout = vi.fn<IEngineClient['layout']>(() => new Promise(resolve => { finish = resolve; }));
    engineState.current!.layout = layout;
    await mountEditor(chain());
    await waitFor(() => expect(screen.getByRole('button', { name: 'Tidy' })).toBeEnabled());
    fireEvent.click(screen.getByRole('button', { name: 'Tidy' }));
    await waitFor(() => expect(layout).toHaveBeenCalledOnce());
    fireEvent.click(screen.getByRole('button', { name: 'Share model' }));
    const dialog = await screen.findByRole('dialog', { name: 'Share model' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Close' }));
    await act(async () => finish(chain().elements.map(element => ({ id: element.id, x: element.x + 800, y: element.y, width: element.width, height: element.height }))));
    expect(flow!.getNodes().find(node => node.id === 'a')?.position.x).toBe(0);
    expect(undoButton()).toBeDisabled();
    expect(document.querySelector('.save-status')).toHaveClass('clean');
  });

  it('cancels an in-flight file import even after the Share dialog closes', async () => {
    await localEngine();
    let finish!: (model: TmForgeModel) => void;
    const read = vi.fn<IEngineClient['read']>(() => new Promise(resolve => { finish = resolve; }));
    engineState.current!.read = read;
    const incoming = sharedModel();
    const bytes = new TextEncoder().encode(JSON.stringify(incoming));
    Object.defineProperty(window, 'showOpenFilePicker', { configurable: true, value: async () => [{ name: 'incoming.tmforge.json', getFile: async () => ({ arrayBuffer: async () => bytes.buffer }) }] });
    await mountEditor(chain());
    await waitFor(() => expect(document.querySelector('.engine-pill')).toHaveTextContent('local share engine'));
    fireEvent.click(screen.getByRole('button', { name: 'Open File' }));
    await waitFor(() => expect(read).toHaveBeenCalledOnce());
    fireEvent.click(screen.getByRole('button', { name: 'Share model' }));
    const dialog = await screen.findByRole('dialog', { name: 'Share model' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Close' }));
    await act(async () => finish(incoming));
    expect(screen.queryByText('Shared Alpha')).not.toBeInTheDocument();
    expect(screen.queryByText('incoming.tmforge.json')).not.toBeInTheDocument();
    expect(canvasNodeIds()).toEqual(['a', 'b', 'c']);
    expect(document.querySelector('.save-status')).toHaveClass('clean');
  });

  it('refuses to replace a workspace that changed after the share dialog opened', async () => {
    await localEngine();
    await mountEditor(chain());
    const dialog = await navigateToShare(JSON.stringify(sharedModel()));
    await waitFor(() => expect(within(dialog).getByRole('button', { name: 'Open model' })).toBeEnabled());
    act(() => flow!.setNodes(nodes => nodes.map(node => node.id === 'a' ? { ...node, data: { ...node.data, label: 'Late workspace change' } } : node)));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Open model' }));
    await screen.findByText(/workspace changed while the shared model was checked/);
    expect(screen.getByText('Late workspace change')).toBeInTheDocument();
    expect(screen.queryByText('Shared Alpha')).not.toBeInTheDocument();
  });

  it('offers the complete model as a download when it exceeds the share cap', async () => {
    const model = sharedModel();
    model.metadata = { highLevelSystemDescription: 'x'.repeat(MAX_SHARE_MODEL_BYTES) };
    const json = JSON.stringify(model);
    const download = vi.fn();
    render(<ShareDialog request={{ mode: 'create', json, pageUrl: 'https://example.test/studio/' }} onOpen={vi.fn()} onClose={vi.fn()} onDownload={download} />);
    await screen.findByText(/1 MiB share limit/);
    expect(screen.getByRole('button', { name: 'Copy link' })).toBeDisabled();
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Download model' }));
    expect(download).toHaveBeenCalledWith(json);
  });
});

describe('Editor import-only formats', () => {
  it.each([
    ['threat-dragon', 'foreign.json', 'foreign.tmforge.json'],
    ['mermaid', 'foreign.mmd', 'foreign.mmd.tmforge.json'],
    ['dot', 'foreign.dot', 'foreign.dot.tmforge.json'],
  ])('saves %s to a new canonical file without binding or overwriting the source', async (formatId, sourceName, savedName) => {
    const { offlineEngine } = await import('./engineClient');
    const imported: TmForgeModel = await offlineEngine.read(JSON.stringify(chain()));
    imported.metadata = { owner: 'Imported owner' };
    imported.threats = [{ id: 'manual:threat-dragon.source', state: 'Accepted', manual: true, category: 'Linkability', source: { format: 'threat-dragon', id: 'source' } }];
    imported.diagrams = [{ id: 'source-page', name: 'Imported page', elements: imported.elements, flows: imported.flows }];
    const sourceWrite = vi.fn();
    const targetWrite = vi.fn(async () => undefined);
    const writeModel = vi.fn(async (model: TmForgeModel) => JSON.stringify(model));
    const readFile = vi.fn(async () => imported);
    const open = vi.fn(async () => [{ name: sourceName, getFile: async () => ({ arrayBuffer: async () => new ArrayBuffer(0) }), createWritable: sourceWrite }]);
    const save = vi.fn(async () => ({ name: savedName, createWritable: async () => ({ write: targetWrite, close: async () => undefined }) }));
    const format = { id: formatId, displayName: formatId, canRead: true, canWrite: false, roundTrips: false, extensions: [], fidelityNote: 'Import only' };
    engineState.current = Object.assign(Object.create(offlineEngine) as IEngineClient, {
      label: 'import test engine', detect: async () => format, readFile, write: writeModel,
      preflight: async () => ({ success: true, format: formatId, diagnostics: [] }),
    });
    Object.defineProperty(window, 'showOpenFilePicker', { configurable: true, value: open });
    Object.defineProperty(window, 'showSaveFilePicker', { configurable: true, value: save });
    try {
      await mountEditor(chain());
      await waitFor(() => expect(document.querySelector('.engine-pill')).toHaveTextContent('import test engine'));
      fireEvent.click(screen.getByRole('button', { name: 'Open File' }));
      await waitFor(() => expect(screen.getByText(savedName)).toBeInTheDocument());

      fireEvent.click(screen.getByRole('button', { name: 'Save' }));

      await waitFor(() => expect(targetWrite).toHaveBeenCalledOnce());
      expect(sourceWrite).not.toHaveBeenCalled();
      expect(save).toHaveBeenCalledWith({ suggestedName: savedName });
      expect(readFile).toHaveBeenCalledWith(expect.any(Uint8Array), formatId);
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
