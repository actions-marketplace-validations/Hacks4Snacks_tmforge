import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ReactFlow,
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  Panel,
  addEdge,
  reconnectEdge,
  applyEdgeChanges as applyEdgeChangesToGraph,
  useNodesState,
  useEdgesState,
  useReactFlow,
  ConnectionMode,
  MarkerType,
  type Connection,
  type NodeTypes,
  type EdgeTypes,
  type DefaultEdgeOptions,
  type EdgeChange,
  type XYPosition,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type { DragEvent as ReactDragEvent } from 'react';
import { ShapeNode } from './nodes/ShapeNode';
import { TrustBoundaryNode } from './nodes/TrustBoundaryNode';
import { Palette } from './Palette';
import { Toolbar } from './Toolbar';
import { Inspector } from './Inspector';
import { AnalysisSettings } from './AnalysisSettings';
import { FALLBACK_PACKS, FALLBACK_STENCILS } from './stencils';
import { createHttpEngine, loadWasmEngine, looksLikeManifest, offlineEngine, probeEngine, type AnalysisReportFormat, type Finding, type FormatInfo, type IEngineClient, type PackInfo, type PreflightResult, type PropertyDescriptorInfo, type RuleBundle, type RuleInfo, type RulePackInfo, type StencilInfo, type Threat } from './engineClient';
import { ThreatsPanel, type NewThreatDraft, type ThreatEdit, type ThreatScopeOption } from './ThreatsPanel';
import { CanvasSearch, type SearchItem } from './CanvasSearch';
import { ModelOutline } from './ModelOutline';
import { buildOutline, type OutlineOrder } from './outline';
import { DEFAULT_NODE_SIZE, modelFromPages, pagesFromModel, toModel, type PageGraph } from './mapping';
import { applyLayoutGeometry, tidyGraph, tidyLabels } from './autosize';
import { cloneGraph, type Clipboard } from './clipboard';
import { useUndoRedo } from './useUndoRedo';
import { FlowEdge } from './edges/FlowEdge';
import { PageTabs } from './PageTabs';
import { MergeResolveModal } from './MergeResolveModal';
import { CompareReview } from './CompareReview';
import { PreflightDialog } from './PreflightDialog';
import { DfdActionsContext, type DfdActions } from './editorContext';
import { Toaster, toast } from './toast';
import type { DfdEdge, DfdKind, DfdNode, ThreatTriage, TmForgeModel, TmForgeAnalysis, TmForgeExpectedRulePack } from './types';

const nodeTypes: NodeTypes = {
  process: ShapeNode,
  datastore: ShapeNode,
  external: ShapeNode,
  boundary: TrustBoundaryNode,
};

const edgeTypes: EdgeTypes = {
  flow: FlowEdge,
};

const defaultEdgeOptions: DefaultEdgeOptions = {
  type: 'flow',
  markerEnd: { type: MarkerType.ArrowClosed },
};

const KIND_COLOR: Record<DfdKind, string> = {
  process: '#6366f1',
  datastore: '#0d9488',
  external: '#475569',
  boundary: '#64748b',
};

export const STORAGE_KEY = 'tmforge.studio.workspace.v2';
export const LEGACY_MODEL_KEY = 'tmforge.studio.model.v1';
export const THEME_KEY = 'tmforge.studio.theme';
export const RECENTS_KEY = 'tmforge.studio.recentStencils.v1';
/** How many recently used stencils to remember. */
export const RECENTS_MAX = 6;
/** Canvas grid pitch (px). Shared by the dotted background and snap-to-grid so they line up. */
const GRID_SIZE = 16;
/** Offset (px) applied to pasted/duplicated elements so a copy is visibly distinct from its source. */
const PASTE_OFFSET = { x: GRID_SIZE * 2, y: GRID_SIZE * 2 };
const PACKS_DISABLED_KEY = 'tmforge.studio.disabledPacks.v1';
const FAVORITES_KEY = 'tmforge.studio.favoriteStencils.v1';
export const OUTLINE_ORDER_KEY = 'tmforge.studio.outlineOrder.v1';

/** The saved outline order, defaulting to the order the model stores. */
export function loadOutlineOrder(): OutlineOrder {
  try {
    return window.localStorage.getItem(OUTLINE_ORDER_KEY) === 'name' ? 'name' : 'model';
  } catch {
    return 'model';
  }
}

type Theme = 'light' | 'dark';

/** The initial theme: a saved choice if present, else the OS preference. */
export function initialTheme(): Theme {
  try {
    const saved = window.localStorage.getItem(THEME_KEY);
    if (saved === 'light' || saved === 'dark') {
      return saved;
    }
  } catch {
    /* storage unavailable */
  }
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

interface StoredWorkspace {
  pages: PageGraph[];
  activePageId: string;
  analysis?: TmForgeAnalysis;
  threats?: ThreatTriage[];
  metadata?: TmForgeModel['metadata'];
}

/** Reads the saved multi-page workspace (v2), migrating a legacy single-page model (v1) when present. */
export function loadStoredWorkspace(): StoredWorkspace | null {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as { model?: TmForgeModel; activePageId?: string };
      if (parsed?.model?.schema === 'tmforge-json') {
        const pages = pagesFromModel(parsed.model);
        const activePageId = pages.some((p) => p.id === parsed.activePageId) ? parsed.activePageId! : pages[0].id;
        return { pages, activePageId, analysis: parsed.model.analysis, threats: parsed.model.threats, metadata: parsed.model.metadata };
      }
    }
  } catch {
    /* fall through to legacy / empty */
  }
  try {
    const raw = window.localStorage.getItem(LEGACY_MODEL_KEY);
    if (raw) {
      const model = JSON.parse(raw) as TmForgeModel;
      if (model?.schema === 'tmforge-json') {
        const pages = pagesFromModel(model);
        return { pages, activePageId: pages[0].id, analysis: model.analysis, threats: model.threats, metadata: model.metadata };
      }
    }
  } catch {
    /* fall through to empty */
  }
  return null;
}

/** A fresh workspace with a single empty page. */
export function emptyWorkspace(): StoredWorkspace {
  const id = crypto.randomUUID();
  return { pages: [{ id, name: 'Page 1', nodes: [], edges: [] }], activePageId: id };
}

/** Reads the recently used stencil ids from browser storage (most recent first). */
export function loadRecentStencilIds(): string[] {
  try {
    const raw = window.localStorage.getItem(RECENTS_KEY);
    if (!raw) {
      return [];
    }
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed)
      ? parsed.filter((x): x is string => typeof x === 'string').slice(0, RECENTS_MAX)
      : [];
  } catch {
    return [];
  }
}

/** Reads a persisted list of string ids from browser storage. */
export function loadStringList(key: string): string[] {
  try {
    const raw = window.localStorage.getItem(key);
    if (!raw) {
      return [];
    }
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

/** Persists a list of string ids to browser storage, ignoring storage failures. */
export function persistStringList(key: string, value: string[]): void {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    /* storage unavailable */
  }
}

// Restore the last saved workspace on load, else start from a single empty page.
const INITIAL_WORKSPACE = loadStoredWorkspace() ?? emptyWorkspace();
const INITIAL_ACTIVE =
  INITIAL_WORKSPACE.pages.find((p) => p.id === INITIAL_WORKSPACE.activePageId) ?? INITIAL_WORKSPACE.pages[0];
const INITIAL_DISABLED_PACKS = INITIAL_WORKSPACE.analysis?.disabledPacks ?? [];
const INITIAL_DISABLED_RULE_IDS = INITIAL_WORKSPACE.analysis?.disabledRuleIds ?? [];
const INITIAL_EXPECTED_PACKS = INITIAL_WORKSPACE.analysis?.expectedPacks ?? [];
const INITIAL_SAVED_JSON = JSON.stringify(
  modelFromPages(
    INITIAL_WORKSPACE.pages,
    buildAnalysis(INITIAL_DISABLED_PACKS, INITIAL_DISABLED_RULE_IDS, INITIAL_EXPECTED_PACKS),
    INITIAL_WORKSPACE.threats,
    INITIAL_WORKSPACE.metadata,
  ),
);

/** Minimal shape of the File System Access API used to open and overwrite files (Chromium). */
interface WritableFileHandle {
  readonly name: string;
  getFile(): Promise<File>;
  createWritable(): Promise<{ write(data: BlobPart): Promise<void>; close(): Promise<void> }>;
}

interface FilePickerWindow {
  showOpenFilePicker?: () => Promise<WritableFileHandle[]>;
  showSaveFilePicker?: (options?: { suggestedName?: string }) => Promise<WritableFileHandle>;
}

/** Builds a browser-compatible accept list, including the terminal suffix of compound extensions. */
export function buildFileAccept(formats: FormatInfo[]): string {
  const extensions = formats
    .filter((format) => format.canRead)
    .flatMap((format) => format.extensions)
    .flatMap((extension) => {
      const terminalDot = extension.lastIndexOf('.');
      return terminalDot > 0 ? [extension, extension.slice(terminalDot)] : [extension];
    });

  return [...new Set(extensions.length > 0 ? extensions : ['.json', '.tm7', '.drawio', '.vsdx'])].join(',');
}

/** True when a file-picker promise rejected because the user cancelled the dialog. */
export function isAbortError(err: unknown): boolean {
  return err instanceof DOMException && err.name === 'AbortError';
}

/** Suffixes stripped from a manifest's file name before the model extension is appended. */
const MANIFEST_NAME_SUFFIXES = [/\.json$/i, /\.(manifest|tm)$/i];

/** A document resolved by the Open/Import path, and how the resulting model may be saved. */
interface OpenedDocument {
  model: TmForgeModel;
  /** The format Save writes in: the source format when it is writable, else tmforge-json. */
  saveFormat: string;
  /** The name to bind, using a new name for manifests and read-only source formats. */
  fileName: string;
  /** Whether Save may overwrite the source. False for manifests and read-only formats. */
  bindable: boolean;
}

/**
 * The name to bind after opening an authoring manifest. The manifest's own name is deliberately not
 * reused: Save falls back to Save As, which offers the bound name, and accepting that would replace
 * the reviewable manifest source with the model built from it.
 */
export function modelNameForManifest(sourceName: string): string {
  let base = sourceName;
  for (const suffix of MANIFEST_NAME_SUFFIXES) {
    base = base.replace(suffix, '');
  }
  return `${base || sourceName}.tmforge.json`;
}

function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

/** Builds the analysis-rule selection from the current toggles, or undefined when nothing is selected. */
export function buildAnalysis(
  disabledPacks: string[],
  disabledRuleIds: string[],
  expectedPacks: TmForgeExpectedRulePack[] = [],
): TmForgeAnalysis | undefined {
  const analysis: TmForgeAnalysis = {};
  if (disabledPacks.length > 0) {
    analysis.disabledPacks = disabledPacks;
  }
  if (disabledRuleIds.length > 0) {
    analysis.disabledRuleIds = disabledRuleIds;
  }
  if (expectedPacks.length > 0) {
    analysis.expectedPacks = expectedPacks;
  }
  return analysis.disabledPacks || analysis.disabledRuleIds || analysis.expectedPacks ? analysis : undefined;
}

/**
 * Runs one analysis action against the engine and shapes it for the panel. This is a single engine
 * request on purpose: findings and threats are the same detection, so asking for them separately
 * makes the engine evaluate every enabled rule twice for one click.
 *
 * The presentation rule lives here too: threat-bearing rules are already shown as threats, so their
 * findings are dropped from "Other findings" — while `flaggedIds` still spans every finding, so the
 * canvas overlay marks everything the analysis touched.
 *
 * @param engine The engine client to analyze with.
 * @param model The model to analyze.
 * @returns The threats, the non-threat findings, the ids to flag, and the rule evidence.
 */
export async function analyzeModel(
  engine: IEngineClient,
  model: TmForgeModel,
): Promise<{
  threats: Threat[];
  otherFindings: Finding[];
  flaggedIds: Set<string>;
  ruleBundle: RuleBundle;
}> {
  const result = await engine.runAnalysis(model);
  const threatRuleIds = new Set(result.threats.map((t) => t.ruleId));
  return {
    threats: result.threats,
    otherFindings: result.findings.filter((f) => !f.ruleId || !threatRuleIds.has(f.ruleId)),
    flaggedIds: new Set([
      ...result.threats.flatMap((t) => t.elementIds),
      ...result.findings.flatMap((f) => f.elementIds),
    ]),
    ruleBundle: { rulePacks: result.rulePacks, diagnostics: result.diagnostics },
  };
}

/**
 * Maps a Report menu choice to the engine call and download name behind it. Threat-model reports
 * describe the model; `analysis` reports are the findings evidence, rendered by a different engine
 * operation. The file names match what the CLI writes, so a download drops into a review folder.
 */
export const REPORT_DOWNLOADS: Record<string, { format: string; fileName: string; analysis: boolean }> = {
  html: { format: 'html', fileName: 'threat-model-report.html', analysis: false },
  svg: { format: 'svg', fileName: 'threat-model-diagram.svg', analysis: false },
  'findings-html': { format: 'html', fileName: 'findings.html', analysis: true },
  'findings-sarif': { format: 'sarif', fileName: 'findings.sarif', analysis: true },
  'findings-json': { format: 'json', fileName: 'findings.json', analysis: true },
};

/** Returns copies of the graph with the `flagged` class applied to elements a finding referenced. */
export function applyFlags(
  nodes: DfdNode[],
  edges: DfdEdge[],
  flagged: ReadonlySet<string>,
): { nodes: DfdNode[]; edges: DfdEdge[] } {
  return {
    nodes: nodes.map((n) => ({ ...n, className: flagged.has(n.id) ? 'flagged' : undefined })),
    edges: edges.map((e) => ({ ...e, className: flagged.has(e.id) ? 'flagged' : undefined })),
  };
}

/**
 * The ids to light up when one object or flow is picked (from the outline, or the search box). A
 * flow highlights with both of its endpoints, so picking it answers what it connects — the same set
 * a finding about that flow highlights.
 */
export function highlightForFocus(id: string, endpoints?: { source: string; target: string }): Set<string> {
  return endpoints ? new Set([id, endpoints.source, endpoints.target]) : new Set([id]);
}

/**
 * Applies React Flow edge changes without letting controlled-prop synchronization discard Tidy's
 * geometry. React Flow can emit `replace` copies after an unrelated canvas edit; those copies do
 * not carry Studio-only handles, routes, or label offsets. Preserve that state when the endpoints
 * are unchanged. A real reconnect changes an endpoint and intentionally receives fresh geometry.
 */
export function applyCanvasEdgeChanges(changes: EdgeChange<DfdEdge>[], current: DfdEdge[]): DfdEdge[] {
  const byId = new Map(current.map((edge) => [edge.id, edge]));
  const geometrySafe = changes.map((change): EdgeChange<DfdEdge> => {
    if (change.type !== 'replace') {
      return change;
    }
    const existing = byId.get(change.id);
    const replacement = change.item;
    if (!existing || existing.source !== replacement.source || existing.target !== replacement.target) {
      return change;
    }
    return {
      ...change,
      item: {
        ...replacement,
        sourceHandle: replacement.sourceHandle ?? existing.sourceHandle,
        targetHandle: replacement.targetHandle ?? existing.targetHandle,
        data:
          existing.data || replacement.data
            ? { ...existing.data, ...replacement.data }
            : undefined,
      },
    };
  });
  return applyEdgeChangesToGraph(geometrySafe, current);
}

/** True when two id lists hold the same ids in the same order. */
export function sameIds(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((id, index) => id === b[index]);
}

/**
 * The graph left after deleting a selection. Deleting an element takes its flows with it, because a
 * flow with a missing endpoint is not a model — so a selection of elements removes more edges than
 * the ones the author selected.
 */
export function deleteFromGraph(
  nodes: DfdNode[],
  edges: DfdEdge[],
  doomedNodeIds: readonly string[],
  doomedEdgeIds: readonly string[],
): { nodes: DfdNode[]; edges: DfdEdge[] } {
  const doomedNodes = new Set(doomedNodeIds);
  const doomedEdges = new Set(doomedEdgeIds);
  return {
    nodes: nodes.filter((n) => !doomedNodes.has(n.id)),
    edges: edges.filter(
      (e) => !doomedEdges.has(e.id) && !doomedNodes.has(e.source) && !doomedNodes.has(e.target),
    ),
  };
}

export function Editor() {
  const [pages, setPages] = useState<PageGraph[]>(INITIAL_WORKSPACE.pages);
  const [activePageId, setActivePageId] = useState<string>(INITIAL_ACTIVE.id);
  const [nodes, setNodes, onNodesChange] = useNodesState<DfdNode>(INITIAL_ACTIVE.nodes);
  const [edges, setEdges] = useEdgesState<DfdEdge>(INITIAL_ACTIVE.edges);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [threatTriage, setThreatTriage] = useState<ThreatTriage[]>(INITIAL_WORKSPACE.threats ?? []);
  const [metadata, setMetadata] = useState<TmForgeModel['metadata']>(INITIAL_WORKSPACE.metadata);
  const flaggedIdsRef = useRef<ReadonlySet<string>>(new Set());
  const [engine, setEngine] = useState<IEngineClient>(offlineEngine);
  const [engineOnline, setEngineOnline] = useState(false);
  const [formats, setFormats] = useState<FormatInfo[]>([]);
  // The whole selection, not just its first member: the Inspector edits every selected element, and
  // a bulk delete has to take the connected flows with it.
  const [selection, setSelection] = useState<{ nodes: string[]; edges: string[] }>({ nodes: [], edges: [] });
  const [stencils, setStencils] = useState<StencilInfo[]>(FALLBACK_STENCILS);
  const [recentStencilIds, setRecentStencilIds] = useState<string[]>(loadRecentStencilIds);
  const [packs, setPacks] = useState<PackInfo[]>(FALLBACK_PACKS);
  const [disabledPacks, setDisabledPacks] = useState<string[]>(() => loadStringList(PACKS_DISABLED_KEY));
  const [favoriteIds, setFavoriteIds] = useState<string[]>(() => loadStringList(FAVORITES_KEY));
  const [rules, setRules] = useState<RuleInfo[]>([]);
  const [rulePacks, setRulePacks] = useState<RulePackInfo[]>([]);
  const [disabledRulePacks, setDisabledRulePacks] = useState<string[]>(() => INITIAL_DISABLED_PACKS);
  const [disabledRuleIds, setDisabledRuleIds] = useState<string[]>(() => INITIAL_DISABLED_RULE_IDS);
  const [expectedPacks, setExpectedPacks] = useState<TmForgeExpectedRulePack[]>(() => INITIAL_EXPECTED_PACKS);
  const [ruleBundle, setRuleBundle] = useState<RuleBundle>({ rulePacks: [], diagnostics: [] });
  const [ruleCatalogToken, setRuleCatalogToken] = useState(0);
  const [showRules, setShowRules] = useState(false);
  const [showMerge, setShowMerge] = useState(false);
  const [compareSnapshot, setCompareSnapshot] = useState<{ model: TmForgeModel; name: string | null } | null>(null);
  const reviewActiveRef = useRef(false);
  const reviewVersionRef = useRef(0);
  reviewActiveRef.current = compareSnapshot !== null;
  const [preflightReview, setPreflightReview] = useState<{ title: string; result: PreflightResult } | null>(null);
  const preflightDecision = useRef<((proceed: boolean) => void) | undefined>(undefined);
  const preflightVersion = useRef(0);
  const [showOutline, setShowOutline] = useState(false);
  const [outlineOrder, setOutlineOrder] = useState<OutlineOrder>(loadOutlineOrder);
  const [outlineCrossingOnly, setOutlineCrossingOnly] = useState(false);
  const analysisActiveRef = useRef(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const fileHandleRef = useRef<WritableFileHandle | null>(null);
  const fileFormatRef = useRef<string>('tmforge-json');
  const [fileName, setFileName] = useState<string | null>(null);
  const { screenToFlowPosition, fitView } = useReactFlow();
  const { takeSnapshot, undo, redo, canUndo, canRedo, reset } = useUndoRedo(nodes, edges, setNodes, setEdges);

  const [theme, setTheme] = useState<Theme>(initialTheme);
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    try {
      window.localStorage.setItem(THEME_KEY, theme);
    } catch {
      /* storage unavailable */
    }
  }, [theme]);
  const toggleTheme = useCallback(() => setTheme((t) => (t === 'dark' ? 'light' : 'dark')), []);

  useEffect(() => {
    let active = true;
    void (async () => {
      // 1. Prefer the hosted /v1 engine — unless this is a static demo build with no /v1 to reach.
      if (import.meta.env.VITE_DEMO !== 'true' && (await probeEngine())) {
        if (active) {
          setEngine(createHttpEngine());
          setEngineOnline(true);
        }
        return;
      }
      // 2. Fall back to the in-browser WebAssembly engine — the SAME engine, no backend.
      const wasm = await loadWasmEngine();
      if (active && wasm) {
        setEngine(wasm);
        setEngineOnline(true);
        return;
      }
      // 3. Neither reachable: the built-in offline client (client-side authoring) remains.
    })();
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    void engine
      .getFormats()
      .then((list) => {
        if (active) {
          setFormats(list);
        }
      })
      .catch(() => {
        if (active) {
          setFormats([]);
        }
      });
    return () => {
      active = false;
    };
  }, [engine]);

  // Load the stencil catalog from whichever engine is active (the real /v1/stencils when online,
  // the generic fallback offline).
  useEffect(() => {
    let active = true;
    void engine
      .getStencils()
      .then((list) => {
        if (active && list.length) {
          setStencils(list);
        }
      })
      .catch(() => {
        /* keep the fallback catalog */
      });
    return () => {
      active = false;
    };
  }, [engine]);

  // Load the stencil packs (for the palette's show/hide toggles) from the active engine.
  useEffect(() => {
    let active = true;
    void engine
      .getStencilPacks()
      .then((list) => {
        if (active && list.length) {
          setPacks(list);
        }
      })
      .catch(() => {
        /* keep the fallback packs */
      });
    return () => {
      active = false;
    };
  }, [engine]);

  // Load the typed property schema (drives the Inspector's typed controls) from the active engine.
  const [propertySchema, setPropertySchema] = useState<PropertyDescriptorInfo[]>([]);
  useEffect(() => {
    let active = true;
    void engine
      .getPropertySchema()
      .then((list) => {
        if (active && list.length) {
          setPropertySchema(list);
        }
      })
      .catch(() => {
        /* no typed schema offline; the Inspector falls back to free text */
      });
    return () => {
      active = false;
    };
  }, [engine]);

  const stencilById = useMemo(() => new Map(stencils.map((s) => [s.id, s])), [stencils]);

  // Load the analysis rule catalog + rule packs (for the Analysis Rules settings panel) from the
  // engine. `ruleCatalogToken` is bumped when a custom pack is loaded or cleared so the catalogs are
  // re-read against the new effective bundle rather than showing a stale built-in-only list.
  useEffect(() => {
    let active = true;
    void engine
      .getRules()
      .then((list) => {
        if (active) {
          setRules(list);
        }
      })
      .catch(() => {
        if (active) {
          setRules([]);
        }
      });
    return () => {
      active = false;
    };
  }, [engine, ruleCatalogToken]);

  useEffect(() => {
    let active = true;
    void engine
      .getRulePacks()
      .then((list) => {
        if (active) {
          setRulePacks(list);
        }
      })
      .catch(() => {
        if (active) {
          setRulePacks([]);
        }
      });
    return () => {
      active = false;
    };
  }, [engine, ruleCatalogToken]);

  // Report what custom rule content the engine actually runs. For a configured /v1 host this is the
  // server's bundle; for the in-browser engine it is whatever pack the author loaded here.
  useEffect(() => {
    let active = true;
    void engine
      .getRuleBundle()
      .then((bundle) => {
        if (active) {
          setRuleBundle(bundle);
        }
      })
      .catch(() => {
        if (active) {
          setRuleBundle({ rulePacks: [], diagnostics: [] });
        }
      });
    return () => {
      active = false;
    };
  }, [engine, ruleCatalogToken]);

  // All pages, with the live React Flow graph substituted for the active page (the store's copy of
  // the active page is only refreshed on switch / page op, so composed reads use the live graph).
  const allPages = useMemo<PageGraph[]>(
    () => pages.map((p) => (p.id === activePageId ? { ...p, nodes, edges } : p)),
    [pages, activePageId, nodes, edges],
  );

  // Persistence. `currentJson` serializes the model the way Save writes it (selection is not part of
  // the model, so selecting a node never marks it dirty); `dirty` compares it to the snapshot from
  // the last explicit Save. A debounced localStorage write of the whole workspace (pages + active
  // tab) runs on every change as a crash-recovery net, so a reload never loses work.
  const currentModel = useMemo(() => {
    return modelFromPages(allPages, buildAnalysis(disabledRulePacks, disabledRuleIds, expectedPacks), threatTriage, metadata);
  }, [allPages, disabledRulePacks, disabledRuleIds, expectedPacks, threatTriage, metadata]);
  const currentJson = useMemo(() => JSON.stringify(currentModel), [currentModel]);
  const [savedJson, setSavedJson] = useState(INITIAL_SAVED_JSON);
  const dirty = currentJson !== savedJson;

  const workspaceJson = useMemo(
    () => JSON.stringify({ v: 2, activePageId, model: currentModel }),
    [activePageId, currentModel],
  );
  const layoutStateRef = useRef({ workspaceJson, nodes, edges });
  layoutStateRef.current = { workspaceJson, nodes, edges };
  const layoutRequestRef = useRef(0);
  const layoutPendingRef = useRef(false);
  const [tidying, setTidying] = useState(false);
  useEffect(() => () => { layoutRequestRef.current += 1; }, []);
  useEffect(() => {
    const id = window.setTimeout(() => {
      try {
        window.localStorage.setItem(STORAGE_KEY, workspaceJson);
      } catch {
        /* storage unavailable (private mode / quota) — ignore */
      }
    }, 600);
    return () => window.clearTimeout(id);
  }, [workspaceJson]);

  // ---- pages: switch, add, rename, delete, reorder ----
  const switchPage = useCallback(
    (targetId: string) => {
      if (targetId === activePageId) {
        return;
      }
      const committed = allPages;
      const target = committed.find((p) => p.id === targetId);
      if (!target) {
        return;
      }
      setPages(committed);
      setActivePageId(targetId);
      const applied = analysisActiveRef.current
        ? applyFlags(target.nodes, target.edges, flaggedIdsRef.current)
        : { nodes: target.nodes, edges: target.edges };
      setNodes(applied.nodes);
      setEdges(applied.edges);
      setSelection({ nodes: [], edges: [] });
      reset();
      window.setTimeout(() => fitView({ padding: 0.25, maxZoom: 1.15, duration: 200 }), 0);
    },
    [allPages, activePageId, setNodes, setEdges, reset, fitView],
  );

  const addPage = useCallback(() => {
    const id = crypto.randomUUID();
    setPages([...allPages, { id, name: `Page ${pages.length + 1}`, nodes: [], edges: [] }]);
    setActivePageId(id);
    setNodes([]);
    setEdges([]);
    setSelection({ nodes: [], edges: [] });
    reset();
  }, [allPages, pages.length, setNodes, setEdges, reset]);

  const renamePage = useCallback((id: string, name: string) => {
    setPages((prev) => prev.map((p) => (p.id === id ? { ...p, name } : p)));
  }, []);

  const deletePage = useCallback(
    (id: string) => {
      if (pages.length <= 1) {
        return;
      }
      const committed = allPages;
      const victim = committed.find((p) => p.id === id);
      if (
        victim &&
        (victim.nodes.length > 0 || victim.edges.length > 0) &&
        !window.confirm(`Delete page “${victim.name}” and its contents?`)
      ) {
        return;
      }
      const index = committed.findIndex((p) => p.id === id);
      const remaining = committed.filter((p) => p.id !== id);
      setPages(remaining);
      if (id === activePageId) {
        const next = remaining[Math.min(index, remaining.length - 1)];
        setActivePageId(next.id);
        const applied = analysisActiveRef.current
          ? applyFlags(next.nodes, next.edges, flaggedIdsRef.current)
          : { nodes: next.nodes, edges: next.edges };
        setNodes(applied.nodes);
        setEdges(applied.edges);
        setSelection({ nodes: [], edges: [] });
        reset();
      }
    },
    [allPages, pages.length, activePageId, setNodes, setEdges, reset],
  );

  const reorderPage = useCallback(
    (from: number, to: number) => {
      const committed = allPages;
      if (from < 0 || to < 0 || from >= committed.length || to >= committed.length) {
        return;
      }
      const next = [...committed];
      const [moved] = next.splice(from, 1);
      next.splice(to, 0, moved);
      setPages(next);
    },
    [allPages],
  );

  // Which page each element id lives on, and which pages currently carry a finding (for tab badges).
  const elementPageIndex = useMemo(() => {
    const map = new Map<string, string>();
    for (const page of allPages) {
      for (const n of page.nodes) {
        map.set(n.id, page.id);
      }
      for (const e of page.edges) {
        map.set(e.id, page.id);
      }
    }
    return map;
  }, [allPages]);

  const findingPageIds = useMemo(() => {
    const set = new Set<string>();
    const elementIdLists = [...findings.map((f) => f.elementIds), ...threats.map((t) => t.elementIds)];
    for (const elementIds of elementIdLists) {
      for (const id of elementIds) {
        const pageId = elementPageIndex.get(id);
        if (pageId) {
          set.add(pageId);
        }
      }
    }
    return set;
  }, [findings, threats, elementPageIndex]);

  const finishPreflight = useCallback((proceed: boolean) => {
    const decide = preflightDecision.current;
    preflightDecision.current = undefined;
    setPreflightReview(null);
    decide?.(proceed);
  }, []);

  const checkDocument = useCallback(async (bytes: Uint8Array, format: string | undefined, target: string | undefined, operation: 'import' | 'export') => {
    const version = ++preflightVersion.current;
    const baseline = layoutStateRef.current.workspaceJson;
    finishPreflight(false);
    const result = await engine.preflight(bytes, format, target);
    const ensureCurrent = () => {
      if (version !== preflightVersion.current || baseline !== layoutStateRef.current.workspaceJson) {
        throw new DOMException('The workspace changed during preflight.', 'AbortError');
      }
    };
    ensureCurrent();
    if (!result.success || result.diagnostics.length > 0) {
      const accepted = await new Promise<boolean>((resolve) => {
        preflightDecision.current = resolve;
        setPreflightReview({ title: result.success ? `Review ${operation}` : `${operation === 'import' ? 'Import' : 'Export'} blocked`, result });
      });
      ensureCurrent();
      if (!accepted || !result.success) {
        throw new DOMException('Preflight cancelled.', 'AbortError');
      }
    }
    return result;
  }, [engine, finishPreflight]);

  const serializeModel = useCallback(
    async (formatId: string): Promise<Blob> => {
      const baseline = layoutStateRef.current.workspaceJson;
      if (engine !== offlineEngine) {
        await checkDocument(new TextEncoder().encode(JSON.stringify(currentModel)), 'tmforge-json', formatId === 'tmforge-json' ? undefined : formatId, 'export');
      }
      const blob = formatId === 'tmforge-json'
        ? new Blob([await engine.write(currentModel)], { type: 'application/json' })
        : await engine.convert(currentModel, formatId);
      if (baseline !== layoutStateRef.current.workspaceJson) {
        throw new DOMException('The workspace changed before export completed.', 'AbortError');
      }
      return blob;
    },
    [engine, currentModel, checkDocument],
  );

  const writeToHandle = useCallback(
    async (handle: WritableFileHandle, formatId: string): Promise<void> => {
      const blob = await serializeModel(formatId);
      const writable = await handle.createWritable();
      await writable.write(blob);
      await writable.close();
    },
    [serializeModel],
  );

  // Save As: pick a new file and write it (Chromium), else download a copy (other browsers).
  const saveAs = useCallback(async () => {
    const picker = window as unknown as FilePickerWindow;
    const formatId = fileFormatRef.current;
    const ext = formats.find((f) => f.id === formatId)?.extensions[0] ?? '.tmforge.json';
    const suggestedName = fileName ?? `model${ext}`;
    try {
      if (picker.showSaveFilePicker) {
        const handle = await picker.showSaveFilePicker({ suggestedName });
        await writeToHandle(handle, formatId);
        fileHandleRef.current = handle;
        setFileName(handle.name);
      } else {
        downloadBlob(await serializeModel(formatId), suggestedName);
      }
      setSavedJson(currentJson);
    } catch (err) {
      if (!isAbortError(err)) {
        toast(err instanceof Error ? err.message : 'Could not save the file.', 'error');
      }
    }
  }, [currentJson, fileName, formats, serializeModel, writeToHandle]);

  // Save: silently overwrite the file this model was opened from / last saved to; when no file is
  // bound (or the browser lacks the File System Access API) fall back to Save As.
  const saveModel = useCallback(async () => {
    const handle = fileHandleRef.current;
    if (!handle) {
      await saveAs();
      return;
    }
    try {
      await writeToHandle(handle, fileFormatRef.current);
      setSavedJson(currentJson);
    } catch (err) {
      if (!isAbortError(err)) toast(err instanceof Error ? err.message : 'Could not write the file.', 'error');
    }
  }, [currentJson, saveAs, writeToHandle]);

  // Keep a ref so the global keydown handler always calls the latest saveModel without re-subscribing.
  const saveModelRef = useRef(saveModel);
  saveModelRef.current = saveModel;

  // ---- clipboard: copy / paste / duplicate the selected nodes and the flows between them ----
  const clipboardRef = useRef<Clipboard | null>(null);

  const copySelection = useCallback(() => {
    const selectedNodes = nodes.filter((n) => n.selected);
    const selectedEdges = edges.filter((e) => e.selected);
    if (selectedNodes.length === 0 && selectedEdges.length === 0) {
      return;
    }
    clipboardRef.current = { nodes: selectedNodes, edges: selectedEdges };
  }, [nodes, edges]);

  // Drops a freshly-cloned graph onto the canvas: existing elements are deselected and the clones
  // become the selection, so the copy is ready to nudge and a repeat paste offsets from this one.
  const placeClone = useCallback(
    (clone: Clipboard) => {
      if (clone.nodes.length === 0 && clone.edges.length === 0) {
        return;
      }
      takeSnapshot();
      setNodes((nds) => [...nds.map((n) => (n.selected ? { ...n, selected: false } : n)), ...clone.nodes]);
      setEdges((eds) => [...eds.map((e) => (e.selected ? { ...e, selected: false } : e)), ...clone.edges]);
      setSelection({ nodes: clone.nodes.map((n) => n.id), edges: clone.edges.map((e) => e.id) });
    },
    [setNodes, setEdges, takeSnapshot],
  );

  const pasteClipboard = useCallback(() => {
    const clip = clipboardRef.current;
    if (clip) {
      placeClone(cloneGraph(clip.nodes, clip.edges, PASTE_OFFSET));
    }
  }, [placeClone]);

  const duplicateSelection = useCallback(() => {
    const selectedNodes = nodes.filter((n) => n.selected);
    const selectedEdges = edges.filter((e) => e.selected);
    placeClone(cloneGraph(selectedNodes, selectedEdges, PASTE_OFFSET));
  }, [nodes, edges, placeClone]);

  // Latest clipboard actions for the global keydown handler, so it never re-subscribes on every edit.
  const clipboardActionsRef = useRef({ copy: copySelection, paste: pasteClipboard, duplicate: duplicateSelection });
  clipboardActionsRef.current = { copy: copySelection, paste: pasteClipboard, duplicate: duplicateSelection };

  // Same, for walking the outline's flow order — assigned once the outline has been built below.
  const stepFlowRef = useRef<(delta: number) => void>(() => {});

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (reviewActiveRef.current) {
        return;
      }
      // Cmd/Ctrl+S saves — even while typing in a field — and never opens the browser's save dialog.
      if ((event.metaKey || event.ctrlKey) && (event.key === 's' || event.key === 'S')) {
        event.preventDefault();
        saveModelRef.current();
        return;
      }
      const target = event.target as HTMLElement | null;
      const tag = target?.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || target?.isContentEditable) {
        return;
      }
      // Alt+Arrow steps through the flows in the outline's order, for reviewing one flow at a time.
      if (event.altKey && (event.key === 'ArrowDown' || event.key === 'ArrowRight')) {
        event.preventDefault();
        stepFlowRef.current(1);
        return;
      }
      if (event.altKey && (event.key === 'ArrowUp' || event.key === 'ArrowLeft')) {
        event.preventDefault();
        stepFlowRef.current(-1);
        return;
      }
      if (!(event.metaKey || event.ctrlKey)) {
        return;
      }
      if (event.key === 'z' || event.key === 'Z') {
        event.preventDefault();
        if (event.shiftKey) {
          redo();
        } else {
          undo();
        }
      } else if (event.key === 'y') {
        event.preventDefault();
        redo();
      } else if (event.key === 'c' || event.key === 'C') {
        clipboardActionsRef.current.copy();
      } else if (event.key === 'v' || event.key === 'V') {
        event.preventDefault();
        clipboardActionsRef.current.paste();
      } else if (event.key === 'd' || event.key === 'D') {
        event.preventDefault();
        clipboardActionsRef.current.duplicate();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [undo, redo]);

  const onConnect = useCallback(
    (connection: Connection) => {
      takeSnapshot();
      setEdges((eds) =>
        addEdge(
          {
            ...connection,
            type: 'flow',
            markerEnd: { type: MarkerType.ArrowClosed },
            label: 'data flow',
            data: { properties: {} },
          },
          eds,
        ),
      );
    },
    [setEdges, takeSnapshot],
  );

  // Drag either end of an existing flow onto a different node or port to re-pin it, instead of
  // deleting the connection and drawing a new one.
  const onReconnect = useCallback(
    (oldEdge: DfdEdge, newConnection: Connection) => {
      takeSnapshot();
      setEdges((eds) => reconnectEdge(oldEdge, newConnection, eds));
    },
    [setEdges, takeSnapshot],
  );

  const onEdgesChange = useCallback(
    (changes: EdgeChange<DfdEdge>[]) => {
      setEdges((current) => applyCanvasEdgeChanges(changes, current));
    },
    [setEdges],
  );

  // Show/hide a whole stencil pack in the palette (persisted).
  const togglePack = useCallback((packId: string) => {
    setDisabledPacks((prev) => {
      const next = prev.includes(packId) ? prev.filter((x) => x !== packId) : [...prev, packId];
      persistStringList(PACKS_DISABLED_KEY, next);
      return next;
    });
  }, []);

  // Star/unstar a stencil so it appears in the palette's Favorites row (persisted).
  const toggleFavorite = useCallback((stencilId: string) => {
    setFavoriteIds((prev) => {
      const next = prev.includes(stencilId) ? prev.filter((x) => x !== stencilId) : [stencilId, ...prev];
      persistStringList(FAVORITES_KEY, next);
      return next;
    });
  }, []);

  // Enable/disable a whole rule pack for this model. The selection travels with the model (saved in
  // the file and sent on analyze), so it is model state, not a persisted UI preference.
  const toggleRulePack = useCallback((packId: string) => {
    setDisabledRulePacks((prev) =>
      prev.includes(packId) ? prev.filter((x) => x !== packId) : [...prev, packId],
    );
  }, []);

  // Enable/disable a single rule for this model.
  const toggleRule = useCallback((ruleId: string) => {
    setDisabledRuleIds((prev) =>
      prev.includes(ruleId) ? prev.filter((x) => x !== ruleId) : [...prev, ruleId],
    );
  }, []);

  // Load a custom rule pack (.tmrules.json) into the engine. The pack content never becomes model
  // data; what the model records is the pack's identity and content fingerprint, so a later analysis
  // that runs without it (or with different content) reports the mismatch instead of looking clean.
  const loadRuleFile = useCallback(
    async (file: File) => {
      try {
        const json = await file.text();
        const bundle = await engine.setRules([{ name: file.name, json }]);
        setRuleBundle(bundle);
        setExpectedPacks(bundle.rulePacks.map((pack) => ({ id: pack.id, fingerprint: pack.fingerprint })));
        setRuleCatalogToken((token) => token + 1);
        if (bundle.rulePacks.length === 0) {
          toast(bundle.diagnostics[0] ?? `No rule pack loaded from ${file.name}.`, 'error');
        } else {
          const rules = bundle.rulePacks.reduce((total, pack) => total + pack.ruleCount, 0);
          toast(`Loaded ${bundle.rulePacks.length} rule pack(s), ${rules} rule(s).`, 'success');
        }
      } catch (err) {
        toast(err instanceof Error ? err.message : String(err), 'error');
      }
    },
    [engine],
  );

  // Drop the custom packs and go back to the built-in rules, clearing the model's expectation too.
  const clearRuleFile = useCallback(async () => {
    try {
      const bundle = await engine.setRules([]);
      setRuleBundle(bundle);
      setExpectedPacks([]);
      setRuleCatalogToken((token) => token + 1);
    } catch (err) {
      toast(err instanceof Error ? err.message : String(err), 'error');
    }
  }, [engine]);

  // Remember the last few stencils the user placed, so the palette can surface them.
  const recordRecentStencil = useCallback((stencilId: string) => {
    setRecentStencilIds((prev) => {
      const next = [stencilId, ...prev.filter((x) => x !== stencilId)].slice(0, RECENTS_MAX);
      try {
        window.localStorage.setItem(RECENTS_KEY, JSON.stringify(next));
      } catch {
        /* storage unavailable */
      }
      return next;
    });
  }, []);

  const addNode = useCallback(
    (stencil: StencilInfo, position: XYPosition) => {
      const id = crypto.randomUUID();
      const base = stencil.base;
      // Only specialized stencils (id differs from the primitive) carry a StencilType identity.
      const stencilType = stencil.id === base ? undefined : stencil.id;
      const data = { label: stencil.label, stencilType, properties: { ...stencil.defaults } };
      const size = DEFAULT_NODE_SIZE[base];
      const node: DfdNode = {
        id,
        type: base,
        position,
        data,
        style: { width: size.width, height: size.height },
        zIndex: base === 'boundary' ? 0 : 1,
      };
      takeSnapshot();
      setNodes((nds) => nds.concat(node));
      recordRecentStencil(stencil.id);
    },
    [setNodes, takeSnapshot, recordRecentStencil],
  );

  const onDragOver = useCallback((event: ReactDragEvent) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
  }, []);

  const onDrop = useCallback(
    (event: ReactDragEvent) => {
      event.preventDefault();
      const stencilId = event.dataTransfer.getData('application/tmforge-stencil');
      const stencil = stencilById.get(stencilId);
      if (!stencil) {
        return;
      }
      addNode(stencil, screenToFlowPosition({ x: event.clientX, y: event.clientY }));
    },
    [addNode, screenToFlowPosition, stencilById],
  );

  const onSelectionChange = useCallback(
    ({ nodes: selectedNodes, edges: selectedEdges }: { nodes: DfdNode[]; edges: DfdEdge[] }) => {
      setSelection((prev) => {
        const nextNodes = selectedNodes.map((n) => n.id);
        const nextEdges = selectedEdges.map((e) => e.id);
        // React Flow re-emits the selection on every graph change. Returning the previous object when
        // nothing moved keeps the Inspector from remounting mid-edit (which would drop focus).
        return sameIds(prev.nodes, nextNodes) && sameIds(prev.edges, nextEdges)
          ? prev
          : { nodes: nextNodes, edges: nextEdges };
      });
    },
    [],
  );

  const renameNode = useCallback(
    (id: string, label: string) =>
      setNodes((nds) => nds.map((n) => (n.id === id ? { ...n, data: { ...n.data, label } } : n))),
    [setNodes],
  );

  const renameEdge = useCallback(
    (id: string, label: string) => setEdges((eds) => eds.map((e) => (e.id === id ? { ...e, label } : e))),
    [setEdges],
  );

  // Persist a label's dragged offset (the snapshot is taken by the edge on drag start via beginEdit).
  const setEdgeLabelOffset = useCallback(
    (id: string, offset: { x: number; y: number }) =>
      setEdges((eds) =>
        eds.map((e) =>
          e.id === id ? { ...e, data: { ...e.data, labelOffset: offset, autoLabelOffset: false } } : e,
        ),
      ),
    [setEdges],
  );

  // The property writers take a set of ids so a bulk edit is one state update under one snapshot.
  // A single selection is just the one-element case, so there is only ever one code path.
  const setEdgeProperty = useCallback(
    (ids: string[], key: string, value: string) => {
      if (ids.length === 0) {
        return;
      }
      takeSnapshot();
      const targets = new Set(ids);
      setEdges((eds) =>
        eds.map((e) => {
          if (!targets.has(e.id)) {
            return e;
          }
          const properties = { ...(e.data?.properties ?? {}) };
          if (value) {
            properties[key] = value;
          } else {
            delete properties[key];
          }
          return { ...e, data: { ...e.data, properties } };
        }),
      );
    },
    [setEdges, takeSnapshot],
  );

  const setNodeProperty = useCallback(
    (ids: string[], key: string, value: string) => {
      if (ids.length === 0) {
        return;
      }
      takeSnapshot();
      const targets = new Set(ids);
      setNodes((nds) =>
        nds.map((n) => {
          if (!targets.has(n.id)) {
            return n;
          }
          const properties = { ...(n.data.properties ?? {}) };
          properties[key] = value;
          return { ...n, data: { ...n.data, properties } };
        }),
      );
    },
    [setNodes, takeSnapshot],
  );

  const removeNodeProperty = useCallback(
    (ids: string[], key: string) => {
      if (ids.length === 0) {
        return;
      }
      takeSnapshot();
      const targets = new Set(ids);
      setNodes((nds) =>
        nds.map((n) => {
          if (!targets.has(n.id)) {
            return n;
          }
          const properties = { ...(n.data.properties ?? {}) };
          delete properties[key];
          return { ...n, data: { ...n.data, properties } };
        }),
      );
    },
    [setNodes, takeSnapshot],
  );

  const deleteSelected = useCallback(() => {
    if (selection.nodes.length === 0 && selection.edges.length === 0) {
      return;
    }
    takeSnapshot();
    setNodes((nds) => deleteFromGraph(nds, [], selection.nodes, selection.edges).nodes);
    setEdges((eds) => deleteFromGraph([], eds, selection.nodes, selection.edges).edges);
    setSelection({ nodes: [], edges: [] });
  }, [selection, setNodes, setEdges, takeSnapshot]);

  // React Flow fires onNodesDelete AND onEdgesDelete for a single deletion (removing an element takes
  // its flows with it), so snapshotting in both would cost two undos for one Backspace. onBeforeDelete
  // fires exactly once, before anything is removed, with the connected flows already resolved.
  const beforeDelete = useCallback(
    ({ nodes: doomedNodes, edges: doomedEdges }: { nodes: DfdNode[]; edges: DfdEdge[] }) => {
      if (doomedNodes.length > 0 || doomedEdges.length > 0) {
        takeSnapshot();
      }
      return Promise.resolve(true);
    },
    [takeSnapshot],
  );

  const clearFlags = useCallback(() => {
    if (flaggedIdsRef.current.size === 0 && !analysisActiveRef.current) {
      return;
    }
    setNodes((nds) => nds.map((n) => (n.className ? { ...n, className: undefined } : n)));
    setEdges((eds) => eds.map((e) => (e.className ? { ...e, className: undefined } : e)));
    setFindings([]);
    setThreats([]);
    flaggedIdsRef.current = new Set();
    analysisActiveRef.current = false;
  }, [setNodes, setEdges]);

  // Analyze the model: one request, one rule-set evaluation. The engine returns the STRIDE threat
  // register and the model-hygiene findings projected from the same detection pass, so they share one
  // panel: the register leads, non-threat findings trail. The register carries the model's acceptance
  // triage, so accepted risks come back Accepted.
  const runAnalyze = useCallback(async () => {
    let analysis: Awaited<ReturnType<typeof analyzeModel>>;
    try {
      analysis = await analyzeModel(engine, currentModel);
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Analysis failed.', 'error');
      return;
    }
    setThreats(analysis.threats);
    setFindings(analysis.otherFindings);
    setRuleBundle(analysis.ruleBundle);
    analysisActiveRef.current = true;
    flaggedIdsRef.current = analysis.flaggedIds;
    const applied = applyFlags(nodes, edges, analysis.flaggedIds);
    setNodes(applied.nodes);
    setEdges(applied.edges);
  }, [engine, currentModel, nodes, edges, setNodes, setEdges]);

  // When an analysis is already on screen, changing the rule selection re-runs it so the results
  // reflect the new choice immediately. A ref holds the latest runAnalyze to avoid a dependency loop.
  const runAnalyzeRef = useRef(runAnalyze);
  runAnalyzeRef.current = runAnalyze;
  useEffect(() => {
    if (analysisActiveRef.current) {
      void runAnalyzeRef.current();
    }
  }, [disabledRulePacks, disabledRuleIds]);

  // Apply an author edit (state / priority / mitigation / description / justification) to a threat:
  // record it on the model's overlay (so it persists and round-trips) and reflect it in the panel.
  const editThreat = useCallback((threat: Threat, edit: ThreatEdit) => {
    setThreatTriage((prev) => {
      const existing = prev.find((t) => t.id === threat.id);
      const base: ThreatTriage = existing ?? {
        id: threat.id,
        state: 'Open',
        ...(threat.manual
          ? { manual: true, category: threat.category, title: threat.title, elementIds: threat.elementIds }
          : {}),
      };
      const next: ThreatTriage = { ...base, state: edit.state };
      if (edit.justification !== undefined) {
        next.justification = edit.justification;
      }
      if (edit.priority !== undefined) {
        next.priority = edit.priority;
      }
      if (edit.description !== undefined) {
        next.description = edit.description;
      }
      if (edit.mitigation !== undefined) {
        next.mitigation = edit.mitigation;
      }
      if (edit.title !== undefined) {
        // An empty title clears the override, so the engine falls back to the rule's wording.
        next.title = edit.title === '' ? undefined : edit.title;
      }
      if (edit.category !== undefined) {
        next.category = edit.category;
      }
      return [...prev.filter((t) => t.id !== threat.id), next];
    });
    setThreats((prev) =>
      prev.map((t) =>
        t.id === threat.id
          ? {
              ...t,
              state: edit.state,
              justification: edit.justification ?? t.justification,
              priority: edit.priority ?? t.priority,
              description: edit.description ?? t.description,
              mitigation: edit.mitigation ?? t.mitigation,
              title: edit.title === undefined || edit.title === '' ? t.title : edit.title,
              category: edit.category ?? t.category,
            }
          : t,
      ),
    );
  }, []);

  // Delete a manually-authored threat from the overlay and the panel.
  const deleteThreat = useCallback((threat: Threat) => {
    setThreatTriage((prev) => prev.filter((t) => t.id !== threat.id));
    setThreats((prev) => prev.filter((t) => t.id !== threat.id));
  }, []);

  // Narrows the canvas highlights to one threat / finding, then navigates to its first referenced page.
  const jumpToElements = useCallback(
    (elementIds: string[]) => {
      const focused = new Set(elementIds);
      flaggedIdsRef.current = focused;
      const pageId = elementIds
        .map((id) => elementPageIndex.get(id))
        .find((id): id is string => Boolean(id));
      if (pageId && pageId !== activePageId) {
        switchPage(pageId);
        return;
      }

      const applied = applyFlags(nodes, edges, focused);
      setNodes(applied.nodes);
      setEdges(applied.edges);
    },
    [elementPageIndex, activePageId, switchPage, nodes, edges, setNodes, setEdges],
  );

  // The name of the page a threat's elements live on, when that is not the page in view (for a badge).
  const offPageLabel = useCallback(
    (elementIds: string[]): string | undefined => {
      const pageId = elementIds.map((id) => elementPageIndex.get(id)).find(Boolean);
      if (!pageId || pageId === activePageId) {
        return undefined;
      }
      return pages.find((p) => p.id === pageId)?.name;
    },
    [elementPageIndex, activePageId, pages],
  );

  // Every placed element and flow across all pages, for the canvas search box.
  const searchItems = useMemo<SearchItem[]>(() => {
    const items: SearchItem[] = [];
    for (const page of allPages) {
      for (const node of page.nodes) {
        const label = typeof node.data.label === 'string' ? node.data.label : '';
        items.push({ id: node.id, name: label || '(unnamed)', kind: (node.type as string) ?? 'process', pageId: page.id, pageName: page.name });
      }
      for (const edge of page.edges) {
        const label = typeof edge.label === 'string' && edge.label ? edge.label : 'data flow';
        items.push({ id: edge.id, name: label, kind: 'flow', pageId: page.id, pageName: page.name });
      }
    }
    return items;
  }, [allPages]);

  // The elements and flows a manual threat can be scoped to (reuses the canvas search index).
  const scopeOptions = useMemo<ThreatScopeOption[]>(
    () => searchItems.map((item) => ({ id: item.id, label: `${item.name} · ${item.kind}` })),
    [searchItems],
  );

  // Author a new manual threat: mint a stable manual id, record it on the overlay (so it persists and
  // round-trips), and show it in the panel immediately.
  const addThreat = useCallback(
    (draft: NewThreatDraft) => {
      const id = `manual:${crypto.randomUUID()}`;
      const elementIds = draft.scopeId ? [draft.scopeId] : [];
      const scope = scopeOptions.find((option) => option.id === draft.scopeId);
      const interaction = draft.scopeId ? scope?.label ?? draft.scopeId : 'Model-wide';
      const entry: ThreatTriage = {
        id,
        state: 'Open',
        manual: true,
        category: draft.category,
        title: draft.title,
        elementIds,
      };
      if (draft.priority) {
        entry.priority = draft.priority;
      }
      if (draft.description) {
        entry.description = draft.description;
      }
      if (draft.mitigation) {
        entry.mitigation = draft.mitigation;
      }
      setThreatTriage((prev) => [...prev, entry]);
      setThreats((prev) => [
        ...prev,
        {
          id,
          ruleId: '',
          category: draft.category,
          title: draft.title,
          mitigation: draft.mitigation,
          description: draft.description,
          severity: 'warning',
          priority: draft.priority ?? 'Medium',
          references: [],
          elementIds,
          interaction,
          state: 'Open',
          manual: true,
        },
      ]);
    },
    [scopeOptions],
  );

  // Selects one element or flow, highlights it on the canvas the way a picked finding is highlighted,
  // and frames it in view, switching to its page first when it is off-page.
  const focusOnCanvas = useCallback(
    (id: string, kind: string, pageId: string) => {
      const focus = () => {
        const isFlow = kind === 'flow';
        const edge = isFlow ? allPages.find((p) => p.id === pageId)?.edges.find((e) => e.id === id) : undefined;
        const highlight = highlightForFocus(id, edge ? { source: edge.source, target: edge.target } : undefined);
        flaggedIdsRef.current = highlight;
        setNodes((nds) =>
          nds.map((n) => ({ ...n, selected: !isFlow && n.id === id, className: highlight.has(n.id) ? 'flagged' : undefined })),
        );
        setEdges((eds) =>
          eds.map((e) => ({ ...e, selected: isFlow && e.id === id, className: highlight.has(e.id) ? 'flagged' : undefined })),
        );
        setSelection(isFlow ? { nodes: [], edges: [id] } : { nodes: [id], edges: [] });
        const framed = isFlow
          ? [edge?.source, edge?.target].filter((end): end is string => Boolean(end)).map((end) => ({ id: end }))
          : [{ id }];
        if (framed.length > 0) {
          fitView({ nodes: framed, padding: isFlow ? 0.5 : 0.6, duration: 400, maxZoom: 1.4 });
        }
      };
      if (pageId !== activePageId) {
        switchPage(pageId);
        window.setTimeout(focus, 80);
      } else {
        focus();
      }
    },
    [allPages, activePageId, switchPage, setNodes, setEdges, fitView],
  );

  // Jump to a searched element: switch to its page if needed, select it, and frame it in view.
  const jumpToSearchItem = useCallback(
    (item: SearchItem) => focusOnCanvas(item.id, item.kind, item.pageId),
    [focusOnCanvas],
  );

  // The active page indexed for review: flows in an explicit order, objects grouped by boundary.
  const outline = useMemo(() => buildOutline(nodes, edges, outlineOrder), [nodes, edges, outlineOrder]);
  const outlineFlows = useMemo(
    () => (outlineCrossingOnly ? outline.flows.filter((flow) => flow.crossings.length > 0) : outline.flows),
    [outline, outlineCrossingOnly],
  );

  const chooseOutlineOrder = useCallback((order: OutlineOrder) => {
    setOutlineOrder(order);
    try {
      window.localStorage.setItem(OUTLINE_ORDER_KEY, order);
    } catch {
      /* storage unavailable */
    }
  }, []);

  // Walks the listed flows one at a time, wrapping at either end, so a review can be worked through
  // in order. Stepping from nothing selected starts at the first flow (or the last, going backwards).
  const stepFlow = useCallback(
    (delta: number) => {
      if (outlineFlows.length === 0) {
        return;
      }
      const current = outlineFlows.findIndex((flow) => flow.id === selection.edges[0]);
      const next = current < 0 ? (delta > 0 ? 0 : outlineFlows.length - 1) : (current + delta + outlineFlows.length) % outlineFlows.length;
      focusOnCanvas(outlineFlows[next].id, 'flow', activePageId);
    },
    [outlineFlows, selection.edges, focusOnCanvas, activePageId],
  );
  stepFlowRef.current = stepFlow;

  const exportAs = useCallback(
    async (formatId: string) => {
      const format = formats.find((f) => f.id === formatId);
      try {
        const blob = await serializeModel(formatId);
        downloadBlob(blob, `model${format?.extensions[0] ?? ''}`);
      } catch (err) {
        if (!isAbortError(err)) toast(err instanceof Error ? err.message : String(err), 'error');
      }
    },
    [serializeModel, formats],
  );

  // Download a report from the engine. The threat-model report and the diagram describe the model;
  // the findings artifacts are the analysis evidence a pipeline gates on, and they run against the
  // same effective rules and disabled selections the Analyze button used. The offline client rejects
  // with a hint to start the engine, which surfaces as a toast — the seam Export/Analyze already use.
  const downloadReport = useCallback(
    async (reportId: string) => {
      try {
        const spec = REPORT_DOWNLOADS[reportId];
        if (!spec) {
          return;
        }
        const blob = spec.analysis
          ? await engine.analysisReport(currentModel, spec.format as AnalysisReportFormat)
          : await engine.report(currentModel, spec.format as 'html' | 'svg');
        downloadBlob(blob, spec.fileName);
      } catch (err) {
        toast(err instanceof Error ? err.message : String(err), 'error');
      }
    },
    [engine, currentModel],
  );

  const loadModel = useCallback(
    (model: TmForgeModel) => {
      // Import never changes trust claims. Routing and label offsets are presentation-only; shape
      // sizing and arrangement require an explicit Tidy action and the engine's preservation guard.
      const nextPages = pagesFromModel(model).map((p) => {
        const tidied = tidyLabels(p.nodes, p.edges);
        return { ...p, nodes: tidied.nodes, edges: tidied.edges };
      });
      const nextPacks = model.analysis?.disabledPacks ?? [];
      const nextRuleIds = model.analysis?.disabledRuleIds ?? [];
      const nextExpected = model.analysis?.expectedPacks ?? [];
      const first = nextPages[0];
      setPages(nextPages);
      setActivePageId(first.id);
      setNodes(first.nodes);
      setEdges(first.edges);
      setDisabledRulePacks(nextPacks);
      setDisabledRuleIds(nextRuleIds);
      setExpectedPacks(nextExpected);
      setFindings([]);
      setThreats([]);
      setThreatTriage(model.threats ?? []);
      setMetadata(model.metadata);
      flaggedIdsRef.current = new Set();
      analysisActiveRef.current = false;
      setSelection({ nodes: [], edges: [] });
      reset();
      // A freshly loaded model is the new saved baseline, so it does not read as dirty.
      setSavedJson(
        JSON.stringify(modelFromPages(nextPages, buildAnalysis(nextPacks, nextRuleIds, nextExpected), model.threats, model.metadata)),
      );
      window.setTimeout(() => fitView({ padding: 0.25, maxZoom: 1.15, duration: 300 }), 0);
    },
    [setNodes, setEdges, fitView, reset],
  );

  const readModelFromBytes = useCallback(
    async (bytes: Uint8Array, formatId: string): Promise<TmForgeModel> => {
      // The native tmforge-json is parsed client-side so the per-model analysis selection is
      // preserved; other formats round-trip through the engine (which projects onto tmforge-json).
      if (formatId === 'tmforge-json') {
        return engine.read(new TextDecoder().decode(bytes));
      }
      return engine.readFile(bytes, formatId);
    },
    [engine],
  );

  // Resolves a picked document to a model, and to how the result may be saved. A file that no
  // registered format claims may still be a declarative authoring manifest — the reviewable source
  // `tmforge apply` builds a model from — so it is materialized through the engine instead of being
  // reported as an unreadable model.
  const readDocument = useCallback(
    async (bytes: Uint8Array, name: string, reviewVersion: number): Promise<OpenedDocument> => {
      const ensureNotSuperseded = () => {
        if (reviewVersion !== reviewVersionRef.current) {
          throw new DOMException('Import cancelled because model review was opened.', 'AbortError');
        }
      };
      ensureNotSuperseded();
      const baseline = layoutStateRef.current.workspaceJson;
      const detected = await engine.detect(bytes).catch(() => null);
      ensureNotSuperseded();
      await checkDocument(bytes, detected?.id, detected?.id === 'tmforge-json' ? undefined : 'tmforge-json', 'import');
      ensureNotSuperseded();
      const version = preflightVersion.current;
      const complete = (opened: OpenedDocument) => {
        ensureNotSuperseded();
        if (baseline !== layoutStateRef.current.workspaceJson || version !== preflightVersion.current) {
          throw new DOMException('The workspace changed while the document was read.', 'AbortError');
        }
        return opened;
      };
      if (detected) {
        return complete({
          model: await readModelFromBytes(bytes, detected.id),
          saveFormat: detected.canWrite ? detected.id : 'tmforge-json',
          fileName: detected.canWrite ? name : modelNameForManifest(name),
          bindable: detected.canWrite,
        });
      }

      const text = new TextDecoder().decode(bytes);
      if (looksLikeManifest(text)) {
        return complete({
          model: await engine.applyManifest(text),
          saveFormat: 'tmforge-json',
          fileName: modelNameForManifest(name),
          // A manifest is an authoring source, not a model file. Binding a writable handle to it
          // would let Save overwrite the reviewable source with the model built from it.
          bindable: false,
        });
      }

      // Nothing claimed it and it is not a manifest: fall back to tmforge-json so the reader reports
      // what is actually wrong with the document.
      return complete({
        model: await readModelFromBytes(bytes, 'tmforge-json'),
        saveFormat: 'tmforge-json',
        fileName: name,
        bindable: true,
      });
    },
    [engine, readModelFromBytes, checkDocument],
  );

  const onImportFile = useCallback(
    async (file: File) => {
      const reviewVersion = reviewVersionRef.current;
      try {
        const opened = await readDocument(new Uint8Array(await file.arrayBuffer()), file.name, reviewVersion);
        loadModel(opened.model);
        // A hidden <input> gives no writable handle, so Save falls back to Save As / download.
        fileHandleRef.current = null;
        fileFormatRef.current = opened.saveFormat;
        setFileName(opened.fileName);
      } catch (err) {
        if (!isAbortError(err)) toast(err instanceof Error ? err.message : 'Could not open that file.', 'error');
      }
    },
    [loadModel, readDocument],
  );

  // Prefer the File System Access API so Open retains a writable handle (Save can then overwrite the
  // same file); browsers without it (Firefox/Safari) fall back to the hidden <input>.
  const openFile = useCallback(async () => {
    const reviewVersion = reviewVersionRef.current;
    const picker = window as unknown as FilePickerWindow;
    if (!picker.showOpenFilePicker) {
      fileRef.current?.click();
      return;
    }
    try {
      const [handle] = await picker.showOpenFilePicker();
      const file = await handle.getFile();
      const opened = await readDocument(new Uint8Array(await file.arrayBuffer()), handle.name, reviewVersion);
      loadModel(opened.model);
      fileHandleRef.current = opened.bindable ? handle : null;
      fileFormatRef.current = opened.saveFormat;
      setFileName(opened.fileName);
    } catch (err) {
      if (!isAbortError(err)) {
        toast(err instanceof Error ? err.message : 'Could not open that file.', 'error');
      }
    }
  }, [loadModel, readDocument]);

  const clearAll = useCallback(() => {
    const id = crypto.randomUUID();
    setPages([{ id, name: 'Page 1', nodes: [], edges: [] }]);
    setActivePageId(id);
    setNodes([]);
    setEdges([]);
    setFindings([]);
    setThreats([]);
    setThreatTriage([]);
    setMetadata(undefined);
    flaggedIdsRef.current = new Set();
    analysisActiveRef.current = false;
    setSelection({ nodes: [], edges: [] });
    reset();
  }, [setNodes, setEdges, reset]);

  // Preserve the author's arrangement and validate the cleanup before creating an undoable edit.
  const tidyActivePage = useCallback(async (mode: 'tidy' | 'labels' = 'tidy') => {
    if (nodes.length === 0 || layoutPendingRef.current) {
      return;
    }
    const version = ++layoutRequestRef.current;
    const baseline = layoutStateRef.current.workspaceJson;
    layoutPendingRef.current = true;
    setTidying(true);
    try {
      let positioned = nodes;
      if (mode !== 'labels') {
        const original = toModel(nodes, edges);
        const candidate = tidyGraph(nodes, edges, 'exact');
        const positions = toModel(candidate.nodes, candidate.edges).elements.map((element) => ({
          id: element.id, x: element.x, y: element.y, width: element.width!, height: element.height!,
        }));
        const geometry = await engine.layout(original, positions);
        if (version !== layoutRequestRef.current) return;
        if (layoutStateRef.current.workspaceJson !== baseline) {
          toast('The model changed while tidying. The cleanup was not applied.', 'info');
          return;
        }
        positioned = applyLayoutGeometry(layoutStateRef.current.nodes, geometry);
      }
      const tidied = tidyLabels(positioned, layoutStateRef.current.edges);
      if (tidied.nodes.every((node, index) => node === layoutStateRef.current.nodes[index])
        && tidied.edges.every((edge, index) => edge === layoutStateRef.current.edges[index])) return;
      takeSnapshot();
      setNodes(tidied.nodes);
      setEdges(tidied.edges);
      window.setTimeout(() => fitView({ padding: 0.25, maxZoom: 1.15, duration: 300 }), 0);
    } catch (err) {
      if (version === layoutRequestRef.current) {
        toast(err instanceof Error ? err.message : 'Could not tidy this page. Nothing was changed.', 'error');
      }
    } finally {
      if (version === layoutRequestRef.current) {
        layoutPendingRef.current = false;
        setTidying(false);
      }
    }
  }, [engine, nodes, edges, setNodes, setEdges, takeSnapshot, fitView]);

  const actions = useMemo<DfdActions>(
    () => ({ beginEdit: takeSnapshot, renameNode, renameEdge, setEdgeLabelOffset }),
    [takeSnapshot, renameNode, renameEdge, setEdgeLabelOffset],
  );

  const selectedNodes = useMemo(() => {
    const ids = new Set(selection.nodes);
    return nodes.filter((n) => ids.has(n.id));
  }, [nodes, selection.nodes]);
  const selectedEdges = useMemo(() => {
    const ids = new Set(selection.edges);
    return edges.filter((e) => ids.has(e.id));
  }, [edges, selection.edges]);

  return (
    <DfdActionsContext.Provider value={actions}>
    <div className="app" inert={compareSnapshot !== null}>
      <Toolbar
        engineLabel={engine.label}
        engineOnline={engineOnline}
        demo={import.meta.env.VITE_DEMO === 'true'}
        exportFormats={formats.filter((f) => f.canWrite).map((f) => ({ id: f.id, displayName: f.displayName }))}
        onExport={exportAs}
        onImport={openFile}
        onSave={saveModel}
        onMerge={() => setShowMerge(true)}
        onCompare={() => {
          reviewVersionRef.current += 1;
          preflightVersion.current += 1;
          finishPreflight(false);
          layoutRequestRef.current += 1;
          layoutPendingRef.current = false;
          setTidying(false);
          setCompareSnapshot({ model: JSON.parse(JSON.stringify(currentModel)) as TmForgeModel, name: fileName });
        }}
        dirty={dirty}
        fileName={fileName}
        onAnalyze={runAnalyze}
        onReport={downloadReport}
        onClear={clearAll}
        onFit={() => fitView({ padding: 0.25, maxZoom: 1.15, duration: 300 })}
        onTidy={tidyActivePage}
        tidying={tidying}
        onUndo={undo}
        onRedo={redo}
        canUndo={canUndo}
        canRedo={canRedo}
        theme={theme}
        onToggleTheme={toggleTheme}
      />
      <div className="body">
        <Palette
          stencils={stencils}
          packs={packs}
          recentIds={recentStencilIds}
          favoriteIds={favoriteIds}
          disabledPacks={disabledPacks}
          onTogglePack={togglePack}
          onToggleFavorite={toggleFavorite}
        />
        <div className="canvas">
          <div className="canvas-flow" onDrop={onDrop} onDragOver={onDragOver}>
          <ReactFlow<DfdNode, DfdEdge>
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onReconnect={onReconnect}
            onNodeDragStart={takeSnapshot}
            onBeforeDelete={beforeDelete}
            onSelectionChange={onSelectionChange}
            onPaneClick={clearFlags}
            nodeTypes={nodeTypes}
            edgeTypes={edgeTypes}
            defaultEdgeOptions={defaultEdgeOptions}
            connectionMode={ConnectionMode.Loose}
            deleteKeyCode={compareSnapshot ? null : 'Backspace'}
            elevateNodesOnSelect={false}
            snapToGrid
            snapGrid={[GRID_SIZE, GRID_SIZE]}
            minZoom={0.2}
            maxZoom={2.5}
            colorMode={theme}
            fitView
            fitViewOptions={{ padding: 0.25, maxZoom: 1.15 }}
          >
            <Background variant={BackgroundVariant.Dots} gap={GRID_SIZE} size={1} color={theme === 'dark' ? '#26344c' : '#cbd5e1'} />
            <MiniMap
              pannable
              zoomable
              nodeStrokeWidth={2}
              nodeColor={(n) =>
                n.type === 'boundary' ? 'rgba(100, 116, 139, 0.15)' : KIND_COLOR[(n.type as DfdKind) ?? 'process'] ?? '#94a3b8'
              }
              nodeStrokeColor={(n) => KIND_COLOR[(n.type as DfdKind) ?? 'process'] ?? '#94a3b8'}
              maskColor={theme === 'dark' ? 'rgba(0, 0, 0, 0.4)' : 'rgba(15, 23, 42, 0.06)'}
              bgColor={theme === 'dark' ? '#0f1728' : '#f8fafc'}
            />
            <Controls />
            <Panel position="top-left">
              <div className="outline-panel">
                <CanvasSearch items={searchItems} onJump={jumpToSearchItem} />
                <button
                  type="button"
                  className="val-panel-toggle"
                  onClick={() => setShowOutline((v) => !v)}
                  aria-expanded={showOutline}
                  title="List this page's flows in order and its objects by trust boundary"
                >
                  <span className={`val-caret${showOutline ? ' open' : ''}`} aria-hidden>
                    ▸
                  </span>
                  Outline
                  <span className="val-off-count">{outline.flows.length} flows</span>
                </button>
                {showOutline && (
                  <ModelOutline
                    outline={outline}
                    flows={outlineFlows}
                    order={outlineOrder}
                    onOrderChange={chooseOutlineOrder}
                    crossingOnly={outlineCrossingOnly}
                    onCrossingOnlyChange={setOutlineCrossingOnly}
                    selectedFlowId={selection.edges[0] ?? null}
                    selectedObjectId={selection.nodes[0] ?? null}
                    onSelectFlow={(id) => focusOnCanvas(id, 'flow', activePageId)}
                    onSelectObject={(id) => focusOnCanvas(id, 'object', activePageId)}
                    onStep={stepFlow}
                  />
                )}
              </div>
            </Panel>
            <Panel position="top-right">
                <div className="val-panel">
                  <button
                    type="button"
                    className="val-panel-toggle"
                    onClick={() => setShowRules((v) => !v)}
                    aria-expanded={showRules}
                  >
                    <span className={`val-caret${showRules ? ' open' : ''}`} aria-hidden>
                      ▸
                    </span>
                    Analysis Rules
                    {disabledRulePacks.length + disabledRuleIds.length > 0 ? (
                      <span className="val-off-count">{disabledRulePacks.length + disabledRuleIds.length} off</span>
                    ) : null}
                  </button>
                  {showRules && (
                    <AnalysisSettings
                      rules={rules}
                      packs={rulePacks}
                      disabledPacks={disabledRulePacks}
                      disabledRuleIds={disabledRuleIds}
                      ruleBundle={ruleBundle}
                      expectedPacks={expectedPacks}
                      onTogglePack={toggleRulePack}
                      onToggleRule={toggleRule}
                      onLoadRuleFile={(file) => void loadRuleFile(file)}
                      onClearRuleFile={() => void clearRuleFile()}
                    />
                  )}
                  {(threats.length > 0 || findings.length > 0) && (
                    <ThreatsPanel
                      threats={threats}
                      findings={findings}
                      onSelect={jumpToElements}
                      offPageLabel={offPageLabel}
                      onEditThreat={editThreat}
                      onAddThreat={addThreat}
                      onDeleteThreat={deleteThreat}
                      scopeOptions={scopeOptions}
                    />
                  )}
                </div>
            </Panel>
          </ReactFlow>
          <input
            ref={fileRef}
            type="file"
            accept={buildFileAccept(formats)}
            hidden
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) {
                void onImportFile(file);
              }
              e.target.value = '';
            }}
          />
          {nodes.length === 0 && (
            <div className="canvas-empty">
              <div className="canvas-empty-card">
                <div className="canvas-empty-icon" aria-hidden>
                  <svg
                    width="34"
                    height="34"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth={1.6}
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <rect x="3" y="3" width="7" height="7" rx="1.5" />
                    <rect x="14" y="3" width="7" height="7" rx="1.5" />
                    <rect x="14" y="14" width="7" height="7" rx="1.5" />
                    <path d="M6.5 10v4h8" />
                  </svg>
                </div>
                <h2>Start your threat model</h2>
                <p>Drag a stencil from the left onto the canvas to begin.</p>
                <div className="canvas-empty-actions">
                  <button className="btn btn-primary" onClick={openFile}>
                    Open a file
                  </button>
                </div>
              </div>
            </div>
          )}
          </div>
          <PageTabs
            pages={pages}
            activePageId={activePageId}
            findingPageIds={findingPageIds}
            onSwitch={switchPage}
            onAdd={addPage}
            onRename={renamePage}
            onDelete={deletePage}
            onReorder={reorderPage}
          />
        </div>
        <Inspector
          nodes={selectedNodes}
          edges={selectedEdges}
          stencils={stencils}
          propertySchema={propertySchema}
          onBeginNameEdit={takeSnapshot}
          onRenameNode={renameNode}
          onRenameEdge={renameEdge}
          onSetEdgeProperty={setEdgeProperty}
          onSetNodeProperty={setNodeProperty}
          onRemoveNodeProperty={removeNodeProperty}
          onDelete={deleteSelected}
        />
      </div>
    </div>
    {compareSnapshot && <CompareReview key={`${engine.label}:${ruleCatalogToken}`} engine={engine}
      current={compareSnapshot.model} currentName={compareSnapshot.name} accept={buildFileAccept(formats)} theme={theme}
      onClose={() => setCompareSnapshot(null)} />}
    {showMerge ? (
      <MergeResolveModal
        engine={engine}
        onClose={() => setShowMerge(false)}
        onResolved={(model) => {
          loadModel(model);
          // A merged model has no writable file handle yet, so Save falls back to Save As / download.
          fileHandleRef.current = null;
          fileFormatRef.current = 'tmforge-json';
          setFileName('merged.tm7');
          setShowMerge(false);
          toast('Loaded the merged model into the editor.', 'success');
        }}
      />
    ) : null}
    {preflightReview && <PreflightDialog title={preflightReview.title} result={preflightReview.result} onDecision={finishPreflight} />}
    <Toaster />
    </DfdActionsContext.Provider>
  );
}
