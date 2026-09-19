import type { Node, Edge } from '@xyflow/react';

/** The DFD element kinds this spike supports. Maps to `node.type` in React Flow. */
export type DfdKind = 'process' | 'datastore' | 'external' | 'boundary';

/**
 * Normalizes the engine's structural-classification vocabulary to the Studio kind vocabulary. The
 * engine's classifier (`ModelSnapshot.Classify`, the basis for the diff and three-way merge) labels
 * a data store `store`, whereas the canvas, the `tmforge-json` element `kind`, and {@link DfdKind}
 * call it `datastore`. This bridges that one naming seam so a conflict chip (and anything else that
 * surfaces an engine-classified kind) shows and styles a single, consistent vocabulary rather than
 * relying on a per-value CSS alias. Kinds without a mismatch pass through unchanged, including the
 * edge kind `flow`, which has no {@link DfdKind} of its own.
 */
export function normalizeKind(engineKind: string): string {
  return engineKind === 'store' ? 'datastore' : engineKind;
}

/** Node payload. Intersecting with Record keeps it assignable to React Flow's data constraint. */
export type DfdNodeData = Record<string, unknown> & {
  label: string;
  /** The catalog stencil id this node was created from (for example, azure-sql), when specialized. */
  stencilType?: string;
  properties?: Record<string, string>;
};

/** Edge payload carries the engine custom properties (Protocol, DataType, ...) for a data flow. */
export type DfdEdgeData = Record<string, unknown> & {
  properties?: Record<string, string>;
  /** Label nudge (px, in flow coordinates) so labels on parallel flows can be pulled apart. */
  labelOffset?: { x: number; y: number };
  /** Whether Tidy generated the current offset; manual label drags set this to false. */
  autoLabelOffset?: boolean;
};

export type DfdNode = Node<DfdNodeData, DfdKind>;
export type DfdEdge = Edge<DfdEdgeData>;

/**
 * The canonical, transport-neutral model the editor + API would speak ("tmforge-json").
 * The real .NET engine converts this to/from `.tm7` and friends at the edges.
 */
export interface TmForgeElement {
  id: string;
  kind: DfdKind;
  name: string;
  x: number;
  y: number;
  width?: number;
  height?: number;
  /** Engine custom properties (for example, DataType) applied to the element. */
  properties?: Record<string, string>;
}

export interface TmForgeFlow {
  id: string;
  source: string;
  target: string;
  name: string;
  /** Engine custom properties (for example, Protocol, DataType) applied to the flow. */
  properties?: Record<string, string>;
  /** Persisted label offset (px) so overlapping labels on parallel flows can be separated. */
  labelOffset?: { x: number; y: number };
  /** Persisted source/target ports ('t' | 'r' | 'b' | 'l') that Tidy routes the flow through. */
  sourceHandle?: string;
  targetHandle?: string;
}

/**
 * Per-model analysis selection. It travels with the model (saved in the .tmforge.json file and
 * sent on analyze) so the Studio and the CLI analyze against the same set of rules. An absent or
 * empty selection runs every rule.
 */
export interface TmForgeAnalysis {
  /** Rule pack ids to skip (for example, 'stride-completeness'). */
  disabledPacks?: string[];
  /** Individual rule ids to skip (for example, 'TM1002'). */
  disabledRuleIds?: string[];
  /**
   * Custom rule packs this model expects to be analyzed with, pinned by content fingerprint. The
   * engine reports a missing pack or a changed fingerprint as an error finding, so a model is never
   * quietly analyzed against different rules than the ones it was reviewed with.
   */
  expectedPacks?: TmForgeExpectedRulePack[];
}

/** A custom rule pack a model expects, pinned by id and (optionally) content fingerprint. */
export interface TmForgeExpectedRulePack {
  id: string;
  fingerprint?: string;
}

/**
 * A named page (diagram) within a {@link TmForgeModel}. Each page has its own elements and flows and
 * maps to one drawing surface in the .NET model. Cross-page flows are out of scope: a flow's
 * endpoints are always on the same page.
 */
export interface TmForgeDiagram {
  /** Stable page identifier. */
  id: string;
  /** Page (tab) label, for example 'Context' or 'Payments service'. */
  name: string;
  elements: TmForgeElement[];
  flows: TmForgeFlow[];
}

export interface TmForgeModel {
  schema: 'tmforge-json';
  version: '0.1';
  metadata?: Record<string, string | null | undefined>;
  elements: TmForgeElement[];
  flows: TmForgeFlow[];
  /**
   * Named pages. When present, this is the authoritative multi-page form and the top-level
  * `elements`/`flows` mirror the first page for older single-page readers. An explicitly identified
  * single page also uses this form so imports retain its name and identity.
   */
  diagrams?: TmForgeDiagram[];
  /** Which rule packs or rules to skip when validating this model. */
  analysis?: TmForgeAnalysis;
  /**
   * The threat triage overlay: the persisted lifecycle state (accepted risks + justifications) of
   * generated threats, keyed by threat id. Absent or empty means every generated threat is open.
   */
  threats?: ThreatTriage[];
}

/**
 * One threat's persisted, author-owned state, carried on {@link TmForgeModel.threats}. Rule-derived
 * threats only need an entry once edited (the rest of the register regenerates from the rules); a
 * manually-authored threat sets `manual` and is keyed `manual:{guid}`.
 */
export interface ThreatTriage {
  /** The threat's register id (`{targetGuid:ruleId}`, or `manual:{guid}` for a manual threat). */
  id: string;
  /** The lifecycle state. */
  state: ThreatLifecycleState;
  /** The risk-acceptance justification or state note. */
  justification?: string;
  /** True when this is a manually-authored threat (not projected from a rule). */
  manual?: boolean;
  /** The STRIDE category, for a manual threat. */
  category?: string;
  /** The author-set title (or the manual threat's title). */
  title?: string;
  /** The author-set description. */
  description?: string;
  /** The author-set mitigation. */
  mitigation?: string;
  source?: Record<string, string>;
  /** The author-set priority (`Critical` / `High` / `Medium` / `Low`). */
  priority?: string;
  /** Element ids a manual threat is scoped to (source[, target, flow]); empty means model-wide. */
  elementIds?: string[];
}

/** The persisted lifecycle state of a threat. `Open` / `Accepted` are retained for back-compatibility. */
export type ThreatLifecycleState = 'Open' | 'NeedsInvestigation' | 'Mitigated' | 'Accepted';
