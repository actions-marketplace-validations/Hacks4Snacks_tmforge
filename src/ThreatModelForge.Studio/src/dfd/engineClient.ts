import createClient, { type Client } from 'openapi-fetch';
import { FALLBACK_PACKS, FALLBACK_STENCILS } from './stencils';
import { normalizeKind } from './types';
import type { DfdKind, ThreatLifecycleState, ThreatTriage, TmForgeModel } from './types';
import type { components, paths } from './engine/schema';

export type Severity = 'info' | 'warning' | 'error';

export interface Finding {
  id: string;
  severity: Severity;
  /** The originating engine rule id (e.g. TM-xxxx), when the finding came from the real engine. */
  ruleId?: string;
  message: string;
  /** ids of elements/flows this finding refers to, so the UI can highlight them. */
  elementIds: string[];
}

/**
 * A generated threat: the persisted-register projection of a threat-bearing finding. Same detection
 * as {@link Finding} (the rules), enriched with category metadata and external references.
 */
export interface Threat {
  /** Deterministic register key (`{targetGuid:ruleId}`). */
  id: string;
  /** The rule that detected the threat (for example `TM1023`). */
  ruleId: string;
  /** Legacy STRIDE token, or the generalized display name when no STRIDE mapping exists. */
  category: string;
  /** Stable effective category id (`S` for built-ins, `pack-id/source-id` for versioned packs). */
  categoryId?: string;
  /** Human-readable category display name. */
  categoryName?: string;
  /** The corresponding STRIDE category, when one exists. */
  stride?: string;
  /** The threat statement (the finding text). */
  title: string;
  /** The suggested mitigation (the rule's help text). */
  mitigation?: string;
  severity: Severity;
  /** The coarse priority hint (`Critical` / `High` / `Medium` / `Low`). */
  priority?: string;
  /** External catalog references (`CWE-###`, `CAPEC-###`, ATT&CK technique ids). */
  references: string[];
  /** ids of the elements/flows this threat refers to, so the UI can highlight them. */
  elementIds: string[];
  /** Human-readable scope (`source -> target` for a flow, else the element name). */
  interaction: string;
  /** The lifecycle state (`Open`, `NeedsInvestigation`, `Mitigated`, or `Accepted`). */
  state: ThreatLifecycleState;
  /** The risk-acceptance justification or state note, when set. */
  justification?: string;
  /** The author-set description, when set. */
  description?: string;
  source?: Record<string, string>;
  /** True when the threat was authored by hand (not projected from a rule). */
  manual?: boolean;
}

/** A single point a three-way merge could not reconcile automatically (the merge kept `ours`). */
export interface MergeConflict {
  /** The stable id of the element the conflict concerns. */
  elementId: string;
  /** The element kind, normalized to the Studio vocabulary ('process' | 'datastore' | 'external' | 'boundary' | 'flow'). */
  elementKind: string;
  /** The element's display name. */
  name: string;
  /** The diagram (page) the element belongs to. */
  diagramName: string;
  /** 'Property' (same attribute, different values) | 'DeleteModify' | 'AddAdd' | 'DanglingReference'. */
  kind: string;
  /** The attribute key in conflict (e.g. 'name', 'Protocol', 'source', 'target'); empty for a structural conflict. */
  property: string;
  /** The ancestor value, when applicable. */
  base?: string;
  /** The `ours` value the merge kept. */
  ours?: string;
  /** The `theirs` value the merge dropped. */
  theirs?: string;
}

/** The result of a three-way merge: the merged model plus any conflicts (all resolved to `ours`). */
export interface MergeResult {
  merged: TmForgeModel;
  conflicts: MergeConflict[];
}

/** An engine-validated rectangle update. All semantic and author-owned data remains client-owned. */
export interface LayoutElement {
  id: string;
  x: number;
  y: number;
  width: number;
  height: number;
}

/** A file format the engine can read and/or write. */
export interface FormatInfo {
  id: string;
  displayName: string;
  extensions: string[];
  canRead: boolean;
  canWrite: boolean;
}

/** An authoring stencil: a categorized specialization of one of the four DFD primitives. */
export interface StencilInfo {
  id: string;
  /** The underlying DFD primitive this stencil maps to (drives analysis + rendering). */
  base: DfdKind;
  label: string;
  category: string;
  /** The stencil pack this stencil ships in (for example, 'azure'). */
  pack: string;
  blurb: string;
  /** Free-form search tags and aliases. */
  tags: string[];
  /** Preset custom properties applied when the stencil is placed. */
  defaults: Record<string, string>;
}

/** A stencil pack: a named, togglable group of related stencils shown in the palette. */
export interface PackInfo {
  id: string;
  name: string;
  /** How many stencils the pack contributes. */
  count: number;
}

/** An analysis rule offered by the engine (surfaced in the Analysis Rules settings UI). */
export interface RuleInfo {
  id: string;
  /** The rule pack this rule belongs to (for example, 'security-properties'). */
  pack: string;
  severity: Severity;
  /** What the rule evaluates and why (the rule's full description). */
  description: string;
  /** How to clear a finding from this rule (shown in the in-app help). */
  helpText: string;
  helpUri?: string;
}

/** A rule pack: a named, selectable group of related analysis rules. */
export interface RulePackInfo {
  id: string;
  name: string;
  /** How many rules the pack contributes. */
  count: number;
}

/** A custom rule pack document handed to the engine as content (never a filesystem path). */
export interface RuleSource {
  /** The logical origin shown in diagnostics, for example the picked file's name. */
  name: string;
  /** The rule pack JSON. */
  json: string;
}

/** The identity of a custom rule pack that actually contributed rules to the effective rule set. */
export interface RulePackIdentity {
  id: string;
  name: string;
  version?: string;
  /** The content fingerprint; pin this in the model to detect rule drift. */
  fingerprint: string;
  dialect: string;
  ruleCount: number;
}

/** What custom rule content the engine loaded, and what it complained about while loading it. */
export interface RuleBundle {
  rulePacks: RulePackIdentity[];
  diagnostics: string[];
}

/**
 * The result of one analysis action: the findings and the threats projected from a single rule-set
 * evaluation, plus the evidence of which rule content produced them.
 */
export interface AnalysisResult {
  findings: Finding[];
  threats: Threat[];
  rulePacks: RulePackIdentity[];
  diagnostics: string[];
}

/** The analysis (findings) report formats the engine renders. */
export type AnalysisReportFormat = 'sarif' | 'html' | 'json';

/** A typed element-property definition: drives typed Inspector controls and canonical values. */
export interface PropertyDescriptorInfo {
  /** The DFD primitive this property applies to ('process' | 'datastore' | 'external' | 'flow'). */
  appliesTo: string;
  /** The property key (custom-attribute name), for example 'AuthenticationScheme'. */
  name: string;
  /** The value kind that drives the control: 'enum' | 'bool' | 'string'. */
  kind: string;
  /** Allowed values for an enum/bool property; empty for free-form string. */
  values: string[];
  /** The default value applied when the property is first added. */
  default: string;
}

/**
 * The seam. The UI depends only on this interface — never on how the engine is reached.
 *
 * Implementations that ship here:
 *   - `HttpEngineClient` - the real .NET engine over the `/v1` API.
 *   - `WasmEngineClient` - the same engine compiled to WebAssembly, in-browser, no backend.
 *   - `OfflineEngineClient` - honest fallback when neither is reachable: client-side authoring only.
 *
 * `read`/`write` just (de)serialize the canonical `tmforge-json` client-side — no engine needed —
 * so all clients share them. Everything else (`analyze`, `getFormats`, `detect`, `readFile`,
 * `convert`, `report`, `exportTm7`) is a coarse-grained engine call.
 */
export interface DocumentDiagnostic {
  code: string;
  severity: 'error' | 'warning' | 'info';
  path: string;
  message: string;
}

export interface PreflightResult {
  success: boolean;
  format?: string;
  targetFormat?: string;
  diagnostics: DocumentDiagnostic[];
}

export interface ModelReviewChange {
  id: string;
  section: 'structure' | 'crossings' | 'findings';
  kind: 'added' | 'removed' | 'modified' | 'introduced' | 'resolved' | 'reclassified';
  title: string;
  elementKind?: string;
  baselineElementIds: string[];
  proposedElementIds: string[];
  baselinePageId?: string;
  proposedPageId?: string;
  baselinePageName?: string;
  proposedPageName?: string;
  properties: { key: string; from?: string; to?: string }[];
  ruleId?: string;
  severity?: string;
}

export interface ModelCompareResult {
  success: boolean;
  findingsAvailable: boolean;
  unchangedFindings: number;
  changes: ModelReviewChange[];
  warnings: string[];
  diagnostics: DocumentDiagnostic[];
}

export interface IEngineClient {
  readonly label: string;
  write(model: TmForgeModel): Promise<string>;
  read(text: string): Promise<TmForgeModel>;
  analyze(model: TmForgeModel): Promise<Finding[]>;
  /** Projects the model's threat-bearing findings into the categorized threat register (the same detection as analyze). */
  generateThreats(model: TmForgeModel): Promise<Threat[]>;
  /**
   * Runs one analysis action: the engine evaluates the rule set once and returns both the findings
   * and the threats. Prefer this over calling `analyze` and `generateThreats` together, which makes
   * the engine evaluate every enabled rule twice for a single user action.
   */
  runAnalysis(model: TmForgeModel): Promise<AnalysisResult>;
  exportTm7(model: TmForgeModel): Promise<Blob>;
  /**
   * Selects the custom rule packs this engine runs, and reports what actually loaded. The selection
   * persists for the session, so catalogs, analysis, threat generation, reports, and exports all use
   * one effective bundle. Hosts that own their rule configuration (the `/v1` API) reject the call
   * rather than pretend a browser-side selection took effect.
   */
  setRules(sources: RuleSource[]): Promise<RuleBundle>;
  /** Describes the custom rule packs this engine currently runs, and any load diagnostics. */
  getRuleBundle(): Promise<RuleBundle>;
  /** Lists the engine's registered file formats and their capabilities. */
  getFormats(): Promise<FormatInfo[]>;
  /** Lists the authoring stencil catalog offered to the palette. */
  getStencils(): Promise<StencilInfo[]>;
  /** Lists the stencil packs offered to the palette (for show/hide toggles). */
  getStencilPacks(): Promise<PackInfo[]>;
  /** Lists the analysis rules offered by the engine (for the Analysis Rules settings UI). */
  getRules(): Promise<RuleInfo[]>;
  /** Lists the rule packs offered by the engine (for per-model analysis-rule toggles). */
  getRulePacks(): Promise<RulePackInfo[]>;
  /** Lists the typed element-property schema (drives typed Inspector controls + canonical values). */
  getPropertySchema(): Promise<PropertyDescriptorInfo[]>;
  /** Detects the format of raw document bytes, or null when none matches. */
  detect(bytes: Uint8Array): Promise<FormatInfo | null>;
  preflight(bytes: Uint8Array, formatId?: string, targetFormat?: string): Promise<PreflightResult>;
  /** Reads a document in any registered format into the canonical tmforge-json model. */
  readFile(bytes: Uint8Array, formatId?: string): Promise<TmForgeModel>;
  /**
   * Materializes a declarative authoring manifest into a model. A manifest is a threat model's
   * reviewable source rather than a model document, so it has no registered format and cannot go
   * through `readFile`; the engine builds it exactly as the CLI's `apply` verb does.
   */
  applyManifest(manifestJson: string): Promise<TmForgeModel>;
  /** Serializes the model to another registered format (for example tm7, drawio, vsdx). */
  convert(model: TmForgeModel, toFormatId: string): Promise<Blob>;
  /** Renders an HTML or SVG report for the model. */
  report(model: TmForgeModel, format: 'html' | 'svg'): Promise<Blob>;
  /**
   * Renders an analysis (findings) report: the SARIF, HTML, or JSON artifacts a pipeline gates on.
   * Distinct from `report`, which renders the threat-model document a reviewer reads.
   */
  analysisReport(model: TmForgeModel, format: AnalysisReportFormat): Promise<Blob>;
  /**
   * Merges two edited models, matched by element id. With a `base` (common ancestor) it is a
   * three-way merge so non-overlapping edits combine automatically; pass `null` when the ancestor
   * is unavailable for a two-way merge, where any overlapping difference is reported as a conflict.
   */
  merge(base: TmForgeModel | null, ours: TmForgeModel, theirs: TmForgeModel): Promise<MergeResult>;
  compare(baseline: TmForgeModel, proposed: TmForgeModel): Promise<ModelCompareResult>;
  /** Validates proposed Tidy geometry without rearranging it or changing trust claims. */
  layout(model: TmForgeModel, positions: LayoutElement[]): Promise<LayoutElement[]>;
}

/**
 * Origin of the engine API. In production the SPA is served by the API itself, so this is the same
 * origin (empty string -> relative `/v1/...`). In `vite dev` the SPA runs on :5199 while the API
 * runs on :5205, so target that explicitly. The generated OpenAPI paths already carry the `/v1`
 * prefix.
 */
export const ENGINE_BASE_URL = import.meta.env.DEV ? 'http://localhost:5205' : '';

async function writeJson(model: TmForgeModel): Promise<string> {
  return JSON.stringify(model, null, 2);
}

async function readJson(text: string): Promise<TmForgeModel> {
  const parsed = JSON.parse(text) as TmForgeModel;
  if (parsed?.schema !== 'tmforge-json') {
    throw new Error('Not a tmforge-json document.');
  }
  return parsed;
}

/** The schema a declarative authoring manifest declares. */
export const MANIFEST_SCHEMA = 'tmforge-manifest';

/**
 * Reports whether document text positively declares itself a tmforge authoring manifest — the
 * reviewable source `tmforge apply` builds a model from. A manifest is not one of the engine's
 * registered model formats, so `detect` cannot claim it and reading it as a model fails; recognizing
 * it here lets the caller route it to `applyManifest` instead of reporting an unreadable file.
 *
 * Recognition requires the explicit `schema`, mirroring the engine's own recognizer: every field of
 * a manifest is optional, so accepting an absent envelope would claim any JSON document.
 */
export function looksLikeManifest(text: string): boolean {
  try {
    return (JSON.parse(text) as { schema?: unknown } | null)?.schema === MANIFEST_SCHEMA;
  } catch {
    return false;
  }
}

/**
 * Normalizes an engine manifest-apply result onto the UI model, turning a refused manifest into a
 * thrown error carrying the engine's own explanation (which names the offending alias or property).
 */
function modelFromApplyResult(dto: components['schemas']['ApplyResultDto'] | undefined): TmForgeModel {
  if (!dto?.success || !dto.model) {
    throw new Error(dto?.error ?? 'The manifest could not be applied.');
  }
  return toModel(dto.model);
}

function toPreflight(dto: components['schemas']['PreflightResultDto'] | undefined): PreflightResult {
  if (typeof dto?.success !== 'boolean' || !Array.isArray(dto.diagnostics)) {
    throw new Error('The engine did not return a complete preflight result. Nothing was changed.');
  }
  const diagnostics = dto.diagnostics.map((item) => {
    if (!item.code || !item.path || !item.message || !['error', 'warning', 'info'].includes(item.severity ?? '')) {
      throw new Error('The engine returned an incomplete preflight diagnostic. Nothing was changed.');
    }
    return { code: item.code, path: item.path, message: item.message, severity: item.severity as DocumentDiagnostic['severity'] };
  });
  return {
    success: dto.success && !diagnostics.some((item) => item.severity === 'error'),
    format: dto.format ?? undefined,
    targetFormat: dto.targetFormat ?? undefined,
    diagnostics,
  };
}

function toComparison(dto: components['schemas']['ModelCompareResultDto'] | undefined): ModelCompareResult {
  if (typeof dto?.success !== 'boolean' || typeof dto.findingsAvailable !== 'boolean'
    || !Number.isInteger(dto.unchangedFindings) || Number(dto.unchangedFindings) < 0
    || !Array.isArray(dto.changes) || !Array.isArray(dto.warnings) || !dto.warnings.every((warning) => typeof warning === 'string')
    || !Array.isArray(dto.diagnostics)) {
    throw new Error('The engine did not return a complete comparison. Update the engine and retry.');
  }
  const diagnostics = toPreflight({ success: true, diagnostics: dto.diagnostics }).diagnostics;
  const seen = new Set<string>();
  const changes = dto.changes.map((change): ModelReviewChange => {
    if (!change.id || seen.has(change.id) || typeof change.title !== 'string'
      || !['structure', 'crossings', 'findings'].includes(change.section ?? '')
      || !['added', 'removed', 'modified', 'introduced', 'resolved', 'reclassified'].includes(change.kind ?? '')
      || !Array.isArray(change.baselineElementIds) || !change.baselineElementIds.every((id) => typeof id === 'string' && id.length > 0)
      || !Array.isArray(change.proposedElementIds) || !change.proposedElementIds.every((id) => typeof id === 'string' && id.length > 0)
      || !Array.isArray(change.properties) || !change.properties.every((property) => typeof property.key === 'string'
        && (property.from == null || typeof property.from === 'string') && (property.to == null || typeof property.to === 'string'))) {
      throw new Error('The engine returned an incomplete comparison change.');
    }
    seen.add(change.id);
    return {
      id: change.id,
      section: change.section as ModelReviewChange['section'],
      kind: change.kind as ModelReviewChange['kind'],
      title: change.title,
      elementKind: change.elementKind ? normalizeKind(change.elementKind) : undefined,
      baselineElementIds: change.baselineElementIds,
      proposedElementIds: change.proposedElementIds,
      baselinePageId: change.baselinePageId ?? undefined,
      proposedPageId: change.proposedPageId ?? undefined,
      baselinePageName: change.baselinePageName ?? undefined,
      proposedPageName: change.proposedPageName ?? undefined,
      ruleId: change.ruleId ?? undefined,
      severity: change.severity ?? undefined,
      properties: change.properties.map((property) => ({ key: property.key ?? '', from: property.from ?? undefined, to: property.to ?? undefined })),
    };
  });
  if ((!dto.success && (changes.length > 0 || dto.findingsAvailable)) || (!dto.findingsAvailable && (dto.unchangedFindings !== 0 || changes.some((change) => change.section === 'findings')))) {
    throw new Error('The engine returned changes for an unavailable comparison.');
  }
  return {
    success: dto.success,
    findingsAvailable: dto.findingsAvailable,
    unchangedFindings: Number(dto.unchangedFindings),
    changes,
    warnings: dto.warnings,
    diagnostics,
  };
}

/** A refused layout never falls back to an unvalidated client-side arrangement. */
function layoutElements(dto: components['schemas']['LayoutResultDto'] | undefined, positions: LayoutElement[]): LayoutElement[] {
  if (!dto?.success || !dto.elements) {
    throw new Error(dto?.error ?? 'The engine did not return a validated arrangement.');
  }
  const elements = dto.elements.map((element) => {
    if (!element.id || ![element.x, element.y, element.width, element.height].every((value) => typeof value === 'number' && Number.isSafeInteger(value))
      || Number(element.width) < 20 || Number(element.height) < 20) {
      throw new Error('The engine returned incomplete layout geometry. Nothing was changed.');
    }
    return { id: element.id, x: Number(element.x), y: Number(element.y), width: Number(element.width), height: Number(element.height) };
  });
  const proposed = new Map(positions.map((element) => [element.id, element]));
  if (elements.length !== positions.length || new Set(elements.map((element) => element.id)).size !== elements.length
    || elements.some((element) => {
      const expected = proposed.get(element.id);
      return !expected || element.x !== expected.x || element.y !== expected.y
        || element.width !== expected.width || element.height !== expected.height;
    })) {
    throw new Error('The engine did not preserve the proposed Tidy layout. Update the engine; nothing was changed.');
  }
  return elements;
}

/** Encodes bytes as base64 for the engine's read/detect payloads. */
function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/** Decodes a base64 string (the WASM boundary's byte encoding) into a typed Blob for download. */
function blobFromBase64(base64: string, type: string): Blob {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new Blob([bytes], { type });
}

/** The download content-type for a converted document (mirrors the /v1 convert endpoint). */
function mimeForFormat(formatId: string): string {
  switch (formatId) {
    case 'vsdx':
      return 'application/vnd.ms-visio.drawing';
    case 'tmforge-json':
      return 'application/json';
    default:
      return 'application/xml';
  }
}

/** The download content-type for an analysis (findings) report. */
function analysisReportMime(format: AnalysisReportFormat): string {
  switch (format) {
    case 'sarif':
      return 'application/sarif+json';
    case 'json':
      return 'application/json';
    default:
      return 'text/html';
  }
}

/** Normalizes a generated FormatDto (all fields optional) onto the UI's FormatInfo. */
function toFormatInfo(dto: components['schemas']['FormatDto']): FormatInfo {
  return {
    id: dto.id ?? '',
    displayName: dto.displayName ?? '',
    extensions: dto.extensions ?? [],
    canRead: dto.canRead ?? false,
    canWrite: dto.canWrite ?? false,
  };
}

/** Normalizes a generated StencilDto (all fields optional) onto the UI's StencilInfo. */
function toStencilInfo(dto: components['schemas']['StencilDto']): StencilInfo {
  return {
    id: dto.id ?? '',
    base: (dto.base ?? 'process') as DfdKind,
    label: dto.label ?? '',
    category: dto.category ?? 'Other',
    pack: dto.pack ?? 'generic',
    blurb: dto.blurb ?? '',
    tags: dto.tags ?? [],
    defaults: dto.defaults ?? {},
  };
}

/** Normalizes a generated PackDto (all fields optional) onto the UI's PackInfo. */
function toPackInfo(dto: components['schemas']['PackDto']): PackInfo {
  return {
    id: dto.id ?? '',
    name: dto.name ?? '',
    count: Number(dto.count ?? 0),
  };
}

/** Normalizes a generated RuleDto (all fields optional) onto the UI's RuleInfo. */
function toRuleInfo(dto: components['schemas']['RuleDto']): RuleInfo {
  return {
    id: dto.id ?? '',
    pack: dto.pack ?? '',
    severity: (dto.severity ?? 'info') as Severity,
    description: dto.description ?? '',
    helpText: dto.helpText ?? '',
    helpUri: dto.helpUri ?? undefined,
  };
}

/** Normalizes a generated RulePackDto (all fields optional) onto the UI's RulePackInfo. */
function toRulePackInfo(dto: components['schemas']['RulePackDto']): RulePackInfo {
  return {
    id: dto.id ?? '',
    name: dto.name ?? '',
    count: Number(dto.count ?? 0),
  };
}

/**
 * Normalizes the engine's rule-bundle evidence onto the UI's RuleBundle. Both transports return the
 * same shape (the API serializes it, the WASM engine hands back the same JSON), so one normalizer
 * keeps them honest.
 */
function toRuleBundle(dto: components['schemas']['RuleBundleDto'] | undefined): RuleBundle {
  return {
    rulePacks: (dto?.rulePacks ?? []).map((pack) => ({
      id: pack.id ?? '',
      name: pack.name ?? '',
      version: pack.version ?? undefined,
      fingerprint: pack.fingerprint ?? '',
      dialect: pack.dialect ?? '',
      ruleCount: Number(pack.ruleCount ?? 0),
    })),
    diagnostics: dto?.diagnostics ?? [],
  };
}

/** Normalizes one analysis action's result (findings, threats, and rule evidence) onto the UI shape. */
function toAnalysisResult(dto: components['schemas']['AnalysisResultDto'] | undefined): AnalysisResult {
  const bundle = toRuleBundle(dto);
  return {
    findings: (dto?.findings ?? []).map(toFinding),
    threats: (dto?.threats ?? []).map(toThreat),
    rulePacks: bundle.rulePacks,
    diagnostics: bundle.diagnostics,
  };
}

/** Normalizes a generated PropertyDescriptor (all fields optional) onto the UI's PropertyDescriptorInfo. */
function toPropertyDescriptor(dto: components['schemas']['PropertyDescriptor']): PropertyDescriptorInfo {
  return {
    appliesTo: dto.appliesTo ?? '',
    name: dto.name ?? '',
    kind: dto.kind ?? 'string',
    values: dto.values ?? [],
    default: dto.default ?? '',
  };
}

/** Normalizes a generated TmForgeModelDto (all fields optional/nullable) onto the UI model. */
export function toModel(dto: components['schemas']['TmForgeModelDto']): TmForgeModel {
  const elements = (items: components['schemas']['TmForgeModelDto']['elements']) => (items ?? []).map((e) => ({
    id: e.id ?? '',
    kind: (e.kind ?? 'process') as DfdKind,
    name: e.name ?? '',
    x: Number(e.x ?? 0),
    y: Number(e.y ?? 0),
    width: e.width == null ? undefined : Number(e.width),
    height: e.height == null ? undefined : Number(e.height),
    properties: e.properties ?? {},
  }));
  const flows = (items: components['schemas']['TmForgeModelDto']['flows']) => (items ?? []).map((f) => ({
    id: f.id ?? '',
    source: f.source ?? '',
    target: f.target ?? '',
    name: f.name ?? '',
    properties: f.properties ?? {},
  }));
  return {
    schema: 'tmforge-json',
    version: '0.1',
    metadata: dto.metadata ?? undefined,
    elements: elements(dto.elements),
    flows: flows(dto.flows),
    diagrams: dto.diagrams?.map((page) => ({
      id: page.id ?? '',
      name: page.name ?? '',
      elements: elements(page.elements),
      flows: flows(page.flows),
    })),
    analysis: dto.analysis
      ? {
          disabledPacks: dto.analysis.disabledPacks ?? undefined,
          disabledRuleIds: dto.analysis.disabledRuleIds ?? undefined,
          expectedPacks: dto.analysis.expectedPacks?.map((pack) => ({ id: pack.id ?? '', fingerprint: pack.fingerprint ?? '' })),
        }
      : undefined,
    threats: dto.threats?.map(toThreatTriage),
  };
}

/** Normalizes one durable threat-overlay entry returned with an engine-read model. */
function toThreatTriage(dto: components['schemas']['ThreatStateDto']): ThreatTriage {
  return {
    id: dto.id ?? '',
    state: normalizeThreatState(dto.state),
    justification: dto.justification ?? undefined,
    manual: dto.manual ?? undefined,
    category: dto.category ?? undefined,
    title: dto.title ?? undefined,
    description: dto.description ?? undefined,
    mitigation: dto.mitigation ?? undefined,
    source: dto.source ?? undefined,
    priority: dto.priority ?? undefined,
    elementIds: dto.elementIds ?? undefined,
  };
}

/** Normalizes a generated MergeResultDto (all fields optional/nullable) onto the UI's MergeResult. */
function toMergeResult(dto: components['schemas']['MergeResultDto']): MergeResult {
  return {
    merged: toModel(dto.merged ?? ({} as components['schemas']['TmForgeModelDto'])),
    conflicts: (dto.conflicts ?? []).map((c) => ({
      elementId: c.elementId ?? '',
      elementKind: normalizeKind(c.elementKind ?? ''),
      name: c.name ?? '',
      diagramName: c.diagramName ?? '',
      kind: c.kind ?? '',
      property: c.property ?? '',
      base: c.base ?? undefined,
      ours: c.ours ?? undefined,
      theirs: c.theirs ?? undefined,
    })),
  };
}

/** Normalizes a generated FindingDto (all fields optional/nullable) onto the UI's Finding. */
function toFinding(dto: components['schemas']['FindingDto']): Finding {
  return {
    id: dto.id ?? '',
    severity: (dto.severity ?? 'info') as Severity,
    ruleId: dto.ruleId ?? undefined,
    message: dto.message ?? '',
    elementIds: dto.elementIds ?? [],
  };
}

/** Normalizes a generated ThreatDto (all fields optional) onto the UI's Threat. */
function toThreat(dto: components['schemas']['ThreatDto']): Threat {
  return {
    id: dto.id ?? '',
    ruleId: dto.ruleId ?? '',
    category: dto.category ?? '',
    categoryId: dto.categoryId ?? undefined,
    categoryName: dto.categoryName ?? undefined,
    stride: dto.stride ?? undefined,
    title: dto.title ?? '',
    mitigation: dto.mitigation ?? undefined,
    severity: (dto.severity ?? 'warning') as Severity,
    priority: dto.priority ?? undefined,
    references: dto.references ?? [],
    elementIds: dto.elementIds ?? [],
    interaction: dto.interaction ?? '',
    state: normalizeThreatState(dto.state),
    justification: dto.justification ?? undefined,
    description: dto.description ?? undefined,
    source: dto.source ?? undefined,
    manual: dto.manual ?? false,
  };
}

/** Coerces the wire state string onto the UI's lifecycle union (defaulting to `Open`). */
function normalizeThreatState(state: string | undefined): ThreatLifecycleState {
  switch (state) {
    case 'NeedsInvestigation':
    case 'Mitigated':
    case 'Accepted':
      return state;
    default:
      return 'Open';
  }
}

class OfflineEngineClient implements IEngineClient {
  public readonly label = 'offline (engine unavailable)';

  public write(model: TmForgeModel): Promise<string> {
    return writeJson(model);
  }

  public read(text: string): Promise<TmForgeModel> {
    return readJson(text);
  }

  public analyze(): Promise<Finding[]> {
    // No fake analysis: when neither the /v1 engine nor the in-browser WASM engine is reachable,
    // fail honestly rather than returning heuristics that disagree with the real rule set.
    return Promise.reject(
      new Error(
        'The analysis engine has not loaded. WebAssembly may be disabled or blocked (for example by a ' +
          'Content-Security-Policy), or is still downloading — reload the page, or use the hosted app.',
      ),
    );
  }

  public generateThreats(): Promise<Threat[]> {
    // Same honesty as analyze: without the engine there is no rule set to project threats from.
    return Promise.reject(
      new Error(
        'The analysis engine has not loaded. WebAssembly may be disabled or blocked (for example by a ' +
          'Content-Security-Policy), or is still downloading — reload the page, or use the hosted app.',
      ),
    );
  }

  public runAnalysis(): Promise<AnalysisResult> {
    return Promise.reject(
      new Error(
        'The analysis engine has not loaded. WebAssembly may be disabled or blocked (for example by a ' +
          'Content-Security-Policy), or is still downloading — reload the page, or use the hosted app.',
      ),
    );
  }

  public exportTm7(): Promise<Blob> {
    return Promise.reject(
      new Error('Real .tm7 export requires the .NET engine. Start the API (see the spike README), then reload.'),
    );
  }

  public setRules(): Promise<RuleBundle> {
    // Offline: there is no rule engine to load a pack into, so say so rather than accept it silently.
    return Promise.reject(
      new Error('Custom rule packs require the analysis engine. Reload the page, or use the hosted app.'),
    );
  }

  public async getRuleBundle(): Promise<RuleBundle> {
    return { rulePacks: [], diagnostics: [] };
  }

  public async getFormats(): Promise<FormatInfo[]> {
    // Offline: only the canonical client-side format is available.
    return [
      {
        id: 'tmforge-json',
        displayName: 'Threat Model Forge JSON (.tmforge.json)',
        extensions: ['.tmforge.json'],
        canRead: true,
        canWrite: true,
      },
    ];
  }

  public async getStencils(): Promise<StencilInfo[]> {
    // Offline: fall back to the generic DFD primitives.
    return FALLBACK_STENCILS;
  }

  public async getStencilPacks(): Promise<PackInfo[]> {
    // Offline: only the generic pack is available.
    return FALLBACK_PACKS;
  }

  public async getRules(): Promise<RuleInfo[]> {
    // Offline: the stub uses canned heuristics, not the real engine rule catalog.
    return [];
  }

  public async getRulePacks(): Promise<RulePackInfo[]> {
    // Offline: no rule packs to configure without the engine.
    return [];
  }

  public async getPropertySchema(): Promise<PropertyDescriptorInfo[]> {
    // Offline: without the engine there is no typed schema; the Inspector falls back to free text.
    return [];
  }

  public async detect(bytes: Uint8Array): Promise<FormatInfo | null> {
    const text = new TextDecoder().decode(bytes);
    return text.includes('tmforge-json') ? (await this.getFormats())[0] : null;
  }

  public readFile(bytes: Uint8Array): Promise<TmForgeModel> {
    // Offline: only tmforge-json can be parsed client-side.
    return readJson(new TextDecoder().decode(bytes));
  }

  public preflight(): Promise<PreflightResult> {
    return Promise.reject(new Error('Document preflight requires the .NET engine. Wait for the engine to load or connect to the API. Nothing was changed.'));
  }

  public applyManifest(): Promise<TmForgeModel> {
    // Building a manifest resolves aliases, derives stable ids, places elements inside their
    // boundaries, and validates every property against the schema. Re-implementing that here would
    // be a second engine that disagrees with the real one, so refuse instead.
    return Promise.reject(
      new Error('Opening an authoring manifest requires the .NET engine. Start the API (or use the hosted app), then reload.'),
    );
  }

  public convert(model: TmForgeModel, toFormatId: string): Promise<Blob> {
    if (toFormatId === 'tmforge-json') {
      return writeJson(model).then((text) => new Blob([text], { type: 'application/json' }));
    }

    return Promise.reject(
      new Error(`Converting to '${toFormatId}' requires the .NET engine. Start the API, then reload.`),
    );
  }

  public report(): Promise<Blob> {
    return Promise.reject(
      new Error('Reports require the .NET engine. Start the API (see the spike README), then reload.'),
    );
  }

  public analysisReport(): Promise<Blob> {
    return Promise.reject(
      new Error('Findings reports require the analysis engine. Reload the page, or use the hosted app.'),
    );
  }

  public merge(): Promise<MergeResult> {
    return Promise.reject(
      new Error('Three-way merge requires the .NET engine. Start the API (or use the hosted app), then reload.'),
    );
  }

  public compare(): Promise<ModelCompareResult> {
    return Promise.reject(new Error('Model comparison requires the .NET engine. Wait for WASM to load or connect to the API.'));
  }

  public layout(): Promise<LayoutElement[]> {
    return Promise.reject(new Error('Tidy requires the .NET engine. Use Labels only until the engine is available.'));
  }
}

class HttpEngineClient implements IEngineClient {
  public readonly label = 'engine (/v1)';

  private readonly client: Client<paths>;

  public constructor(baseUrl: string) {
    this.client = createClient<paths>({ baseUrl });
  }

  public write(model: TmForgeModel): Promise<string> {
    return writeJson(model);
  }

  public read(text: string): Promise<TmForgeModel> {
    return readJson(text);
  }

  public async analyze(model: TmForgeModel): Promise<Finding[]> {
    const { data, response } = await this.client.POST('/v1/model/analyze', { body: model });
    if (!response.ok) {
      throw new Error(`Engine analyze failed (${response.status}).`);
    }
    // The generated FindingDto has every field optional/nullable; normalize onto the UI's Finding.
    return (data ?? []).map(toFinding);
  }

  public async generateThreats(model: TmForgeModel): Promise<Threat[]> {
    const { data, response } = await this.client.POST('/v1/model/threats', { body: model });
    if (!response.ok) {
      throw new Error(`Engine threat generation failed (${response.status}).`);
    }
    return (data ?? []).map(toThreat);
  }

  public async runAnalysis(model: TmForgeModel): Promise<AnalysisResult> {
    const { data, response } = await this.client.POST('/v1/model/analysis', { body: model });
    if (!response.ok) {
      throw new Error(`Engine analysis failed (${response.status}).`);
    }
    return toAnalysisResult(data);
  }

  public async exportTm7(model: TmForgeModel): Promise<Blob> {
    // parseAs 'stream' leaves the response body unconsumed so we can hand back a Blob for download.
    const { response } = await this.client.POST('/v1/model/export/tm7', {
      body: model,
      parseAs: 'stream',
    });
    if (!response.ok) {
      throw new Error(`Engine export failed (${response.status}).`);
    }
    return await response.blob();
  }

  public async getFormats(): Promise<FormatInfo[]> {
    const { data, response } = await this.client.GET('/v1/formats');
    if (!response.ok) {
      throw new Error(`Engine formats failed (${response.status}).`);
    }
    return (data ?? []).map(toFormatInfo);
  }

  public async getStencils(): Promise<StencilInfo[]> {
    const { data, response } = await this.client.GET('/v1/stencils');
    if (!response.ok) {
      throw new Error(`Engine stencils failed (${response.status}).`);
    }
    return (data ?? []).map(toStencilInfo);
  }

  public async getStencilPacks(): Promise<PackInfo[]> {
    const { data, response } = await this.client.GET('/v1/stencil-packs');
    if (!response.ok) {
      throw new Error(`Engine stencil packs failed (${response.status}).`);
    }
    return (data ?? []).map(toPackInfo);
  }

  public async getRules(): Promise<RuleInfo[]> {
    const { data, response } = await this.client.GET('/v1/rules');
    if (!response.ok) {
      throw new Error(`Engine rules failed (${response.status}).`);
    }
    return (data ?? []).map(toRuleInfo);
  }

  public setRules(): Promise<RuleBundle> {
    // The /v1 host owns its rule configuration (trusted, operator-supplied, read at startup), so a
    // browser-side pack cannot take effect here. Fail loudly instead of implying that it did.
    return Promise.reject(
      new Error(
        'This engine runs the rule packs its host was configured with. Configure them on the server, ' +
          'or use the in-browser engine to load a pack locally.',
      ),
    );
  }

  public async getRuleBundle(): Promise<RuleBundle> {
    const { data, response } = await this.client.GET('/v1/rule-bundle');
    if (!response.ok) {
      throw new Error(`Engine rule bundle failed (${response.status}).`);
    }
    return toRuleBundle(data);
  }

  public async getRulePacks(): Promise<RulePackInfo[]> {
    const { data, response } = await this.client.GET('/v1/rule-packs');
    if (!response.ok) {
      throw new Error(`Engine rule packs failed (${response.status}).`);
    }
    return (data ?? []).map(toRulePackInfo);
  }

  public async getPropertySchema(): Promise<PropertyDescriptorInfo[]> {
    const { data, response } = await this.client.GET('/v1/property-schema');
    if (!response.ok) {
      throw new Error(`Engine property schema failed (${response.status}).`);
    }
    return (data ?? []).map(toPropertyDescriptor);
  }

  public async detect(bytes: Uint8Array): Promise<FormatInfo | null> {
    const { data, response } = await this.client.POST('/v1/detect', {
      body: { contentBase64: toBase64(bytes) },
    });
    if (response.status === 404) {
      return null;
    }
    if (!response.ok) {
      throw new Error(`Engine detect failed (${response.status}).`);
    }
    return data ? toFormatInfo(data) : null;
  }

  public async preflight(bytes: Uint8Array, formatId?: string, targetFormat?: string): Promise<PreflightResult> {
    const { data, response } = await this.client.POST('/v1/model/preflight', {
      params: { query: { to: targetFormat } },
      body: { contentBase64: toBase64(bytes), formatId },
    });
    if (!response.ok) {
      throw new Error(`Engine preflight failed (${response.status}). Nothing was changed.`);
    }
    return toPreflight(data);
  }

  public async readFile(bytes: Uint8Array, formatId?: string): Promise<TmForgeModel> {
    const { data, response } = await this.client.POST('/v1/model/read', {
      body: { contentBase64: toBase64(bytes), formatId },
    });
    if (!response.ok || !data) {
      throw new Error(`Engine read failed (${response.status}).`);
    }
    return toModel(data);
  }

  public async applyManifest(manifestJson: string): Promise<TmForgeModel> {
    const { data, response } = await this.client.POST('/v1/model/manifest', {
      body: { manifest: manifestJson },
    });
    if (!response.ok) {
      throw new Error(`Engine manifest apply failed (${response.status}).`);
    }
    return modelFromApplyResult(data);
  }

  public async convert(model: TmForgeModel, toFormatId: string): Promise<Blob> {
    const { response } = await this.client.POST('/v1/model/convert', {
      params: { query: { to: toFormatId } },
      body: model,
      parseAs: 'stream',
    });
    if (!response.ok) {
      throw new Error(`Engine convert failed (${response.status}).`);
    }
    return await response.blob();
  }

  public async report(model: TmForgeModel, format: 'html' | 'svg'): Promise<Blob> {
    const { response } = await this.client.POST('/v1/model/report', {
      params: { query: { format } },
      body: model,
      parseAs: 'stream',
    });
    if (!response.ok) {
      throw new Error(`Engine report failed (${response.status}).`);
    }
    return await response.blob();
  }

  public async analysisReport(model: TmForgeModel, format: AnalysisReportFormat): Promise<Blob> {
    const { response } = await this.client.POST('/v1/model/analysis-report', {
      params: { query: { format } },
      body: model,
      parseAs: 'stream',
    });
    if (!response.ok) {
      throw new Error(`Engine findings report failed (${response.status}).`);
    }
    return await response.blob();
  }

  public async merge(base: TmForgeModel | null, ours: TmForgeModel, theirs: TmForgeModel): Promise<MergeResult> {
    const { data, response } = await this.client.POST('/v1/model/merge', {
      body: { base: base ?? undefined, ours, theirs },
    });
    if (!response.ok || !data) {
      throw new Error(`Engine merge failed (${response.status}).`);
    }
    return toMergeResult(data);
  }

  public async compare(baseline: TmForgeModel, proposed: TmForgeModel): Promise<ModelCompareResult> {
    const { data, response } = await this.client.POST('/v1/model/compare', { body: { baseline, proposed } });
    if (!response.ok) {
      throw new Error(`Engine comparison failed (${response.status}).`);
    }
    return toComparison(data);
  }

  public async layout(model: TmForgeModel, positions: LayoutElement[]): Promise<LayoutElement[]> {
    const { data, response } = await this.client.POST('/v1/model/layout', {
      body: { model, positions },
    });
    if (!response.ok) {
      throw new Error(`Engine layout failed (${response.status}). Nothing was changed.`);
    }
    return layoutElements(data, positions);
  }
}

/** The `[JSExport]` methods on the WASM `ThreatModelForge.Wasm.Engine` type (all string in/out). */
interface WasmEngineExports {
  Ping(): string;
  Formats(): string;
  Stencils(): string;
  StencilPacks(): string;
  Rules(): string;
  RulePacks(): string;
  PropertySchema(): string;
  Analyze(tmforgeJson: string): string;
  Threats(tmforgeJson: string): string;
  Detect(contentBase64: string): string;
  Preflight(contentBase64: string, formatId: string, targetFormat: string): string;
  ReadFile(contentBase64: string, formatId: string): string;
  ApplyManifest(manifestJson: string): string;
  ExportTm7(tmforgeJson: string): string;
  ConvertModel(tmforgeJson: string, toFormatId: string): string;
  Report(tmforgeJson: string, format: string): string;
  Merge(baseJson: string, oursJson: string, theirsJson: string): string;
  Compare(requestJson: string): string;
  SetRules(sourcesJson: string): string;
  RuleBundle(): string;
  Analysis(tmforgeJson: string): string;
  AnalysisReport(tmforgeJson: string, format: string): string;
  Layout(requestJson: string): string;
}

/**
 * Calls the real .NET engine compiled to WebAssembly, in-browser, with no network. It is the SAME
 * engine the `/v1` API runs (both go through the shared `ThreatModelForge.Engine` facade); only the
 * transport differs. tmforge-json crosses the boundary as a string, binary documents as base64.
 */
export class WasmEngineClient implements IEngineClient {
  public readonly label = 'engine (wasm)';

  private readonly wasm: WasmEngineExports;

  public constructor(wasm: WasmEngineExports) {
    this.wasm = wasm;
  }

  public write(model: TmForgeModel): Promise<string> {
    return writeJson(model);
  }

  public read(text: string): Promise<TmForgeModel> {
    return readJson(text);
  }

  public async preflight(bytes: Uint8Array, formatId?: string, targetFormat?: string): Promise<PreflightResult> {
    return toPreflight(JSON.parse(this.wasm.Preflight(toBase64(bytes), formatId ?? '', targetFormat ?? '')));
  }

  public async analyze(model: TmForgeModel): Promise<Finding[]> {
    const findings = JSON.parse(this.wasm.Analyze(JSON.stringify(model))) as Array<components['schemas']['FindingDto']>;
    return findings.map(toFinding);
  }

  public async generateThreats(model: TmForgeModel): Promise<Threat[]> {
    const threats = JSON.parse(this.wasm.Threats(JSON.stringify(model))) as Array<components['schemas']['ThreatDto']>;
    return threats.map(toThreat);
  }

  public async runAnalysis(model: TmForgeModel): Promise<AnalysisResult> {
    return toAnalysisResult(
      JSON.parse(this.wasm.Analysis(JSON.stringify(model))) as components['schemas']['AnalysisResultDto'],
    );
  }

  public async exportTm7(model: TmForgeModel): Promise<Blob> {
    return blobFromBase64(this.wasm.ExportTm7(JSON.stringify(model)), 'application/xml');
  }

  public async getFormats(): Promise<FormatInfo[]> {
    return (JSON.parse(this.wasm.Formats()) as Array<components['schemas']['FormatDto']>).map(toFormatInfo);
  }

  public async getStencils(): Promise<StencilInfo[]> {
    return (JSON.parse(this.wasm.Stencils()) as Array<components['schemas']['StencilDto']>).map(toStencilInfo);
  }

  public async getStencilPacks(): Promise<PackInfo[]> {
    return (JSON.parse(this.wasm.StencilPacks()) as Array<components['schemas']['PackDto']>).map(toPackInfo);
  }

  public async getRules(): Promise<RuleInfo[]> {
    return (JSON.parse(this.wasm.Rules()) as Array<components['schemas']['RuleDto']>).map(toRuleInfo);
  }

  public async setRules(sources: RuleSource[]): Promise<RuleBundle> {
    return toRuleBundle(JSON.parse(this.wasm.SetRules(sources.length === 0 ? '' : JSON.stringify(sources))));
  }

  public async getRuleBundle(): Promise<RuleBundle> {
    return toRuleBundle(JSON.parse(this.wasm.RuleBundle()));
  }

  public async getRulePacks(): Promise<RulePackInfo[]> {
    return (JSON.parse(this.wasm.RulePacks()) as Array<components['schemas']['RulePackDto']>).map(toRulePackInfo);
  }

  public async getPropertySchema(): Promise<PropertyDescriptorInfo[]> {
    return (JSON.parse(this.wasm.PropertySchema()) as Array<components['schemas']['PropertyDescriptor']>).map(
      toPropertyDescriptor,
    );
  }

  public async detect(bytes: Uint8Array): Promise<FormatInfo | null> {
    const json = this.wasm.Detect(toBase64(bytes));
    return json ? toFormatInfo(JSON.parse(json) as components['schemas']['FormatDto']) : null;
  }

  public async readFile(bytes: Uint8Array, formatId?: string): Promise<TmForgeModel> {
    const dto = JSON.parse(this.wasm.ReadFile(toBase64(bytes), formatId ?? '')) as components['schemas']['TmForgeModelDto'];
    return toModel(dto);
  }

  public async applyManifest(manifestJson: string): Promise<TmForgeModel> {
    return modelFromApplyResult(
      JSON.parse(this.wasm.ApplyManifest(manifestJson)) as components['schemas']['ApplyResultDto'],
    );
  }

  public async convert(model: TmForgeModel, toFormatId: string): Promise<Blob> {
    return blobFromBase64(this.wasm.ConvertModel(JSON.stringify(model), toFormatId), mimeForFormat(toFormatId));
  }

  public async report(model: TmForgeModel, format: 'html' | 'svg'): Promise<Blob> {
    return blobFromBase64(this.wasm.Report(JSON.stringify(model), format), format === 'svg' ? 'image/svg+xml' : 'text/html');
  }

  public async analysisReport(model: TmForgeModel, format: AnalysisReportFormat): Promise<Blob> {
    return blobFromBase64(
      this.wasm.AnalysisReport(JSON.stringify(model), format),
      analysisReportMime(format),
    );
  }

  public async merge(base: TmForgeModel | null, ours: TmForgeModel, theirs: TmForgeModel): Promise<MergeResult> {
    const dto = JSON.parse(
      this.wasm.Merge(base ? JSON.stringify(base) : '', JSON.stringify(ours), JSON.stringify(theirs)),
    ) as components['schemas']['MergeResultDto'];
    return toMergeResult(dto);
  }

  public async compare(baseline: TmForgeModel, proposed: TmForgeModel): Promise<ModelCompareResult> {
    return toComparison(JSON.parse(this.wasm.Compare(JSON.stringify({ baseline, proposed }))));
  }

  public async layout(model: TmForgeModel, positions: LayoutElement[]): Promise<LayoutElement[]> {
    return layoutElements(JSON.parse(this.wasm.Layout(JSON.stringify({ model, positions }))), positions);
  }
}

/** The honest offline fallback client (client-side authoring only). */
export const offlineEngine: IEngineClient = new OfflineEngineClient();

/** Creates a client bound to the real engine API. */
export function createHttpEngine(baseUrl: string = ENGINE_BASE_URL): IEngineClient {
  return new HttpEngineClient(baseUrl);
}

/** Minimal typing for the .NET WASM bootstrap module (`_framework/dotnet.js`). */
interface DotnetBootstrap {
  dotnet: {
    create(): Promise<{
      getConfig(): { mainAssemblyName: string };
      getAssemblyExports(assemblyName: string): Promise<Record<string, Record<string, Record<string, WasmEngineExports>>>>;
    }>;
  };
}

let wasmEnginePromise: Promise<IEngineClient | null> | undefined;

/**
 * Lazily loads the in-browser (.NET WebAssembly) engine and returns a client bound to it, or `null`
 * when the runtime can't load (WebAssembly disabled, blocked by a Content-Security-Policy, the bundle
 * isn't staged, offline before it's cached, etc.). Cached, so the multi-MB runtime loads at most once.
 */
export function loadWasmEngine(baseUrl: string = import.meta.env.BASE_URL): Promise<IEngineClient | null> {
  wasmEnginePromise ??= (async (): Promise<IEngineClient | null> => {
    try {
      const url = `${baseUrl}wasm/_framework/dotnet.js`;
      const mod = (await import(/* @vite-ignore */ url)) as DotnetBootstrap;
      const runtime = await mod.dotnet.create();
      const exports = await runtime.getAssemblyExports(runtime.getConfig().mainAssemblyName);
      const wasm = exports?.ThreatModelForge?.Wasm?.Engine;
      return wasm ? new WasmEngineClient(wasm) : null;
    } catch {
      return null;
    }
  })();
  return wasmEnginePromise;
}

/** Returns true when the engine API answers its health probe. */
export async function probeEngine(baseUrl: string = ENGINE_BASE_URL): Promise<boolean> {
  try {
    const client = createClient<paths>({ baseUrl });
    const { response } = await client.GET('/v1/health');
    return response.ok;
  } catch {
    return false;
  }
}
