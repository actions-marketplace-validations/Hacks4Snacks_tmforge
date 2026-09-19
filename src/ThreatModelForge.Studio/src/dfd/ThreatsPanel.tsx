import { useState } from 'react';
import type { Finding, Threat } from './engineClient';
import type { ThreatLifecycleState } from './types';

/** STRIDE categories in canonical display order (matches the engine's `StrideCategory`). */
const STRIDE_ORDER: readonly string[] = [
  'Spoofing',
  'Tampering',
  'Repudiation',
  'InformationDisclosure',
  'DenialOfService',
  'ElevationOfPrivilege',
];

/** Human-readable STRIDE headings. */
const STRIDE_LABEL: Record<string, string> = {
  Spoofing: 'Spoofing',
  Tampering: 'Tampering',
  Repudiation: 'Repudiation',
  InformationDisclosure: 'Information disclosure',
  DenialOfService: 'Denial of service',
  ElevationOfPrivilege: 'Elevation of privilege',
};

const STRIDE_ID: Record<string, string> = {
  Spoofing: 'S',
  Tampering: 'T',
  Repudiation: 'R',
  InformationDisclosure: 'I',
  DenialOfService: 'D',
  ElevationOfPrivilege: 'E',
};

/** Builds a catalog deep-link for a CWE / CAPEC / ATT&CK reference id, or undefined when unrecognized. */
function referenceUrl(id: string): string | undefined {
  const cwe = /^CWE-(\d+)$/i.exec(id);
  if (cwe) {
    return `https://cwe.mitre.org/data/definitions/${cwe[1]}.html`;
  }
  const capec = /^CAPEC-(\d+)$/i.exec(id);
  if (capec) {
    return `https://capec.mitre.org/data/definitions/${capec[1]}.html`;
  }
  const attack = /^(T\d{4})(?:\.(\d{3}))?$/i.exec(id);
  if (attack) {
    return `https://attack.mitre.org/techniques/${attack[1]}${attack[2] ? `/${attack[2]}` : ''}/`;
  }
  return undefined;
}

/** One element or flow a manually-authored threat can be scoped to. */
export interface ThreatScopeOption {
  /** The element or flow id. */
  id: string;
  /** The display label (name and kind). */
  label: string;
}

/** An author edit to a threat's owned fields. `state` is always carried; the rest are sparse. */
export interface ThreatEdit {
  state: ThreatLifecycleState;
  title?: string;
  category?: string;
  priority?: string;
  description?: string;
  mitigation?: string;
  justification?: string;
}

/** A manually-authored threat the user is creating. */
export interface NewThreatDraft {
  title: string;
  category: string;
  /** The scoped element or flow id, or the empty string for a model-wide threat. */
  scopeId: string;
  priority?: string;
  description?: string;
  mitigation?: string;
}

/** Lifecycle states offered in the editor, in workflow order. */
const STATE_OPTIONS: readonly { value: ThreatLifecycleState; label: string }[] = [
  { value: 'Open', label: 'Open' },
  { value: 'NeedsInvestigation', label: 'Needs investigation' },
  { value: 'Mitigated', label: 'Mitigated' },
  { value: 'Accepted', label: 'Accepted' },
];

/** Priorities offered in the editor, most urgent first. Mirrors the engine's `ThreatPriority`. */
const PRIORITY_OPTIONS: readonly string[] = ['Critical', 'High', 'Medium', 'Low'];

/** The short badge shown for a non-open state (open threats show no badge). */
const STATE_BADGE: Record<string, string> = {
  NeedsInvestigation: 'Investigating',
  Mitigated: 'Mitigated',
  Accepted: 'Accepted',
};

/**
 * A manual threat has no rule severity, so its leading badge reflects the author's priority instead.
 * This maps that priority onto the shared severity colour scale (Critical/High -> error, Low -> info,
 * else warning).
 */
function severityClassForPriority(priority: string | undefined): string {
  switch (priority) {
    case 'Critical':
    case 'High':
      return 'error';
    case 'Low':
      return 'info';
    default:
      return 'warning';
  }
}

/** The inline editor for a single threat's author-owned fields. */
function ThreatEditor({ threat, onSave, onCancel }: { threat: Threat; onSave: (edit: ThreatEdit) => void; onCancel: () => void }) {
  const [state, setState] = useState<ThreatLifecycleState>(threat.state);
  const [title, setTitle] = useState(threat.title ?? '');
  const [priority, setPriority] = useState(threat.priority ?? 'Medium');
  const [description, setDescription] = useState(threat.description ?? '');
  const [mitigation, setMitigation] = useState(threat.mitigation ?? '');
  const [justification, setJustification] = useState(threat.justification ?? '');
  const [category, setCategory] = useState(threat.category ?? 'Spoofing');

  function save() {
    const edit: ThreatEdit = { state };
    if (title !== (threat.title ?? '')) {
      edit.title = title;
    }
    if (threat.manual && category !== (threat.category ?? '')) {
      edit.category = category;
    }
    if (priority !== (threat.priority ?? 'Medium')) {
      edit.priority = priority;
    }
    if (description !== (threat.description ?? '')) {
      edit.description = description;
    }
    if (mitigation !== (threat.mitigation ?? '')) {
      edit.mitigation = mitigation;
    }
    if (justification !== (threat.justification ?? '')) {
      edit.justification = justification;
    }
    onSave(edit);
  }

  return (
    <form className="threat-accept threat-edit" onSubmit={(event) => { event.preventDefault(); save(); }}>
      <label className="inspector-field">
        <span>Title</span>
        <input value={title} onChange={(event) => setTitle(event.target.value)} />
      </label>
      {threat.manual ? null : (
        <p className="threat-edit-hint">
          Clear the title to restore the wording its rule produces.
        </p>
      )}
      <label className="inspector-field">
        <span>Category</span>
        <select
          value={threat.manual ? category : (threat.category ?? '')}
          disabled={!threat.manual}
          onChange={(event) => setCategory(event.target.value)}
        >
          {threat.manual && !STRIDE_ORDER.includes(category) && <option value={category}>{category}</option>}
          {threat.manual ? (
            STRIDE_ORDER.map((option) => (
              <option key={option} value={option}>
                {STRIDE_LABEL[option] ?? option}
              </option>
            ))
          ) : (
            <option value={threat.category ?? ''}>{threat.categoryName ?? threat.category}</option>
          )}
        </select>
      </label>
      {threat.manual ? null : (
        <p className="threat-edit-hint">
          The category belongs to the rule that detected this threat, so it is not editable here.
        </p>
      )}
      <label className="inspector-field">
        <span>State</span>
        <select value={state} onChange={(event) => setState(event.target.value as ThreatLifecycleState)}>
          {STATE_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
      <label className="inspector-field">
        <span>Priority</span>
        <select value={priority} onChange={(event) => setPriority(event.target.value)}>
          {PRIORITY_OPTIONS.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      </label>
      <label className="inspector-field">
        <span>Description</span>
        <textarea className="threat-accept-input" value={description} onChange={(event) => setDescription(event.target.value)} />
      </label>
      <label className="inspector-field">
        <span>Mitigation</span>
        <textarea className="threat-accept-input" value={mitigation} onChange={(event) => setMitigation(event.target.value)} />
      </label>
      {state === 'Accepted' ? (
        <label className="inspector-field">
          <span>Justification</span>
          <textarea
            className="threat-accept-input"
            placeholder="Why is this risk accepted?"
            value={justification}
            onChange={(event) => setJustification(event.target.value)}
          />
        </label>
      ) : null}
      <div className="threat-accept-buttons">
        <button type="submit" className="btn btn-primary">
          Save
        </button>
        <button type="button" className="btn" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

/** The form for authoring a new manual threat. */
function AddThreatForm({ scopeOptions, onAdd, onCancel }: { scopeOptions: ThreatScopeOption[]; onAdd: (draft: NewThreatDraft) => void; onCancel: () => void }) {
  const [title, setTitle] = useState('');
  const [category, setCategory] = useState<string>('Spoofing');
  const [scopeId, setScopeId] = useState('');
  const [priority, setPriority] = useState('Medium');
  const [description, setDescription] = useState('');
  const [mitigation, setMitigation] = useState('');

  function add() {
    const trimmed = title.trim();
    if (!trimmed) {
      return;
    }
    const draft: NewThreatDraft = { title: trimmed, category, scopeId, priority };
    if (description.trim()) {
      draft.description = description.trim();
    }
    if (mitigation.trim()) {
      draft.mitigation = mitigation.trim();
    }
    onAdd(draft);
  }

  return (
    <form className="threat-accept threat-edit" onSubmit={(event) => { event.preventDefault(); add(); }}>
      <label className="inspector-field">
        <span>Title</span>
        <input value={title} autoFocus placeholder="Threat statement" onChange={(event) => setTitle(event.target.value)} />
      </label>
      <label className="inspector-field">
        <span>Category</span>
        <select value={category} onChange={(event) => setCategory(event.target.value)}>
          {STRIDE_ORDER.map((option) => (
            <option key={option} value={option}>
              {STRIDE_LABEL[option] ?? option}
            </option>
          ))}
        </select>
      </label>
      <label className="inspector-field">
        <span>Scope</span>
        <select value={scopeId} onChange={(event) => setScopeId(event.target.value)}>
          <option value="">Model-wide</option>
          {scopeOptions.map((option) => (
            <option key={option.id} value={option.id}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
      <label className="inspector-field">
        <span>Priority</span>
        <select value={priority} onChange={(event) => setPriority(event.target.value)}>
          {PRIORITY_OPTIONS.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      </label>
      <label className="inspector-field">
        <span>Description</span>
        <textarea className="threat-accept-input" value={description} onChange={(event) => setDescription(event.target.value)} />
      </label>
      <label className="inspector-field">
        <span>Mitigation</span>
        <textarea className="threat-accept-input" value={mitigation} onChange={(event) => setMitigation(event.target.value)} />
      </label>
      <div className="threat-accept-buttons">
        <button type="submit" className="btn btn-primary" disabled={!title.trim()}>
          Add threat
        </button>
        <button type="button" className="btn" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

export interface ThreatsPanelProps {
  /** The generated threat register for the current model (rule-derived + manual). */
  threats: Threat[];
  /** Non-threat hygiene findings (structural / naming rules), shown in a trailing section. */
  findings: Finding[];
  /** Narrows the canvas highlights to the elements a threat or finding refers to and reveals them. */
  onSelect: (elementIds: string[]) => void;
  /** Returns the name of the page an item's elements live on, when it is not the active page. */
  offPageLabel: (elementIds: string[]) => string | undefined;
  /** Applies an author edit (state / priority / mitigation / description / justification) to a threat. */
  onEditThreat: (threat: Threat, edit: ThreatEdit) => void;
  /** Creates a manually-authored threat. */
  onAddThreat: (draft: NewThreatDraft) => void;
  /** Deletes a manually-authored threat (rule threats cannot be deleted). */
  onDeleteThreat: (threat: Threat) => void;
  /** The elements and flows a manual threat can be scoped to. */
  scopeOptions: ThreatScopeOption[];
}

/**
 * The Studio analysis panel: one place for the model's analysis. It leads with the categorized threat
 * register (grouped by category, each threat editable inline — author its state, priority, mitigation,
 * and description, or create a threat by hand) and trails with any non-threat hygiene findings.
 * Threats and findings are the same detection — a threat is a threat-bearing finding with a lifecycle
 * — so they share one box rather than two near-identical ones.
 */
export function ThreatsPanel({
  threats,
  findings,
  onSelect,
  offPageLabel,
  onEditThreat,
  onAddThreat,
  onDeleteThreat,
  scopeOptions,
}: ThreatsPanelProps) {
  const [editingId, setEditingId] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);

  const byCategory = new Map<string, Threat[]>();
  const categoryLabels = new Map<string, string>();
  const categoryStride = new Map<string, string>();
  for (const threat of threats) {
    const inferredStride =
      threat.stride ?? (!threat.categoryId && STRIDE_ORDER.includes(threat.category) ? threat.category : undefined);
    const key = threat.categoryId ?? (inferredStride ? STRIDE_ID[inferredStride] : threat.category);
    const list = byCategory.get(key) ?? [];
    list.push(threat);
    byCategory.set(key, list);
    categoryLabels.set(key, threat.categoryName ?? STRIDE_LABEL[inferredStride ?? ''] ?? threat.category);
    if (inferredStride) categoryStride.set(key, inferredStride);
  }
  // Known STRIDE categories first, in canonical order; custom categories trail by label then identity.
  const known = STRIDE_ORDER.flatMap((stride) =>
    [...byCategory.keys()].filter((key) => categoryStride.get(key) === stride),
  );
  const knownSet = new Set(known);
  const unknown = [...byCategory.keys()]
    .filter((key) => !knownSet.has(key))
    .sort((left, right) =>
      (categoryLabels.get(left) ?? left).localeCompare(categoryLabels.get(right) ?? right) || left.localeCompare(right),
    );
  const ordered = [...known, ...unknown];

  const openCount = threats.filter((threat) => threat.state === 'Open').length;
  const triagedCount = threats.length - openCount;

  return (
    <div className="threats">
      <div className="threats-head">
        <h3>
          {openCount} open threat{openCount === 1 ? '' : 's'}
          {triagedCount > 0 ? <span className="threats-accepted-count"> · {triagedCount} triaged</span> : null}
        </h3>
        <button
          type="button"
          className="threat-action"
          onClick={() => {
            setEditingId(null);
            setAdding((value) => !value);
          }}
        >
          {adding ? 'Close' : '+ Add threat'}
        </button>
      </div>
      {adding ? (
        <AddThreatForm
          scopeOptions={scopeOptions}
          onAdd={(draft) => {
            onAddThreat(draft);
            setAdding(false);
          }}
          onCancel={() => setAdding(false)}
        />
      ) : null}
      {ordered.map((category) => {
        const items = byCategory.get(category) ?? [];
        return (
          <div key={category} className="threat-group">
            <div className="threat-group-head">
              {categoryLabels.get(category) ?? category}
              <span className="threat-count">{items.length}</span>
            </div>
            {items.map((threat) => {
              const offPage = offPageLabel(threat.elementIds);
              const triaged = threat.state !== 'Open';
              const isEditing = editingId === threat.id;
              const badge = STATE_BADGE[threat.state];
              // A manual threat carries no rule severity, so its badge shows the author's priority.
              const severityClass = threat.manual ? severityClassForPriority(threat.priority) : threat.severity;
              const severityLabel = threat.manual ? threat.priority ?? 'Medium' : threat.severity;
              return (
                <div key={threat.id} className={triaged ? 'threat threat-accepted' : 'threat'}>
                  <div className="threat-row">
                    <div
                      className="threat-head"
                      role="button"
                      tabIndex={0}
                      title={threat.mitigation ? `Mitigation: ${threat.mitigation}` : undefined}
                      onClick={() => onSelect(threat.elementIds)}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault();
                          onSelect(threat.elementIds);
                        }
                      }}
                    >
                      <span className={`sev sev-${severityClass}`} title={threat.manual ? 'Priority' : 'Severity'}>{severityLabel}</span>
                      <div className="threat-body">
                        <div className="threat-title">
                          {threat.ruleId ? <code className="rule-id">{threat.ruleId}</code> : null} {threat.title}
                          {threat.manual ? <span className="threat-badge threat-badge-manual">Manual</span> : null}
                          {badge ? <span className="threat-badge">{badge}</span> : null}
                          {offPage ? <span className="finding-page">{offPage}</span> : null}
                        </div>
                        <div className="threat-meta">
                          {!threat.manual ? (
                            <span
                              className={`threat-priority sev-${severityClassForPriority(threat.priority)}`}
                              title="Priority"
                            >
                              Priority: {threat.priority ?? 'Medium'}
                            </span>
                          ) : null}
                          {threat.interaction ? <span className="threat-scope">{threat.interaction}</span> : null}
                          {threat.references.map((reference) => {
                            const url = referenceUrl(reference);
                            return url ? (
                              <a
                                key={reference}
                                className="threat-ref"
                                href={url}
                                target="_blank"
                                rel="noreferrer"
                                onClick={(event) => event.stopPropagation()}
                              >
                                {reference}
                              </a>
                            ) : (
                              <span key={reference} className="threat-ref">
                                {reference}
                              </span>
                            );
                          })}
                        </div>
                        {threat.description ? <div className="threat-desc">{threat.description}</div> : null}
                        {threat.state === 'Accepted' && threat.justification ? (
                          <div className="threat-justification">“{threat.justification}”</div>
                        ) : null}
                      </div>
                    </div>
                    <div className="threat-actions">
                      {!isEditing ? (
                        <button
                          type="button"
                          className="threat-action"
                          onClick={() => {
                            setAdding(false);
                            setEditingId(threat.id);
                          }}
                        >
                          Edit
                        </button>
                      ) : null}
                      {threat.manual ? (
                        <button type="button" className="threat-action" onClick={() => onDeleteThreat(threat)}>
                          Delete
                        </button>
                      ) : null}
                    </div>
                  </div>
                  {isEditing ? (
                    <ThreatEditor
                      key={threat.id}
                      threat={threat}
                      onSave={(edit) => {
                        onEditThreat(threat, edit);
                        setEditingId(null);
                      }}
                      onCancel={() => setEditingId(null)}
                    />
                  ) : null}
                </div>
              );
            })}
          </div>
        );
      })}
      {findings.length > 0 ? (
        <div className="threat-group">
          <div className="threat-group-head">
            Other findings
            <span className="threat-count">{findings.length}</span>
          </div>
          {findings.map((finding) => {
            const offPage = offPageLabel(finding.elementIds);
            return (
              <div key={finding.id} className="threat">
                <div className="threat-row">
                  <div
                    className="threat-head"
                    role="button"
                    tabIndex={0}
                    onClick={() => onSelect(finding.elementIds)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault();
                        onSelect(finding.elementIds);
                      }
                    }}
                  >
                    <span className={`sev sev-${finding.severity}`}>{finding.severity}</span>
                    <div className="threat-body">
                      <div className="threat-title">
                        {finding.ruleId ? <code className="rule-id">{finding.ruleId}</code> : null} {finding.message}
                        {offPage ? <span className="finding-page">{offPage}</span> : null}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}
