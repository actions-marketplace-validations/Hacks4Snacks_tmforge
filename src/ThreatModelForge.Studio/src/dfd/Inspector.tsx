import { useState } from 'react';
import type { DfdEdge, DfdNode, TmForgeNote } from './types';
import type { PropertyDescriptorInfo, StencilInfo } from './engineClient';

const KIND_LABEL: Record<string, string> = {
  process: 'Process',
  datastore: 'Data store',
  external: 'External entity',
  boundary: 'Trust boundary',
};

const KIND_PLURAL: Record<string, string> = {
  process: 'processes',
  datastore: 'data stores',
  external: 'external entities',
  boundary: 'trust boundaries',
};

/**
 * The value shown for a property the selection disagrees about. It is only ever rendered as a
 * disabled option, so it can never be committed; the NUL prefix keeps it from colliding with a real
 * schema value.
 */
const MIXED = '\u0000mixed';
const MIXED_LABEL = '(mixed)';

/** The shared value of one property across a selection, and whether the selection disagrees. */
export interface PropertySummary {
  /** The common value, or empty when the selection disagrees. */
  value: string;
  /** True when at least two selected items hold different values for the property. */
  mixed: boolean;
}

/**
 * Reduces one property across the selection. An item that does not carry the property counts as
 * empty, so a value set on some-but-not-all of the selection reads as mixed rather than as the value
 * one of them happens to have.
 */
export function summarizeProperty(bags: readonly Record<string, string>[], key: string): PropertySummary {
  const first = bags[0]?.[key] ?? '';
  const mixed = bags.some((bag) => (bag[key] ?? '') !== first);
  return { value: mixed ? '' : first, mixed };
}

/** The distinct custom (non-schema) property keys across the selection, in first-seen order. */
export function customKeys(bags: readonly Record<string, string>[], schemaNames: ReadonlySet<string>): string[] {
  const keys: string[] = [];
  for (const bag of bags) {
    for (const key of Object.keys(bag)) {
      if (!schemaNames.has(key) && !keys.includes(key)) {
        keys.push(key);
      }
    }
  }
  return keys;
}

interface InspectorProps {
  /** Every selected element: none, one, or many. */
  nodes: DfdNode[];
  /** Every selected data flow: none, one, or many. */
  edges: DfdEdge[];
  /** The stencil catalog, so a specialized node can show its stencil identity. */
  stencils: StencilInfo[];
  /** The typed property schema, so element properties render as dropdowns/checkboxes with canonical values. */
  propertySchema: PropertyDescriptorInfo[];
  notes?: TmForgeNote[];
  notesOpen?: boolean;
  onCloseNotes?: () => void;
  onChangeNotes?: (notes: TmForgeNote[]) => void;
  /** Called when a name edit begins, so a single undo step covers the whole edit. */
  onBeginNameEdit: () => void;
  onRenameNode: (id: string, label: string) => void;
  onRenameEdge: (id: string, label: string) => void;
  /** Sets (or, when value is empty, clears) a flow custom property such as Protocol or DataType. */
  onSetEdgeProperty: (ids: string[], key: string, value: string) => void;
  /** Adds or updates an element custom property. */
  onSetNodeProperty: (ids: string[], key: string, value: string) => void;
  /** Removes an element custom property. */
  onRemoveNodeProperty: (ids: string[], key: string) => void;
  onDelete: () => void;
}

/**
 * The schema-driven property editor shared by elements and data flows. It renders a typed control
 * for every property the engine's schema declares for the selected primitive — so every property an
 * analysis rule can read is reachable — followed by any custom (non-schema) properties and a
 * free-form add row. Enum and boolean properties render as dropdowns of canonical values; string
 * properties render as text inputs. Selecting "(none)" or clearing a value removes the property.
 *
 * Over a multi-selection every control writes the whole selection. A property the selection disagrees
 * about renders as "(mixed)" and is left alone unless the author changes it, so opening the Inspector
 * on a mixed selection never flattens the values it is showing.
 */
function PropertyFields(props: {
  /** The DFD primitive whose schema to render: 'process' | 'datastore' | 'external' | 'flow'. */
  appliesTo: string;
  /** The custom properties of each selected element or flow, one bag per item. */
  selection: Record<string, string>[];
  /** The full typed property schema; filtered here by the primitive it applies to. */
  schema: PropertyDescriptorInfo[];
  /** Adds or updates a property across the whole selection. */
  onSet: (key: string, value: string) => void;
  /** Removes a property across the whole selection. */
  onRemove: (key: string) => void;
  /** Called when a free-text edit begins, so one undo step covers the whole edit. */
  onBeginEdit: () => void;
}) {
  const { appliesTo, selection, schema, onSet, onRemove, onBeginEdit } = props;
  const [newKey, setNewKey] = useState('');
  const [newValue, setNewValue] = useState('');

  const schemaFor = schema.filter((descriptor) => descriptor.appliesTo === appliesTo);
  const schemaNames = new Set(schemaFor.map((descriptor) => descriptor.name));
  const custom = customKeys(selection, schemaNames);

  const typedControl = (descriptor: PropertyDescriptorInfo) => {
    const { value, mixed } = summarizeProperty(selection, descriptor.name);
    const commit = (next: string) => (next ? onSet(descriptor.name, next) : onRemove(descriptor.name));
    if (descriptor.kind === 'enum' || descriptor.kind === 'bool') {
      return (
        <select value={mixed ? MIXED : value} onChange={(event) => commit(event.target.value)}>
          {mixed && (
            <option value={MIXED} disabled>
              {MIXED_LABEL}
            </option>
          )}
          <option value="">(none)</option>
          {descriptor.values.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      );
    }
    return (
      <input
        value={mixed ? '' : value}
        placeholder={mixed ? MIXED_LABEL : undefined}
        onFocus={onBeginEdit}
        onChange={(event) => commit(event.target.value)}
      />
    );
  };

  return (
    <div className="inspector-props">
      <span className="inspector-props-title">Properties</span>
      {schemaFor.length === 0 && (
        <p className="inspector-hint">
          Typed properties load from the analysis engine. Add properties by name below (for example, Protocol or
          DataType).
        </p>
      )}
      {schemaFor.map((descriptor) => (
        <label className="inspector-field" key={descriptor.name}>
          <span>{descriptor.name}</span>
          {typedControl(descriptor)}
        </label>
      ))}
      {custom.length > 0 && (
        <>
          <span className="inspector-props-title">Custom properties</span>
          {custom.map((key) => {
            const { value, mixed } = summarizeProperty(selection, key);
            return (
              <div className="inspector-prop-row" key={key}>
                <span className="inspector-prop-key" title={key}>
                  {key}
                </span>
                <input
                  value={mixed ? '' : value}
                  placeholder={mixed ? MIXED_LABEL : undefined}
                  onFocus={onBeginEdit}
                  onChange={(event) => onSet(key, event.target.value)}
                />
                <button className="inspector-prop-del" title={`Remove ${key}`} onClick={() => onRemove(key)}>
                  ×
                </button>
              </div>
            );
          })}
        </>
      )}
      <div className="inspector-prop-add">
        <input placeholder="key" value={newKey} onChange={(event) => setNewKey(event.target.value)} />
        <input placeholder="value" value={newValue} onChange={(event) => setNewValue(event.target.value)} />
        <button
          className="btn"
          disabled={!newKey.trim()}
          onClick={() => {
            const key = newKey.trim();
            onSet(key, newValue);
            setNewKey('');
            setNewValue('');
          }}
        >
          Add
        </button>
      </div>
    </div>
  );
}

/** The shell every selection shape shares: a title, a body, and the delete button. */
function Panel(props: {
  title: string;
  subtitle?: string;
  deleteLabel: string;
  onDelete: () => void;
  children?: React.ReactNode;
}) {
  return (
    <aside className="inspector">
      <h2 className="inspector-title">{props.title}</h2>
      {props.subtitle && <p className="inspector-type">{props.subtitle}</p>}
      {props.children}
      <button className="btn btn-danger" onClick={props.onDelete}>
        {props.deleteLabel}
      </button>
    </aside>
  );
}

export function Inspector(props: InspectorProps) {
  const { nodes, edges } = props;
  const nodeIds = nodes.map((n) => n.id);
  const edgeIds = edges.map((e) => e.id);
  const total = nodes.length + edges.length;

  if (total === 0 && props.onChangeNotes) {
    const notes = props.notes ?? [];
    const changeNotes = props.onChangeNotes;
    return (
      <aside className={`inspector model-notes${props.notesOpen ? ' model-notes-open' : ''}`} aria-label="Model notes"
        onKeyDown={event => {
          if (event.key === 'Escape' && props.notesOpen) {
            event.stopPropagation();
            props.onCloseNotes?.();
          }
        }}>
        <div className="model-note-heading">
          <h2 className="inspector-title">Model notes</h2>
          {props.onCloseNotes && <button className="inspector-prop-del model-notes-close" title="Close model notes"
            aria-label="Close model notes" onClick={props.onCloseNotes}>&#215;</button>}
        </div>
        <button className="btn" onClick={() => {
          const ids = new Set(notes.map(note => note.id));
          let id = 1;
          while (ids.has(id)) id++;
          props.onBeginNameEdit();
          changeNotes([...notes, { id, message: '', date: new Date().toISOString() }]);
        }}>Add note</button>
        {notes.length === 0 && <p className="inspector-empty">No model notes.</p>}
        {notes.map((note, index) => (
          <section className="model-note" key={`${index}:${note.id}`} aria-label={`Note ${note.id}`}>
            <div className="model-note-heading">
              <span>Note {note.id}</span>
              <button className="inspector-prop-del" title={`Delete note ${note.id}`} aria-label={`Delete note ${note.id}`} onClick={() => {
                props.onBeginNameEdit();
                changeNotes(notes.filter((_, position) => position !== index));
              }}>&#215;</button>
            </div>
            <time className="model-note-date" dateTime={note.date} title={note.date}>
              {note.date.startsWith('0001-01-01') ? 'Date not recorded' : new Date(note.date).toLocaleString()}
            </time>
            <label className="inspector-field">
              <span>Note</span>
              <textarea rows={5} aria-label={`Note ${note.id} text`} value={note.message ?? ''}
                onFocus={props.onBeginNameEdit}
                onChange={event => changeNotes(notes.map((entry, position) => position === index ? { ...entry, message: event.target.value } : entry))} />
            </label>
            <label className="inspector-field">
              <span>Author</span>
              <input aria-label={`Note ${note.id} author`} value={note.addedBy ?? ''}
                onFocus={props.onBeginNameEdit}
                onChange={event => changeNotes(notes.map((entry, position) => position === index ? { ...entry, addedBy: event.target.value || undefined } : entry))} />
            </label>
          </section>
        ))}
      </aside>
    );
  }

  if (total === 0) {
    return (
      <aside className="inspector">
        <h2 className="inspector-title">Inspector</h2>
        <p className="inspector-empty">Select an element or data flow to edit its name and properties.</p>
      </aside>
    );
  }

  // Elements and flows have disjoint schemas, so there is no property the whole selection shares.
  // Deleting is still unambiguous, so that is what stays on offer.
  if (nodes.length > 0 && edges.length > 0) {
    return (
      <Panel
        title={`${total} items selected`}
        subtitle={`${nodes.length} ${nodes.length === 1 ? 'element' : 'elements'} · ${edges.length} ${
          edges.length === 1 ? 'data flow' : 'data flows'
        }`}
        deleteLabel={`Delete ${total} items`}
        onDelete={props.onDelete}
      >
        <p className="inspector-hint">
          Elements and data flows have no properties in common. Select only elements, or only flows, to edit them
          together.
        </p>
      </Panel>
    );
  }

  if (edges.length > 0) {
    const single = edges.length === 1 ? edges[0] : null;
    const label = typeof single?.label === 'string' ? single.label : '';
    return (
      <Panel
        title={single ? 'Data flow' : `${edges.length} data flows`}
        deleteLabel={single ? 'Delete flow' : `Delete ${edges.length} flows`}
        onDelete={props.onDelete}
      >
        {single && (
          <label className="inspector-field">
            <span>Label</span>
            <input
              value={label}
              onFocus={props.onBeginNameEdit}
              onChange={(event) => props.onRenameEdge(single.id, event.target.value)}
            />
          </label>
        )}
        <PropertyFields
          key={edgeIds.join(',')}
          appliesTo="flow"
          selection={edges.map((e) => e.data?.properties ?? {})}
          schema={props.propertySchema}
          onSet={(key, value) => props.onSetEdgeProperty(edgeIds, key, value)}
          onRemove={(key) => props.onSetEdgeProperty(edgeIds, key, '')}
          onBeginEdit={props.onBeginNameEdit}
        />
        <p className="inspector-hint">
          Set the properties a rule reads — for example <b>Protocol</b> and <b>Port</b>, a <b>DataType</b>, or an{' '}
          <b>Algorithm</b> — and mention the protocol in the label, then re-analyze to clear the flow findings
          (for example TM1008 / TM1009 / TM1010 / TM1013 / TM1016 / TM1025).
        </p>
      </Panel>
    );
  }

  const kinds = [...new Set(nodes.map((n) => n.type ?? 'process'))];

  // The same property name can carry different values on different kinds — AuthenticationScheme
  // allows Token and PublicKey on an external entity but not on a process — so a single control over
  // a mixed-kind selection would offer values the schema rejects for part of it.
  if (kinds.length > 1) {
    return (
      <Panel
        title={`${nodes.length} elements selected`}
        subtitle={kinds.map((kind) => KIND_LABEL[kind] ?? kind).join(' · ')}
        deleteLabel={`Delete ${nodes.length} elements`}
        onDelete={props.onDelete}
      >
        <p className="inspector-hint">
          These elements are of different kinds, and the same property does not accept the same values on each.
          Select one kind to edit properties together.
        </p>
      </Panel>
    );
  }

  const single = nodes.length === 1 ? nodes[0] : null;
  const baseKind = kinds[0];
  const stencil = single?.data.stencilType
    ? props.stencils.find((s) => s.id === single.data.stencilType)
    : undefined;

  return (
    <Panel
      title={
        single
          ? stencil?.label ?? KIND_LABEL[baseKind] ?? 'Element'
          : `${nodes.length} ${KIND_PLURAL[baseKind] ?? 'elements'}`
      }
      subtitle={single && stencil ? `${stencil.category} · ${KIND_LABEL[stencil.base] ?? stencil.base}` : undefined}
      deleteLabel={single ? 'Delete element' : `Delete ${nodes.length} elements`}
      onDelete={props.onDelete}
    >
      {single && (
        <label className="inspector-field">
          <span>Name</span>
          <input
            value={single.data.label}
            onFocus={props.onBeginNameEdit}
            onChange={(event) => props.onRenameNode(single.id, event.target.value)}
          />
        </label>
      )}
      <PropertyFields
        key={nodeIds.join(',')}
        appliesTo={baseKind}
        selection={nodes.map((n) => n.data.properties ?? {})}
        schema={props.propertySchema}
        onSet={(key, value) => props.onSetNodeProperty(nodeIds, key, value)}
        onRemove={(key) => props.onRemoveNodeProperty(nodeIds, key)}
        onBeginEdit={props.onBeginNameEdit}
      />
    </Panel>
  );
}
