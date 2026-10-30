import '@testing-library/jest-dom/vitest';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, within } from '@testing-library/react';
import { Inspector } from './Inspector';
import type { PropertyDescriptorInfo } from './engineClient';
import type { DfdEdge, DfdNode } from './types';

/**
 * A representative slice of the engine property schema. It deliberately includes the flow
 * properties (Port, Algorithm) that the old hard-coded inspector could NOT expose — the bug this
 * suite guards against — alongside a process property.
 */
const SCHEMA: PropertyDescriptorInfo[] = [
  { appliesTo: 'flow', name: 'Protocol', kind: 'enum', values: ['HTTPS', 'HTTP', 'FTP'], default: 'HTTPS' },
  { appliesTo: 'flow', name: 'Port', kind: 'string', values: [], default: '' },
  { appliesTo: 'flow', name: 'DataType', kind: 'enum', values: ['Customer Content', 'EUII'], default: 'Customer Content' },
  { appliesTo: 'flow', name: 'Algorithm', kind: 'enum', values: ['None', 'AES-GCM', 'RC4'], default: 'None' },
  { appliesTo: 'flow', name: 'Cached', kind: 'bool', values: ['Yes', 'No'], default: 'No' },
  { appliesTo: 'process', name: 'AuthenticationScheme', kind: 'enum', values: ['None', 'OAuth'], default: 'None' },
  { appliesTo: 'process', name: 'SanitizesInput', kind: 'bool', values: ['Yes', 'No'], default: 'No' },
  { appliesTo: 'process', name: 'Multiplicity', kind: 'string', values: [], default: '' },
  // Deliberately narrower than the process list: an external entity accepts values a process does
  // not, which is why a mixed-kind selection cannot share one control.
  { appliesTo: 'external', name: 'AuthenticationScheme', kind: 'enum', values: ['None', 'OAuth', 'PublicKey'], default: 'None' },
];

function handlers() {
  return {
    onBeginNameEdit: vi.fn(),
    onRenameNode: vi.fn(),
    onRenameEdge: vi.fn(),
    onSetEdgeProperty: vi.fn(),
    onSetNodeProperty: vi.fn(),
    onRemoveNodeProperty: vi.fn(),
    onDelete: vi.fn(),
  };
}

function edge(properties: Record<string, string> = {}): DfdEdge {
  return { id: 'f1', source: 'n1', target: 'n2', label: 'request', data: { properties } };
}

function processNode(properties: Record<string, string> = {}): DfdNode {
  return { id: 'n1', type: 'process', position: { x: 0, y: 0 }, data: { label: 'API', properties } };
}

/** A second process, so a multi-selection can be built without repeating the literal. */
function otherProcess(id: string, properties: Record<string, string> = {}): DfdNode {
  return { id, type: 'process', position: { x: 0, y: 0 }, data: { label: id, properties } };
}

describe('Inspector model notes', () => {
  it('closes the narrow-screen notes panel without changing notes', () => {
    const onChangeNotes = vi.fn();
    const onCloseNotes = vi.fn();
    render(<Inspector nodes={[]} edges={[]} stencils={[]} propertySchema={[]} notesOpen
      onCloseNotes={onCloseNotes} onChangeNotes={onChangeNotes} {...handlers()} />);

    expect(screen.getByRole('complementary', { name: 'Model notes' })).toHaveClass('model-notes-open');
    fireEvent.click(screen.getByRole('button', { name: 'Close model notes' }));
    fireEvent.keyDown(screen.getByRole('complementary', { name: 'Model notes' }), { key: 'Escape' });
    expect(onCloseNotes).toHaveBeenCalledTimes(2);
    expect(onChangeNotes).not.toHaveBeenCalled();
  });

  it('adds a note with an unused native ID and no invented author', () => {
    const onChangeNotes = vi.fn();
    const callbacks = handlers();
    const notes = [1, 3].map(id => ({ id, message: `Existing ${id}`, date: '2026-09-30T12:00:00Z' }));
    render(<Inspector nodes={[]} edges={[]} stencils={[]} propertySchema={[]} notes={notes} onChangeNotes={onChangeNotes} {...callbacks} />);

    expect(onChangeNotes).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Add note' }));

    expect(callbacks.onBeginNameEdit).toHaveBeenCalledOnce();
    expect(onChangeNotes).toHaveBeenCalledWith([...notes, { id: 2, message: '', date: expect.any(String) }]);
    expect(onChangeNotes.mock.calls[0][0][2].addedBy).toBeUndefined();
  });

  it('edits multiline text and author without replacing the original timestamp, and removes only that note', () => {
    const onChangeNotes = vi.fn();
    const callbacks = handlers();
    const note = { id: 7, message: 'Original', date: '2026-09-30T12:00:00.1234567Z', addedBy: 'Reviewer' };
    const other = { id: 8, message: 'Keep this', date: '0001-01-01T00:00:00' };
    render(<Inspector nodes={[]} edges={[]} stencils={[]} propertySchema={[]} notes={[note, other]} onChangeNotes={onChangeNotes} {...callbacks} />);

    fireEvent.focus(screen.getByLabelText('Note 7 text'));
    fireEvent.change(screen.getByLabelText('Note 7 text'), { target: { value: 'Scope\nEvidence <review>' } });
    expect(callbacks.onBeginNameEdit).toHaveBeenCalledOnce();
    expect(onChangeNotes).toHaveBeenLastCalledWith([{ ...note, message: 'Scope\nEvidence <review>' }, other]);
    fireEvent.change(screen.getByLabelText('Note 7 author'), { target: { value: 'Author' } });
    expect(onChangeNotes).toHaveBeenLastCalledWith([{ ...note, addedBy: 'Author' }, other]);
    fireEvent.click(screen.getByRole('button', { name: 'Delete note 7' }));
    expect(onChangeNotes).toHaveBeenLastCalledWith([other]);
    expect(note.message).toBe('Original');
    expect(screen.getByText('Date not recorded')).toBeInTheDocument();
  });
});

describe('Inspector — data flow', () => {
  it('renders a typed control for every flow schema property (incl. the previously-missing Port/Algorithm)', () => {
    const h = handlers();
    render(<Inspector nodes={[]} edges={[edge()]} stencils={[]} propertySchema={SCHEMA} {...h} />);

    // Every flow property is now reachable — this is the core regression guard.
    for (const name of ['Protocol', 'Port', 'DataType', 'Algorithm', 'Cached']) {
      expect(screen.getByLabelText(name)).toBeInTheDocument();
    }
    // A process-only property must NOT leak onto a flow.
    expect(screen.queryByLabelText('AuthenticationScheme')).not.toBeInTheDocument();
  });

  it('renders enum properties as dropdowns of the schema values and strings as text inputs', () => {
    const h = handlers();
    render(<Inspector nodes={[]} edges={[edge()]} stencils={[]} propertySchema={SCHEMA} {...h} />);

    const protocol = screen.getByLabelText('Protocol');
    expect(protocol.tagName).toBe('SELECT');
    const options = within(protocol).getAllByRole('option').map((o) => o.textContent);
    expect(options).toEqual(['(none)', 'HTTPS', 'HTTP', 'FTP']);

    expect(screen.getByLabelText('Port').tagName).toBe('INPUT');
  });

  it('setting a flow property emits the canonical value via onSetEdgeProperty', () => {
    const h = handlers();
    render(<Inspector nodes={[]} edges={[edge()]} stencils={[]} propertySchema={SCHEMA} {...h} />);

    fireEvent.change(screen.getByLabelText('Protocol'), { target: { value: 'HTTPS' } });
    expect(h.onSetEdgeProperty).toHaveBeenCalledWith(['f1'], 'Protocol', 'HTTPS');

    fireEvent.change(screen.getByLabelText('Port'), { target: { value: '443' } });
    expect(h.onSetEdgeProperty).toHaveBeenCalledWith(['f1'], 'Port', '443');
  });

  it('clearing a flow property to "(none)" removes it', () => {
    const h = handlers();
    render(<Inspector nodes={[]} edges={[edge({ Protocol: 'HTTPS' })]} stencils={[]} propertySchema={SCHEMA} {...h} />);

    fireEvent.change(screen.getByLabelText('Protocol'), { target: { value: '' } });
    // The edge's remove path is onSetEdgeProperty(ids, key, '') — empty clears the property.
    expect(h.onSetEdgeProperty).toHaveBeenCalledWith(['f1'], 'Protocol', '');
  });

  it('shows a non-schema property under Custom properties with a remove control', () => {
    const h = handlers();
    render(<Inspector nodes={[]} edges={[edge({ Legacy: 'x' })]} stencils={[]} propertySchema={SCHEMA} {...h} />);

    expect(screen.getByText('Custom properties')).toBeInTheDocument();
    fireEvent.click(screen.getByTitle('Remove Legacy'));
    expect(h.onSetEdgeProperty).toHaveBeenCalledWith(['f1'], 'Legacy', '');
  });
});

describe('Inspector — element', () => {
  it('renders the selected kind\'s schema controls and writes via onSetNodeProperty', () => {
    const h = handlers();
    render(<Inspector nodes={[processNode()]} edges={[]} stencils={[]} propertySchema={SCHEMA} {...h} />);

    const scheme = screen.getByLabelText('AuthenticationScheme');
    expect(scheme).toBeInTheDocument();
    // Flow-only properties must not appear on a process.
    expect(screen.queryByLabelText('Protocol')).not.toBeInTheDocument();

    fireEvent.change(scheme, { target: { value: 'OAuth' } });
    expect(h.onSetNodeProperty).toHaveBeenCalledWith(['n1'], 'AuthenticationScheme', 'OAuth');
  });

  it('falls back to a free-text add row when the engine schema is unavailable (offline)', () => {
    const h = handlers();
    render(<Inspector nodes={[processNode()]} edges={[]} stencils={[]} propertySchema={[]} {...h} />);

    // No typed controls, but the author can still add properties by name.
    expect(screen.queryByLabelText('AuthenticationScheme')).not.toBeInTheDocument();
    expect(screen.getByPlaceholderText('key')).toBeInTheDocument();
  });
});

describe('Inspector — multi-selection', () => {
  it('shows the shared value when every selected element agrees', () => {
    const h = handlers();
    render(
      <Inspector
        nodes={[processNode({ AuthenticationScheme: 'OAuth' }), otherProcess('n2', { AuthenticationScheme: 'OAuth' })]}
        edges={[]}
        stencils={[]}
        propertySchema={SCHEMA}
        {...h}
      />,
    );

    expect((screen.getByLabelText('AuthenticationScheme') as HTMLSelectElement).value).toBe('OAuth');
    expect(screen.queryByText('(mixed)')).not.toBeInTheDocument();
  });

  it('shows a disagreed property as (mixed) and writes nothing just by rendering', () => {
    const h = handlers();
    render(
      <Inspector
        nodes={[processNode({ AuthenticationScheme: 'OAuth' }), otherProcess('n2', { AuthenticationScheme: 'None' })]}
        edges={[]}
        stencils={[]}
        propertySchema={SCHEMA}
        {...h}
      />,
    );

    const scheme = screen.getByLabelText('AuthenticationScheme');
    const mixed = within(scheme).getByRole('option', { name: '(mixed)' });
    expect(mixed).toBeInTheDocument();
    // Disabled, so the placeholder can never be committed back over the real values.
    expect(mixed).toBeDisabled();
    // Rendering a mixed selection must not flatten it.
    expect(h.onSetNodeProperty).not.toHaveBeenCalled();
    expect(h.onRemoveNodeProperty).not.toHaveBeenCalled();
  });

  it('a property set on only some of the selection counts as mixed, not as the value one of them has', () => {
    const h = handlers();
    render(
      <Inspector
        nodes={[processNode({ AuthenticationScheme: 'OAuth' }), otherProcess('n2')]}
        edges={[]}
        stencils={[]}
        propertySchema={SCHEMA}
        {...h}
      />,
    );

    expect(within(screen.getByLabelText('AuthenticationScheme')).getByRole('option', { name: '(mixed)' })).toBeInTheDocument();
  });

  it('changing a property writes it to every selected element at once', () => {
    const h = handlers();
    render(
      <Inspector
        nodes={[processNode({ AuthenticationScheme: 'OAuth' }), otherProcess('n2', { AuthenticationScheme: 'None' })]}
        edges={[]}
        stencils={[]}
        propertySchema={SCHEMA}
        {...h}
      />,
    );

    fireEvent.change(screen.getByLabelText('AuthenticationScheme'), { target: { value: 'OAuth' } });
    expect(h.onSetNodeProperty).toHaveBeenCalledWith(['n1', 'n2'], 'AuthenticationScheme', 'OAuth');
  });

  it('writes only the field the author changed, leaving the other mixed fields alone', () => {
    const h = handlers();
    render(
      <Inspector
        nodes={[
          processNode({ AuthenticationScheme: 'OAuth', SanitizesInput: 'Yes', Multiplicity: 'one' }),
          otherProcess('n2', { AuthenticationScheme: 'None', SanitizesInput: 'Yes', Multiplicity: 'many' }),
        ]}
        edges={[]}
        stencils={[]}
        propertySchema={SCHEMA}
        {...h}
      />,
    );

    fireEvent.change(screen.getByLabelText('SanitizesInput'), { target: { value: 'No' } });

    // Exactly one write, for exactly the field that was touched. The two mixed fields stay mixed.
    expect(h.onSetNodeProperty).toHaveBeenCalledTimes(1);
    expect(h.onSetNodeProperty).toHaveBeenCalledWith(['n1', 'n2'], 'SanitizesInput', 'No');
  });

  it('clearing a property to "(none)" removes it from every selected element', () => {
    const h = handlers();
    render(
      <Inspector
        nodes={[processNode({ AuthenticationScheme: 'OAuth' }), otherProcess('n2', { AuthenticationScheme: 'OAuth' })]}
        edges={[]}
        stencils={[]}
        propertySchema={SCHEMA}
        {...h}
      />,
    );

    fireEvent.change(screen.getByLabelText('AuthenticationScheme'), { target: { value: '' } });
    expect(h.onRemoveNodeProperty).toHaveBeenCalledWith(['n1', 'n2'], 'AuthenticationScheme');
  });

  it('lists a custom property held by any of the selection once, and removes it from all of them', () => {
    const h = handlers();
    render(
      <Inspector
        nodes={[processNode({ Owner: 'platform' }), otherProcess('n2', { Owner: 'payments' })]}
        edges={[]}
        stencils={[]}
        propertySchema={SCHEMA}
        {...h}
      />,
    );

    // One row, showing that the selection disagrees rather than showing one element's value.
    expect(screen.getByPlaceholderText('(mixed)')).toBeInTheDocument();
    fireEvent.click(screen.getByTitle('Remove Owner'));
    expect(h.onRemoveNodeProperty).toHaveBeenCalledWith(['n1', 'n2'], 'Owner');
  });

  it('offers no Name field for a multi-selection, and counts the elements it will delete', () => {
    const h = handlers();
    render(
      <Inspector
        nodes={[processNode(), otherProcess('n2'), otherProcess('n3')]}
        edges={[]}
        stencils={[]}
        propertySchema={SCHEMA}
        {...h}
      />,
    );

    // Renaming three elements to one name is not an edit anyone wants.
    expect(screen.queryByLabelText('Name')).not.toBeInTheDocument();
    expect(screen.getByText('3 processes')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Delete 3 elements' }));
    expect(h.onDelete).toHaveBeenCalled();
  });

  it('bulk-edits data flows the same way', () => {
    const h = handlers();
    const second: DfdEdge = { id: 'f2', source: 'n2', target: 'n3', label: 'reply', data: { properties: {} } };
    render(<Inspector nodes={[]} edges={[edge({ Protocol: 'HTTPS' }), second]} stencils={[]} propertySchema={SCHEMA} {...h} />);

    // A flow label is per-flow, so it is not offered across a selection.
    expect(screen.queryByLabelText('Label')).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Protocol'), { target: { value: 'HTTPS' } });
    expect(h.onSetEdgeProperty).toHaveBeenCalledWith(['f1', 'f2'], 'Protocol', 'HTTPS');
  });

  it('refuses typed editing across kinds, because a shared property name does not share its values', () => {
    const h = handlers();
    const store: DfdNode = { id: 'd1', type: 'datastore', position: { x: 0, y: 0 }, data: { label: 'DB' } };
    render(<Inspector nodes={[processNode(), store]} edges={[]} stencils={[]} propertySchema={SCHEMA} {...h} />);

    expect(screen.queryByLabelText('AuthenticationScheme')).not.toBeInTheDocument();
    expect(screen.getByText(/different kinds/i)).toBeInTheDocument();
    // Deleting is still unambiguous, so it stays on offer.
    expect(screen.getByRole('button', { name: 'Delete 2 elements' })).toBeInTheDocument();
  });

  it('offers only delete when the selection mixes elements and flows', () => {
    const h = handlers();
    render(<Inspector nodes={[processNode()]} edges={[edge()]} stencils={[]} propertySchema={SCHEMA} {...h} />);

    expect(screen.queryByLabelText('AuthenticationScheme')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Protocol')).not.toBeInTheDocument();
    expect(screen.getByText(/no properties in common/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Delete 2 items' })).toBeInTheDocument();
  });
});
