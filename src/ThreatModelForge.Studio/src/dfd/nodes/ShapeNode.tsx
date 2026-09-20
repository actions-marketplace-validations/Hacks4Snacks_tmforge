import { useContext, useState } from 'react';
import { Handle, NodeResizer, Position, type NodeProps } from '@xyflow/react';
import { StencilIcon } from '../icons';
import { DfdActionsContext, DfdReadOnlyContext } from '../editorContext';
import type { DfdKind, DfdNode } from '../types';

/** Four ports; ConnectionMode.Loose lets any port be a source or a target. */
const PORTS = [
  { id: 't', position: Position.Top },
  { id: 'r', position: Position.Right },
  { id: 'b', position: Position.Bottom },
  { id: 'l', position: Position.Left },
] as const;

/** Humanizes a stencil id for a subtle on-node caption (azure-app-service -> "app service"). */
function stencilCaption(id: string | undefined): string | null {
  if (!id) {
    return null;
  }
  return id.replace(/^azure-/, '').replace(/-/g, ' ');
}

/** Renders Process / Data Store / External Entity (class per node type). Double-click to rename in place. */
export function ShapeNode({ id, type, data, selected }: NodeProps<DfdNode>) {
  const caption = stencilCaption(data.stencilType);
  const actions = useContext(DfdActionsContext);
  const readOnly = useContext(DfdReadOnlyContext);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(data.label);

  const startEdit = () => {
    if (readOnly) {
      return;
    }
    actions.beginEdit();
    setDraft(data.label);
    setEditing(true);
  };

  const commit = () => {
    actions.renameNode(id, draft.trim() || data.label);
    setEditing(false);
  };

  return (
    <div
      className={`dfd-node dfd-${type}${selected ? ' selected' : ''}`}
      data-stencil={data.stencilType}
      onDoubleClick={(event) => {
        event.stopPropagation();
        startEdit();
      }}
    >
      <NodeResizer
        isVisible={selected && !readOnly}
        minWidth={72}
        minHeight={48}
        lineClassName="dfd-resize-line"
        handleClassName="dfd-resize-handle"
      />
      {PORTS.map((p) => (
        <Handle key={p.id} id={p.id} type="source" position={p.position} className="dfd-port" />
      ))}
      <span className="dfd-icon" aria-hidden>
        <StencilIcon id={data.stencilType} base={(type ?? 'process') as DfdKind} size={22} />
      </span>
      {caption && <span className="dfd-stencil">{caption}</span>}
      {editing ? (
        <input
          className="dfd-label-input nodrag"
          autoFocus
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          onBlur={commit}
          onKeyDown={(event) => {
            if (event.key === 'Enter') {
              commit();
            } else if (event.key === 'Escape') {
              setDraft(data.label);
              setEditing(false);
            }
          }}
        />
      ) : (
        <span className="dfd-label">{data.label}</span>
      )}
    </div>
  );
}
