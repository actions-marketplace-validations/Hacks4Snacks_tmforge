import { useContext, useState } from 'react';
import { NodeResizer, type NodeProps } from '@xyflow/react';
import { DfdActionsContext, DfdReadOnlyContext } from '../editorContext';
import type { DfdNode } from '../types';

/** A resizable dashed region that sits behind the other nodes (zIndex 0). Double-click the label to rename. */
export function TrustBoundaryNode({ id, data, selected }: NodeProps<DfdNode>) {
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
    <div className="dfd-boundary">
      <NodeResizer
        isVisible={selected && !readOnly}
        minWidth={140}
        minHeight={90}
        lineClassName="dfd-resize-line"
        handleClassName="dfd-resize-handle"
      />
      {editing ? (
        <input
          className="dfd-boundary-label-input nodrag"
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
        <span
          className="dfd-boundary-label"
          onDoubleClick={(event) => {
            event.stopPropagation();
            startEdit();
          }}
        >
          {data.label}
        </span>
      )}
    </div>
  );
}
