import { useContext, useId, useRef, useState } from 'react';
import type { PointerEvent as ReactPointerEvent } from 'react';
import { BaseEdge, EdgeLabelRenderer, getSmoothStepPath, useReactFlow, type EdgeProps } from '@xyflow/react';
import { DfdActionsContext, DfdReadOnlyContext } from '../editorContext';
import type { DfdEdge } from '../types';

/**
 * A smoothstep data-flow edge. Its label is renamed in place on double-click and can be dragged off
 * the line — a persisted per-edge offset (with a faint leader back to the line) — so that parallel
 * flows sharing a path don't stack their labels on top of one another.
 */
export function FlowEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  label,
  markerEnd,
  style,
  data,
}: EdgeProps<DfdEdge>) {
  const [edgePath, labelX, labelY] = getSmoothStepPath({
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
  });
  const actions = useContext(DfdActionsContext);
  const readOnly = useContext(DfdReadOnlyContext);
  const reviewPathId = useId();
  const { getZoom } = useReactFlow();
  const text = typeof label === 'string' ? label : '';
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(text);

  // The label sits at the path midpoint plus a persisted nudge (edge data) plus any live drag delta.
  const committed = data?.labelOffset ?? { x: 0, y: 0 };
  const [drag, setDrag] = useState<{ x: number; y: number } | null>(null);
  const dragRef = useRef<{ startX: number; startY: number; moved: boolean } | null>(null);
  const offsetX = committed.x + (drag?.x ?? 0);
  const offsetY = committed.y + (drag?.y ?? 0);
  const moved = offsetX !== 0 || offsetY !== 0;

  const startEdit = () => {
    actions.beginEdit();
    setDraft(text);
    setEditing(true);
  };

  const commit = () => {
    actions.renameEdge(id, draft.trim() || 'data flow');
    setEditing(false);
  };

  const onLabelPointerDown = (event: ReactPointerEvent) => {
    if (editing || event.button !== 0) {
      return;
    }
    event.stopPropagation();
    dragRef.current = { startX: event.clientX, startY: event.clientY, moved: false };
    event.currentTarget.setPointerCapture(event.pointerId);
  };

  const onLabelPointerMove = (event: ReactPointerEvent) => {
    const state = dragRef.current;
    if (!state) {
      return;
    }
    const zoom = getZoom() || 1;
    const dx = (event.clientX - state.startX) / zoom;
    const dy = (event.clientY - state.startY) / zoom;
    // Ignore sub-threshold jitter so a plain click still selects and a double-click still renames.
    if (!state.moved && Math.hypot(dx, dy) < 3) {
      return;
    }
    if (!state.moved) {
      state.moved = true;
      actions.beginEdit(); // one undo snapshot per drag
    }
    setDrag({ x: dx, y: dy });
  };

  const onLabelPointerUp = (event: ReactPointerEvent) => {
    const state = dragRef.current;
    dragRef.current = null;
    if (state?.moved && drag) {
      actions.setEdgeLabelOffset(id, { x: committed.x + drag.x, y: committed.y + drag.y });
    }
    setDrag(null);
    try {
      event.currentTarget.releasePointerCapture(event.pointerId);
    } catch {
      /* pointer already released */
    }
  };

  return (
    <>
      <BaseEdge id={readOnly ? reviewPathId : id} path={edgePath} markerEnd={markerEnd} style={style} />
      {moved && (
        <path className="edge-leader" d={`M${labelX},${labelY} L${labelX + offsetX},${labelY + offsetY}`} />
      )}
      <EdgeLabelRenderer>
        <div
          className="edge-label-wrap nodrag nopan"
          style={{ transform: `translate(-50%, -50%) translate(${labelX + offsetX}px, ${labelY + offsetY}px)` }}
        >
          {readOnly ? (
            <span className="edge-label">{text || 'data flow'}</span>
          ) : editing ? (
            <input
              className="edge-label-input"
              autoFocus
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              onBlur={commit}
              onKeyDown={(event) => {
                if (event.key === 'Enter') {
                  commit();
                } else if (event.key === 'Escape') {
                  setDraft(text);
                  setEditing(false);
                }
              }}
            />
          ) : (
            <button
              className={`edge-label${drag ? ' dragging' : ''}`}
              onDoubleClick={startEdit}
              onPointerDown={onLabelPointerDown}
              onPointerMove={onLabelPointerMove}
              onPointerUp={onLabelPointerUp}
              onPointerCancel={onLabelPointerUp}
              title="Drag to move · double-click to rename"
            >
              {text || 'data flow'}
            </button>
          )}
        </div>
      </EdgeLabelRenderer>
    </>
  );
}
