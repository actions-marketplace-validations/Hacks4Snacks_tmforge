import { useCallback, useRef, useState } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import type { DfdEdge, DfdNode } from './types';

interface Snapshot<DocumentState> {
  nodes: DfdNode[];
  edges: DfdEdge[];
  document?: DocumentState;
}

const MAX_HISTORY = 50;

/**
 * A minimal command-stack undo/redo over the React Flow graph. `takeSnapshot()` is called at the
 * start of each discrete edit (add / connect / delete / rename / property change / load); undo and
 * redo swap whole graph snapshots. Snapshots are read through refs so the callbacks never close
 * over stale state.
 */
export function useUndoRedo<DocumentState = undefined>(
  nodes: DfdNode[],
  edges: DfdEdge[],
  setNodes: Dispatch<SetStateAction<DfdNode[]>>,
  setEdges: Dispatch<SetStateAction<DfdEdge[]>>,
  document?: { value: DocumentState; restore: (value: DocumentState) => void },
) {
  const nodesRef = useRef(nodes);
  const edgesRef = useRef(edges);
  nodesRef.current = nodes;
  edgesRef.current = edges;
  const documentRef = useRef(document);
  documentRef.current = document;

  const past = useRef<Snapshot<DocumentState>[]>([]);
  const future = useRef<Snapshot<DocumentState>[]>([]);
  const [canUndo, setCanUndo] = useState(false);
  const [canRedo, setCanRedo] = useState(false);

  const refresh = useCallback(() => {
    setCanUndo(past.current.length > 0);
    setCanRedo(future.current.length > 0);
  }, []);

  const takeSnapshot = useCallback(() => {
    past.current.push({ nodes: nodesRef.current, edges: edgesRef.current, document: documentRef.current?.value });
    if (past.current.length > MAX_HISTORY) {
      past.current.shift();
    }
    future.current = [];
    refresh();
  }, [refresh]);

  const undo = useCallback(() => {
    const previous = past.current.pop();
    if (!previous) {
      return;
    }
    future.current.push({ nodes: nodesRef.current, edges: edgesRef.current, document: documentRef.current?.value });
    setNodes(previous.nodes);
    setEdges(previous.edges);
    if (previous.document !== undefined) documentRef.current?.restore(previous.document);
    refresh();
  }, [setNodes, setEdges, refresh]);

  const redo = useCallback(() => {
    const next = future.current.pop();
    if (!next) {
      return;
    }
    past.current.push({ nodes: nodesRef.current, edges: edgesRef.current, document: documentRef.current?.value });
    setNodes(next.nodes);
    setEdges(next.edges);
    if (next.document !== undefined) documentRef.current?.restore(next.document);
    refresh();
  }, [setNodes, setEdges, refresh]);

  // Drop all history. Called when the active page changes or a new model is loaded, so undo never
  // reaches back across a page switch onto the wrong graph.
  const reset = useCallback(() => {
    past.current = [];
    future.current = [];
    refresh();
  }, [refresh]);

  return { takeSnapshot, undo, redo, canUndo, canRedo, reset };
}
