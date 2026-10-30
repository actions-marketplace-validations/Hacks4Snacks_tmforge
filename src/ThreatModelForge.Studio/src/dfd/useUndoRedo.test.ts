import { describe, it, expect, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import type { Dispatch, SetStateAction } from 'react';
import { useUndoRedo } from './useUndoRedo';
import type { DfdEdge, DfdNode } from './types';

function node(id: string): DfdNode {
  return { id, type: 'process', position: { x: 0, y: 0 }, data: { label: id } };
}

/**
 * Drives the hook the way the editor does: a backing nodes/edges pair whose setters mutate it, plus
 * a `sync()` that re-renders the hook with the latest graph so its refs update (mirroring React
 * flushing the parent state the setter changed).
 */
function setup(initialNodes: DfdNode[], initialEdges: DfdEdge[] = []) {
  let nodes = initialNodes;
  let edges = initialEdges;
  const setNodes = vi.fn((next: SetStateAction<DfdNode[]>) => {
    nodes = typeof next === 'function' ? next(nodes) : next;
  });
  const setEdges = vi.fn((next: SetStateAction<DfdEdge[]>) => {
    edges = typeof next === 'function' ? next(edges) : next;
  });
  const view = renderHook(
    ({ n, e }: { n: DfdNode[]; e: DfdEdge[] }) =>
      useUndoRedo(n, e, setNodes as Dispatch<SetStateAction<DfdNode[]>>, setEdges as Dispatch<SetStateAction<DfdEdge[]>>),
    { initialProps: { n: nodes, e: edges } },
  );
  return {
    result: view.result,
    setNodes,
    setEdges,
    setGraph(nextNodes: DfdNode[], nextEdges: DfdEdge[] = edges) {
      nodes = nextNodes;
      edges = nextEdges;
    },
    sync() {
      act(() => view.rerender({ n: nodes, e: edges }));
    },
  };
}

describe('useUndoRedo', () => {
  it('restores document state and its native undo source with the graph', () => {
    const before = { threats: ['scoped-decision'], source: 'original native register' };
    const after = { threats: [] as string[], source: 'edited native register' };
    const restore = vi.fn();
    const setNodes = vi.fn();
    const setEdges = vi.fn();
    const view = renderHook(({ document }) => useUndoRedo([node('A')], [], setNodes, setEdges, { value: document, restore }), {
      initialProps: { document: before },
    });
    act(() => view.result.current.takeSnapshot());
    view.rerender({ document: after });
    act(() => view.result.current.undo());
    expect(restore).toHaveBeenLastCalledWith(before);
    view.rerender({ document: before });
    act(() => view.result.current.redo());
    expect(restore).toHaveBeenLastCalledWith(after);
  });

  it('starts with nothing to undo or redo', () => {
    const h = setup([node('A')]);

    expect(h.result.current.canUndo).toBe(false);
    expect(h.result.current.canRedo).toBe(false);
  });

  it('takeSnapshot enables undo', () => {
    const h = setup([node('A')]);

    act(() => h.result.current.takeSnapshot());

    expect(h.result.current.canUndo).toBe(true);
    expect(h.result.current.canRedo).toBe(false);
  });

  it('undo restores the snapshotted graph and enables redo', () => {
    const before = [node('A')];
    const after = [node('A'), node('B')];
    const h = setup(before);

    act(() => h.result.current.takeSnapshot());
    h.setGraph(after);
    h.sync();
    act(() => h.result.current.undo());

    expect(h.setNodes).toHaveBeenLastCalledWith(before);
    expect(h.setEdges).toHaveBeenLastCalledWith([]);
    expect(h.result.current.canUndo).toBe(false);
    expect(h.result.current.canRedo).toBe(true);
  });

  it('redo re-applies the undone graph', () => {
    const before = [node('A')];
    const after = [node('A'), node('B')];
    const h = setup(before);

    act(() => h.result.current.takeSnapshot());
    h.setGraph(after);
    h.sync();
    act(() => h.result.current.undo());
    h.sync();
    act(() => h.result.current.redo());

    expect(h.setNodes).toHaveBeenLastCalledWith(after);
    expect(h.result.current.canRedo).toBe(false);
    expect(h.result.current.canUndo).toBe(true);
  });

  it('a new snapshot clears the redo stack', () => {
    const h = setup([node('A')]);

    act(() => h.result.current.takeSnapshot());
    h.setGraph([node('A'), node('B')]);
    h.sync();
    act(() => h.result.current.undo());
    expect(h.result.current.canRedo).toBe(true);

    act(() => h.result.current.takeSnapshot());

    expect(h.result.current.canRedo).toBe(false);
    expect(h.result.current.canUndo).toBe(true);
  });

  it('undo with empty history is a no-op', () => {
    const h = setup([node('A')]);

    act(() => h.result.current.undo());

    expect(h.setNodes).not.toHaveBeenCalled();
    expect(h.result.current.canUndo).toBe(false);
  });

  it('redo with empty future is a no-op', () => {
    const h = setup([node('A')]);

    act(() => h.result.current.redo());

    expect(h.setNodes).not.toHaveBeenCalled();
    expect(h.result.current.canRedo).toBe(false);
  });

  it('reset clears both the undo and redo stacks', () => {
    const h = setup([node('A')]);

    act(() => h.result.current.takeSnapshot());
    h.setGraph([node('A'), node('B')]);
    h.sync();
    act(() => h.result.current.undo());
    expect(h.result.current.canRedo).toBe(true);

    act(() => h.result.current.reset());

    expect(h.result.current.canUndo).toBe(false);
    expect(h.result.current.canRedo).toBe(false);
  });

  it('caps the history depth at 50 snapshots', () => {
    const h = setup([node('A')]);

    for (let i = 0; i < 51; i++) {
      act(() => h.result.current.takeSnapshot());
    }

    let undos = 0;
    while (h.result.current.canUndo && undos < 60) {
      act(() => h.result.current.undo());
      undos += 1;
    }

    expect(undos).toBe(50);
  });
});
