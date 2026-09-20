import { useEffect, useState } from 'react';
import { Background, ConnectionMode, Controls, ReactFlow, ReactFlowProvider, useNodesInitialized, useReactFlow } from '@xyflow/react';
import { DfdReadOnlyContext } from './editorContext';
import { ShapeNode } from './nodes/ShapeNode';
import { TrustBoundaryNode } from './nodes/TrustBoundaryNode';
import { FlowEdge } from './edges/FlowEdge';
import type { ModelReviewChange } from './engineClient';
import type { PageGraph } from './mapping';
import type { DfdEdge, DfdNode } from './types';

const nodeTypes = { process: ShapeNode, datastore: ShapeNode, external: ShapeNode, boundary: TrustBoundaryNode };
const edgeTypes = { flow: FlowEdge };

export function reviewPageId(pages: PageGraph[], pageId: string | undefined, ids: string[]): string | undefined {
  return pages.find((page) => page.id === pageId)?.id
    ?? pages.find((page) => page.nodes.some((node) => ids.includes(node.id)) || page.edges.some((edge) => ids.includes(edge.id)))?.id
    ?? (pages.length === 1 && pageId ? pages[0].id : undefined);
}

function ReviewCanvas({ canvasId, page, ids, theme }: { canvasId: string; page: PageGraph; ids: string[]; theme: 'light' | 'dark' }) {
  const { fitView } = useReactFlow<DfdNode, DfdEdge>();
  const ready = useNodesInitialized();
  const focusKey = ids.join('\0');
  useEffect(() => {
    if (ready) {
      const targets = page.nodes.filter((node) => ids.includes(node.id));
      void fitView({ nodes: targets.length ? targets : undefined, padding: 0.3, maxZoom: 1.2 });
    }
  }, [page, focusKey, ready, fitView]);

  const highlighted = new Set(ids);
  return (
    <DfdReadOnlyContext.Provider value={true}>
      <ReactFlow<DfdNode, DfdEdge>
        id={canvasId}
        nodes={page.nodes.map((node) => ({ ...node, selected: highlighted.has(node.id), className: highlighted.has(node.id) ? 'review-highlight' : '' }))}
        edges={page.edges.map((edge) => ({ ...edge, selected: highlighted.has(edge.id), className: highlighted.has(edge.id) ? 'review-highlight' : '' }))}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        nodesDraggable={false}
        nodesConnectable={false}
        nodesFocusable={false}
        edgesFocusable={false}
        edgesReconnectable={false}
        elementsSelectable={false}
        deleteKeyCode={null}
        selectionKeyCode={null}
        multiSelectionKeyCode={null}
        disableKeyboardA11y
        connectionMode={ConnectionMode.Loose}
        elevateNodesOnSelect={false}
        colorMode={theme}
        minZoom={0.05}
        maxZoom={2.5}
        fitView
        fitViewOptions={{ padding: 0.25, maxZoom: 1.2 }}
      >
        <Background gap={16} color="var(--dots)" />
        <Controls showInteractive={false} />
      </ReactFlow>
    </DfdReadOnlyContext.Provider>
  );
}

interface ReviewDiagramProps {
  side: 'baseline' | 'proposed';
  pages: PageGraph[];
  selection: ModelReviewChange | undefined;
  theme: 'light' | 'dark';
}

export function ReviewDiagram({ side, pages, selection, theme }: ReviewDiagramProps) {
  const [pageId, setPageId] = useState(pages[0]?.id ?? '');
  const ids = (side === 'baseline' ? selection?.baselineElementIds : selection?.proposedElementIds) ?? [];
  const targetPageId = side === 'baseline' ? selection?.baselinePageId : selection?.proposedPageId;
  useEffect(() => {
    const target = reviewPageId(pages, targetPageId, ids);
    if (target) {
      setPageId(target);
    }
  }, [pages, selection, side]);
  const page = pages.find((candidate) => candidate.id === pageId) ?? pages[0];
  const label = side === 'baseline' ? 'Baseline' : 'Proposed';
  const absent = selection && !targetPageId && ids.length === 0;
  return (
    <section className={`review-diagram review-${selection?.kind ?? 'modified'}`} aria-label={`${label} diagram`}>
      <header className="review-diagram-head">
        <strong>{label}</strong>
        <select aria-label={`${label} page`} value={page?.id ?? ''} onChange={(event) => setPageId(event.target.value)}>
          {pages.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
        </select>
      </header>
      <div className="review-canvas">
        {page && <ReactFlowProvider key={page.id}><ReviewCanvas canvasId={`tmforge-review-${side}`} page={page} ids={ids} theme={theme} /></ReactFlowProvider>}
        {page?.nodes.length === 0 && <span className="review-canvas-note">Empty page</span>}
        {absent && <span className="review-side-note">{selection.section === 'findings' ? 'Finding not present' : 'Not present'} in {side}</span>}
      </div>
    </section>
  );
}
