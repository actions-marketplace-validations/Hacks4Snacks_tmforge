import { createContext } from 'react';

export const DfdReadOnlyContext = createContext(false);

/**
 * Editor actions shared with the custom node/edge components so they can rename in place.
 * `beginEdit` takes one undo snapshot at the start of an edit; `rename*` commit the new label.
 */
export interface DfdActions {
  beginEdit: () => void;
  renameNode: (id: string, label: string) => void;
  renameEdge: (id: string, label: string) => void;
  /** Persist a label's drag offset (px, in flow coordinates) so parallel-flow labels can be separated. */
  setEdgeLabelOffset: (id: string, offset: { x: number; y: number }) => void;
}

export const DfdActionsContext = createContext<DfdActions>({
  beginEdit: () => {},
  renameNode: () => {},
  renameEdge: () => {},
  setEdgeLabelOffset: () => {},
});
