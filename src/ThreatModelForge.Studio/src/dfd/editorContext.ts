import { createContext } from 'react';
import type { IEngineClient } from './engineClient';
import type { TmForgeModel } from './types';

export const DfdReadOnlyContext = createContext(false);

export interface EditorHost {
  model: TmForgeModel;
  engine: IEngineClient;
  fileName: string;
  dirty: boolean;
  theme: 'light' | 'dark';
  onChange(previous: TmForgeModel, model: TmForgeModel): void;
  save(): Promise<void>;
  open(): Promise<{ name: string; bytes: Uint8Array } | undefined>;
  create(model: TmForgeModel, name: string): Promise<void>;
  download(blob: Blob, name: string): Promise<void>;
  readNative?(): Promise<Uint8Array>;
  confirm(message: string): Promise<boolean>;
  undo(): void;
  redo(): void;
  chooseTheme(): void;
}

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
