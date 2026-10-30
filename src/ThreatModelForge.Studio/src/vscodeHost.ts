import type { TmForgeModel } from './dfd/types';
import type { PreflightResult } from './dfd/engineClient';

export function listenForHostMessages(receive: (message: Record<string, unknown>) => void): () => void {
  const trustedOrigin = window.origin;
  const listener = (event: MessageEvent) => {
    if (!trustedOrigin || trustedOrigin === 'null' || event.origin !== trustedOrigin) return;
    if (event.data && typeof event.data === 'object' && !Array.isArray(event.data)) receive(event.data);
  };
  window.addEventListener('message', listener);
  return () => window.removeEventListener('message', listener);
}

export interface StudioDocument {
  version: number;
  dirty: boolean;
  fileName: string;
  theme: 'light' | 'dark';
  format?: 'tm7' | 'tmforge-json';
  warnings?: string[];
  model?: TmForgeModel;
  error?: string;
  preflight?: PreflightResult;
}

export class StudioBridge {
  onDocument: (document: StudioDocument) => void = () => {};
  onStatus: (status: Omit<StudioDocument, 'model'>) => void = () => {};
  onError: (error: string) => void = () => {};
  private version = 0;
  private generation = 0;
  private sequence = 0;
  private edits: Promise<void> = Promise.resolve();
  private readonly pending = new Map<number, { resolve(value: unknown): void; reject(error: Error): void; timer?: ReturnType<typeof setTimeout> }>();

  constructor(private readonly post: (message: unknown) => void) {}

  receive(message: Record<string, unknown>): void {
    if (message.type === 'response') {
      const pending = this.pending.get(message.id as number);
      if (!pending) return;
      this.pending.delete(message.id as number);
      clearTimeout(pending.timer);
      if (typeof message.error === 'string') pending.reject(new Error(message.error));
      else pending.resolve(message.result);
    } else if (message.type === 'document' && typeof message.version === 'number' && message.version >= this.version) {
      this.version = message.version;
      this.generation++;
      this.onDocument(message as unknown as StudioDocument);
    } else if (message.type === 'status' && typeof message.version === 'number' && message.version >= this.version) {
      this.onStatus(message as unknown as StudioDocument);
    }
  }

  request<Result>(method: string, params: Record<string, unknown> = {}): Promise<Result> {
    const id = ++this.sequence;
    return new Promise((resolve, reject) => {
      const timer = method === 'engine' || method === 'edit' ? setTimeout(() => {
        this.pending.delete(id);
        reject(new Error('VS Code did not finish the request. Reopen the model to retry.'));
      }, 35000) : undefined;
      this.pending.set(id, { resolve: value => resolve(value as Result), reject, timer });
      this.post({ type: 'request', id, method, params });
    });
  }

  edit(previous: TmForgeModel, next: TmForgeModel): void {
    const generation = this.generation;
    this.edits = this.edits.then(async () => {
      if (generation !== this.generation) return;
      const status = await this.request<StudioDocument>('edit', { version: this.version, previous, next });
      if (generation !== this.generation) return;
      this.version = status.version;
      this.onStatus(status);
    }).catch(error => {
      this.generation++;
      this.onError(error instanceof Error ? error.message : String(error));
      this.post({ type: 'ready' });
    });
  }

  async afterEdits<Result>(method: string): Promise<Result> {
    await this.edits;
    return this.request<Result>(method);
  }

  async command(method: string): Promise<void> {
    await this.afterEdits(method);
  }

  dispose(): void {
    this.generation++;
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error('Studio was closed.'));
    }
    this.pending.clear();
  }
}
