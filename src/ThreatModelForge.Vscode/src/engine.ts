import { join } from 'node:path';
import { Worker } from 'node:worker_threads';

export const MAX_DOCUMENT_BYTES = 8 * 1024 * 1024;
export const MAX_REQUEST_BYTES = 16 * 1024 * 1024;
export const ENGINE_METHODS: Readonly<Record<string, number>> = Object.freeze({
  Ping: 0, Formats: 0, Stencils: 0, StencilPacks: 0, Rules: 0, RulePacks: 0, PropertySchema: 0,
  Analyze: 1, Threats: 1, Detect: 1, Preflight: 3, ReadFile: 2, RecoverTm7: 1, ApplyManifest: 1,
  ExportTm7: 1, SaveTm7: 2, SaveTm7WithPrevious: 3, ConvertModel: 2, Report: 2, Merge: 3, Compare: 1, SetRules: 1,
  RuleBundle: 0, Analysis: 1, AnalysisReport: 2, Layout: 1,
});

export interface InputDiagnostic {
  code: string;
  severity: string;
  path: string;
  message: string;
}

export interface ModelPreflight {
  success: boolean;
  canRecover?: boolean;
  format?: string;
  targetFormat?: string;
  diagnostics: InputDiagnostic[];
}

export class ModelPreflightError extends Error {
  constructor(readonly preflight: ModelPreflight) {
    super(preflight.diagnostics.filter(item => item.severity === 'error').map(item => `${item.path}: ${item.message}`).join('\n') || 'The model is invalid.');
  }
}

export interface Finding {
  id: string;
  ruleId?: string;
  severity: string;
  message: string;
  elementIds: string[];
}

export interface Inspection {
  format?: string;
  diagnostics: InputDiagnostic[];
  pages: { id: string; name: string; svg: string }[];
  analysis?: { findings: Finding[]; diagnostics: string[] } | null;
}

export class EngineWorker {
  private worker: Worker | undefined;
  private sequence = 0;
  private disposed = false;
  private readonly pending = new Map<number, {
    resolve: (result: Inspection | string) => void;
    reject: (error: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }>();

  constructor(
    private readonly runtimeDirectory: string,
    private readonly timeoutMs = 30000,
    private readonly workerPath = join(__dirname, 'engine-worker.mjs'),
  ) {}

  inspect(bytes: Uint8Array, format?: string): Promise<Inspection> {
    if (this.disposed) return Promise.reject(new Error('The analysis engine is closed.'));
    if (bytes.byteLength > MAX_DOCUMENT_BYTES) return Promise.reject(new Error('Model inspection is limited to 8 MiB.'));
    return this.request<Inspection>({ bytes, format });
  }

  async readModel(text: string, format = 'tmforge-json'): Promise<{ model: Record<string, unknown>; warnings: string[] }> {
    if (Buffer.byteLength(text, 'utf8') > MAX_DOCUMENT_BYTES) throw new Error('Model documents are limited to 8 MiB.');
    const content = Buffer.from(text).toString('base64');
    const result = JSON.parse(await this.invoke('Preflight', [content, format, format === 'tm7' ? 'tmforge-json' : ''])) as ModelPreflight;
    if (!result.success) throw new ModelPreflightError(result);
    const model = JSON.parse(format === 'tm7' ? await this.invoke('ReadFile', [content, 'tm7']) : text) as Record<string, unknown> & {
      diagrams?: { elements?: unknown[]; flows?: unknown[] }[]; elements?: unknown[]; flows?: unknown[];
    };
    const pages = model.diagrams?.length ? model.diagrams : [model];
    const elements = pages.reduce((count, page) => count + (page.elements?.length ?? 0), 0);
    const flows = pages.reduce((count, page) => count + (page.flows?.length ?? 0), 0);
    if (pages.length > 32 || elements > 1024 || flows > 2048 || elements * flows > 1000000) {
      throw new Error('Studio is limited to 32 pages, 1024 elements, 2048 flows and one million element/flow pairs.');
    }
    return {
      model: { ...model, elements: model.elements ?? [], flows: model.flows ?? [] },
      warnings: result.diagnostics.filter(item => item.code !== 'conversion.knowledge-base' && item.code !== 'conversion.generated-register')
        .map(item => item.code === 'conversion.line-boundaries'
          ? 'Native line trust boundaries are retained on save but are not shown on the canvas. Canvas analysis may omit their crossings. Deleting a page also removes its hidden objects.'
          : item.message),
    };
  }

  async applyManifest(manifest: unknown): Promise<{ model: Record<string, unknown>; warnings: string[] }> {
    const text = JSON.stringify(manifest);
    if (!text || Buffer.byteLength(text, 'utf8') > MAX_DOCUMENT_BYTES) throw new Error('Manifests are limited to 8 MiB.');
    const preflight = JSON.parse(await this.invoke('Preflight', [Buffer.from(text).toString('base64'), 'tmforge-manifest', ''])) as {
      success: boolean; diagnostics: InputDiagnostic[];
    };
    if (!preflight.success) throw new Error(preflight.diagnostics.map(item => `${item.path}: ${item.message}`).join('\n'));
    const result = JSON.parse(await this.invoke('ApplyManifest', [text])) as {
      success: boolean; error?: string; model: Record<string, unknown>; warnings?: string[];
    };
    if (!result.success) throw new Error(result.error || 'The manifest could not be applied.');
    const candidate = JSON.stringify(result.model);
    if (!candidate) throw new Error('The engine returned no model.');
    const checked = await this.readModel(candidate);
    return { model: checked.model, warnings: [...preflight.diagnostics.map(item => item.message), ...checked.warnings, ...(result.warnings ?? [])] };
  }

  invoke(method: string, args: string[] = []): Promise<string> {
    if (this.disposed) return Promise.reject(new Error('The analysis engine is closed.'));
    if (!Object.hasOwn(ENGINE_METHODS, method) || !Array.isArray(args) || args.length !== ENGINE_METHODS[method]
      || args.some(value => typeof value !== 'string')) {
      return Promise.reject(new Error('Unsupported engine operation or arguments.'));
    }
    if (args.reduce((size, value) => size + Buffer.byteLength(value, 'utf8'), 0) > MAX_REQUEST_BYTES) {
      return Promise.reject(new Error('Engine requests are limited to 16 MiB.'));
    }
    return this.request<string>({ method, args });
  }

  private request<Result extends Inspection | string>(payload: object): Promise<Result> {
    if (this.pending.size >= 16) return Promise.reject(new Error('The analysis queue is full. Retry after the current models finish.'));
    const id = ++this.sequence;
    return new Promise((resolve, reject) => {
      try {
        const worker = this.ensureWorker();
        const timer = setTimeout(() => this.stop(new Error('Model inspection timed out after 30 seconds. The worker was stopped; retry to restart it.')), this.timeoutMs);
        this.pending.set(id, { resolve: result => resolve(result as Result), reject, timer });
        worker.postMessage({ id, ...payload });
      } catch (error) {
        this.stop(error instanceof Error ? error : new Error(String(error)));
        reject(error);
      }
    });
  }

  dispose(): void {
    this.disposed = true;
    this.stop(new Error('The analysis engine is closed.'));
  }

  private ensureWorker(): Worker {
    if (this.worker) return this.worker;
    const worker = new Worker(this.workerPath, {
      workerData: { runtimeDirectory: this.runtimeDirectory },
      resourceLimits: { maxOldGenerationSizeMb: 256 },
    });
    this.worker = worker;
    worker.on('message', (message: { id: number; result?: Inspection | string; error?: string }) => {
      if (this.worker !== worker) return;
      const request = this.pending.get(message.id);
      if (!request) return;
      clearTimeout(request.timer);
      this.pending.delete(message.id);
      if (message.error) request.reject(new Error(message.error));
      else if (message.result !== undefined) request.resolve(message.result);
      else request.reject(new Error('The analysis engine returned no result.'));
    });
    worker.on('error', error => { if (this.worker === worker) this.stop(error); });
    worker.on('exit', code => {
      if (this.worker === worker) this.stop(new Error(`The analysis worker stopped unexpectedly (${code}). Retry to restart it.`));
    });
    return worker;
  }

  private stop(error: Error): void {
    const worker = this.worker;
    this.worker = undefined;
    for (const request of this.pending.values()) {
      clearTimeout(request.timer);
      request.reject(error);
    }
    this.pending.clear();
    if (worker) void worker.terminate();
  }
}
