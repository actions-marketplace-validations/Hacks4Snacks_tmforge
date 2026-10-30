import { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { ReactFlowProvider } from '@xyflow/react';
import { Editor } from './dfd/Editor';
import { PreflightDialog } from './dfd/PreflightDialog';
import { WasmEngineClient } from './dfd/engineClient';
import type { EditorHost } from './dfd/editorContext';
import { listenForHostMessages, StudioBridge, type StudioDocument } from './vscodeHost';
import './index.css';
import './App.css';
import './vscode.css';

declare function acquireVsCodeApi(): { postMessage(message: unknown): void };

const vscode = acquireVsCodeApi();
const bridge = new StudioBridge(message => vscode.postMessage(message));
const engine = new WasmEngineClient((method, ...args) => bridge.request<string>('engine', { method, args }), 'engine (VS Code)');

function decode(content: string): Uint8Array {
  return Uint8Array.from(atob(content), character => character.charCodeAt(0));
}

async function encode(blob: Blob): Promise<string> {
  const bytes = new Uint8Array(await blob.arrayBuffer());
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 32768) binary += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
  return btoa(binary);
}

function Studio() {
  const [document, setDocument] = useState<StudioDocument>();
  const [error, setError] = useState('');
  const [reviewRecovery, setReviewRecovery] = useState(false);
  const [recovering, setRecovering] = useState(false);
  const command = (method: string) => { void bridge.command(method).catch(failure => setError(String(failure))); };
  useEffect(() => {
    bridge.onDocument = value => { setDocument(value); setError(value.error ?? ''); setReviewRecovery(value.preflight?.canRecover === true); };
    bridge.onStatus = value => setDocument(current => current ? { ...current, ...value } : current);
    bridge.onError = setError;
    const stopListening = listenForHostMessages(message => bridge.receive(message));
    vscode.postMessage({ type: 'ready' });
    return () => { stopListening(); bridge.dispose(); };
  }, []);
  useEffect(() => {
    if (document?.model && !document.error) vscode.postMessage({ type: 'rendered', version: document.version });
  }, [document?.version, document?.model, document?.error]);
  const host: EditorHost | undefined = document?.model ? {
    model: document.model, engine, fileName: document.fileName, dirty: document.dirty, theme: document.theme,
    onChange: (previous, next) => { setError(''); setDocument(current => current ? { ...current, dirty: true } : current); bridge.edit(previous, next); },
    save: () => bridge.command('save'),
    undo: () => command('undo'), redo: () => command('redo'), chooseTheme: () => command('theme'),
    open: async () => {
      const file = await bridge.request<{ name: string; content: string } | null>('open');
      return file ? { name: file.name, bytes: decode(file.content) } : undefined;
    },
    create: (model, name) => bridge.request('create', { model, name }),
    download: async (blob, name) => { await bridge.request('download', { name, content: await encode(blob) }); },
    readNative: document.format === 'tm7' ? async () => decode(await bridge.afterEdits<string>('nativeSource')) : undefined,
    confirm: message => bridge.request('confirm', { message }),
  } : undefined;
  return <>
    <div className="host-bar">
      <button className="btn" onClick={() => command('source')}>Open source</button>
      {document?.preflight?.canRecover && <button className="btn" disabled={recovering} onClick={() => setReviewRecovery(true)}>Review recovery import</button>}
      {error && <span role="alert">{error}</span>}
    </div>
    {document?.warnings?.length ? <div className="host-warnings" role="status">{document.warnings.map(message => <p key={message}>{message}</p>)}</div> : null}
    {host && !document?.error ? <ReactFlowProvider><Editor host={host} /></ReactFlowProvider>
      : <p role="status" className="host-status">{document?.error ?? 'Loading model...'}</p>}
    {reviewRecovery && document?.preflight && <PreflightDialog title="Review recovery import" result={document.preflight} operation="import" onDecision={proceed => {
      setReviewRecovery(false);
      if (!proceed || recovering) return;
      setRecovering(true);
      void bridge.request('recover', { version: document.version }).catch(failure => setError(String(failure))).finally(() => setRecovering(false));
    }} />}
  </>;
}

createRoot(document.getElementById('root')!, {
  onUncaughtError: error => vscode.postMessage({ type: 'renderError', error: String(error) }),
}).render(<Studio />);
