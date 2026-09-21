import { useEffect, useId, useRef, useState } from 'react';
import { loadWasmEngine, offlineEngine, type PreflightResult } from './engineClient';
import { pagesFromModel } from './mapping';
import { createShareUrl, readShareFragment } from './shareLink';
import type { TmForgeModel } from './types';

export type ShareRequest =
  | { mode: 'create'; json: string; pageUrl: string }
  | { mode: 'open'; fragment: string; hasWorkspace: boolean };

interface ShareDialogProps {
  request: ShareRequest;
  onClose: () => void;
  onOpen: (model: TmForgeModel) => void;
  onDownload: (json: string) => void;
}

export function ShareDialog({ request, onClose, onOpen, onDownload }: ShareDialogProps) {
  const titleId = useId();
  const panel = useRef<HTMLDivElement>(null);
  const cancel = useRef<HTMLButtonElement>(null);
  const linkInput = useRef<HTMLInputElement>(null);
  const [result, setResult] = useState<{
    pending: boolean; url?: string; model?: TmForgeModel; preflight?: PreflightResult; error?: string;
  }>({ pending: true });
  const [copyError, setCopyError] = useState('');
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    cancel.current?.focus();
    return () => previous?.focus();
  }, []);

  useEffect(() => {
    let active = true;
    setResult({ pending: true });
    setCopied(false);
    setCopyError('');
    void (async () => {
      try {
        if (request.mode === 'create') {
          const url = await createShareUrl(request.json, request.pageUrl);
          if (active) setResult({ pending: false, url });
          return;
        }
        const json = await readShareFragment(request.fragment);
        if (!active || json === null) return;
        const localEngine = await loadWasmEngine();
        if (!active) return;
        if (!localEngine) {
          throw new Error('Opening a shared model requires the in-browser engine. Enable WebAssembly or ask the sender for a model file. Nothing was sent to the server.');
        }
        const preflight = await localEngine.preflight(new TextEncoder().encode(json), 'tmforge-json');
        if (!active) return;
        if (!preflight.success) {
          setResult({ pending: false, preflight });
          return;
        }
        const model = await offlineEngine.read(json);
        if (model.version !== '0.1' || !Array.isArray(model.elements) || !Array.isArray(model.flows)) {
          throw new Error('This link does not contain a supported Studio model. Ask the sender for a model file.');
        }
        pagesFromModel(model);
        if (active) setResult({ pending: false, model, preflight });
      } catch (error) {
        if (active) setResult({ pending: false, error: error instanceof Error ? error.message : 'Could not read the share link.' });
      }
    })();
    return () => { active = false; };
  }, [request]);

  const copyLink = async () => {
    if (!result.url) return;
    try {
      await navigator.clipboard.writeText(result.url);
      setCopied(true);
      setCopyError('');
    } catch {
      setCopyError('Clipboard access is unavailable. Copy the selected link or download the model.');
      linkInput.current?.focus();
      linkInput.current?.select();
    }
  };

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby={titleId}
      onClick={onClose}
      onKeyDown={(event) => {
        event.stopPropagation();
        if (event.key === 'Escape') {
          event.preventDefault();
          onClose();
        }
        if (event.key === 'Tab') {
          const controls = panel.current?.querySelectorAll<HTMLElement>('button:not(:disabled), input');
          const first = controls?.[0];
          const last = controls?.[controls.length - 1];
          if (event.shiftKey && document.activeElement === first) {
            event.preventDefault();
            last?.focus();
          } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault();
            first?.focus();
          }
        }
      }}>
      <div ref={panel} className="modal preflight-modal" onClick={(event) => event.stopPropagation()}>
        <header className="merge-head"><h2 id={titleId}>{request.mode === 'create' ? 'Share model' : 'Open shared model'}</h2></header>
        {request.mode === 'create' ? (
          <p className="merge-intro">Anyone with this link can read the full model. It is not encrypted and may remain in browser history, clipboard, and chat logs.</p>
        ) : (
          <p className="merge-intro">{request.hasWorkspace
            ? 'Opening this model replaces the current workspace, including unsaved changes. Cancel to keep your work.'
            : 'This link contains a model shared with you. Open it in this workspace?'}</p>
        )}
        {result.pending && <p role="status">{request.mode === 'create' ? 'Preparing link...' : 'Checking shared model locally...'}</p>}
        {result.error && <p role="alert">{result.error}</p>}
        {result.url && <label className="share-link-field">Share link
          <input ref={linkInput} readOnly value={result.url} onFocus={(event) => event.target.select()} />
        </label>}
        {result.preflight && result.preflight.diagnostics.length > 0 && (
          <ol className="preflight-diagnostics">
            {result.preflight.diagnostics.map((diagnostic, index) => (
              <li key={`${diagnostic.code}:${index}`}>
                <div className="preflight-diagnostic-head"><strong>{diagnostic.severity}</strong><code>{diagnostic.code}</code></div>
                <code className="preflight-path">{diagnostic.path}</code>
                <p>{diagnostic.message}</p>
              </li>
            ))}
          </ol>
        )}
        {copyError && <p role="alert">{copyError}</p>}
        {copied && <p role="status">Link copied.</p>}
        <div className="preflight-actions share-actions">
          <button ref={cancel} className="btn" onClick={onClose}>{request.mode === 'open' ? 'Cancel' : 'Close'}</button>
          {request.mode === 'create' && <button className="btn" onClick={() => onDownload(request.json)}>Download model</button>}
          {request.mode === 'create' && <button className="btn btn-primary" disabled={!result.url} onClick={copyLink}>Copy link</button>}
          {request.mode === 'open' && <button className="btn btn-primary" disabled={!result.model} onClick={() => result.model && onOpen(result.model)}>Open model</button>}
        </div>
      </div>
    </div>
  );
}
