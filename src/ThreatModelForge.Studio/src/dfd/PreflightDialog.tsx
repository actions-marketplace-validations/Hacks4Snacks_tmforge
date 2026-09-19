import { useEffect, useId, useRef } from 'react';
import type { PreflightResult } from './engineClient';

interface PreflightDialogProps {
  title: string;
  result: PreflightResult;
  onDecision: (proceed: boolean) => void;
}

export function PreflightDialog({ title, result, onDecision }: PreflightDialogProps) {
  const titleId = useId();
  const panel = useRef<HTMLDivElement>(null);
  const cancel = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    cancel.current?.focus();
    return () => previous?.focus();
  }, []);

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby={titleId}
      onClick={() => onDecision(false)}
      onKeyDown={(event) => {
        event.stopPropagation();
        if (event.key === 'Escape') {
          event.preventDefault();
          onDecision(false);
        }
        if (event.key === 'Tab') {
          const buttons = panel.current?.querySelectorAll<HTMLButtonElement>('button');
          const first = buttons?.[0];
          const last = buttons?.[buttons.length - 1];
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
        <header className="merge-head"><h2 id={titleId}>{title}</h2></header>
        <p className="merge-intro">{result.format ?? 'Unknown format'}{result.targetFormat ? ` -> ${result.targetFormat}` : ''}</p>
        <ol className="preflight-diagnostics">
          {result.diagnostics.map((diagnostic, index) => (
            <li key={`${diagnostic.code}:${diagnostic.path}:${index}`} className={`preflight-${diagnostic.severity}`}>
              <div className="preflight-diagnostic-head"><strong>{diagnostic.severity}</strong><code>{diagnostic.code}</code></div>
              <code className="preflight-path">{diagnostic.path}</code>
              <p>{diagnostic.message}</p>
            </li>
          ))}
        </ol>
        <div className="preflight-actions">
          <button ref={cancel} className="btn" onClick={() => onDecision(false)}>{result.success ? 'Cancel' : 'Close'}</button>
          {result.success && <button className="btn btn-primary" onClick={() => onDecision(true)}>Continue</button>}
        </div>
      </div>
    </div>
  );
}
