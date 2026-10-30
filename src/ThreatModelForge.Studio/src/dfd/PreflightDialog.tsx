import { useEffect, useId, useRef } from 'react';
import type { PreflightResult } from './engineClient';

interface PreflightDialogProps {
  title: string;
  result: PreflightResult;
  operation: 'import' | 'export';
  onDecision: (proceed: boolean) => void;
}

export function PreflightDialog({ title, result, operation, onDecision }: PreflightDialogProps) {
  const recovery = operation === 'import' && !result.success && result.canRecover === true;
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
          const controls = panel.current?.querySelectorAll<HTMLElement>('button, summary');
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
        <header className="merge-head"><h2 id={titleId}>{title}</h2></header>
        <div className="preflight-body">
          {recovery && <p role="alert">The recovery copy will omit the listed broken flows and threats scoped to them. Native-only data is not carried into the copy. Your original file will remain unchanged.</p>}
          <ol className="preflight-diagnostics">
            {result.diagnostics.map((diagnostic, index) => (
              <li key={`${diagnostic.code}:${diagnostic.path}:${index}`} className={`preflight-${diagnostic.severity}`}>
                <div className="preflight-diagnostic-head">
                  <strong>{diagnostic.severity}</strong>
                  {diagnostic.code === 'conversion.knowledge-base' && <h3>Embedded template will not be preserved</h3>}
                  {diagnostic.code === 'native.analysis-rules' && <h3>Original TM7 data will be preserved</h3>}
                </div>
                {diagnostic.code === 'conversion.knowledge-base' && operation === 'export' ? <>
                  <p>This exported copy will not include the original Microsoft Threat Modeling Tool template, including stencil definitions and threat-generation rules.</p>
                  <p>Your open native TM7 document is still retained. Keep its TM7 copy: opening the converted JSON later cannot recover the original template or full threat register.</p>
                </> : diagnostic.code === 'conversion.knowledge-base' ? <>
                  <p>Studio imports your diagram but does not retain its embedded Microsoft Threat Modeling Tool template, including stencil definitions and threat-generation rules.</p>
                  <p>Analysis uses tmforge's built-in and separately loaded rules, so the threats reported may differ.</p>
                  <p><strong>Opening leaves your original file unchanged.</strong> Saving back to .tm7 rebuilds the template rather than preserving the original. Save a separate copy if you need to retain the original template.</p>
                </> : <p>{diagnostic.message}</p>}
              </li>
            ))}
          </ol>
          <details className="preflight-details">
            <summary>Technical details</summary>
            <p>{result.format ?? 'Unknown format'}{result.targetFormat ? ` -> ${result.targetFormat}` : ''}</p>
            <ol className="preflight-diagnostics">
              {result.diagnostics.map((diagnostic, index) => (
                <li key={`${diagnostic.code}:${diagnostic.path}:${index}`}>
                  <code>{diagnostic.code}</code>
                  <code className="preflight-path">{diagnostic.path}</code>
                </li>
              ))}
            </ol>
          </details>
        </div>
        <div className="preflight-actions">
          <button ref={cancel} className="btn" onClick={() => onDecision(false)}>{result.success || recovery ? 'Cancel' : 'Close'}</button>
          {result.success && <button className="btn btn-primary" onClick={() => onDecision(true)}>{operation === 'import' ? 'Continue import' : 'Continue'}</button>}
          {recovery && <button className="btn btn-primary" onClick={() => onDecision(true)}>Import recovery copy</button>}
        </div>
      </div>
    </div>
  );
}
