import { useDeferredValue, useEffect, useId, useMemo, useRef, useState } from 'react';
import { toModel, type DocumentDiagnostic, type IEngineClient, type ModelCompareResult, type ModelReviewChange, type PreflightResult } from './engineClient';
import { pagesFromModel } from './mapping';
import { tidyLabels } from './autosize';
import { PreflightDialog } from './PreflightDialog';
import { ReviewDiagram } from './ReviewDiagram';
import { normalizeKind, type TmForgeModel } from './types';

interface ReviewInput {
  name: string;
  model: TmForgeModel;
  diagnostics: DocumentDiagnostic[];
}

interface CompareReviewProps {
  engine: IEngineClient;
  current: TmForgeModel;
  currentName: string | null;
  accept: string;
  theme: 'light' | 'dark';
  onClose: () => void;
}

const sections = [
  { id: 'all', label: 'All changes' },
  { id: 'structure', label: 'Structure' },
  { id: 'crossings', label: 'Boundary crossings' },
  { id: 'findings', label: 'Findings' },
] as const;

function canvasInput(model: TmForgeModel, name: string | null): ReviewInput {
  return { name: name ? `Canvas snapshot: ${name}` : 'Canvas snapshot', model: JSON.parse(JSON.stringify(model)) as TmForgeModel, diagnostics: [] };
}

function diagramPages(input: ReviewInput | null, result: ModelCompareResult | null) {
  return input && result?.success
    ? pagesFromModel(toModel(input.model)).map((page) => ({ ...page, ...tidyLabels(page.nodes, page.edges) }))
    : [];
}

function InputDiagnostics({ label, input }: { label: string; input: ReviewInput | null }) {
  if (!input?.diagnostics.length) {
    return null;
  }
  return (
    <details className="review-import-notice" open>
      <summary>{label} import: {input.diagnostics.length} diagnostics</summary>
      <ul>{input.diagnostics.map((item, index) => <li key={index}><code>{item.path}</code> {item.message}</li>)}</ul>
    </details>
  );
}

export function CompareReview({ engine, current, currentName, accept, theme, onClose }: CompareReviewProps) {
  const titleId = useId();
  const panel = useRef<HTMLDivElement>(null);
  const closeButton = useRef<HTMLButtonElement>(null);
  const baselineFile = useRef<HTMLInputElement>(null);
  const proposedFile = useRef<HTMLInputElement>(null);
  const version = useRef(0);
  const decision = useRef<((proceed: boolean) => void) | undefined>(undefined);
  const [baseline, setBaseline] = useState<ReviewInput | null>(null);
  const [proposed, setProposed] = useState<ReviewInput>(() => canvasInput(current, currentName));
  const [result, setResult] = useState<ModelCompareResult | null>(null);
  const [busy, setBusy] = useState<'baseline' | 'proposed' | 'compare' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [preflight, setPreflight] = useState<{ title: string; result: PreflightResult } | null>(null);
  const [section, setSection] = useState<(typeof sections)[number]['id']>('all');
  const [query, setQuery] = useState('');
  const search = useDeferredValue(query).trim().toLowerCase();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    closeButton.current?.focus();
    return () => {
      version.current += 1;
      decision.current?.(false);
      previous?.focus();
    };
  }, []);

  function decide(proceed: boolean) {
    decision.current?.(proceed);
    decision.current = undefined;
    setPreflight(null);
  }

  function begin(operation: typeof busy) {
    const next = ++version.current;
    decide(false);
    setResult(null);
    setSelectedId(null);
    setError(null);
    setBusy(operation);
    return next;
  }

  async function readFile(file: File, side: 'baseline' | 'proposed') {
    const request = begin(side);
    try {
      if (file.size > 8 * 1024 * 1024) {
        throw new Error('Review input exceeds the 8 MiB limit.');
      }
      const bytes = new Uint8Array(await file.arrayBuffer());
      const detected = await engine.detect(bytes).catch(() => null);
      const checked = await engine.preflight(bytes, detected?.id, detected?.id === 'tmforge-json' ? undefined : 'tmforge-json');
      if (version.current !== request) {
        return;
      }
      if (!checked.success || checked.diagnostics.length) {
        const proceed = await new Promise<boolean>((resolve) => {
          decision.current = resolve;
          setPreflight({ title: `${side === 'baseline' ? 'Baseline' : 'Proposed'} import: ${file.name}`, result: checked });
        });
        if (!proceed || !checked.success || version.current !== request) {
          return;
        }
      }
      const format = checked.format ?? detected?.id;
      const model = format === 'tmforge-manifest'
        ? await engine.applyManifest(new TextDecoder().decode(bytes))
        : format === 'tmforge-json'
          ? await engine.read(new TextDecoder().decode(bytes))
          : await engine.readFile(bytes, format);
      if (version.current === request) {
        const input = { name: file.name, model, diagnostics: checked.diagnostics };
        if (side === 'baseline') {
          setBaseline(input);
        } else {
          setProposed(input);
        }
      }
    } catch (failure) {
      if (version.current === request) {
        setError(failure instanceof Error ? failure.message : 'The review input could not be read.');
      }
    } finally {
      if (version.current === request) {
        setBusy(null);
      }
    }
  }

  async function compare() {
    if (!baseline) {
      return;
    }
    const request = begin('compare');
    try {
      const comparison = await engine.compare(baseline.model, proposed.model);
      if (version.current === request) {
        setResult(comparison);
        setSelectedId(comparison.changes[0]?.id ?? null);
      }
    } catch (failure) {
      if (version.current === request) {
        setError(failure instanceof Error ? failure.message : 'Comparison failed.');
      }
    } finally {
      if (version.current === request) {
        setBusy(null);
      }
    }
  }

  const baselinePages = useMemo(() => diagramPages(baseline, result), [baseline, result]);
  const proposedPages = useMemo(() => diagramPages(proposed, result), [proposed, result]);
  const filtered = (result?.changes ?? []).filter((change) => (section === 'all' || change.section === section)
    && (!search || [change.title, change.kind, change.ruleId, change.elementKind, change.baselinePageName, change.proposedPageName,
      ...change.properties.flatMap((property) => [property.key, property.from, property.to])].join(' ').toLowerCase().includes(search)));
  const selectedIndex = Math.max(0, filtered.findIndex((change) => change.id === selectedId));
  const selected = filtered[selectedIndex];
  const pageStart = Math.floor(selectedIndex / 100) * 100;
  const importing = busy === 'baseline' || busy === 'proposed';
  const selectedRow = useRef<HTMLButtonElement>(null);
  useEffect(() => { selectedRow.current?.scrollIntoView?.({ block: 'nearest' }); }, [selected?.id]);

  function step(delta: number) {
    if (filtered.length) {
      setSelectedId(filtered[(selectedIndex + delta + filtered.length) % filtered.length].id);
    }
  }

  return (
    <div className="review-workspace" ref={panel} role="dialog" aria-modal="true" aria-labelledby={titleId}
      onKeyDown={(event) => {
        event.stopPropagation();
        if (event.key === 'Escape') {
          event.preventDefault();
          onClose();
        }
        if ((event.metaKey || event.ctrlKey) && ['s', 'd', 'z', 'y'].includes(event.key.toLowerCase())) {
          event.preventDefault();
        }
        if (event.key === 'Tab') {
          const focusable = panel.current?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled):not([hidden]), select:not(:disabled), summary, [tabindex="0"]');
          const first = focusable?.[0];
          const last = focusable?.[focusable.length - 1];
          if (event.shiftKey && document.activeElement === first) {
            event.preventDefault();
            last?.focus();
          } else if (!event.shiftKey && document.activeElement === last) {
            event.preventDefault();
            first?.focus();
          }
        }
      }}>
      <header className="review-header">
        <h1 id={titleId}>Model Review</h1><span className="review-mode">Read-only</span>
        <span className="review-engine">{engine.label}</span>
        <button ref={closeButton} className="btn btn-icon" onClick={onClose} aria-label="Close review" title="Close review">&times;</button>
      </header>
      <div className="review-inputs">
        {(['baseline', 'proposed'] as const).map((side) => (
          <div className="review-input" key={side}>
            <button className="btn" disabled={importing} onClick={() => (side === 'baseline' ? baselineFile : proposedFile).current?.click()}>Open {side}</button>
              <input ref={side === 'baseline' ? baselineFile : proposedFile} type="file" accept={accept} aria-label={`${side} file`} disabled={importing} hidden
                onChange={(event) => {
                  const file = event.target.files?.[0];
                  event.target.value = '';
                  if (file) void readFile(file, side);
                }} />
            <span className="review-file-name" title={(side === 'baseline' ? baseline : proposed)?.name}>
              {(side === 'baseline' ? baseline : proposed)?.name ?? 'No baseline selected'}
            </span>
            {side === 'proposed' && <button className="btn" disabled={importing} onClick={() => {
              begin(null);
              setProposed(canvasInput(current, currentName));
            }}>Use current canvas</button>}
          </div>
        ))}
        <button className="btn btn-primary review-run" disabled={!baseline || busy !== null} onClick={() => void compare()}>
          {busy === 'compare' ? 'Comparing...' : 'Compare'}
        </button>
      </div>
      {(error || preflight || importing || baseline?.diagnostics.length || proposed.diagnostics.length || result?.warnings.length || result?.diagnostics.length || (result?.success && !result.findingsAvailable)) ? (
        <div className="review-notices" aria-live="polite">
          {importing && <p role="status">Reading {busy}...</p>}
          {error && <p role="alert">{error}</p>}
          <InputDiagnostics label="Baseline" input={baseline} />
          <InputDiagnostics label="Proposed" input={proposed} />
          {result?.success && !result.findingsAvailable && <p role="alert"><strong>Findings comparison unavailable.</strong></p>}
          {result?.warnings.map((warning, index) => <p className="review-warning" key={index}>{warning}</p>)}
          {result?.diagnostics.map((item, index) => <p key={index}><code>{item.path}</code> {item.message}</p>)}
        </div>
      ) : null}
      <div className="review-body">
        <aside className="review-changes" aria-label="Review changes">
          <div className="review-filters">
            <div className="review-tabs" role="tablist" aria-label="Change category">
              {sections.map((item, index) => <button key={item.id} id={`${titleId}-${item.id}`} role="tab" aria-selected={section === item.id}
                aria-controls={`${titleId}-changes`} tabIndex={section === item.id ? 0 : -1}
                onClick={() => setSection(item.id)} onKeyDown={(event) => {
                  const direction = event.key === 'ArrowRight' ? 1 : event.key === 'ArrowLeft' ? -1 : 0;
                  if (direction) {
                    event.preventDefault();
                    const next = sections[(index + direction + sections.length) % sections.length];
                    setSection(next.id);
                    document.getElementById(`${titleId}-${next.id}`)?.focus();
                  }
                }}>
                {item.label} <span>{result ? (item.id === 'findings' && !result.findingsAvailable ? 'N/A'
                  : result.changes.filter((change) => item.id === 'all' || change.section === item.id).length) : '-'}</span>
              </button>)}
            </div>
            <input type="search" aria-label="Filter changes" placeholder="Filter changes" value={query}
              onChange={(event) => setQuery(event.target.value)} />
            <div className="review-stepper">
              <button className="btn btn-icon" aria-label="Previous change" title="Previous change" disabled={!filtered.length} onClick={() => step(-1)}>&larr;</button>
              <output>{filtered.length ? `${selectedIndex + 1} / ${filtered.length}` : '0 changes'}</output>
              <button className="btn btn-icon" aria-label="Next change" title="Next change" disabled={!filtered.length} onClick={() => step(1)}>&rarr;</button>
            </div>
          </div>
          <div className="review-change-list" role="tabpanel" id={`${titleId}-changes`} aria-labelledby={`${titleId}-${section}`}>
            {filtered.slice(pageStart, pageStart + 100).map((change) => <button key={change.id} ref={selected?.id === change.id ? selectedRow : undefined}
              className={`review-change${selected?.id === change.id ? ' active' : ''}`} aria-pressed={selected?.id === change.id}
              onClick={() => setSelectedId(change.id)}>
              <span className="review-change-meta"><span className={`review-kind review-kind-${change.kind}`}>{change.kind}</span><span>{change.ruleId ?? normalizeKind(change.elementKind ?? '')}</span></span>
              <strong>{change.title}</strong>
              <small>{change.proposedPageName ?? change.baselinePageName ?? 'Model'}</small>
            </button>)}
            {!filtered.length && <p className="review-empty">{!result ? 'Not compared' : !result.success ? 'Comparison unavailable'
              : section === 'findings' && !result.findingsAvailable ? 'Findings unavailable' : search ? 'No matching changes' : 'No changes in this category'}</p>}
          </div>
          {filtered.length > 100 && <div className="review-list-pages">
            <button className="btn btn-icon" aria-label="Previous 100 changes" title="Previous 100 changes" disabled={pageStart === 0}
              onClick={() => setSelectedId(filtered[pageStart - 100].id)}>&larr;</button>
            <span>{pageStart + 1}-{Math.min(pageStart + 100, filtered.length)}</span>
            <button className="btn btn-icon" aria-label="Next 100 changes" title="Next 100 changes" disabled={pageStart + 100 >= filtered.length}
              onClick={() => setSelectedId(filtered[pageStart + 100].id)}>&rarr;</button>
          </div>}
          {result?.findingsAvailable && <footer className="review-unchanged">{result.unchangedFindings} unchanged findings</footer>}
        </aside>
        <main className="review-content">
          <div className="review-diagrams">
            <ReviewDiagram side="baseline" pages={baselinePages} selection={selected} theme={theme} />
            <ReviewDiagram side="proposed" pages={proposedPages} selection={selected} theme={theme} />
          </div>
          <section className="review-details" aria-label="Change details">
            {selected ? <ChangeDetails change={selected} /> : <p className="review-empty">{result?.success ? 'No selected change' : 'No comparison yet'}</p>}
          </section>
        </main>
      </div>
      {preflight && <PreflightDialog title={preflight.title} result={preflight.result} onDecision={decide} />}
    </div>
  );
}

function ChangeDetails({ change }: { change: ModelReviewChange }) {
  return <>
    <header className="review-detail-head"><span className={`review-kind review-kind-${change.kind}`}>{change.kind}</span><h2>{change.title}</h2></header>
    <dl className="review-identities">
      <dt>Baseline</dt><dd>{change.baselinePageName ?? 'Model'}{change.baselineElementIds.length > 0 && <code>{change.baselineElementIds.join(', ')}</code>}</dd>
      <dt>Proposed</dt><dd>{change.proposedPageName ?? 'Model'}{change.proposedElementIds.length > 0 && <code>{change.proposedElementIds.join(', ')}</code>}</dd>
    </dl>
    {change.properties.length > 0 && <table className="review-properties">
      <thead><tr><th>Property</th><th>Baseline</th><th>Proposed</th></tr></thead>
      <tbody>{change.properties.map((property, index) => <tr key={index}>
        <th scope="row">{property.key}</th><td>{property.from ?? '(absent)'}</td><td>{property.to ?? '(absent)'}</td>
      </tr>)}</tbody>
    </table>}
  </>;
}
