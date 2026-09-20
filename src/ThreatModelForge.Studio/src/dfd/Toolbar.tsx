import { useEffect, useRef, useState } from 'react';
import { UndoIcon, RedoIcon } from './icons';

interface ExportFormat {
  id: string;
  displayName: string;
}

/** One entry in a toolbar dropdown. */
interface MenuOption {
  id: string;
  label: string;
  /** Secondary line explaining what the artifact actually is. */
  hint?: string;
}

/**
 * A compact toolbar dropdown. It replaces a native `<select>`, which stretched to its widest option,
 * and closes on outside click or Escape.
 */
function ToolbarMenu({
  label,
  title,
  options,
  onSelect,
  disabled = false,
  ariaLabel,
}: {
  label: string;
  title: string;
  options: MenuOption[];
  onSelect: (id: string) => void;
  disabled?: boolean;
  ariaLabel?: string;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) {
      return;
    }
    const onPointer = (event: MouseEvent) => {
      if (ref.current && !ref.current.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', onPointer);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onPointer);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  return (
    <div className="menu" ref={ref}>
      <button
        className="btn"
        disabled={disabled || options.length === 0}
        aria-haspopup="menu"
        aria-label={ariaLabel}
        aria-expanded={open}
        title={title}
        onClick={() => setOpen((value) => !value)}
      >
        {label} ▾
      </button>
      {open && (
        <div className="menu-list" role="menu">
          {options.map((option) => (
            <button
              key={option.id}
              type="button"
              role="menuitem"
              className="menu-item"
              onClick={() => {
                onSelect(option.id);
                setOpen(false);
              }}
            >
              <span>{option.label}</span>
              {option.hint ? <span className="menu-item-hint">{option.hint}</span> : null}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/** A compact dropdown for Export/convert. */
function ExportMenu({ formats, onExport }: { formats: ExportFormat[]; onExport: (formatId: string) => void }) {
  return (
    <ToolbarMenu
      label="Export"
      title="Export or convert to a file format"
      options={formats.map((format) => ({ id: format.id, label: format.displayName }))}
      onSelect={onExport}
    />
  );
}

/**
 * The report formats the engine can render. Threat-model reports and analysis (findings) artifacts
 * are deliberately separated: the first is the document a reviewer reads, the second is the evidence
 * a pipeline gates on. The SVG entry says "diagram" because it is the picture, not a threat report.
 */
export const REPORT_OPTIONS: MenuOption[] = [
  { id: 'html', label: 'Threat model report', hint: 'HTML · threats, mitigations, diagrams' },
  { id: 'svg', label: 'Diagram only', hint: 'SVG · every page, no analysis' },
  { id: 'findings-html', label: 'Findings report', hint: 'HTML · analysis results' },
  { id: 'findings-sarif', label: 'Findings (SARIF)', hint: 'SARIF · code scanning / CI' },
  { id: 'findings-json', label: 'Findings (JSON)', hint: 'JSON · automation' },
];

interface ToolbarProps {
  engineLabel: string;
  engineOnline: boolean;
  /** True in a static demo build (no /v1 engine): the engine pill frames it as in-browser. */
  demo?: boolean;
  exportFormats: ExportFormat[];
  onExport: (formatId: string) => void;
  onImport: () => void;
  onSave: () => void;
  /** Opens the three-way merge / conflict-resolution dialog. */
  onMerge: () => void;
  onCompare: () => void;
  /** True when the model has changes not yet written to a file. */
  dirty: boolean;
  /** Name of the file the model is bound to (what Save overwrites), or null when unsaved. */
  fileName: string | null;
  onAnalyze: () => void;
  /** Downloads a report from the engine, by report format id. */
  onReport: (reportId: string) => void;
  onClear: () => void;
  onFit: () => void;
  /** Tidies the existing layout with engine validation, or only its visual labels. */
  onTidy: (mode: 'tidy' | 'labels') => void;
  tidying?: boolean;
  onUndo: () => void;
  onRedo: () => void;
  canUndo: boolean;
  canRedo: boolean;
  theme: 'light' | 'dark';
  onToggleTheme: () => void;
}

export function Toolbar(props: ToolbarProps) {
  return (
    <header className="toolbar">
      <span className="toolbar-brand">
        Threat Model Forge <small>· Studio</small>
      </span>

      <span className="toolbar-div" />

      <div className="toolbar-group">
        <button className="btn btn-icon" onClick={props.onUndo} disabled={!props.canUndo} aria-label="Undo" title="Undo (⌘Z)">
          <UndoIcon />
        </button>
        <button className="btn btn-icon" onClick={props.onRedo} disabled={!props.canRedo} aria-label="Redo" title="Redo (⇧⌘Z)">
          <RedoIcon />
        </button>
      </div>

      <span className="toolbar-div" />

      <div className="toolbar-group">

        <button className="btn" onClick={props.onImport}>
          Open File
        </button>
        <button
          className="btn"
          onClick={props.onSave}
          title={props.fileName ? `Save to ${props.fileName} (⌘S)` : 'Save to a file (⌘S)'}
        >
          Save
        </button>
        <ExportMenu formats={props.exportFormats} onExport={props.onExport} />
        <button className="btn" onClick={props.onCompare} disabled={!props.engineOnline}
          title={props.engineOnline ? 'Review model changes without editing the canvas' : 'Comparison requires the engine'}>
          Compare
        </button>
        <button
          className="btn"
          onClick={props.onMerge}
          title="Three-way merge two edited .tm7 files against their common ancestor"
        >
          Merge
        </button>
      </div>

      <span className="toolbar-div" />

      <button
        className="btn btn-primary"
        onClick={props.onAnalyze}
        title="Analyze the model: generate the categorized threat register and check model hygiene"
      >
        Analyze
      </button>
      <ToolbarMenu
        label="Report"
        title="Download a threat model report, the diagram, or the analysis findings"
        options={REPORT_OPTIONS}
        onSelect={props.onReport}
      />

      <span className="toolbar-spacer" />

      {props.fileName ? (
        <span className="file-chip" title={`Editing ${props.fileName}`}>
          {props.fileName}
        </span>
      ) : null}
      <span
        className={`save-status ${props.dirty ? 'dirty' : 'clean'}`}
        title={props.dirty ? 'You have unsaved changes' : 'All changes saved'}
      >
        {props.dirty ? '● Unsaved' : '✓ Saved'}
      </span>
      <span
        className={`engine-pill ${props.engineOnline ? 'online' : 'offline'}`}
        title={props.demo ? 'Runs entirely in your browser — no server. Your model never leaves this page.' : props.engineLabel}
      >
        <span className="engine-dot" />
        {props.engineLabel}
      </span>

      <span className="toolbar-div" />

      <div className="toolbar-group">
        <button
          className="btn btn-icon"
          onClick={props.onToggleTheme}
          aria-label="Toggle dark mode"
          title={props.theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
        >
          {props.theme === 'dark' ? '☀' : '☾'}
        </button>
        <button className="btn" onClick={props.onFit}>
          Fit
        </button>
        <button
          className="btn"
          disabled={props.tidying || !props.engineOnline}
          onClick={() => props.onTidy('tidy')}
          title={props.engineOnline ? 'Tidy the existing layout, preserving its arrangement and trust boundaries' : 'Tidy requires the engine; Labels only is available in Tidy options'}
        >
          {props.tidying ? 'Tidying…' : 'Tidy'}
        </button>
        <ToolbarMenu
          label=""
          ariaLabel="Tidy options"
          title="Tidy options"
          disabled={props.tidying}
          options={[
            { id: 'labels', label: 'Labels only' },
          ]}
          onSelect={() => props.onTidy('labels')}
        />
        <button className="btn" onClick={props.onClear}>
          Clear
        </button>
      </div>
    </header>
  );
}
