import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Toolbar, REPORT_OPTIONS } from './Toolbar';
import { REPORT_DOWNLOADS } from './Editor';

function renderToolbar(onReport: (id: string) => void, onTidy = vi.fn(), engineOnline = true, tidying = false) {
  render(
    <Toolbar
      onImport={vi.fn()}
      onSave={vi.fn()}
      onExport={vi.fn()}
      onMerge={vi.fn()}
      onAnalyze={vi.fn()}
      onReport={onReport}
      onClear={vi.fn()}
      onUndo={vi.fn()}
      onRedo={vi.fn()}
      onFit={vi.fn()}
      onTidy={onTidy}
      tidying={tidying}
      onToggleTheme={vi.fn()}
      canUndo={false}
      canRedo={false}
      dirty={false}
      fileName={null}
      exportFormats={[]}
      engineOnline={engineOnline}
      engineLabel="test"
      theme="light"
      demo={false}
    />,
  );
}

describe('report menu', () => {
  it('offers the threat model report, the diagram, and every findings artifact', () => {
    expect(REPORT_OPTIONS.map((option) => option.id)).toEqual([
      'html',
      'svg',
      'findings-html',
      'findings-sarif',
      'findings-json',
    ]);
  });

  it('labels SVG as diagram output rather than a threat report', () => {
    const svg = REPORT_OPTIONS.find((option) => option.id === 'svg');

    // The old fixed button implied every download was a threat report; the diagram is not one.
    expect(svg?.label).toMatch(/diagram/i);
    expect(svg?.label).not.toMatch(/threat/i);
    expect(svg?.hint).toMatch(/no analysis/i);
  });

  it('maps every menu option to a download', () => {
    for (const option of REPORT_OPTIONS) {
      expect(REPORT_DOWNLOADS[option.id], option.id).toBeDefined();
    }
  });

  it('routes findings artifacts to the analysis report operation and the rest to the model report', () => {
    expect(REPORT_DOWNLOADS['html']).toEqual({ format: 'html', fileName: 'threat-model-report.html', analysis: false });
    expect(REPORT_DOWNLOADS['svg'].analysis).toBe(false);
    expect(REPORT_DOWNLOADS['findings-sarif']).toEqual({
      format: 'sarif',
      fileName: 'findings.sarif',
      analysis: true,
    });
    expect(REPORT_DOWNLOADS['findings-json'].analysis).toBe(true);
    expect(REPORT_DOWNLOADS['findings-html'].analysis).toBe(true);
  });

  it('reports the chosen format when a menu entry is picked', () => {
    const onReport = vi.fn();
    renderToolbar(onReport);

    fireEvent.click(screen.getByRole('button', { name: /report/i }));
    fireEvent.click(screen.getByRole('menuitem', { name: /findings \(SARIF\)/i }));

    expect(onReport).toHaveBeenCalledWith('findings-sarif');
  });

  it('closes the menu after a choice so a second report needs a deliberate click', () => {
    renderToolbar(vi.fn());

    fireEvent.click(screen.getByRole('button', { name: /report/i }));
    expect(screen.getAllByRole('menuitem').length).toBe(REPORT_OPTIONS.length);

    fireEvent.click(screen.getByRole('menuitem', { name: /diagram only/i }));

    expect(screen.queryAllByRole('menuitem')).toHaveLength(0);
  });
});

describe('Tidy menu', () => {
  it('tidies the existing arrangement with one click', () => {
    const onTidy = vi.fn();
    renderToolbar(vi.fn(), onTidy);

    fireEvent.click(screen.getByRole('button', { name: 'Tidy' }));

    expect(onTidy).toHaveBeenCalledWith('tidy');
    expect(screen.queryAllByRole('menuitem')).toHaveLength(0);
  });

  it('offers only labels-only cleanup in the secondary menu, not rearrangement', () => {
    const onTidy = vi.fn();
    renderToolbar(vi.fn(), onTidy);

    fireEvent.click(screen.getByRole('button', { name: 'Tidy options' }));
    expect(screen.getAllByRole('menuitem')).toHaveLength(1);
    expect(screen.queryByRole('menuitem', { name: /Arrange/ })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('menuitem', { name: /Labels only/ }));
    expect(onTidy).toHaveBeenCalledWith('labels');
  });

  it('keeps labels-only cleanup available offline without promising a safe arrangement', () => {
    renderToolbar(vi.fn(), vi.fn(), false);

    expect(screen.getByRole('button', { name: 'Tidy' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Tidy options' }));

    expect(screen.getByRole('menuitem', { name: /Labels only/ })).toBeEnabled();
  });

  it('disables repeated requests while tidying', () => {
    renderToolbar(vi.fn(), vi.fn(), true, true);

    expect(screen.getByRole('button', { name: /Tidying/ })).toBeDisabled();
  });
});
