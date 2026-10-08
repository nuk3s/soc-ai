// An analyst override (dogfood 2026-10-06, first hour S3 and C5). The dialog
// listed code values and preselected the current verdict. After a true
// positive override the page kept the benign paragraph and no toast said
// the save landed. The negative controls: nothing is preselected, so the
// confirm is off until a verdict is chosen, and a run with no override shows
// its paragraph open.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '../lib/toast';
import type { Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'alice' }),
  getAbout: vi.fn().mockResolvedValue({}),
  getActionScope: vi.fn().mockResolvedValue(null),
  overrideVerdict: vi.fn().mockResolvedValue({ ok: true, verdict: 'true_positive', confidence: 1, resolvedBy: 'alice' }),
}));

import { overrideVerdict } from '../lib/api';
import { Investigation, overrideToast } from './Investigation';

const inv = (over: Partial<Inv> = {}): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'ET INFO Outbound MSSQL',
    kind: 'suricata',
    host: '192.0.2.1',
    ip: '—',
    verdict: 'false_positive',
    conf: 0.8,
    rationale: 'Benign.',
    summary: [{ t: 'text', v: 'This is benign MSSQL traffic.' }],
    status: 'complete',
    elapsedLabel: '1m',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  }) as Inv;

const mount = (i: Inv, onVerdictApplied = vi.fn()) =>
  render(
    <ToastProvider>
      <MemoryRouter>
        <Investigation inv={i} layout="page" onVerdictApplied={onVerdictApplied} />
      </MemoryRouter>
    </ToastProvider>,
  );

describe('the override dialog', () => {
  it('lists labels, preselects nothing and confirms the save with a toast', async () => {
    const applied = vi.fn();
    mount(inv(), applied);
    fireEvent.click(screen.getByRole('button', { name: /Override verdict/ }));
    const select = screen.getByRole('combobox') as HTMLSelectElement;
    expect(select.value).toBe('');
    const labels = within(select).getAllByRole('option').map((o) => o.textContent);
    expect(labels).toEqual([
      'Choose a verdict',
      'True positive',
      'False positive (the current verdict)',
      'Needs more info',
    ]);
    expect(screen.getByRole('button', { name: /Confirm override/ })).toBeDisabled();
    fireEvent.change(select, { target: { value: 'true_positive' } });
    fireEvent.click(screen.getByRole('button', { name: /Confirm override/ }));
    await waitFor(() => expect(applied).toHaveBeenCalled());
    expect(overrideVerdict).toHaveBeenCalledWith('INV-1', 'true_positive', undefined);
    expect(await screen.findByText('Verdict changed to true positive. Recorded under alice.')).toBeTruthy();
  });

  it('folds the model paragraph under a label after an override', () => {
    mount(
      inv({
        verdict: 'true_positive',
        rationale: 'Verdict set by alice: PCAP shows exfiltration.',
        resolution: {
          original_verdict: 'false_positive',
          resolved_via: 'manual',
          resolved_by: 'alice',
          resolved_at: '2026-10-06T11:09:00+00:00',
        },
      }),
    );
    const fold = screen.getByTestId('pre-override-summary');
    expect(fold.textContent).toContain('soc·ai said before the override');
    expect(screen.queryByText('This is benign MSSQL traffic.')).toBeNull();
    fireEvent.click(within(fold).getByRole('button'));
    expect(screen.getByText('This is benign MSSQL traffic.')).toBeTruthy();
    expect(screen.getByText(/Previous verdict:/).parentElement?.textContent).toContain(
      'Previous verdict: False positive.',
    );
  });

  it('control: a run with no override shows its paragraph', () => {
    mount(inv());
    expect(screen.queryByTestId('pre-override-summary')).toBeNull();
    expect(screen.getByText('This is benign MSSQL traffic.')).toBeTruthy();
    expect(overrideToast('needs_more_info', 'bob')).toBe(
      'Verdict changed to needs more info. Recorded under bob.',
    );
  });
});
