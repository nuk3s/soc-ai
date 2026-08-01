// Regression tests for bucket FE2_screens code-review fixes.
//
// F39 (Backtest): a run that fails to start returns { active:false, note } from
//   the POST; the screen must surface that note instead of swallowing it and
//   leaving a stale/empty panel with no explanation.
// F41 (Runbooks): a row Delete must arm a two-step confirm — one click must NOT
//   destroy the runbook; only a second Confirm click deletes it.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

const IDLE_BACKTEST = vi.hoisted(() => ({
  active: false,
  backtest_id: null,
  total: 0,
  replayed: 0,
  failed: 0,
  finished_at: null,
  current: null,
  note: null,
  params: null,
  results: null,
  status: null,
  sampled: null,
}));

const RUNBOOK = vi.hoisted(() => ({
  id: 7,
  title: 'Triage an ET SCAN Nmap alert',
  content: 'Steps to triage.',
  tags: ['scan'],
  linked_rules: ['ET SCAN Nmap'],
  draft: false,
  created_by: 'analyst',
  created_at: '2026-07-01T00:00:00+00:00',
  updated_at: '2026-07-20T00:00:00+00:00',
  embedded: null,
  stale: null,
}));

const startBacktestMock = vi.hoisted(() => vi.fn());
const deleteRunbookMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getBacktest: vi.fn().mockResolvedValue(IDLE_BACKTEST),
  startBacktest: startBacktestMock,
  getRunbooks: vi.fn().mockResolvedValue([RUNBOOK]),
  deleteRunbook: deleteRunbookMock,
}));

import { Backtest } from './Backtest';
import { Runbooks } from './Runbooks';

describe('Backtest start-failure note (F39)', () => {
  it('surfaces the POST note when the run does not start', async () => {
    startBacktestMock.mockResolvedValue({
      ...IDLE_BACKTEST,
      active: false,
      note: 'no dispositioned alerts in the window to replay',
    });
    render(
      <MemoryRouter>
        <Backtest />
      </MemoryRouter>,
    );
    fireEvent.click(await screen.findByRole('button', { name: /Run backtest/i }));
    expect(
      await screen.findByText('no dispositioned alerts in the window to replay'),
    ).toBeInTheDocument();
  });
});

describe('Runbook delete confirmation (F41)', () => {
  it('does not delete on the first click; a second Confirm click does', async () => {
    deleteRunbookMock.mockResolvedValue({ deleted: true });
    render(
      <MemoryRouter>
        <Runbooks />
      </MemoryRouter>,
    );
    await screen.findByText('Triage an ET SCAN Nmap alert');

    // First click only arms the confirm — nothing is deleted.
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    expect(deleteRunbookMock).not.toHaveBeenCalled();

    // Second (Confirm) click performs the delete.
    fireEvent.click(await screen.findByRole('button', { name: 'Confirm delete' }));
    await waitFor(() => expect(deleteRunbookMock).toHaveBeenCalledWith(7));
  });
});
