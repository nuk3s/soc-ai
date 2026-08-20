// A blind auto-triage sweep must not render as a drained queue.
//
// Degraded-grid sweep, 2026-08-13 (G3): with the sensor unreachable, planning
// read nothing and returned the same shape a genuinely empty backlog returns —
// total=0, hunted=0, failed=0 — so this tile said "Last batch · 0 investigated"
// for the whole blind window. An analyst reads that as a calm night and moves
// on. The numbers cannot carry the difference, so the backend sends `degraded`
// and these tests pin that the two states render differently.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { AutoTriageStatus } from '../lib/api';

const triageStatus = vi.hoisted(() => ({ current: null as AutoTriageStatus | null }));

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue([]),
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  listInvestigations: vi.fn().mockResolvedValue({
    rows: [], total: 0, running: 0, truePositives: 0, totalAll: 0, active: false, limit: 100, offset: 0,
  }),
  getAutoTriageStatus: vi.fn(async () => triageStatus.current),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getHealth: vi.fn().mockResolvedValue(null),
  getDetectionTuningSummary: vi.fn().mockResolvedValue(null),
  // Setup-health card: unconditional on mount, so every Dashboard-rendering
  // test needs it named or the global fetch guard rejects loudly. Green here
  // (this file isn't about setup health), so the admin-only detail read is
  // never reached regardless of role.
  getMe: vi.fn().mockResolvedValue({ username: 'ana', role: 'analyst', status: '' }),
  getPreflight: vi.fn().mockResolvedValue({ status: 'green', failing: 0, warned: 0, checked_at: '2026-08-19T00:00:00+00:00' }),
  getPreflightDetail: vi.fn().mockResolvedValue({ rows: [], checked_at: '2026-08-19T00:00:00+00:00' }),
}));

import { Dashboard } from './Dashboard';

const BASE: AutoTriageStatus = {
  active: false,
  total: 0,
  hunted: 0,
  skipped: 0,
  failed: 0,
  finished_at: '2026-08-13T02:00:00+00:00',
  severities: ['critical', 'high'],
  note: null,
  current: null,
  tool_calls: 0,
};

const mount = async (s: AutoTriageStatus) => {
  triageStatus.current = s;
  render(
    <MemoryRouter initialEntries={['/']}>
      <Dashboard />
    </MemoryRouter>,
  );
  // The tile renders once the status resolves; either testid proves that.
  await screen.findByText('Investigation outcomes');
};

describe('Dashboard auto-investigate tile — blind sweep vs quiet queue', () => {
  it('shows the degraded state when the sweep could not read the grid', async () => {
    await mount({ ...BASE, degraded: true, grid_errors: ['severity critical', 'severity high'] });
    expect(await screen.findByTestId('autotriage-degraded')).toBeTruthy();
    // ...and specifically NOT the clean "last batch" summary, which is the
    // false all-clear this whole finding is about.
    expect(screen.queryByTestId('autotriage-summary')).toBeNull();
  });

  it('shows the ordinary summary when the queue is genuinely drained', async () => {
    // Identical counters — the ONLY difference is `degraded`. If the tile ever
    // starts inferring the state from `total === 0` again, this pair breaks.
    await mount({ ...BASE, degraded: false, grid_errors: [] });
    expect(await screen.findByTestId('autotriage-summary')).toBeTruthy();
    expect(screen.queryByTestId('autotriage-degraded')).toBeNull();
  });

  it('keeps the last-batch summary when a half-blind sweep still investigated something', async () => {
    // Partial blindness is survivable by design: the readable severities are
    // swept. Replacing the summary with the note alone would under-claim work
    // that really happened — the analyst loses "5 investigated" and cannot tell
    // a partly-degraded sweep from one that read nothing at all.
    await mount({
      ...BASE,
      total: 8,
      hunted: 5,
      degraded: true,
      grid_errors: ['severity critical'],
    });
    expect(await screen.findByTestId('autotriage-degraded')).toBeTruthy();
    expect(screen.getByTestId('autotriage-summary')).toBeTruthy();
    expect(screen.getByText('5')).toBeTruthy();
  });

  it('marks a running sweep degraded too, without hiding its progress', async () => {
    await mount({
      ...BASE,
      active: true,
      total: 4,
      hunted: 1,
      finished_at: null,
      degraded: true,
      grid_errors: ['severity critical'],
    });
    expect(await screen.findByTestId('autotriage-degraded')).toBeTruthy();
    expect(screen.getByText(/tool calls/)).toBeTruthy();
  });
});
