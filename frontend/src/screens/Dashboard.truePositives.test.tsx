// One tile, three denominators (dogfood 2026-09-07, D4). "True positives · 24h"
// is labelled for a 24-hour window, its number counts DETECTION GROUPS, and its
// subtext counted INVESTIGATION RUNS over thirty days. Read in two tabs at the
// same minute the tile said one and the investigations list said three, and
// nothing on the tile said the two were counting different things.
//
// Every number in the tile now names the unit and the window it answers for.
//
// Dogfood 2026-10-06 (S6): the tile read "0 of 2 detection groups" for 7 days
// while the Investigations list said 15 true positives for the same 7 days.
// The tile now reads the list's own count, from the list's own query.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { AlertGroup, InvestigationList, InvestigationRow, Verdict } from '../lib/types';

const group = (id: string, verdict: Verdict): AlertGroup => ({
  id,
  name: `ET TEST ${id}`,
  kind: 'suricata',
  sev: 'high',
  count: 4,
  verdict,
  conf: verdict === 'untriaged' ? null : 0.8,
  latest: '2m ago',
  inherited: false,
  events: [],
});

// One true positive among three groups: the shape the range was in when the
// tile read "1" beside a 24h investigations list reading "3 true positives".
const GROUPS: [string, Verdict][] = [
  ['g-tp', 'true_positive'],
  ['g-fp', 'false_positive'],
  ['g-nmi', 'needs_more_info'],
];

const listInvestigations = vi.hoisted(() => vi.fn());

const empty = (): InvestigationList => ({
  rows: [] as InvestigationRow[],
  total: 0,
  running: 0,
  truePositives: 0,
  totalAll: 0,
  active: false,
  limit: 100,
  offset: 0,
});

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue({ groups: [], truncated: false, other_docs: 0 }),
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  listInvestigations,
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getHealth: vi.fn().mockResolvedValue(null),
  getDetectionTuningSummary: vi.fn().mockResolvedValue(null),
  getMe: vi.fn().mockResolvedValue({ username: 'ana', role: 'analyst', status: '' }),
  getPreflight: vi.fn().mockResolvedValue({ status: 'green', failing: 0, warned: 0, checked_at: '2026-08-19T00:00:00+00:00' }),
  getPreflightDetail: vi.fn().mockResolvedValue({ rows: [], checked_at: '2026-08-19T00:00:00+00:00' }),
}));

import { queueOf } from '../test/alertQueue';
import { Dashboard } from './Dashboard';
import { getAlerts } from '../lib/api';

const fallback = (id: string): InvestigationRow => ({
  id,
  name: `Run ${id}`,
  kind: 'suricata',
  verdict: 'needs_more_info',
  conf: 0.3,
  host: '192.0.2.10',
  status: 'complete',
  when: '2d ago',
  ts: '2026-08-20T10:00:00+00:00',
  alertId: `ev-${id}`,
  isPrimary: true,
  fallback: true,
});

/** The list query of the tile: a window and one row, no verdict filter. */
const isTileQuery = (q: { verdict?: string[]; limit?: number; since?: string } = {}) =>
  !q.verdict?.length && q.limit === 1 && !!q.since;

const mount = async (pipelineErrors: InvestigationRow[] = []) => {
  vi.mocked(getAlerts).mockResolvedValue(queueOf(GROUPS.map(([id, v]) => group(id, v))));
  listInvestigations.mockImplementation(async (q: { verdict?: string[]; limit?: number; since?: string } = {}) =>
    q.verdict?.length
      ? { ...empty(), rows: pipelineErrors, total: pipelineErrors.length }
      : isTileQuery(q)
        ? { ...empty(), total: 37, truePositives: 15 }
        : empty(),
  );
  render(
    <MemoryRouter>
      <Dashboard />
    </MemoryRouter>,
  );
  await screen.findByText('Investigation outcomes');
};

/** The whole true-positives tile (the Panel), located from its label. */
const tpTile = async () =>
  (await screen.findByText('True positives · 24h')).closest('.rounded-panel')!;

describe('Dashboard true-positives tile — every number answers one question', () => {
  it('reads the count of the Investigations list query, over the window', async () => {
    await mount();
    const tile = await tpTile();
    // 15 true positives among 37 investigations: the list's own header count.
    await waitFor(() => expect(tile.textContent).toContain('15'));
    expect(tile.textContent).toContain('of 37 investigations');
    const query = listInvestigations.mock.calls.map((c) => c[0]).find(isTileQuery);
    expect(query).toBeTruthy();
    // The 24h window, as the list computes it.
    const since = Date.parse(query.since);
    expect(Math.abs(Date.now() - since - 24 * 3_600_000)).toBeLessThan(60_000);
  });

  it('links to the list it counts, with the window and the verdict filter', async () => {
    await mount();
    const tile = await tpTile();
    await waitFor(() => expect(tile.textContent).toContain('Open them'));
    const link = screen.getByRole('link', { name: 'Open them' });
    expect(link.getAttribute('href')).toBe('/investigations?range=24h&verdict=true_positive');
  });

  it('reads the new window when the range changes', async () => {
    await mount();
    await tpTile();
    fireEvent.click(screen.getByText('7d'));
    expect(await screen.findByText('True positives · 7d')).toBeTruthy();
    await waitFor(() => {
      const sinces = listInvestigations.mock.calls
        .map((c) => c[0])
        .filter(isTileQuery)
        .map((q) => Date.now() - Date.parse(q.since));
      expect(sinces.some((ms) => Math.abs(ms - 7 * 86_400_000) < 60_000)).toBe(true);
    });
  });

  // NEGATIVE CONTROL. The alert groups in the window no longer decide the
  // tile. The outcomes chart still counts them, on its own unit.
  it('does not count alert groups', async () => {
    await mount();
    const tile = await tpTile();
    await waitFor(() => expect(tile.textContent).toContain('15'));
    expect(tile.textContent).not.toContain('detection groups');
  });

  it('labels the pipeline-error clause with its OWN window and unit', async () => {
    await mount([fallback('fb1'), fallback('fb2')]);
    const tile = await tpTile();
    // It counts investigation runs over thirty days, which is neither the unit
    // nor the window in the tile's heading, so it says so. The clause waits for
    // its own read.
    await waitFor(() => expect(tile.textContent).toMatch(/runs, last 30 days/i));
    expect(await screen.findByRole('button', { name: '2 pipeline errors' })).toBeTruthy();
  });

  it('says nothing about a 30-day window when there is nothing to say', async () => {
    await mount();
    const tile = await tpTile();
    expect(tile.textContent).not.toMatch(/30 days/);
  });
});
