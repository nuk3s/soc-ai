// The Dashboard's "N pipeline errors" KPI must be THE SAME QUERY its deep link
// opens (?verdict=pipeline_error over the 30d widening). It used to count
// fallbacks in the newest-100 unfiltered sample: once the Investigations list
// became a real server-side query, the list told the truth (19 fallbacks in 30d
// on production) while the tile still read 0 — a dashboard count and its
// click-through disagreeing, in the direction that teaches an operator to stop
// looking. The seeded shape below reproduces that: zero fallbacks in the recent
// sample, several in the older match set.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { InvestigationList, InvestigationRow } from '../lib/types';

const inv = (id: string, over: Partial<InvestigationRow> = {}): InvestigationRow => ({
  id,
  name: `Run ${id}`,
  kind: 'suricata',
  verdict: 'false_positive',
  conf: 0.9,
  host: '192.0.2.10',
  dst: '198.51.100.7',
  status: 'complete',
  when: '1h ago',
  ts: '2026-08-08T10:00:00+00:00',
  alertId: `ev-${id}`,
  isPrimary: true,
  fallback: false,
  ...over,
});

const envelope = (rows: InvestigationRow[], total = rows.length): InvestigationList => ({
  rows,
  total,
  running: 0,
  truePositives: 0,
  totalAll: 200,
  active: false,
  limit: rows.length || 50,
  offset: 0,
});

// The recent sample: completed FPs only — the saturated page that made the old
// tile read zero.
const RECENT = [inv('r1'), inv('r2'), inv('r3')];

// The deep link's match set, all older than the recent sample: two LIVE
// fallbacks, one the operator dismissed, one superseded by a later run. The
// tile counts the live two — dismiss and supersede semantics are the KPI's
// documented exclusions (livePipelineErrors) and must survive the move.
const FB = (id: string, over: Partial<InvestigationRow> = {}) =>
  inv(id, { verdict: 'needs_more_info', conf: 0.3, fallback: true, ts: '2026-07-20T10:00:00+00:00', ...over });
const FALLBACKS = [
  FB('fb1'),
  FB('fb2'),
  FB('fb3', { errorDismissed: true }),
  FB('fb4', { isPrimary: false }),
];

const listInvestigations = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue([]),
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  listInvestigations,
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getHealth: vi.fn().mockResolvedValue(null),
}));

import { Dashboard } from './Dashboard';

describe('Dashboard pipeline-error KPI', () => {
  it('counts the deep-link query, not the recent sample', async () => {
    listInvestigations.mockImplementation(async (q: { verdict?: string[] } = {}) =>
      q.verdict?.length ? envelope(FALLBACKS) : envelope(RECENT),
    );
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    );
    // Live fallbacks = 2 (dismissed + superseded excluded) even though the
    // recent sample holds ZERO fallbacks — the old newest-100 tally read 0 here.
    expect(await screen.findByRole('button', { name: '2 pipeline errors' })).toBeTruthy();

    // And the number is the DESTINATION's query: same verdict filter, same 30d
    // widening the deep-linked screen applies (Investigations.test pins the
    // screen's side of this handshake).
    const call = listInvestigations.mock.calls.find((c) => c[0]?.verdict?.length)?.[0];
    expect(call.verdict).toEqual(['pipeline_error']);
    const age = Date.now() - new Date(call.since).getTime();
    expect(age).toBeGreaterThan(29 * 86_400_000);
    expect(age).toBeLessThan(31 * 86_400_000);
  });

  it('hides the tile when the deep-link query has no live fallbacks', async () => {
    listInvestigations.mockImplementation(async (q: { verdict?: string[] } = {}) =>
      q.verdict?.length
        ? envelope([FB('fb3', { errorDismissed: true })])
        : envelope(RECENT),
    );
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    );
    await screen.findByText('Run r1');
    expect(screen.queryByText(/pipeline error/)).toBeNull();
  });

  // The KPI counts rows, because its two exclusions (dismissed, superseded)
  // are per-row facts SQL does not carry — so it can only ever count as far as
  // the page reaches. The server caps a page at 500, and a multi-hour gateway
  // outage against auto-triage produces fallbacks in the hundreds, so the cap
  // is reachable. Past it the tile must say it is a floor: an unmarked "500"
  // beside a list header reading "1–500 of 812" is the tile disagreeing with
  // its own click-through again, just quieter.
  it('marks the count as a floor when the match set overflows the page', async () => {
    const many = Array.from({ length: 500 }, (_, i) => FB(`fb${i}`));
    listInvestigations.mockImplementation(async (q: { verdict?: string[] } = {}) =>
      q.verdict?.length ? envelope(many, 812) : envelope(RECENT),
    );
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    );
    const link = await screen.findByRole('button', { name: '500+ pipeline errors' });
    // And the "+" is explained where the operator can see it, not left to guess.
    expect(link.getAttribute('title')).toMatch(/at least/i);
  });

  it('leaves the count unmarked when the whole match set fits on the page', async () => {
    listInvestigations.mockImplementation(async (q: { verdict?: string[] } = {}) =>
      // total counts the dismissed and superseded rows the KPI excludes, so
      // total > live-count is NORMAL and must not be mistaken for truncation.
      q.verdict?.length ? envelope(FALLBACKS) : envelope(RECENT),
    );
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    );
    expect(await screen.findByRole('button', { name: '2 pipeline errors' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: /\+ pipeline error/ })).toBeNull();
  });
});
