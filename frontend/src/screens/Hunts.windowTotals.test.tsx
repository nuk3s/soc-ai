// The Hunts header said "100 hunts" over a window of 140. The header, the
// section badge and the active type chip counted the rows of GET /hunts, and
// that route caps a page at 100 rows. The counts now come from GET
// /hunts/totals, which counts the whole window. When that read fails and the
// page is full, the counts say "100+".
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DemoProvider } from '../lib/demo';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunts: vi.fn(),
  getHuntTotals: vi.fn(),
  getHuntStats: vi.fn().mockResolvedValue([{ label: 'Hunts', value: '140' }]),
  getHuntTemplates: vi.fn().mockResolvedValue([]),
  getHuntSchedules: vi.fn().mockResolvedValue({ schedules: [], masterSwitchEnabled: true }),
  listSavedViews: vi.fn().mockResolvedValue([]),
  getShadowHits: vi.fn().mockResolvedValue({ hits: [], unread: 0 }),
  getAnalytics: vi.fn().mockResolvedValue({ analytics: [], counts: {} }),
  getAnalytic: vi.fn(),
  getAnalyticHits: vi.fn().mockResolvedValue({
    hits: [],
    counts: { all: 0, unread: 0, live: 0, shadow: 0 },
  }),
  getNeedsYou: vi
    .fn()
    .mockResolvedValue({ unread_shadow_hits: 0, leads_needing_decision: 0, total: 0 }),
  getLeads: vi.fn().mockResolvedValue([]),
  getHuntCatalog: vi.fn().mockResolvedValue({
    specs: [],
    sweeps_enabled: true,
    sweep_interval_minutes: 60,
    sweep_window_minutes: 61,
    last_sweep_at: null,
  }),
}));

import { getHunts, getHuntTotals, type HuntTotals, type HuntsQuery } from '../lib/api';
import type { HuntKind, HuntRow } from '../lib/types';
import { ShellProvider } from '../shell/ShellContext';
import { Hunts } from './Hunts';

const row = (n: number, kind: HuntKind): HuntRow => ({
  id: `h-${kind}-${n}`,
  objective: `${kind} hunt ${n}`,
  kind,
  status: 'complete',
  findingCount: 1,
  threatFindingCount: 0,
  affectedHosts: 0,
  confidence: null,
  startedBy: 'alice',
  when: '1h',
  ts: '2026-10-14T06:00:00Z',
});

/** A full page: the 100 newest of the window, catalog runs first. */
const PAGE: HuntRow[] = [
  ...Array.from({ length: 90 }, (_, n) => row(n, 'triggered')),
  ...Array.from({ length: 10 }, (_, n) => row(n, 'chat')),
];

const TOTALS: HuntTotals = {
  hunts: 140,
  findings: 170,
  threat_findings: 40,
  running: 10,
  by_kind: {
    chat: { hunts: 40, findings: 80, threat_findings: 40, running: 0 },
    scheduled: { hunts: 10, findings: 0, threat_findings: 0, running: 10 },
    triggered: { hunts: 90, findings: 90, threat_findings: 0, running: 0 },
  },
};

const BADGE_TITLE = 'The hunts in the window and the type on screen.';

function renderHunts() {
  return render(
    <MemoryRouter initialEntries={['/hunts']}>
      <DemoProvider demo={false}>
        <ShellProvider>
          <Routes>
            <Route path="/hunts" element={<Hunts />} />
          </Routes>
        </ShellProvider>
      </DemoProvider>
    </MemoryRouter>,
  );
}

/** A type chip: the one outside the leads strip and the hits block. */
const chip = (label: string) => {
  const strip = screen.queryByTestId('leads-strip');
  const hits = document.getElementById('analytic-hits');
  const el = screen.getAllByText(label).find((c) => !strip?.contains(c) && !hits?.contains(c))!;
  return el.closest('button')!;
};

beforeEach(() => {
  vi.mocked(getHunts).mockReset();
  vi.mocked(getHuntTotals).mockReset();
  vi.mocked(getHunts).mockImplementation(async (q?: HuntsQuery) =>
    q?.kind ? PAGE.filter((h) => h.kind === q.kind) : PAGE,
  );
  vi.mocked(getHuntTotals).mockResolvedValue(TOTALS);
});

describe('Hunts window totals', () => {
  it('counts the whole window in the header, past the page cap', async () => {
    renderHunts();
    const line = await screen.findByTestId('hunt-stats-line');
    await waitFor(() => expect(line.textContent).toContain('140 hunts'));
    expect(line.textContent).toContain('(40 manual, 10 scheduled, 90 catalog)');
    expect(line.textContent).toContain('170 findings');
    expect(line.textContent).toContain('10 in progress');
    expect(screen.getByTitle(BADGE_TITLE).textContent).toBe('140');
  });

  it('says the table shows the newest page of a larger window', async () => {
    renderHunts();
    expect(
      (await screen.findByTestId('hunts-page-note')).textContent,
    ).toBe('The table shows the 100 newest of 140 hunts in this window.');
  });

  it('reads the totals over the window the list reads', async () => {
    renderHunts();
    await screen.findByTestId('hunts-page-note');
    const listQuery = vi.mocked(getHunts).mock.calls[0][0]!;
    const totalsQuery = vi.mocked(getHuntTotals).mock.calls[0][0]!;
    // Each loader anchors "now" on its own, so the two bounds can differ by
    // the milliseconds between the two calls.
    expect(Math.abs(Date.parse(totalsQuery.since!) - Date.parse(listQuery.since!))).toBeLessThan(
      1000,
    );
    // The default 7 day window: a preset sends no upper bound.
    expect(Date.now() - Date.parse(totalsQuery.since!)).toBeGreaterThan(6.9 * 86_400_000);
    expect(totalsQuery.until).toBe(listQuery.until);
  });

  it('counts the type on screen from the totals of that type', async () => {
    renderHunts();
    const line = await screen.findByTestId('hunt-stats-line');
    await waitFor(() => expect(line.textContent).toContain('140 hunts'));
    fireEvent.click(chip('Manual'));
    await waitFor(() => expect(line.textContent).toContain('40 hunts'));
    expect(line.textContent).toContain('80 findings');
    expect(line.textContent).not.toContain('(');
    expect(chip('Manual').textContent).toBe('Manual40');
    expect(screen.getByTitle(BADGE_TITLE).textContent).toBe('40');
    // The page holds 10 manual hunts of the 40.
    expect(screen.getByTestId('hunts-page-note').textContent).toBe(
      'The table shows the 10 newest of 40 hunts in this window.',
    );
  });

  it('says 100+ when the totals are not available and the page is full', async () => {
    vi.mocked(getHuntTotals).mockRejectedValue(new Error('404'));
    renderHunts();
    const line = await screen.findByTestId('hunt-stats-line');
    await waitFor(() => expect(line.textContent).toContain('100+ hunts'));
    expect(line.textContent).toContain('100+ findings');
    expect(screen.getByTitle(BADGE_TITLE).textContent).toBe('100+');
    fireEvent.click(chip('All'));
    expect(chip('All').textContent).toBe('All100+');
    expect(screen.queryByTestId('hunts-page-note')).toBeNull();
  });

  // R3-D6 and R3-D7, on the page path: the header counts what the cells state.
  it('counts no failure marker and every hunt in progress from the page', async () => {
    vi.mocked(getHuntTotals).mockRejectedValue(new Error('404'));
    const failed = (n: number): HuntRow => ({
      ...row(n, 'triggered'),
      outcome: 'could_not_run',
      outcome_label: 'Could not run',
    });
    vi.mocked(getHunts).mockResolvedValue([
      failed(1),
      failed(2),
      failed(3),
      { ...row(4, 'lead'), status: 'investigating', findingCount: 2, threatFindingCount: 2 },
      { ...row(5, 'chat'), findingCount: 2, threatFindingCount: 1 },
    ]);
    renderHunts();
    const line = await screen.findByTestId('hunt-stats-line');
    await waitFor(() => expect(line.textContent).toContain('5 hunts'));
    expect(line.textContent).toContain('4 findings');
    expect(line.textContent).toContain('1 in progress');
  });

  it('keeps the page counts when the totals fail and the page is not full', async () => {
    vi.mocked(getHuntTotals).mockRejectedValue(new Error('404'));
    vi.mocked(getHunts).mockResolvedValue(PAGE.slice(0, 3));
    renderHunts();
    const line = await screen.findByTestId('hunt-stats-line');
    await waitFor(() => expect(line.textContent).toContain('3 hunts'));
    expect(line.textContent).not.toContain('+');
    expect(screen.getByTitle(BADGE_TITLE).textContent).toBe('3');
  });
});
