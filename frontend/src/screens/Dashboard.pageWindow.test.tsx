// The owner rule for every page: the time filter on the page filters
// everything on it, unless the screen labels a part otherwise in visible
// words. A hover title is not a label.
//
// The Dashboard broke the rule in five places. The Needs-you lines for leads
// and shadow hits named no scope, and the total mixed four scopes under one
// number with a tooltip only. The shadow-hit tile counted every unread hit
// and its link opened a 7-day block. The recent list ignored the window. The
// tuning nudge counted 7 days of alerts against every verdict on record.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { InvestigationListQuery } from '../lib/api';

const ROW = vi.hoisted(() => ({
  id: 'INV-OLD',
  name: 'ET Old Run',
  kind: 'suricata',
  verdict: 'false_positive',
  conf: 0.9,
  host: '192.0.2.10',
  dst: '198.51.100.7',
  status: 'complete',
  when: '2d ago',
  ts: '2026-10-12T10:00:00+00:00',
  fallback: false,
}));

const page = (rows: unknown[], extra: Record<string, unknown> = {}) => ({
  rows,
  total: rows.length,
  running: 0,
  truePositives: 0,
  totalAll: rows.length,
  active: false,
  limit: 100,
  offset: 0,
  ...extra,
});

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue({ groups: [], truncated: false, other_docs: 0 }),
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  listInvestigations: vi.fn(),
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getHealth: vi.fn().mockResolvedValue(null),
  getDetectionTuningSummary: vi.fn().mockResolvedValue(null),
  getMe: vi.fn().mockResolvedValue({ username: 'ana', role: 'analyst', status: '' }),
  getPreflight: vi.fn().mockResolvedValue({ status: 'green', failing: 0, warned: 0, checked_at: '2026-08-19T00:00:00+00:00' }),
  getPreflightDetail: vi.fn().mockResolvedValue({ rows: [], checked_at: '2026-08-19T00:00:00+00:00' }),
  getShadowHits: vi.fn().mockResolvedValue({ hits: [], unread: 0 }),
  getNeedsYouCount: vi.fn(),
}));

import {
  getAutoTriageStatus,
  getDetectionTuningSummary,
  getNeedsYouCount,
  getShadowHits,
  listInvestigations,
} from '../lib/api';
import { Dashboard } from './Dashboard';

const NEEDS = {
  leads_needing_decision: 2,
  unread_shadow_hits: 3,
  untriaged_groups: 4,
  needs_more_info: 1,
  pending_actions: 5,
  total: 15,
  unknown: [],
  alert_window: '7d',
  verdict_window: '30d',
  alert_floor: false,
};

/** The newest-100 read of the running tile has no window. The recent list
 *  reads the page window. The true-positive tile reads one row. */
const isRecentRead = (q: InvestigationListQuery) => Boolean(q.since) && q.limit !== 1 && !q.verdict;

const mount = () =>
  render(
    <MemoryRouter initialEntries={['/']}>
      <Dashboard />
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getNeedsYouCount).mockResolvedValue(NEEDS);
  vi.mocked(getShadowHits).mockResolvedValue({ hits: [], unread: 0 });
  vi.mocked(getAutoTriageStatus).mockResolvedValue({ active: false, hunted: 0, total: 0 } as never);
  vi.mocked(getDetectionTuningSummary).mockResolvedValue(null as never);
  vi.mocked(listInvestigations).mockReset();
  // Every read holds the one old row: the server applies the window, so the
  // mock answers the windowed read below in each test that needs it.
  vi.mocked(listInvestigations).mockImplementation(async () => page([ROW]) as never);
});

describe('Needs-you tile scope words', () => {
  it('states the scope of every line in visible words', async () => {
    mount();
    expect((await screen.findByTestId('needs-you-line-leads')).textContent).toBe(
      '2 leads wait on a decision · all open',
    );
    expect(screen.getByTestId('needs-you-line-hits').textContent).toBe(
      '3 shadow hits are unread · all unread',
    );
    expect(screen.getByTestId('needs-you-line-alerts').textContent).toBe(
      '4 alert groups have no verdict · last 7 days',
    );
    expect(screen.getByTestId('needs-you-line-nmi').textContent).toBe(
      '1 verdict needs more info · last 30 days',
    );
    expect(screen.getByTestId('needs-you-line-actions').textContent).toBe(
      '5 recommended actions wait for you · last 30 days',
    );
  });

  it('opens the runs with a pending action from the actions line (R1-I1)', async () => {
    // The line opened every true positive of 30 days, a list that did not
    // match its number.
    mount();
    const line = await screen.findByTestId('needs-you-line-actions');
    expect(within(line).getByRole('link').getAttribute('href')).toBe(
      '/investigations?range=30d&actions=pending',
    );
  });

  it('labels the total as the sum of the lines, each with its own scope', async () => {
    mount();
    const total = await screen.findByTestId('needs-you-total');
    await waitFor(() => expect(total.textContent).toBe('15'));
    expect(screen.getByTestId('needs-you-total-scope').textContent).toBe(
      'The sum of the lines below. Each line states its scope.',
    );
  });

  it('names every scope when nothing needs the analyst', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue({
      ...NEEDS,
      leads_needing_decision: 0,
      unread_shadow_hits: 0,
      untriaged_groups: 0,
      needs_more_info: 0,
      pending_actions: 0,
      total: 0,
    });
    mount();
    await screen.findByText('Nothing needs you.');
    expect(screen.getByTestId('needs-you-total-scope').textContent).toBe(
      'The count covers all open leads, all unread shadow hits, alert groups of the last 7 days, and verdicts and actions of the last 30 days.',
    );
  });
});

// Found by the browser pass on a hermetic server: with the grid down and
// every other part zero, the tile read "0+" over one "could not count" line
// and the caption said each line states its scope. No line stated one.
describe('Needs-you tile with no counted line', () => {
  it('names every scope when the only line is a part it could not read', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue({
      ...NEEDS,
      leads_needing_decision: 0,
      unread_shadow_hits: 0,
      untriaged_groups: null,
      needs_more_info: 0,
      pending_actions: 0,
      total: 0,
      unknown: ['untriaged_groups'],
    });
    mount();
    await screen.findByText('Could not count the alert groups. The grid did not answer.');
    expect(screen.getByTestId('needs-you-total-scope').textContent).toBe(
      'The count covers all open leads, all unread shadow hits, alert groups of the last 7 days, and verdicts and actions of the last 30 days.',
    );
  });
});

describe('Shadow-hit tile scope words', () => {
  it('says all unread, and says the link opens the last 7 days', async () => {
    vi.mocked(getShadowHits).mockResolvedValue({ hits: [], unread: 2 });
    mount();
    const tile = await screen.findByTestId('kpi-shadow-hits');
    expect(within(tile).getByText('Shadow hits · all unread')).toBeTruthy();
    const link = within(tile).getByRole('link', { name: 'Read them on Hunts' });
    expect(link.getAttribute('href')).toBe('/hunts?hits=unread#analytic-hits');
  });
});

describe('Recent investigations obey the page window', () => {
  it('reads the list over the page window and names the window when it is empty', async () => {
    vi.mocked(listInvestigations).mockImplementation(async (q: InvestigationListQuery = {}) =>
      (isRecentRead(q) ? page([]) : page([ROW])) as never,
    );
    mount();
    expect(await screen.findByText('No investigations in the last 24 hours.')).toBeTruthy();
    expect(screen.queryByText('ET Old Run')).toBeNull();

    fireEvent.click(screen.getByText('15m'));
    expect(await screen.findByText('No investigations in the last 15 minutes.')).toBeTruthy();
    // The last read of the list named the 15-minute window.
    const recentCalls = vi
      .mocked(listInvestigations)
      .mock.calls.map(([q]) => q ?? {})
      .filter(isRecentRead);
    const since = Date.parse(recentCalls[recentCalls.length - 1].since!);
    expect(Date.now() - since).toBeGreaterThan(14 * 60_000);
    expect(Date.now() - since).toBeLessThan(16 * 60_000);
  });

  it('shows the rows the windowed read returns', async () => {
    mount();
    expect(await screen.findByText('ET Old Run')).toBeTruthy();
  });

  it('keeps the first-run sentence when no investigation exists at all', async () => {
    vi.mocked(listInvestigations).mockImplementation(async () => page([]) as never);
    mount();
    expect(
      await screen.findByText('No investigations yet. Investigate an alert to start one.'),
    ).toBeTruthy();
  });

  it('opens the Investigations list on the same window', async () => {
    mount();
    fireEvent.click(await screen.findByText('7d'));
    await waitFor(() =>
      expect(screen.getByRole('link', { name: /View all/ }).getAttribute('href')).toBe(
        '/investigations?range=7d',
      ),
    );
  });
});

describe('Running tile scope', () => {
  it('keeps its scope words visible while Auto-Investigate runs', async () => {
    vi.mocked(getAutoTriageStatus).mockResolvedValue({ active: true, hunted: 0, total: 3 } as never);
    mount();
    expect(await screen.findByText('Auto-Investigate active')).toBeTruthy();
    expect(screen.getByText('now, of 1 investigation on record')).toBeTruthy();
  });
});

describe('Tuning nudge scope words', () => {
  it('states the window of the alert counts and the scope of the verdicts', async () => {
    vi.mocked(getDetectionTuningSummary).mockResolvedValue({
      pending: 2,
      nominated: 5,
      volume_window: '7d',
    } as never);
    mount();
    expect((await screen.findByTestId('tuning-nudge-scope')).textContent).toBe(
      'Alert counts cover the last 7 days. Verdict counts cover all investigations.',
    );
  });

  it('falls back to 7 days for a backend that sends no window', async () => {
    vi.mocked(getDetectionTuningSummary).mockResolvedValue({ pending: 2 } as never);
    mount();
    expect((await screen.findByTestId('tuning-nudge-scope')).textContent).toBe(
      'Alert counts cover the last 7 days. Verdict counts cover all investigations.',
    );
  });
});
