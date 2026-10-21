// Two false statements on the Dashboard (dogfood 2026-10-06).
//
// A slow grid read as a down one: the headline said "not reachable" in red
// over the probe's own line "answered in 4.3 s, budget 5 s", and the tiles
// under it still said "queue clear". A probe that answered inside its budget
// now reads amber, "Elasticsearch is slow. Counts can be late.", and every
// tile that reads the grid says it may be incomplete.
//
// A window not yet read read as an empty one: the tiles showed "0 · No alerts
// in the last 30d" while the 30d read ran, for a window with 388 groups. A
// count of a window that is still being read is "…".
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AlertGroup, Verdict } from '../lib/types';
import type { AlertQueue, Health } from '../lib/api';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn(),
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  listInvestigations: vi.fn().mockResolvedValue({
    rows: [], total: 0, running: 0, truePositives: 0, totalAll: 0, active: false, limit: 100, offset: 0,
  }),
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getHealth: vi.fn(),
  getDetectionTuningSummary: vi.fn().mockResolvedValue(null),
  getMe: vi.fn().mockResolvedValue({ username: 'ana', role: 'analyst', status: '' }),
  getPreflight: vi.fn().mockResolvedValue({ status: 'green', failing: 0, warned: 0, checked_at: '2026-10-06T00:00:00+00:00' }),
  getPreflightDetail: vi.fn().mockResolvedValue({ rows: [], checked_at: '2026-10-06T00:00:00+00:00' }),
  getNeedsYouCount: vi.fn().mockResolvedValue({
    leads_needing_decision: 1,
    unread_shadow_hits: 0,
    untriaged_groups: 0,
    needs_more_info: 0,
    pending_actions: 0,
    total: 1,
    unknown: [],
    alert_window: '7d',
    verdict_window: '30d',
    alert_floor: false,
  }),
}));

import { queueOf } from '../test/alertQueue';
import { getAlerts, getHealth } from '../lib/api';
import { Dashboard } from './Dashboard';

const group = (id: string, verdict: Verdict, count = 2): AlertGroup => ({
  id,
  name: `ET TEST ${id}`,
  kind: 'suricata',
  sev: 'high',
  count,
  verdict,
  conf: verdict === 'untriaged' ? null : 0.8,
  latest: '2m ago',
  inherited: false,
  events: [],
});

const health = (es: { ok: boolean; detail: string; kind?: string; state?: string }): Health =>
  ({ es, llm: { ok: true, detail: 'up' }, so: { ok: true, detail: 'up' } }) as Health;

const mount = async () => {
  render(
    <MemoryRouter initialEntries={['/']}>
      <Dashboard />
    </MemoryRouter>,
  );
  await screen.findByText('Investigation outcomes');
};

beforeEach(() => {
  vi.mocked(getAlerts).mockResolvedValue(queueOf([group('a', 'untriaged')]));
  vi.mocked(getHealth).mockResolvedValue(health({ ok: true, detail: 'up' }));
});

describe('Dashboard on a slow grid', () => {
  it('reads a probe that answered inside its budget as slow, in amber', async () => {
    vi.mocked(getHealth).mockResolvedValue(
      health({
        ok: false,
        kind: 'slow',
        state: 'slow',
        detail: 'Elasticsearch answered the probe in 4.3 s. The budget is 5 s. soc-ai treats it as slow.',
      }),
    );
    await mount();
    const banner = await screen.findByRole('alert');
    expect(banner.textContent).toContain('The grid is slow. Counts can be late.');
    expect(banner.textContent).not.toContain('not reachable');
    expect(banner.getAttribute('data-tone')).toBe('warn');
    // The tiles that read the grid say so.
    await waitFor(() => expect(screen.getAllByTestId('tile-incomplete').length).toBeGreaterThanOrEqual(2));
  });

  it('keeps red for a probe that did not answer', async () => {
    vi.mocked(getHealth).mockResolvedValue(
      health({ ok: false, kind: 'timeout', state: 'slow', detail: 'Elasticsearch did not answer the probe in 5 s.' }),
    );
    await mount();
    const banner = await screen.findByRole('alert');
    expect(banner.getAttribute('data-tone')).toBe('danger');
    expect(banner.textContent).not.toContain('Counts can be late');
    await waitFor(() => expect(screen.getAllByTestId('tile-incomplete').length).toBeGreaterThanOrEqual(2));
  });

  // NEGATIVE CONTROL. A healthy grid marks nothing.
  it('marks no tile on a healthy grid', async () => {
    await mount();
    await screen.findByText('1 detection group');
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.queryByTestId('tile-incomplete')).toBeNull();
  });
});

describe('Dashboard while a new window is read', () => {
  it('shows "counting" for every grid count, never the old window and never a zero', async () => {
    await mount();
    await screen.findByText('1 detection group');

    // The 30d read does not answer yet.
    let answer: (q: AlertQueue) => void = () => {};
    vi.mocked(getAlerts).mockReturnValue(new Promise<AlertQueue>((resolve) => (answer = resolve)));
    await act(async () => {
      fireEvent.click(screen.getByText('30d'));
    });

    const events = screen.getByText(/^Alert events/).parentElement!.parentElement!;
    expect(events.textContent).toContain('counting');
    expect(events.textContent).not.toMatch(/\d+ detection group/);
    expect(screen.getByText('Loading the last 30d window')).toBeTruthy();
    expect(screen.queryByText(/No alerts in the last 30d/)).toBeNull();

    // The answer lands: the counts are the new window's.
    await act(async () => {
      answer(queueOf([group('a', 'untriaged'), group('b', 'false_positive'), group('c', 'false_positive')]));
    });
    await waitFor(() => expect(screen.getAllByText('3 detection groups').length).toBeGreaterThan(0));
    expect(screen.queryByText('Loading the last 30d window')).toBeNull();
  });

  // NEGATIVE CONTROL. A background poll of the same window keeps its counts on
  // screen. Only a different window blanks them.
  it('keeps the counts through a poll of the same window', async () => {
    await mount();
    await screen.findByText('1 detection group');
    vi.mocked(getAlerts).mockReturnValue(new Promise<AlertQueue>(() => {}));
    expect(screen.getByText('1 detection group')).toBeTruthy();
    expect(screen.queryByText(/Loading the last/)).toBeNull();
  });
});
