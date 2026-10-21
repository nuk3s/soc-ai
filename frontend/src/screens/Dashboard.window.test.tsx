// The Dashboard window and its links (dogfood 2026-10-19, R1). The window was
// component state, so Back reset it to 24 hours (D22). "Open them" and "View
// all" opened a different window from the tile (D7). The live mark never
// changed (D10). The True positives tile, which reads the store, said "May be
// incomplete" in a grid outage (D26). The outcomes panel named no clock (D9).
// The Auto-Investigate panel dated nothing (D11).
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AlertQuery } from '../lib/api';

const page = (extra: Record<string, unknown> = {}) => ({
  rows: [],
  total: 0,
  running: 0,
  truePositives: 0,
  totalAll: 0,
  active: false,
  limit: 100,
  offset: 0,
  ...extra,
});

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn(),
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  listInvestigations: vi.fn(),
  getAutoTriageStatus: vi.fn(),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getHealth: vi.fn(),
  getDetectionTuningSummary: vi.fn().mockResolvedValue(null),
  getMe: vi.fn().mockResolvedValue({ username: 'ana', role: 'analyst', status: '' }),
  getPreflight: vi.fn().mockResolvedValue({ status: 'green', failing: 0, warned: 0, checked_at: '2026-08-19T00:00:00+00:00' }),
  getPreflightDetail: vi.fn().mockResolvedValue({ rows: [], checked_at: '2026-08-19T00:00:00+00:00' }),
  getShadowHits: vi.fn().mockResolvedValue({ hits: [], unread: 0 }),
  getNeedsYouCount: vi.fn().mockResolvedValue({
    leads_needing_decision: 0,
    unread_shadow_hits: 0,
    untriaged_groups: 0,
    needs_more_info: 0,
    pending_actions: 0,
    total: 0,
    unknown: [],
    alert_window: '7d',
    verdict_window: '30d',
    alert_floor: false,
  }),
}));

import { getAlerts, getAutoTriageStatus, getHealth, listInvestigations } from '../lib/api';
import { Dashboard } from './Dashboard';

function Where() {
  const loc = useLocation();
  return <div data-testid="where">{loc.pathname + loc.search}</div>;
}

const mount = (url = '/dashboard') =>
  render(
    <MemoryRouter initialEntries={[url]}>
      <Dashboard />
      <Where />
    </MemoryRouter>,
  );

const lastAlertQuery = (): AlertQuery => {
  const calls = vi.mocked(getAlerts).mock.calls;
  return calls[calls.length - 1][0] as AlertQuery;
};

beforeEach(() => {
  vi.mocked(getAlerts).mockReset().mockResolvedValue({ groups: [], truncated: false, other_docs: 0 });
  vi.mocked(listInvestigations).mockReset().mockResolvedValue(page() as never);
  vi.mocked(getAutoTriageStatus).mockReset().mockResolvedValue({ active: false, hunted: 0, total: 0 } as never);
  vi.mocked(getHealth).mockReset().mockResolvedValue(null as never);
});

describe('the window in the URL (D22)', () => {
  it('opens on the window the URL names', async () => {
    mount('/dashboard?range=7d');
    await waitFor(() => expect(lastAlertQuery()).toEqual({ range: '7d' }));
    expect(screen.getByText('Counts for the last 7 days')).toBeTruthy();
  });

  it('opens on a custom window from the URL', async () => {
    mount('/dashboard?range=custom&from=2026-10-08T00:00&to=2026-10-09T00:00');
    await waitFor(() =>
      expect(lastAlertQuery()).toEqual({ range: 'custom', from: '2026-10-08T00:00', to: '2026-10-09T00:00' }),
    );
  });

  it('writes a picked window into the URL', async () => {
    mount('/dashboard');
    await screen.findByText('Counts for the last 24 hours');
    fireEvent.click(screen.getByRole('button', { name: '3d' }));
    await waitFor(() => expect(screen.getByTestId('where').textContent).toBe('/dashboard?range=3d'));
    await waitFor(() => expect(lastAlertQuery()).toEqual({ range: '3d' }));
  });

  it('reads a bad window as 24 hours', async () => {
    mount('/dashboard?range=forever');
    await waitFor(() => expect(lastAlertQuery()).toEqual({ range: '24h' }));
  });
});

describe('the links carry the window (D7)', () => {
  it('"Open them" and "View all" name the preset window', async () => {
    mount('/dashboard?range=7d');
    const open = await screen.findByRole('link', { name: 'Open them' });
    expect(open.getAttribute('href')).toBe('/investigations?range=7d&verdict=true_positive');
    expect(screen.getByRole('link', { name: /View all/ }).getAttribute('href')).toBe('/investigations?range=7d');
  });

  it('a custom window travels with its bounds', async () => {
    mount('/dashboard?range=custom&from=2026-10-08T00:00&to=2026-10-09T00:00');
    const open = await screen.findByRole('link', { name: 'Open them' });
    const p = new URLSearchParams(open.getAttribute('href')!.split('?')[1]);
    expect(p.get('range')).toBe('custom');
    expect(p.get('from')).toBe('2026-10-08T00:00');
    expect(p.get('to')).toBe('2026-10-09T00:00');
    expect(p.get('verdict')).toBe('true_positive');
  });
});

describe('the live mark (D10)', () => {
  it('says live while the alert counts read', async () => {
    mount();
    expect((await screen.findByTestId('live-mark')).textContent).toBe('live');
  });

  it('says the counts stopped when the alert read fails', async () => {
    vi.mocked(getAlerts).mockRejectedValue(new Error('grid down'));
    mount();
    await waitFor(() => expect(screen.getByTestId('live-mark').textContent).toBe('not updating'));
  });
});

describe('the store-read tiles in a grid outage (D26)', () => {
  it('marks the grid tiles and leaves the True positives tile clean', async () => {
    vi.mocked(getHealth).mockResolvedValue({
      es: { ok: false, detail: 'refused' },
      llm: { ok: true, detail: 'ok' },
      so: { ok: true, detail: 'ok' },
    } as never);
    mount();
    await waitFor(() => expect(screen.getAllByTestId('tile-incomplete').length).toBeGreaterThanOrEqual(2));
    const tp = screen.getByText('True positives · 24h').closest('div.px-4') as HTMLElement;
    expect(within(tp).queryByTestId('tile-incomplete')).toBeNull();
    // The banner names the grid with the one term.
    expect(screen.getByRole('alert').textContent).toContain('The grid is not reachable.');
  });
});

describe('the clocks (D9)', () => {
  it('names the clock of the chart and of the tile', async () => {
    mount();
    expect((await screen.findByTestId('outcomes-clock')).textContent).toMatch(
      /alert groups with an alert in this window.*investigations that started in this window/,
    );
    expect((await screen.findByTestId('tp-clock')).textContent).toBe('started in this window');
  });
});

describe('the Auto-Investigate times (D11)', () => {
  const at = new Date(Date.now() - 23 * 60_000).toISOString();

  it('dates the last batch', async () => {
    vi.mocked(getAutoTriageStatus).mockResolvedValue({
      active: false, hunted: 0, skipped: 0, failed: 0, total: 0, finished_at: at,
    } as never);
    mount();
    const t = await screen.findByTestId('autotriage-last-batch-time');
    expect(t.getAttribute('dateTime')).toBe(at);
    expect(t.getAttribute('title')).toBe('23 minutes ago');
  });

  it('dates a degraded sweep', async () => {
    vi.mocked(getAutoTriageStatus).mockResolvedValue({
      active: false, hunted: 0, skipped: 0, failed: 0, total: 0, finished_at: at,
      degraded: true, grid_errors: ['severity high'],
    } as never);
    mount();
    const note = await screen.findByTestId('autotriage-degraded');
    expect(note.textContent).toContain('could not read the grid for 1 of its queries');
    expect(within(note).getByTestId('autotriage-degraded-time').getAttribute('dateTime')).toBe(at);
  });

  it('says no batch has run', async () => {
    mount();
    expect(await screen.findByText('No Auto-Investigate batch has run since soc-ai started.')).toBeTruthy();
  });
});

describe('the page title and the running scope', () => {
  it('reads Dashboard and names the scope of the running count', async () => {
    mount();
    expect(await screen.findByRole('heading', { name: 'Dashboard' })).toBeTruthy();
    // "of all 0" read as a fragment (H1-D24). V1-S8: "0 of 36 investigations"
    // under a 24h page named no window. The count is of now, over every run
    // on record, and the words say so.
    expect(await screen.findByText('now, of 0 investigations on record')).toBeTruthy();
  });
});
