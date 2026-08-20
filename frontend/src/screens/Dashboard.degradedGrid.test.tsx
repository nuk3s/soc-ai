// The Dashboard's account of the grid must match the grid (dogfood 2026-08-14).
//
// Two independent false claims lived on this screen at once. The
// awaiting-investigation tile printed an honest "—" for its value and then
// "queue clear" underneath it, in all four degraded states — "—" says unknown
// and "queue clear" says safe, and during an outage those are opposite
// statements. And the connection banner announced a grid answering 429 as "not
// reachable" directly above its own circuit-breaker detail line, sending the
// analyst to check connectivity and firewalls when the grid was up and shedding
// load.
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AlertGroup, Verdict } from '../lib/types';
import type { Health } from '../lib/api';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue([]),
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  listInvestigations: vi.fn().mockResolvedValue({
    rows: [], total: 0, running: 0, truePositives: 0, totalAll: 0, active: false, limit: 100, offset: 0,
  }),
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
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
import { getAlerts, getHealth } from '../lib/api';

const mount = async () => {
  render(
    <MemoryRouter initialEntries={['/']}>
      <Dashboard />
    </MemoryRouter>,
  );
  await screen.findByText('Investigation outcomes');
};

/** The whole KPI card, so the assertions cover its value AND its caption —
 *  the defect was the two disagreeing with each other. */
const awaitingTile = async (): Promise<HTMLElement> => {
  const label = await screen.findByText('Awaiting investigation');
  return label.parentElement!.parentElement!;
};

/** Same card, read synchronously — for the fake-timer suite, which settles the
 *  render itself and must not hand control back to a real-clock wait. */
const awaitingTileNow = (): HTMLElement =>
  screen.getByText('Awaiting investigation').parentElement!.parentElement!;

const untriagedGroup: AlertGroup = {
  id: 'g-unt',
  name: 'ET TEST untriaged',
  kind: 'suricata',
  sev: 'high',
  count: 3,
  verdict: 'untriaged' as Verdict,
  conf: null,
  latest: '2m ago',
  inherited: false,
  events: [],
};

beforeEach(() => {
  vi.mocked(getAlerts).mockResolvedValue([]);
  vi.mocked(getHealth).mockResolvedValue(null as unknown as Health);
});

describe('Dashboard awaiting-investigation tile — unknown is not zero', () => {
  it('does not call the queue clear when the read that would prove it failed', async () => {
    vi.mocked(getAlerts).mockRejectedValue(new Error('grid_unavailable'));
    await mount();
    const tile = await awaitingTile();
    // The string this whole exercise exists to catch. Asserting the em-dash
    // value instead would pass today: the VALUE was already honest.
    expect(tile.textContent).not.toContain('queue clear');
    // …and no number is asserted either, since none was read.
    expect(tile.textContent).not.toMatch(/\d/);
  });

  it('still says queue clear when the queue really was read and really is empty', async () => {
    await mount();
    const tile = await awaitingTile();
    expect(tile.textContent).toContain('queue clear');
  });

  it('still offers the hand-triage link when a group really is waiting', async () => {
    vi.mocked(getAlerts).mockResolvedValue([untriagedGroup]);
    await mount();
    expect(await screen.findByText(/triage from Alerts/i)).toBeTruthy();
  });

  it('keeps the calm caption when the probe is degraded but this read succeeded', async () => {
    // The over-correction control, and a deliberate NON-implementation: the
    // caption is keyed on the alerts read, never on /health. The probe reads an
    // unfiltered match_all across the whole index pattern precisely so a cold
    // red shard cannot be skipped, while these counts come from a time-filtered
    // query that may never touch it — so "probe partial, alerts complete" is the
    // expected state for one old red shard, not a corner case. A successful
    // alerts read has proved itself (the client raises on any search whose
    // shards failed), so the count is a complete answer to the question asked.
    // Disclaiming it would leave the screen permanently uncertain on a grid the
    // analyst can in fact read.
    vi.mocked(getHealth).mockResolvedValue(
      health({ ok: false, kind: 'partial', detail: 'the grid read only 2 of 4 shards' }),
    );
    vi.mocked(getAlerts).mockResolvedValue([]);
    await mount();
    expect((await awaitingTile()).textContent).toContain('queue clear');
  });
});

// `kind` is carried by /health (routes_meta.HealthComponentOut) but is not on
// the shared HealthComponent type, so these fixtures assert their shape.
const health = (es: { ok: boolean; detail: string; kind?: string }): Health =>
  ({ es, llm: { ok: true, detail: 'up' } }) as Health;

describe('Dashboard connection banner — the headline names the failure', () => {
  it('calls a saturated grid overloaded, not unreachable', async () => {
    vi.mocked(getHealth).mockResolvedValue(
      health({ ok: false, kind: 'overloaded', detail: 'the grid is up but shedding load' }),
    );
    await mount();
    const banner = await screen.findByRole('alert');
    expect(banner.textContent).not.toContain('not reachable');
    expect(banner.textContent).toContain('overloaded');
  });

  it('calls a half-read grid incomplete, not unreachable', async () => {
    vi.mocked(getHealth).mockResolvedValue(
      health({ ok: false, kind: 'partial', detail: 'the grid read only 2 of 4 shards' }),
    );
    await mount();
    const banner = await screen.findByRole('alert');
    expect(banner.textContent).not.toContain('not reachable');
    expect(banner.textContent).toContain('incomplete');
  });

  it('still says not reachable for a grid that genuinely is not answering', async () => {
    vi.mocked(getHealth).mockResolvedValue(
      health({ ok: false, kind: 'refused', detail: 'the grid could not be reached' }),
    );
    await mount();
    const banner = await screen.findByRole('alert');
    expect(banner.textContent).toContain('not reachable');
  });

  it('keeps the generic headline when the probe could not classify the failure', async () => {
    vi.mocked(getHealth).mockResolvedValue(health({ ok: false, detail: 'something else entirely' }));
    await mount();
    const banner = await screen.findByRole('alert');
    expect(banner.textContent).toContain('not reachable');
  });
});

// The fix above keys off `alerts.error`, which is a FOREGROUND load failure —
// the state the punch-list screenshots were captured in (a fresh load onto an
// already-sick grid). A grid that dies with the tab already open never reaches
// it: useAsync counts a failed background poll toward `failCount` and keeps the
// last-good data, deliberately, so a blip doesn't blank the screen. That left
// the calm caption asserting a queue read minutes earlier, under a red banner
// saying the grid is down, with nothing on the screen dating the number
// (review of batch A, 2026-08-14).
describe('Dashboard KPI row — a grid that dies with the tab open', () => {
  const outageAfterFirstLoad = () => {
    vi.mocked(getAlerts)
      .mockResolvedValueOnce([])
      .mockRejectedValue(new Error('grid_unavailable'));
    vi.mocked(getHealth).mockResolvedValue(
      health({ ok: false, kind: 'overloaded', detail: 'the grid is up but shedding load' }),
    );
  };

  /** Mount under fake timers and settle the first (successful) load. */
  const mountAndSettle = async () => {
    render(
      <MemoryRouter initialEntries={['/']}>
        <Dashboard />
      </MemoryRouter>,
    );
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
  };

  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('stops calling the queue clear once the polls that would prove it are failing', async () => {
    outageAfterFirstLoad();
    await mountAndSettle();
    // The control: the first read really did succeed, and really was empty.
    expect(awaitingTileNow().textContent).toContain('queue clear');

    // Two 30s poll ticks later the grid has answered nothing for a minute.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(65_000);
    });
    expect(awaitingTileNow().textContent).not.toContain('queue clear');
  });

  it('dates the counts it is still showing instead of passing them off as current', async () => {
    outageAfterFirstLoad();
    await mountAndSettle();
    expect(screen.queryByText(/Showing data from/)).toBeNull(); // healthy: no marker

    await act(async () => {
      await vi.advanceTimersByTimeAsync(65_000);
    });
    expect(screen.getByText(/Showing data from/)).toBeTruthy();
  });

  it('rides out a single missed poll without crying stale', async () => {
    // The over-correction control. One failed tick on a 30s cadence is a blip;
    // the counts are no older than they are on a healthy screen between polls,
    // and a marker that fires on every hiccup is one the analyst learns to
    // ignore. `failCount >= 2` is the house threshold (Hosts, Hunts,
    // Notifications, Investigations all use it) and this screen keeps it.
    vi.mocked(getAlerts)
      .mockResolvedValueOnce([])
      .mockRejectedValueOnce(new Error('grid_unavailable'))
      .mockResolvedValue([]);
    await mountAndSettle();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(35_000);
    });
    expect(screen.queryByText(/Showing data from/)).toBeNull();
    expect(awaitingTileNow().textContent).toContain('queue clear');
  });
});

// The other half of "the screen never says the numbers are old": a FOREGROUND
// failure — the analyst changed the time range, or hit Refresh — keeps the prior
// counts on screen by design (useAsync: an error arriving after the data must
// not take it away). Nothing dated them, so a count fetched for the last 24h sat
// under a header now reading "last 1h" as if it had been read for it.
describe('Dashboard KPI row — a refresh the analyst asked for and did not get', () => {
  it('says the counts are from the earlier read, and keeps them', async () => {
    vi.mocked(getAlerts).mockResolvedValue([untriagedGroup]);
    await mount();
    // `mount` waits for the outcomes chart, which renders off a DIFFERENT fetch —
    // so it can return while the alerts read is still in flight and the tile is
    // still showing its loading caption. Asserting straight after it passed on an
    // idle box and failed on a loaded CI runner, where the assertion won the race:
    // "expected 'Awaiting investigation…checking the queue…' to contain '1'".
    // waitFor retries, so this tracks the fetch instead of racing a wall clock —
    // the same fix that finally killed the generalChat flake.
    await waitFor(() => expect(awaitingTileNow().textContent).toContain('1'));

    vi.mocked(getAlerts).mockRejectedValue(new Error('grid_unavailable'));
    await act(async () => {
      fireEvent.click(screen.getByText('1h'));
    });

    expect(await screen.findByText(/Refresh failed/)).toBeTruthy();
    // Still the best account of the network anyone has — marked, not deleted.
    expect(awaitingTileNow().textContent).toContain('1');
  });
});
