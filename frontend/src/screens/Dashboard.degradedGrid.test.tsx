// The Dashboard's account of the grid must match the grid (dogfood 2026-08-14).
//
// Two independent false claims lived on this screen at once. The
// awaiting-investigation tile printed an honest "—" for its value and then
// "queue clear" underneath it, in all four degraded states — "—" says unknown
// and "queue clear" says safe, and during an outage those are opposite
// statements. The Needs-you tile took its place (dogfood 2026-10-06) and keeps
// the rule: "Nothing needs you" only after every part was read and every part
// is zero. And the connection banner announced a grid answering 429 as "not
// reachable" directly above its own circuit-breaker detail line, sending the
// analyst to check connectivity and firewalls when the grid was up and shedding
// load.
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AlertGroup, Verdict } from '../lib/types';
import type { Health } from '../lib/api';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue({ groups: [], truncated: false, other_docs: 0 }),
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
  getNeedsYouCount: vi.fn(),
}));

import { queueOf } from '../test/alertQueue';
import { Dashboard } from './Dashboard';
import { getAlerts, getHealth, getNeedsYouCount, type NeedsYouCount } from '../lib/api';

const mount = async () => {
  render(
    <MemoryRouter initialEntries={['/']}>
      <Dashboard />
    </MemoryRouter>,
  );
  await screen.findByText('Investigation outcomes');
};

/** The whole Needs-you tile, so the assertions cover its value AND its lines:
 *  the defect was the two disagreeing with each other. */
const needsYouTile = async (): Promise<HTMLElement> => screen.findByTestId('kpi-needs-you');

/** The Alert events tile, read synchronously. The fake-timer suite settles the
 *  render itself and must not hand control back to a real-clock wait. */
const eventsTileNow = (): HTMLElement =>
  screen.getByText(/^Alert events/).parentElement!.parentElement!;

const zeroCount = (parts: Partial<NeedsYouCount> = {}): NeedsYouCount => ({
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
  ...parts,
});

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
  vi.mocked(getAlerts).mockResolvedValue(queueOf([]));
  vi.mocked(getHealth).mockResolvedValue(null as unknown as Health);
  vi.mocked(getNeedsYouCount).mockResolvedValue(zeroCount());
});

describe('Dashboard Needs-you tile — unknown is not zero', () => {
  it('does not say nothing needs you when the read that would prove it failed', async () => {
    vi.mocked(getNeedsYouCount).mockRejectedValue(new Error('needs-you unavailable'));
    await mount();
    const tile = await needsYouTile();
    await waitFor(() => expect(tile.textContent).toContain('Could not read what needs you.'));
    // The string this whole exercise exists to catch.
    expect(tile.textContent).not.toContain('Nothing needs you');
    // …and no number is asserted either, since none was read.
    expect(tile.textContent).not.toMatch(/\d/);
    expect(screen.getByTestId('needs-you-total').textContent).toBe('?');
  });

  it('says nothing needs you when every part was read and every part is zero', async () => {
    await mount();
    const tile = await needsYouTile();
    await waitFor(() => expect(tile.textContent).toContain('Nothing needs you.'));
    expect(screen.getByTestId('needs-you-total').textContent).toBe('0');
  });

  it('keeps a line for the part the grid could not answer, and marks the total a floor', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue(
      zeroCount({ leads_needing_decision: 2, untriaged_groups: null, total: 2, unknown: ['untriaged_groups'] }),
    );
    await mount();
    const tile = await needsYouTile();
    await waitFor(() => expect(tile.textContent).toContain('Could not count the alert groups.'));
    expect(tile.textContent).not.toContain('Nothing needs you');
    expect(screen.getByTestId('needs-you-total').textContent).toBe('2+');
  });

  // NEGATIVE CONTROL. A failed ALERTS read takes the alert counts off the page
  // and leaves the Needs-you tile alone: the two reads are separate, and the
  // tile's alert part has its own grid read on the server.
  it('keeps the Needs-you count when only the alert counts failed', async () => {
    vi.mocked(getAlerts).mockRejectedValue(new Error('grid_unavailable'));
    vi.mocked(getNeedsYouCount).mockResolvedValue(zeroCount({ leads_needing_decision: 3, total: 3 }));
    await mount();
    expect(await screen.findByText('Could not load the alert counts')).toBeTruthy();
    expect(screen.queryByText('Could not load the dashboard')).toBeNull();
    await waitFor(() => expect(screen.getByTestId('needs-you-total').textContent).toBe('3'));
  });

  it('counts one group as one group', async () => {
    vi.mocked(getAlerts).mockResolvedValue(queueOf([untriagedGroup]));
    await mount();
    // One group reads as one group. The header said "1 detection groups".
    expect(await screen.findByText('1 detection group')).toBeTruthy();
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

  // The Security Onion web API carries every acknowledge, escalate and case
  // write. It was absent from /health entirely, so a hung API left both the
  // header pill and this banner silent (dogfood 2026-09-07, D1).
  it('names the Security Onion API when it is the upstream that is down', async () => {
    vi.mocked(getHealth).mockResolvedValue({
      es: { ok: true, detail: 'up' },
      llm: { ok: true, detail: 'up' },
      so: { ok: false, kind: 'timeout', detail: 'took the request, never answered' },
    } as Health);
    await mount();
    const banner = await screen.findByRole('alert');
    expect(banner.textContent).toContain('Security Onion API');
  });

  it('raises no banner for a payload with no Security Onion component at all', async () => {
    // An older server never sends `so`. "Not reported" is not "down".
    vi.mocked(getHealth).mockResolvedValue({
      es: { ok: true, detail: 'up' },
      llm: { ok: true, detail: 'up' },
    } as Health);
    await mount();
    expect(screen.queryByRole('alert')).toBeNull();
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
      .mockResolvedValueOnce(queueOf([]))
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

  it('dates the counts it is still showing instead of passing them off as current', async () => {
    outageAfterFirstLoad();
    await mountAndSettle();
    expect(screen.queryByText(/This data is from/)).toBeNull(); // healthy: no marker

    await act(async () => {
      await vi.advanceTimersByTimeAsync(65_000);
    });
    expect(screen.getByText(/This data is from/)).toBeTruthy();
  });

  it('rides out a single missed poll without crying stale', async () => {
    // The over-correction control. One failed tick on a 30s cadence is a blip;
    // the counts are no older than they are on a healthy screen between polls,
    // and a marker that fires on every hiccup is one the analyst learns to
    // ignore. `failCount >= 2` is the house threshold (Hosts, Hunts,
    // Notifications, Investigations all use it) and this screen keeps it.
    vi.mocked(getAlerts)
      .mockResolvedValueOnce(queueOf([]))
      .mockRejectedValueOnce(new Error('grid_unavailable'))
      .mockResolvedValue(queueOf([]));
    await mountAndSettle();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(35_000);
    });
    expect(screen.queryByText(/This data is from/)).toBeNull();
    expect(eventsTileNow().textContent).toContain('0');
  });

  it('answers a Refresh clicked from the stale line, even when that refresh fails too', async () => {
    // The stale line's own button is this row's only foreground refetch.
    // useAsync keeps the fail count through a foreground failure and sets
    // `error`; with the stale branch checked first the click landed on the
    // same "This data is from" line and the failure was silent. The hunt
    // catalog panel checks `error` first for the same reason.
    outageAfterFirstLoad();
    await mountAndSettle();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(65_000);
    });
    const stale = screen.getByText(/This data is from/).closest<HTMLElement>('[role="status"]')!;

    await act(async () => {
      fireEvent.click(within(stale).getByText('Refresh'));
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(screen.getByText(/Refresh failed/)).toBeTruthy();
    // One notice, not a lingering plain stale line beside the failure one —
    // "Refresh failed. This data is from…" replaces it in place.
    expect(screen.getAllByText(/This data is from/)).toHaveLength(1);
  });
});

// The other half of "the screen never says the numbers are old": a FOREGROUND
// failure — the analyst changed the time range, or hit Refresh — keeps the prior
// counts on screen by design (useAsync: an error arriving after the data must
// not take it away). Nothing dated them, so a count fetched for the last 24h sat
// under a header now reading "last 1h" as if it had been read for it.
describe('Dashboard KPI row — a refresh the analyst asked for and did not get', () => {
  it('says the counts are from the earlier read, and keeps them', async () => {
    vi.mocked(getAlerts).mockResolvedValue(queueOf([untriagedGroup]));
    await mount();
    // `mount` waits for the outcomes chart, which renders off a DIFFERENT fetch —
    // so it can return while the alerts read is still in flight and the tile is
    // still showing its loading caption. Asserting straight after it passed on an
    // idle box and failed on a loaded CI runner, where the assertion won the race:
    // "expected 'Alert events…' to contain '3'".
    // waitFor retries, so this tracks the fetch instead of racing a wall clock —
    // the same fix that finally killed the generalChat flake.
    await waitFor(() => expect(eventsTileNow().textContent).toContain('3'));

    vi.mocked(getAlerts).mockRejectedValue(new Error('grid_unavailable'));
    await act(async () => {
      fireEvent.click(screen.getByText('1h'));
    });

    expect(await screen.findByText(/Refresh failed/)).toBeTruthy();
    // Still the best account of the network anyone has — marked, not deleted.
    expect(eventsTileNow().textContent).toContain('3');
  });
});
