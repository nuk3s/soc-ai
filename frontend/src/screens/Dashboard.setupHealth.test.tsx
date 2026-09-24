// The Dashboard's setup-health card surfaces Wave 1's doctor checks (minus the
// expensive fitness probe) as a PERSISTENT card — green when every check
// passes, specific when one doesn't — so a broken integration is visible on
// arrival instead of discovered when a triage run mysteriously comes up empty.
//
// Two boundaries matter as much as the happy path. First, per-check failure
// detail (rule names, upstream detail strings, remediation hints) is
// admin-only server-side (GET /health/preflight/detail, require_admin_api) —
// an analyst session must never even ISSUE that request, let alone render its
// contents, so the gate is pinned both ways: rows show for an admin, and the
// endpoint is provably uncalled for an analyst (a leak here would be an
// analyst learning exactly which internal check failed and why). Second, the
// read sits behind a 600s server cache and a 300s client poll, so a problem
// fixed a minute ago could otherwise still read degraded for up to ten
// minutes with nothing on screen to force a look — the admin Re-check
// affordance exists for that gap, pinned by call counts rather than by
// wording that could drift out of sync with the button's actual behavior.
// That includes the detail rows, not just the summary count: a PARTIAL fix
// (still degraded, but a different check now the one failing) leaves the
// summary's `degraded` boolean unchanged, so the row list's own dependency
// array never moves on its own — Re-check has to force it, or the count goes
// fresh while an already-fixed check's row sits there unchanged.
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { PreflightDetail, PreflightSummary } from '../lib/types';

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
  getMe: vi.fn(),
  getPreflight: vi.fn(),
  getPreflightDetail: vi.fn(),
  refreshPreflight: vi.fn(),
}));

import { getMe, getPreflight, getPreflightDetail, refreshPreflight } from '../lib/api';
import { Dashboard } from './Dashboard';

const GREEN: PreflightSummary = {
  status: 'green',
  failing: 0,
  warned: 0,
  checked_at: '2026-08-19T10:00:00+00:00',
};

const DEGRADED: PreflightSummary = {
  status: 'degraded',
  failing: 1,
  warned: 0,
  checked_at: '2026-08-19T10:00:00+00:00',
};

// Warnings only: `status` is FAIL-driven server-side (the same exit_code
// semantics `soc-ai doctor` uses), so a grid with two WARNing checks and no
// FAILing one reports green with a non-zero `warned`. Measured on a live
// deployment on 2026-09-06: {"status":"green","failing":0,"warned":2}.
const WARNED: PreflightSummary = {
  status: 'green',
  failing: 0,
  warned: 2,
  checked_at: '2026-08-19T10:00:00+00:00',
};

const DETAIL: PreflightDetail = {
  rows: [
    { name: 'audit write grant', status: 'FAIL', detail: 'missing write', hint: 'run the script' },
  ],
  checked_at: '2026-08-19T10:00:00+00:00',
};

const WARN_DETAIL: PreflightDetail = {
  rows: [
    {
      name: 'alerts feed filter',
      status: 'WARN',
      detail: "'tags:alert' matched 2 in the last 24h while 'event.kind:alert' matched 34",
      hint: 'Set WEBUI_ALERTS_QUERY=tags:alert OR event.kind:alert',
    },
    { name: 'index pattern', status: 'WARN', detail: 'no suricata.alert events', hint: '' },
  ],
  checked_at: '2026-08-19T10:00:00+00:00',
};

const ADMIN = { username: 'root', role: 'admin', status: '' };
const ANALYST = { username: 'ana', role: 'analyst', status: '' };

const mount = () =>
  render(
    <MemoryRouter>
      <Dashboard />
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getMe).mockReset().mockResolvedValue(ANALYST);
  vi.mocked(getPreflight).mockReset().mockResolvedValue(GREEN);
  vi.mocked(getPreflightDetail).mockReset().mockResolvedValue({ rows: [], checked_at: GREEN.checked_at });
  vi.mocked(refreshPreflight).mockReset().mockResolvedValue(DETAIL);
});

describe('Dashboard setup-health card', () => {
  it('renders the green compact row when preflight is clean', async () => {
    mount();
    expect(await screen.findByText(/setup health/i)).toBeTruthy();
    expect(screen.getByText(/all checks pass/i)).toBeTruthy();
  });

  it('shows a distinct errored state on a persistently rejecting preflight read, not an endless "Checking…"', async () => {
    // Pins the calm-looking-hang regression: `!summary` alone used to render
    // "Checking setup health…" forever on a getPreflight that rejects (500,
    // a proxy 504, an old backend without this route) rather than merely
    // being slow — indistinguishable on screen from a load still in flight.
    // preflight.error was computed by useAsync and simply never read.
    vi.mocked(getPreflight).mockRejectedValue(new Error('500'));
    mount();
    expect(await screen.findByText(/setup health read failed/i)).toBeTruthy();
    expect(screen.queryByText(/checking setup health/i)).toBeNull();
    expect(screen.queryByText(/all checks pass/i)).toBeNull();
  });

  it('never calls a warning an all-clear', async () => {
    // The measured failure: on 2026-09-06 a live deployment answered
    // {"status":"green","failing":0,"warned":2} while the alerts-feed-filter
    // check was warning that 34 alerts never reach the triage queue. The one
    // surface that could have shown that asserted there was nothing to show.
    // `status` alone was the whole summary; `warned` was on the wire, sent by
    // the same response, and never read. A false all-clear outranks any 500,
    // and this is the card whose entire job is to not be one.
    vi.mocked(getMe).mockResolvedValue(ADMIN);
    vi.mocked(getPreflight).mockResolvedValue(WARNED);
    vi.mocked(getPreflightDetail).mockResolvedValue(WARN_DETAIL);
    mount();
    expect(await screen.findByText(/2 checks warning/i)).toBeTruthy();
    expect(screen.queryByText(/all checks pass/i)).toBeNull();
    // Not reported as failures either: a WARN said in FAIL's words is the
    // opposite over-correction, and it is the one that gets the row ignored.
    expect(screen.queryByText(/checks? failing/i)).toBeNull();
  });

  it('warning + admin fetches and shows the warning rows', async () => {
    // The detail read was gated on `degraded`, so even after the summary
    // learned to count warnings the rows behind them would never be
    // requested: an admin would see "2 checks warning" and no way to learn
    // which two without opening Diagnostics.
    vi.mocked(getMe).mockResolvedValue(ADMIN);
    vi.mocked(getPreflight).mockResolvedValue(WARNED);
    vi.mocked(getPreflightDetail).mockResolvedValue(WARN_DETAIL);
    mount();
    expect(await screen.findByText(/alerts feed filter/i)).toBeTruthy();
    expect(screen.getByText(/WEBUI_ALERTS_QUERY=tags:alert OR event.kind:alert/i)).toBeTruthy();
  });

  it('warning + analyst shows the count, never the internals', async () => {
    vi.mocked(getPreflight).mockResolvedValue(WARNED);
    mount();
    expect(await screen.findByText(/2 checks warning/i)).toBeTruthy();
    expect(screen.queryByText(/alerts feed filter/i)).toBeNull();
    // Same privilege boundary the failing path already holds: per-check
    // detail is admin-only server-side, so an analyst session must not ask.
    expect(getPreflightDetail).not.toHaveBeenCalled();
  });

  it('still reads as green when nothing is failing AND nothing is warning', async () => {
    // The negative control for the three tests above. A card that can no
    // longer say "all checks passing" is not a fix, it is the same defect
    // pointing the other way: an operator who is warned about a clean grid
    // stops reading the card, and the next real warning goes unread with it.
    vi.mocked(getMe).mockResolvedValue(ADMIN);
    vi.mocked(getPreflight).mockResolvedValue(GREEN);
    mount();
    expect(await screen.findByText(/all checks pass/i)).toBeTruthy();
    expect(screen.queryByText(/warning/i)).toBeNull();
    expect(getPreflightDetail).not.toHaveBeenCalled();
  });

  it('degraded + admin shows rows with hints', async () => {
    vi.mocked(getMe).mockResolvedValue(ADMIN);
    vi.mocked(getPreflight).mockResolvedValue(DEGRADED);
    vi.mocked(getPreflightDetail).mockResolvedValue(DETAIL);
    mount();
    expect(await screen.findByText(/audit write grant/i)).toBeTruthy();
    expect(screen.getByText(/run the script/i)).toBeTruthy();
  });

  it('degraded + analyst shows counts, never internals', async () => {
    vi.mocked(getPreflight).mockResolvedValue(DEGRADED);
    mount();
    expect(await screen.findByText(/1 check failing/i)).toBeTruthy();
    expect(screen.queryByText(/audit write grant/i)).toBeNull();
    // The privilege boundary, proven at the network-call level rather than
    // only "not visible" — an analyst session must never even ask.
    expect(getPreflightDetail).not.toHaveBeenCalled();
  });

  it('admin Re-check calls refreshPreflight, then refetches both the summary and the detail rows', async () => {
    // Pins the partial-fix staleness regression: a still-degraded state after
    // Re-check (e.g. a different check now the one failing) leaves
    // `preflightDegraded` unchanged, so the detail read's own dependency array
    // never moves and its loader never re-runs on its own — the count would
    // read fresh while the row list kept showing an already-fixed check. A
    // full fix hides this (status flips to green, hiding the stale rows along
    // with it), so the regression only shows up when the count changes but
    // degraded status does not — which is exactly why Re-check must refetch
    // BOTH reads unconditionally rather than relying on either's own deps.
    vi.mocked(getMe).mockResolvedValue(ADMIN);
    vi.mocked(getPreflight).mockResolvedValue(DEGRADED);
    vi.mocked(getPreflightDetail).mockResolvedValue(DETAIL);
    mount();
    const button = await screen.findByRole('button', { name: /re-check/i });
    // The mount-degraded transition already fetched detail once.
    await waitFor(() => expect(getPreflightDetail).toHaveBeenCalledTimes(1));
    const preflightCallsBefore = vi.mocked(getPreflight).mock.calls.length;

    fireEvent.click(button);

    await waitFor(() => expect(refreshPreflight).toHaveBeenCalledTimes(1));
    await waitFor(() =>
      expect(vi.mocked(getPreflight).mock.calls.length).toBeGreaterThan(preflightCallsBefore),
    );
    // The regression: without an explicit preflightDetail.refetch() in the
    // Re-check handler, this stays at 1 forever once already degraded+admin.
    await waitFor(() =>
      expect(vi.mocked(getPreflightDetail).mock.calls.length).toBeGreaterThanOrEqual(2),
    );
  });
});

// Fake timers, scoped to this describe only (Dashboard.degradedGrid.test.tsx
// precedent) — the tests above don't need a live poll tick, this one is
// ABOUT one. House idiom: advance under `act`, then assert synchronously
// (getByText/queryByText, not findByText) — waitFor's own polling doesn't
// drive itself forward under fake timers, so mixing it in after an advance
// is a standing hang/timeout risk this file avoids.
describe('Dashboard setup-health card — live transition', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('shows detail rows once a live poll turns degraded (no remount), and names a failed re-check', async () => {
    // Pins the dep-array mechanism the 1a0e2d5 fix reasons about: the SAME
    // mounted card has to react to a LIVE green-to-degraded transition for
    // preflightDetail's gated loader to ever fire on its own — a test that
    // only ever mounts already-degraded (the tests above) cannot tell "reacts
    // to a change" from "reads correctly at birth". getPreflight answers
    // green on the mount call and degraded on every call after, so it's the
    // 300s interval tick — not a fresh render — that has to flip
    // `preflightDegraded` and, through it, the detail read's own deps.
    //
    // The second half (item 1) reuses this same now-degraded+admin mount to
    // pin the failed-recheck affordance: a rejected refreshPreflight must
    // name itself rather than read as a re-check that simply found nothing
    // new — indistinguishable, on screen, from the problem actually having
    // been fixed.
    vi.mocked(getMe).mockResolvedValue(ADMIN);
    vi.mocked(getPreflight).mockResolvedValueOnce(GREEN).mockResolvedValue(DEGRADED);
    vi.mocked(getPreflightDetail).mockResolvedValue(DETAIL);

    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    );
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    // The control: it really did mount green, with no rows yet to find —
    // otherwise the assertions below would pass even without a live poll.
    expect(screen.getByText(/all checks pass/i)).toBeTruthy();
    expect(screen.queryByText(/audit write grant/i)).toBeNull();

    // The summary's own 300s poll interval ticks; the answer is now degraded.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300_000);
    });
    expect(screen.getByText(/audit write grant/i)).toBeTruthy();
    expect(screen.getByText(/run the script/i)).toBeTruthy();

    // Item 1: force the next Re-check to fail server-side.
    vi.mocked(refreshPreflight).mockRejectedValue(new Error('500'));
    const button = screen.getByRole('button', { name: /re-check/i });
    await act(async () => {
      fireEvent.click(button);
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(screen.getByText(/re-check failed/i)).toBeTruthy();
    // Still showing the last-good rows, not blanked by the failed attempt —
    // a failed re-check must not also take away what was already known.
    expect(screen.getByText(/audit write grant/i)).toBeTruthy();
  });
});
