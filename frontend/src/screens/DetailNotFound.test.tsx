// "Not found" is not "the backend is down" (dogfood B3, 2026-08-11).
//
// An unknown investigation / hunt / host id rendered the same alarm-red
// "Couldn't load this view" card, with a Retry button, as a genuine outage — so
// the analyst opening a stale link could not tell whether the run had been
// deleted or the grid had fallen over. These tests pin the split: a 404 gets a
// calm not-found card with a way back to the list and NO retry; a 500 or a
// client timeout keeps the error card exactly as it was.
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getInvestigation: vi.fn(),
  getHunt: vi.fn(),
  getHuntChat: vi.fn(),
  getDossier: vi.fn(),
  getHostActivity: vi.fn(),
  getMe: vi.fn(),
}));

// Stand-in for the report body, with the one control the page hands it that
// forces a FOREGROUND refetch (applying a verdict). The real component needs a
// full investigation payload to render and none of it is what's under test.
vi.mock('./Investigation', () => ({
  Investigation: ({ onVerdictApplied }: { onVerdictApplied?: () => void }) => (
    <div data-testid="investigation-report">
      <button onClick={() => onVerdictApplied?.()}>Apply verdict</button>
    </div>
  ),
}));

import {
  ApiError,
  getDossier,
  getHostActivity,
  getHunt,
  getHuntChat,
  getInvestigation,
  getMe,
} from '../lib/api';
import type { HuntDetailData } from '../lib/types';
import { HostDetail } from './HostDetail';
import { HuntDetail } from './HuntDetail';
import { InvestigationPage } from './InvestigationPage';

/** HuntDetail's own live-refresh interval. */
const POLL_MS = 3000;
const RUNNING_OBJECTIVE = 'Beaconing to rare destinations';
/** Still running, so the poll loop is armed rather than paused. */
const runningHunt: HuntDetailData = {
  id: 'HUNT-nope',
  objective: RUNNING_OBJECTIVE,
  kind: 'chat',
  status: 'running',
  narrative: '',
  findings: [],
  affectedHosts: [],
  mitreTechniques: [],
  recommendedActions: [],
  confidence: 0,
  startedBy: 'ana',
  elapsedLabel: '1m',
  elapsedSec: 60,
  ts: '2026-08-11T10:00:00Z',
  timeline: [],
};

const notFound = () => Promise.reject(new ApiError('404 Not Found', 404));
const serverError = () => Promise.reject(new ApiError('500 Internal Server Error', 500));
/** No response at all: the client budget expired. Carries no status by design. */
const timedOut = () =>
  Promise.reject(new Error('Request timed out — the soc-ai API (or Security Onion behind it) is slow or down.'));

const at = (path: string, element: JSX.Element, route: string) =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path={route} element={element} />
      </Routes>
    </MemoryRouter>,
  );

const mountInvestigation = () =>
  at('/investigation/INV-nope', <InvestigationPage />, '/investigation/:id');
const mountHunt = () => at('/hunts/HUNT-nope', <HuntDetail />, '/hunts/:id');
const mountHost = () => at('/hosts/10.0.0.9', <HostDetail />, '/hosts/:ip');

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getMe).mockResolvedValue({ username: 'ana', role: 'analyst', status: '' });
  vi.mocked(getHostActivity).mockRejectedValue(new ApiError('404 Not Found', 404));
  vi.mocked(getHuntChat).mockResolvedValue({ messages: [], pending: false });
});
afterEach(() => {
  vi.useRealTimers(); // one test drives the poll clock; a throw must not leak it
});

describe('an unknown id is a calm answer, not an alarm', () => {
  it('investigation: a 404 explains and offers the list, with no Retry', async () => {
    vi.mocked(getInvestigation).mockImplementation(notFound);
    mountInvestigation();
    const card = (await screen.findByText(/No such investigation/i)).parentElement!;
    // The id the analyst typed or bookmarked, echoed back — "no such thing" is
    // only useful if it names the thing.
    expect(card.textContent).toContain('INV-nope');
    expect(card.textContent).toMatch(/Back to Alerts/);
    expect(screen.queryByText(/Couldn't load/i)).toBeNull();
    expect(screen.queryByRole('button', { name: /retry/i })).toBeNull();
  });

  it('hunt: a 404 explains and offers the list, with no Retry', async () => {
    vi.mocked(getHunt).mockImplementation(notFound);
    mountHunt();
    expect(await screen.findByText(/No such hunt/i)).toBeTruthy();
    expect(screen.queryByText(/Couldn't load/i)).toBeNull();
    expect(screen.queryByRole('button', { name: /retry/i })).toBeNull();
  });

  it('host: a 404 explains and offers the list, with no Retry', async () => {
    vi.mocked(getDossier).mockImplementation(notFound);
    mountHost();
    expect(await screen.findByText(/No such host/i)).toBeTruthy();
    expect(screen.queryByText(/Couldn't load/i)).toBeNull();
    expect(screen.queryByRole('button', { name: /retry/i })).toBeNull();
  });
});

describe('a later 404 never takes away a report already on screen', () => {
  // The guard has to be `error && !data`, not `error`, on every one of these
  // screens — and it was not, which is how the three disagreed. A run deleted
  // in another tab 404s the NEXT foreground load, and on the screen the analyst
  // is reading that load is a side effect of something else they did (applying
  // a verdict, hitting the stale-data Refresh). Replacing the report they are
  // mid-sentence in with "no such thing" loses their place to answer a question
  // they did not ask.

  it('investigation: applying a verdict against a deleted run keeps the report', async () => {
    vi.mocked(getInvestigation).mockResolvedValueOnce({
      id: 'INV-nope',
      status: 'complete',
    } as never);
    mountInvestigation();
    await screen.findByTestId('investigation-report');

    // Deleted elsewhere. The verdict apply refetches — and that fetch 404s.
    let reject!: (reason: unknown) => void;
    vi.mocked(getInvestigation).mockImplementationOnce(
      () => new Promise((_resolve, rej) => { reject = rej; }),
    );
    fireEvent.click(screen.getByRole('button', { name: /apply verdict/i }));
    await waitFor(() => expect(vi.mocked(getInvestigation)).toHaveBeenCalledTimes(2));
    await act(async () => {
      reject(new ApiError('404 Not Found', 404));
    });

    expect(screen.getByTestId('investigation-report')).toBeTruthy();
    expect(screen.queryByText(/No such investigation/i)).toBeNull();
    expect(screen.queryByText(/Couldn't load/i)).toBeNull();
  });

  it('hunt: refreshing stale data on a deleted hunt keeps the report', async () => {
    vi.useFakeTimers();
    vi.mocked(getHunt).mockResolvedValue(runningHunt);
    mountHunt();
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(screen.getAllByText(RUNNING_OBJECTIVE).length).toBeGreaterThan(0);

    // Two failed background polls mark the surface stale — no error card, by
    // design — and offer the Refresh that makes the next load a foreground one.
    vi.mocked(getHunt).mockImplementation(notFound);
    await act(async () => { await vi.advanceTimersByTimeAsync(POLL_MS * 2 + 1); });
    fireEvent.click(screen.getByRole('button', { name: /refresh/i }));
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });

    expect(screen.getAllByText(RUNNING_OBJECTIVE).length).toBeGreaterThan(0);
    expect(screen.queryByText(/No such hunt/i)).toBeNull();
  });
});

// The other half of the `!data` guard above. Keeping the content is right;
// keeping it SILENTLY is not — the analyst is then reading data that stopped
// being refreshed, with nothing on screen disagreeing (#85). The marker is
// non-destructive by construction: a strip above the content, and the content
// untouched.
describe('a failed foreground refresh is marked, not swallowed', () => {
  const REFRESH_FAILED = /Refresh failed — still showing data from/i;

  it('investigation: the report stays and says it is not current', async () => {
    vi.mocked(getInvestigation).mockResolvedValueOnce({
      id: 'INV-nope',
      status: 'complete',
    } as never);
    mountInvestigation();
    await screen.findByTestId('investigation-report');
    expect(screen.queryByText(REFRESH_FAILED)).toBeNull();

    // Applying a verdict refetches in the foreground — and the backend is down.
    let reject!: (reason: unknown) => void;
    vi.mocked(getInvestigation).mockImplementationOnce(
      () => new Promise((_resolve, rej) => { reject = rej; }),
    );
    fireEvent.click(screen.getByRole('button', { name: /apply verdict/i }));
    await waitFor(() => expect(vi.mocked(getInvestigation)).toHaveBeenCalledTimes(2));
    await act(async () => {
      reject(new ApiError('500 Internal Server Error', 500));
    });

    expect(screen.getByTestId('investigation-report')).toBeTruthy();
    expect(screen.getByText(REFRESH_FAILED)).toBeTruthy();
    // This investigation is COMPLETE, so the poll loop is paused: the Refresh
    // button really is the only way forward, and the copy promises nothing else.
    expect(screen.queryByText(/retrying/i)).toBeNull();
    // Still not the alarm card — the report was never taken away.
    expect(screen.queryByText(/Couldn't load/i)).toBeNull();

    // And a refresh that WORKS clears it. Nothing to dismiss by hand: the
    // marker is a statement about the last load, not a notification.
    vi.mocked(getInvestigation).mockResolvedValueOnce({
      id: 'INV-nope',
      status: 'complete',
    } as never);
    fireEvent.click(screen.getByRole('button', { name: /refresh/i }));
    await waitFor(() => expect(screen.queryByText(REFRESH_FAILED)).toBeNull());
    expect(screen.getByTestId('investigation-report')).toBeTruthy();
  });

  it('hunt: the report stays and the marker replaces the polling one', async () => {
    vi.useFakeTimers();
    vi.mocked(getHunt).mockResolvedValue(runningHunt);
    mountHunt();
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });

    // Two failed background polls: the stale marker, which promises a retry.
    vi.mocked(getHunt).mockImplementation(serverError);
    await act(async () => { await vi.advanceTimersByTimeAsync(POLL_MS * 2 + 1); });
    expect(screen.getByText(/Showing data from .* — retrying/i)).toBeTruthy();

    // The analyst takes the retry themselves, and THAT fails. The click is what
    // failed, so the strip says so — but this hunt is still RUNNING and its 3s
    // poll was never cancelled, so the page is already healing itself. Dropping
    // the retry promise here would send the analyst off to fix a page that is
    // about to fix itself.
    fireEvent.click(screen.getByRole('button', { name: /refresh/i }));
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(screen.getByText(REFRESH_FAILED)).toBeTruthy();
    expect(screen.getByText(/— retrying/i)).toBeTruthy();
    expect(screen.getAllByText(RUNNING_OBJECTIVE).length).toBeGreaterThan(0);

    // And it does heal itself: the next poll lands, nobody having clicked.
    vi.mocked(getHunt).mockResolvedValue(runningHunt);
    await act(async () => { await vi.advanceTimersByTimeAsync(POLL_MS + 1); });
    expect(screen.queryByText(REFRESH_FAILED)).toBeNull();
  });

  it('a 404 with nothing on screen is still the calm not-found state', async () => {
    // The marker is for a page that HAS content. The first-load answers are
    // untouched.
    vi.mocked(getHunt).mockImplementation(notFound);
    mountHunt();
    expect(await screen.findByText(/No such hunt/i)).toBeTruthy();
    expect(screen.queryByText(REFRESH_FAILED)).toBeNull();
  });
});

describe('a real failure still reads like one', () => {
  it('investigation: a 500 keeps the error card', async () => {
    vi.mocked(getInvestigation).mockImplementation(serverError);
    mountInvestigation();
    expect(await screen.findByText(/Couldn't load/i)).toBeTruthy();
    expect(screen.queryByText(/No such investigation/i)).toBeNull();
  });

  it('hunt: a client timeout keeps the error card and its Retry', async () => {
    vi.mocked(getHunt).mockImplementation(timedOut);
    mountHunt();
    expect(await screen.findByText(/Couldn't load/i)).toBeTruthy();
    expect(screen.getByRole('button', { name: /retry/i })).toBeTruthy();
    expect(screen.queryByText(/No such hunt/i)).toBeNull();
  });

  it('host: a 500 keeps the error card', async () => {
    vi.mocked(getDossier).mockImplementation(serverError);
    mountHost();
    await waitFor(() => expect(screen.getByText(/Couldn't load/i)).toBeTruthy());
    expect(screen.queryByText(/No such host/i)).toBeNull();
  });
});

// A genuine outage is the one failure the analyst can do something about —
// wait a moment and ask again. Without a Retry the card's only affordance is a
// Details disclosure, which leaves a browser reload as the way forward.
describe('the error card offers a way out of the outage', () => {
  it('investigation: Retry re-runs the fetch', async () => {
    // The one of the three detail screens that never wired it.
    vi.mocked(getInvestigation).mockImplementation(serverError);
    mountInvestigation();
    await screen.findByText(/Couldn't load/i);
    const before = vi.mocked(getInvestigation).mock.calls.length;

    fireEvent.click(screen.getByRole('button', { name: /retry/i }));
    await waitFor(() =>
      expect(vi.mocked(getInvestigation).mock.calls.length).toBeGreaterThan(before),
    );
  });

  it('host: Retry re-runs the fetch', async () => {
    vi.mocked(getDossier).mockImplementation(serverError);
    mountHost();
    await waitFor(() => expect(screen.getByText(/Couldn't load/i)).toBeTruthy());
    const before = vi.mocked(getDossier).mock.calls.length;

    fireEvent.click(screen.getByRole('button', { name: /retry/i }));
    await waitFor(() => expect(vi.mocked(getDossier).mock.calls.length).toBeGreaterThan(before));
  });

  it('hunt: Retry re-runs the fetch', async () => {
    vi.mocked(getHunt).mockImplementation(timedOut);
    mountHunt();
    await screen.findByText(/Couldn't load/i);
    const before = vi.mocked(getHunt).mock.calls.length;

    fireEvent.click(screen.getByRole('button', { name: /retry/i }));
    await waitFor(() => expect(vi.mocked(getHunt).mock.calls.length).toBeGreaterThan(before));
  });
});
