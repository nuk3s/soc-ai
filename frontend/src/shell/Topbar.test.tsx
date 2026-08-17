// The Topbar mounts on every in-shell route and drives two of the app's
// hottest pollers: /notifications every 15s (four DB queries a call) and
// /health every 60s. Both used to be bare setIntervals — an analyst parking a
// handful of tabs over a weekend kept every one of them hitting the API around
// the clock. These pin the fix: no poll while the tab is hidden, and one
// immediate refresh on return to visible so the bell is current the moment the
// analyst looks again (the house guard, lib/useAsync.ts:118).
import { act, render } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getWorkspaces: vi.fn(),
  getNotifications: vi.fn(),
  getHealth: vi.fn(),
}));

import { getHealth, getNotifications, getWorkspaces } from '../lib/api';
import { ShellProvider } from './ShellContext';
import { Topbar } from './Topbar';

const NOTIF_MS = 15_000;

// happy-dom derives document.hidden from visibilityState; shadow it with a
// mutable getter so a test can park and un-park the tab.
let hidden = false;

/** Advance the clock (firing the pollers) AND settle the promise chains. */
const tick = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
/** Settle already-resolved promises without moving the clock. */
const flush = () => tick(0);

/** Toggle tab visibility and dispatch the event the effects listen for. */
const setHidden = (v: boolean) => {
  hidden = v;
  act(() => {
    document.dispatchEvent(new Event('visibilitychange'));
  });
};

const mount = () =>
  render(
    <MemoryRouter>
      <ShellProvider>
        <Topbar />
      </ShellProvider>
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.clearAllMocks(); // call history is per-test — don't carry counts across
  vi.useFakeTimers();
  hidden = false;
  Object.defineProperty(document, 'hidden', { configurable: true, get: () => hidden });
  vi.mocked(getWorkspaces).mockResolvedValue([]);
  vi.mocked(getNotifications).mockResolvedValue([]);
  vi.mocked(getHealth).mockResolvedValue({
    es: { ok: true, detail: 'ok' },
    llm: { ok: true, detail: 'ok' },
    pcap: null,
  });
});

afterEach(() => {
  vi.useRealTimers();
});

describe('Topbar pollers respect tab visibility', () => {
  it('stops polling notifications and health while the tab is hidden', async () => {
    mount();
    await flush();
    // One immediate load of each on mount.
    expect(getNotifications).toHaveBeenCalledTimes(1);
    expect(getHealth).toHaveBeenCalledTimes(1);

    setHidden(true); // going hidden must not itself fetch
    await flush();
    expect(getNotifications).toHaveBeenCalledTimes(1);
    expect(getHealth).toHaveBeenCalledTimes(1);

    // 20 notification intervals (and several health intervals) pass with the
    // tab backgrounded — not one poll fires.
    await tick(NOTIF_MS * 20);
    expect(getNotifications).toHaveBeenCalledTimes(1);
    expect(getHealth).toHaveBeenCalledTimes(1);
  });

  it('refreshes once on return to visible and resumes the live poll', async () => {
    mount();
    await flush();
    setHidden(true);
    await tick(NOTIF_MS * 3);
    expect(getNotifications).toHaveBeenCalledTimes(1);

    // Coming back to the tab re-reads both surfaces immediately, without
    // waiting out an interval.
    setHidden(false);
    await flush();
    expect(getNotifications).toHaveBeenCalledTimes(2);
    expect(getHealth).toHaveBeenCalledTimes(2);

    // …and the 15s notifications poll is live again.
    await tick(NOTIF_MS);
    expect(getNotifications).toHaveBeenCalledTimes(3);
  });
});
