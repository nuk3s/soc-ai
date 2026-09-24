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

import { emitNeedsYouChanged, getHealth, getNotifications, getWorkspaces } from '../lib/api';
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
    so: { ok: true, detail: 'ok' },
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

// The pill is the product's one always-on trust indicator, and it used to cover
// Elasticsearch and the model gateway only. Every acknowledge, escalate and case
// write travels the Security Onion API, so with that API hung the pill said
// "connected" on the same screen as a setup-health card reporting a Security
// Onion timeout (dogfood 2026-09-07, D1).
describe('Topbar health pill covers every upstream it claims', () => {
  it('does not say connected while the Security Onion API is down', async () => {
    vi.mocked(getHealth).mockResolvedValue({
      es: { ok: true, detail: 'ok' },
      llm: { ok: true, detail: 'ok' },
      so: { ok: false, detail: 'the API took the request but did not answer in time' },
      pcap: null,
    });
    const { getByTitle } = mount();
    await flush();
    const pill = getByTitle('Upstream health');
    expect(pill.textContent).not.toContain('connected');
    expect(pill.textContent).toContain('1 degraded');
  });

  it('lists Security Onion as its own row in the dropdown', async () => {
    vi.mocked(getHealth).mockResolvedValue({
      es: { ok: true, detail: 'ok' },
      llm: { ok: true, detail: 'ok' },
      so: { ok: false, detail: 'so.example.com — /api/info answered HTTP 403' },
      pcap: null,
    });
    const { getByTitle, getByText } = mount();
    await flush();
    act(() => {
      getByTitle('Upstream health').click();
    });
    expect(getByText('Security Onion API')).toBeTruthy();
    expect(getByText(/answered HTTP 403/)).toBeTruthy();
  });

  it('still says connected when every upstream is healthy', async () => {
    const { getByTitle } = mount();
    await flush();
    expect(getByTitle('Upstream health').textContent).toContain('connected');
  });
});

describe('Topbar badge counts actionable notifications only', () => {
  it('does not badge when every notification is informational (accent)', async () => {
    vi.mocked(getNotifications).mockResolvedValue([
      { id: 'inv-done:1', tone: 'accent', title: 'Verdict false_positive: ET INFO X', when: '2m', href: '/investigation/1' },
      { id: 'inv-done:2', tone: 'accent', title: 'Verdict false_positive: ET INFO Y', when: '5m', href: '/investigation/2' },
    ]);
    const { container } = mount();
    await flush();
    expect(container.querySelector('[data-testid="notif-badge"]')).toBeNull();
  });

  it('badges only the danger/warn count when informational items are mixed in', async () => {
    vi.mocked(getNotifications).mockResolvedValue([
      { id: 'inv-done:1', tone: 'accent', title: 'Verdict false_positive: ET INFO X', when: '2m', href: null },
      { id: 'inv-done:2', tone: 'danger', title: 'Verdict true_positive: ET MALWARE Z', when: '3m', href: null },
      { id: 'hunt-done:3', tone: 'warn', title: 'Hunt finished — 2 findings: sweep', when: '4m', href: null },
    ]);
    const { container } = mount();
    await flush();
    expect(container.querySelector('[data-testid="notif-badge"]')?.textContent).toBe('2');
  });
});

// The bell holds a notice per unread shadow hit. An analyst who read a hit on
// the Hunts page watched the strip and the sidebar move and the bell stand
// still for up to 15 s, so one number read two ways on one screen. The bell
// reads the list again the moment a hit is read or a lead changes.
describe('Topbar bell follows a hit that was read', () => {
  it('reads the notifications again when what needs the analyst changes', async () => {
    mount();
    await flush();
    expect(getNotifications).toHaveBeenCalledTimes(1);

    act(() => {
      emitNeedsYouChanged();
    });
    await flush();
    expect(getNotifications).toHaveBeenCalledTimes(2);
  });
});
