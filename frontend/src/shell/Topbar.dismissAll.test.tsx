// The bell panel accounts for every unit of its badge, pages, and dismisses all.
//
// Production 2026-10-14: the badge read 309 (7 leads, 300 unread shadow hits,
// 2 runs that need more info) and the panel listed 12 rows, all shadow hits.
// A shadow hit has no dismiss control, so nothing in the bell could clear them.
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getWorkspaces: vi.fn(),
  getNotifications: vi.fn(),
  getHealth: vi.fn(),
  getNeedsYouCount: vi.fn(),
  markAllShadowHitsRead: vi.fn(),
}));

import {
  ApiError,
  getHealth,
  getNeedsYouCount,
  getNotifications,
  getWorkspaces,
  markAllShadowHitsRead,
  type NeedsYouCount,
} from '../lib/api';
import type { Notification } from '../lib/types';
import { ShellProvider } from './ShellContext';
import { Topbar } from './Topbar';

const NOW = new Date('2026-10-14T09:00:00Z');
const PROD: NeedsYouCount = {
  leads_needing_decision: 7,
  unread_shadow_hits: 300,
  untriaged_groups: 0,
  needs_more_info: 2,
  pending_actions: 0,
  total: 309,
  unknown: [],
  alert_window: '7d',
  verdict_window: '30d',
  alert_floor: false,
};

const minutesAgo = (m: number) => new Date(NOW.getTime() - m * 60_000).toISOString();

const event = (id: string, title: string, at: string | null, extra: Partial<Notification> = {}): Notification => ({
  id,
  tone: 'accent',
  title,
  when: '5m',
  href: `/x/${id}`,
  at,
  ...extra,
});

const runs = (n: number, from = 0): Notification[] =>
  Array.from({ length: n }, (_, i) => event(`inv-done:R${from + i}`, `Verdict false_positive: ET RUN ${from + i}`, minutesAgo(10 + i)));

const tick = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
const flush = () => tick(0);
const bell = () => screen.getByRole('button', { name: /^Notifications/ });
const panel = () => screen.getByRole('dialog', { name: 'Notifications' });
const badge = () => document.querySelector('[data-testid="notif-badge"]')?.textContent;
const titles = () => within(panel()).queryAllByTestId('bell-title').map((t) => t.textContent);

const mount = async () => {
  render(
    <MemoryRouter>
      <ShellProvider>
        <Topbar />
      </ShellProvider>
    </MemoryRouter>,
  );
  await flush();
  act(() => bell().click());
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
  localStorage.clear();
  vi.mocked(getWorkspaces).mockResolvedValue([]);
  vi.mocked(getHealth).mockResolvedValue({
    es: { ok: true, detail: 'ok' },
    llm: { ok: true, detail: 'ok' },
  } as never);
  vi.mocked(getNeedsYouCount).mockResolvedValue(PROD);
  vi.mocked(markAllShadowHitsRead).mockResolvedValue({ read: 300 });
});

afterEach(() => {
  vi.useRealTimers();
  localStorage.clear();
});

describe('the bell panel accounts for every unit of the badge', () => {
  it('lists each part of the count with its scope, and the parts add up to the badge', async () => {
    vi.mocked(getNotifications).mockResolvedValue([
      event('inv-done:A', 'Verdict false_positive: ET A', minutesAgo(5)),
      event('hunt-done:B', 'Hunt finished: no threat found. Sweep', minutesAgo(6)),
    ]);
    await mount();
    expect(badge()).toBe('309');
    const block = within(panel()).getByTestId('needs-you-block');
    const parts = within(block).getAllByTestId(/^needs-you-part-/).map((p) => p.textContent);
    expect(parts).toEqual([
      '7 leads wait on a decision, all open',
      '300 shadow hits are unread, all unread',
      '2 verdicts need more info, last 30 days',
    ]);
    const sum = parts.reduce((s, p) => s + Number(p!.split(' ')[0]), 0);
    expect(String(sum)).toBe(badge());
    expect(screen.getByTestId('notif-summary').textContent).toBe('309 need you · 2 notifications');
  });

  it('asks the server for the events only, and leaves the hit and lead rows to the block', async () => {
    // An older server sends the rows anyway. The block counts them already.
    vi.mocked(getNotifications).mockResolvedValue([
      event('shadow-hit:1', 'Shadow hit: a rare thing on 10.0.0.1', minutesAgo(3), { dismissible: false, group: 'hunting' }),
      event('lead:18', 'Lead 18 formed on host-a: rare process', minutesAgo(4), { group: 'hunting' }),
      event('inv-done:A', 'Verdict false_positive: ET A', minutesAgo(5)),
    ]);
    await mount();
    expect(getNotifications).toHaveBeenCalledWith({ limit: 12, eventsOnly: true, after: null });
    expect(titles()).toEqual(['False positive: ET A']);
  });

  it('says a part it could not read, as the badge "+" does', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue({
      ...PROD,
      untriaged_groups: null,
      unknown: ['untriaged_groups'],
    });
    vi.mocked(getNotifications).mockResolvedValue([]);
    await mount();
    expect(badge()).toBe('309+');
    expect(within(panel()).getByTestId('needs-you-part-untriaged_groups').textContent).toBe(
      'Could not count the alert groups. The grid did not answer.',
    );
  });
});

describe('Show more in the bell panel', () => {
  it('loads 20 more rows, and hides the control when the answer is not full', async () => {
    vi.mocked(getNotifications).mockResolvedValueOnce(runs(12)).mockResolvedValueOnce(runs(20));
    await mount();
    expect(titles()).toHaveLength(12);
    fireEvent.click(within(panel()).getByRole('button', { name: 'Show more' }));
    await flush();
    expect(getNotifications).toHaveBeenLastCalledWith({ limit: 32, eventsOnly: true, after: null });
    expect(titles()).toHaveLength(20);
    expect(within(panel()).queryByRole('button', { name: 'Show more' })).toBeNull();
  });

  // NEGATIVE CONTROL: a short answer has nothing more to show.
  it('offers no Show more under a short list', async () => {
    vi.mocked(getNotifications).mockResolvedValue(runs(3));
    await mount();
    expect(within(panel()).queryByRole('button', { name: 'Show more' })).toBeNull();
  });
});

describe('Dismiss all in the bell panel', () => {
  const tamper = event(
    'audit-chain-break:content_altered|x|1',
    'Audit trail broken (content_altered): 1 record no longer matches its own hash',
    minutesAgo(600),
    { dismissible: false, tone: 'danger' },
  );

  it('states exactly what happens before it acts', async () => {
    vi.mocked(getNotifications).mockResolvedValue([...runs(2), tamper]);
    await mount();
    fireEvent.click(within(panel()).getByRole('button', { name: 'Dismiss all' }));
    expect(within(panel()).getByRole('group', { name: 'Confirm dismiss all' }).textContent).toContain(
      'Hide 2 notifications and mark 300 shadow hits read? Leads and verdicts that need more info stay. 1 notice you cannot dismiss stays.',
    );
    expect(markAllShadowHitsRead).not.toHaveBeenCalled();
    expect(localStorage.getItem('soc-ai:notifications-cleared-at')).toBeNull();
  });

  // NEGATIVE CONTROL: Cancel changes nothing.
  it('does nothing on Cancel', async () => {
    vi.mocked(getNotifications).mockResolvedValue(runs(2));
    await mount();
    fireEvent.click(within(panel()).getByRole('button', { name: 'Dismiss all' }));
    fireEvent.click(within(panel()).getByRole('button', { name: 'Cancel' }));
    expect(markAllShadowHitsRead).not.toHaveBeenCalled();
    expect(titles()).toHaveLength(2);
  });

  it('hides the events, marks the hits read on the server and leaves the decisions', async () => {
    vi.mocked(getNotifications).mockResolvedValue([...runs(2), tamper]);
    await mount();
    expect(getNeedsYouCount).toHaveBeenCalledTimes(1);
    // The count after the read: the hits are gone, the decisions stay.
    vi.mocked(getNeedsYouCount).mockResolvedValue({ ...PROD, unread_shadow_hits: 0, total: 9 });

    fireEvent.click(within(panel()).getByRole('button', { name: 'Dismiss all' }));
    fireEvent.click(within(panel()).getByRole('button', { name: 'Dismiss all' }));
    await flush();

    expect(markAllShadowHitsRead).toHaveBeenCalledTimes(1);
    // The count the prompt named travels with the call, so the server refuses
    // to mark a hit that arrived after it.
    expect(markAllShadowHitsRead).toHaveBeenCalledWith(NOW.toISOString(), 300);
    expect(localStorage.getItem('soc-ai:notifications-cleared-at')).toBe(NOW.toISOString());
    // The tamper finding is never hidden.
    expect(titles()).toEqual([tamper.title]);
    // The badge read the count again at once, and the leads are still on it.
    expect(getNeedsYouCount).toHaveBeenCalledTimes(2);
    expect(badge()).toBe('9');
    const parts = within(panel()).getAllByTestId(/^needs-you-part-/).map((p) => p.textContent);
    expect(parts).toEqual(['7 leads wait on a decision, all open', '2 verdicts need more info, last 30 days']);
    // The next read sends the moment, so hidden rows take no place in the limit.
    expect(getNotifications).toHaveBeenLastCalledWith({ limit: 12, eventsOnly: true, after: NOW.toISOString() });
  });

  it('says so when the server could not mark the hits read, and offers it again', async () => {
    vi.mocked(markAllShadowHitsRead).mockRejectedValue(new Error('503'));
    vi.mocked(getNotifications).mockResolvedValue(runs(2));
    await mount();
    fireEvent.click(within(panel()).getByRole('button', { name: 'Dismiss all' }));
    fireEvent.click(within(panel()).getByRole('button', { name: 'Dismiss all' }));
    await flush();
    expect(within(panel()).getByRole('alert').textContent).toBe(
      'Dismiss all hid the notifications. It could not mark the shadow hits read. Try again.',
    );
    expect(titles()).toEqual([]);
    // The hits are still unread, so the control is there to try again.
    expect(within(panel()).getByRole('button', { name: 'Dismiss all' })).toBeTruthy();
  });

  it('says so when new shadow hits arrived after the count, and marks none', async () => {
    vi.mocked(markAllShadowHitsRead).mockRejectedValue(
      new ApiError('New shadow hits arrived.', 409, 'shadow_hits_changed'),
    );
    vi.mocked(getNotifications).mockResolvedValue(runs(2));
    await mount();
    fireEvent.click(within(panel()).getByRole('button', { name: 'Dismiss all' }));
    fireEvent.click(within(panel()).getByRole('button', { name: 'Dismiss all' }));
    await flush();
    expect(within(panel()).getByRole('alert').textContent).toBe(
      'New shadow hits arrived after the count. Dismiss all hid the notifications and marked no hit read. Check the new count and try again.',
    );
    expect(within(panel()).getByRole('button', { name: 'Dismiss all' })).toBeTruthy();
  });

  it('hides an older row it never loaded, and shows a newer one', async () => {
    vi.mocked(getNotifications).mockResolvedValue(runs(2));
    await mount();
    fireEvent.click(within(panel()).getByRole('button', { name: 'Dismiss all' }));
    fireEvent.click(within(panel()).getByRole('button', { name: 'Dismiss all' }));
    await flush();

    // An older server ignores the moment and sends an old row it never sent.
    vi.mocked(getNotifications).mockResolvedValue([
      event('inv-done:OLD', 'Verdict false_positive: ET OLD', minutesAgo(90)),
      event('inv-done:NEW', 'Verdict false_positive: ET NEW', new Date(NOW.getTime() + 60_000).toISOString()),
    ]);
    await tick(15_000);
    expect(titles()).toEqual(['False positive: ET NEW']);
  });
});
