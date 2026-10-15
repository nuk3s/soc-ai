// The Notifications screen: the same Needs-you block, the same paging and the
// same Dismiss all as the bell panel.
//
// Production 2026-10-14: "Clear all" dismissed the 12 rows the screen had
// loaded, the header said "the 10 newest", and nothing could load the rest or
// clear the 300 unread shadow hits behind the badge.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getNotifications: vi.fn(),
  getNeedsYouCount: vi.fn(),
  markAllShadowHitsRead: vi.fn(),
}));

import { getNeedsYouCount, getNotifications, markAllShadowHitsRead, type NeedsYouCount } from '../lib/api';
import type { Notification } from '../lib/types';
import { Notifications } from './Notifications';

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

const ago = (minutes: number) => new Date(Date.now() - minutes * 60_000).toISOString();

const runs = (n: number, from = 0): Notification[] =>
  Array.from({ length: n }, (_, i) => ({
    id: `inv-done:R${from + i}`,
    tone: 'accent' as const,
    title: `Verdict false_positive: ET RUN ${from + i}`,
    when: '10m',
    href: `/investigation/R${from + i}`,
    at: ago(10 + i),
  }));

const tamper: Notification = {
  id: 'audit-chain-break:content_altered|x|1',
  tone: 'danger',
  title: 'Audit trail broken (content_altered): 1 record no longer matches its own hash',
  when: '10h',
  href: '/config',
  dismissible: false,
  at: ago(600),
};

const rows = () => screen.queryAllByTestId('notification-row');

const renderScreen = () =>
  render(
    <MemoryRouter>
      <Notifications />
    </MemoryRouter>,
  );

beforeEach(() => {
  localStorage.clear();
  vi.mocked(getNotifications).mockReset();
  vi.mocked(getNeedsYouCount).mockReset();
  vi.mocked(markAllShadowHitsRead).mockReset();
  vi.mocked(getNeedsYouCount).mockResolvedValue(PROD);
  vi.mocked(markAllShadowHitsRead).mockResolvedValue({ read: 300 });
});
afterEach(() => localStorage.clear());

describe('Notifications: the Needs-you block', () => {
  it('states every part of the count with its scope and its list', async () => {
    vi.mocked(getNotifications).mockResolvedValue(runs(2));
    renderScreen();
    const block = await screen.findByTestId('needs-you-block');
    await waitFor(() =>
      expect(within(block).getAllByTestId(/^needs-you-part-/).map((p) => p.textContent)).toEqual([
        '7 leads wait on a decision, all open',
        '300 shadow hits are unread, all unread',
        '2 verdicts need more info, last 30 days',
      ]),
    );
    expect(getNotifications).toHaveBeenCalledWith({ limit: 12, eventsOnly: true, after: null });
  });
});

describe('Notifications: paging', () => {
  it('says the loaded count, that more exist, and loads 20 more', async () => {
    vi.mocked(getNotifications).mockResolvedValueOnce(runs(12)).mockResolvedValueOnce(runs(15));
    const { container } = renderScreen();
    await screen.findByText(/ET RUN 0$/);
    expect(container.textContent).toContain(
      '12 items loaded: 12 completed investigations. More items exist. Select Show more to load them.',
    );
    fireEvent.click(screen.getByRole('button', { name: 'Show more' }));
    await waitFor(() => expect(rows()).toHaveLength(15));
    expect(getNotifications).toHaveBeenLastCalledWith({ limit: 32, eventsOnly: true, after: null });
    expect(screen.queryByRole('button', { name: 'Show more' })).toBeNull();
    expect(container.textContent).toContain('15 items: 15 completed investigations.');
  });
});

describe('Notifications: Dismiss all', () => {
  it('replaces Clear all and states what happens', async () => {
    vi.mocked(getNotifications).mockResolvedValue([...runs(2), tamper]);
    renderScreen();
    await screen.findByText(/ET RUN 0$/);
    await screen.findByTestId('needs-you-part-unread_shadow_hits');
    expect(screen.queryByRole('button', { name: /clear all/i })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss all' }));
    expect(screen.getByRole('group', { name: 'Confirm dismiss all' }).textContent).toContain(
      'Hide 2 events and mark 300 shadow hits read? Leads and verdicts that need more info stay. 1 notice you cannot dismiss stays.',
    );
  });

  it('hides the events, marks the hits read and keeps the tamper finding', async () => {
    vi.mocked(getNotifications).mockResolvedValue([...runs(2), tamper]);
    renderScreen();
    await screen.findByText(/ET RUN 0$/);
    await screen.findByTestId('needs-you-part-unread_shadow_hits');
    const before = Date.now();
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss all' }));
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss all' }));

    await waitFor(() => expect(markAllShadowHitsRead).toHaveBeenCalledTimes(1));
    const mark = vi.mocked(markAllShadowHitsRead).mock.calls[0][0];
    expect(Date.parse(mark)).toBeLessThanOrEqual(before);
    expect(localStorage.getItem('soc-ai:notifications-cleared-at')).toBe(mark);
    await waitFor(() => expect(rows()).toHaveLength(1));
    expect(rows()[0].textContent).toContain('Audit trail broken');
  });

  it('hides an older row the screen never loaded', async () => {
    vi.mocked(getNotifications).mockResolvedValue(runs(2));
    renderScreen();
    await screen.findByText(/ET RUN 0$/);
    await screen.findByTestId('needs-you-part-unread_shadow_hits');
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss all' }));
    // The read after the Dismiss all: a row older than the mark that the
    // screen never loaded, and a newer one. An older server ignores `after`.
    vi.mocked(getNotifications).mockResolvedValue([
      { ...runs(1, 50)[0], at: ago(120) },
      { ...runs(1, 60)[0], at: new Date(Date.now() + 60_000).toISOString() },
    ]);
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss all' }));
    await waitFor(() => expect(markAllShadowHitsRead).toHaveBeenCalled());
    await waitFor(() =>
      expect(rows().map((r) => r.textContent)).toEqual([expect.stringContaining('ET RUN 60')]),
    );
    expect(getNotifications).toHaveBeenLastCalledWith({
      limit: 12,
      eventsOnly: true,
      after: localStorage.getItem('soc-ai:notifications-cleared-at'),
    });
  });
});
