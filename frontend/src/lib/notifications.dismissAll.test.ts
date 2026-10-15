// Dismiss all, the paging helpers and the moment a Dismiss all stores.
//
// Production 2026-10-14: the bell badge read 309 and the panel listed 12 shadow
// hits. A shadow hit is not dismissible from a browser, so nothing in the bell
// could clear them, and "Clear all" on the Notifications screen dismissed only
// the 12 rows it had loaded. Dismiss all now stores a moment and hides every
// dismissible row up to it, the rows it never loaded too, and marks every
// unread shadow hit up to it read on the server.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('./api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./api')>()),
  markAllShadowHitsRead: vi.fn(),
}));

import { markAllShadowHitsRead, onNeedsYouChanged } from './api';
import {
  NOTIFICATIONS_CAP,
  NOTIFICATIONS_DISMISSED_EVENT,
  NOTIFICATIONS_MAX,
  dismissAll,
  dismissAllPrompt,
  dismissNotification,
  getClearedAt,
  hasMoreNotifications,
  nextNotificationLimit,
  visibleNotifications,
} from './notifications';
import type { Notification } from './types';

const LOADED = Date.parse('2026-10-14T09:00:00Z');

const row = (id: string, at: string | null, extra: Partial<Notification> = {}): Notification => ({
  id,
  tone: 'accent',
  title: id,
  when: '1h',
  href: null,
  at,
  ...extra,
});

beforeEach(() => {
  localStorage.clear();
  vi.mocked(markAllShadowHitsRead).mockReset();
  vi.mocked(markAllShadowHitsRead).mockResolvedValue({ read: 300 });
});
afterEach(() => localStorage.clear());

describe('the paging helpers', () => {
  it('steps the limit by 20 up to the API maximum', () => {
    expect(nextNotificationLimit(NOTIFICATIONS_CAP)).toBe(32);
    expect(nextNotificationLimit(32)).toBe(52);
    expect(nextNotificationLimit(195)).toBe(NOTIFICATIONS_MAX);
  });

  it('offers more only when the API answered with a full list', () => {
    expect(hasMoreNotifications(12, 12)).toBe(true);
    expect(hasMoreNotifications(11, 12)).toBe(false);
    expect(hasMoreNotifications(200, NOTIFICATIONS_MAX)).toBe(false);
  });
});

describe('dismissAll', () => {
  it('stores the load moment, hides the loaded rows and marks the shadow hits read', async () => {
    const events = vi.fn();
    const needsYou = vi.fn();
    window.addEventListener(NOTIFICATIONS_DISMISSED_EVENT, events);
    const stop = onNeedsYouChanged(needsYou);
    const rows = [row('inv-done:1', '2026-10-14T08:00:00+00:00'), row('hunt-done:2', '2026-10-14T08:30:00+00:00')];

    const read = await dismissAll({ rows, loadedAt: LOADED, shadowHits: 300 });

    window.removeEventListener(NOTIFICATIONS_DISMISSED_EVENT, events);
    stop();
    expect(read).toBe(300);
    expect(getClearedAt()).toBe('2026-10-14T09:00:00.000Z');
    expect(markAllShadowHitsRead).toHaveBeenCalledWith('2026-10-14T09:00:00.000Z', 300);
    expect(visibleNotifications(rows)).toEqual([]);
    expect(events).toHaveBeenCalled();
    // The badge reads the needs-you count again at once.
    expect(needsYou).toHaveBeenCalled();
  });

  it('hides an older row it never loaded, and keeps a newer one', async () => {
    await dismissAll({ rows: [], loadedAt: LOADED, shadowHits: 0 });
    const older = row('inv-done:old', '2026-10-14T07:00:00+00:00');
    const atTheMark = row('inv-done:mark', '2026-10-14T09:00:00+00:00');
    const newer = row('inv-done:new', '2026-10-14T09:00:01+00:00');
    expect(visibleNotifications([older, atTheMark, newer])).toEqual([newer]);
  });

  // NEGATIVE CONTROL: a row the server marks undismissible is a tamper finding.
  // No local click may hide it, however old it is.
  it('never hides an undismissible row', async () => {
    await dismissAll({ rows: [], loadedAt: LOADED, shadowHits: 0 });
    const tamper = row('audit-chain-break:content_altered|x|1', '2026-10-01T00:00:00+00:00', {
      dismissible: false,
      tone: 'danger',
    });
    expect(visibleNotifications([tamper])).toEqual([tamper]);
  });

  it('keeps a row with no moment, and hides it on a per-row dismissal only', async () => {
    await dismissAll({ rows: [], loadedAt: LOADED, shadowHits: 0 });
    const timeless = row('dep-down:es:1', null);
    expect(visibleNotifications([timeless])).toEqual([timeless]);
    dismissNotification('dep-down:es:1');
    expect(visibleNotifications([timeless])).toEqual([]);
  });

  it('does not call the server when no shadow hit is unread', async () => {
    await dismissAll({ rows: [row('inv-done:1', null)], loadedAt: LOADED, shadowHits: 0 });
    expect(markAllShadowHitsRead).not.toHaveBeenCalled();
  });

  it('calls the server when the count of shadow hits is unknown', async () => {
    await dismissAll({ rows: [], loadedAt: LOADED, shadowHits: null });
    // With no count to name, no guard travels with the call.
    expect(markAllShadowHitsRead).toHaveBeenCalledWith('2026-10-14T09:00:00.000Z', undefined);
  });

  it('never moves the stored moment back', async () => {
    await dismissAll({ rows: [], loadedAt: LOADED, shadowHits: 0 });
    await dismissAll({ rows: [], loadedAt: LOADED - 60_000, shadowHits: 0 });
    expect(getClearedAt()).toBe('2026-10-14T09:00:00.000Z');
  });

  it('keeps the rows hidden when the server call fails, and reports the failure', async () => {
    vi.mocked(markAllShadowHitsRead).mockRejectedValue(new Error('503'));
    const rows = [row('inv-done:1', '2026-10-14T08:00:00+00:00')];
    await expect(dismissAll({ rows, loadedAt: LOADED, shadowHits: 3 })).rejects.toThrow('503');
    expect(visibleNotifications(rows)).toEqual([]);
  });
});

describe('dismissAllPrompt', () => {
  it('states what happens and what stays', () => {
    expect(
      dismissAllPrompt({ events: 14, more: false, shadowHits: 300, stay: ['leads_needing_decision', 'needs_more_info'], fixed: 0 }),
    ).toBe('Hide 14 events and mark 300 shadow hits read? Leads and verdicts that need more info stay.');
  });

  it('says when more events exist than the list loaded', () => {
    expect(dismissAllPrompt({ events: 12, more: true, shadowHits: 0, stay: [], fixed: 0 })).toBe(
      'Hide 12 events and every older event?',
    );
  });

  it('names every decision that stays, and the notices nobody can dismiss', () => {
    expect(
      dismissAllPrompt({
        events: 1,
        more: false,
        shadowHits: 1,
        stay: ['leads_needing_decision', 'untriaged_groups', 'needs_more_info', 'pending_actions'],
        fixed: 1,
      }),
    ).toBe(
      'Hide 1 event and mark 1 shadow hit read? Leads, alert groups with no verdict, verdicts that need more info and recommended actions stay. 1 notice you cannot dismiss stays.',
    );
  });

  it('marks every unread shadow hit when the count is unknown', () => {
    expect(dismissAllPrompt({ events: 0, more: false, shadowHits: null, stay: [], fixed: 0 })).toBe(
      'Mark every unread shadow hit read?',
    );
  });
});
