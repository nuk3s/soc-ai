// Regression coverage for the stale-bell bug: a dismiss must broadcast so the
// Topbar badge (and the pane) can re-read immediately instead of waiting out
// their 15s poll — before the fix, "Clear all" left a red count on the bell.
// Also pins the verdict-enum → human-label rewrite for notification titles.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  NOTIFICATIONS_DISMISSED_EVENT,
  NOTIFICATION_KINDS,
  dismissMany,
  dismissNotification,
  formatNotificationTitle,
  formatNotificationWhen,
  getDismissed,
  notificationKind,
} from './notifications';

describe('notification dismissal', () => {
  beforeEach(() => localStorage.clear());
  afterEach(() => localStorage.clear());

  it('persists dismissed ids and broadcasts on dismissMany', () => {
    const spy = vi.fn();
    window.addEventListener(NOTIFICATIONS_DISMISSED_EVENT, spy);
    dismissMany(['inv-done:INV-1', 'inv-done:INV-2']);
    window.removeEventListener(NOTIFICATIONS_DISMISSED_EVENT, spy);

    expect(getDismissed().has('inv-done:INV-1')).toBe(true);
    expect(getDismissed().has('inv-done:INV-2')).toBe(true);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('broadcasts on a single dismissNotification', () => {
    const spy = vi.fn();
    window.addEventListener(NOTIFICATIONS_DISMISSED_EVENT, spy);
    dismissNotification('inv-done:INV-9');
    window.removeEventListener(NOTIFICATIONS_DISMISSED_EVENT, spy);

    expect(getDismissed().has('inv-done:INV-9')).toBe(true);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('does not broadcast when there is nothing to dismiss', () => {
    const spy = vi.fn();
    window.addEventListener(NOTIFICATIONS_DISMISSED_EVENT, spy);
    dismissMany([]);
    window.removeEventListener(NOTIFICATIONS_DISMISSED_EVENT, spy);
    expect(spy).not.toHaveBeenCalled();
  });
});

describe('formatNotificationTitle', () => {
  it('maps the raw verdict enum to its human label', () => {
    expect(formatNotificationTitle('Verdict false_positive: ET INFO Observed DNS Query')).toBe(
      'False positive: ET INFO Observed DNS Query',
    );
    expect(formatNotificationTitle('Verdict true_positive: Suspicious PowerShell')).toBe(
      'True positive: Suspicious PowerShell',
    );
    expect(formatNotificationTitle('Verdict needs_more_info: INV-42')).toBe('Needs info: INV-42');
  });

  it('passes non-verdict titles through unchanged', () => {
    expect(formatNotificationTitle('Investigating: ET INFO Observed DNS Query')).toBe(
      'Investigating: ET INFO Observed DNS Query',
    );
    expect(formatNotificationTitle('Hunt finished — 2 findings: beaconing sweep')).toBe(
      'Hunt finished — 2 findings: beaconing sweep',
    );
  });

  it('leaves an unknown verdict token untouched', () => {
    expect(formatNotificationTitle('Verdict mystery_state: INV-1')).toBe('Verdict mystery_state: INV-1');
  });
});

describe('notificationKind', () => {
  it('reads the source off the id prefix the backend mints', () => {
    expect(notificationKind({ id: 'inv:01ABC' })).toBe('investigation');
    expect(notificationKind({ id: 'inv-done:01ABC' })).toBe('investigation');
    expect(notificationKind({ id: 'hunt-done:01ABC' })).toBe('hunt');
    expect(notificationKind({ id: 'dossier-conflict:10.0.0.14:hostname:2' })).toBe('host');
    expect(notificationKind({ id: 'dep-down:es:20260812234343' })).toBe('system');
  });

  it('does not confuse the two investigation prefixes', () => {
    // `inv-done:` must not be swallowed by a naive startsWith('inv') — both are
    // investigations here, but a substring match would also claim `invite:`.
    expect(notificationKind({ id: 'invite:99' })).toBe('system');
  });

  it('files an unrecognised source under system rather than dropping it', () => {
    // Kind is a lens, never a gate: a source this build has not heard of must
    // still appear somewhere, or the bell badge would out-count the pane.
    expect(notificationKind({ id: 'approval:tok-1' })).toBe('system');
    expect(notificationKind({ id: 'no-colon-at-all' })).toBe('system');
  });

  it('lists every kind the derivation can return', () => {
    const kinds = NOTIFICATION_KINDS.map((k) => k.id);
    expect(kinds).toEqual(['system', 'host', 'investigation', 'hunt']);
  });
});

describe('formatNotificationWhen', () => {
  // The API's relative label is a bare magnitude ('3m', '2h'), so the surface
  // appends "ago" — except under a minute, where the backend already returns
  // the word "now" and the append produced "now ago" (F61, fixed on the Topbar
  // bell and missed on the pane, which shows the SAME rows).
  it('reads "just now" under a minute, never "now ago"', () => {
    expect(formatNotificationWhen('now')).toBe('just now');
  });

  it('appends "ago" to a magnitude', () => {
    expect(formatNotificationWhen('3m')).toBe('3m ago');
    expect(formatNotificationWhen('2h')).toBe('2h ago');
    expect(formatNotificationWhen('5d')).toBe('5d ago');
  });

  it('has nothing to say when the backend sent no timestamp', () => {
    // _ago() returns '' for a missing @timestamp; the caller renders nothing
    // rather than a lone "ago".
    expect(formatNotificationWhen('')).toBeNull();
    expect(formatNotificationWhen(null)).toBeNull();
    expect(formatNotificationWhen(undefined)).toBeNull();
  });
});
