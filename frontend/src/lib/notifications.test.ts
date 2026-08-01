// Regression coverage for the stale-bell bug: a dismiss must broadcast so the
// Topbar badge (and the pane) can re-read immediately instead of waiting out
// their 15s poll — before the fix, "Clear all" left a red count on the bell.
// Also pins the verdict-enum → human-label rewrite for notification titles.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  NOTIFICATIONS_DISMISSED_EVENT,
  dismissMany,
  dismissNotification,
  formatNotificationTitle,
  getDismissed,
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
