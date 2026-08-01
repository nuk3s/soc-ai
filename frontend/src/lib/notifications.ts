// Client-side dismissal for notifications. Notifications are derived fresh from
// live state on every fetch (no per-notification row to persist a "read" flag),
// so we remember dismissed ids locally and filter them out. Ids are stable
// (`inv:<id>` / `approval:<token>`), so a dismissed item stays dismissed and new
// ones still surface.

import { VERDICT } from './tokens';
import type { Verdict } from './types';

const KEY = 'soc-ai:dismissed-notifications';

/** Broadcast when the dismissed set changes so cross-component listeners (the
 * Topbar bell, the Notifications pane) can re-read immediately instead of
 * waiting out their poll interval — otherwise "Clear all" leaves a stale count
 * on the bell for up to 15s. */
export const NOTIFICATIONS_DISMISSED_EVENT = 'soc-ai:notifications-dismissed';

export function getDismissed(): Set<string> {
  try {
    return new Set(JSON.parse(localStorage.getItem(KEY) || '[]') as string[]);
  } catch {
    return new Set();
  }
}

export function dismissNotification(id: string): void {
  dismissMany([id]);
}

/** Dismiss several notifications in a single write — backs the "Clear all" action. */
export function dismissMany(ids: string[]): void {
  if (ids.length === 0) return;
  const set = getDismissed();
  for (const id of ids) set.add(id);
  // Bound the set so a long-lived browser can't grow it without limit.
  const arr = Array.from(set).slice(-200);
  try {
    localStorage.setItem(KEY, JSON.stringify(arr));
  } catch {
    // Writes can be blocked (site data disabled, private-mode quota) — the
    // caller's in-memory state update still proceeds; best-effort persistence.
  }
  // Notify other mounted views (bell badge, pane) to re-read the dismissed set
  // now, so a per-item dismiss or "Clear all" reflects everywhere immediately.
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(NOTIFICATIONS_DISMISSED_EVENT));
  }
}

/** Notification titles arrive from the API with the raw verdict enum baked in
 * (`Verdict false_positive: <rule>`). Swap the enum for its human label so the
 * bell and pane read like the rest of the UI. Non-verdict titles pass through
 * unchanged. */
export function formatNotificationTitle(title: string): string {
  const m = title.match(/^Verdict ([a-z_]+): ([\s\S]*)$/);
  if (!m) return title;
  const meta = VERDICT[m[1] as Verdict];
  if (!meta) return title;
  return `${meta.label}: ${m[2]}`;
}
