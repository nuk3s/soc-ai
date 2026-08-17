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

/**
 * The row's relative time, as a phrase.
 *
 * The API sends a bare magnitude ('3m', '2h', '5d') — except under a minute,
 * where it sends the WORD "now". Appending " ago" unconditionally therefore
 * printed "now ago" on every fresh notification, which on a screen about what
 * just happened is most of them. The Topbar bell fixed that inline (F61) and
 * the pane kept the wart, so the same row read two ways depending on where you
 * looked at it; both surfaces call this now. An absent timestamp returns null
 * so callers render nothing rather than a lone "ago".
 */
export function formatNotificationWhen(when: string | null | undefined): string | null {
  if (!when) return null;
  return when === 'now' ? 'just now' : `${when} ago`;
}

// ── What produced this notification ────────────────────────────────────────

/** Which part of the app raised the item. */
export type NotificationKind = 'system' | 'host' | 'investigation' | 'hunt';

/**
 * The kinds in the order /notifications itself emits them: standing conditions
 * first (a down dependency, a dossier disagreement), then work — in flight, then
 * finished. The pane's preset chips and its group headers both read this, so the
 * two can never disagree about what a kind is called or where it sits.
 */
export const NOTIFICATION_KINDS: ReadonlyArray<{ id: NotificationKind; label: string }> = [
  { id: 'system', label: 'System' },
  { id: 'host', label: 'Hosts' },
  { id: 'investigation', label: 'Investigations' },
  { id: 'hunt', label: 'Hunts' },
];

/**
 * The source of a notification, off the id prefix the API mints.
 *
 * The id is already this list's stable identity — the dismissal store above is
 * built on it — so the prefix is the one discriminator that is guaranteed
 * present, unlike `href` (a down dependency has none) or `tone` (which says how
 * loud, not who). Matching the segment BEFORE the first colon rather than a
 * `startsWith` keeps `inv:` and `inv-done:` apart from anything that merely
 * begins with those letters.
 *
 * Anything unrecognised is `system`, never dropped: the bell badge counts the
 * same rows this pane shows, so a source a future build adds has to land in a
 * bucket rather than disappear out of one.
 */
export function notificationKind(n: { id: string }): NotificationKind {
  switch (n.id.split(':', 1)[0]) {
    case 'inv':
    case 'inv-done':
      return 'investigation';
    case 'hunt-done':
      return 'hunt';
    case 'dossier-conflict':
      return 'host';
    default:
      return 'system';
  }
}
