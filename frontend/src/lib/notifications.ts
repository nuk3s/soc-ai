// Client-side dismissal for notifications. Notifications are derived fresh from
// live state on every fetch (no per-notification row to persist a "read" flag),
// so we remember dismissed ids locally and filter them out. Ids are stable
// (`inv:<id>` / `approval:<token>`), so a dismissed item stays dismissed and new
// ones still surface.

const KEY = 'soc-ai:dismissed-notifications';

export function getDismissed(): Set<string> {
  try {
    return new Set(JSON.parse(localStorage.getItem(KEY) || '[]') as string[]);
  } catch {
    return new Set();
  }
}

export function dismissNotification(id: string): void {
  const set = getDismissed();
  set.add(id);
  // Bound the set so a long-lived browser can't grow it without limit.
  const arr = Array.from(set).slice(-200);
  localStorage.setItem(KEY, JSON.stringify(arr));
}
