// ---------------------------------------------------------------------------
// Shared facts about the host page's LIVE half.
//
// Both of the things here were previously decided independently in two places.
// They agreed, but nothing made them agree, and the two failure modes are the
// kind this codebase treats as serious: a strip saying "last good read" above a
// row saying "could not be read", and an honesty footnote that quietly becomes
// false the day a server constant moves.
// ---------------------------------------------------------------------------

import type { HostActivity } from './types';

/**
 * What the page HAS of the live half.
 *
 * `loading` is deliberately NOT an input. `useAsync` keeps the last-good data
 * through a foreground failure and clears `error` when a retry starts, so a
 * re-read over good data is already `ok` while its request is in flight —
 * whether a request is running governs dimming and disabling, which is a
 * different question from what there is to show. Folding the two together is
 * precisely what would let a manual refresh blank a populated panel.
 */
export type ActivityState =
  /** Nothing has arrived yet. */
  | 'loading'
  /** The grid answered. */
  | 'ok'
  /** A read failed with nothing to fall back on — say so where the data would be. */
  | 'down'
  /** A refresh failed OVER a good read: what is on screen is older than it looks. */
  | 'stale';

export function activityState(
  activity: HostActivity | null,
  error: Error | null,
): ActivityState {
  if (error) return activity ? 'stale' : 'down';
  return activity ? 'ok' : 'loading';
}

// There are deliberately no copied server cap constants here any more. The wire
// now says when a list WAS cut (`peers_truncated` / `users_truncated`, decided
// by the backend from the pre-cut lengths), so the truncation footnotes read
// the flags instead of comparing lengths against a constant that could drift.
