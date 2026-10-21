// Client-side dismissal for notifications. Notifications are derived fresh from
// live state on every fetch (no per-notification row to persist a "read" flag),
// so we remember dismissed ids locally and filter them out. Ids are stable
// (`inv:<id>` / `approval:<token>`), so a dismissed item stays dismissed and new
// ones still surface.

import { emitNeedsYouChanged, markAllShadowHitsRead, type NeedsYouCount } from './api';
import { OUTCOME_LABELS, TONE, humanize, outcomeMeta } from './labels';
import { VERDICT } from './tokens';
import type { Notification, Verdict } from './types';

const KEY = 'soc-ai:dismissed-notifications';

/** The moment of the last Dismiss all, as ISO-8601. Every dismissible row at or
 *  before it is hidden, the rows the list never loaded too. */
const CLEARED_AT_KEY = 'soc-ai:notifications-cleared-at';

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
  return when === 'now' ? 'now' : `${when} ago`;
}

// ── What produced this notification ────────────────────────────────────────

/** Which part of the app raised the item. */
export type NotificationKind = 'system' | 'host' | 'investigation' | 'hunting';

/**
 * The kinds in the order /notifications itself emits them: standing conditions
 * first (a down dependency, a dossier disagreement), then work. The pane's
 * preset chips and its group headers both read this, so the two can never
 * disagree about what a kind is called or where it sits.
 *
 * "Hunting" holds shadow hits, leads and finished hunts. Shadow hits and leads
 * used to fall to "System" on the chips while their heading said HUNTING, so
 * the chip and the heading named one row two ways (D7, RD7).
 */
export const NOTIFICATION_KINDS: ReadonlyArray<{ id: NotificationKind; label: string }> = [
  { id: 'system', label: 'System' },
  { id: 'host', label: 'Hosts' },
  { id: 'investigation', label: 'Investigations' },
  { id: 'hunting', label: 'Hunting' },
];

/** The one empty-state line for the bell and the Notifications screen. They
 *  said "No notifications." and "No active notifications." (D8). */
export const NO_NOTIFICATIONS = 'No active notifications.';

/** The rows that are part of the needs-you count: the leads and the unread
 *  shadow hits. Every other row is an event. The bell panel and the
 *  Notifications screen show the count in a Needs-you block and ask the API
 *  for the events only, so these rows arrive only from an older server. Both
 *  surfaces leave them out, so one unit never shows twice. */
const NEEDS_YOU_ROWS = new Set(['lead', 'lead-more', 'shadow-hit']);

export function isNeedsYouRow(n: { id: string }): boolean {
  return NEEDS_YOU_ROWS.has(n.id.split(':', 1)[0]);
}

/** The rows GET /notifications returns when the console names no limit
 *  (routes_meta.NOTIF_DEFAULT_LIMIT). The bell and the screen open on it. */
export const NOTIFICATIONS_CAP = 12;

/** How many rows "Show more" adds. */
export const NOTIFICATIONS_STEP = 20;

/** The most rows GET /notifications returns (routes_meta.NOTIF_MAX_LIMIT). */
export const NOTIFICATIONS_MAX = 200;

/** The limit after one "Show more". */
export function nextNotificationLimit(limit: number): number {
  return Math.min(limit + NOTIFICATIONS_STEP, NOTIFICATIONS_MAX);
}

/** Whether more rows can exist past the ones loaded. The API cuts the list at
 *  the limit, so a full answer can have more behind it and a short one cannot. */
export function hasMoreNotifications(received: number, limit: number): boolean {
  return received >= limit && limit < NOTIFICATIONS_MAX;
}

// ── Dismiss all ────────────────────────────────────────────────────────────

/** The moment of the last Dismiss all, or null when there was none. */
export function getClearedAt(): string | null {
  try {
    const raw = localStorage.getItem(CLEARED_AT_KEY);
    return raw && !Number.isNaN(Date.parse(raw)) ? raw : null;
  } catch {
    return null;
  }
}

type Hideable = { id: string; dismissible?: boolean; at?: string | null };

/**
 * Whether the console hides a row.
 *
 * A row dismissed by its id is hidden. A dismissible row whose moment is at or
 * before the last Dismiss all is hidden too, so a row the list never loaded is
 * covered. A row the server marks undismissible is never hidden by the moment:
 * that is the tamper finding, and no local click may hide it.
 */
export function isHiddenNotification(
  n: Hideable,
  dismissed: ReadonlySet<string>,
  clearedAt: string | null,
): boolean {
  if (dismissed.has(n.id)) return true;
  if (n.dismissible === false || !n.at || !clearedAt) return false;
  const at = Date.parse(n.at);
  return !Number.isNaN(at) && at <= Date.parse(clearedAt);
}

/** The rows the console shows: every row the analyst has not hidden. */
export function visibleNotifications<T extends Hideable>(rows: ReadonlyArray<T>): T[] {
  const dismissed = getDismissed();
  const clearedAt = getClearedAt();
  return rows.filter((n) => !isHiddenNotification(n, dismissed, clearedAt));
}

/** The parts of the needs-you count that are decisions. Dismiss all leaves them. */
export type DecisionPart = 'leads_needing_decision' | 'untriaged_groups' | 'needs_more_info' | 'pending_actions';

const DECISION_PARTS: ReadonlyArray<[DecisionPart, string]> = [
  ['leads_needing_decision', 'leads'],
  ['untriaged_groups', 'alert groups with no verdict'],
  ['needs_more_info', 'verdicts that need more info'],
  ['pending_actions', 'recommended actions'],
];

/** The decisions that stay after a Dismiss all: the parts above zero, or every
 *  part when the count could not be read. */
export function decisionsThatStay(data: NeedsYouCount | null): DecisionPart[] {
  return DECISION_PARTS.map(([key]) => key).filter((key) => {
    if (!data) return true;
    const value = data[key];
    return value === null || value > 0;
  });
}

function joinWords(words: string[]): string {
  if (words.length <= 1) return words.join('');
  return `${words.slice(0, -1).join(', ')} and ${words[words.length - 1]}`;
}

/**
 * The confirm sentence of Dismiss all. It states what is hidden, what is
 * marked read on the server and what stays.
 *
 * `events` is the dismissible event rows on the list, `more` says the list was
 * cut, `shadowHits` is the unread count (null when it could not be read),
 * `stay` the decisions that stay and `fixed` the rows nobody can dismiss.
 */
export function dismissAllPrompt(p: {
  events: number;
  more: boolean;
  shadowHits: number | null;
  stay: ReadonlyArray<DecisionPart>;
  fixed: number;
}): string {
  const acts: string[] = [];
  if (p.events > 0) {
    const noun = p.events === 1 ? 'notification' : 'notifications';
    acts.push(p.more ? `hide ${p.events} ${noun} and every older notification` : `hide ${p.events} ${noun}`);
  }
  if (p.shadowHits === null) acts.push('mark every unread shadow hit read');
  else if (p.shadowHits > 0) {
    acts.push(`mark ${p.shadowHits} shadow hit${p.shadowHits === 1 ? '' : 's'} read`);
  }
  const ask = acts.length > 0 ? `${acts.join(' and ')}?` : 'nothing to dismiss.';
  const sentences = [ask.charAt(0).toUpperCase() + ask.slice(1)];
  const stay = DECISION_PARTS.filter(([key]) => p.stay.includes(key)).map(([, words]) => words);
  if (stay.length > 0) {
    const list = joinWords(stay);
    sentences.push(`${list.charAt(0).toUpperCase()}${list.slice(1)} stay.`);
  }
  if (p.fixed > 0) {
    sentences.push(
      p.fixed === 1 ? '1 notice you cannot dismiss stays.' : `${p.fixed} notices you cannot dismiss stay.`,
    );
  }
  return sentences.join(' ');
}

/** The sentence the confirm adds after the prompt: what an Undo restores and
 *  what it cannot. The server marks the shadow hits read, and no local undo
 *  can take that back (dogfood 2026-10-19, R1-I6). */
export function dismissAllUndoNote(p: { events: number; shadowHits: number | null }): string {
  const parts: string[] = [];
  if (p.events > 0) parts.push('Undo shows the notifications again.');
  if (p.shadowHits === null || p.shadowHits > 0) parts.push('The shadow hits stay read.');
  return parts.join(' ');
}

/** The local hide before a Dismiss all, for its Undo. */
export interface DismissalSnapshot {
  dismissed: string[];
  clearedAt: string | null;
}

/** Read the local hide: the dismissed ids and the stored moment. */
export function snapshotDismissals(): DismissalSnapshot {
  return { dismissed: Array.from(getDismissed()), clearedAt: getClearedAt() };
}

/** Put the local hide back the way a snapshot read it, and tell every
 *  surface to read the list again. The shadow hits the server marked read
 *  stay read. */
export function restoreDismissals(snapshot: DismissalSnapshot): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(snapshot.dismissed));
    if (snapshot.clearedAt) localStorage.setItem(CLEARED_AT_KEY, snapshot.clearedAt);
    else localStorage.removeItem(CLEARED_AT_KEY);
  } catch {
    // Writes can be blocked. The rows then stay hidden.
  }
  if (typeof window !== 'undefined') window.dispatchEvent(new CustomEvent(NOTIFICATIONS_DISMISSED_EVENT));
  emitNeedsYouChanged();
}

/**
 * Dismiss all: one helper for the bell panel and the Notifications screen.
 *
 * 1. Store `loadedAt` as the moment of the last Dismiss all. Every dismissible
 *    row at or before it is hidden, the rows the list never loaded too. The
 *    moment never moves back.
 * 2. Dismiss the loaded dismissible rows by id as well, so a server clock
 *    ahead of this one cannot keep a row the analyst saw.
 * 3. Mark every unread shadow hit born at or before the moment read on the
 *    server, which writes an audit record. A hit born later was not in the
 *    count the analyst saw, so it stays unread. No call is made when the
 *    count says no hit is unread.
 * 4. Tell every surface that counts what needs the analyst to read it again.
 *
 * Leads, alert groups, runs that need more info and recommended actions are
 * decisions. Nothing here touches them.
 *
 * Resolves with the number of hits the server read, or null when no call was
 * made. Rejects when the server call fails. The rows stay hidden then.
 */
export async function dismissAll(p: {
  rows: ReadonlyArray<Notification>;
  loadedAt: number;
  shadowHits: number | null;
}): Promise<number | null> {
  const before = new Date(p.loadedAt).toISOString();
  const previous = getClearedAt();
  if (!previous || Date.parse(previous) < p.loadedAt) {
    try {
      localStorage.setItem(CLEARED_AT_KEY, before);
    } catch {
      // Writes can be blocked. The per-id dismissal below still holds for the
      // rows on screen.
    }
  }
  const ids = p.rows.filter((n) => n.dismissible !== false).map((n) => n.id);
  if (ids.length > 0) dismissMany(ids);
  else if (typeof window !== 'undefined') window.dispatchEvent(new CustomEvent(NOTIFICATIONS_DISMISSED_EVENT));
  try {
    if (p.shadowHits === 0) return null;
    const answer = await markAllShadowHitsRead(before, p.shadowHits ?? undefined);
    return answer.read;
  } finally {
    emitNeedsYouChanged();
  }
}

/**
 * The source of a notification, off the id prefix the API mints.
 *
 * The id is already this list's stable identity — the dismissal store above is
 * built on it — so the prefix is the one discriminator that is guaranteed
 * present, unlike `href` (a down dependency has none) or `tone` (which says how
 * loud, not who). Matching the segment BEFORE the first colon rather than a
 * `startsWith` keeps `inv:` and `inv-done:` apart from anything that merely
 * begins with those letters. A row whose wire `group` is "hunting" is hunting
 * whatever its prefix. The wire says "system" for every other row, so only
 * "hunting" on the wire decides anything.
 *
 * Anything unrecognised is `system`, never dropped: the bell badge counts the
 * same rows this pane shows, so a source a future build adds has to land in a
 * bucket rather than disappear out of one.
 */
export function notificationKind(n: { id: string; group?: unknown }): NotificationKind {
  if (n.group === 'hunting') return 'hunting';
  switch (n.id.split(':', 1)[0]) {
    case 'inv':
    case 'inv-done':
    // A failed triage is an investigation that ended with no verdict. It sat
    // under "System" while the Investigations chip held verdicts only (D7).
    case 'inv-failed':
      return 'investigation';
    case 'hunt':
    case 'hunt-done':
    // One line for the catalog runs of one sweep that share an outcome.
    case 'hunt-sweep':
    case 'lead':
    case 'lead-more':
    case 'shadow-hit':
    case 'analytic-held':
      return 'hunting';
    case 'dossier-conflict':
      return 'host';
    default:
      return 'system';
  }
}

/** The noun for each row source, singular and plural. */
const ROW_NOUN: Record<string, [string, string]> = {
  'shadow-hit': ['shadow hit', 'shadow hits'],
  // The budget moved an analytic to shadow. The row is a hunting row, and
  // the header called it a system notice (dogfood 2026-10-19, R1-D15).
  'analytic-held': ['analytic notice', 'analytic notices'],
  lead: ['lead', 'leads'],
  inv: ['running investigation', 'running investigations'],
  'inv-failed': ['failed triage', 'failed triages'],
  'inv-done': ['completed investigation', 'completed investigations'],
  'hunt-done': ['finished hunt', 'finished hunts'],
  'hunt-sweep': ['catalog sweep', 'catalog sweeps'],
  hunt: ['running hunt', 'running hunts'],
  'lead-more': ['count of more leads', 'counts of more leads'],
  'dossier-conflict': ['host disagreement', 'host disagreements'],
};
const SYSTEM_NOUN: [string, string] = ['system notice', 'system notices'];

/**
 * The header line of the Notifications screen.
 *
 * It names only the row types that are present, in list order, with a count
 * each. The header said "shadow hits, leads, hunts and investigations from the
 * last 24 h" whatever the list held, over 10 completed investigations out of
 * 65 (D3).
 *
 * `more` is true when the API answered with a full list, so more rows can
 * exist. The header then says the count is what was loaded, and that "Show
 * more" loads the rest. It said "the 10 newest" over a list cut at 12 rows,
 * and nothing could load the rest (production 2026-10-14).
 *
 * Only finished runs have a window. A lead stays on the list until somebody
 * decides it, whenever it formed, so the window is said once, after the list,
 * and only when the list holds a finished run.
 */
export function describeNotifications(rows: ReadonlyArray<{ id: string }>, more: boolean): string {
  if (rows.length === 0) return '0 notifications.';
  const order: string[] = [];
  const counts = new Map<string, number>();
  for (const r of rows) {
    const prefix = r.id.split(':', 1)[0];
    const key = prefix in ROW_NOUN ? prefix : 'system';
    if (!counts.has(key)) order.push(key);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  const parts = order.map((key) => {
    const n = counts.get(key)!;
    const [one, many] = ROW_NOUN[key] ?? SYSTEM_NOUN;
    return `${n} ${n === 1 ? one : many}`;
  });
  const list = joinWords(parts);
  const finished = rows.some((r) => FINISHED_RUNS.has(r.id.split(':', 1)[0]));
  const window = finished ? ' Finished runs cover the last 24 h.' : '';
  // One row has one name on every surface: a notification. The header said
  // "items" and the bell said "events" (dogfood 2026-10-19, V1-S7).
  const count = `${rows.length} notification${rows.length === 1 ? '' : 's'}`;
  if (!more) return `${count}: ${list}.${window}`;
  return `${count} loaded: ${list}. More notifications exist. Select Show more to load them.${window}`;
}

/** The rows that report a finished run. Only these have a 24 h window. */
const FINISHED_RUNS = new Set(['inv-done', 'inv-failed', 'hunt-done', 'hunt-sweep']);

/** The label and colour of a hunt outcome, from lib/labels.ts, or null for
 *  a row with none. An outcome this build does not know keeps its own words
 *  in amber, so a newer server cannot make a hunt read as clean. */
export function huntOutcomeChip(outcome: string | null | undefined): { label: string; color: string } | null {
  if (!outcome) return null;
  const m = outcomeMeta(outcome);
  if (m.label === humanize(outcome) && !(outcome in OUTCOME_LABELS)) return { label: m.label, color: TONE.warn.color };
  return { label: m.label, color: m.color };
}
