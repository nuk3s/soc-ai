// ---------------------------------------------------------------------------
// The Needs you list: one list the analyst works from top to bottom.
//
// The server sends the items oldest first. The page puts the campaigns first,
// because the campaign is the unit of work, then the investigations, the
// leads and the one item of the alert groups. Inside each type the oldest
// item comes first. An item stays until a person decides it, so the age
// states how long it waits, and past 30 days it states the days with no
// decision.
// ---------------------------------------------------------------------------

import type { NeedsYouItem, NeedsYouItemType } from './api';

/** The most items the server sends. */
export const NEEDS_YOU_LIMIT = 200;

/** Past this many days an item reads "No decision for {n} days". */
export const OLD_DAYS = 30;

export const NEEDS_YOU_TYPE_ORDER: readonly NeedsYouItemType[] = ['campaign', 'investigation', 'lead', 'alerts'];

export const NEEDS_YOU_TYPE_LABEL: Record<NeedsYouItemType, string> = {
  campaign: 'Campaign',
  investigation: 'Investigation',
  lead: 'Lead',
  alerts: 'Alerts',
};

/** The words of the one link of a row. */
export const NEEDS_YOU_OPEN: Record<NeedsYouItemType, string> = {
  campaign: 'Open the campaign',
  investigation: 'Open the investigation',
  lead: 'Open the lead',
  alerts: 'Open the alerts',
};

export const NEEDS_YOU_EMPTY = 'Nothing needs you.';
/** The empty list when a type could not be read: a floor is no "nothing". */
export const NEEDS_YOU_EMPTY_FLOOR = 'The list holds no item that soc-ai could read.';
export const NEEDS_YOU_SCOPE =
  'The list holds each decision at any age, campaigns first. Each type lists its oldest item first.';

export function needsYouTypeLabel(t: NeedsYouItemType): string {
  return NEEDS_YOU_TYPE_LABEL[t] ?? String(t);
}

export function needsYouOpenLabel(t: NeedsYouItemType): string {
  return NEEDS_YOU_OPEN[t] ?? 'Open';
}

/** "14 decisions wait on you." A floor reads "At least 14 decisions wait on
 *  you.": the top bar marks the same number with "+". */
export function needsYouTotalWords(n: number, floor = false): string {
  if (floor && n === 0) return 'soc-ai could not count what needs you.';
  const words = n === 1 ? '1 decision waits on you.' : `${n.toLocaleString()} decisions wait on you.`;
  return floor ? `At least ${words}` : words;
}

const UNREAD_WORDS: Record<NeedsYouItemType, string> = {
  campaign: 'the campaigns',
  investigation: 'the investigations',
  lead: 'the leads',
  alerts: 'the alert groups',
};

/** "soc-ai could not read the campaigns and the alert groups.", or null
 *  when every type was read. */
export function needsYouUnreadWords(unknown: readonly NeedsYouItemType[] | undefined): string | null {
  const words = (unknown ?? []).map((t) => UNREAD_WORDS[t] ?? String(t));
  if (words.length === 0) return null;
  const list = words.length === 1 ? words[0] : `${words.slice(0, -1).join(', ')} and ${words[words.length - 1]}`;
  return `soc-ai could not read ${list}.`;
}

function rank(t: NeedsYouItemType): number {
  const i = NEEDS_YOU_TYPE_ORDER.indexOf(t);
  return i < 0 ? NEEDS_YOU_TYPE_ORDER.length : i;
}

function time(since: string | null): number {
  const t = since ? Date.parse(since) : Number.NaN;
  return Number.isNaN(t) ? Number.POSITIVE_INFINITY : t;
}

/** The items in the order of the page: campaigns first, then each type with
 *  its oldest item first. An item with no time ends its type. */
export function sortNeedsYou(items: readonly NeedsYouItem[]): NeedsYouItem[] {
  return items
    .map((item, i) => ({ item, i }))
    .sort((a, b) => rank(a.item.type) - rank(b.item.type) || time(a.item.since) - time(b.item.since) || a.i - b.i)
    .map((x) => x.item);
}

const unit = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;

/** How long an item waits, in words. Past 30 days it states the days with no
 *  decision, and `old` is true. Null for an item with no time. */
export function waitAge(since: string | null, now = Date.now()): { text: string; old: boolean } | null {
  const t = since ? Date.parse(since) : Number.NaN;
  if (Number.isNaN(t)) return null;
  const ms = Math.max(0, now - t);
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 1) return { text: 'Waits for less than a minute', old: false };
  if (minutes < 60) return { text: `Waits for ${unit(minutes, 'minute')}`, old: false };
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return { text: `Waits for ${unit(hours, 'hour')}`, old: false };
  const days = Math.floor(hours / 24);
  if (days > OLD_DAYS) return { text: `No decision for ${unit(days, 'day')}`, old: true };
  return { text: `Waits for ${unit(days, 'day')}`, old: false };
}
