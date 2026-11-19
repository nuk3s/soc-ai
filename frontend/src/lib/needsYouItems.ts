// ---------------------------------------------------------------------------
// The Needs you list: one list the analyst works from top to bottom.
//
// The server sends the items in the order of the page, the most important
// first (soc_ai/api/webui/needs_you_facts.py, order_key): campaigns, true
// positive investigations, leads, other investigations, then the alert
// groups. Inside each group the impact, the severity and the newest event
// decide. Inside the group of the rules the count with checked evidence
// decides, then the newest event: a rule states no impact (D11). The page
// keeps that order: one rule for the order, on the server.
// The list was the oldest first, and the live lead was row 31 of 31 under
// 30 investigations of 134 days (dogfood 2026-11-17, a09).
// ---------------------------------------------------------------------------

import type { NeedsYouItem, NeedsYouItemType } from './api';
import { utcStamp } from './timeRange';

/** The most items the server sends. */
export const NEEDS_YOU_LIMIT = 200;

/** Past this many days the age of an item takes the warning color. */
export const OLD_DAYS = 30;

export const NEEDS_YOU_TYPE_LABEL: Record<NeedsYouItemType, string> = {
  campaign: 'Campaign',
  investigation: 'Investigation',
  lead: 'Lead',
  alerts: 'Alerts',
  rule: 'Rule',
};

/** The words of the one link of a row. */
export const NEEDS_YOU_OPEN: Record<NeedsYouItemType, string> = {
  campaign: 'Open the campaign',
  investigation: 'Open the investigation',
  lead: 'Open the lead',
  alerts: 'Open the alerts',
  rule: 'Open the rule',
};

export const NEEDS_YOU_EMPTY = 'Nothing needs you.';

/** The type filters of the page, in the order of the list. A line of the
 *  Dashboard tile or of the bell opens the page with one of them. */
export const NEEDS_YOU_FILTERS: ReadonlyArray<{ type: NeedsYouItemType; label: string }> = [
  { type: 'campaign', label: 'Campaigns' },
  { type: 'investigation', label: 'Investigations' },
  { type: 'lead', label: 'Leads' },
  { type: 'rule', label: 'Rules' },
  { type: 'alerts', label: 'Alert groups' },
];

/** The type filter of a `?type=` value, or null for every type. */
export function needsYouFilterOf(value: string | null): NeedsYouItemType | null {
  return NEEDS_YOU_FILTERS.find((f) => f.type === value)?.type ?? null;
}

const FILTER_EMPTY: Record<NeedsYouItemType, string> = {
  campaign: 'No campaign waits on you.',
  investigation: 'No investigation waits on you.',
  lead: 'No lead waits on you.',
  alerts: 'No alert group waits for a verdict.',
  rule: 'No rule with open false positives waits on you.',
};

/** The empty list under a type filter. */
export function needsYouFilterEmpty(t: NeedsYouItemType): string {
  return FILTER_EMPTY[t] ?? NEEDS_YOU_EMPTY;
}
/** An item with no machine that soc-ai holds. */
export const NO_MACHINE = 'No machine is on record.';
/** The empty list when a type could not be read: a floor is no "nothing". */
export const NEEDS_YOU_EMPTY_FLOOR = 'The list holds no item that soc-ai could read.';
/** The order of the list, in one line on the page. */
export const NEEDS_YOU_SCOPE =
  'The list holds each decision at any age, the most important first: campaigns, true positives, ' +
  'leads, other investigations, rules with open false positives, then alert groups. ' +
  'Each group sorts by impact, severity and newest event. The rules sort by the count with checked ' +
  'evidence, the largest first, and then by newest event.';

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
  rule: 'the rules',
};

/** "soc-ai could not read the campaigns and the alert groups.", or null
 *  when every type was read. */
export function needsYouUnreadWords(unknown: readonly NeedsYouItemType[] | undefined): string | null {
  const words = (unknown ?? []).map((t) => UNREAD_WORDS[t] ?? String(t));
  if (words.length === 0) return null;
  const list = words.length === 1 ? words[0] : `${words.slice(0, -1).join(', ')} and ${words[words.length - 1]}`;
  return `soc-ai could not read ${list}.`;
}

const unit = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;

/** How long an item waits, in words: "Waits for {duration}", the one phrase
 *  of the page. Past 30 days `old` is true, and the page shows the age in the
 *  warning color. The page said "No decision for 134 days" beside "Waits for
 *  3 days" for one state (dogfood 2026-11-17, a09). Null for an item with no
 *  time. */
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
  return { text: `Waits for ${unit(days, 'day')}`, old: days > OLD_DAYS };
}

/** The hover text of a machine chip: the name and the address, or what soc-ai
 *  does not hold of them. */
export function machineTitle(m: { name: string | null; address: string | null }): string {
  const name = m.name ? `Name: ${m.name}.` : 'soc-ai holds no name for this machine.';
  const address = m.address ? `Address: ${m.address}.` : 'soc-ai holds no address for this machine.';
  return `${name} ${address}`;
}

// ── The groups of the list (OW5) ────────────────────────────────────────────

/** The groups of the list, in the order of the server (needs_you_facts.group_of). */
export type NeedsYouGroup = 'campaign' | 'true_positive' | 'lead' | 'other' | 'alerts' | 'rule';

export const NEEDS_YOU_GROUP_LABEL: Record<NeedsYouGroup, string> = {
  campaign: 'Campaigns',
  true_positive: 'True positive investigations',
  lead: 'Leads',
  other: 'Other investigations',
  alerts: 'Alert groups with no verdict',
  rule: 'Rules with open false positives',
};

/** The group of an item: a true positive investigation is a group of its own. */
export function needsYouGroupOf(item: Pick<NeedsYouItem, 'type' | 'verdict'>): NeedsYouGroup {
  if (item.type === 'investigation') return item.verdict === 'true_positive' ? 'true_positive' : 'other';
  return item.type;
}

/** "True positive investigations · 13". No count when it is not known. */
export function needsYouGroupHeading(group: NeedsYouGroup, n: number | null): string {
  const label = NEEDS_YOU_GROUP_LABEL[group];
  return n === null ? label : `${label} · ${n.toLocaleString()}`;
}

/** The items in their groups, the order of the server kept. */
export function needsYouGroups<T extends Pick<NeedsYouItem, 'type' | 'verdict'>>(
  items: readonly T[],
): { group: NeedsYouGroup; items: T[] }[] {
  const out: { group: NeedsYouGroup; items: T[] }[] = [];
  for (const item of items) {
    const group = needsYouGroupOf(item);
    const last = out[out.length - 1];
    if (last && last.group === group) last.items.push(item);
    else out.push({ group, items: [item] });
  }
  return out;
}

/** The time of the event that the order reads: "Event 2026-11-14 09:00 UTC".
 *  An item with no event time says so. */
export function needsYouEventWords(eventAt: string | null | undefined): string {
  return eventAt ? `Event ${utcStamp(eventAt)}` : 'Event time unknown';
}

/** The impact mark applies to a true positive: one chip, "Impact unknown"
 *  when it states none. Another verdict, a verdict that needs more info
 *  included, reads no impact chip. */
export function needsYouShowsImpact(item: Pick<NeedsYouItem, 'verdict'>): boolean {
  return item.verdict === 'true_positive';
}

// ── The rule items (rule decisions) ─────────────────────────────────────────

/** "471 investigations: 470 with checked evidence, 1 with weak evidence". The first
 *  number is `count` of the server. A group with none is not named. */
export function ruleCountWords(item: Pick<NeedsYouItem, 'count' | 'confident' | 'weak'>): string {
  const count = item.count ?? 0;
  const head = count === 1 ? '1 investigation' : `${count.toLocaleString()} investigations`;
  const parts: string[] = [];
  if ((item.confident ?? 0) > 0) parts.push(`${(item.confident ?? 0).toLocaleString()} with checked evidence`);
  if ((item.weak ?? 0) > 0) parts.push(`${(item.weak ?? 0).toLocaleString()} with weak evidence`);
  return parts.length > 0 ? `${head}: ${parts.join(', ')}` : head;
}

/** The span of the open events of a rule: "Events from {oldest} to
 *  {newest}". One time when both are the same. Null with no time. */
export function ruleSpanWords(since: string | null, eventAt: string | null | undefined): string | null {
  if (!since && !eventAt) return null;
  if (!since || !eventAt || since === eventAt) return `Event ${utcStamp(eventAt ?? since)}`;
  return `Events from ${utcStamp(since)} to ${utcStamp(eventAt)}`;
}
