import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';

import { getNeedsYouCount, onNeedsYouChanged, type NeedsYouCount } from './api';

// ---------------------------------------------------------------------------
// The needs-you count, read once for the whole shell.
//
// The Dashboard tile, the sidebar badges and the bell state one number. Each
// surface used to count its own part: the Dashboard said "queue clear" while
// 11 leads waited, and the bell said "None need attention". One provider reads
// GET /needs-you and every surface reads the provider, so the three cannot
// state different numbers.
// ---------------------------------------------------------------------------

/** How often the count is read again. A write in the console reads it at once
 *  through onNeedsYouChanged. */
export const NEEDS_YOU_POLL_MS = 60_000;

export interface NeedsYouState {
  /** The last good answer. Null until the first read lands. */
  data: NeedsYouCount | null;
  /** True after a read failed, until the next read lands. */
  failed: boolean;
  /** Read the count again now. */
  refetch: () => void;
  /** When the last good answer landed, in epoch ms. Dismiss all marks the
   *  shadow hits read up to the moment the count it shows was read. */
  loadedAt?: number | null;
}

const Ctx = createContext<NeedsYouState | null>(null);

function useNeedsYouPoll(enabled: boolean): NeedsYouState {
  const [data, setData] = useState<NeedsYouCount | null>(null);
  const [loadedAt, setLoadedAt] = useState<number | null>(null);
  const [failed, setFailed] = useState(false);
  const [nonce, setNonce] = useState(0);
  const refetch = useCallback(() => setNonce((n) => n + 1), []);

  useEffect(() => {
    if (!enabled) return;
    let alive = true;
    const read = () =>
      getNeedsYouCount()
        .then((answer) => {
          if (!alive) return;
          setData(answer);
          setLoadedAt(Date.now());
          setFailed(false);
        })
        .catch(() => {
          if (alive) setFailed(true);
        });
    void read();
    // A parked tab does not poll. It reads once when it is visible again.
    const timer = window.setInterval(() => {
      if (!document.hidden) void read();
    }, NEEDS_YOU_POLL_MS);
    const onVisible = () => {
      if (!document.hidden) void read();
    };
    document.addEventListener('visibilitychange', onVisible);
    const stop = onNeedsYouChanged(() => void read());
    return () => {
      alive = false;
      window.clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisible);
      stop();
    };
  }, [enabled, nonce]);

  return { data, failed, refetch, loadedAt };
}

/** One read of the count for every surface below it. `enabled` holds the read
 *  until the session is known, so a signed-out visit sends no request. */
export function NeedsYouProvider({ enabled, children }: { enabled: boolean; children: ReactNode }) {
  const state = useNeedsYouPoll(enabled);
  return <Ctx.Provider value={state}>{children}</Ctx.Provider>;
}

/** The shared count. A surface mounted outside the provider reads its own. */
export function useNeedsYouCount(): NeedsYouState {
  const shared = useContext(Ctx);
  const own = useNeedsYouPoll(shared === null);
  return shared ?? own;
}

export type PartKey =
  | 'campaigns'
  | 'investigations_waiting'
  | 'leads_needing_decision'
  | 'unread_shadow_hits'
  | 'untriaged_groups'
  | 'needs_more_info'
  | 'pending_actions'
  | 'rules_waiting';

/** The parts of the count that wait on a decision, each decision once, in the
 *  order of the lines. An unread shadow hit is review work: one press of
 *  Dismiss all reads every hit. "Needs you 280" held 233 hits in red
 *  (production review 2026-11-12, ui-core 4). `needs_more_info` and
 *  `pending_actions` are the detail of `investigations_waiting` and no part:
 *  the actions part counted each action, so one investigation with two
 *  actions counted twice, and the number did not match the Needs you page. */
export const DECISION_PART_KEYS: ReadonlyArray<PartKey> = [
  'campaigns',
  'investigations_waiting',
  'leads_needing_decision',
  'untriaged_groups',
  'rules_waiting',
];

/** The parts an older server summed. It sends no `investigations_waiting`. */
const OLDER_DECISION_PART_KEYS: ReadonlyArray<PartKey> = [
  'campaigns',
  'leads_needing_decision',
  'untriaged_groups',
  'needs_more_info',
  'pending_actions',
];

function decisionKeys(data: NeedsYouCount): ReadonlyArray<PartKey> {
  return data.investigations_waiting === undefined ? OLDER_DECISION_PART_KEYS : DECISION_PART_KEYS;
}

/** The decision count: the number every surface states. The server sums it
 *  (`decisions`). An older server sends no such field, and the console sums
 *  the parts of that server. */
export function decisionCount(data: NeedsYouCount): number {
  if (typeof data.decisions === 'number') return data.decisions;
  return decisionKeys(data).reduce((sum, key) => sum + (data[key] ?? 0), 0);
}

/** True when a part of the number could not be read: the count is then a
 *  floor. A failed read of a detail of the number is no floor. */
export function decisionFloor(data: NeedsYouCount): boolean {
  const keys = decisionKeys(data) as ReadonlyArray<string>;
  return data.unknown.some((key) => keys.includes(key));
}

/** The Campaigns badge: the active campaigns with no decision. Null when the
 *  server could not read them. An older server sends no part, and the badge
 *  then shows nothing, never an unknown mark. */
export function campaignsWaiting(data: NeedsYouCount | null): number | null {
  if (!data) return null;
  return data.campaigns === undefined ? 0 : data.campaigns;
}

/** The review count: the unread shadow hits, or null when they were not read. */
export function reviewCount(data: NeedsYouCount): number | null {
  const value = data.review !== undefined ? data.review : data.unread_shadow_hits;
  return value === undefined ? 0 : value;
}

/** The investigations that wait: the Investigations badge and the line of the
 *  tile and the bell. An older server sends no such count, and the console
 *  then sums the two parts that server counted. */
export function investigationsWaiting(data: NeedsYouCount | null): number | null {
  if (!data) return null;
  if (data.investigations_waiting !== undefined) return data.investigations_waiting;
  return needsYouPart(data, 'needs_more_info', 'pending_actions');
}

/** "236 shadow hits to review": the words of the review count. */
export function reviewText(n: number): string {
  return `${n.toLocaleString()} shadow ${n === 1 ? 'hit' : 'hits'} to review`;
}

/** The sum of some parts of the count, or null when one of them is unknown. */
export function needsYouPart(data: NeedsYouCount | null, ...keys: PartKey[]): number | null {
  if (!data) return null;
  let sum = 0;
  for (const key of keys) {
    const value = data[key];
    if (typeof value !== 'number') return null;
    sum += value;
  }
  return sum;
}

/** The page that lists every decision that waits, one item each. */
export const NEEDS_YOU_PAGE = '/needs-you';

/** The types of the Needs you list that a link can filter on. */
export type NeedsYouFilter = 'campaign' | 'investigation' | 'lead' | 'alerts' | 'rule';

/** The Needs you page with a type filter. Each line of the Dashboard tile and
 *  of the bell opens it, so a line opens the one list and no other
 *  (dogfood 2026-11-17, NY4). */
export function needsYouTypeLink(type: NeedsYouFilter): string {
  return `${NEEDS_YOU_PAGE}?type=${type}`;
}

/** Where each part of the count is read and decided. The sidebar badges link
 *  here, so the number on a badge is the list it opens. The lines of the tile
 *  and of the bell open the Needs you page (needsYouTypeLink). */
export function needsYouLinks(data: NeedsYouCount | null) {
  const alertWindow = data?.alert_window ?? '7d';
  const verdictWindow = data?.verdict_window ?? '30d';
  return {
    // The campaigns list with the filter "Waits on you": the campaigns the
    // part counts.
    campaigns: '/campaigns?decision=waits',
    leads: '/hunts?leads=needs_decision#leads',
    shadowHits: '/hunts?hits=unread#analytic-hits',
    untriaged: `/alerts?range=${alertWindow}&verdict=untriaged`,
    needsMoreInfo: `/investigations?range=${verdictWindow}&verdict=needs_more_info`,
    // The runs with a pending action, by the rule of the count. The line
    // opened every true positive, and the list did not match the number.
    pendingActions: `/investigations?range=${verdictWindow}&actions=pending`,
    // The Needs you view of the list: the runs the Investigations badge
    // counts, over the same window.
    investigations: `/investigations?view=needs_you&range=${verdictWindow}`,
  };
}

/** The filter of the Needs you page that holds each decision part. */
const PART_FILTER: Partial<Record<PartKey, NeedsYouFilter>> = {
  campaigns: 'campaign',
  investigations_waiting: 'investigation',
  leads_needing_decision: 'lead',
  untriaged_groups: 'alerts',
  rules_waiting: 'rule',
};

/** One part of the count as the bell panel and the Notifications screen say it. */
export interface NeedsYouLine {
  key: PartKey;
  /** The part, or null when the server could not read it. */
  count: number | null;
  /** The count and its noun: "300 shadow hits". */
  text: string;
  /** What the count covers, in words: "all unread", "last 7 days". */
  scope: string;
  /** What to say when the server could not read the part. */
  unknown: string;
  /** The list that holds the part: the Needs you page with the type filter
   *  of the part. The review line opens the shadow hits. */
  to: string;
}

/** The scope words of a part with no window. */
export const ANY_AGE = 'at any age';

/** A range word ("7d") as a scope: "last 7 days". The window "all" has no
 *  limit: an item stays until a person decides it, so it reads "at any age". */
export function scopeOfWindow(range: string): string {
  if (range === 'all') return ANY_AGE;
  const m = range.match(/^(\d+)([mhd])$/);
  if (!m) return `last ${range}`;
  const n = Number(m[1]);
  const unit = m[2] === 'm' ? 'minute' : m[2] === 'h' ? 'hour' : 'day';
  return `last ${n} ${unit}${n === 1 ? '' : 's'}`;
}

const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

/**
 * Every decision part of the needs-you count that is not zero, with its scope
 * in words: the campaigns, the investigations, the leads and the alert groups.
 *
 * The bell badge states the decision count, and the bell panel listed 12
 * shadow hits under a badge of 309 (production 2026-10-14). These lines add up
 * to the badge, so the panel accounts for every unit of it. A part the server
 * could not read keeps its line with `count` null, as the badge's "+" does.
 * The backlog parts keep their whole scope, and the scope is said: the leads
 * have no window, the other parts have the window the count uses. The unread
 * shadow hits are not a decision. needsYouReviewLine states them apart.
 *
 * One line states the investigations that wait, each investigation once. Two
 * lines said "verdicts need more info" and "recommended actions wait", and
 * the second counted actions: an investigation with two actions counted
 * twice, and the lines did not add up to the Needs you page.
 *
 * The Dashboard tile and the bell both read these lines.
 */
export function needsYouLines(data: NeedsYouCount | null): NeedsYouLine[] {
  return allNeedsYouLines(data).filter((line) => line.key !== 'unread_shadow_hits');
}

/** The review line: the unread shadow hits, or null when none is unread. A
 *  failed read keeps the line with `count` null. */
export function needsYouReviewLine(data: NeedsYouCount | null): NeedsYouLine | null {
  if (!data) return null;
  const count = reviewCount(data);
  if (count === 0) return null;
  return {
    key: 'unread_shadow_hits',
    count,
    text: count === null ? '' : reviewText(count),
    scope: 'all unread',
    unknown: 'Could not count the shadow hits.',
    to: needsYouLinks(data).shadowHits,
  };
}

function allNeedsYouLines(data: NeedsYouCount | null): NeedsYouLine[] {
  if (!data) return [];
  const links = needsYouLinks(data);
  // The defaults of needsYouLinks: an older server sends no window.
  const alerts = scopeOfWindow(data.alert_window ?? '7d');
  const verdicts = scopeOfWindow(data.verdict_window ?? '30d');
  const lines: NeedsYouLine[] = [
    // The campaign is the unit of work, so its line comes first. An older
    // server sends no part, and the line then does not show.
    ...(data.campaigns === undefined
      ? []
      : [
          {
            key: 'campaigns' as const,
            count: data.campaigns,
            text: '',
            scope: ANY_AGE,
            unknown: 'Could not count the campaigns.',
            to: links.campaigns,
          },
        ]),
    {
      key: 'investigations_waiting',
      count: investigationsWaiting(data),
      text: '',
      scope: verdicts,
      unknown: 'Could not count the investigations that wait.',
      to: links.investigations,
    },
    {
      key: 'leads_needing_decision',
      count: data.leads_needing_decision,
      text: '',
      scope: 'all open',
      unknown: 'Could not count the leads.',
      to: links.leads,
    },
    // The rules with open false positives, after the leads and before the
    // alert groups: the order of the list. An older server sends no part,
    // and the line then does not show.
    ...(data.rules_waiting === undefined
      ? []
      : [
          {
            key: 'rules_waiting' as const,
            count: data.rules_waiting,
            text: '',
            scope: ANY_AGE,
            unknown: 'Could not count the rules with open false positives.',
            to: needsYouTypeLink('rule'),
          },
        ]),
    {
      key: 'unread_shadow_hits',
      count: data.unread_shadow_hits,
      text: '',
      scope: 'all unread',
      unknown: 'Could not count the shadow hits.',
      to: links.shadowHits,
    },
    {
      key: 'untriaged_groups',
      count: data.untriaged_groups,
      text: '',
      scope: alerts,
      unknown: 'Could not count the alert groups. The grid did not answer.',
      to: links.untriaged,
    },
  ];
  return lines
    .filter((line) => line.count === null || line.count > 0)
    .map((line) => {
      // A decision part opens the one list. The shadow hits are review work
      // and no item of it: their line keeps the Hunts page.
      const filter = PART_FILTER[line.key];
      return {
        ...line,
        to: filter ? needsYouTypeLink(filter) : line.to,
        text: line.count === null ? '' : lineText(line.key, line.count, data.alert_floor),
      };
    });
}

function lineText(key: PartKey, n: number, alertFloor: boolean): string {
  switch (key) {
    case 'campaigns':
      return `${n} ${plural(n, 'campaign waits', 'campaigns wait')} on your decision`;
    case 'investigations_waiting':
      return `${n} ${plural(n, 'investigation waits', 'investigations wait')} on your decision`;
    case 'leads_needing_decision':
      return `${n} ${plural(n, 'lead waits', 'leads wait')} on a decision`;
    case 'unread_shadow_hits':
      return reviewText(n);
    case 'untriaged_groups':
      return `${n}${alertFloor ? '+' : ''} ${plural(n, 'alert group has', 'alert groups have')} no verdict`;
    case 'needs_more_info':
      return `${n} ${plural(n, 'verdict needs', 'verdicts need')} more info`;
    case 'pending_actions':
      return `${n} recommended ${plural(n, 'action waits', 'actions wait')} for you`;
    case 'rules_waiting':
      return `${n} ${plural(n, 'rule waits', 'rules wait')} on your decision`;
  }
}

/** The rules with open false positives: the chip of the Needs you page. An
 *  older server sends no part, and the chip then shows no count. */
export function rulesWaiting(data: NeedsYouCount | null): number | null {
  if (!data || data.rules_waiting === undefined) return null;
  return data.rules_waiting;
}
