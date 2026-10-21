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
  | 'leads_needing_decision'
  | 'unread_shadow_hits'
  | 'untriaged_groups'
  | 'needs_more_info'
  | 'pending_actions';

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

/** Where each part of the count is read and decided. The tile lines and the
 *  sidebar badges link here, so the number on the link is the list it opens. */
export function needsYouLinks(data: NeedsYouCount | null) {
  const alertWindow = data?.alert_window ?? '7d';
  const verdictWindow = data?.verdict_window ?? '30d';
  return {
    leads: '/hunts?leads=needs_decision#leads',
    shadowHits: '/hunts?hits=unread#analytic-hits',
    untriaged: `/alerts?range=${alertWindow}&verdict=untriaged`,
    needsMoreInfo: `/investigations?range=${verdictWindow}&verdict=needs_more_info`,
    // The runs with a pending action, by the rule of the count. The line
    // opened every true positive, and the list did not match the number.
    pendingActions: `/investigations?range=${verdictWindow}&actions=pending`,
  };
}

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
  /** The list that holds the part. */
  to: string;
}

/** A range word ("7d") as a scope: "last 7 days". */
export function scopeOfWindow(range: string): string {
  const m = range.match(/^(\d+)([mhd])$/);
  if (!m) return `last ${range}`;
  const n = Number(m[1]);
  const unit = m[2] === 'm' ? 'minute' : m[2] === 'h' ? 'hour' : 'day';
  return `last ${n} ${unit}${n === 1 ? '' : 's'}`;
}

const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

/**
 * Every part of the needs-you count that is not zero, with its scope in words.
 *
 * The bell badge states the total, and the bell panel listed 12 shadow hits
 * under a badge of 309 (production 2026-10-14). These lines add up to the
 * total, so the panel accounts for every unit of the badge. A part the server
 * could not read keeps its line with `count` null, as the badge's "+" does.
 * The backlog parts keep their whole scope, and the scope is said: the leads
 * and the hits have no window, the other three have the window the count uses.
 */
export function needsYouLines(data: NeedsYouCount | null): NeedsYouLine[] {
  if (!data) return [];
  const links = needsYouLinks(data);
  // The defaults of needsYouLinks: an older server sends no window.
  const alerts = scopeOfWindow(data.alert_window ?? '7d');
  const verdicts = scopeOfWindow(data.verdict_window ?? '30d');
  const lines: NeedsYouLine[] = [
    {
      key: 'leads_needing_decision',
      count: data.leads_needing_decision,
      text: '',
      scope: 'all open',
      unknown: 'Could not count the leads.',
      to: links.leads,
    },
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
    {
      key: 'needs_more_info',
      count: data.needs_more_info,
      text: '',
      scope: verdicts,
      unknown: 'Could not count the verdicts that need more info.',
      to: links.needsMoreInfo,
    },
    {
      key: 'pending_actions',
      count: data.pending_actions,
      text: '',
      scope: verdicts,
      unknown: 'Could not count the recommended actions.',
      to: links.pendingActions,
    },
  ];
  return lines
    .filter((line) => line.count === null || line.count > 0)
    .map((line) => ({ ...line, text: line.count === null ? '' : lineText(line.key, line.count, data.alert_floor) }));
}

function lineText(key: PartKey, n: number, alertFloor: boolean): string {
  switch (key) {
    case 'leads_needing_decision':
      return `${n} ${plural(n, 'lead waits', 'leads wait')} on a decision`;
    case 'unread_shadow_hits':
      return `${n} ${plural(n, 'shadow hit is', 'shadow hits are')} unread`;
    case 'untriaged_groups':
      return `${n}${alertFloor ? '+' : ''} ${plural(n, 'alert group has', 'alert groups have')} no verdict`;
    case 'needs_more_info':
      return `${n} ${plural(n, 'verdict needs', 'verdicts need')} more info`;
    case 'pending_actions':
      return `${n} recommended ${plural(n, 'action waits', 'actions wait')} for you`;
  }
}
