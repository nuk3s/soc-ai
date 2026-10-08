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
}

const Ctx = createContext<NeedsYouState | null>(null);

function useNeedsYouPoll(enabled: boolean): NeedsYouState {
  const [data, setData] = useState<NeedsYouCount | null>(null);
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

  return { data, failed, refetch };
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

type PartKey =
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
    pendingActions: `/investigations?range=${verdictWindow}&verdict=true_positive`,
  };
}
