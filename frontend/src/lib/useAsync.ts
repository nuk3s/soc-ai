import { useCallback, useEffect, useState } from 'react';

export interface AsyncState<T> {
  data: T | null;
  loading: boolean;
  error: Error | null;
  /** Wall-clock ms of the last SUCCESSFUL load, or null if never. Powers "updated Xs ago". */
  lastUpdated: number | null;
  /**
   * Consecutive BACKGROUND-poll failures, reset to 0 on any success. A surface
   * is "stale" at >= 2 (show the last-good data with a degraded marker). A
   * FOREGROUND failure sets `error` instead — that's a hard load failure, not a
   * silently-stale poll.
   */
  failCount: number;
}

export interface UseAsyncResult<T> extends AsyncState<T> {
  /** Re-run the loader now (foreground semantics; keeps prior data on failure). */
  refetch: () => void;
}

export interface UseAsyncOptions {
  /** When > 0, re-run the loader on this interval (ms) to keep the screen live. */
  refetchInterval?: number;
  /** Skip a scheduled background refetch while this returns true (e.g. a drawer is open). */
  pauseWhen?: () => boolean;
}

/**
 * Minimal data-fetching hook over the api.ts boundary. Gives every screen a
 * real loading / error / empty lifecycle without a heavy state lib. `deps`
 * re-runs the loader (e.g. when a route param changes). Pass
 * `{ refetchInterval }` to make a screen poll itself live; background refetches
 * keep the last-good data on screen (no loading flash, no flap on a transient
 * grid blip) and pause while the tab is hidden.
 *
 * The result also carries `lastUpdated` (for an "updated Xs ago" marker),
 * `failCount` (consecutive background-poll failures; >= 2 means the surface is
 * showing stale data), and `refetch()` (a manual re-run — screens should use
 * this instead of a hand-rolled `reloadKey` counter, and pass it to
 * `<ErrorState onRetry>`).
 */
export function useAsync<T>(
  loader: () => Promise<T>,
  deps: unknown[] = [],
  options: UseAsyncOptions = {},
): UseAsyncResult<T> {
  const { refetchInterval, pauseWhen } = options;
  const [state, setState] = useState<AsyncState<T>>({
    data: null,
    loading: true,
    error: null,
    lastUpdated: null,
    failCount: 0,
  });
  // Bumping this re-runs the effect (foreground). Replaces the per-screen
  // hand-rolled reloadKey pattern; `refetch` is stable across renders.
  const [reloadTick, setReloadTick] = useState(0);
  const refetch = useCallback(() => setReloadTick((t) => t + 1), []);

  useEffect(() => {
    let alive = true;
    // Monotonic request id: a slow earlier response must not overwrite a newer
    // one, and no setState may fire after unmount / dep change. Every invocation
    // captures its id and bails unless it's still the latest (and still alive).
    let seq = 0;

    let inFlight = false;
    const run = (foreground: boolean) => {
      inFlight = true;
      const id = ++seq;
      const fresh = () => alive && id === seq;
      // Foreground (initial / dep change / refetch): show loading but keep prior
      // data so the screen doesn't flash. Background (poll): silent.
      if (foreground) setState((s) => ({ ...s, loading: true, error: null }));
      loader()
        .finally(() => {
          if (id === seq) inFlight = false;
        })
        .then((data) => {
          if (fresh())
            setState((s) => ({
              ...s,
              data,
              loading: false,
              error: null,
              lastUpdated: Date.now(),
              failCount: 0,
            }));
        })
        .catch((error: unknown) => {
          if (!fresh()) return;
          if (!foreground) {
            // A background poll failed — keep the last good data, don't flap,
            // and count toward staleness.
            setState((s) => ({ ...s, loading: false, failCount: s.failCount + 1 }));
            return;
          }
          // Foreground failure — surface the error. Keep prior data (null on the
          // first load, so the screen still blanks to the ErrorState there; a
          // populated screen keeps its data so a failed manual refresh doesn't
          // wipe it).
          setState((s) => ({
            ...s,
            loading: false,
            error: error instanceof Error ? error : new Error(String(error)),
          }));
        });
    };

    run(true);

    let timer: ReturnType<typeof setInterval> | undefined;
    if (refetchInterval && refetchInterval > 0) {
      timer = setInterval(() => {
        if (!alive) return;
        if (typeof document !== 'undefined' && document.hidden) return; // don't poll a backgrounded tab
        if (pauseWhen && pauseWhen()) return;
        // In-flight guard: when the API is slow/down, a bare interval stacks a
        // new request on top of the unresolved previous one — with several
        // pollers that exhausts the browser's per-origin connection pool and
        // freezes UNRELATED widgets (dogfood 2026-08-05). Skip the tick instead.
        if (inFlight) return;
        run(false);
      }, refetchInterval);
    }

    return () => {
      alive = false;
      if (timer) clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, reloadTick]);

  return { ...state, refetch };
}
