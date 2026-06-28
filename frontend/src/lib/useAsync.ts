import { useEffect, useState } from 'react';

export interface AsyncState<T> {
  data: T | null;
  loading: boolean;
  error: Error | null;
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
 */
export function useAsync<T>(
  loader: () => Promise<T>,
  deps: unknown[] = [],
  options: UseAsyncOptions = {},
): AsyncState<T> {
  const { refetchInterval, pauseWhen } = options;
  const [state, setState] = useState<AsyncState<T>>({ data: null, loading: true, error: null });

  useEffect(() => {
    let alive = true;

    const run = (foreground: boolean) => {
      // Foreground (initial / dep change): show loading but keep prior data so
      // the screen doesn't flash. Background (poll): silent.
      if (foreground) setState((s) => ({ data: s.data, loading: true, error: null }));
      loader()
        .then((data) => {
          if (alive) setState({ data, loading: false, error: null });
        })
        .catch((error: unknown) => {
          if (!alive) return;
          if (!foreground) {
            // A background poll failed — keep the last good data, don't flap.
            setState((s) => ({ ...s, loading: false }));
            return;
          }
          setState({
            data: null,
            loading: false,
            error: error instanceof Error ? error : new Error(String(error)),
          });
        });
    };

    run(true);

    let timer: ReturnType<typeof setInterval> | undefined;
    if (refetchInterval && refetchInterval > 0) {
      timer = setInterval(() => {
        if (!alive) return;
        if (typeof document !== 'undefined' && document.hidden) return; // don't poll a backgrounded tab
        if (pauseWhen && pauseWhen()) return;
        run(false);
      }, refetchInterval);
    }

    return () => {
      alive = false;
      if (timer) clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return state;
}
