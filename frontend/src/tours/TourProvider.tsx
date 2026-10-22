import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { useLocation } from 'react-router-dom';
import { ApiError, getMyTours, putMyTours } from '../lib/api';
import { useDemo } from '../lib/demo';
import { useToast } from '../lib/toast';
import { useSession } from '../shell/Session';
import { useOptionalShell } from '../shell/ShellContext';
import { type WaitOptions, waitForAnchors } from './anchors';
import { autoStartBlock } from './autoStart';
import { WELCOME_TOUR, pageTourFor } from './content';
import { defaultState, isPending, markSeen, readBrowserState, sanitizeState, writeBrowserState } from './state';
import { type TourEnd, TourOverlay } from './TourOverlay';
import type { Tour, ToursState, TourStep } from './types';

// ---------------------------------------------------------------------------
// The tours of the console: when one starts, where the state lives, and the
// one overlay on screen.
//
// Triggers
// - The welcome tour starts on the first in-shell page after the first
//   sign-in, or on the first visit with authentication off.
// - A page tour starts on the first visit to its page, after the welcome tour
//   when both apply. Never two tours at once.
// - A tour the operator closed or skipped holds the next tour until the route
//   changes. Done on the welcome tour leads into the tour of the page.
// - A route change ends a page tour and marks nothing. The welcome tour keeps
//   running while its step is in the shell.
// - autoStartBlock() (autoStart.ts) keeps automated browsers free of tours.
//   The "?" menu still opens a tour on purpose.
//
// The state
// - A signed-in user: GET/PUT /api/v1/me/tours, read on first need. An
//   automated browser that never opens the menu sends no request.
// - Authentication off, the demo, or a 401 from the route: localStorage.
// - A read that fails for another reason: the state is unknown for this
//   visit, so nothing starts by itself and nothing is written.
// ---------------------------------------------------------------------------

export type TourStore = 'server' | 'browser' | 'memory';

interface Running {
  tour: Tour;
  /** The path the tour started on. */
  path: string;
  /** Where the focus goes on close. */
  returnFocus: HTMLElement | null;
}

export interface ToursApi {
  /** Null until the state is read. */
  state: ToursState | null;
  store: TourStore | null;
  /** The tour on screen, or null. */
  running: Tour | null;
  /** The tour of the current page, or undefined. */
  pageTour: Tour | undefined;
  /** Read the state now, when it is not read yet. */
  ensureLoaded: () => void;
  /** Open the tour of the current page. */
  startPageTour: (returnFocus?: HTMLElement | null) => void;
  /** Reset every tour to unseen and open the welcome tour. */
  startFromBeginning: (returnFocus?: HTMLElement | null) => void;
  /** Turn the tours on or off. */
  setOff: (off: boolean) => void;
}

const Ctx = createContext<ToursApi | null>(null);

/** The tours, or null outside a TourProvider. */
export function useTours(): ToursApi | null {
  return useContext(Ctx);
}

/** How long a tour waits for its anchors. */
export interface TourTimings {
  auto: WaitOptions;
  manual: WaitOptions;
}

export const DEFAULT_TIMINGS: TourTimings = {
  // A page that just mounted still loads its data. The tour waits for the set
  // of anchors to hold for 800 ms, up to 5 s.
  auto: { pollMs: 200, settleMs: 800, maxMs: 5000 },
  // From the menu the page is already on screen.
  manual: { pollMs: 100, settleMs: 0, maxMs: 1500 },
};

function isAuthFailure(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 401 || err.status === 403);
}

const DISMISSED: ReadonlySet<TourEnd> = new Set(['skipped', 'closed']);
const MARKS_SEEN: ReadonlySet<TourEnd> = new Set(['done', 'skipped', 'closed', 'off']);

export function TourProvider({
  children,
  timings = DEFAULT_TIMINGS,
}: {
  children: ReactNode;
  timings?: TourTimings;
}) {
  const { pathname } = useLocation();
  const session = useSession();
  const demo = useDemo();
  const shell = useOptionalShell();
  const { toast } = useToast();

  const [state, setState] = useState<ToursState | null>(null);
  const [store, setStore] = useState<TourStore | null>(null);
  const [running, setRunning] = useState<Running | null>(null);
  // The path where the operator closed or skipped a tour. Nothing starts by
  // itself there until the route changes.
  const [holdPath, setHoldPath] = useState<string | null>(null);

  const stateRef = useRef(state);
  stateRef.current = state;
  const storeRef = useRef(store);
  storeRef.current = store;
  const runningRef = useRef(running);
  runningRef.current = running;
  const pathRef = useRef(pathname);
  pathRef.current = pathname;
  const stepRef = useRef<TourStep | null>(null);
  const loading = useRef<Promise<void> | null>(null);
  const writes = useRef<Promise<unknown>>(Promise.resolve());
  const pending = useRef<{ key: string; cancel: () => void } | null>(null);
  // Auto-starts that found no anchor, per path visit. They do not retry
  // until the route changes.
  const exhausted = useRef(new Set<string>());

  const pageTour = pageTourFor(pathname);

  // The state is read on first need: the auto-start, the menu, or the end of
  // a tour. A need before /me answers waits for it.
  const [wanted, setWanted] = useState(false);
  const ensureLoaded = useCallback(() => setWanted(true), []);
  const loaded = useRef<{ promise: Promise<void>; resolve: () => void } | null>(null);
  if (!loaded.current) {
    let resolve: () => void = () => {};
    const promise = new Promise<void>((r) => {
      resolve = r;
    });
    loaded.current = { promise, resolve };
  }

  useEffect(() => {
    if (!wanted || loading.current || session.status !== 'ready') return;
    const done = (where: TourStore, value: ToursState) => {
      storeRef.current = where;
      stateRef.current = value;
      setStore(where);
      setState(value);
      loaded.current?.resolve();
    };
    loading.current = (async () => {
      if (demo || session.me?.signed_in === false) {
        done('browser', readBrowserState());
        return;
      }
      try {
        done('server', sanitizeState(await getMyTours()));
      } catch (err) {
        if (isAuthFailure(err)) {
          done('browser', readBrowserState());
          return;
        }
        // Unknown for this visit. Tours open from the menu, and nothing is
        // written over a state the read could not fetch.
        done('memory', defaultState());
      }
    })();
  }, [wanted, session.status, session.me, demo]);

  /** Run once the state is read. */
  const afterLoad = useCallback(
    (fn: () => void) => {
      ensureLoaded();
      void loaded.current?.promise.then(fn);
    },
    [ensureLoaded],
  );

  const commit = useCallback((next: ToursState) => {
    setState(next);
    stateRef.current = next;
    if (storeRef.current === 'browser') {
      writeBrowserState(next);
    } else if (storeRef.current === 'server') {
      const op = () => putMyTours(next);
      const run = writes.current.then(op, op);
      writes.current = run.catch(() => undefined);
    }
  }, []);

  const start = useCallback(
    (tour: Tour, returnFocus: HTMLElement | null) => {
      pending.current?.cancel();
      pending.current = null;
      setRunning({ tour, path: pathRef.current, returnFocus });
    },
    [],
  );

  /** Open a tour on purpose. A tour with no anchor on the page says so. */
  const openNow = useCallback(
    (tour: Tour, returnFocus: HTMLElement | null) => {
      const path = pathRef.current;
      setRunning(null);
      const w = waitForAnchors(tour, timings.manual);
      pending.current?.cancel();
      pending.current = { key: `manual:${tour.id}`, cancel: w.cancel };
      void w.done.then((ok) => {
        pending.current = null;
        if (pathRef.current !== path) return;
        if (ok) start(tour, returnFocus);
        else
          toast({
            message: 'The tour found nothing to show on this page. Try again when the page has loaded.',
            tone: 'info',
          });
      });
    },
    [timings.manual, start, toast],
  );

  const startPageTour = useCallback(
    (returnFocus: HTMLElement | null = null) => {
      ensureLoaded();
      const tour = pageTourFor(pathRef.current);
      if (tour) openNow(tour, returnFocus);
    },
    [ensureLoaded, openNow],
  );

  // "Tour soc-ai from the start" replays the welcome tour only. The page tours
  // keep their seen state, and the tours stay off when the operator turned
  // them off (owner decision 2026-10-22).
  const startFromBeginning = useCallback(
    (returnFocus: HTMLElement | null = null) => {
      afterLoad(() => {
        openNow(WELCOME_TOUR, returnFocus);
      });
    },
    [afterLoad, openNow],
  );

  const setOff = useCallback(
    (off: boolean) => {
      afterLoad(() => {
        const cur = stateRef.current ?? defaultState();
        commit({ ...cur, off });
        if (!off) setHoldPath(pathRef.current);
      });
    },
    [afterLoad, commit],
  );

  const onEnd = useCallback(
    (how: TourEnd) => {
      const cur = runningRef.current;
      setRunning(null);
      runningRef.current = null;
      stepRef.current = null;
      if (!cur) return;
      if (DISMISSED.has(how)) setHoldPath(pathRef.current);
      if (!MARKS_SEEN.has(how)) return;
      // A tour opened from the menu can end before the first read lands.
      afterLoad(() => {
        const base = stateRef.current ?? defaultState();
        let next = markSeen(base, cur.tour);
        if (how === 'off') next = { ...next, off: true };
        if (next !== base) commit(next);
      });
    },
    [afterLoad, commit],
  );

  const onStep = useCallback((step: TourStep) => {
    stepRef.current = step;
  }, []);

  // Route changes: a page tour ends and marks nothing. The welcome tour keeps
  // running while its step is in the shell. A hold lasts until the route
  // changes; a wait for anchors belongs to its path.
  useEffect(() => {
    exhausted.current.clear();
    setHoldPath((h) => (h === pathname ? h : null));
    const cur = runningRef.current;
    if (cur && cur.path !== pathname) {
      const isWelcome = cur.tour.id === WELCOME_TOUR.id;
      const scope = stepRef.current?.scope ?? (isWelcome ? 'shell' : 'page');
      if (!isWelcome || scope === 'page') onEnd('interrupted');
      else setRunning({ ...cur, path: pathname });
    }
    if (pending.current && !pending.current.key.endsWith(`@${pathname}`) && !pending.current.key.startsWith('manual:')) {
      pending.current.cancel();
      pending.current = null;
    }
  }, [pathname, onEnd]);

  // Count a running tour into the shell's modal stack, so page key layers
  // disarm, and nothing else starts by itself over it.
  const pushModal = shell?.pushModal;
  const popModal = shell?.popModal;
  const isRunning = running !== null;
  useEffect(() => {
    if (!isRunning || !pushModal || !popModal) return;
    pushModal();
    return () => popModal();
  }, [isRunning, pushModal, popModal]);

  // The auto-start.
  const modalOpen = shell?.modalOpen ?? false;
  useEffect(() => {
    if (running || modalOpen || session.status !== 'ready') return;
    if (autoStartBlock()) return;
    if (!state) {
      ensureLoaded();
      return;
    }
    if (state.off || store === 'memory' || holdPath === pathname) return;
    const candidate = isPending(state, WELCOME_TOUR)
      ? WELCOME_TOUR
      : pageTour && isPending(state, pageTour)
        ? pageTour
        : null;
    if (!candidate) return;
    const key = `${candidate.id}@${pathname}`;
    if (exhausted.current.has(key) || pending.current?.key === key) return;
    pending.current?.cancel();
    const w = waitForAnchors(candidate, timings.auto);
    pending.current = { key, cancel: w.cancel };
    void w.done.then((ok) => {
      if (pending.current?.key !== key) return;
      pending.current = null;
      if (!ok) {
        exhausted.current.add(key);
        return;
      }
      const s = stateRef.current;
      if (runningRef.current || pathRef.current !== pathname || !s || s.off || !isPending(s, candidate)) return;
      if (autoStartBlock()) return;
      start(candidate, null);
    });
  }, [running, modalOpen, session.status, state, store, holdPath, pathname, pageTour, ensureLoaded, timings.auto, start]);

  // A wait still running when the provider unmounts.
  useEffect(() => () => pending.current?.cancel(), []);

  const value = useMemo<ToursApi>(
    () => ({
      state,
      store,
      running: running?.tour ?? null,
      pageTour,
      ensureLoaded,
      startPageTour,
      startFromBeginning,
      setOff,
    }),
    [state, store, running, pageTour, ensureLoaded, startPageTour, startFromBeginning, setOff],
  );

  return (
    <Ctx.Provider value={value}>
      {children}
      {running && (
        <TourOverlay
          key={`${running.tour.id}`}
          tour={running.tour}
          onEnd={onEnd}
          onStep={onStep}
          returnFocus={running.returnFocus}
        />
      )}
    </Ctx.Provider>
  );
}
