import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError, deleteDashboardLayout, getDashboardLayout, getMe, putDashboardLayout } from './api';
import {
  LAYOUT_STORAGE_KEY,
  type PanelSlot,
  defaultLayout,
  normalizeLayout,
  sameLayout,
  toWire,
} from './dashboardLayout';

// ---------------------------------------------------------------------------
// Where the Dashboard layout lives, and the three things an operator does to
// it: read it, change it, reset it.
//
// A signed-in user keeps one layout on the server, so it follows them between
// workstations, the way a saved view does. A deployment with authentication
// off (the range, the demo, every hermetic instance) has no user row to own
// one: /me says `signed_in: false`, and the layout then lives in this browser's
// localStorage under LAYOUT_STORAGE_KEY. In that mode the hook never calls the
// layout API, so a box with authentication off logs no 401 on every load.
//
// A server read that fails for any other reason locks the layout for this
// visit. Editing on top of the shipped layout would save over the layout the
// read could not fetch.
// ---------------------------------------------------------------------------

/** Where the layout is kept. */
export type LayoutStore = 'server' | 'browser';

/** Changes inside this window go to the server as one write. */
export const SAVE_DELAY_MS = 400;

export interface DashboardLayoutBinding {
  /** Every known panel, placed. The shipped layout until a saved one loads. */
  layout: PanelSlot[];
  /** True when a saved layout is in force, so Reset has something to undo. */
  saved: boolean;
  /** Null until /me answers. */
  store: LayoutStore | null;
  /** True when the layout may change. */
  editable: boolean;
  /** Why the layout may not change, when it may not. */
  lockedReason: string | null;
  /** One or more sentences that say where the layout is kept. */
  storeNote: string;
  /** The last read or write failure, as one sentence. */
  error: string | null;
  commit: (next: PanelSlot[]) => void;
  reset: () => void;
}

const SERVER_NOTE = 'soc-ai keeps this layout for your user account.';
const BROWSER_NOTE =
  'Authentication is off. This browser keeps the layout. Another browser shows the shipped layout.';
const LOADING = 'The layout is loading.';
const READ_FAILED = 'soc-ai could not read your saved layout. Reload the page to try again.';

function isAuthFailure(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 401 || err.status === 403);
}

function readBrowser(): PanelSlot[] | null {
  try {
    const raw = localStorage.getItem(LAYOUT_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { panels?: unknown };
    return Array.isArray(parsed?.panels) ? normalizeLayout(parsed.panels) : null;
  } catch {
    return null;
  }
}

function writeBrowser(layout: PanelSlot[] | null): boolean {
  try {
    if (layout) {
      localStorage.setItem(LAYOUT_STORAGE_KEY, JSON.stringify({ version: 1, panels: toWire(layout) }));
    } else {
      localStorage.removeItem(LAYOUT_STORAGE_KEY);
    }
    return true;
  } catch {
    return false;
  }
}

export function useDashboardLayout(): DashboardLayoutBinding {
  const [layout, setLayout] = useState<PanelSlot[]>(defaultLayout);
  const [saved, setSaved] = useState(false);
  const [store, setStore] = useState<LayoutStore | null>(null);
  const [readFailed, setReadFailed] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const storeRef = useRef<LayoutStore | null>(null);
  const alive = useRef(true);
  // Server writes run one after another, so a reset can never land before the
  // save it follows.
  const queue = useRef<Promise<unknown>>(Promise.resolve());
  const pending = useRef<PanelSlot[] | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const enqueue = useCallback(<T,>(op: () => Promise<T>): Promise<T> => {
    const run = queue.current.then(op, op);
    queue.current = run.catch(() => undefined);
    return run;
  }, []);

  useEffect(() => {
    alive.current = true;
    let live = true;
    const useBrowser = () => {
      storeRef.current = 'browser';
      setStore('browser');
      const kept = readBrowser();
      if (kept) {
        setLayout(kept);
        setSaved(true);
      }
    };
    void (async () => {
      let signedIn: boolean | undefined;
      try {
        signedIn = (await getMe()).signed_in;
      } catch {
        // Unknown. The layout read answers for itself.
      }
      if (!live) return;
      if (signedIn === false) {
        useBrowser();
        return;
      }
      try {
        const wire = await getDashboardLayout();
        if (!live) return;
        storeRef.current = 'server';
        setStore('server');
        if (wire.panels) {
          setLayout(normalizeLayout(wire.panels));
          setSaved(true);
        }
      } catch (err) {
        if (!live) return;
        if (isAuthFailure(err)) {
          useBrowser();
          return;
        }
        storeRef.current = 'server';
        setStore('server');
        setReadFailed(true);
      }
    })();
    return () => {
      live = false;
    };
  }, []);

  const flush = useCallback(() => {
    timer.current = null;
    const next = pending.current;
    if (!next) return;
    pending.current = null;
    enqueue(() => putDashboardLayout(toWire(next))).catch((err: unknown) => {
      if (!alive.current) return;
      setError(
        isAuthFailure(err)
          ? 'Sign in again to keep the layout.'
          : 'soc-ai could not save the layout. The next change tries again.',
      );
    });
  }, [enqueue]);

  // Leaving the Dashboard sends a save that is still waiting.
  useEffect(
    () => () => {
      alive.current = false;
      if (timer.current) {
        clearTimeout(timer.current);
        flush();
      }
    },
    [flush],
  );

  const commit = useCallback(
    (next: PanelSlot[]) => {
      setLayout((prev) => (sameLayout(prev, next) ? prev : next));
      setSaved(true);
      setError(null);
      if (storeRef.current === 'browser') {
        if (!writeBrowser(next)) setError('This browser did not keep the layout.');
        return;
      }
      if (storeRef.current !== 'server') return;
      pending.current = next;
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(flush, SAVE_DELAY_MS);
    },
    [flush],
  );

  const reset = useCallback(() => {
    if (timer.current) {
      clearTimeout(timer.current);
      timer.current = null;
    }
    pending.current = null;
    setLayout(defaultLayout());
    setSaved(false);
    setError(null);
    if (storeRef.current === 'browser') {
      if (!writeBrowser(null)) setError('This browser did not remove the saved layout.');
      return;
    }
    if (storeRef.current !== 'server') return;
    enqueue(() => deleteDashboardLayout()).catch(() => {
      if (alive.current) setError('soc-ai could not reset the saved layout. Try again.');
    });
  }, [enqueue]);

  const editable = store !== null && !readFailed;
  return {
    layout,
    saved,
    store,
    editable,
    lockedReason: store === null ? LOADING : readFailed ? READ_FAILED : null,
    storeNote: store === 'browser' ? BROWSER_NOTE : SERVER_NOTE,
    error: error ?? (readFailed ? READ_FAILED : null),
    commit,
    reset,
  };
}
