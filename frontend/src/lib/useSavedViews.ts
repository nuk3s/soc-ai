import { useCallback, useEffect, useRef, useState } from 'react';
import type { ToolbarView } from '../components/ListToolbar';
import { ApiError, deleteSavedView, listSavedViews, saveView } from './api';
import type { SavedView, SavedViewQuery, SavedViewScreen } from './types';

/**
 * Saved views for one list screen, in the shape ListToolbar takes.
 *
 * The views live on the server, per user, because the owner asked for them to
 * follow the analyst between workstations — a filter set that only exists in
 * one browser profile is one the analyst re-types at the other desk.
 *
 * `query` is the screen's CURRENT filter state on every render; it is held in a
 * ref so "Save view" captures what is on screen at the moment of the click
 * rather than whatever was there when the toolbar mounted.
 *
 * A caller with no user row — a bearer-token client, a no-auth dev session —
 * gets `onSaveView: undefined`, so the toolbar simply omits the control instead
 * of offering a button that 401s. That latch is scoped to AUTH failures: a
 * transient 500 used to remove "Save view" for the rest of the mount, which is
 * a working feature deleted by one bad response.
 */
export interface SavedViewsBinding {
  views: SavedView[];
  activeViewId: number | null;
  onApplyView: (view: ToolbarView) => void;
  onDeleteView: (view: ToolbarView) => void;
  /** Resolves once the write has settled, so the toolbar can keep its composer
   *  open and show the reason when the server refuses. */
  onSaveView?: (name: string) => Promise<void>;
  /** The last write's failure, for surfaces that show it inline. */
  error: string | null;
  /** The screen calls this when the operator edits a facet by hand, so a chip
   *  stops claiming to describe filters that have since moved on. */
  clearActive: () => void;
}

/**
 * A 401/403 is "you have no user row"; anything else is weather.
 *
 * Read the STATUS first. This used to match on the message alone, and the
 * message a refused call actually carries is the server's prose hint ("Saved
 * views belong to a signed-in user.") — which matches neither pattern, so the
 * latch below could never fire in the real app. The string checks stay as a
 * fallback for callers that throw a bare Error.
 */
function isAuthFailure(err: unknown): boolean {
  if (err instanceof ApiError) return err.status === 401 || err.status === 403;
  const msg = err instanceof Error ? err.message : String(err);
  return /^(401|403)\b/.test(msg) || /no_session/.test(msg);
}

/** The server's `reason`/`hint` if it sent one, else the raw message. */
function readableError(err: unknown, fallback: string): string {
  const msg = err instanceof Error ? err.message : String(err);
  const reason = err instanceof ApiError ? (err.reason ?? '') : '';
  const code = `${reason} ${msg}`;
  if (/too_many_views/.test(code)) return 'You have reached the saved-view limit — delete one first.';
  if (/query_too_large|query_too_deep/.test(code)) return 'These filters are too large to save.';
  if (/empty_name/.test(code)) return 'A view needs a name.';
  if (isAuthFailure(err)) return 'Saved views need a signed-in session.';
  return msg || fallback;
}

export function useSavedViews(
  screen: SavedViewScreen,
  query: SavedViewQuery,
  onApply: (query: SavedViewQuery) => void,
): SavedViewsBinding {
  const [views, setViews] = useState<SavedView[]>([]);
  const [available, setAvailable] = useState(true);
  const [activeViewId, setActiveViewId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Latest-render values, so the callbacks below never close over a stale
  // filter state or a stale apply handler.
  const queryRef = useRef(query);
  queryRef.current = query;
  const applyRef = useRef(onApply);
  applyRef.current = onApply;

  // Bumped to force a reload — a delete that 404s means this list is stale, and
  // the only fetch is keyed on [screen], so without this the dead chip is
  // permanent for the mount.
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let live = true;
    listSavedViews(screen)
      .then((rows) => {
        if (!live) return;
        setViews(rows);
        setAvailable(true);
      })
      .catch((err: unknown) => {
        if (!live) return;
        setViews([]);
        // ONLY an auth failure means there is no user to own a view. A 500 or a
        // dropped connection is weather: keep the control, let the next write
        // report its own outcome.
        if (isAuthFailure(err)) setAvailable(false);
      });
    return () => {
      live = false;
    };
  }, [screen, reloadKey]);

  // onApplyView reads the current rows (and the active id) without re-creating
  // itself each time either changes — the toolbar re-renders on every keystroke
  // as it is.
  const viewsRef = useRef(views);
  viewsRef.current = views;
  const activeRef = useRef(activeViewId);
  activeRef.current = activeViewId;

  // A real toggle, not a one-way switch. The chip renders `aria-pressed`, which
  // promises a second press undoes the first — and it did not: the chip went
  // false→true on the first click and stayed true for the rest of the mount.
  // Only Alerts ships an "All" preset to get back to, so on Investigations,
  // Hunts and Hosts the only route out of an applied view was clearing the
  // search box and every facet by hand.
  //
  // Clicking the ACTIVE chip applies the EMPTY query. That is the screen's own
  // unfiltered default rather than a special case: apply is total, so a facet
  // the query does not name returns to that screen's named default.
  const onApplyView = useCallback((view: ToolbarView) => {
    if (activeRef.current === view.id) {
      setActiveViewId(null);
      applyRef.current({});
      return;
    }
    const row = viewsRef.current.find((v) => v.id === view.id);
    if (!row) return;
    setActiveViewId(row.id);
    applyRef.current(row.query);
  }, []);

  const onDeleteView = useCallback((view: ToolbarView) => {
    setError(null);
    void deleteSavedView(view.id)
      .then(() => {
        setViews((prev) => prev.filter((v) => v.id !== view.id));
        setActiveViewId((prev) => (prev === view.id ? null : prev));
      })
      .catch((err: unknown) => {
        setError(readableError(err, "That view couldn't be deleted."));
        // A 404 means the chip is describing a row that is gone — leaving it
        // there makes a permanently dead chip, because the only fetch is keyed
        // on [screen]. Re-read rather than guess.
        setReloadKey((k) => k + 1);
      });
  }, []);

  const onSaveView = useCallback(
    (name: string): Promise<void> => {
      setError(null);
      return saveView(screen, name, queryRef.current).then(
        (row) => {
          // Replace by id: the backend upserts on (user, screen, name), so
          // re-saving must swap the chip rather than double it.
          setViews((prev) => [...prev.filter((v) => v.id !== row.id), row]);
          setActiveViewId(row.id);
        },
        (err: unknown) => {
          // Rethrow after recording it: the toolbar keeps its composer (and the
          // typed name) open on a rejection. Swallowing this produced the worst
          // possible outcome for a real `too_many_views` — the name gone, no
          // chip, and no message.
          setError(readableError(err, "That view couldn't be saved."));
          throw err;
        },
      );
    },
    [screen],
  );

  const clearActive = useCallback(() => setActiveViewId(null), []);

  return {
    views,
    activeViewId,
    onApplyView,
    onDeleteView,
    onSaveView: available ? onSaveView : undefined,
    error,
    clearActive,
  };
}
