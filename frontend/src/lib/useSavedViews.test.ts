// The hook that turns the saved-view endpoints into the props ListToolbar
// wants. What is worth pinning: "Save view" captures the filter state as it is
// at the moment of the click (not at mount), applying a chip hands the screen
// the stored query back, and a caller with no user row (bearer token, dev
// no-auth) gets a toolbar with no saved-view controls rather than buttons that
// 401.
import { act, renderHook, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from './api';
import type { SavedView } from './types';

const listSavedViews = vi.hoisted(() => vi.fn());
const saveView = vi.hoisted(() => vi.fn());
const deleteSavedView = vi.hoisted(() => vi.fn());

vi.mock('./api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./api')>()),
  listSavedViews,
  saveView,
  deleteSavedView,
}));

import { useSavedViews } from './useSavedViews';

const view = (over: Partial<SavedView> = {}): SavedView => ({
  id: 1,
  screen: 'investigations',
  name: 'Beacons',
  query: { verdict: ['true_positive'] },
  created_at: null,
  ...over,
});

beforeEach(() => {
  listSavedViews.mockReset().mockResolvedValue([]);
  saveView.mockReset();
  deleteSavedView.mockReset().mockResolvedValue({ ok: true });
});

describe('useSavedViews', () => {
  it('loads this screen\'s views', async () => {
    listSavedViews.mockResolvedValue([view()]);
    const { result } = renderHook(() => useSavedViews('investigations', {}, vi.fn()));
    await waitFor(() => expect(result.current.views).toHaveLength(1));
    expect(listSavedViews).toHaveBeenCalledWith('investigations');
    expect(result.current.views[0].name).toBe('Beacons');
  });

  it('saves the filter state as it is when the button is clicked', async () => {
    saveView.mockResolvedValue(view({ id: 9, name: 'Later' }));
    const { result, rerender } = renderHook(
      ({ q }) => useSavedViews('hosts', q, vi.fn()),
      { initialProps: { q: { role: 'server' } as Record<string, unknown> } },
    );
    await waitFor(() => expect(listSavedViews).toHaveBeenCalled());
    // The operator changes a filter, THEN saves.
    rerender({ q: { role: 'printer' } });
    await act(async () => {
      result.current.onSaveView?.('Later');
    });
    expect(saveView).toHaveBeenCalledWith('hosts', 'Later', { role: 'printer' });
    await waitFor(() => expect(result.current.views.map((v) => v.name)).toContain('Later'));
  });

  it('hands the stored query back to the screen when a chip is applied', async () => {
    const onApply = vi.fn();
    const v = view({ query: { verdict: ['false_positive'], status: ['error'] } });
    listSavedViews.mockResolvedValue([v]);
    const { result } = renderHook(() => useSavedViews('investigations', {}, onApply));
    await waitFor(() => expect(result.current.views).toHaveLength(1));
    act(() => result.current.onApplyView(v));
    expect(onApply).toHaveBeenCalledWith({ verdict: ['false_positive'], status: ['error'] });
    expect(result.current.activeViewId).toBe(v.id);
  });

  it('clicking the ACTIVE chip again clears the filters and turns the chip off', async () => {
    // The chip rendered aria-pressed and went false→true on the first click,
    // then stayed true forever. Investigations/Hunts/Hosts ship no "All" preset
    // to get back to, so the only way out of an applied view was clearing the
    // search box and every facet by hand.
    const onApply = vi.fn();
    const v = view({ query: { verdict: ['false_positive'] } });
    listSavedViews.mockResolvedValue([v]);
    const { result } = renderHook(() => useSavedViews('investigations', {}, onApply));
    await waitFor(() => expect(result.current.views).toHaveLength(1));

    act(() => result.current.onApplyView(v));
    expect(result.current.activeViewId).toBe(v.id);

    act(() => result.current.onApplyView(v));
    // An empty query IS the screen's own default: apply is total, so every
    // facet the query does not name goes back to that screen's named default.
    expect(onApply).toHaveBeenLastCalledWith({});
    expect(result.current.activeViewId).toBeNull();
  });

  it('clicking a DIFFERENT chip switches views rather than clearing', async () => {
    const onApply = vi.fn();
    const a = view({ id: 1, name: 'A', query: { q: 'a' } });
    const b = view({ id: 2, name: 'B', query: { q: 'b' } });
    listSavedViews.mockResolvedValue([a, b]);
    const { result } = renderHook(() => useSavedViews('investigations', {}, onApply));
    await waitFor(() => expect(result.current.views).toHaveLength(2));

    act(() => result.current.onApplyView(a));
    act(() => result.current.onApplyView(b));
    expect(onApply).toHaveBeenLastCalledWith({ q: 'b' });
    expect(result.current.activeViewId).toBe(2);
  });

  it('drops a deleted view from the chip row', async () => {
    const v = view();
    listSavedViews.mockResolvedValue([v]);
    const { result } = renderHook(() => useSavedViews('investigations', {}, vi.fn()));
    await waitFor(() => expect(result.current.views).toHaveLength(1));
    await act(async () => {
      result.current.onDeleteView(v);
    });
    expect(deleteSavedView).toHaveBeenCalledWith(1);
    await waitFor(() => expect(result.current.views).toHaveLength(0));
  });

  it('offers no save control when the caller has no user row to own a view', async () => {
    listSavedViews.mockRejectedValue(new Error('401 no_session'));
    const { result } = renderHook(() => useSavedViews('hunts', {}, vi.fn()));
    await waitFor(() => expect(result.current.onSaveView).toBeUndefined());
    expect(result.current.views).toEqual([]);
  });

  it('recognises the refusal in the shape the API actually throws', async () => {
    // The case above uses a hand-made '401 no_session' message, which nothing
    // in api.ts ever produces — so the latch it pins was unreachable in the
    // real app. A refused /me/views arrives as an ApiError whose MESSAGE is the
    // server's prose hint; only its status and reason say what happened.
    listSavedViews.mockRejectedValue(
      new ApiError('Saved views belong to a signed-in user.', 401, 'no_session'),
    );
    const { result } = renderHook(() => useSavedViews('investigations', {}, vi.fn()));
    await waitFor(() => expect(result.current.onSaveView).toBeUndefined());
    expect(result.current.views).toEqual([]);
  });

  it('says a refused save needs a session, rather than echoing raw prose', async () => {
    saveView.mockRejectedValue(
      new ApiError('Saved views belong to a signed-in user.', 401, 'no_session'),
    );
    const { result } = renderHook(() => useSavedViews('hosts', {}, vi.fn()));
    await waitFor(() => expect(listSavedViews).toHaveBeenCalled());
    await act(async () => {
      await expect(result.current.onSaveView?.('Nope')).rejects.toThrow();
    });
    expect(result.current.error).toMatch(/signed-in session/i);
  });

  it('KEEPS the save control through a transient server failure', async () => {
    // The latch used to fire on any rejection, so one 500 deleted a working
    // feature for the rest of the mount. Only "you have no user row" means the
    // control cannot work.
    listSavedViews.mockRejectedValue(new Error('500 Internal Server Error'));
    const { result } = renderHook(() => useSavedViews('hosts', {}, vi.fn()));
    await waitFor(() => expect(result.current.views).toEqual([]));
    expect(result.current.onSaveView).toBeDefined();
  });

  it('reports a refused save instead of swallowing it', async () => {
    // A real `too_many_views` used to produce: the typed name gone, no chip,
    // and no message — the worst of the three possible outcomes.
    saveView.mockRejectedValue(new Error('400 too_many_views'));
    const { result } = renderHook(() => useSavedViews('hosts', { role: 'server' }, vi.fn()));
    await waitFor(() => expect(listSavedViews).toHaveBeenCalled());
    await act(async () => {
      await expect(result.current.onSaveView?.('Nope')).rejects.toThrow();
    });
    expect(result.current.error).toMatch(/limit/i);
    expect(result.current.views).toEqual([]);
  });

  it('reports a refused delete and re-reads, so a dead chip cannot persist', async () => {
    const v = view();
    listSavedViews.mockResolvedValue([v]);
    deleteSavedView.mockRejectedValue(new Error('404 not_found'));
    const { result } = renderHook(() => useSavedViews('investigations', {}, vi.fn()));
    await waitFor(() => expect(result.current.views).toHaveLength(1));

    listSavedViews.mockResolvedValue([]); // the row really is gone server-side
    await act(async () => {
      result.current.onDeleteView(v);
    });
    await waitFor(() => expect(result.current.error).toBeTruthy());
    // The only fetch is keyed on [screen], so without a forced re-read the
    // chip would stay on screen forever.
    await waitFor(() => expect(result.current.views).toHaveLength(0));
    expect(listSavedViews).toHaveBeenCalledTimes(2);
  });

  it('re-saving a name replaces the chip instead of adding a second', async () => {
    const first = view({ id: 4, name: 'Beacons', query: { a: 1 } });
    listSavedViews.mockResolvedValue([first]);
    saveView.mockResolvedValue(view({ id: 4, name: 'Beacons', query: { a: 2 } }));
    const { result } = renderHook(() => useSavedViews('investigations', { a: 2 }, vi.fn()));
    await waitFor(() => expect(result.current.views).toHaveLength(1));
    await act(async () => {
      result.current.onSaveView?.('Beacons');
    });
    await waitFor(() => expect(result.current.views).toHaveLength(1));
    expect(result.current.views[0].query).toEqual({ a: 2 });
  });
});
