// The selection contract every list screen shares, lifted verbatim from the
// behaviour Investigations already had: a header checkbox that selects the
// visible page and clears it on a second click, a count that survives a filter
// change (a selection the operator made is not un-made by narrowing the view),
// and an explicit clear.
import { act, renderHook } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { useListSelection } from './useListSelection';

describe('useListSelection', () => {
  it('starts empty', () => {
    const { result } = renderHook(() => useListSelection(['a', 'b']));
    expect(result.current.count).toBe(0);
    expect(result.current.ids).toEqual([]);
    expect(result.current.allVisibleSelected).toBe(false);
    expect(result.current.someVisibleSelected).toBe(false);
  });

  it('toggles one id on and off', () => {
    const { result } = renderHook(() => useListSelection(['a', 'b']));
    act(() => result.current.toggle('a'));
    expect(result.current.isSelected('a')).toBe(true);
    expect(result.current.ids).toEqual(['a']);
    expect(result.current.count).toBe(1);
    expect(result.current.someVisibleSelected).toBe(true);
    expect(result.current.allVisibleSelected).toBe(false);

    act(() => result.current.toggle('a'));
    expect(result.current.isSelected('a')).toBe(false);
    expect(result.current.count).toBe(0);
  });

  it('selects every visible id, then deselects them all on a second toggle', () => {
    const { result } = renderHook(() => useListSelection(['a', 'b', 'c']));
    act(() => result.current.toggleAll());
    expect(result.current.count).toBe(3);
    expect(result.current.allVisibleSelected).toBe(true);

    act(() => result.current.toggleAll());
    expect(result.current.count).toBe(0);
    expect(result.current.allVisibleSelected).toBe(false);
  });

  it('toggleAll over a partial selection selects the rest rather than clearing', () => {
    const { result } = renderHook(() => useListSelection(['a', 'b', 'c']));
    act(() => result.current.toggle('b'));
    act(() => result.current.toggleAll());
    expect(result.current.count).toBe(3);
  });

  it('an empty page is never "all selected"', () => {
    const { result } = renderHook(() => useListSelection([]));
    expect(result.current.allVisibleSelected).toBe(false);
    act(() => result.current.toggleAll());
    expect(result.current.count).toBe(0);
  });

  it('keeps a selection the current page no longer shows, AND says how much', () => {
    // A filter change swaps the visible ids. The operator selected 'a'; the
    // count must still say so, because the bulk action still targets it.
    //
    // But persistence on its own is a trap — it was shipped that way and the
    // old version of this test pinned the trap green. The operator filtered to
    // critical, selected all, cleared the filter, and the strip still read N
    // while the header box read unchecked and the rows were gone; a bulk action
    // then submitted ids nothing on screen showed. So the contract is
    // persistence PLUS disclosure: whatever renders `count` renders
    // `offPageCount` too.
    const { result, rerender } = renderHook(({ ids }) => useListSelection(ids), {
      initialProps: { ids: ['a', 'b'] },
    });
    act(() => result.current.toggle('a'));
    expect(result.current.offPageCount).toBe(0);

    rerender({ ids: ['c', 'd'] });
    expect(result.current.count).toBe(1);
    expect(result.current.ids).toEqual(['a']);
    expect(result.current.someVisibleSelected).toBe(false);
    expect(result.current.offPageCount).toBe(1);
  });

  it('counts only the off-page part when the selection straddles the page', () => {
    const { result, rerender } = renderHook(({ ids }) => useListSelection(ids), {
      initialProps: { ids: ['a', 'b', 'c'] },
    });
    act(() => result.current.toggleAll());
    rerender({ ids: ['a', 'z'] });
    expect(result.current.count).toBe(3);
    expect(result.current.offPageCount).toBe(2); // b and c
  });

  it('clearOffPage drops the invisible ids and keeps the visible ones', () => {
    const { result, rerender } = renderHook(({ ids }) => useListSelection(ids), {
      initialProps: { ids: ['a', 'b', 'c'] },
    });
    act(() => result.current.toggleAll());
    rerender({ ids: ['a'] });
    act(() => result.current.clearOffPage());
    expect(result.current.ids).toEqual(['a']);
    expect(result.current.offPageCount).toBe(0);
  });

  it('toggleAll only deselects the VISIBLE ids, leaving off-page ones selected', () => {
    const { result, rerender } = renderHook(({ ids }) => useListSelection(ids), {
      initialProps: { ids: ['a', 'b'] },
    });
    act(() => result.current.toggleAll());
    rerender({ ids: ['a'] });
    act(() => result.current.toggleAll()); // 'a' is all-visible-selected → clear it
    expect(result.current.ids).toEqual(['b']);
  });

  it('clear() drops everything, on-page or not', () => {
    const { result, rerender } = renderHook(({ ids }) => useListSelection(ids), {
      initialProps: { ids: ['a', 'b'] },
    });
    act(() => result.current.toggleAll());
    rerender({ ids: ['c'] });
    act(() => result.current.clear());
    expect(result.current.count).toBe(0);
  });

  it('select() replaces the selection with exactly the given ids', () => {
    // The retry path: a bulk action keeps the FAILED ids selected so the
    // operator can click the same button again.
    const { result } = renderHook(() => useListSelection(['a', 'b', 'c']));
    act(() => result.current.toggleAll());
    act(() => result.current.select(['b']));
    expect(result.current.ids).toEqual(['b']);
    expect(result.current.count).toBe(1);
  });

  it('ids are ordered by the visible page, then by selection order', () => {
    const { result } = renderHook(() => useListSelection(['c', 'b', 'a']));
    act(() => result.current.toggle('a'));
    act(() => result.current.toggle('c'));
    expect(result.current.ids).toEqual(['c', 'a']);
  });
});
