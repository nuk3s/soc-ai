import { useCallback, useMemo, useState } from 'react';

/**
 * Checkbox selection for a list screen.
 *
 * Lifted from the Investigations screen rather than re-derived: it already had
 * the header-checkbox semantics the other lists copied by hand (Hunts) or never
 * got at all (Hosts). Four screens each owning a `Record<string, boolean>` and
 * their own `toggleSelectAll` is how they drifted apart in the first place.
 *
 * Three decisions worth stating, because all three are behaviour and not detail:
 *
 * - The selection is keyed by id and OUTLIVES the page. Narrowing a filter does
 *   not un-select what the operator picked; the bulk action still targets it,
 *   and the count still says so. `someVisibleSelected` is the only figure that
 *   speaks about the page.
 * - Persistence without DISCLOSURE is a trap, and this hook shipped it. Filter
 *   to critical, select all, clear the filter: the count still said N, the
 *   header box read unchecked (it asks about the NEW visible set), a second
 *   "select all" piled the new page on top of the invisible N, and the bulk
 *   action then submitted ids the operator could not see anywhere on screen.
 *   So `offPageCount` is part of the contract, not a convenience — every
 *   surface that renders `count` must render this too when it is non-zero, and
 *   ListToolbar does.
 * - `toggleAll` operates on the VISIBLE ids only. Selecting page 1, paging to
 *   page 2 and clicking the header box selects page 2 as well — it does not
 *   silently drop page 1.
 */
export interface ListSelection {
  /** The selected ids: visible ones first (in page order), then off-page ones. */
  ids: string[];
  /** How many ids are selected — including any the current page does not show. */
  count: number;
  /**
   * How many selected ids the current page does NOT show.
   *
   * Non-zero means the operator is holding a selection they cannot see. It is
   * what turns silent persistence into stated persistence; a bulk action's
   * label and confirmation have to account for it.
   */
  offPageCount: number;
  isSelected: (id: string) => boolean;
  toggle: (id: string) => void;
  /** Select every visible id, or clear them if they are already all selected. */
  toggleAll: () => void;
  /** Replace the selection with exactly these ids (the "keep the failures selected" path). */
  select: (ids: string[]) => void;
  clear: () => void;
  /** Drop only the ids the current page does not show — the disclosure's escape hatch. */
  clearOffPage: () => void;
  allVisibleSelected: boolean;
  someVisibleSelected: boolean;
}

export function useListSelection(visibleIds: string[]): ListSelection {
  const [selected, setSelected] = useState<Record<string, boolean>>({});

  // Array identity changes every render, so key the memos off the contents.
  const visibleKey = visibleIds.join(' ');

  const { ids, offPageCount } = useMemo(() => {
    const chosen = new Set(Object.keys(selected).filter((id) => selected[id]));
    const visible = new Set(visibleIds);
    const onPage = visibleIds.filter((id) => chosen.has(id));
    const offPage = [...chosen].filter((id) => !visible.has(id));
    return { ids: [...onPage, ...offPage], offPageCount: offPage.length };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected, visibleKey]);

  const allVisibleSelected = visibleIds.length > 0 && visibleIds.every((id) => selected[id]);
  const someVisibleSelected = visibleIds.some((id) => selected[id]);

  const toggle = useCallback((id: string) => {
    setSelected((prev) => ({ ...prev, [id]: !prev[id] }));
  }, []);

  const toggleAll = useCallback(() => {
    setSelected((prev) => {
      const next = { ...prev };
      const everyOn = visibleIds.length > 0 && visibleIds.every((id) => prev[id]);
      for (const id of visibleIds) {
        if (everyOn) delete next[id];
        else next[id] = true;
      }
      return next;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visibleKey]);

  const select = useCallback((next: string[]) => {
    setSelected(Object.fromEntries(next.map((id) => [id, true])));
  }, []);

  const clear = useCallback(() => setSelected({}), []);

  const clearOffPage = useCallback(() => {
    setSelected((prev) => {
      const next: Record<string, boolean> = {};
      for (const id of visibleIds) if (prev[id]) next[id] = true;
      return next;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visibleKey]);

  const isSelected = useCallback((id: string) => !!selected[id], [selected]);

  return {
    ids,
    count: ids.length,
    offPageCount,
    isSelected,
    toggle,
    toggleAll,
    select,
    clear,
    clearOffPage,
    allVisibleSelected,
    someVisibleSelected,
  };
}
