import { useState } from 'react';

export type SortDir = 'asc' | 'desc';

export interface SortState<K extends string> {
  key: K;
  dir: SortDir;
}

// Shared table-header sort mechanics: state + toggle + direction caret + header
// cell class, used by the Alerts and Investigations grids. Clicking the active
// column flips its direction; clicking a NEW column selects it at `newKeyDir` —
// that starting direction is deliberately per-screen (Alerts starts new columns
// descending, Investigations ascending), so it's a parameter, not a default.
export function useSort<K extends string>(initial: SortState<K>, newKeyDir: SortDir) {
  const [sort, setSort] = useState<SortState<K>>(initial);

  const toggleSort = (key: K) => {
    setSort((prev) =>
      prev.key === key
        ? { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' }
        : { key, dir: newKeyDir },
    );
  };

  // Direction caret — rendered only on the active sort column.
  const caret = (key: K) => {
    if (sort.key !== key) return null;
    return <span className="ml-0.5 text-accent">{sort.dir === 'asc' ? '↑' : '↓'}</span>;
  };

  // Header-cell class: clickable, highlighted when it's the active sort column.
  const headerCls = (key: K) =>
    'cursor-pointer select-none hover:text-text ' + (sort.key === key ? 'text-text' : '');

  return { sort, toggleSort, caret, headerCls };
}
