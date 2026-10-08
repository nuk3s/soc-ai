import { useEffect, useRef } from 'react';
import { useLocation } from 'react-router-dom';
import { pageLabel } from './pages';
import { useShell } from './ShellContext';

/**
 * Records the in-shell page the analyst left, with its search, in
 * `previousPage`. A change of search on one page updates the address the
 * page is left from, so a back link returns to the list with its filters.
 * Only a change of page moves `previousPage`.
 */
export function PreviousPageTracker() {
  const { pathname, search } = useLocation();
  const { setPreviousPage } = useShell();
  const last = useRef<{ pathname: string; path: string } | null>(null);
  useEffect(() => {
    const prev = last.current;
    if (prev && prev.pathname !== pathname) {
      const label = pageLabel(prev.pathname);
      setPreviousPage(label ? { path: prev.path, label } : null);
    }
    last.current = { pathname, path: pathname + search };
  }, [pathname, search, setPreviousPage]);
  return null;
}
