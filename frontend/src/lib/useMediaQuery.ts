import { useEffect, useState } from 'react';

/** Tailwind's `lg` breakpoint, the width where the Dashboard becomes a grid. */
export const WIDE_QUERY = '(min-width: 1024px)';

function matches(query: string): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return true;
  return window.matchMedia(query).matches;
}

/** Whether a media query matches now, kept current as the window changes. */
export function useMediaQuery(query: string): boolean {
  const [on, setOn] = useState(() => matches(query));
  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return;
    const list = window.matchMedia(query);
    const update = () => setOn(list.matches);
    update();
    list.addEventListener('change', update);
    return () => list.removeEventListener('change', update);
  }, [query]);
  return on;
}

/** The width where the Alerts and Investigations rows show every column. Under
 *  it a row folds its low-value columns into the name cell, so the row and its
 *  actions fit the card (prod review 2026-11-12, ui-core 12). */
export const WIDE_TABLE_QUERY = '(min-width: 1280px)';
