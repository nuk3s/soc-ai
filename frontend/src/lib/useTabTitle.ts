// ---------------------------------------------------------------------------
// The browser tab title of a page.
//
// Every page read "soc·ai: SOC alert triage", the title of index.html. An
// analyst with three hunt tabs and two lead tabs could not tell them apart
// (R3-D15). A page names itself, and the old title comes back when the page
// unmounts.
// ---------------------------------------------------------------------------

import { useEffect } from 'react';

/** The product name the tab title ends with. */
export const TAB_TITLE_SUFFIX = 'soc·ai';

/** "Lead 5 · soc·ai". An empty name leaves the title as it is. */
export function tabTitle(name: string): string {
  const trimmed = name.trim();
  return trimmed ? `${trimmed} · ${TAB_TITLE_SUFFIX}` : '';
}

/** Set the tab title to `name` while the page is mounted. */
export function useTabTitle(name: string | null | undefined): void {
  const title = tabTitle(name ?? '');
  useEffect(() => {
    if (!title) return;
    const before = document.title;
    document.title = title;
    return () => {
      document.title = before;
    };
  }, [title]);
}
