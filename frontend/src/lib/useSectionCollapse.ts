import { useCallback, useRef, useState } from 'react';

// ---------------------------------------------------------------------------
// The fold of one section of the Hunts page.
//
// The page is long: hits, leads, hunts, schedules. An analyst who works the
// leads should not scroll past fifty hit cards to reach them, and the fold must
// survive a reload, because a fold an analyst redoes on every visit is a fold
// they stop using.
//
// The fold is kept in localStorage, on this browser. It is a view preference,
// not a record: nothing on the server changes, and a second browser opens the
// page whole. A storage that refuses to write (private mode, a full quota) is
// not an error here. The section folds for this visit and the next visit opens
// it.
// ---------------------------------------------------------------------------

/** The key of one section's fold. The sections are named in the address of the
 *  page they live on, so the key names the page too. */
export const collapseKey = (section: string): string => `soc-ai.hunts.collapsed.${section}`;

function read(section: string): boolean {
  try {
    return localStorage.getItem(collapseKey(section)) === '1';
  } catch {
    return false;
  }
}

export interface SectionCollapse {
  /** True while the section is folded. */
  collapsed: boolean;
  /** Fold an open section, open a folded one. */
  toggle: () => void;
  /** Open the section. A link that jumps to a block opens it first: a jump to
   *  a folded block lands on a header and reads as a dead link. */
  expand: () => void;
}

export function useSectionCollapse(section: string): SectionCollapse {
  const [collapsed, setCollapsed] = useState(() => read(section));
  // The state, in a ref beside the state. `toggle` and `expand` read it, so
  // both are stable for the life of the section. An `expand` that changed
  // identity on every fold re-fired the effect that opens a block a link jumps
  // to, and that effect then re-opened the section the analyst had just
  // folded under an address that still carried the fragment.
  const current = useRef(collapsed);

  const set = useCallback(
    (next: boolean) => {
      current.current = next;
      setCollapsed(next);
      try {
        localStorage.setItem(collapseKey(section), next ? '1' : '0');
      } catch {
        /* the fold holds for this visit */
      }
    },
    [section],
  );

  return {
    collapsed,
    toggle: useCallback(() => set(!current.current), [set]),
    expand: useCallback(() => {
      if (current.current) set(false);
    }, [set]),
  };
}
