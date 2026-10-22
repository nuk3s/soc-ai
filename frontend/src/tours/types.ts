// ---------------------------------------------------------------------------
// A tour is data. The engine (TourOverlay) reads it, finds each anchor on the
// page and draws the spotlight and the card. All tour text lives in
// content.ts, so the owner reviews it in one place.
// ---------------------------------------------------------------------------

/** Where the card sits beside the spotlit element. `auto` picks the side
 *  with room, in the order bottom, top, right, left. */
export type TourPlacement = 'auto' | 'top' | 'bottom' | 'left' | 'right';

export interface TourStep {
  /** The `data-tour` value of the element the step points at. A step whose
   *  anchor is not on the page is skipped, never shown pointing at nothing. */
  anchor: string;
  /** A plain noun phrase: "Page time filter", "Waiting actions". */
  title: string;
  /** One to three ASD-STE100 sentences. */
  body: string;
  placement?: TourPlacement;
  /** The spotlit element takes clicks during this step. Use it sparingly. */
  tryIt?: boolean;
  /** Where the anchor lives. `shell`: the sidebar or the top bar, on every
   *  page. `page`: the routed screen. The welcome tour keeps running across a
   *  route change while its step is in the shell, and ends at a `page` step.
   *  The default is `shell` for the welcome tour and `page` for a page tour. */
  scope?: 'shell' | 'page';
}

export interface Tour {
  /** Stable id, the key of the stored "seen" map. Lowercase and hyphens. */
  id: string;
  /** Bump only when the tour changes in a way a returning operator needs to
   *  see. A tour starts again on a first visit when the stored version is
   *  lower than this one. */
  version: number;
  /** The page name, for the "?" menu and the card. */
  name: string;
  /** react-router path patterns of the page the tour belongs to. Empty for
   *  the welcome tour, which runs over the shell on any page. */
  routes: string[];
  steps: TourStep[];
}

/** What the store keeps per user: the global opt-out and, per tour id, the
 *  version the operator saw. The server and localStorage hold the same shape. */
export interface ToursState {
  off: boolean;
  seen: Record<string, number>;
}
