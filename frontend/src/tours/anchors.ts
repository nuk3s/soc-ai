// ---------------------------------------------------------------------------
// Finding the element a step points at, and placing the card beside it.
// ---------------------------------------------------------------------------
import type { Tour, TourPlacement, TourStep } from './types';

/** True when the browser lays the page out. happy-dom does not: every box
 *  there is 0 x 0, so a size check would hide every anchor in a unit test. */
function hasLayout(): boolean {
  return document.documentElement.getBoundingClientRect().width > 0;
}

/** True when the element takes part in the layout: connected, no ancestor
 *  hides it, and it has an area. A hidden element counts as absent, and so
 *  does an empty wrapper whose content rendered nothing: the step would
 *  light an empty box. */
export function isShown(el: Element): boolean {
  if (!el.isConnected) return false;
  const check = (el as Element & { checkVisibility?: (o?: object) => boolean }).checkVisibility;
  if (typeof check === 'function') {
    if (!check.call(el, { visibilityProperty: true })) return false;
  } else {
    for (let n: Element | null = el; n; n = n.parentElement) {
      if (n instanceof HTMLElement && n.hidden) return false;
      const cs = getComputedStyle(n);
      if (cs.display === 'none' || cs.visibility === 'hidden') return false;
    }
  }
  if (hasLayout()) {
    const r = el.getBoundingClientRect();
    if (r.width === 0 || r.height === 0) return false;
  }
  return true;
}

/** The first shown element with this `data-tour` value, or null. */
export function findAnchor(anchor: string, root: ParentNode = document): HTMLElement | null {
  const all = root.querySelectorAll<HTMLElement>(`[data-tour="${CSS.escape(anchor)}"]`);
  for (const el of all) if (isShown(el)) return el;
  return null;
}

/** The indexes of the steps whose anchor is on the page now. */
export function presentSteps(steps: readonly TourStep[]): number[] {
  const out: number[] = [];
  steps.forEach((s, i) => {
    if (findAnchor(s.anchor)) out.push(i);
  });
  return out;
}

export interface WaitOptions {
  /** How often to look. */
  pollMs: number;
  /** The set of present anchors must hold this long before the tour starts.
   *  A page that is still loading adds anchors; the wait lets it finish. */
  settleMs: number;
  /** The longest wait. The tour then starts with the anchors it has. */
  maxMs: number;
}

/**
 * Wait until the tour has anchors on the page and the set stops growing.
 * Resolves true when at least one anchor is present at the end, false when
 * none is. `cancel` stops the wait; the promise then never resolves.
 */
export function waitForAnchors(tour: Tour, opts: WaitOptions): { done: Promise<boolean>; cancel: () => void } {
  let timer: ReturnType<typeof setTimeout> | null = null;
  let cancelled = false;
  const done = new Promise<boolean>((resolve) => {
    const started = Date.now();
    let last = '';
    let stableSince = started;
    const look = () => {
      if (cancelled) return;
      const now = Date.now();
      const present = presentSteps(tour.steps);
      const key = present.join(',');
      if (key !== last) {
        last = key;
        stableSince = now;
      }
      const settled = present.length > 0 && now - stableSince >= opts.settleMs;
      if (settled || now - started >= opts.maxMs) {
        resolve(present.length > 0);
        return;
      }
      timer = setTimeout(look, opts.pollMs);
    };
    look();
  });
  return {
    done,
    cancel: () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    },
  };
}

export interface Box {
  top: number;
  left: number;
  width: number;
  height: number;
}

export interface CardPlace {
  top: number;
  left: number;
  side: Exclude<TourPlacement, 'auto'> | 'over';
}

const ORDER: Exclude<TourPlacement, 'auto'>[] = ['bottom', 'top', 'right', 'left'];

function clamp(v: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(v, hi));
}

/**
 * Where the card goes: beside the anchor on the first side with room, in the
 * order of the step's placement, then bottom, top, right, left. When no side
 * has room (an anchor as large as the window), the card sits over the
 * bottom-right corner of the window. The card never leaves the viewport.
 */
export function placeCard(
  anchor: Box,
  card: { width: number; height: number },
  view: { width: number; height: number },
  placement: TourPlacement = 'auto',
  margin = 12,
  gap = 12,
): CardPlace {
  const maxLeft = Math.max(margin, view.width - card.width - margin);
  const maxTop = Math.max(margin, view.height - card.height - margin);
  const cx = anchor.left + anchor.width / 2;
  const cy = anchor.top + anchor.height / 2;
  const sides = placement === 'auto' ? ORDER : [placement, ...ORDER.filter((s) => s !== placement)];
  for (const side of sides) {
    let top: number;
    let left: number;
    let fits: boolean;
    switch (side) {
      case 'bottom':
        top = anchor.top + anchor.height + gap;
        left = clamp(cx - card.width / 2, margin, maxLeft);
        fits = top + card.height <= view.height - margin;
        break;
      case 'top':
        top = anchor.top - gap - card.height;
        left = clamp(cx - card.width / 2, margin, maxLeft);
        fits = top >= margin;
        break;
      case 'right':
        left = anchor.left + anchor.width + gap;
        top = clamp(cy - card.height / 2, margin, maxTop);
        fits = left + card.width <= view.width - margin;
        break;
      case 'left':
        left = anchor.left - gap - card.width;
        top = clamp(cy - card.height / 2, margin, maxTop);
        fits = left >= margin;
        break;
    }
    if (fits) return { top, left, side };
  }
  // No side has room. Take the corner of the window that covers the least of
  // the anchor.
  const corners = [
    { top: maxTop, left: maxLeft },
    { top: maxTop, left: margin },
    { top: margin, left: maxLeft },
    { top: margin, left: margin },
  ];
  const overlap = (c: { top: number; left: number }) => {
    const w = Math.min(c.left + card.width, anchor.left + anchor.width) - Math.max(c.left, anchor.left);
    const h = Math.min(c.top + card.height, anchor.top + anchor.height) - Math.max(c.top, anchor.top);
    return Math.max(0, w) * Math.max(0, h);
  };
  const best = corners.reduce((a, b) => (overlap(b) < overlap(a) ? b : a));
  return { ...best, side: 'over' };
}

/** The elements that scroll and hold `el`, nearest first, and the window. */
export function scrollParents(el: Element): (Element | Window)[] {
  const out: (Element | Window)[] = [];
  for (let n = el.parentElement; n; n = n.parentElement) {
    const oy = getComputedStyle(n).overflowY;
    if ((oy === 'auto' || oy === 'scroll') && n.scrollHeight > n.clientHeight) out.push(n);
  }
  out.push(window);
  return out;
}

/** The spotlight box: the anchor with padding, cut to the viewport. */
export function spotlightBox(anchor: Box, view: { width: number; height: number }, pad = 6): Box {
  const top = Math.max(anchor.top - pad, 2);
  const left = Math.max(anchor.left - pad, 2);
  const bottom = Math.min(anchor.top + anchor.height + pad, view.height - 2);
  const right = Math.min(anchor.left + anchor.width + pad, view.width - 2);
  return { top, left, width: Math.max(0, right - left), height: Math.max(0, bottom - top) };
}
