import { X } from 'lucide-react';
import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { isEditableTarget } from '../lib/triageKeys';
import { type Box, findAnchor, placeCard, presentSteps, scrollParents, spotlightBox } from './anchors';
import type { Tour, TourStep } from './types';

/**
 * How a tour ended. The provider marks the tour seen on `done`, `skipped`,
 * `closed` and `off`. It marks nothing on `interrupted` (a route change) and
 * on `empty` (no step could show).
 */
export type TourEnd = 'done' | 'skipped' | 'closed' | 'off' | 'interrupted' | 'empty';

interface Props {
  tour: Tour;
  onEnd: (how: TourEnd) => void;
  /** The step on screen, for the provider's route rule. */
  onStep?: (step: TourStep) => void;
  /** Where the focus goes on close. The default is the element that held the
   *  focus when the tour opened. */
  returnFocus?: HTMLElement | null;
}

const FOCUSABLE =
  'a[href],button:not([disabled]),textarea:not([disabled]),input:not([disabled]),select:not([disabled]),[tabindex]:not([tabindex="-1"])';

// happy-dom lays nothing out, so a card measures 0 x 0 in a unit test. These
// stand in until a real measure arrives.
const CARD_FALLBACK = { width: 320, height: 200 };

function viewport(): { width: number; height: number } {
  return { width: window.innerWidth, height: window.innerHeight };
}

function reducedMotion(): boolean {
  try {
    return window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
  } catch {
    return false;
  }
}

function sameBox(a: Box | null, b: Box | null): boolean {
  if (a === b) return true;
  if (!a || !b) return false;
  return a.top === b.top && a.left === b.left && a.width === b.width && a.height === b.height;
}

function sameList(a: number[], b: number[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/**
 * The tour engine: a spotlight on the step's anchor and a card beside it.
 *
 * - The page under the overlay takes no click, except the spotlit element on
 *   a step with `tryIt`. Page keys are off while the tour runs.
 * - A step whose anchor is not on the page is skipped. With no step present,
 *   the tour ends at once with `empty`.
 * - Escape closes the tour, Left and Right move, Tab cycles inside the card.
 *   The focus moves to the card on open and back to the opener on close.
 * - The card is a dialog with aria-modal false: the page stays readable. A
 *   live region announces each step.
 * - The overlay is fixed over the page, so the page layout does not move.
 */
export function TourOverlay({ tour, onEnd, onStep, returnFocus }: Props) {
  const [present, setPresent] = useState<number[]>(() => presentSteps(tour.steps));
  const [index, setIndex] = useState<number | null>(() => presentSteps(tour.steps)[0] ?? null);
  const [phase, setPhase] = useState<'step' | 'skip'>('step');
  const [rect, setRect] = useState<Box | null>(null);
  const [view, setView] = useState(viewport);
  const [cardSize, setCardSize] = useState(CARD_FALLBACK);
  const cardRef = useRef<HTMLDivElement>(null);
  const ended = useRef(false);
  const opener = useRef<HTMLElement | null>(
    returnFocus ?? (document.activeElement instanceof HTMLElement ? document.activeElement : null),
  );
  const titleId = useId();
  const bodyId = useId();

  // Where each scrolled container stood before the tour moved it. The page
  // returns there when the tour ends, so a first visit does not end at the
  // bottom of the page.
  const scrolled = useRef(new Map<Element | Window, number>());
  const restoreScroll = useCallback(() => {
    for (const [node, top] of scrolled.current) {
      if (node === window) window.scrollTo({ top, behavior: 'auto' });
      else if ((node as Element).isConnected) (node as Element).scrollTo({ top, behavior: 'auto' });
    }
    scrolled.current.clear();
  }, []);

  const end = useCallback(
    (how: TourEnd) => {
      if (ended.current) return;
      ended.current = true;
      restoreScroll();
      onEnd(how);
    },
    [onEnd, restoreScroll],
  );

  const step = index !== null ? tour.steps[index] : null;

  // No step can show: the tour does not start.
  useEffect(() => {
    if (index === null) end('empty');
  }, [index, end]);

  useEffect(() => {
    if (step) onStep?.(step);
  }, [step, onStep]);

  // Bring the anchor into view when the step changes.
  useEffect(() => {
    if (!step) return;
    const el = findAnchor(step.anchor);
    if (!el || typeof el.scrollIntoView !== 'function') return;
    const r = el.getBoundingClientRect();
    const vh = window.innerHeight;
    if (r.top >= 0 && r.bottom <= vh) return;
    for (const node of scrollParents(el)) {
      if (scrolled.current.has(node)) continue;
      scrolled.current.set(node, node === window ? window.scrollY : (node as Element).scrollTop);
    }
    el.scrollIntoView({
      block: r.height > vh - 120 ? 'start' : 'center',
      inline: 'nearest',
      behavior: reducedMotion() ? 'auto' : 'smooth',
    });
  }, [step]);

  // Follow the anchor: scroll, resize, data that loads late, smooth scroll.
  const measure = useCallback(() => {
    setView((v) => {
      const n = viewport();
      return v.width === n.width && v.height === n.height ? v : n;
    });
    const now = presentSteps(tour.steps);
    setPresent((p) => (sameList(p, now) ? p : now));
    const el = step ? findAnchor(step.anchor) : null;
    if (!el) {
      setRect(null);
      return;
    }
    const r = el.getBoundingClientRect();
    const box = { top: r.top, left: r.left, width: r.width, height: r.height };
    setRect((p) => (sameBox(p, box) ? p : box));
  }, [step, tour.steps]);

  useLayoutEffect(() => {
    measure();
  }, [measure]);

  useEffect(() => {
    let raf = 0;
    const schedule = () => {
      if (raf) return;
      raf = window.requestAnimationFrame(() => {
        raf = 0;
        measure();
      });
    };
    window.addEventListener('resize', schedule);
    window.addEventListener('scroll', schedule, true);
    const t = window.setInterval(measure, 250);
    return () => {
      window.removeEventListener('resize', schedule);
      window.removeEventListener('scroll', schedule, true);
      window.clearInterval(t);
      if (raf) window.cancelAnimationFrame(raf);
    };
  }, [measure]);

  // The anchor of the step on screen left the page: move to the next step
  // that is present, or back to an earlier one. With none, end and mark
  // nothing.
  useEffect(() => {
    if (index === null || present.includes(index)) return;
    if (step && findAnchor(step.anchor)) return;
    const after = present.find((i) => i > index);
    const before = [...present].reverse().find((i) => i < index);
    const to = after ?? before;
    if (to === undefined) end('empty');
    else setIndex(to);
  }, [present, index, step, end]);

  useLayoutEffect(() => {
    const r = cardRef.current?.getBoundingClientRect();
    if (!r || r.width === 0 || r.height === 0) return;
    if (r.width !== cardSize.width || r.height !== cardSize.height) {
      setCardSize({ width: r.width, height: r.height });
    }
  });

  const go = useCallback(
    (dir: 1 | -1) => {
      if (index === null) return;
      const now = presentSteps(tour.steps);
      const to = dir === 1 ? now.find((i) => i > index) : [...now].reverse().find((i) => i < index);
      if (to !== undefined) setIndex(to);
      else if (dir === 1) end('done');
    },
    [index, tour.steps, end],
  );

  // Refs for the window listener, so it does not rebind on each step.
  const goRef = useRef(go);
  goRef.current = go;
  const phaseRef = useRef(phase);
  phaseRef.current = phase;

  // Keys. One capture listener on the window, ahead of every page layer.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const card = cardRef.current;
      const inCard = !!card && e.target instanceof Node && card.contains(e.target);
      if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
        end(phaseRef.current === 'skip' ? 'skipped' : 'closed');
        return;
      }
      if (e.key === 'Tab' && card) {
        const items = Array.from(card.querySelectorAll<HTMLElement>(FOCUSABLE));
        if (items.length === 0) return;
        const first = items[0];
        const last = items[items.length - 1];
        const active = document.activeElement;
        if (!inCard || (e.shiftKey && (active === first || active === card)) || (!e.shiftKey && active === last)) {
          e.preventDefault();
          e.stopPropagation();
          (e.shiftKey ? last : first).focus();
        }
        return;
      }
      if (
        (e.key === 'ArrowRight' || e.key === 'ArrowLeft') &&
        phaseRef.current === 'step' &&
        !e.altKey &&
        !e.ctrlKey &&
        !e.metaKey &&
        !isEditableTarget(e.target as HTMLElement | null)
      ) {
        e.preventDefault();
        e.stopPropagation();
        goRef.current(e.key === 'ArrowRight' ? 1 : -1);
        return;
      }
      // Page keys stay off while the tour runs.
      if (!inCard) e.stopPropagation();
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [end]);

  // The focus moves to the card on open, and on each step when it is
  // elsewhere. It returns to the opener on close.
  useEffect(() => {
    const t = window.setTimeout(() => {
      const card = cardRef.current;
      if (card && !card.contains(document.activeElement)) card.focus({ preventScroll: true });
    }, 0);
    return () => window.clearTimeout(t);
  }, [index, phase]);

  useEffect(
    () => () => {
      const el = opener.current;
      if (el && el.isConnected && typeof el.focus === 'function') el.focus({ preventScroll: true });
    },
    [],
  );

  if (index === null || !step) return null;

  const spot = rect ? spotlightBox(rect, view) : null;
  const place = spot
    ? placeCard(spot, cardSize, view, step.placement ?? 'auto')
    : {
        top: Math.max(12, (view.height - cardSize.height) / 2),
        left: Math.max(12, (view.width - cardSize.width) / 2),
        side: 'over' as const,
      };
  const shown = present.includes(index) ? present : [...present, index].sort((a, b) => a - b);
  const n = shown.indexOf(index) + 1;
  const m = shown.length;
  const hasPrev = shown.some((i) => i < index);
  const isLast = !shown.some((i) => i > index);
  const announce = phase === 'skip' ? 'Tour skipped.' : `Step ${n} of ${m}. ${step.title}.`;
  const motion = 'motion-safe:transition-[top,left,width,height] motion-safe:duration-150';

  return createPortal(
    <div data-tour-overlay={tour.id} className="pointer-events-none fixed inset-0 z-[80]">
      {/* The page takes no click during a step. A "Try it" step leaves a hole
          over the spotlit element. */}
      {step.tryIt && spot && phase === 'step' ? (
        <>
          <div className="pointer-events-auto fixed" style={{ top: 0, left: 0, width: view.width, height: spot.top }} />
          <div
            className="pointer-events-auto fixed"
            style={{ top: spot.top + spot.height, left: 0, width: view.width, height: Math.max(0, view.height - spot.top - spot.height) }}
          />
          <div className="pointer-events-auto fixed" style={{ top: spot.top, left: 0, width: spot.left, height: spot.height }} />
          <div
            className="pointer-events-auto fixed"
            style={{ top: spot.top, left: spot.left + spot.width, width: Math.max(0, view.width - spot.left - spot.width), height: spot.height }}
          />
        </>
      ) : (
        <div data-testid="tour-blocker" className="pointer-events-auto fixed inset-0" />
      )}

      {spot ? (
        <div
          data-testid="tour-spotlight"
          className={`pointer-events-none fixed rounded-[8px] ${motion}`}
          style={{
            top: spot.top,
            left: spot.left,
            width: spot.width,
            height: spot.height,
            boxShadow: '0 0 0 2px #4b8bf5, 0 0 0 9999px rgba(4,6,9,.62)',
          }}
        />
      ) : (
        <div className="pointer-events-none fixed inset-0" style={{ background: 'rgba(4,6,9,.62)' }} />
      )}

      <div
        ref={cardRef}
        role="dialog"
        aria-modal="false"
        aria-labelledby={titleId}
        aria-describedby={bodyId}
        tabIndex={-1}
        data-testid="tour-card"
        data-side={place.side}
        className={`pointer-events-auto fixed w-[320px] max-w-[calc(100vw-24px)] overflow-y-auto rounded-panel border border-border-input bg-surface-card p-4 shadow-dropdown outline-none focus-visible:ring-2 focus-visible:ring-accent ${motion}`}
        style={{ top: place.top, left: place.left, maxHeight: 'calc(100vh - 24px)' }}
      >
        {phase === 'step' ? (
          <>
            <div className="flex items-start gap-2">
              <div className="min-w-0 flex-1">
                <div className="text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">{tour.name} tour</div>
                <h2 id={titleId} className="mt-1 text-[14px] font-semibold text-text">
                  {step.title}
                </h2>
              </div>
              <button
                type="button"
                onClick={() => end('closed')}
                aria-label="Close the tour"
                title="Close the tour"
                className="flex flex-none rounded-control p-1 text-faint hover:text-text"
              >
                <X size={14} />
              </button>
            </div>
            <p id={bodyId} className="mt-2 text-[12.5px] leading-[1.6] text-text-2">
              {step.body}
            </p>
            {step.tryIt && (
              <p className="mt-2 text-[11.5px] leading-[1.5] text-accent">
                The highlighted control works during the tour. Try it.
              </p>
            )}
            <div className="mt-4 flex items-center gap-2">
              <span data-testid="tour-progress" className="font-mono text-[11px] text-faint">
                {n} of {m}
              </span>
              <button
                type="button"
                onClick={() => setPhase('skip')}
                className="rounded-control px-1.5 py-1 text-[12px] text-dim hover:text-text"
              >
                Skip
              </button>
              <div className="flex-1" />
              <button
                type="button"
                aria-disabled={!hasPrev}
                onClick={() => hasPrev && go(-1)}
                className="rounded-control border border-border-2 px-3 py-1.5 text-[12px] font-semibold text-text-2 hover:border-border-strong aria-disabled:cursor-default aria-disabled:opacity-40"
              >
                Back
              </button>
              <button
                type="button"
                onClick={() => go(1)}
                className="rounded-control border border-accent-deep bg-[rgba(75,139,245,.18)] px-3 py-1.5 text-[12px] font-semibold text-[#cfe0ff] hover:border-accent"
              >
                {isLast ? 'Done' : 'Next'}
              </button>
            </div>
            {isLast && (
              <div className="mt-3 border-t border-border-2 pt-2.5">
                <button
                  type="button"
                  onClick={() => end('off')}
                  className="text-[11.5px] text-faint underline-offset-2 hover:text-text hover:underline"
                >
                  Turn off tours
                </button>
              </div>
            )}
          </>
        ) : (
          <>
            <h2 id={titleId} className="text-[14px] font-semibold text-text">
              Tours
            </h2>
            <p id={bodyId} className="mt-2 text-[12.5px] leading-[1.6] text-text-2">
              Each page shows its tour one time, on the first visit. The ? menu in the top bar opens a
              tour at any time.
            </p>
            <div className="mt-4 flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={() => end('off')}
                className="rounded-control border border-border-2 px-3 py-1.5 text-[12px] font-semibold text-text-2 hover:border-border-strong"
              >
                Turn off tours
              </button>
              <button
                type="button"
                onClick={() => end('skipped')}
                className="rounded-control border border-accent-deep bg-[rgba(75,139,245,.18)] px-3 py-1.5 text-[12px] font-semibold text-[#cfe0ff] hover:border-accent"
              >
                Keep tours on
              </button>
            </div>
          </>
        )}
      </div>

      <div className="sr-only" aria-live="polite" data-testid="tour-announce">
        {announce}
      </div>
    </div>,
    document.body,
  );
}
