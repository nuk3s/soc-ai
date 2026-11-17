import { useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';

/** The space between the tooltip and the edge of the window. */
const MARGIN = 8;

/**
 * The tooltip of a mark of a campaign graphic.
 *
 * The tooltip draws on the document body in window coordinates. A panel that
 * scrolls or clips its content does not cut it. The tooltip stays in the
 * window: it moves left at the right edge, and it opens above its mark when
 * the room below is too small.
 */
export function HoverTip({
  container,
  x,
  y,
  width,
  gap,
  rise = 0,
  testId,
  children,
}: {
  /** The graphic. `x` and `y` are relative to its top left corner. */
  container: HTMLElement | null;
  /** The left edge that the tooltip asks for. */
  x: number;
  /** The bottom of the mark, or the pointer. */
  y: number;
  width: number;
  /** The space between the mark and the tooltip. */
  gap: number;
  /** The height of the mark. The tooltip clears it when it opens above. */
  rise?: number;
  testId: string;
  children: ReactNode;
}) {
  const tip = useRef<HTMLDivElement>(null);
  const [at, setAt] = useState<{ left: number; top: number } | null>(null);

  // No dependency list: the content sets the height, and it changes with the mark.
  useLayoutEffect(() => {
    const place = () => {
      const box = container?.getBoundingClientRect();
      const height = tip.current?.offsetHeight ?? 0;
      const view = document.documentElement;
      const anchor = (box?.top ?? 0) + y;
      const left = Math.max(MARGIN, Math.min((box?.left ?? 0) + x, view.clientWidth - width - MARGIN));
      const below = anchor + gap;
      const fits = below + height + MARGIN <= view.clientHeight;
      const top = fits ? below : Math.max(MARGIN, anchor - rise - gap - height);
      setAt((prev) => (prev && prev.left === left && prev.top === top ? prev : { left, top }));
    };
    place();
    window.addEventListener('scroll', place, true);
    window.addEventListener('resize', place);
    return () => {
      window.removeEventListener('scroll', place, true);
      window.removeEventListener('resize', place);
    };
  });

  return createPortal(
    <div
      ref={tip}
      data-testid={testId}
      role="status"
      className="pointer-events-none fixed z-[35] rounded-card border border-border-strong bg-surface-3 px-3 py-2 text-[11.5px] shadow-lg"
      style={{ width, left: at?.left ?? 0, top: at?.top ?? 0, visibility: at ? 'visible' : 'hidden' }}
    >
      {children}
    </div>,
    document.body,
  );
}
