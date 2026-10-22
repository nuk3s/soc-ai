import { ExternalLink, HelpCircle } from 'lucide-react';
import { useEffect, useId, useRef, useState } from 'react';
import type { KeyboardEvent as ReactKeyboardEvent, ReactNode } from 'react';
import { GUIDE_URL } from '../shell/pages';
import { useShell } from '../shell/ShellContext';
import { useTours } from './TourProvider';

/**
 * The "?" in the top bar: a menu of help.
 *
 * - Tour this page: the tour of the current page. Off on a page with no tour.
 * - Tour soc-ai from the start: the welcome tour again. Page tours keep their state.
 * - Keyboard shortcuts: the shortcut sheet.
 * - Open the guide: the guide in a new tab.
 * - Turn on tours: shown while the operator has turned the tours off.
 *
 * The menu works in an automated browser too, so a check can open a tour on
 * purpose. It is a menu button: Enter, Space and the arrow keys open it, the
 * arrow keys, Home and End move, Escape closes it and returns the focus to the
 * button, and Tab closes it.
 */
export function HelpMenu() {
  const tours = useTours();
  const { openShortcuts } = useShell();
  const [open, setOpen] = useState(false);
  const btnRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const menuId = useId();
  // Where the first focus goes when the menu opens: the first or the last item.
  const focusOnOpen = useRef<'first' | 'last'>('first');

  const items = (): HTMLElement[] =>
    Array.from(menuRef.current?.querySelectorAll<HTMLElement>('[role="menuitem"]') ?? []);

  const close = (refocus: boolean) => {
    setOpen(false);
    if (refocus) btnRef.current?.focus();
  };

  // Read the tour state when the menu opens, so "Turn on tours" shows when the
  // tours are off.
  const ensureLoaded = tours?.ensureLoaded;
  useEffect(() => {
    if (open) ensureLoaded?.();
  }, [open, ensureLoaded]);

  useEffect(() => {
    if (!open) return;
    const list = items();
    (focusOnOpen.current === 'last' ? list[list.length - 1] : list[0])?.focus();
    const onDown = (e: MouseEvent) => {
      const t = e.target as Node | null;
      if (t && (menuRef.current?.contains(t) || btnRef.current?.contains(t))) return;
      setOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    return () => document.removeEventListener('mousedown', onDown);
  }, [open]);

  const onMenuKey = (e: ReactKeyboardEvent<HTMLDivElement>) => {
    const list = items();
    const at = list.indexOf(document.activeElement as HTMLElement);
    const move = (i: number) => {
      e.preventDefault();
      list[(i + list.length) % list.length]?.focus();
    };
    switch (e.key) {
      case 'ArrowDown':
        move(at + 1);
        break;
      case 'ArrowUp':
        move(at - 1);
        break;
      case 'Home':
        move(0);
        break;
      case 'End':
        move(list.length - 1);
        break;
      case 'Escape':
        e.preventDefault();
        e.stopPropagation();
        close(true);
        break;
      case 'Tab':
        close(false);
        break;
    }
  };

  const onButtonKey = (e: ReactKeyboardEvent<HTMLButtonElement>) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      focusOnOpen.current = e.key === 'ArrowUp' ? 'last' : 'first';
      setOpen(true);
    }
  };

  const run = (fn: () => void) => () => {
    setOpen(false);
    fn();
  };

  const pageTour = tours?.pageTour;
  const toursOff = tours?.state?.off === true;

  return (
    <div className="relative flex-none">
      <button
        ref={btnRef}
        type="button"
        data-tour="help"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        aria-label="Help"
        title="Help: tours, keyboard shortcuts and the guide"
        onClick={() => {
          focusOnOpen.current = 'first';
          setOpen((o) => !o);
        }}
        onKeyDown={onButtonKey}
        className="flex h-[34px] w-[34px] items-center justify-center rounded-control border border-border-2 text-dim hover:border-border-strong hover:text-text"
      >
        <HelpCircle size={16} />
      </button>
      {open && (
        <div
          ref={menuRef}
          id={menuId}
          role="menu"
          aria-label="Help"
          onKeyDown={onMenuKey}
          className="absolute right-0 top-[42px] z-[33] w-[248px] animate-fadeUp rounded-panel border border-border-input bg-surface-card p-1.5 shadow-dropdown"
        >
          {tours && (
            <>
              <MenuItem
                disabled={!pageTour}
                hint={pageTour ? undefined : 'This page has no tour.'}
                onSelect={run(() => tours.startPageTour(btnRef.current))}
              >
                Tour this page
              </MenuItem>
              <MenuItem
                hint="The welcome tour starts again."
                onSelect={run(() => tours.startFromBeginning(btnRef.current))}
              >
                Tour soc-ai from the start
              </MenuItem>
            </>
          )}
          <MenuItem onSelect={run(openShortcuts)}>Keyboard shortcuts</MenuItem>
          <a
            role="menuitem"
            tabIndex={-1}
            href={GUIDE_URL}
            target="_blank"
            rel="noopener noreferrer"
            onClick={() => setOpen(false)}
            className="flex w-full items-center gap-2 rounded-control px-2.5 py-2 text-left text-[12.5px] text-text-2 outline-none hover:bg-[#141b25] focus:bg-[#141b25]"
          >
            <span className="flex-1">Open the guide</span>
            <span className="flex text-faint" aria-hidden="true">
              <ExternalLink size={12} />
            </span>
          </a>
          {tours && toursOff && (
            <div className="mt-1 border-t border-border-2 pt-1">
              <MenuItem hint="Tours are off." onSelect={run(() => tours.setOff(false))}>
                Turn on tours
              </MenuItem>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function MenuItem({
  children,
  hint,
  disabled = false,
  onSelect,
}: {
  children: ReactNode;
  hint?: string;
  disabled?: boolean;
  onSelect: () => void;
}) {
  // The label names the item. The hint describes it, so a screen reader
  // reads the name first and the hint after.
  const labelId = useId();
  const hintId = useId();
  return (
    <button
      type="button"
      role="menuitem"
      tabIndex={-1}
      aria-disabled={disabled || undefined}
      aria-labelledby={labelId}
      aria-describedby={hint ? hintId : undefined}
      onClick={disabled ? undefined : onSelect}
      className="flex w-full flex-col items-start rounded-control px-2.5 py-2 text-left outline-none hover:bg-[#141b25] focus:bg-[#141b25] aria-disabled:cursor-default"
    >
      <span id={labelId} className={`text-[12.5px] ${disabled ? 'text-faint' : 'text-text-2'}`}>
        {children}
      </span>
      {hint && (
        <span id={hintId} className="mt-0.5 text-[11px] leading-[1.4] text-faint">
          {hint}
        </span>
      )}
    </button>
  );
}
