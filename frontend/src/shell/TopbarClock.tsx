import { Check } from 'lucide-react';
import { useEffect, useId, useMemo, useRef, useState } from 'react';
import type { FocusEvent as ReactFocusEvent, KeyboardEvent as ReactKeyboardEvent } from 'react';
import {
  browserTimeZone,
  filterZones,
  minuteIso,
  secondClockZone,
  setSecondClock,
  useMinuteNow,
  useSecondClock,
  utcClock,
  utcClockTitle,
  zoneClock,
  zoneList,
} from '../lib/clock';

type Mode = 'off' | 'browser' | 'zone';

/** The hint of "Another zone". */
export const ZONE_HINT = 'The tooltips of the console state the local time in this zone.';

/**
 * The clocks of the top bar: the time now in UTC to the minute, "14:32 UTC",
 * and a second clock for a local time when the analyst sets one, "08:32 CST".
 *
 * Every absolute time of the console reads UTC, and the UTC clock is the time
 * of the page. The clocks are text of the bar in the weight and the colour of
 * the other secondary text, with no box. The tooltip of each clock states the
 * full date and time. The second clock states its weekday when its date is
 * not the UTC date, and its tooltip names the IANA zone.
 *
 * A press on the clocks opens the "Second clock" panel. It follows the bell:
 * Escape closes it and gives the focus back to the clocks, and a click on the
 * page closes it. The focus goes to the checked choice when it opens, and it
 * closes when the focus leaves it.
 *
 * No live region holds the clocks. A screen reader reads them when the
 * analyst goes to them, and never hears a tick each minute.
 */
export function TopbarClock() {
  const now = useMinuteNow();
  const choice = useSecondClock();
  const browser = useMemo(browserTimeZone, []);
  const zone = secondClockZone(choice, browser);
  const second = zone ? zoneClock(now, zone) : null;

  const [open, setOpen] = useState(false);
  // "Another zone" is checked and its list shows. The choice changes when the
  // analyst picks a zone of the list.
  const [picking, setPicking] = useState(false);
  const [filter, setFilter] = useState('');
  const zones = useMemo(() => (open ? zoneList() : []), [open]);
  const shown = useMemo(() => filterZones(zones, filter), [zones, filter]);
  const checked: Mode = picking ? 'zone' : choice.mode;

  const wrapRef = useRef<HTMLDivElement>(null);
  const btnRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const filterRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const panelId = useId();
  const headId = useId();
  const group = useId();
  const hintId = useId();

  const close = (refocus: boolean) => {
    setOpen(false);
    if (refocus) btnRef.current?.focus();
  };

  const toggle = () => {
    if (!open) {
      setPicking(choice.mode === 'zone');
      setFilter('');
    }
    setOpen((o) => !o);
  };

  useEffect(() => {
    if (!open) return;
    panelRef.current?.querySelector<HTMLInputElement>('input[type="radio"]:checked')?.focus();
    const onDown = (e: MouseEvent) => {
      if (e.target instanceof Node && wrapRef.current?.contains(e.target)) return;
      setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      e.preventDefault();
      setOpen(false);
      btnRef.current?.focus();
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  // Tab out of the panel closes it, the rule of the Help menu. A click on a
  // part of the panel that takes no focus is no exit.
  const onBlur = (e: ReactFocusEvent<HTMLDivElement>) => {
    const next = e.relatedTarget;
    if (open && next instanceof Node && !wrapRef.current?.contains(next)) setOpen(false);
  };

  const choose = (mode: Mode) => {
    if (mode === 'zone') {
      setPicking(true);
      return;
    }
    setPicking(false);
    setSecondClock({ mode });
  };

  const pick = (z: string) => {
    setSecondClock({ mode: 'zone', zone: z });
    close(true);
  };

  const zoneButtons = (): HTMLButtonElement[] =>
    Array.from(listRef.current?.querySelectorAll<HTMLButtonElement>('button') ?? []);

  const onFilterKey = (e: ReactKeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      zoneButtons()[0]?.focus();
    } else if (e.key === 'Enter' && shown.length > 0) {
      e.preventDefault();
      pick(shown[0]);
    }
  };

  const onListKey = (e: ReactKeyboardEvent<HTMLDivElement>) => {
    const list = zoneButtons();
    const at = list.indexOf(document.activeElement as HTMLButtonElement);
    const move = (i: number) => {
      e.preventDefault();
      if (i < 0) filterRef.current?.focus();
      else list[Math.min(i, list.length - 1)]?.focus();
    };
    if (e.key === 'ArrowDown') move(at + 1);
    else if (e.key === 'ArrowUp') move(at - 1);
    else if (e.key === 'Home') move(0);
    else if (e.key === 'End') move(list.length - 1);
  };

  // The hint sits outside the label, so the name of the choice stays short
  // and a screen reader reads the hint after it.
  const radio = (mode: Mode, label: string, beside?: string | null, hint?: string) => (
    <div className="rounded-control px-2.5 py-2 hover:bg-[#141b25]">
      <label className="flex cursor-pointer items-start gap-2">
        <input
          type="radio"
          name={group}
          value={mode}
          checked={checked === mode}
          onChange={() => choose(mode)}
          aria-describedby={hint ? hintId : undefined}
          className="mt-[3px] flex-none accent-[#4b8bf5]"
        />
        <span className="min-w-0 flex-1 text-[12.5px] text-text-2">
          {label}
          {beside && (
            <span className="mt-0.5 block break-words font-mono text-[11px] text-faint">{beside}</span>
          )}
        </span>
      </label>
      {hint && (
        <div id={hintId} className="ml-[21px] mt-0.5 text-[11px] leading-[1.4] text-faint">
          {hint}
        </div>
      )}
    </div>
  );

  return (
    <div ref={wrapRef} data-testid="topbar-clock" className="relative flex flex-none items-center" onBlur={onBlur}>
      <button
        ref={btnRef}
        type="button"
        data-testid="topbar-clock-button"
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls={open ? panelId : undefined}
        onClick={toggle}
        className="flex items-center gap-2 whitespace-nowrap rounded-control font-mono text-[11.5px] text-dim outline-none hover:text-text focus-visible:ring-1 focus-visible:ring-accent"
      >
        <time dateTime={minuteIso(now)} title={utcClockTitle(now)} data-testid="topbar-clock-utc">
          {utcClock(now)}
        </time>
        {second && (
          <time
            dateTime={minuteIso(now)}
            title={second.title}
            data-testid="topbar-clock-second"
            className="topbar-clock-second"
          >
            {second.text}
          </time>
        )}
      </button>
      {open && (
        <div
          ref={panelRef}
          id={panelId}
          role="dialog"
          aria-labelledby={headId}
          className="absolute right-0 top-[42px] z-[33] w-[288px] animate-fadeUp rounded-panel border border-border-input bg-surface-card p-1.5 shadow-dropdown"
        >
          <div id={headId} className="px-2.5 pb-1.5 pt-1.5 text-[13px] font-semibold text-text">
            Second clock
          </div>
          {second && zone && (
            <div data-testid="clock-menu-second" className="break-words px-2.5 pb-1.5 font-mono text-[11.5px] text-dim">
              <time dateTime={minuteIso(now)} title={second.title}>
                {second.text}
              </time>{' '}
              <span className="text-faint">· {zone}</span>
            </div>
          )}
          <div role="radiogroup" aria-labelledby={headId}>
            {radio('off', 'Off')}
            {radio('browser', 'Local time of this browser', browser)}
            {/* The picked zone is the local time of the console: each
                tooltip of a time states it (round 4, C4). */}
            {radio('zone', 'Another zone', choice.mode === 'zone' ? choice.zone : null, ZONE_HINT)}
          </div>
          {checked === 'zone' && (
            <div className="mt-1 border-t border-border-2 px-1 pt-2">
              <input
                ref={filterRef}
                type="text"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                onKeyDown={onFilterKey}
                aria-label="Filter the zones"
                placeholder="Filter the zones"
                data-testid="clock-zone-filter"
                className="w-full rounded-control border border-border-input bg-surface-1 px-2 py-1.5 text-[12.5px] text-text outline-none placeholder:text-faint focus:border-accent"
              />
              <div
                ref={listRef}
                role="group"
                aria-label="Zones"
                onKeyDown={onListKey}
                data-testid="clock-zone-list"
                className="mt-1.5 max-h-[220px] overflow-y-auto"
              >
                {shown.length === 0 && (
                  <div className="px-1.5 py-2 text-[12px] text-faint">No zone holds this text.</div>
                )}
                {shown.map((z) => {
                  const current = choice.mode === 'zone' && choice.zone === z;
                  return (
                    <button
                      key={z}
                      type="button"
                      aria-pressed={current}
                      onClick={() => pick(z)}
                      className="flex w-full items-center gap-2 rounded-control px-1.5 py-1 text-left font-mono text-[11.5px] text-text-2 outline-none hover:bg-[#141b25] focus:bg-[#141b25]"
                    >
                      <span className="min-w-0 flex-1 break-words">{z}</span>
                      {current && (
                        <span className="flex flex-none text-accent" aria-hidden="true">
                          <Check size={12} />
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
