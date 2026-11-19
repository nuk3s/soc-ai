import { useEffect, useState, useSyncExternalStore } from 'react';

// ---------------------------------------------------------------------------
// The clocks of the top bar (round 4, the owner's decision on UTC times).
//
// Every absolute time of the console reads UTC. The top bar states the time
// now in UTC to the minute, so the analyst reads the clock of the page
// beside the times on it. The analyst can add a second clock for a local
// time: the zone of this browser or another IANA zone.
// ---------------------------------------------------------------------------

/** The second clock: off, the zone of this browser, or another zone. */
export type SecondClock = { mode: 'off' } | { mode: 'browser' } | { mode: 'zone'; zone: string };

export const SECOND_CLOCK_OFF: SecondClock = { mode: 'off' };

/** True when the browser knows `zone` as an IANA zone. */
export function isTimeZone(zone: string): boolean {
  if (!zone) return false;
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: zone });
    return true;
  } catch {
    return false;
  }
}

/** The IANA zone of this browser, "America/Chicago". UTC when the browser
 *  names none. */
export function browserTimeZone(): string {
  try {
    const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    return zone && isTimeZone(zone) ? zone : 'UTC';
  } catch {
    return 'UTC';
  }
}

/** The zones of the list when the browser has no `Intl.supportedValuesOf`. */
export const FALLBACK_ZONES: readonly string[] = [
  'UTC',
  'America/Anchorage',
  'America/Chicago',
  'America/Denver',
  'America/Los_Angeles',
  'America/New_York',
  'America/Sao_Paulo',
  'America/Toronto',
  'Europe/Berlin',
  'Europe/London',
  'Europe/Madrid',
  'Europe/Moscow',
  'Europe/Paris',
  'Africa/Johannesburg',
  'Africa/Lagos',
  'Asia/Dubai',
  'Asia/Kolkata',
  'Asia/Shanghai',
  'Asia/Singapore',
  'Asia/Tokyo',
  'Australia/Sydney',
  'Pacific/Auckland',
  'Pacific/Honolulu',
];

/** The IANA zones that the analyst can pick, sorted. The list of the browser
 *  when it has one, else a short list. The zone of this browser is always on
 *  the list, and each zone on the list is a zone that the browser knows. */
export function zoneList(): string[] {
  let list: string[] = [];
  try {
    const supported = (Intl as { supportedValuesOf?: (key: string) => string[] }).supportedValuesOf;
    if (typeof supported === 'function') list = supported('timeZone');
  } catch {
    list = [];
  }
  if (!Array.isArray(list) || list.length === 0) list = [...FALLBACK_ZONES];
  const all = new Set([...list, 'UTC', browserTimeZone()]);
  return [...all].filter(isTimeZone).sort((a, b) => a.localeCompare(b));
}

const zoneWords = (s: string) => s.toLowerCase().replace(/[\s_]+/g, ' ').trim();

/** The zones that hold the filter text. "new york" finds America/New_York. */
export function filterZones(list: readonly string[], text: string): string[] {
  const want = zoneWords(text);
  if (!want) return [...list];
  return list.filter((zone) => zoneWords(zone).includes(want));
}

/** The zone that the second clock states, or null when it is off. */
export function secondClockZone(choice: SecondClock, browser = browserTimeZone()): string | null {
  if (choice.mode === 'browser') return browser;
  if (choice.mode === 'zone') return choice.zone;
  return null;
}

/** The second clock in `zone` at `at`.
 *
 *  `text` is the time with the short name of the zone that Intl gives,
 *  "08:32 CST". When the date in the zone is not the UTC date, the weekday
 *  comes first, "Wed 18:32 CST", so the analyst sees the day change. `title`
 *  states the full date, the time and the IANA zone. */
export function zoneClock(at: Date, zone: string): { text: string; title: string; short: string } {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: zone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    weekday: 'short',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
    timeZoneName: 'short',
  }).formatToParts(at);
  const get = (type: Intl.DateTimeFormatPartTypes): string => parts.find((p) => p.type === type)?.value ?? '';
  const date = `${get('year')}-${get('month')}-${get('day')}`;
  const time = `${get('hour')}:${get('minute')}`;
  const short = get('timeZoneName') || zone;
  const day = date === at.toISOString().slice(0, 10) ? '' : `${get('weekday')} `;
  return { text: `${day}${time} ${short}`, title: `${date} ${time} ${short}, ${zone}`, short };
}

// ---------------------------------------------------------------------------
// The choice of the second clock: one value for the console, read with
// useSyncExternalStore, so each clock and each page follows a change.
//
// This browser keeps the choice in localStorage under one key, so it stays
// after a reload. A bad stored value reads as "Off", and storage that is off
// or full keeps the choice for this tab only. A second tab of the console
// follows a change through the `storage` event.
// ---------------------------------------------------------------------------

/** The localStorage key of the second clock. */
export const SECOND_CLOCK_KEY = 'soc-ai.topbar.second-clock';

/** The stored choice from its raw text. Any value that is not a known
 *  choice reads as "Off": no text, bad JSON, an unknown mode, or a zone that
 *  this browser does not know. */
export function parseSecondClock(raw: string | null | undefined): SecondClock {
  if (!raw) return SECOND_CLOCK_OFF;
  try {
    const value = JSON.parse(raw) as { mode?: unknown; zone?: unknown } | null;
    if (value?.mode === 'browser') return { mode: 'browser' };
    if (value?.mode === 'zone' && typeof value.zone === 'string' && isTimeZone(value.zone)) {
      return { mode: 'zone', zone: value.zone };
    }
  } catch {
    return SECOND_CLOCK_OFF;
  }
  return SECOND_CLOCK_OFF;
}

function readStored(): SecondClock {
  try {
    return parseSecondClock(localStorage.getItem(SECOND_CLOCK_KEY));
  } catch {
    return SECOND_CLOCK_OFF;
  }
}

function writeStored(choice: SecondClock): void {
  try {
    if (choice.mode === 'off') localStorage.removeItem(SECOND_CLOCK_KEY);
    else localStorage.setItem(SECOND_CLOCK_KEY, JSON.stringify({ version: 1, ...choice }));
  } catch {
    // Storage is off or full. The choice holds for this tab.
  }
}

// Null until the first read, so the module reads storage when a clock first
// asks, not on import.
let secondClock: SecondClock | null = null;
const listeners = new Set<() => void>();

function sameChoice(a: SecondClock, b: SecondClock): boolean {
  if (a.mode !== b.mode) return false;
  return a.mode !== 'zone' || (b.mode === 'zone' && a.zone === b.zone);
}

function publish(next: SecondClock): void {
  if (secondClock !== null && sameChoice(secondClock, next)) return;
  secondClock = next;
  for (const listener of [...listeners]) listener();
}

/** The choice of the second clock now. */
export function getSecondClock(): SecondClock {
  if (secondClock === null) secondClock = readStored();
  return secondClock;
}

/** Set the second clock and keep it for this browser. A zone that the
 *  browser does not know reads as off. */
export function setSecondClock(next: SecondClock): void {
  const choice = next.mode === 'zone' && !isTimeZone(next.zone) ? SECOND_CLOCK_OFF : next;
  writeStored(choice);
  publish(choice);
}

/** Read the stored choice again: after a change in another tab, or as a
 *  reload of the page reads it. */
export function reloadSecondClock(): void {
  publish(readStored());
}

function onStorage(e: StorageEvent): void {
  // A null key is a clear of the whole storage.
  if (e.key === null || e.key === SECOND_CLOCK_KEY) reloadSecondClock();
}

export function subscribeSecondClock(listener: () => void): () => void {
  listeners.add(listener);
  if (listeners.size === 1) window.addEventListener('storage', onStorage);
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0) window.removeEventListener('storage', onStorage);
  };
}

/** The choice of the second clock, for a component. */
export function useSecondClock(): SecondClock {
  return useSyncExternalStore(subscribeSecondClock, getSecondClock, () => SECOND_CLOCK_OFF);
}

/** The local time zone of the console: the zone that the analyst picked for
 *  the second clock. Undefined for "Off" and for "Local time of this
 *  browser": a tooltip then states the zone of the browser, as before. */
export function consoleTimeZone(): string | undefined {
  const choice = getSecondClock();
  return choice.mode === 'zone' ? choice.zone : undefined;
}

/** The local time zone of the console, for a component. A change of the
 *  second clock renders the component again. */
export function useConsoleTimeZone(): string | undefined {
  return useSyncExternalStore(subscribeSecondClock, consoleTimeZone, () => undefined);
}

/** The time of day in UTC to the minute: "14:32 UTC". */
export function utcClock(at: Date): string {
  return `${at.toISOString().slice(11, 16)} UTC`;
}

/** The tooltip of the UTC clock, the full date and time: "2026-11-19 14:32 UTC". */
export function utcClockTitle(at: Date): string {
  const iso = at.toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;
}

/** The `dateTime` of a clock, to the minute: "2026-11-19T14:32Z". */
export function minuteIso(at: Date): string {
  return `${at.toISOString().slice(0, 16)}Z`;
}

/** The time now, renewed on each minute.
 *
 *  The timer aims at the start of the next minute and aims again after each
 *  tick, so the clock never drifts off the minute. A tab in the background
 *  gets slow timers, so the hook reads the time again when the tab shows. */
export function useMinuteNow(): Date {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const arm = () => {
      clearTimeout(timer);
      timer = setTimeout(
        () => {
          setNow(new Date());
          arm();
        },
        60_000 - (Date.now() % 60_000),
      );
    };
    const onVisible = () => {
      if (document.hidden) return;
      setNow(new Date());
      arm();
    };
    arm();
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      clearTimeout(timer);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, []);
  return now;
}
