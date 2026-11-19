import type { CustomRange } from '../components/TimeRangeFilter';
import { consoleTimeZone } from './clock';

// Shared time-range helpers so every page filters by the same presets the
// TimeRangeFilter offers (and the backend's TIME_RANGES). Presets are
// "<n><unit>" where unit is one of m, h, d; 'custom' uses an explicit from/to.

const UNIT_MS: Record<string, number> = { m: 60_000, h: 3_600_000, d: 86_400_000 };

/** Resolve a range preset (or custom) to an inclusive [from, to] in epoch ms. */
export function rangeBounds(range: string, custom?: CustomRange | null, now = Date.now()): {
  from: number;
  to: number;
} {
  if (range === 'custom' && custom?.from && custom?.to) {
    return { from: new Date(custom.from).getTime(), to: new Date(custom.to).getTime() };
  }
  const m = /^(\d+)([mhd])$/.exec(range);
  const span = m ? Number(m[1]) * (UNIT_MS[m[2]] ?? UNIT_MS.h) : 24 * UNIT_MS.h;
  return { from: now - span, to: now };
}

/** True when an ISO timestamp falls within the selected range. Empty ts = keep. */
export function inRange(ts: string | undefined, range: string, custom?: CustomRange | null): boolean {
  if (!ts) return true;
  const t = new Date(ts).getTime();
  if (Number.isNaN(t)) return true;
  const { from, to } = rangeBounds(range, custom);
  return t >= from && t <= to;
}

// An ISO time that names its zone: "Z" or an offset such as "+02:00".
const ZONED = /(?:Z|[+-]\d\d:?\d\d)$/i;

/**
 * A custom-window bound as the server reads it: an ISO time with its zone.
 *
 * The picker gives a wall time in the browser zone ("2026-10-08T00:00"). The
 * investigation reads sent it as UTC, and the alert reads sent it bare, which
 * the server read in `so_timezone`. With the browser and the grid in two
 * zones, one custom window counted alerts and investigations over two spans
 * six hours apart (dogfood 2026-10-19, R1-D8). Every read now sends the UTC
 * form of the browser's wall time. A bound that already names its zone, or
 * one that does not parse, goes as it is: the server refuses a bad one.
 */
export function wireBound(value: string): string {
  if (ZONED.test(value.trim())) return value;
  const t = new Date(value).getTime();
  return Number.isNaN(t) ? value : new Date(t).toISOString();
}

const PRESET = /^\d+[mhd]$/;

/**
 * The page window a URL names: `?range=7d`, or `?range=custom&from=…&to=…`.
 * Anything else is `fallback`. A page that keeps its window in the URL opens
 * on the same window after Back and from a link (R1-D22).
 */
export function windowFromSearch(
  search: URLSearchParams | string,
  fallback = '24h',
): { range: string; custom: CustomRange | null } {
  const p = typeof search === 'string' ? new URLSearchParams(search) : search;
  const range = p.get('range') ?? '';
  if (range === 'custom') {
    const from = p.get('from') ?? '';
    const to = p.get('to') ?? '';
    if (from && to && !Number.isNaN(new Date(from).getTime()) && !Number.isNaN(new Date(to).getTime())) {
      return { range, custom: { from, to } };
    }
    return { range: fallback, custom: null };
  }
  return { range: PRESET.test(range) ? range : fallback, custom: null };
}

/** The URL params of a page window: the inverse of `windowFromSearch`. */
export function windowParams(range: string, custom: CustomRange | null): Record<string, string> {
  if (range === 'custom' && custom) return { range, from: custom.from, to: custom.to };
  return { range };
}

/** Convert the selected range to the hunts API's `since`/`until` ISO params.
 * Presets ("last 24h") send only `since` — the upper edge is implicitly "now",
 * and sending a client-clock `until` could exclude a row the server creates a
 * moment later (clock skew). Custom sends both edges (inclusive, matching
 * `inRange`'s [from, to]). */
export function rangeToSinceUntil(
  range: string,
  custom?: CustomRange | null,
  now = Date.now(),
): { since: string; until?: string } {
  if (range === 'custom' && custom?.from && custom?.to) {
    return { since: wireBound(custom.from), until: wireBound(custom.to) };
  }
  const { from } = rangeBounds(range, custom, now);
  return { since: new Date(from).toISOString() };
}

// ---------------------------------------------------------------------------
// The one time formatter.
//
// Every screen that prints a time reads it from here. The console had three
// date formats, an unlabelled UTC timeline beside an unlabelled local one, and
// "4d", "4d ago" and "27h ago" on one page.
//
//   ago(iso)              "now", "8m ago", "4h ago", "4d ago"
//   absoluteTime(iso)     "2026-10-01 08:18 EDT", in the local zone of the
//                         console: the browser zone or the picked zone
//   formatDuration(199)   "3m 19s"
//   timeLabel(iso)        { text: ago, title: absoluteTime } for a cell
//   utcStamp(iso)         "2026-10-05 04:12 UTC", or with { seconds: true }
//                         "2026-10-05 04:12:09 UTC"
//   utcWindow(a, b)       "2026-10-05 04:00 to 05:00 UTC"
//
// A list states the relative time and puts the absolute time in the title.
// A line that dates a record states the absolute time with its zone.
// ---------------------------------------------------------------------------

/** Relative age for a wire timestamp ("now", "8m ago", "4h ago", "3d ago",
 * "2mo ago", "2y ago").
 *
 * Hours stop at 24: a day and more reads in days. "27h ago" sat beside "3d
 * ago" on one page and the reader had to convert one of them. Days stop at 60
 * and months at 24, so a host header does not read "first seen 395d ago". The
 * host header, the facts and the entity page read this rule too: they had a
 * second one, and one instant read "30h ago" and "1d ago" (dogfood round 2,
 * R4-D15). Every unit floors.
 *
 * A list or a KPI strip is scanned for "is this recent?", which a wall-clock
 * time answers only after the reader does the subtraction; the absolute time
 * rides in a `title` for when the answer is "not recent". `null` is 'never' —
 * an ISO field that is null means the thing has not happened, not that its date
 * is missing. */
export function ago(iso: string | number | null | undefined, now = Date.now()): string {
  if (iso == null || iso === '') return 'never';
  const ms = now - new Date(iso).getTime();
  if (!Number.isFinite(ms)) return '—';
  if (ms < 60_000) return 'now';
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = ms / 86_400_000;
  if (days < 60) return `${Math.floor(days)}d ago`;
  const months = days / 30.44;
  if (months < 24) return `${Math.floor(months)}mo ago`;
  return `${Math.floor(days / 365.25)}y ago`;
}

/** An absolute time in the local zone of the console, with the zone named:
 *  "2026-10-01 08:18 EDT". Year first, so two dates sort as they read. An
 *  empty value reads as an empty string, and an unparseable one as itself.
 *
 *  This is the one helper that gives the local time of a tooltip. The local
 *  zone is the zone of the browser, or the zone that the analyst picked for
 *  the second clock of the top bar (round 4, C4). `timeZone` names a zone
 *  for a caller that needs one. */
export function absoluteTime(
  iso: string | number | null | undefined,
  opts: { timeZone?: string } = {},
): string {
  if (iso == null || iso === '') return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  const timeZone = opts.timeZone ?? consoleTimeZone();
  const parts = new Intl.DateTimeFormat('en-US', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
    timeZoneName: 'short',
    ...(timeZone ? { timeZone } : {}),
  }).formatToParts(d);
  const get = (type: Intl.DateTimeFormatPartTypes): string =>
    parts.find((p) => p.type === type)?.value ?? '';
  return `${get('year')}-${get('month')}-${get('day')} ${get('hour')}:${get('minute')} ${get('timeZoneName')}`.trim();
}

/** A span of time: "42s", "3m 19s", "1h 04m", "2d 3h". Seconds in. A
 *  negative or missing span reads as an empty string. */
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null || !Number.isFinite(seconds) || seconds < 0) return '';
  const s = Math.round(seconds);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  if (s < 86_400) return `${Math.floor(s / 3600)}h ${String(Math.floor((s % 3600) / 60)).padStart(2, '0')}m`;
  return `${Math.floor(s / 86_400)}d ${Math.floor((s % 86_400) / 3600)}h`;
}

/** A relative label the server wrote ("4d", "9m", "now") in the shared form
 *  ("4d ago"). Use it only where the row carries no timestamp to pass to `ago`. */
export function agoFromLabel(label: string | null | undefined): string {
  if (!label) return '';
  return /^\d+[smhd]$/.test(label.trim()) ? `${label.trim()} ago` : label;
}

/** The relative time for a cell and the absolute time for its title. The
 *  title states the time in UTC and the local time with its zone. */
export function timeLabel(
  iso: string | number | null | undefined,
  now = Date.now(),
): { text: string; title: string } {
  return { text: ago(iso, now), title: timeTitle(iso) };
}

/** An absolute time as a page shows it: UTC with the zone named, to the
 *  second, "2026-07-06 18:23:05 UTC". It is the form of {@link utcStamp} on
 *  the investigation page. An empty value reads as '—', and an unparseable
 *  one as itself.
 *
 *  It gave the local time with no zone. The host rows, the entity rows and
 *  other lists read a local time beside the UTC times of the investigation
 *  page, and nothing said which clock they read (round 3, T3). The local
 *  time with its zone goes in the tooltip: {@link localTitle}. */
export function absTime(iso?: string | null): string {
  if (!iso) return '—';
  return utcStamp(iso, { seconds: true });
}

/** The tooltip of an absolute time: the local time with its zone, "Local
 *  time: 2026-07-06 14:23 EDT". An empty or unparseable value gives no
 *  tooltip. `timeZone` is for tests. */
export function localTitle(
  iso: string | number | null | undefined,
  opts: { timeZone?: string } = {},
): string | undefined {
  if (iso == null || iso === '' || Number.isNaN(new Date(iso).getTime())) return undefined;
  return `Local time: ${absoluteTime(iso, opts)}`;
}

/** The tooltip of a relative time: the time in UTC, then the local time with
 *  its zone. "2026-07-06 18:23 UTC. Local time: 2026-07-06 14:23 EDT". An
 *  empty value gives an empty string, and an unparseable one itself. */
export function timeTitle(
  iso: string | number | null | undefined,
  opts: { timeZone?: string } = {},
): string {
  if (iso == null || iso === '') return '';
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return String(iso);
  return `${utcStamp(at.toISOString())}. ${localTitle(iso, opts)}`;
}

/** A relative time in words, for a sentence: "5 days ago", "3 hours ago",
 *  "now". `ago` writes "5d ago", which fits a column and not a sentence.
 *  Hours stop at 24, and a day and more reads in days. */
export function agoWords(iso: string | null | undefined): string {
  if (!iso) return 'at an unknown time';
  const ms = Date.now() - new Date(iso).getTime();
  if (!Number.isFinite(ms)) return 'at an unknown time';
  if (ms < 60_000) return 'now';
  const unit = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'} ago`;
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 60) return unit(minutes, 'minute');
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return unit(hours, 'hour');
  return unit(Math.floor(hours / 24), 'day');
}

/** UTC with seconds, for a list of event times where two documents can share
 *  a minute. */
export interface UtcOptions {
  seconds?: boolean;
}

function utcParts(at: Date, opts: UtcOptions): [string, string] {
  const [day, time] = at.toISOString().slice(0, opts.seconds ? 19 : 16).split('T');
  return [day, time];
}

/** A time in UTC with the zone named: "2026-10-05 04:12 UTC", or
 *  "2026-10-05 04:12:09 UTC" with `{ seconds: true }`. The lead timeline and
 *  the Event timeline state their times in UTC, because the summaries and the
 *  queries the server writes are in UTC. */
export function utcStamp(iso: string | null | undefined, opts: UtcOptions = {}): string {
  if (!iso) return 'no time on record';
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return iso;
  const [day, time] = utcParts(at, opts);
  return `${day} ${time} UTC`;
}

/** A window in UTC: "2026-10-05 04:00 to 05:00 UTC", or with both dates when
 *  the window crosses midnight. One instant reads as one time. */
export function utcWindow(start: string, end: string, opts: UtcOptions = {}): string {
  const a = new Date(start);
  const b = new Date(end);
  if (Number.isNaN(a.getTime()) || Number.isNaN(b.getTime())) return `${start} to ${end}`;
  const [aDay, aTime] = utcParts(a, opts);
  const [bDay, bTime] = utcParts(b, opts);
  if (aDay === bDay && aTime === bTime) return `${aDay} ${aTime} UTC`;
  return aDay === bDay
    ? `${aDay} ${aTime} to ${bTime} UTC`
    : `${aDay} ${aTime} to ${bDay} ${bTime} UTC`;
}

// An ISO 8601 instant as a model or a tool writes it into prose:
// 2026-11-04T15:36:54Z, 2026-11-04T15:36:54.120+00:00, 2026-11-04T15:36. A
// time with no zone is UTC, the clock of the text the server writes.
const ISO_INSTANT = /\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?(?![\w:])/g;

/** Prose with each ISO instant in the form of {@link utcStamp}: one time form
 *  on a page (dogfood 2026-11-17, AA5). The investigation page showed one
 *  event in local time, in UTC and as "2026-11-04T15:36:54Z". An instant that
 *  does not parse stays as it is. */
/** The time of a step, "18:42:01", in the UTC form of the page: "18:42:01
 *  UTC". The server stamps a step with the time of day in UTC, and the step
 *  showed no zone (dogfood 2026-11-17, F15). Any other text stays. */
export function stepTimeUtc(time: string | null | undefined): string {
  const t = (time ?? '').trim();
  return /^\d{2}:\d{2}(?::\d{2})?$/.test(t) ? `${t} UTC` : t;
}

export function utcTimesInText(text: string): string {
  return text.replace(ISO_INSTANT, (instant) => {
    const zoned = /(?:Z|[+-]\d{2}:?\d{2})$/.test(instant) ? instant : `${instant}Z`;
    const at = new Date(zoned);
    if (Number.isNaN(at.getTime())) return instant;
    return utcStamp(at.toISOString(), { seconds: /T\d{2}:\d{2}:\d{2}/.test(instant) });
  });
}
