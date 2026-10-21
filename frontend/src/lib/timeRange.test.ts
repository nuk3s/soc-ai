// Pins the range → GET /hunts?since=&until= contract: presets send ONLY
// `since` (the upper edge is implicitly "now" on the server, so client clock
// skew can never exclude a just-created hunt), while a custom range sends both
// edges. Bounds are inclusive [from, to], matching inRange.
import { describe, expect, it } from 'vitest';
import { absTime, absoluteTime, ago, agoFromLabel, formatDuration, rangeToSinceUntil, timeLabel } from './timeRange';

describe('absTime', () => {
  const at = '2026-10-02T12:10:28Z';
  // The zone the test machine runs in, in the short form the formatter uses.
  const zone = new Intl.DateTimeFormat(undefined, { timeZoneName: 'short' })
    .formatToParts(new Date(at))
    .find((p) => p.type === 'timeZoneName')!.value;

  it('states the time zone when it is asked to', () => {
    const text = absTime(at, { zone: true });
    expect(text.endsWith(zone)).toBe(true);
    expect(text.startsWith(absTime(at))).toBe(true);
  });

  it('leaves the zone out by default', () => {
    // Negative control: the tooltips keep the short form.
    expect(absTime(at).endsWith(zone)).toBe(false);
  });

  it('keeps the dash and the raw string with the zone option', () => {
    expect(absTime(null, { zone: true })).toBe('—');
    expect(absTime('not-a-date', { zone: true })).toBe('not-a-date');
  });
});

describe('ago', () => {
  const at = (ms: number) => new Date(Date.now() - ms).toISOString();

  it('answers in the unit a reader is scanning for', () => {
    expect(ago(at(5_000))).toBe('now');
    expect(ago(at(8 * 60_000))).toBe('8m ago');
    expect(ago(at(4 * 3_600_000))).toBe('4h ago');
    expect(ago(at(3 * 86_400_000))).toBe('3d ago');
  });

  it('says never for a stamp that is absent, and does not fake one for junk', () => {
    // Null means the thing has not happened — a host list's "last seen", a KPI
    // strip's "last swept". Rendering it as a date would invent an event.
    expect(ago(null)).toBe('never');
    expect(ago('')).toBe('never');
    expect(ago('not-a-date')).toBe('—');
  });

  it('reads in days from 24 hours on', () => {
    // "27h ago" sat beside "3d ago" on one page.
    const now = Date.UTC(2026, 9, 6, 12, 0, 0);
    const before = (ms: number) => new Date(now - ms).toISOString();
    expect(ago(before(23 * 3_600_000 + 59 * 60_000), now)).toBe('23h ago');
    expect(ago(before(24 * 3_600_000), now)).toBe('1d ago');
    expect(ago(before(27 * 3_600_000), now)).toBe('1d ago');
    expect(ago(before(4 * 86_400_000 + 5 * 3_600_000), now)).toBe('4d ago');
    // Negative control: under an hour stays in minutes.
    expect(ago(before(59 * 60_000), now)).toBe('59m ago');
  });

  it('reads in months from 60 days and in years from 24 months', () => {
    // The host header read "first seen 395d ago" for a host the operator
    // thinks of as a year old. The list and the header share this rule.
    const now = Date.UTC(2026, 9, 6, 12, 0, 0);
    const days = (n: number) => new Date(now - n * 86_400_000).toISOString();
    expect(ago(days(59), now)).toBe('59d ago');
    expect(ago(days(61), now)).toBe('2mo ago');
    expect(ago(days(400), now)).toBe('13mo ago');
    expect(ago(days(900), now)).toBe('2y ago');
  });

  it('takes an epoch number too', () => {
    const now = Date.UTC(2026, 9, 6, 12, 0, 0);
    expect(ago(now - 2 * 86_400_000, now)).toBe('2d ago');
  });
});

describe('absoluteTime', () => {
  it('prints year first, the minute and the zone', () => {
    expect(absoluteTime('2026-10-01T12:18:40Z', { timeZone: 'America/New_York' })).toBe(
      '2026-10-01 08:18 EDT',
    );
    expect(absoluteTime('2026-12-01T12:18:00Z', { timeZone: 'America/New_York' })).toBe(
      '2026-12-01 07:18 EST',
    );
    expect(absoluteTime('2026-10-01T00:05:00Z', { timeZone: 'UTC' })).toBe('2026-10-01 00:05 UTC');
  });

  it('uses the browser zone by default and names it', () => {
    const at = '2026-10-02T12:10:28Z';
    const zone = new Intl.DateTimeFormat('en-US', { timeZoneName: 'short' })
      .formatToParts(new Date(at))
      .find((p) => p.type === 'timeZoneName')!.value;
    expect(absoluteTime(at).endsWith(` ${zone}`)).toBe(true);
    expect(absoluteTime(at)).toMatch(/^2026-10-0[12] \d{2}:\d{2} /);
  });

  it('reads an empty value as empty and junk as itself', () => {
    expect(absoluteTime(null)).toBe('');
    expect(absoluteTime('')).toBe('');
    expect(absoluteTime('not-a-date')).toBe('not-a-date');
  });
});

describe('formatDuration', () => {
  it('prints minutes and seconds, never a clock face', () => {
    expect(formatDuration(199)).toBe('3m 19s');
    expect(formatDuration(42)).toBe('42s');
    expect(formatDuration(0)).toBe('0s');
    expect(formatDuration(3_840)).toBe('1h 04m');
    expect(formatDuration(2 * 86_400 + 3 * 3_600)).toBe('2d 3h');
    // Negative control: "03:19" is the form this replaces.
    expect(formatDuration(199)).not.toMatch(/:/);
  });

  it('prints nothing for a missing or negative span', () => {
    expect(formatDuration(null)).toBe('');
    expect(formatDuration(-1)).toBe('');
    expect(formatDuration(Number.NaN)).toBe('');
  });
});

describe('timeLabel and agoFromLabel', () => {
  it('pairs the relative text with the absolute title', () => {
    const now = Date.UTC(2026, 9, 6, 12, 0, 0);
    const iso = new Date(now - 4 * 86_400_000).toISOString();
    const label = timeLabel(iso, now);
    expect(label.text).toBe('4d ago');
    expect(label.title).toBe(absoluteTime(iso));
  });

  it('adds "ago" to a server label and leaves other text alone', () => {
    expect(agoFromLabel('4d')).toBe('4d ago');
    expect(agoFromLabel('9m')).toBe('9m ago');
    expect(agoFromLabel('now')).toBe('now');
    expect(agoFromLabel('4d ago')).toBe('4d ago');
    expect(agoFromLabel('')).toBe('');
  });
});

describe('rangeToSinceUntil', () => {
  const now = Date.UTC(2026, 6, 7, 12, 0, 0); // 2026-07-07T12:00:00Z

  it('maps a preset to a since-only window anchored at now', () => {
    expect(rangeToSinceUntil('24h', null, now)).toEqual({
      since: '2026-07-06T12:00:00.000Z',
    });
    expect(rangeToSinceUntil('15m', null, now)).toEqual({
      since: '2026-07-07T11:45:00.000Z',
    });
    expect(rangeToSinceUntil('7d', null, now)).toEqual({
      since: '2026-06-30T12:00:00.000Z',
    });
  });

  it('falls back to a 24h window for an unknown preset (mirrors rangeBounds)', () => {
    expect(rangeToSinceUntil('bogus', null, now)).toEqual({
      since: '2026-07-06T12:00:00.000Z',
    });
  });

  it('maps a custom range to both edges as UTC ISO', () => {
    // datetime-local values are interpreted in the browser's local zone, so
    // assert round-trip equivalence rather than a hardcoded UTC string.
    const custom = { from: '2026-07-01T09:30', to: '2026-07-02T18:00' };
    expect(rangeToSinceUntil('custom', custom, now)).toEqual({
      since: new Date(custom.from).toISOString(),
      until: new Date(custom.to).toISOString(),
    });
  });

  it('degrades to the default preset window when custom is incomplete', () => {
    expect(rangeToSinceUntil('custom', null, now)).toEqual({
      since: '2026-07-06T12:00:00.000Z',
    });
    expect(rangeToSinceUntil('custom', { from: '2026-07-01T09:30', to: '' }, now)).toEqual({
      since: '2026-07-06T12:00:00.000Z',
    });
  });
});
