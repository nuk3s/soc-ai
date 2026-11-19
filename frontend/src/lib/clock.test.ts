// Round 4, C2: the second clock of the top bar. Each test names the zone that
// it reads, so it passes under any TZ of the machine.
import { afterEach, describe, expect, it } from 'vitest';
import {
  FALLBACK_ZONES,
  browserTimeZone,
  filterZones,
  isTimeZone,
  secondClockZone,
  utcClock,
  utcClockTitle,
  zoneClock,
  zoneList,
} from './clock';

type WithSupported = { supportedValuesOf?: unknown };
const intl = Intl as unknown as WithSupported;
const supported = intl.supportedValuesOf;

afterEach(() => {
  intl.supportedValuesOf = supported;
});

describe('zoneClock', () => {
  it('states the time with the short name of the zone, and the IANA zone in the tooltip', () => {
    const at = new Date('2026-11-19T14:32:10Z');
    expect(utcClock(at)).toBe('14:32 UTC');
    expect(utcClockTitle(at)).toBe('2026-11-19 14:32 UTC');
    expect(zoneClock(at, 'America/Chicago')).toEqual({
      text: '08:32 CST',
      title: '2026-11-19 08:32 CST, America/Chicago',
      short: 'CST',
    });
  });

  it('states the weekday first when the date in the zone is not the UTC date', () => {
    // 03:32 UTC on Thursday is 21:32 on Wednesday in Chicago.
    expect(zoneClock(new Date('2026-11-19T03:32:00Z'), 'America/Chicago').text).toBe('Wed 21:32 CST');
    // 20:00 UTC on Thursday is 05:00 on Friday in Tokyo.
    const tokyo = zoneClock(new Date('2026-11-19T20:00:00Z'), 'Asia/Tokyo');
    expect(tokyo.text).toMatch(/^Fri 05:00 \S+$/);
    expect(tokyo.title).toMatch(/^2026-11-20 05:00 \S+, Asia\/Tokyo$/);
  });

  it('states no weekday when the dates are the same', () => {
    // Negative control: the same date in the zone and in UTC.
    expect(zoneClock(new Date('2026-11-19T06:00:00Z'), 'America/Chicago').text).toBe('00:00 CST');
    expect(zoneClock(new Date('2026-11-19T14:32:00Z'), 'UTC').text).toBe('14:32 UTC');
  });
});

describe('the zone list', () => {
  it('holds the zones of the browser, UTC and the zone of this browser, sorted', () => {
    const list = zoneList();
    expect(list).toContain('America/Chicago');
    expect(list).toContain('UTC');
    expect(list).toContain(browserTimeZone());
    expect([...list].sort((a, b) => a.localeCompare(b))).toEqual(list);
    expect(list.every(isTimeZone)).toBe(true);
  });

  it('falls back to a short list when the browser has none', () => {
    intl.supportedValuesOf = undefined;
    const list = zoneList();
    expect(list).toContain('America/New_York');
    expect(list).toContain(browserTimeZone());
    expect(list.length).toBeLessThanOrEqual(FALLBACK_ZONES.length + 1);
    intl.supportedValuesOf = () => {
      throw new RangeError('no list');
    };
    expect(zoneList()).toContain('Asia/Tokyo');
    intl.supportedValuesOf = () => [];
    expect(zoneList()).toContain('Europe/London');
  });

  it('filters by text with a space for an underscore', () => {
    const list = ['America/Chicago', 'America/New_York', 'Asia/Tokyo'];
    expect(filterZones(list, 'new york')).toEqual(['America/New_York']);
    expect(filterZones(list, 'TOKYO')).toEqual(['Asia/Tokyo']);
    expect(filterZones(list, '  ')).toEqual(list);
    expect(filterZones(list, 'mars')).toEqual([]);
  });

  it('knows a zone of the browser and refuses a name that is no zone', () => {
    expect(isTimeZone('Europe/Paris')).toBe(true);
    expect(isTimeZone('Mars/Olympus')).toBe(false);
    expect(isTimeZone('')).toBe(false);
  });
});

describe('secondClockZone', () => {
  it('reads the zone of each choice', () => {
    expect(secondClockZone({ mode: 'off' }, 'Europe/Paris')).toBeNull();
    expect(secondClockZone({ mode: 'browser' }, 'Europe/Paris')).toBe('Europe/Paris');
    expect(secondClockZone({ mode: 'zone', zone: 'Asia/Tokyo' }, 'Europe/Paris')).toBe('Asia/Tokyo');
  });
});
