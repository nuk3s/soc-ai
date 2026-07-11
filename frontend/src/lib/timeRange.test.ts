// Pins the range → GET /hunts?since=&until= contract: presets send ONLY
// `since` (the upper edge is implicitly "now" on the server, so client clock
// skew can never exclude a just-created hunt), while a custom range sends both
// edges. Bounds are inclusive [from, to], matching inRange.
import { describe, expect, it } from 'vitest';
import { rangeToSinceUntil } from './timeRange';

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
