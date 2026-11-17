import { describe, expect, it } from 'vitest';
import type { NeedsYouItem } from './api';
import { NEEDS_YOU_LIMIT, sortNeedsYou, waitAge } from './needsYouItems';

const NOW = Date.parse('2026-11-14T12:00:00Z');

function item(type: NeedsYouItem['type'], id: string, since: string | null): NeedsYouItem {
  return { type, id, title: id, detail: '', since, href: `/${id}`, stage: null };
}

describe('sortNeedsYou', () => {
  it('puts the campaigns first, then each type with its oldest item first', () => {
    const items = [
      item('lead', 'lead-new', '2026-11-13T00:00:00Z'),
      item('investigation', 'inv-new', '2026-11-12T00:00:00Z'),
      item('campaign', 'camp-new', '2026-11-10T00:00:00Z'),
      item('alerts', 'alerts', '2026-11-07T00:00:00Z'),
      item('lead', 'lead-old', '2026-10-01T00:00:00Z'),
      item('campaign', 'camp-old', '2026-10-24T00:00:00Z'),
      item('investigation', 'inv-none', null),
      item('investigation', 'inv-old', '2026-11-01T00:00:00Z'),
    ];
    expect(sortNeedsYou(items).map((i) => i.id)).toEqual([
      'camp-old',
      'camp-new',
      'inv-old',
      'inv-new',
      'inv-none',
      'lead-old',
      'lead-new',
      'alerts',
    ]);
  });
});

describe('waitAge', () => {
  it('states the age in words, and the days with no decision past 30 days', () => {
    expect(waitAge('2026-11-14T11:48:00Z', NOW)).toEqual({ text: 'Waits for 12 minutes', old: false });
    expect(waitAge('2026-11-14T07:00:00Z', NOW)).toEqual({ text: 'Waits for 5 hours', old: false });
    expect(waitAge('2026-11-13T12:00:00Z', NOW)).toEqual({ text: 'Waits for 1 day', old: false });
    expect(waitAge('2026-10-15T12:00:00Z', NOW)).toEqual({ text: 'Waits for 30 days', old: false });
    expect(waitAge('2026-10-14T11:00:00Z', NOW)).toEqual({ text: 'No decision for 31 days', old: true });
    expect(waitAge('2026-11-14T11:59:40Z', NOW)).toEqual({ text: 'Waits for less than a minute', old: false });
  });

  it('states no age for an item with no time', () => {
    expect(waitAge(null, NOW)).toBeNull();
    expect(waitAge('not a time', NOW)).toBeNull();
  });

  it('caps the list at the limit of the server', () => {
    expect(NEEDS_YOU_LIMIT).toBe(200);
  });
});
