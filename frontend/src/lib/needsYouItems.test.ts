import { describe, expect, it } from 'vitest';
import { NEEDS_YOU_LIMIT, NEEDS_YOU_SCOPE, waitAge } from './needsYouItems';

const NOW = Date.parse('2026-11-14T12:00:00Z');

describe('NEEDS_YOU_SCOPE', () => {
  it('states the order of the list in one line', () => {
    expect(NEEDS_YOU_SCOPE).toContain('the most important first');
    expect(NEEDS_YOU_SCOPE).toContain('campaigns, true positives, leads, other investigations, rules with open false positives, then alert groups');
    expect(NEEDS_YOU_SCOPE).toContain('impact, severity and newest event');
    // The rules sort by another key on the server (needs_you_facts.order_key).
    expect(NEEDS_YOU_SCOPE).toContain(
      'The rules sort by the count with checked evidence, the largest first, and then by newest event.',
    );
  });
});

describe('waitAge', () => {
  it('states the age in one phrase, and marks an age past 30 days', () => {
    expect(waitAge('2026-11-14T11:48:00Z', NOW)).toEqual({ text: 'Waits for 12 minutes', old: false });
    expect(waitAge('2026-11-14T07:00:00Z', NOW)).toEqual({ text: 'Waits for 5 hours', old: false });
    expect(waitAge('2026-11-13T12:00:00Z', NOW)).toEqual({ text: 'Waits for 1 day', old: false });
    expect(waitAge('2026-10-15T12:00:00Z', NOW)).toEqual({ text: 'Waits for 30 days', old: false });
    expect(waitAge('2026-10-14T11:00:00Z', NOW)).toEqual({ text: 'Waits for 31 days', old: true });
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
