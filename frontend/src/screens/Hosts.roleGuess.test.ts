// The role menu named "low confidence 1" and "old guess 1" and no guessed
// role (dogfood 2026-10-19, R4-I6). It now lists each guessed role with its
// count, marked as a guess.
import { describe, expect, it } from 'vitest';
import type { MachineSummary } from '../lib/types';
import { bulkValueLabel, roleFilterLabel, roleMenuNote, roleOptions } from './Hosts';

const summary = (over: Partial<MachineSummary> = {}): MachineSummary =>
  ({
    machines: 5,
    addresses: 7,
    with_agent: 2,
    without_agent: 3,
    new_7d: 0,
    named: 3,
    unnamed: 2,
    roles: { workstation: 1, unknown: 1, low_confidence: 1, stale: 2 },
    needs_attention: 0,
    out_of_date: 0,
    conflicts: 0,
    never_built: 0,
    last_sweep_at: null,
    stale_hours: null,
    ...over,
  }) as MachineSummary;

describe('the role menu', () => {
  it('lists each guessed role with its count, marked as a guess', () => {
    const options = roleOptions(summary({ role_guesses: { server: 2, iot: 1 } }), '');
    const guesses = options.filter((o) => o.value.startsWith('guess:'));
    expect(guesses).toEqual([
      { value: 'guess:iot', label: 'IoT device · guess', count: 1 },
      { value: 'guess:server', label: 'server · guess', count: 2 },
    ]);
    // The firm role comes first, the buckets last.
    expect(options[1].value).toBe('workstation');
    expect(options.slice(-3).map((o) => o.value).sort()).toEqual(['low_confidence', 'stale', 'unknown']);
  });

  it('names a guess filter on its chip', () => {
    expect(roleFilterLabel('guess:server')).toBe('server · guess');
    // NEGATIVE CONTROL: a firm role keeps its label.
    expect(roleFilterLabel('server')).toBe('server');
  });

  it('lists no guess for an older server', () => {
    // NEGATIVE CONTROL: no field, no guess entries.
    expect(roleOptions(summary(), '').some((o) => o.value.startsWith('guess:'))).toBe(false);
  });
});

// Dogfood round 2 (V2-5): a guessed role also counts in "weak guess" or "old
// guess", and the menu did not say so. The counts overlap.
describe('the role menu note', () => {
  it('says a guessed role also counts in a guess bucket', () => {
    expect(roleMenuNote(summary({ role_guesses: { server: 2 } }), 'all')).toBe(
      'Counts across all 5 machines. A guessed role also counts in "weak guess" or "old guess".',
    );
    expect(roleMenuNote(summary({ role_guesses: { server: 2 } }), 'active')).toBe(
      'Counts in this list of 5 machines with events. A guessed role also counts in "weak guess" or "old guess".',
    );
  });

  it('adds no overlap sentence with no guessed role', () => {
    // NEGATIVE CONTROL: no guess entries, no overlap.
    expect(roleMenuNote(summary(), 'all')).toBe('Counts across all 5 machines.');
    expect(roleMenuNote(null, 'all')).toBeUndefined();
  });
});

// Dogfood round 2 (V2-6): the bulk note and Undo printed the role slug:
// 'Declared role "domain_controller"'.
describe('the bulk value label', () => {
  it('reads a role by its display label and a criticality as is', () => {
    expect(bulkValueLabel('role', 'domain_controller')).toBe('domain controller');
    expect(bulkValueLabel('role', 'iot')).toBe('IoT device');
    expect(bulkValueLabel('criticality', 'low')).toBe('low');
  });
});
