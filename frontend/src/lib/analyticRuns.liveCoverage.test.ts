// L5 (review 2026-11-12): the tab read "15 live" while 7 query analytics read
// "live, blind on the last run" and 4 baseline analytics scored no host.
import { describe, expect, it } from 'vitest';
import type { HuntCatalog } from './api';
import { liveCoverage, liveCoverageWords } from './analyticRuns';

const NOW = Date.now();
const ago = (ms: number) => new Date(NOW - ms).toISOString();

const CATALOG = {
  specs: [
    { id: 'q-measures', evaluator: 'match', blind: false },
    { id: 'q-blind', evaluator: 'match', blind: true },
    { id: 'p-scored', evaluator: 'profile', coverage: { measured: 3, learning: 0, blind: 1, not_applicable: 0 } },
    { id: 'p-unscored', evaluator: 'profile', coverage: { measured: 0, learning: 0, blind: 0, not_applicable: 0 } },
  ],
  sweeps_enabled: true,
  last_sweep_at: ago(600_000),
  prior_sweeps_enabled: true,
  last_prior_run_at: ago(600_000),
} as unknown as HuntCatalog;

const row = (id: string, evaluator: string, status = 'live') => ({ id, evaluator, status });

describe('liveCoverage', () => {
  it('counts the measuring and the blind live analytics from the row run state', () => {
    const c = liveCoverage(
      [
        row('q-measures', 'match'),
        row('q-blind', 'match'),
        row('p-scored', 'profile'),
        row('p-unscored', 'profile'),
        // A shadow analytic is no live analytic.
        row('q-blind', 'match', 'shadow'),
      ],
      CATALOG,
    );
    expect(c).toEqual({ live: 4, measuring: 2, blind: 2, failed: 0, notRunning: 0 });
    expect(liveCoverageWords(c, true)).toBe('4 live (2 measuring, 2 blind)');
  });

  it('counts a live analytic whose loop is off as not running', () => {
    // NEGATIVE CONTROL: a loop that is off never reads as measuring.
    const off = { ...CATALOG, sweeps_enabled: false } as HuntCatalog;
    const c = liveCoverage([row('q-measures', 'match')], off);
    expect(liveCoverageWords(c, true)).toBe('1 live (0 measuring, 0 blind, 1 not running)');
    expect(liveCoverageWords(c, false)).toBe('1 live');
  });
});
