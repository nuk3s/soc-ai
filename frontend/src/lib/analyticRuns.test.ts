import { describe, expect, it } from 'vitest';

import type { HuntCatalog, HuntCatalogSpec, LoopHealth } from './api';
import { loopResultLine, specRunState, statusLabel } from './analyticRuns';

// Dogfood 2026-10-19 R3-D1, H1-D2, R5-I3. Nine live query analytics read a
// green "live" while every sweep failed, and nine profile analytics read
// "live" over a sweep that measured no host.

const NOW = Date.parse('2026-10-19T12:00:00Z');
const at = (minutesAgo: number) => new Date(NOW - minutesAgo * 60_000).toISOString();

function spec(over: Partial<HuntCatalogSpec> = {}): HuntCatalogSpec {
  return {
    id: 'a1',
    title: 'A1',
    level: 'high',
    scope_kind: 'host',
    attack: [],
    evaluator: 'match',
    coverage: null,
    last_swept_at: at(10),
    last_fired_at: null,
    blind: false,
    last_error: null,
    sweeps_24h: 24,
    fired_24h: 0,
    fresh_24h: 0,
    already_handled_24h: 0,
    shadow_24h: 0,
    undecided_docs: 0,
    unattributed_docs: 0,
    truncated_docs: 0,
    ...over,
  };
}

function catalog(over: Partial<HuntCatalog> = {}): HuntCatalog {
  return {
    specs: [],
    sweeps_enabled: true,
    sweep_interval_minutes: 60,
    sweep_window_minutes: 1440,
    last_sweep_at: at(10),
    prior_sweeps_enabled: true,
    last_prior_run_at: at(5),
    ...over,
  };
}

const coverage = (measured: number, blind = 0) => ({
  last_run_at: at(5),
  measured,
  learning: 0,
  blind,
  not_applicable: 0,
  fired: 0,
  shadow: false,
});

describe('specRunState', () => {
  it('reads a failed newest run as failed, not live', () => {
    const s = spec({ last_error: 'precondition: x', last_error_text: 'soc-ai could not connect to the grid.' });
    expect(specRunState(catalog(), s)).toBe('failed');
    expect(statusLabel('live', 'failed')).toBe('live, last run failed');
  });

  it('reads a blind newest run as blind', () => {
    expect(specRunState(catalog(), spec({ blind: true }))).toBe('blind');
    expect(statusLabel('live', 'blind')).toBe('live, blind on the last run');
  });

  it('reads a profile run that measured no host as unmeasured', () => {
    const s = spec({ evaluator: 'profile', coverage: coverage(0) });
    expect(specRunState(catalog(), s)).toBe('unmeasured');
    expect(statusLabel('live', 'unmeasured')).toBe('live, measured no host');
  });

  it('reads a profile run with a blind host as measured', () => {
    // Control: a blind count is a measurement of the estate. The coverage
    // cell says it, and the dot stays live.
    expect(specRunState(catalog(), spec({ evaluator: 'profile', coverage: coverage(0, 3) }))).toBe(true);
    expect(specRunState(catalog(), spec({ evaluator: 'profile', coverage: coverage(4) }))).toBe(true);
  });

  it('reads a profile analytic whose loop never completed and then failed as failed', () => {
    const s = spec({ evaluator: 'profile', last_error_text: 'The grid did not answer the health check.' });
    expect(specRunState(catalog({ last_prior_run_at: null }), s)).toBe('failed');
  });

  it('keeps the loop state when the loop is off', () => {
    const s = spec({ last_error: 'boom' });
    expect(specRunState(catalog({ sweeps_enabled: false }), s)).toBe(false);
  });

  it('reads a healthy analytic as live', () => {
    expect(specRunState(catalog(), spec())).toBe(true);
    expect(specRunState(catalog(), undefined)).toBe(true);
  });
});

describe('loopResultLine', () => {
  const failed: LoopHealth = {
    last_run_at: at(13),
    last_outcome: 'failed',
    last_error_text: 'soc-ai could not connect to the grid.',
    runs_24h: 25,
    failed_24h: 25,
    failing_since: at(4 * 24 * 60),
    counted_since: null,
  };

  it('states the last result, the failed runs of the day and the first failure', () => {
    expect(loopResultLine(failed, NOW)).toBe(
      'Last sweep failed 13m ago. soc-ai could not connect to the grid. ' +
        '25 of 25 runs failed in 24 h. First failure 4d ago.',
    );
  });

  it('keeps the outage in the line after one good sweep', () => {
    const line = loopResultLine(
      { ...failed, last_outcome: 'ok', last_error_text: null, failing_since: null, failed_24h: 24 },
      NOW,
    );
    expect(line).toBe('Last sweep completed 13m ago. 24 of 25 runs failed in 24 h.');
  });

  it('says a skipped run did not run', () => {
    const line = loopResultLine(
      {
        ...failed,
        last_outcome: 'skipped',
        last_error_text: 'The grid did not answer the health check. soc-ai skipped the sweep.',
        runs_24h: 3,
        failed_24h: 3,
        failing_since: at(180),
        counted_since: at(180),
      },
      NOW,
    );
    expect(line).toBe(
      'Last sweep did not run 13m ago. The grid did not answer the health check. ' +
        'soc-ai skipped the sweep. 3 of 3 runs did not complete in the last 3 h. First failure 3h ago.',
    );
  });

  it('states a healthy day in one sentence', () => {
    const line = loopResultLine(
      { ...failed, last_outcome: 'ok', last_error_text: null, failing_since: null, failed_24h: 0, runs_24h: 1 },
      NOW,
    );
    expect(line).toBe('Last sweep completed 13m ago. 1 of 1 run completed in 24 h.');
  });

  it('has no line for a loop with no run on record', () => {
    expect(loopResultLine(null, NOW)).toBeNull();
    expect(loopResultLine(undefined, NOW)).toBeNull();
  });
});
