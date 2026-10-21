import { describe, expect, it } from 'vitest';

import type { HuntCatalog, HuntCatalogSpec } from '../lib/api';
import { emptyHitsText } from './AnalyticHits';

// Dogfood 2026-10-19 H1-D2. "The profile analytics found nothing." over a
// profile sweep that measured no host against a dead grid, and "The match
// analytics found nothing." over 25 failed sweeps. Both were false all-clears.

const recent = new Date(Date.now() - 600_000).toISOString();
const HEAD = 'No analytic hit in the last 7 days.';

function profileSpec(measured: number): HuntCatalogSpec {
  return {
    id: `p-${measured}`,
    title: 'P',
    level: 'low',
    scope_kind: 'host',
    attack: [],
    evaluator: 'profile',
    coverage: {
      last_run_at: recent,
      measured,
      learning: 0,
      blind: 0,
      not_applicable: 0,
      fired: 0,
      shadow: false,
    },
    last_swept_at: recent,
    last_fired_at: null,
    blind: false,
    last_error: null,
    sweeps_24h: 1,
    fired_24h: 0,
    fresh_24h: 0,
    already_handled_24h: 0,
    shadow_24h: 0,
    undecided_docs: 0,
    unattributed_docs: 0,
    truncated_docs: 0,
  };
}

const BOTH_RAN: HuntCatalog = {
  specs: [profileSpec(4)],
  sweeps_enabled: true,
  sweep_interval_minutes: 60,
  sweep_window_minutes: 1440,
  last_sweep_at: recent,
  prior_sweeps_enabled: true,
  last_prior_run_at: recent,
};

describe('emptyHitsText', () => {
  it('keeps the quiet sentence when both loops ran and read the grid', () => {
    expect(emptyHitsText(BOTH_RAN)).toBe(
      `${HEAD} No analytic matched a document the sweeps read.`,
    );
  });

  it('says the profile analytics measured no host', () => {
    const text = emptyHitsText({ ...BOTH_RAN, specs: [profileSpec(0), profileSpec(0)] });
    expect(text).toContain('The profile analytics measured no host.');
    expect(text).not.toContain('The profile analytics found nothing.');
  });

  it('says the profile sweep could not read the grid', () => {
    const text = emptyHitsText({
      ...BOTH_RAN,
      last_prior_run_at: null,
      prior_sweep_health: {
        last_run_at: recent,
        last_outcome: 'skipped',
        last_error_text: 'The grid did not answer the health check. soc-ai skipped the sweep.',
        runs_24h: 3,
        failed_24h: 3,
      },
    });
    expect(text).toContain('The last profile sweep could not read the grid.');
    expect(text).not.toContain('The profile analytics found nothing.');
    // Control: the analytic sweep read the grid, so its sentence stays.
    expect(text).toContain('The match analytics found nothing.');
    expect(text).not.toContain('has not run yet');
  });

  it('says the analytic sweep could not read the grid', () => {
    const text = emptyHitsText({
      ...BOTH_RAN,
      sweep_health: {
        last_run_at: recent,
        last_outcome: 'failed',
        last_error_text: 'soc-ai could not connect to the grid.',
        runs_24h: 25,
        failed_24h: 25,
      },
    });
    expect(text).toContain('The last analytic sweep could not read the grid.');
    expect(text).not.toContain('The match analytics found nothing.');
    expect(text).toContain('The profile analytics found nothing.');
  });
});
