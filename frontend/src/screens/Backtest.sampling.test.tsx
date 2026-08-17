// A run that has not sampled anything yet is not a run that replayed nothing.
//
// Degraded-grid dogfood, 2026-08-14 (D18, second face): against a grid that
// answered nothing, this screen rendered "Replaying 0 dispositioned alerts…"
// over "0 / 0 replayed". Every number in that is true and the sentence they add
// up to is false — a completed replay of an empty set reads as "there was
// nothing to compare", which is exactly the clean-and-quiet story a blind read
// must never be allowed to tell. A backtest is `active` from the moment the
// sampling search goes out, before a backtest_id exists, so those zeros are the
// SAMPLING phase, not a result.
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { Backtest as BacktestData } from '../lib/types';

const state = vi.hoisted(() => ({ current: null as BacktestData | null }));

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getBacktest: vi.fn(async () => state.current),
  startBacktest: vi.fn(),
}));

import { Backtest } from './Backtest';

const IDLE: BacktestData = {
  active: false,
  backtest_id: null,
  total: 0,
  replayed: 0,
  failed: 0,
  finished_at: null,
  current: null,
  note: null,
  params: null,
  results: null,
  status: null,
  sampled: null,
};

// A completed, scored run — the history every console has after its first
// backtest, and the state in which the note below used to be undrawable.
const SCORED: BacktestData = {
  ...IDLE,
  backtest_id: 'BT-1',
  total: 3,
  replayed: 3,
  finished_at: '2026-08-08T11:00:00Z',
  status: 'complete',
  sampled: 3,
  params: { window_days: 30, sample_size: 20, min_severity: null },
  results: {
    metrics: {
      agreement_rate: 1,
      fp_reduction: 1,
      missed_tp: 0,
      n_needs_more_info: 0,
      counts: {
        total: 3,
        human_tp: 1,
        human_fp: 2,
        agreements: 3,
        fp_cleared: 2,
      },
    },
    confusion: {
      true_positive: {
        true_positive: 1,
        false_positive: 0,
        needs_more_info: 0,
        inconclusive: 0,
        no_verdict: 0,
      },
      false_positive: {
        true_positive: 0,
        false_positive: 2,
        needs_more_info: 0,
        inconclusive: 0,
        no_verdict: 0,
      },
    },
    missed_tp_rows: [],
    rows: [],
    caveat: 'Ground truth is read from Security Onion.',
  },
};

const GRID_NOTE =
  'Grid unavailable — the window could not be read, so no alerts were sampled. ' +
  'Security Onion (Elasticsearch) is slow or unreachable; retry shortly.';

const mount = async (d: BacktestData) => {
  state.current = d;
  render(<Backtest />);
  // findBy, not getBy: the panel under test renders off the getBacktest fetch,
  // so a synchronous assertion after this would race the very thing it checks.
  await screen.findByText('New backtest');
};

describe('Backtest — the sampling phase is not a finished replay', () => {
  it('names the phase instead of counting zero replays', async () => {
    await mount({ ...IDLE, active: true, backtest_id: null, total: 0 });

    expect(await screen.findByTestId('backtest-sampling')).toBeTruthy();
    // The specific claim that was wrong: a replay of nothing, reported as done.
    expect(screen.queryByText(/Replaying 0 dispositioned alerts/)).toBeNull();
    expect(screen.queryByText(/0 \/ 0 replayed/)).toBeNull();
  });

  it('still reports real progress once the run has a sample', async () => {
    // The control. Without it "never render progress" would pass the test above
    // and silently delete the live progress panel from a working backtest.
    await mount({
      ...IDLE,
      active: true,
      backtest_id: 'BT-9',
      total: 20,
      replayed: 3,
      current: 'ET SCAN thing',
    });

    expect(await screen.findByText(/Replaying 20 dispositioned alerts/)).toBeTruthy();
    expect(screen.getByText(/3 \/ 20 replayed/)).toBeTruthy();
    expect(screen.queryByTestId('backtest-sampling')).toBeNull();
  });
});

describe("Backtest — the newest attempt's outcome is not hidden by an older score", () => {
  it('shows the failed run’s note above the run that did produce a score', async () => {
    // The failure has no results of its own: it died in the sampling read, so
    // what the API serves is last week's score with this note over it. The note
    // was only ever rendered inside the empty panel, which a console with
    // history never draws — so the failure was invisible.
    await mount({ ...SCORED, note: GRID_NOTE });

    expect(await screen.findByTestId('backtest-note')).toHaveTextContent(/retry shortly/);
    // ...without deleting the measurement that really happened. Losing a real
    // score to an unrelated outage is this fix's own over-correction.
    expect(screen.getByText(/Agreement with analysts/)).toBeTruthy();
  });

  it('says nothing extra when the stored run is all there is to report', async () => {
    // The control: no note, no banner. Without it, "always render a notice"
    // would pass the test above and put an empty warning strip on every score.
    await mount(SCORED);

    expect(await screen.findByText(/Agreement with analysts/)).toBeTruthy();
    expect(screen.queryByTestId('backtest-note')).toBeNull();
  });
});
