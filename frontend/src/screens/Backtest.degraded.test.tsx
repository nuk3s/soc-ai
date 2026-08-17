// The adoption report must not price an outage as a model regression.
//
// Degraded-grid sweep, 2026-08-13 (G5): a backtest that lost the grid after 2 of
// 20 replays finalized `complete` with the 18 unreadable rows counted as
// disagreements, so this screen rendered "Agreement with analysts 10%" — a
// persisted, wrong conclusion about model quality caused by an infrastructure
// failure, on the one screen built to earn an owner's trust. Interrupted runs
// now land as `error` and render their coverage instead of a score.
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

const mount = async (d: BacktestData) => {
  state.current = d;
  render(<Backtest />);
  await screen.findByText('New backtest');
};

describe('Backtest — an interrupted run is not a verdict on the model', () => {
  it('renders the cut-short state with its coverage, not an agreement score', async () => {
    await mount({
      ...IDLE,
      backtest_id: 'BT-1',
      status: 'error',
      sampled: 20,
      finished_at: '2026-08-13T02:00:00+00:00',
      results: {
        metrics: {
          agreement_rate: 1.0,
          completion_rate: 0.1,
          fp_reduction: 1.0,
          missed_tp: 0,
          n_needs_more_info: 0,
          n_no_verdict: 18,
          counts: {
            total: 20, decided: 2, no_verdict: 18, human_tp: 0, human_fp: 20,
            human_fp_decided: 2, agreements: 2, fp_cleared: 2,
          },
        },
        completion: {
          total: 20, decided: 2, no_verdict: 18, completion_rate: 0.1,
          degraded: true, reason: 'cut short',
        },
        confusion: {
          true_positive: { true_positive: 0, false_positive: 0, needs_more_info: 0, inconclusive: 0, no_verdict: 0 },
          false_positive: { true_positive: 0, false_positive: 2, needs_more_info: 0, inconclusive: 0, no_verdict: 18 },
        },
        missed_tp_rows: [],
        rows: [],
        caveat: 'x',
      },
    });
    expect(await screen.findByTestId('backtest-interrupted')).toBeTruthy();
    // No headline metric cards: an incomplete run has no score to publish.
    expect(screen.queryByText('Agreement with analysts')).toBeNull();
  });

  it('distinguishes an interrupted run from a genuinely empty window', async () => {
    await mount({ ...IDLE, note: 'no dispositioned alerts in the window to replay' });
    expect(await screen.findByTestId('backtest-empty')).toBeTruthy();
    expect(screen.queryByTestId('backtest-interrupted')).toBeNull();
  });

  it('flags partial coverage on a run that still completed', async () => {
    await mount({
      ...IDLE,
      backtest_id: 'BT-2',
      status: 'complete',
      sampled: 10,
      finished_at: '2026-08-13T02:00:00+00:00',
      results: {
        metrics: {
          agreement_rate: 1.0,
          completion_rate: 0.8,
          fp_reduction: 1.0,
          missed_tp: 0,
          n_needs_more_info: 0,
          n_no_verdict: 2,
          counts: {
            total: 10, decided: 8, no_verdict: 2, human_tp: 0, human_fp: 10,
            human_fp_decided: 8, agreements: 8, fp_cleared: 8,
          },
        },
        completion: {
          total: 10, decided: 8, no_verdict: 2, completion_rate: 0.8,
          degraded: false, reason: null,
        },
        confusion: {
          true_positive: { true_positive: 0, false_positive: 0, needs_more_info: 0, inconclusive: 0, no_verdict: 0 },
          false_positive: { true_positive: 0, false_positive: 8, needs_more_info: 0, inconclusive: 0, no_verdict: 2 },
        },
        missed_tp_rows: [],
        rows: [],
        caveat: 'x',
      },
    });
    // The score stands, but the gap in coverage is stated beside it.
    expect(await screen.findByTestId('backtest-partial-coverage')).toBeTruthy();
    expect(screen.getByText('Agreement with analysts')).toBeTruthy();
  });

  it('shows no coverage banner on a fully replayed run', async () => {
    await mount({
      ...IDLE,
      backtest_id: 'BT-3',
      status: 'complete',
      sampled: 4,
      finished_at: '2026-08-13T02:00:00+00:00',
      results: {
        metrics: {
          agreement_rate: 1.0,
          completion_rate: 1.0,
          fp_reduction: 1.0,
          missed_tp: 0,
          n_needs_more_info: 0,
          n_no_verdict: 0,
          counts: {
            total: 4, decided: 4, no_verdict: 0, human_tp: 0, human_fp: 4,
            human_fp_decided: 4, agreements: 4, fp_cleared: 4,
          },
        },
        completion: {
          total: 4, decided: 4, no_verdict: 0, completion_rate: 1.0,
          degraded: false, reason: null,
        },
        confusion: {
          true_positive: { true_positive: 0, false_positive: 0, needs_more_info: 0, inconclusive: 0, no_verdict: 0 },
          false_positive: { true_positive: 0, false_positive: 4, needs_more_info: 0, inconclusive: 0, no_verdict: 0 },
        },
        missed_tp_rows: [],
        rows: [],
        caveat: 'x',
      },
    });
    expect(await screen.findByText('Agreement with analysts')).toBeTruthy();
    expect(screen.queryByTestId('backtest-partial-coverage')).toBeNull();
    expect(screen.queryByTestId('backtest-interrupted')).toBeNull();
  });
});
