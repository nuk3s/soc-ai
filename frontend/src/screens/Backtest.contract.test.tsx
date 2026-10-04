// Fleet dogfood 2026-10-01 (H6, RO11, RO20): what the Backtest result claims.
//
// A run with no escalated alert read "Missed true positives 0 · none missed ·
// soc-ai agreed on every one of the 0 escalated incidents · Agreement 100%".
// Nothing was tested and the screen said everything passed. A refused attempt
// rode on the earlier run as that run's own note.
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

const scored = (humanTp: number, humanFp: number): BacktestData => ({
  ...IDLE,
  backtest_id: 'BT-1',
  total: humanTp + humanFp,
  replayed: humanTp + humanFp,
  finished_at: '2026-08-08T11:00:00Z',
  status: 'complete',
  sampled: humanTp + humanFp,
  requested: 20,
  skipped_reason:
    'The window held 3 distinct pairs of detection and disposition. soc-ai samples one alert for each pair.',
  params: { window_days: 30, sample_size: 20, min_severity: null },
  results: {
    metrics: {
      agreement_rate: 1,
      fp_reduction: 1,
      missed_tp: 0,
      n_needs_more_info: 0,
      counts: {
        total: humanTp + humanFp,
        human_tp: humanTp,
        human_fp: humanFp,
        agreements: humanTp + humanFp,
        fp_cleared: humanFp,
      },
    },
    confusion: {
      true_positive: {
        true_positive: humanTp,
        false_positive: 0,
        needs_more_info: 0,
        inconclusive: 0,
        no_verdict: 0,
      },
      false_positive: {
        true_positive: 0,
        false_positive: humanFp,
        needs_more_info: 0,
        inconclusive: 0,
        no_verdict: 0,
      },
    },
    missed_tp_rows: [],
    rows: [],
    caveat: 'soc-ai reads the ground truth from Security Onion.',
  },
});

const mount = async (d: BacktestData) => {
  state.current = d;
  render(<Backtest />);
  await screen.findByText('New backtest');
};

describe('Backtest result claims', () => {
  it('says agreement is not measurable when no alert was escalated', async () => {
    await mount(scored(0, 3));
    expect(await screen.findAllByText('Not measurable')).toHaveLength(2);
    expect(
      screen.getByText('No escalated alert in the window. Agreement is not measurable.'),
    ).toBeTruthy();
    expect(screen.queryByText(/none missed/)).toBeNull();
    // The one 100% left is the false-positive card, which did measure 3 rows.
    expect(screen.getAllByText('100%')).toHaveLength(1);
    expect(screen.queryByText(/every one of the 0/)).toBeNull();
  });

  it('keeps the score when an escalated alert was tested', async () => {
    // The control: the not-measurable branch must not swallow a real score.
    await mount(scored(2, 1));
    expect(await screen.findByText(/none missed/)).toBeTruthy();
    expect(screen.queryByText('Not measurable')).toBeNull();
    expect(
      screen.getByText('soc-ai called none of the 2 escalated incidents a false positive.'),
    ).toBeTruthy();
  });

  it('reads correctly for one escalated incident', async () => {
    await mount(scored(1, 2));
    expect(
      await screen.findByText('soc-ai did not call the one escalated incident a false positive.'),
    ).toBeTruthy();
  });

  it('says why fewer alerts were replayed than requested', async () => {
    await mount(scored(1, 2));
    expect(await screen.findByTestId('backtest-skipped')).toHaveTextContent(/3 distinct pairs/);
    expect(screen.getByText(/20 requested/)).toBeTruthy();
  });

  it('draws a refusal on its own when no earlier run exists', async () => {
    await mount({
      ...IDLE,
      refused: {
        reason: 'no_dispositioned_alerts',
        hint: 'The window holds no alert that an analyst escalated or acknowledged.',
      },
    });
    const panel = await screen.findByTestId('backtest-refused');
    expect(panel).toHaveTextContent(/The last backtest attempt did not run/);
    expect(panel).not.toHaveTextContent(/earlier run/);
  });
});
