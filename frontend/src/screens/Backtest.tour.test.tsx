// The smoke test of the Backtest tour. A running backtest shows the cancel
// control, and an earlier run opened from Past runs shows the report. Both
// together put every anchor of the tour on the page. A renamed or removed
// `data-tour` attribute fails here.
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Health } from '../lib/api';
import type { Backtest as BacktestData, BacktestRunSummary } from '../lib/types';

const state = vi.hoisted(() => ({
  current: null as BacktestData | null,
  byId: {} as Record<string, BacktestData>,
  runs: [] as BacktestRunSummary[],
}));

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getBacktest: vi.fn(async () => state.current),
  getBacktestById: vi.fn(async (id: string) => state.byId[id]),
  getBacktestRuns: vi.fn(async () => ({ runs: state.runs })),
  getHealth: vi.fn(async () => HEALTHY),
  startBacktest: vi.fn(),
  cancelBacktest: vi.fn(),
}));

import { BACKTEST_TOUR } from '../tours/content';
import { missingAnchors } from '../tours/testing';
import { Backtest } from './Backtest';

const UP = { ok: true, detail: 'ok', state: 'ok' };
const HEALTHY: Health = { es: UP, llm: UP, so: UP } as Health;
const MINUTE = 60_000;
const ago = (ms: number) => new Date(Date.now() - ms).toISOString();

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
  max_sample: 50,
  estimate: { seconds_per_alert: 120, runs: 12, basis: 'backtest' },
};

const RUNNING: BacktestData = {
  ...IDLE,
  active: true,
  backtest_id: 'bt-live',
  total: 10,
  replayed: 3,
  failed: 0,
  current: 'ET SCAN Example Port Sweep',
  status: 'running',
  max_sample: null,
  estimate: null,
};

const row = (i: number) => ({
  alert_id: `a${i}`,
  rule_name: `Example rule ${i}`,
  human_disposition: 'false_positive' as const,
  soc_ai_verdict: 'false_positive' as const,
  match: true,
  investigation_id: `inv-${i}`,
});

const EARLIER: BacktestData = {
  ...IDLE,
  backtest_id: 'bt-old',
  total: 2,
  replayed: 2,
  finished_at: ago(3 * 60 * MINUTE),
  status: 'complete',
  sampled: 2,
  params: { window_days: 30, sample_size: 20, min_severity: null },
  results: {
    metrics: {
      agreement_rate: 1,
      fp_agreement_rate: 1,
      fp_reduction: 1,
      missed_tp: 0,
      n_needs_more_info: 0,
      counts: {
        total: 2,
        decided: 2,
        agreements: 2,
        human_tp: 0,
        human_fp: 2,
        human_fp_decided: 2,
        fp_cleared: 2,
      },
    },
    completion: {
      total: 2,
      decided: 2,
      no_verdict: 0,
      completion_rate: 1,
      degraded: false,
      reason: null,
    },
    confusion: {
      true_positive: { true_positive: 0, false_positive: 0, needs_more_info: 0, inconclusive: 0, no_verdict: 0 },
      false_positive: { true_positive: 0, false_positive: 2, needs_more_info: 0, inconclusive: 0, no_verdict: 0 },
    },
    missed_tp_rows: [],
    rows: [row(1), row(2)],
    caveat: 'The acknowledged alerts are a proxy.',
  },
} as BacktestData;

const summary = (o: Partial<BacktestRunSummary>): BacktestRunSummary => ({
  backtest_id: 'bt-live',
  status: 'running',
  started_at: ago(10 * MINUTE),
  finished_at: null,
  sampled: 10,
  requested: 10,
  window_days: 30,
  min_severity: null,
  listed: false,
  agreement_rate: null,
  fp_agreement_rate: null,
  missed_tp: null,
  human_tp: null,
  human_fp: null,
  ...o,
});

async function mount(data: BacktestData) {
  state.current = data;
  render(
    <MemoryRouter initialEntries={['/backtest']}>
      <Backtest />
    </MemoryRouter>,
  );
  await act(async () => {});
}

beforeEach(() => {
  state.current = null;
  state.byId = { 'bt-old': EARLIER };
  state.runs = [];
});

describe('the Backtest tour', () => {
  it('finds every anchor it names on a running backtest with an earlier run open', async () => {
    state.runs = [
      summary({}),
      summary({
        backtest_id: 'bt-old',
        status: 'complete',
        started_at: ago(4 * 60 * MINUTE),
        finished_at: ago(3 * 60 * MINUTE),
        sampled: 2,
        agreement_rate: 1,
        fp_agreement_rate: 1,
        missed_tp: 0,
        human_tp: 0,
        human_fp: 2,
      }),
    ];
    await mount(RUNNING);
    await screen.findByRole('button', { name: 'Cancel backtest' });
    const runs = await screen.findByTestId('backtest-runs');
    fireEvent.click(within(runs).getByRole('button', { name: 'Open' }));
    await screen.findByTestId('backtest-viewed');
    await screen.findByText('Example rule 1');
    expect(missingAnchors(BACKTEST_TOUR)).toEqual([]);
  });

  it('shows the header and the form on a first visit', async () => {
    await mount(IDLE);
    await screen.findByTestId('backtest-empty');
    expect(missingAnchors(BACKTEST_TOUR)).toEqual([
      'backtest-cancel',
      'backtest-runs',
      'backtest-figures',
      'backtest-table',
    ]);
  });
});
