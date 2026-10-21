// Dogfood 2026-10-19, R5-I9: a backtest runs N full investigations by the
// model and had no cancel. The page warned "A backtest has no cancel." before
// the start. The server now takes POST /backtest/{id}/cancel and stops the run
// after the alert in flight. These tests hold the console half: the Cancel
// control on a running backtest, its confirm, the pending state a reload reads
// back, and the stored cancelled run.
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Health } from '../lib/api';
import { ApiError } from '../lib/api';
import type { Backtest as BacktestData, BacktestRunSummary } from '../lib/types';

const state = vi.hoisted(() => ({
  current: null as BacktestData | null,
  byId: {} as Record<string, BacktestData>,
  runs: [] as BacktestRunSummary[],
}));
const cancelBacktestMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getBacktest: vi.fn(async () => state.current),
  getBacktestById: vi.fn(async (id: string) => state.byId[id]),
  getBacktestRuns: vi.fn(async () => ({ runs: state.runs })),
  getHealth: vi.fn(async () => HEALTHY),
  startBacktest: vi.fn(),
  cancelBacktest: cancelBacktestMock,
}));

import { Backtest } from './Backtest';

const UP = { ok: true, detail: 'ok', state: 'ok' };
const HEALTHY: Health = { es: UP, llm: UP, so: UP } as Health;

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
  total: 14,
  replayed: 4,
  failed: 1,
  current: 'ET SCAN example',
  status: 'running',
  max_sample: null,
  estimate: null,
};

const row = (i: number) => ({
  alert_id: `a${i}`,
  rule_name: `rule ${i}`,
  human_disposition: 'false_positive' as const,
  soc_ai_verdict: 'false_positive' as const,
  match: true,
  investigation_id: `inv-${i}`,
});

const CANCELLED: BacktestData = {
  ...IDLE,
  backtest_id: 'bt-cancelled',
  total: 3,
  replayed: 3,
  finished_at: new Date(Date.now() - 5 * 60_000).toISOString(),
  status: 'cancelled',
  sampled: 3,
  requested: 20,
  params: { window_days: 30, sample_size: 20, min_severity: null },
  skipped_reason: 'An operator cancelled the backtest after 3 of 14 alerts.',
  results: {
    metrics: {
      agreement_rate: 1,
      fp_agreement_rate: 1,
      fp_reduction: 1,
      missed_tp: 0,
      n_needs_more_info: 0,
      counts: {
        total: 3,
        decided: 3,
        agreements: 3,
        human_tp: 0,
        human_fp: 3,
        human_fp_decided: 3,
        fp_cleared: 3,
      },
    },
    completion: {
      total: 3,
      decided: 3,
      no_verdict: 0,
      completion_rate: 1,
      degraded: false,
      reason: null,
    },
    confusion: {
      true_positive: { true_positive: 0, false_positive: 0, needs_more_info: 0, inconclusive: 0, no_verdict: 0 },
      false_positive: { true_positive: 0, false_positive: 3, needs_more_info: 0, inconclusive: 0, no_verdict: 0 },
    },
    missed_tp_rows: [],
    rows: [row(1), row(2), row(3)],
    caveat: 'The acknowledged alerts are a proxy.',
    cancel: { after: 3, of: 14, by: 'admin' },
  },
} as BacktestData;

async function mount(data: BacktestData) {
  state.current = data;
  render(
    <MemoryRouter>
      <Backtest />
    </MemoryRouter>,
  );
  await act(async () => {});
}

beforeEach(() => {
  state.current = null;
  state.byId = {};
  state.runs = [];
  cancelBacktestMock.mockReset();
});

describe('the start confirm', () => {
  it('no longer warns that a backtest has no cancel', async () => {
    await mount(IDLE);
    fireEvent.click(await screen.findByRole('button', { name: /Run backtest/ }));
    const confirm = await screen.findByTestId('backtest-confirm');
    expect(confirm).toHaveTextContent('This backtest runs up to 20 investigations by the model.');
    expect(confirm).not.toHaveTextContent(/no cancel/);
  });
});

describe('cancel a running backtest', () => {
  it('asks first and names the results soc-ai keeps', async () => {
    await mount(RUNNING);
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel backtest' }));
    expect(cancelBacktestMock).not.toHaveBeenCalled();

    const confirm = await screen.findByTestId('backtest-cancel-confirm');
    expect(confirm).toHaveTextContent(
      'Stop the backtest after the current alert. soc-ai keeps the 5 results so far.',
    );
  });

  it('sends the cancel on confirm and shows the pending stop', async () => {
    cancelBacktestMock.mockImplementation(async () => {
      state.current = { ...RUNNING, cancel_requested: true };
      return state.current;
    });
    await mount(RUNNING);
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel backtest' }));
    const confirm = await screen.findByTestId('backtest-cancel-confirm');
    fireEvent.click(within(confirm).getByRole('button', { name: 'Stop the backtest' }));

    await waitFor(() => expect(cancelBacktestMock).toHaveBeenCalledWith('bt-live'));
    expect(
      await screen.findByText('soc-ai stops the backtest after the current alert.'),
    ).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Cancel backtest' })).toBeNull();
  });

  it('keeps the run on Keep running', async () => {
    await mount(RUNNING);
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel backtest' }));
    const confirm = await screen.findByTestId('backtest-cancel-confirm');
    fireEvent.click(within(confirm).getByRole('button', { name: 'Keep running' }));

    expect(screen.queryByTestId('backtest-cancel-confirm')).toBeNull();
    expect(cancelBacktestMock).not.toHaveBeenCalled();
  });

  it('reads a pending cancel back from the server after a reload', async () => {
    await mount({ ...RUNNING, cancel_requested: true });
    expect(
      await screen.findByText('soc-ai stops the backtest after the current alert.'),
    ).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Cancel backtest' })).toBeNull();
  });

  it('states the refusal of the server', async () => {
    cancelBacktestMock.mockRejectedValue(
      new ApiError('This backtest is not running. Its status is complete.', 409, 'not_running'),
    );
    await mount(RUNNING);
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel backtest' }));
    fireEvent.click(
      within(await screen.findByTestId('backtest-cancel-confirm')).getByRole('button', {
        name: 'Stop the backtest',
      }),
    );

    expect(
      await screen.findByText('This backtest is not running. Its status is complete.'),
    ).toBeInTheDocument();
  });

  it('offers no cancel while the run still samples the window', async () => {
    await mount({ ...RUNNING, backtest_id: null, total: 0, replayed: 0, failed: 0 });
    expect(await screen.findByTestId('backtest-sampling')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Cancel backtest' })).toBeNull();
  });
});

describe('a cancelled run', () => {
  it('states where it stopped and keeps the results', async () => {
    await mount(CANCELLED);
    expect(await screen.findByText('Cancelled after 3 of 14 alerts.')).toBeInTheDocument();
    // The finished replays keep their rows and their score.
    expect(screen.getByText('Per-alert comparison')).toBeInTheDocument();
    expect(screen.getAllByText('rule 2').length).toBeGreaterThan(0);
    expect(screen.queryByTestId('backtest-empty')).toBeNull();
  });

  it('states that there is no score when no alert finished', async () => {
    await mount({
      ...CANCELLED,
      sampled: 0,
      results: {
        ...CANCELLED.results!,
        rows: [],
        completion: { ...CANCELLED.results!.completion!, total: 0, decided: 0 },
        cancel: { after: 0, of: 14, by: 'admin' },
      },
    });
    expect(await screen.findByText('Cancelled after 0 of 14 alerts.')).toBeInTheDocument();
    expect(screen.getByText(/There is no score to report\./)).toBeInTheDocument();
    expect(screen.queryByText('Per-alert comparison')).toBeNull();
  });

  it('reads Cancelled in the list of past runs', async () => {
    state.runs = [
      {
        backtest_id: 'bt-cancelled',
        status: 'cancelled',
        started_at: '2026-10-19T10:00:00Z',
        finished_at: '2026-10-19T10:06:00Z',
        sampled: 3,
        requested: 20,
        window_days: 30,
        min_severity: null,
        listed: false,
        agreement_rate: null,
        fp_agreement_rate: null,
        missed_tp: null,
        human_tp: null,
        human_fp: null,
      },
      {
        backtest_id: 'bt-old',
        status: 'complete',
        started_at: '2026-10-18T10:00:00Z',
        finished_at: '2026-10-18T10:30:00Z',
        sampled: 10,
        requested: 10,
        window_days: 14,
        min_severity: null,
        listed: false,
        agreement_rate: 0.6,
        fp_agreement_rate: 0.5,
        missed_tp: 0,
        human_tp: 2,
        human_fp: 8,
      },
    ];
    await mount(CANCELLED);
    const list = await screen.findByTestId('backtest-runs');
    expect(within(list).getByText('Cancelled')).toBeInTheDocument();
  });
});
