// Dogfood 2026-10-19: what the Backtest page claims and what it lets the
// operator start.
//
// R5-D13: "FALSE-POSITIVE TOIL CLEARED 56% · soc-ai would auto-clear 5 of 9".
// The figure is the share of acknowledged alerts that soc-ai called a false
// positive. Auto-acknowledge also applies a threshold, an evidence test and a
// severity guard, so "auto-clear" overstated it.
// H1-D13: "Run backtest" stayed enabled while the grid and the model gateway
// were down. R5-I9: a run of 20 investigations started on one click, with no
// cost and no way to stop it. R5-I10: the rows linked nowhere and the page held
// one run only.
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Health } from '../lib/api';
import type { Backtest as BacktestData, BacktestRunSummary } from '../lib/types';

const state = vi.hoisted(() => ({
  current: null as BacktestData | null,
  byId: {} as Record<string, BacktestData>,
  runs: [] as BacktestRunSummary[],
  health: null as Health | null,
  healthFails: false,
}));
const startBacktestMock = vi.hoisted(() => vi.fn());
const getBacktestByIdMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getBacktest: vi.fn(async () => state.current),
  getBacktestById: getBacktestByIdMock,
  getBacktestRuns: vi.fn(async () => ({ runs: state.runs })),
  getHealth: vi.fn(async () => {
    if (state.healthFails) throw new Error('health did not load');
    return state.health;
  }),
  startBacktest: startBacktestMock,
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

const run = (id: string, rule: string, over: Partial<BacktestData['results']> = {}): BacktestData => ({
  ...IDLE,
  backtest_id: id,
  total: 10,
  replayed: 10,
  finished_at: '2026-10-01T12:34:19Z',
  status: 'complete',
  sampled: 10,
  params: { window_days: 14, sample_size: 10, min_severity: null },
  results: {
    metrics: {
      agreement_rate: 0.6,
      fp_agreement_rate: 5 / 9,
      fp_reduction: 5 / 9,
      missed_tp: 0,
      n_needs_more_info: 0,
      counts: {
        total: 10,
        decided: 10,
        human_tp: 1,
        human_fp: 9,
        human_fp_decided: 9,
        agreements: 6,
        fp_cleared: 5,
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
        true_positive: 2,
        false_positive: 5,
        needs_more_info: 2,
        inconclusive: 0,
        no_verdict: 0,
      },
    },
    missed_tp_rows: [],
    rows: [
      {
        alert_id: 'es-1',
        rule_name: rule,
        human_disposition: 'false_positive',
        soc_ai_verdict: 'false_positive',
        match: true,
        investigation_id: `INV-${id}`,
      },
      {
        alert_id: 'es-2',
        rule_name: 'ET SCAN Potential SSH Scan',
        human_disposition: 'false_positive',
        soc_ai_verdict: 'needs_more_info',
        match: false,
      },
    ],
    caveat: 'soc-ai reads the ground truth from Security Onion.',
    ...over,
  },
});

const mount = async (d: BacktestData) => {
  state.current = d;
  render(
    <MemoryRouter>
      <Backtest />
    </MemoryRouter>,
  );
  await screen.findByText('New backtest');
};

beforeEach(() => {
  state.current = null;
  state.byId = {};
  state.runs = [];
  state.health = HEALTHY;
  state.healthFails = false;
  startBacktestMock.mockReset();
  startBacktestMock.mockResolvedValue({ ...IDLE, active: true, backtest_id: 'BT-NEW', total: 20 });
  getBacktestByIdMock.mockReset();
  getBacktestByIdMock.mockImplementation(async (id: string) => state.byId[id]);
});

describe('the false-positive figure', () => {
  it('is an agreement figure, with no auto-clear claim', async () => {
    await mount(run('BT-1', 'ET INFO NTLM Session Setup Request'));
    expect(await screen.findByText('False-positive agreement')).toBeTruthy();
    expect(
      screen.getByText('soc-ai called 5 of 9 acknowledged alerts a false positive.'),
    ).toBeTruthy();
    expect(screen.getByText('56%')).toBeTruthy();
    expect(screen.queryByText(/auto-clear/i)).toBeNull();
    expect(screen.queryByText(/cleared/i)).toBeNull();
  });

  it('reads an older server that sends fp_reduction only', async () => {
    const d = run('BT-1', 'r');
    delete d.results!.metrics.fp_agreement_rate;
    d.results!.metrics.fp_reduction = 0.25;
    await mount(d);
    expect(await screen.findByText('25%')).toBeTruthy();
  });
});

describe('the result rows', () => {
  it('link a row to its replay investigation', async () => {
    await mount(run('BT-1', 'ET INFO NTLM Session Setup Request'));
    const link = await screen.findByRole('link', { name: 'ET INFO NTLM Session Setup Request' });
    expect(link.getAttribute('href')).toBe('/investigation/INV-BT-1');
  });

  it('leave a row with no replay id as text', async () => {
    await mount(run('BT-1', 'r'));
    await screen.findByText('ET SCAN Potential SSH Scan');
    expect(screen.queryByRole('link', { name: 'ET SCAN Potential SSH Scan' })).toBeNull();
  });
});

describe('Run backtest while a dependency is down', () => {
  it('is disabled when the grid is down, and says why', async () => {
    state.health = { ...HEALTHY, es: { ok: false, detail: 'refused', state: 'down', kind: 'refused' } } as Health;
    await mount(IDLE);
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /Run backtest/ })).toBeDisabled(),
    );
    expect(
      screen.getByText('The grid is down. A backtest needs the grid and the model gateway.'),
    ).toBeTruthy();
  });

  it('is disabled when the model gateway does not answer the probe', async () => {
    state.health = {
      ...HEALTHY,
      llm: { ok: false, detail: 'no answer', state: 'slow', kind: 'timeout' },
    } as Health;
    await mount(IDLE);
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /Run backtest/ })).toBeDisabled(),
    );
    expect(
      screen.getByText(
        'The model gateway is down. A backtest needs the grid and the model gateway.',
      ),
    ).toBeTruthy();
  });

  it('names both when both are down', async () => {
    const down = { ok: false, detail: 'refused', state: 'down' };
    state.health = { ...HEALTHY, es: down, llm: down } as Health;
    await mount(IDLE);
    expect(
      await screen.findByText(
        'The grid and the model gateway are down. A backtest needs the grid and the model gateway.',
      ),
    ).toBeTruthy();
  });

  it('stays enabled on a slow grid, a healthy pair and an unknown state', async () => {
    state.health = {
      ...HEALTHY,
      es: { ok: false, detail: 'slow', state: 'slow', kind: 'slow' },
    } as Health;
    await mount(IDLE);
    // Let the health read land before the assertion.
    await act(async () => {});
    expect(screen.getByRole('button', { name: /Run backtest/ })).toBeEnabled();
    expect(screen.queryByText(/is down/)).toBeNull();
  });

  it('stays enabled when the health read fails', async () => {
    state.healthFails = true;
    await mount(IDLE);
    await act(async () => {});
    expect(screen.getByRole('button', { name: /Run backtest/ })).toBeEnabled();
  });
});

describe('the cost of a run', () => {
  it('asks before a run, with the real count and time, and starts on confirm', async () => {
    await mount(IDLE);
    fireEvent.click(await screen.findByRole('button', { name: /Run backtest/ }));
    expect(startBacktestMock).not.toHaveBeenCalled();
    const confirm = await screen.findByTestId('backtest-confirm');
    expect(confirm).toHaveTextContent(
      'This backtest runs up to 20 investigations by the model. It takes about 40 minutes.',
    );
    fireEvent.click(within(confirm).getByRole('button', { name: 'Start backtest' }));
    await waitFor(() => expect(startBacktestMock).toHaveBeenCalledTimes(1));
    expect(startBacktestMock.mock.calls[0][0]).toMatchObject({ sampleSize: 20, windowDays: 30 });
  });

  it('counts the server cap, and states no time without history', async () => {
    await mount({ ...IDLE, max_sample: 10, estimate: null });
    fireEvent.click(await screen.findByRole('button', { name: /Run backtest/ }));
    const confirm = await screen.findByTestId('backtest-confirm');
    expect(confirm).toHaveTextContent(
      'This backtest runs up to 10 investigations by the model.',
    );
    expect(confirm).not.toHaveTextContent(/about/);
  });

  it('starts nothing on Cancel or Escape', async () => {
    await mount(IDLE);
    fireEvent.click(await screen.findByRole('button', { name: /Run backtest/ }));
    fireEvent.click(within(await screen.findByTestId('backtest-confirm')).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByTestId('backtest-confirm')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: /Run backtest/ }));
    const confirm = await screen.findByTestId('backtest-confirm');
    fireEvent.keyDown(confirm, { key: 'Escape' });
    expect(screen.queryByTestId('backtest-confirm')).toBeNull();
    expect(startBacktestMock).not.toHaveBeenCalled();
  });

  // Verify 2026-10-20, V3-N6. The confirm put the focus on "Start backtest",
  // so Enter started a run of about 42 minutes. After Cancel or Escape the
  // focus went to the page body.
  it('puts the focus on Cancel, and returns it to Run backtest on close', async () => {
    await mount(IDLE);
    const run = await screen.findByRole('button', { name: /Run backtest/ });
    fireEvent.click(run);
    const confirm = await screen.findByTestId('backtest-confirm');
    const cancel = within(confirm).getByRole('button', { name: 'Cancel' });
    expect(document.activeElement).toBe(cancel);
    // NEGATIVE CONTROL: Enter on the focused control starts nothing.
    expect(document.activeElement).not.toBe(
      within(confirm).getByRole('button', { name: 'Start backtest' }),
    );
    fireEvent.click(cancel);
    await waitFor(() => expect(document.activeElement).toBe(run));

    fireEvent.click(run);
    fireEvent.keyDown(await screen.findByTestId('backtest-confirm'), { key: 'Escape' });
    await waitFor(() => expect(document.activeElement).toBe(run));
    expect(document.activeElement).not.toBe(document.body);
    expect(startBacktestMock).not.toHaveBeenCalled();
  });

  it('names the cap in the form text', async () => {
    await mount(IDLE);
    expect(
      await screen.findByText(
        'Each sampled alert is one investigation by the model. The server caps the sample at 50 alerts. soc-ai samples only the alerts that your analysts closed.',
      ),
    ).toBeTruthy();
  });
});

describe('the past runs', () => {
  const summary = (id: string, over: Partial<BacktestRunSummary> = {}): BacktestRunSummary => ({
    backtest_id: id,
    status: 'complete',
    started_at: '2026-10-01T12:20:00Z',
    finished_at: '2026-10-01T12:34:19Z',
    sampled: 10,
    requested: 10,
    window_days: 14,
    min_severity: null,
    listed: false,
    agreement_rate: 0.6,
    fp_agreement_rate: 5 / 9,
    missed_tp: 0,
    human_tp: 1,
    human_fp: 9,
    ...over,
  });

  it('lists every run and opens an older one', async () => {
    state.runs = [
      summary('BT-NEW'),
      summary('BT-OLD', { finished_at: '2026-09-20T08:00:00Z', agreement_rate: 0.3 }),
      summary('BT-ERR', { status: 'error', agreement_rate: null, fp_agreement_rate: null }),
    ];
    state.byId['BT-OLD'] = run('BT-OLD', 'ET POLICY old rule');
    await mount(run('BT-NEW', 'ET INFO new rule'));
    const list = await screen.findByTestId('backtest-runs');
    expect(within(list).getAllByRole('listitem')).toHaveLength(3);
    expect(within(list).getByText('30% agreement')).toBeTruthy();
    expect(within(list).getByText('No score')).toBeTruthy();
    // The run on screen is marked, and its row opens nothing.
    const shown = within(list).getAllByRole('listitem')[0];
    expect(within(shown).getByRole('button', { name: 'Shown' })).toBeDisabled();

    const older = within(list).getByText('30% agreement').closest('li')!;
    fireEvent.click(within(older as HTMLElement).getByRole('button', { name: 'Open' }));
    await waitFor(() => expect(getBacktestByIdMock).toHaveBeenCalledWith('BT-OLD'));
    expect(await screen.findByText('ET POLICY old rule')).toBeTruthy();
    expect(screen.queryByText('ET INFO new rule')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Show the latest run' }));
    expect(await screen.findByText('ET INFO new rule')).toBeTruthy();
  });

  it('shows no list for one run', async () => {
    state.runs = [summary('BT-NEW')];
    await mount(run('BT-NEW', 'ET INFO new rule'));
    await screen.findByText('ET INFO new rule');
    expect(screen.queryByTestId('backtest-runs')).toBeNull();
  });
});
