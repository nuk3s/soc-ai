// Backtest replays on the Investigations list. A replay measures the model on
// an alert an analyst already closed. On the range, 12 of 14 "true positives"
// in a week were replays with no mark, each offering "Escalate to case"
// (dogfood 2026-10-06). The server now leaves replays out by default. These
// tests pin the console half: the toggle asks the server for them, a replay
// row carries a grey chip, and the header line says what its figures count.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { InvestigationList, InvestigationRow } from '../lib/types';

const row = (over: Partial<InvestigationRow>): InvestigationRow => ({
  id: 'INV-X',
  name: 'ET MALWARE beacon',
  kind: 'suricata',
  verdict: 'true_positive',
  conf: 0.9,
  host: '192.0.2.10',
  dst: '198.51.100.7',
  status: 'complete',
  when: '1h ago',
  ts: '2026-07-15T01:00:00+00:00',
  alertId: 'ev-x',
  isPrimary: true,
  fallback: false,
  ranBy: 'analyst',
  ...over,
});

const list = (rows: InvestigationRow[], over: Partial<InvestigationList> = {}): InvestigationList => ({
  rows,
  total: rows.length,
  running: 0,
  truePositives: 0,
  totalAll: rows.length,
  active: false,
  limit: 50,
  offset: 0,
  ...over,
});

const listInvestigations = vi.hoisted(() => vi.fn());
const listSavedViews = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  listInvestigations,
  listSavedViews,
}));

import { countLine, Investigations } from './Investigations';

const mount = () =>
  render(
    <MemoryRouter initialEntries={['/investigations']}>
      <Investigations />
    </MemoryRouter>,
  );

const lastQuery = () => listInvestigations.mock.calls[listInvestigations.mock.calls.length - 1][0];

beforeEach(() => {
  listInvestigations.mockReset();
  listInvestigations.mockResolvedValue(list([]));
  listSavedViews.mockReset();
  listSavedViews.mockResolvedValue([]);
});

describe('the backtest replay toggle', () => {
  it('asks for no replays by default and for replays when turned on', async () => {
    listInvestigations.mockResolvedValue(list([row({ id: 'live' })], { totalAll: 3 }));
    mount();
    await screen.findByTestId('inv-name-live');
    expect(lastQuery().includeBacktest).toBeUndefined();
    const toggle = screen.getByTestId('show-backtest-replays');
    expect(toggle.getAttribute('aria-pressed')).toBe('false');
    expect(toggle.textContent).toBe('Show backtest replays');

    fireEvent.click(toggle);
    await waitFor(() => {
      expect(lastQuery().includeBacktest).toBe(true);
      expect(lastQuery().offset).toBe(0);
    });
    expect(screen.getByTestId('show-backtest-replays').getAttribute('aria-pressed')).toBe('true');

    // And off again: the request drops the parameter.
    fireEvent.click(screen.getByTestId('show-backtest-replays'));
    await waitFor(() => expect(lastQuery().includeBacktest).toBeUndefined());
  });
});

describe('the backtest replay chip', () => {
  it('marks a replay row and leaves a live row alone', async () => {
    listInvestigations.mockResolvedValue(
      list(
        [
          row({ id: 'replay', alertId: 'replay', ranBy: 'backtest' }),
          row({ id: 'live', alertId: 'ev-live', ranBy: 'scheduler' }),
        ],
        { backtestReplays: 1, includesBacktest: true },
      ),
    );
    mount();
    const chip = await screen.findByTestId('backtest-replay-replay');
    expect(chip.textContent).toBe('Backtest replay');
    expect(chip.getAttribute('title')).toMatch(/writes nothing to Security Onion/);
    // The control: a live run carries no chip.
    expect(screen.getByTestId('inv-name-live')).toBeTruthy();
    expect(screen.queryByTestId('backtest-replay-live')).toBeNull();
  });
});

describe('the header count line', () => {
  it('names the replays it does not count', async () => {
    listInvestigations.mockResolvedValue(
      list([row({ id: 'live' })], {
        total: 2,
        truePositives: 2,
        totalAll: 14,
        backtestReplays: 12,
        includesBacktest: false,
      }),
    );
    mount();
    await screen.findByTestId('inv-name-live');
    expect(screen.getByTestId('investigations-count').textContent).toBe(
      '2 investigations in the last 24 hours · 0 in progress · 2 true positives · 12 backtest replays not counted',
    );
  });

  it('names the replays it counts when they are shown', async () => {
    listInvestigations.mockResolvedValue(
      list([row({ id: 'live' })], {
        total: 14,
        truePositives: 14,
        totalAll: 14,
        backtestReplays: 12,
        includesBacktest: true,
      }),
    );
    mount();
    await screen.findByTestId('inv-name-live');
    expect(screen.getByTestId('investigations-count').textContent).toBe(
      '14 investigations in the last 24 hours · 0 in progress · 14 true positives · includes 12 backtest replays',
    );
  });

  it('adds nothing when no replay matches, or the server is older', () => {
    const base = { total: 3, running: 1, truePositives: 1, range: '7d', includesReplays: false };
    expect(countLine({ ...base, replays: 0 })).toBe(
      '3 investigations in the last 7 days · 1 in progress · 1 true positive',
    );
    expect(countLine({ ...base, replays: 1 })).toBe(
      '3 investigations in the last 7 days · 1 in progress · 1 true positive · 1 backtest replay not counted',
    );
  });

  it('says why the list is empty when only replays match', async () => {
    listInvestigations.mockResolvedValue(
      list([], { total: 0, totalAll: 2, backtestReplays: 2, includesBacktest: false }),
    );
    mount();
    expect(
      await screen.findByText('Only 2 backtest replays match. Turn on "Show backtest replays" to see them.'),
    ).toBeTruthy();
  });
});
