// The Investigations filters live in the URL (dogfood 2026-10-19, R2-D13 and
// R2-I6).
//
// The window, the Verdict and Status filters, the search, the group-by and the
// backtest toggle stayed in component state. A reload returned the list to
// 24 hours with every filter off, and a copied address opened a different
// list. Each filter now goes into the query string on change, with a history
// replace, and comes back from it on load. Alerts keeps its filters the same
// way.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, useLocation, useNavigate, useNavigationType } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { pickerValue } from '../components/TimeRangeFilter';
import type { InvestigationList, InvestigationRow } from '../lib/types';

const row = (over: Partial<InvestigationRow>): InvestigationRow => ({
  id: 'INV-X',
  name: 'ET INFO NTLM Session Setup Request',
  kind: 'suricata',
  verdict: 'false_positive',
  conf: 0.8,
  host: '192.0.2.10',
  dst: '198.51.100.7',
  status: 'complete',
  when: '2h',
  ts: new Date(Date.now() - 2 * 3_600_000).toISOString(),
  alertId: 'ev-x',
  isPrimary: true,
  fallback: false,
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

import { Investigations } from './Investigations';

/** The address bar, the last navigation type and two links to this screen. */
function Probe() {
  const location = useLocation();
  const type = useNavigationType();
  const navigate = useNavigate();
  return (
    <>
      <div data-testid="loc">{location.pathname + location.search}</div>
      <div data-testid="nav-type">{type}</div>
      <button onClick={() => navigate('/investigations?range=30d&verdict=needs_more_info')}>
        open the needs-more-info link
      </button>
      <button onClick={() => navigate('/investigations')}>open the nav entry</button>
      <button onClick={() => navigate(-1)}>go back</button>
    </>
  );
}

const mount = (url: string) =>
  render(
    <MemoryRouter initialEntries={[url]}>
      <Investigations />
      <Probe />
    </MemoryRouter>,
  );

/** The query string the screen shows in the address bar now. */
const params = () =>
  new URL(screen.getByTestId('loc').textContent ?? '', 'http://x').searchParams;

const lastQuery = () =>
  listInvestigations.mock.calls[listInvestigations.mock.calls.length - 1][0];

/** The span of a `since` bound up to now, in hours. */
const hoursBack = (since: string) => (Date.now() - new Date(since).getTime()) / 3_600_000;

beforeEach(() => {
  listInvestigations.mockReset();
  listInvestigations.mockResolvedValue(list([row({})]));
  listSavedViews.mockReset();
  listSavedViews.mockResolvedValue([]);
});

describe('the filters in the URL', () => {
  it('writes each filter to the URL with a replace', async () => {
    mount('/investigations');
    await screen.findByTestId('inv-name-INV-X');
    // The default list keeps the plain address.
    expect(screen.getByTestId('loc').textContent).toBe('/investigations');

    fireEvent.click(screen.getByText('7d'));
    await waitFor(() => expect(params().get('range')).toBe('7d'));
    expect(screen.getByTestId('nav-type').textContent).toBe('REPLACE');

    fireEvent.click(screen.getByRole('button', { name: 'Verdict' }));
    fireEvent.click(screen.getByLabelText('True positive'));
    fireEvent.click(screen.getByLabelText('Needs more info'));
    await waitFor(() => expect(params().get('verdict')).toBe('true_positive,needs_more_info'));

    fireEvent.click(screen.getByRole('button', { name: 'Status' }));
    fireEvent.click(screen.getByLabelText('Failed: error'));
    await waitFor(() => expect(params().get('status')).toBe('error'));

    fireEvent.click(screen.getByText('Group by detection'));
    await waitFor(() => expect(params().get('group')).toBe('detection'));

    fireEvent.click(screen.getByTestId('show-backtest-replays'));
    await waitFor(() => expect(params().get('backtest')).toBe('1'));

    // A typed search replaces the entry. Every keystroke is not a Back step.
    fireEvent.change(screen.getByLabelText('Search investigations'), {
      target: { value: '192.0.2.10' },
    });
    await waitFor(() => expect(params().get('q')).toBe('192.0.2.10'));
    expect(screen.getByTestId('nav-type').textContent).toBe('REPLACE');
    // The window stays.
    expect(params().get('range')).toBe('7d');
  });

  it('takes a filter out of the URL when the analyst clears it', async () => {
    mount('/investigations?group=detection&backtest=1&q=192.0.2.10');
    await screen.findByTestId('inv-name-INV-X');
    fireEvent.click(screen.getByText(/Group by detection/));
    fireEvent.click(screen.getByTestId('show-backtest-replays'));
    fireEvent.change(screen.getByLabelText('Search investigations'), { target: { value: '' } });
    await waitFor(() => expect(screen.getByTestId('loc').textContent).toBe('/investigations'));
  });

  it('restores every filter from the URL on a reload', async () => {
    mount(
      '/investigations?range=7d&verdict=true_positive&status=error&q=192.0.2.10&group=detection&backtest=1',
    );
    await screen.findByTestId('inv-name-INV-X');
    const q = listInvestigations.mock.calls[0][0];
    expect(hoursBack(q.since)).toBeGreaterThan(7 * 24 - 0.1);
    expect(hoursBack(q.since)).toBeLessThan(7 * 24 + 0.1);
    expect(q.verdict).toEqual(['true_positive']);
    expect(q.status).toEqual(['error']);
    expect(q.q).toBe('192.0.2.10');
    expect(q.includeBacktest).toBe(true);
    expect((screen.getByLabelText('Search investigations') as HTMLInputElement).value).toBe(
      '192.0.2.10',
    );
    expect(screen.getByText(/Group by detection ✓/)).toBeTruthy();
    expect(screen.getByText(/Show backtest replays ✓/)).toBeTruthy();
    expect(screen.getByTestId('investigations-count').textContent).toContain('in the last 7 days');
    // The screen does not rewrite an address that already holds its filters.
    expect(params().get('range')).toBe('7d');
    expect(params().get('verdict')).toBe('true_positive');
  });

  it('keeps a custom window over a reload', async () => {
    const from = pickerValue(Date.now() - 10 * 86_400_000);
    const to = pickerValue(Date.now() - 2 * 86_400_000);
    mount(`/investigations?range=custom&from=${from}&to=${to}`);
    await screen.findByTestId('inv-name-INV-X');
    const q = listInvestigations.mock.calls[0][0];
    expect(q.since).toBe(new Date(from).toISOString());
    expect(q.until).toBe(new Date(to).toISOString());
    expect(params().get('range')).toBe('custom');
    expect(params().get('from')).toBe(from);
    expect(params().get('to')).toBe(to);
  });

  it('writes a custom window that the analyst picks', async () => {
    mount('/investigations');
    await screen.findByTestId('inv-name-INV-X');
    fireEvent.click(screen.getByLabelText('Custom date range'));
    const [fromBox, toBox] = Array.from(
      document.querySelectorAll<HTMLInputElement>('input[type="datetime-local"]'),
    );
    const from = pickerValue(Date.now() - 5 * 86_400_000);
    const to = pickerValue(Date.now() - 86_400_000);
    fireEvent.change(fromBox, { target: { value: from } });
    fireEvent.change(toBox, { target: { value: to } });
    fireEvent.click(screen.getByText('Apply'));
    await waitFor(() => expect(params().get('range')).toBe('custom'));
    expect(params().get('from')).toBe(from);
    expect(params().get('to')).toBe(to);
  });

  it('keeps the all-time window over a reload', async () => {
    mount('/investigations?range=all');
    await screen.findByTestId('inv-name-INV-X');
    expect(listInvestigations.mock.calls[0][0].since).toBeUndefined();
    expect(params().get('range')).toBe('all');
  });

  it('keeps the deep link of the pipeline-error tile', async () => {
    mount('/investigations?verdict=pipeline_error&errors=live');
    await screen.findByTestId('inv-name-INV-X');
    const q = listInvestigations.mock.calls[0][0];
    expect(q.verdict).toEqual(['pipeline_error']);
    expect(q.errorState).toBe('live');
    expect(hoursBack(q.since)).toBeGreaterThan(30 * 24 - 0.1);
    expect(params().get('verdict')).toBe('pipeline_error');
    expect(params().get('errors')).toBe('live');
  });

  it('leaves the window it widened on its own out of the URL', async () => {
    // A reload makes the same landing guess again, and the note says why.
    const threeDaysAgo = new Date(Date.now() - 3 * 86_400_000).toISOString();
    listInvestigations
      .mockResolvedValueOnce(list([], { total: 0, totalAll: 4 }))
      .mockResolvedValueOnce(list([row({ ts: threeDaysAgo })], { total: 1, totalAll: 4 }))
      .mockResolvedValue(list([row({ ts: threeDaysAgo })], { total: 1, totalAll: 4 }));
    mount('/investigations');
    expect(await screen.findByText(/1 investigation in the last 7 days/)).toBeTruthy();
    expect(screen.getByTestId('window-widened')).toBeTruthy();
    expect(params().get('range')).toBeNull();
    // A window the analyst picks goes into the URL.
    fireEvent.click(screen.getByText('30d'));
    await waitFor(() => expect(params().get('range')).toBe('30d'));
  });
});

describe('a link to the screen while it is open', () => {
  it('applies the filters of the link and drops the old ones', async () => {
    mount('/investigations?q=192.0.2.10&status=error');
    await screen.findByTestId('inv-name-INV-X');
    fireEvent.click(screen.getByText('open the needs-more-info link'));
    await waitFor(() => expect(lastQuery().verdict).toEqual(['needs_more_info']));
    const q = lastQuery();
    expect(q.q).toBeUndefined();
    expect(q.status).toEqual([]);
    expect(hoursBack(q.since)).toBeGreaterThan(30 * 24 - 0.1);
    expect((screen.getByLabelText('Search investigations') as HTMLInputElement).value).toBe('');
    expect(params().get('verdict')).toBe('needs_more_info');
    expect(params().get('range')).toBe('30d');
    expect(params().get('q')).toBeNull();
  });

  it('restores the filters of the earlier entry on Back', async () => {
    mount('/investigations?q=192.0.2.10&status=error');
    await screen.findByTestId('inv-name-INV-X');
    fireEvent.click(screen.getByText('open the needs-more-info link'));
    await waitFor(() => expect(lastQuery().verdict).toEqual(['needs_more_info']));
    fireEvent.click(screen.getByText('go back'));
    await waitFor(() => expect(lastQuery().q).toBe('192.0.2.10'));
    expect(lastQuery().status).toEqual(['error']);
    expect(lastQuery().verdict).toEqual([]);
    expect((screen.getByLabelText('Search investigations') as HTMLInputElement).value).toBe(
      '192.0.2.10',
    );
  });

  it('keeps the filters on screen for the bare nav entry, and puts them back in the URL', async () => {
    mount('/investigations?range=7d&group=detection');
    await screen.findByTestId('inv-name-INV-X');
    const calls = listInvestigations.mock.calls.length;
    fireEvent.click(screen.getByText('open the nav entry'));
    await waitFor(() => expect(params().get('range')).toBe('7d'));
    expect(params().get('group')).toBe('detection');
    expect(screen.getByText(/Group by detection ✓/)).toBeTruthy();
    // The same filters, so no new read.
    expect(listInvestigations.mock.calls.length).toBe(calls);
  });
});
