// The time of an investigation is the time of its event (owner, 2026-11-15).
//
// A hunt and a Re-run judged events of 3 and 17 days ago, and the When column
// read "1h ago", "6h ago" and "10h ago". The column states the time of the
// event. A second line states the time of the investigation when it is more
// than one hour later. The Failed view reads the time of the investigation:
// a pipeline error is a fact about what soc-ai did.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { InvestigationList, InvestigationRow } from '../lib/types';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const row = (over: Partial<InvestigationRow>): InvestigationRow =>
  ({
    id: 'INV-X',
    name: 'ET EXPLOIT Example Upload Request',
    kind: 'suricata',
    verdict: 'true_positive',
    conf: 0.9,
    host: '10.40.50.7',
    dst: '10.20.30.5',
    status: 'complete',
    when: '1h',
    ts: iso(HOUR + 60_000),
    alertId: 'ev-x',
    isPrimary: true,
    fallback: false,
    ...over,
  }) as InvestigationRow;

const list = (rows: InvestigationRow[]): InvestigationList => ({
  rows,
  total: rows.length,
  running: 0,
  truePositives: rows.length,
  totalAll: rows.length,
  active: false,
  limit: 50,
  offset: 0,
});

const listInvestigations = vi.hoisted(() => vi.fn());
const listSavedViews = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  listInvestigations,
  listSavedViews,
}));

import { Investigations, clockFromSearch, countLine, rowTime } from './Investigations';

const mount = (url = '/investigations?range=30d') =>
  render(
    <MemoryRouter initialEntries={[url]}>
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

describe('the When cell', () => {
  it('states the event time and the later investigation on a second line', async () => {
    listInvestigations.mockResolvedValue(
      list([row({ id: 'OLD', eventAt: iso(17 * DAY), eventWhen: '17d', ts: iso(HOUR + 60_000) })]),
    );
    mount();
    const cell = await screen.findByTestId('when-OLD');
    expect(cell.firstElementChild?.textContent).toBe('17d ago');
    expect(screen.getByTestId('investigated-OLD').textContent).toBe('investigated 1h ago');
    expect(cell.getAttribute('title')).toMatch(
      /^Event \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC\. Investigated \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC\.$/,
    );
  });

  it('states one time when the investigation is at most one hour later', async () => {
    listInvestigations.mockResolvedValue(
      list([row({ id: 'NEW', eventAt: iso(2 * HOUR), ts: iso(HOUR + 60_000) })]),
    );
    mount();
    const cell = await screen.findByTestId('when-NEW');
    expect(cell.textContent).toBe('2h ago');
    expect(screen.queryByTestId('investigated-NEW')).toBeNull();
  });

  it('sorts the page by the time of the event', async () => {
    listInvestigations.mockResolvedValue(
      list([
        // Investigated now, on an event of 10 days ago.
        row({ id: 'A', eventAt: iso(10 * DAY), ts: iso(60_000) }),
        // Investigated 2 days ago, on an event of 2 days ago.
        row({ id: 'B', eventAt: iso(2 * DAY + 60_000), ts: iso(2 * DAY) }),
      ]),
    );
    mount();
    await screen.findByTestId('when-A');
    const order = screen.getAllByTestId(/^when-/).map((el) => el.getAttribute('data-testid'));
    expect(order).toEqual(['when-B', 'when-A']);
  });
});

describe('the clock', () => {
  it('reads the time of the event by default and the time of the investigation for Failed', () => {
    expect(clockFromSearch('?range=24h')).toBe('event');
    expect(clockFromSearch('?view=failed')).toBe('investigated');
    expect(clockFromSearch('?verdict=pipeline_error&errors=live')).toBe('investigated');
    expect(clockFromSearch('?clock=investigated&verdict=false_positive')).toBe('investigated');
    // A negative control: a URL that names the event clock keeps it on the Failed view.
    expect(clockFromSearch('?view=failed&clock=event')).toBe('event');
  });

  it('sends no clock for the default list and the investigation clock for Failed', async () => {
    mount('/investigations?range=24h');
    await screen.findByTestId('investigations-count');
    expect(lastQuery().clock).toBeUndefined();
    listInvestigations.mockClear();
    mount('/investigations?view=failed');
    await screen.findByTestId('investigated-clock-filter');
    expect(lastQuery().clock).toBe('investigated');
  });

  it('names the clock in the count line', () => {
    const base = { running: 0, truePositives: 0, replays: 0, includesReplays: false, total: 3 };
    expect(countLine({ ...base, range: '30d', clock: 'investigated' })).toBe(
      '3 investigations started in the last 30 days · 0 in progress · 0 true positives',
    );
    expect(countLine({ ...base, range: '30d' })).toBe(
      '3 investigations in the last 30 days · 0 in progress · 0 true positives',
    );
  });

  it('reads the time of a row on each clock', () => {
    const r = row({ eventAt: '2026-11-01T00:00:00+00:00', ts: '2026-11-15T00:00:00+00:00' });
    expect(rowTime(r)).toBe('2026-11-01T00:00:00+00:00');
    expect(rowTime(r, 'investigated')).toBe('2026-11-15T00:00:00+00:00');
    expect(rowTime(row({ eventAt: undefined, ts: '2026-11-15T00:00:00+00:00' }))).toBe(
      '2026-11-15T00:00:00+00:00',
    );
  });
});
