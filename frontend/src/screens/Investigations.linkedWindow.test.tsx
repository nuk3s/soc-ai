// A link into the Investigations list opens on the window it names (dogfood
// 2026-10-19, R1-D7): the 24h "Open them" on the Dashboard opened a 30-day
// list, because a ?verdict= link forced 30 days. The Needs-you line "N
// recommended actions wait for you" opens the runs with a pending action
// (R1-I1). It opened every true positive.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { InvestigationList } from '../lib/types';

const list = (over: Partial<InvestigationList> = {}): InvestigationList => ({
  rows: [],
  total: 0,
  running: 0,
  truePositives: 0,
  totalAll: 0,
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

const mount = (url: string) =>
  render(
    <MemoryRouter initialEntries={[url]}>
      <Investigations />
    </MemoryRouter>,
  );

const lastQuery = () => listInvestigations.mock.calls[listInvestigations.mock.calls.length - 1][0];
const HOUR = 3_600_000;

beforeEach(() => {
  listInvestigations.mockReset();
  listInvestigations.mockResolvedValue(list());
  listSavedViews.mockReset();
  listSavedViews.mockResolvedValue([]);
});

describe('the window a link names', () => {
  it('keeps a 24h window beside a verdict filter', async () => {
    mount('/investigations?range=24h&verdict=true_positive');
    await waitFor(() => expect(lastQuery().verdict).toEqual(['true_positive']));
    const since = new Date(lastQuery().since).getTime();
    // 24 hours back, not 30 days back.
    expect(Math.abs(Date.now() - since - 24 * HOUR)).toBeLessThan(5 * 60_000);
  });

  it('opens 30 days for a verdict link that names no window', async () => {
    mount('/investigations?verdict=pipeline_error');
    await waitFor(() => expect(lastQuery().verdict).toEqual(['pipeline_error']));
    const since = new Date(lastQuery().since).getTime();
    expect(Math.abs(Date.now() - since - 30 * 24 * HOUR)).toBeLessThan(5 * 60_000);
  });

  it('opens a custom window with its bounds', async () => {
    mount('/investigations?range=custom&from=2026-10-08T00:00&to=2026-10-09T00:00&verdict=true_positive');
    await waitFor(() => expect(lastQuery().verdict).toEqual(['true_positive']));
    expect(lastQuery().since).toBe(new Date('2026-10-08T00:00').toISOString());
    expect(lastQuery().until).toBe(new Date('2026-10-09T00:00').toISOString());
  });
});

describe('the runs with a pending action', () => {
  it('asks the server for them and says so on the filter bar', async () => {
    mount('/investigations?range=30d&actions=pending');
    await waitFor(() => expect(lastQuery().pendingAction).toBe(true));
    const chip = await screen.findByTestId('pending-actions-filter');
    expect(chip.textContent).toBe('Action waits for you ✓');
    // The chip clears the filter.
    fireEvent.click(chip);
    await waitFor(() => expect(lastQuery().pendingAction).toBeUndefined());
    expect(screen.queryByTestId('pending-actions-filter')).toBeNull();
  });

  it('asks for every run without the param', async () => {
    mount('/investigations');
    await waitFor(() => expect(listInvestigations).toHaveBeenCalled());
    expect(lastQuery().pendingAction).toBeUndefined();
  });
});
