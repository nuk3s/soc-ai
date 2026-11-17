// The card of an authorized activity links to the runs that matched it. The
// list reads `?authorization=`, asks the server for those runs, and shows the
// filter as a chip. The runs stay in the plain list too, each with its chip.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { InvestigationList, InvestigationRow } from '../lib/types';

const row = (over: Partial<InvestigationRow> = {}): InvestigationRow =>
  ({
    id: 'INV-1',
    name: 'ET EXPLOIT PHP php2shell Nested Empty File Control OOM (CVE-2026-109618)',
    kind: 'suricata',
    verdict: 'true_positive',
    conf: 0.85,
    host: '10.50.0.26',
    dst: '10.40.0.164',
    status: 'complete',
    when: '1h',
    ts: new Date().toISOString(),
    alertId: 'alert-1',
    isPrimary: true,
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

const AUTHORIZED = {
  id: 3,
  label: 'php2shell test',
  state: 'active' as const,
  expiresAt: '2099-01-01T00:00:00+00:00',
  by: 'casey',
};

const listInvestigations = vi.hoisted(() => vi.fn());
const listSavedViews = vi.hoisted(() => vi.fn());
const getAuthorizedActivity = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  listInvestigations,
  listSavedViews,
  getAuthorizedActivity,
}));

import { Investigations, authorizationFromSearch } from './Investigations';

const mount = (path: string) =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <Investigations />
    </MemoryRouter>,
  );

const lastQuery = () => listInvestigations.mock.calls[listInvestigations.mock.calls.length - 1][0];

beforeEach(() => {
  listInvestigations
    .mockReset()
    .mockResolvedValue(
      list([
        row({ authorizationId: 3, authorization: AUTHORIZED }),
        row({ id: 'INV-2', alertId: 'alert-2', host: '10.50.0.200' }),
      ]),
    );
  listSavedViews.mockReset().mockResolvedValue([]);
  getAuthorizedActivity.mockReset().mockResolvedValue({ rows: [], active: 0 });
});

describe('Investigations: the authorized activity filter', () => {
  it('asks the server for the runs of one record and names it on the chip', async () => {
    mount('/investigations?authorization=3&range=all');
    await waitFor(() => expect(listInvestigations).toHaveBeenCalled());
    expect(lastQuery().authorization).toBe(3);
    // Every window: the card counted every run of the record.
    expect(lastQuery().since).toBeUndefined();
    const chip = await screen.findByTestId('inv-authorization-filter');
    await waitFor(() => expect(chip.textContent).toContain('Authorized activity: php2shell test'));
  });

  it('clears the filter from its chip', async () => {
    mount('/investigations?authorization=3&range=all');
    fireEvent.click(
      await screen.findByRole('button', { name: 'Clear the authorized activity filter' }),
    );
    await waitFor(() => expect(lastQuery().authorization).toBeUndefined());
    expect(screen.queryByTestId('inv-authorization-filter')).toBeNull();
  });

  it('keeps an authorized run in the plain list, with its chip', async () => {
    // NEGATIVE CONTROL: no filter, and the run is still a row of the list.
    mount('/investigations?range=all');
    await waitFor(() => expect(listInvestigations).toHaveBeenCalled());
    expect(lastQuery().authorization).toBeUndefined();
    expect(screen.queryByTestId('inv-authorization-filter')).toBeNull();
    const chips = await screen.findAllByTestId('authorized-chip');
    expect(chips).toHaveLength(1);
    expect(await screen.findByTestId('inv-tags-INV-2')).toBeTruthy();
    expect(screen.getByTestId('inv-tags-INV-2').textContent).not.toContain('Authorized activity');
  });

  it('reads only a whole positive number from the link', () => {
    expect(authorizationFromSearch('?authorization=3')).toBe(3);
    expect(authorizationFromSearch('?authorization=abc')).toBeNull();
    expect(authorizationFromSearch('?authorization=-1')).toBeNull();
    expect(authorizationFromSearch('?authorization=1.5')).toBeNull();
    expect(authorizationFromSearch('')).toBeNull();
  });
});
