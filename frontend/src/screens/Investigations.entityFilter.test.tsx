// The host page links the Investigations list filtered on one machine. A
// search for the host name found 1 of the 7 runs of a domain controller
// (dogfood 2026-10-19, R4-D3 and R4-I1). The list reads `?entity=`, asks the
// server for every run of the machine, and shows the filter as a chip.
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

const mount = (path: string) =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <Investigations />
    </MemoryRouter>,
  );

const lastQuery = () => listInvestigations.mock.calls[listInvestigations.mock.calls.length - 1][0];

beforeEach(() => {
  listInvestigations.mockReset().mockResolvedValue(list({ entityKeys: ['agent:ea2d', '192.0.2.10', 'dc01'] }));
  listSavedViews.mockReset().mockResolvedValue([]);
});

describe('Investigations: the machine filter', () => {
  it('asks the server for every run of the machine and shows the filter chip', async () => {
    mount('/investigations?entity=agent%3Aea2d&entity_label=dc01&range=all');
    await waitFor(() => expect(listInvestigations).toHaveBeenCalled());
    expect(lastQuery().entity).toBe('agent:ea2d');
    // All time: the host page counted every run of the machine.
    expect(lastQuery().since).toBeUndefined();
    const chip = await screen.findByTestId('inv-entity-filter');
    expect(chip.textContent).toContain('Host: dc01');
  });

  it('clears the filter from its chip', async () => {
    mount('/investigations?entity=agent%3Aea2d&entity_label=dc01&range=all');
    fireEvent.click(await screen.findByRole('button', { name: 'Clear the host filter' }));
    await waitFor(() => expect(lastQuery().entity).toBeUndefined());
    expect(screen.queryByTestId('inv-entity-filter')).toBeNull();
  });

  it('sends no entity and shows no chip without the parameter', async () => {
    // NEGATIVE CONTROL: the plain list is unchanged.
    mount('/investigations');
    await waitFor(() => expect(listInvestigations).toHaveBeenCalled());
    expect(lastQuery().entity).toBeUndefined();
    expect(screen.queryByTestId('inv-entity-filter')).toBeNull();
  });
});
