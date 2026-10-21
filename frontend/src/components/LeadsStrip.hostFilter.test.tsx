// "all leads" on the host page opened the Hunts page with every lead of the
// estate (dogfood 2026-10-19, R4-I2). The link now names the machine, and the
// Hunts page keeps the leads that name it until the analyst clears the chip.
// The heading also wrapped at 1280 px (R4-D24).
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getLeads: vi.fn(),
  getLeadCount: vi.fn(),
  getNeedsYou: vi.fn(),
}));

import { getLeadCount, getLeads, getNeedsYou, type Lead } from '../lib/api';
import { LeadsStrip, leadsHref } from './LeadsStrip';

const iso = new Date(Date.now() - 3_600_000).toISOString();

const LEAD: Lead = {
  id: 7,
  status: 'open',
  formed_at: iso,
  updated_at: iso,
  entities: [['host', '192.0.2.10']],
  kinds: ['novel_destination'],
  weight_at_formation: 1.0,
  scope_count: 1,
  hunt_id: null,
  shadow: false,
  single_signal: false,
  observations: [],
};

beforeEach(() => {
  vi.mocked(getLeads).mockReset().mockResolvedValue([LEAD]);
  vi.mocked(getLeadCount)
    .mockReset()
    .mockImplementation(async (status = 'open', query) => ({ status, entity: query?.entity ?? null, total: 1 }));
  vi.mocked(getNeedsYou).mockReset().mockRejectedValue(new Error('offline'));
});

describe('the leads link of a host', () => {
  it('opens the Hunts page filtered on the host', async () => {
    render(
      <MemoryRouter>
        <LeadsStrip entityKey="192.0.2.10" entityLabel="dc01" status="all" />
      </MemoryRouter>,
    );
    const link = await screen.findByTestId('leads-host-link');
    expect(link.getAttribute('href')).toBe(leadsHref('192.0.2.10', 'dc01'));
    expect(leadsHref('192.0.2.10', 'dc01')).toBe(
      '/hunts?lead_entity=192.0.2.10&lead_entity_label=dc01&leads=all#leads',
    );
    // The heading holds on one line.
    expect(screen.getByTestId('leads-heading').className).toContain('whitespace-nowrap');
  });
});

describe('the Hunts page with a host filter', () => {
  const mount = (path: string) =>
    render(
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/hunts" element={<LeadsStrip paramBound />} />
        </Routes>
      </MemoryRouter>,
    );

  it('reads the leads of the host and shows the filter chip', async () => {
    mount('/hunts?lead_entity=192.0.2.10&lead_entity_label=dc01&leads=all');
    const chip = await screen.findByTestId('leads-entity-filter');
    expect(chip.textContent).toContain('Host: dc01');
    await waitFor(() => expect(getLeads).toHaveBeenCalledWith('all', { entity: '192.0.2.10' }));
    expect(getLeadCount).toHaveBeenCalledWith('all', { entity: '192.0.2.10' });
  });

  it('clears the filter from its chip', async () => {
    mount('/hunts?lead_entity=192.0.2.10&lead_entity_label=dc01&leads=all');
    fireEvent.click(await screen.findByRole('button', { name: 'Clear the host filter' }));
    await waitFor(() => expect(getLeads).toHaveBeenLastCalledWith('all'));
    expect(screen.queryByTestId('leads-entity-filter')).toBeNull();
  });

  it('reads every lead without the parameter', async () => {
    // NEGATIVE CONTROL: the plain Hunts page is unchanged.
    mount('/hunts');
    await waitFor(() => expect(getLeads).toHaveBeenCalledWith('needs_decision'));
    expect(screen.queryByTestId('leads-entity-filter')).toBeNull();
  });
});
