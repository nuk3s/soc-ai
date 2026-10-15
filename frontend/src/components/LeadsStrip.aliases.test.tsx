import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// One machine under two keys: the address and the host name. The strip read
// the newest 50 leads of the estate and kept the ones that named the host on
// the client, so a host lead older than the newest 50 never showed. The
// server now reads every key of the machine and filters before its row limit.
// tests/test_leads_host_window.py pins the join and its negative controls: a
// user named like the host and another host's leads stay out.
vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getLeads: vi.fn(),
  getLeadCount: vi.fn(),
}));

import { getLeadCount, getLeads, type Lead } from '../lib/api';
import { LeadsStrip } from './LeadsStrip';

const iso = new Date(Date.now() - 3_600_000).toISOString();

const lead = (id: number, entities: [string, string][]): Lead => ({
  id,
  status: 'open',
  formed_at: iso,
  updated_at: iso,
  entities,
  kinds: ['novel_process', 'off_hours'],
  weight_at_formation: 0.9,
  scope_count: 1,
  hunt_id: null,
  shadow: false,
  single_signal: false,
  observations: [],
});

beforeEach(() => {
  // What the server answers for the address: the lead on the address and
  // the lead stored under the host name.
  vi.mocked(getLeads)
    .mockReset()
    .mockResolvedValue([lead(3, [['host', '192.0.2.10']]), lead(14, [['host', 'DC01']])]);
  vi.mocked(getLeadCount).mockReset().mockResolvedValue({ status: 'all', entity: '192.0.2.10', total: 2 });
});

describe('LeadsStrip: one machine under two keys', () => {
  it('asks the server for the leads of the entity', async () => {
    render(
      <MemoryRouter>
        <LeadsStrip entityKey="192.0.2.10" status="all" />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getLeads).toHaveBeenCalledWith('all', { entity: '192.0.2.10' }));
    expect(getLeadCount).toHaveBeenCalledWith('all', { entity: '192.0.2.10' });
  });

  it('lists the leads on the address and on the host name', async () => {
    render(
      <MemoryRouter>
        <LeadsStrip entityKey="192.0.2.10" status="all" />
      </MemoryRouter>,
    );
    expect(await screen.findByTestId('lead-3')).toBeTruthy();
    // The server joined the host name. The strip does not drop it again.
    expect(screen.getByTestId('lead-14')).toBeTruthy();
  });
});
