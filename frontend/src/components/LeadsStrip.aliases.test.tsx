// A lead on the host name belongs on the address's page. The page keyed by IP
// listed leads 3 to 6 and missed lead 14, which named the machine by host
// name (dogfood 2026-10-01, RO1).
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getLeads: vi.fn(),
}));

import { getLeads, type Lead } from '../lib/api';
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
  vi.mocked(getLeads)
    .mockReset()
    .mockResolvedValue([
      lead(3, [['host', '192.0.2.10']]),
      lead(14, [['host', 'DC01']]),
      lead(15, [['user', 'dc01']]),
      lead(16, [['host', 'dc02']]),
    ]);
});

describe('LeadsStrip — one machine under two keys', () => {
  it('lists the leads on the address and on the host name, in any case', async () => {
    render(
      <MemoryRouter>
        <LeadsStrip entityKey="192.0.2.10" aliases={['dc01.example.test', 'dc01']} status="all" />
      </MemoryRouter>,
    );
    expect(await screen.findByTestId('lead-3')).toBeTruthy();
    expect(screen.getByTestId('lead-14')).toBeTruthy();
  });

  it('never joins a user account or another host through an alias', async () => {
    // Negative control: a user named like the host, and a different host.
    render(
      <MemoryRouter>
        <LeadsStrip entityKey="192.0.2.10" aliases={['dc01']} status="all" />
      </MemoryRouter>,
    );
    await screen.findByTestId('lead-3');
    expect(screen.queryByTestId('lead-15')).toBeNull();
    expect(screen.queryByTestId('lead-16')).toBeNull();
  });
});
