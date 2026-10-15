import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// The owner rule: a page filters everything by its time filter, unless the
// screen labels it otherwise in visible words. A backlog count keeps its full
// scope and says so. The heading counted the rows it held, and the list stops
// at 50, so the Hunts page never said more than "50 need a decision".
vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getLeads: vi.fn(),
  getLeadCount: vi.fn(),
  getNeedsYou: vi.fn(),
}));

import { getLeadCount, getLeads, getNeedsYou, type Lead } from '../lib/api';
import { LeadsStrip } from './LeadsStrip';

const iso = new Date(Date.now() - 3_600_000).toISOString();

const LEAD: Lead = {
  id: 7,
  status: 'open',
  formed_at: iso,
  updated_at: iso,
  entities: [['host', '192.0.2.10']],
  kinds: ['novel_destination', 'off_hours'],
  weight_at_formation: 1.0,
  scope_count: 1,
  hunt_id: null,
  shadow: false,
  single_signal: false,
  observations: [],
};

const mountHunts = (path = '/hunts') =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/hunts" element={<LeadsStrip paramBound />} />
      </Routes>
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getLeads).mockReset().mockResolvedValue([LEAD]);
  vi.mocked(getLeadCount)
    .mockReset()
    .mockImplementation(async (status = 'open') => ({ status, entity: null, total: 73 }));
  vi.mocked(getNeedsYou).mockReset().mockRejectedValue(new Error('offline'));
});

describe('the leads heading on the Hunts page', () => {
  it('counts every lead that waits, past the rows on screen', async () => {
    mountHunts();
    const heading = await screen.findByTestId('leads-heading');
    await waitFor(() => expect(heading.textContent).toContain('73 need a decision'));
    expect(getLeadCount).toHaveBeenCalledWith('needs_decision');
    // The scope is visible text, not a hover.
    expect(screen.getByTestId('leads-scope').textContent).toBe('all open');
  });

  it('says the list holds the newest rows of a larger set', async () => {
    mountHunts();
    expect((await screen.findByTestId('leads-capped')).textContent).toBe(
      'The list shows the newest 1 of 73 leads.',
    );
  });

  it('says all time on the tabs that hold closed leads', async () => {
    mountHunts('/hunts?leads=closed');
    await waitFor(() => expect(screen.getByTestId('leads-heading').textContent).toContain('73 closed leads'));
    expect(screen.getByTestId('leads-scope').textContent).toBe('all time');
  });

  it('counts the rows when the server cannot count', async () => {
    // Negative control: no total, no claim of a larger set.
    vi.mocked(getLeadCount).mockRejectedValue(new Error('offline'));
    mountHunts();
    const heading = await screen.findByTestId('leads-heading');
    await waitFor(() => expect(heading.textContent).toContain('1 needs a decision'));
    expect(screen.getByTestId('leads-scope').textContent).toBe('all open');
    expect(screen.queryByTestId('leads-capped')).toBeNull();
  });

  it('adds no note when every lead is on screen', async () => {
    vi.mocked(getLeadCount).mockResolvedValue({ status: 'needs_decision', entity: null, total: 1 });
    mountHunts();
    await screen.findByTestId('lead-7');
    await waitFor(() => expect(getLeadCount).toHaveBeenCalled());
    expect(screen.queryByTestId('leads-capped')).toBeNull();
  });
});

describe('the leads heading on a host page', () => {
  it('reads the host total from the server and says all time on the All tab', async () => {
    vi.mocked(getLeadCount).mockResolvedValue({ status: 'all', entity: '192.0.2.10', total: 4 });
    render(
      <MemoryRouter>
        <LeadsStrip entityKey="192.0.2.10" status="all" />
      </MemoryRouter>,
    );
    const heading = await screen.findByTestId('leads-heading');
    await waitFor(() => expect(heading.textContent).toContain('4 leads'));
    expect(heading.textContent).toContain('Leads on this host');
    expect(getLeadCount).toHaveBeenCalledWith('all', { entity: '192.0.2.10' });
    expect(screen.getByTestId('leads-scope').textContent).toBe('all time');
  });
});
