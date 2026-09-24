// The entity page is where a user account lands. It held one timeline and
// nothing else, so the observations and the leads written against the account
// were unreachable from the page that names the account.
import { render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getEntity: vi.fn(),
  getObservations: vi.fn(),
  getLeads: vi.fn(),
}));

import { getEntity, getLeads, getObservations, type Lead } from '../lib/api';
import { ENTITY_ADDRESS, ENTITY_NAME } from '../lib/tooltips';
import { Entity } from './Entity';

const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const ENTITY = {
  value: 'svc_sql',
  kind: 'host' as const,
  timeline: [],
  summary: { investigationCount: 0, huntFindingCount: 0, latestVerdict: null },
};

const OBSERVATION = {
  id: 91,
  kind: 'catalog_match',
  spec_id: 'identity-4769-service-ticket',
  source: 'catalog',
  shadow: false,
  summary: '4769 for svc_sql from a workstation',
  weight_now: 0.62,
  lead_id: 12,
  born_at: iso(3 * HOUR),
  occurrences: 2,
  read: true,
};

const LEAD: Lead = {
  id: 12,
  status: 'open',
  formed_at: iso(2 * HOUR),
  updated_at: iso(2 * HOUR),
  entities: [['user', 'svc_sql']],
  kinds: ['catalog_match', 'off_hours'],
  weight_at_formation: 0.91,
  scope_count: 1,
  hunt_id: null,
  shadow: false,
  single_signal: false,
  observations: [],
};

const OTHER_LEAD: Lead = { ...LEAD, id: 13, entities: [['user', 'svc_web']] };

function mount(value = 'svc_sql') {
  return render(
    <MemoryRouter initialEntries={[`/entity/${value}`]}>
      <Routes>
        <Route path="/entity/:value" element={<Entity />} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.mocked(getEntity).mockReset().mockResolvedValue(ENTITY as never);
  vi.mocked(getObservations)
    .mockReset()
    .mockResolvedValue({ entity: 'svc_sql', days: 7, observations: [OBSERVATION] });
  vi.mocked(getLeads).mockReset().mockResolvedValue([LEAD, OTHER_LEAD]);
});

describe('Entity hunting panels', () => {
  it('reads the observations on the entity and names the entity in the heading', async () => {
    mount();
    await waitFor(() => expect(getObservations).toHaveBeenCalledWith('svc_sql', 7));
    expect(screen.getByText(/Observations on this entity/)).toBeTruthy();
    expect(screen.getByText('4769 for svc_sql from a workstation')).toBeTruthy();
  });

  it('reads every lead and keeps the ones that name this entity', async () => {
    mount();
    await waitFor(() => expect(getLeads).toHaveBeenCalledWith('all'));
    const strip = await screen.findByTestId('leads-strip');
    expect(within(strip).getByText(/Leads on this entity/)).toBeTruthy();
    expect(within(strip).getByTestId('lead-12')).toBeTruthy();
    expect(within(strip).queryByTestId('lead-13')).toBeNull();
  });

  it('links each lead row to the lead', async () => {
    mount();
    const row = await screen.findByTestId('lead-12');
    expect(within(row).getByText('Lead 12').getAttribute('href')).toBe('/leads/12');
  });

  it('offers the status filter on the strip', async () => {
    mount();
    await screen.findByTestId('leads-strip');
    expect(screen.getByRole('button', { name: 'All' }).getAttribute('aria-pressed')).toBe('true');
    expect(screen.getByRole('button', { name: 'Closed' })).toBeTruthy();
  });

  it('leaves the panels off an address, because the host page holds them', async () => {
    vi.mocked(getEntity).mockResolvedValue({ ...ENTITY, value: '8.8.8.8', kind: 'ip' } as never);
    mount('8.8.8.8');
    await waitFor(() => expect(getEntity).toHaveBeenCalled());
    expect(screen.queryByTestId('entity-hunting')).toBeNull();
    expect(getObservations).not.toHaveBeenCalled();
  });
});

// The header chip read "host" over a user account, because the server calls
// anything that is not an address a host. The chip says what the page knows
// instead of naming a class it cannot read.
describe('Entity header chip', () => {
  it('calls a value that is not an address a name, and says what that means', async () => {
    mount();
    const chip = await screen.findByTestId('entity-type');
    expect(chip.textContent).toBe('name');
    expect(chip.getAttribute('title')).toBe(ENTITY_NAME);
  });

  it('calls an address an address', async () => {
    vi.mocked(getEntity).mockResolvedValue({ ...ENTITY, value: '8.8.8.8', kind: 'ip' } as never);
    mount('8.8.8.8');
    const chip = await screen.findByTestId('entity-type');
    expect(chip.textContent).toBe('address');
    expect(chip.getAttribute('title')).toBe(ENTITY_ADDRESS);
  });
});
