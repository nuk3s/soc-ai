// The entity page is where a user account lands. It held one timeline and
// nothing else, so the observations and the leads written against the account
// were unreachable from the page that names the account.
import { render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getEntity: vi.fn(),
  resolveMachine: vi.fn(),
  getObservations: vi.fn(),
  getLeads: vi.fn(),
}));

import { ApiError, getEntity, getLeads, getObservations, resolveMachine, type Lead } from '../lib/api';
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
  // An account belongs to no machine.
  vi.mocked(resolveMachine)
    .mockReset()
    .mockRejectedValue(new ApiError('No machine holds this value.', 404, 'no_host'));
});

describe('Entity hunting panels', () => {
  it('reads the observations on the entity and names the entity in the heading', async () => {
    mount();
    await waitFor(() => expect(getObservations).toHaveBeenCalledWith('svc_sql', 7));
    // The call is on record before its answer renders. Wait for the rows.
    expect(await screen.findByText(/Observations on this entity/)).toBeTruthy();
    expect(await screen.findByText('4769 for svc_sql from a workstation')).toBeTruthy();
  });

  it('asks the server for the leads that name this entity', async () => {
    // The server filters before its row limit. The strip read the newest 50
    // leads of the estate and kept the ones that named the entity, so an
    // older lead never showed. tests/test_leads_host_window.py pins the
    // negative control: the leads of another entity stay out.
    vi.mocked(getLeads).mockResolvedValue([LEAD]);
    mount();
    await waitFor(() => expect(getLeads).toHaveBeenCalledWith('all', { entity: 'svc_sql' }));
    const strip = await screen.findByTestId('leads-strip');
    expect(within(strip).getByText(/Leads on this entity/)).toBeTruthy();
    // The strip renders while the leads load. Wait for the row.
    expect(await within(strip).findByTestId('lead-12')).toBeTruthy();
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

  it('shows the panels on an address no machine holds too', async () => {
    // Dogfood 2026-10-06, S2: an address an investigation named had no host
    // page. The entity page is its page, and the leads and observations on it
    // belong here.
    vi.mocked(getEntity).mockResolvedValue({ ...ENTITY, value: '8.8.8.8', kind: 'ip' } as never);
    mount('8.8.8.8');
    expect(await screen.findByTestId('entity-hunting')).toBeTruthy();
    await waitFor(() => expect(getObservations).toHaveBeenCalledWith('8.8.8.8', 7));
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

// "Who is this and should I worry" (dogfood 2026-10-06, S5). The page held a
// timeline and two counts, and said nothing about what the value was.
describe('Entity identity and worry lines', () => {
  it('says an external address is outside the internal ranges', async () => {
    vi.mocked(getEntity).mockResolvedValue({
      ...ENTITY,
      value: '8.8.4.4',
      kind: 'ip',
      type: 'external_address',
      summary: {
        investigationCount: 2,
        huntFindingCount: 0,
        latestVerdict: 'true_positive',
        truePositiveCount: 2,
        leadCount: 1,
        openLeadCount: 1,
        observationCount: 0,
      },
      first_seen: iso(48 * HOUR),
      last_seen: iso(2 * HOUR),
    } as never);
    mount('8.8.4.4');
    expect((await screen.findByTestId('entity-identity')).textContent).toBe(
      '8.8.4.4 is an external address. It is outside the internal ranges.',
    );
    const worry = screen.getByTestId('entity-worry').textContent ?? '';
    expect(worry).toContain('1 open lead names it.');
    expect(worry).toContain('2 investigations reached a true-positive verdict.');
    expect(screen.getByTestId('entity-type').textContent).toBe('external address');
    const seen = screen.getByTestId('entity-seen').textContent ?? '';
    // Dogfood round 2 (V2-7): the entity page names soc-ai records as the
    // source. The host page names the grid.
    expect(seen).toContain('first soc-ai record 2d ago');
    expect(seen).toContain('last soc-ai record 2h ago');
    expect(seen).not.toContain('last seen');
    expect(screen.queryByTestId('entity-nothing-known')).toBeNull();
  });

  it('says when nothing is known', async () => {
    vi.mocked(getEntity).mockResolvedValue({
      ...ENTITY,
      value: 'ghost',
      type: 'name',
      summary: { investigationCount: 0, huntFindingCount: 0, leadCount: 0, observationCount: 0 },
      first_seen: null,
      last_seen: null,
    } as never);
    mount('ghost');
    expect((await screen.findByTestId('entity-nothing-known')).textContent).toBe(
      'soc-ai knows nothing about ghost yet. No investigation, hunt finding, lead or observation names it.',
    );
    expect(screen.queryByTestId('entity-worry')).toBeNull();
    expect(screen.getByTestId('entity-seen').textContent).toContain('no soc-ai record');
  });

  it('does not say nothing is known when a lead names the value', async () => {
    // NEGATIVE CONTROL: an empty timeline is not an empty record.
    vi.mocked(getEntity).mockResolvedValue({
      ...ENTITY,
      type: 'user',
      summary: { investigationCount: 0, huntFindingCount: 0, leadCount: 1, openLeadCount: 0, observationCount: 0 },
    } as never);
    mount();
    expect((await screen.findByTestId('entity-identity')).textContent).toBe('svc_sql is a user account.');
    expect(screen.queryByTestId('entity-nothing-known')).toBeNull();
    expect(screen.getByTestId('entity-worry').textContent).toBe(
      'No open lead names it. No investigation reached a true-positive verdict.',
    );
  });

  it('counts the addresses joined to a domain', async () => {
    vi.mocked(getEntity).mockResolvedValue({
      ...ENTITY,
      value: 'corp.example',
      type: 'domain',
      domain_machines: 3,
    } as never);
    mount('corp.example');
    expect((await screen.findByTestId('entity-identity')).textContent).toBe(
      'corp.example is a domain. 3 addresses are joined to it.',
    );
  });
});
