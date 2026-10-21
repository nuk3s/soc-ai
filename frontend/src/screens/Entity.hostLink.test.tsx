// A machine's value opens the machine page (dogfood 2026-10-06, S1). A host
// name the dossier knows used to stop on "the timeline is empty" (2026-10-01,
// H8), and then on a page with a link to the machine (2026-10-02, U5). Every
// entity link in the console now lands here, so the page moves a machine's
// value on to the machine page and keeps the rest.
import { act, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getEntity: vi.fn(),
  resolveMachine: vi.fn(),
  getObservations: vi.fn(),
  getLeads: vi.fn(),
  getNeedsYou: vi.fn(),
}));

import { ApiError, getEntity, getLeads, getNeedsYou, getObservations, resolveMachine } from '../lib/api';
import { Entity } from './Entity';

const NAMED = {
  value: 'dc01',
  kind: 'host' as const,
  type: 'name' as const,
  timeline: [],
  summary: { investigationCount: 0, huntFindingCount: 0, latestVerdict: null },
  host_ip: null,
};

const noMachine = () => new ApiError('No machine holds this value.', 404, 'no_host');

function Here() {
  const loc = useLocation();
  return <div data-testid="here">{`${loc.pathname}${loc.search}`}</div>;
}

const mount = (path: string) =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/entity/:value" element={<Entity />} />
        <Route path="/hosts/:key" element={<Here />} />
      </Routes>
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getEntity).mockReset().mockResolvedValue(NAMED as never);
  vi.mocked(resolveMachine).mockReset().mockRejectedValue(noMachine());
  vi.mocked(getObservations).mockReset().mockResolvedValue({ entity: 'dc01', days: 7, observations: [] });
  vi.mocked(getLeads).mockReset().mockResolvedValue([]);
  vi.mocked(getNeedsYou).mockReset().mockRejectedValue(new Error('offline'));
});

describe('Entity: a value a machine holds', () => {
  it('opens the machine page for a name', async () => {
    vi.mocked(resolveMachine).mockResolvedValue({
      key: 'agent:ea2d',
      primary_ip: '192.0.2.129',
      matched: 'name',
    });
    mount('/entity/files01');
    expect((await screen.findByTestId('here')).textContent).toBe('/hosts/agent%3Aea2d');
    expect(resolveMachine).toHaveBeenCalledWith('files01');
  });

  it('opens the machine page for an address and keeps the address in focus', async () => {
    vi.mocked(resolveMachine).mockResolvedValue({
      key: 'agent:ea2d',
      primary_ip: '192.0.2.129',
      matched: 'address',
    });
    mount('/entity/192.0.2.130');
    expect((await screen.findByTestId('here')).textContent).toBe(
      '/hosts/agent%3Aea2d?address=192.0.2.130',
    );
  });

  it('keeps the entity page with view=entity, and links the machine', async () => {
    vi.mocked(resolveMachine).mockResolvedValue({
      key: 'agent:ea2d',
      primary_ip: '192.0.2.129',
      matched: 'name',
    });
    mount('/entity/files01?view=entity');
    const link = await screen.findByTestId('entity-host-link');
    expect(link.getAttribute('href')).toBe('/hosts/agent%3Aea2d');
    expect(link.textContent).toBe('machine 192.0.2.129 →');
    expect(screen.queryByTestId('here')).toBeNull();
  });

  it('never asks for the machine of a user', async () => {
    // NEGATIVE CONTROL: an account that shares a name with a machine.
    vi.mocked(resolveMachine).mockResolvedValue({
      key: 'agent:ea2d',
      primary_ip: '192.0.2.129',
      matched: 'name',
    });
    vi.mocked(getEntity).mockResolvedValue({ ...NAMED, value: 'backup', type: 'user' } as never);
    mount('/entity/backup?type=user');
    expect((await screen.findByTestId('entity-identity')).textContent).toBe(
      'backup is a user account.',
    );
    expect(resolveMachine).not.toHaveBeenCalled();
    expect(getEntity).toHaveBeenCalledWith('backup', 'user');
    expect(screen.queryByTestId('here')).toBeNull();
  });

  it('names the entity in the crumb', async () => {
    mount('/entity/dc01');
    expect((await screen.findByTestId('entity-crumb')).textContent).toBe('dc01');
  });

  it('offers no machine link for a name no machine answers to', async () => {
    // Negative control: a shared label or an account names no machine page.
    mount('/entity/ws01');
    await screen.findByTestId('entity-type');
    await waitFor(() => expect(resolveMachine).toHaveBeenCalledWith('ws01'));
    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });
    expect(screen.queryByTestId('entity-host-link')).toBeNull();
    expect(screen.queryByTestId('here')).toBeNull();
  });
});

// Dogfood 2026-10-19, R4-D2 and R4-D23. The address view said "No machine in
// the census holds it" beside the chip of the machine, and its counts read
// the address alone. A user page wore the host icon.
describe('Entity: the counts of a machine', () => {
  const ADDRESS = {
    ...NAMED,
    value: '192.0.2.130',
    kind: 'ip' as const,
    type: 'address' as const,
    host_key: 'agent:ea2d',
    host_name: 'files01',
    machine_keys: ['192.0.2.130', '192.0.2.129', 'files01', 'a-ea2d', 'agent:ea2d'],
    summary: {
      investigationCount: 7,
      huntFindingCount: 2,
      latestVerdict: 'true_positive',
      truePositiveCount: 6,
    },
  };

  it('names the machine of an address and the keys the counts read', async () => {
    vi.mocked(resolveMachine).mockResolvedValue({
      key: 'agent:ea2d',
      primary_ip: '192.0.2.129',
      matched: 'address',
    });
    vi.mocked(getEntity).mockResolvedValue(ADDRESS as never);
    mount('/entity/192.0.2.130?view=entity');
    const line = await screen.findByTestId('entity-identity');
    expect(line.textContent).toBe('192.0.2.130 is an internal address of the machine files01.');
    expect((await screen.findByTestId('entity-keys')).textContent).toBe(
      'The counts cover every key of the machine: 192.0.2.130, 192.0.2.129, files01 and a-ea2d.',
    );
  });

  it('says that no machine holds an address only when none does', async () => {
    // NEGATIVE CONTROL: an address no machine holds reads itself only.
    vi.mocked(getEntity).mockResolvedValue({
      ...ADDRESS,
      value: '198.51.100.7',
      host_key: null,
      host_name: null,
      machine_keys: ['198.51.100.7'],
    } as never);
    mount('/entity/198.51.100.7');
    expect((await screen.findByTestId('entity-identity')).textContent).toBe(
      '198.51.100.7 is an internal address. No machine holds it.',
    );
    expect(screen.queryByTestId('entity-keys')).toBeNull();
  });

  it('wears the user icon on a user page', async () => {
    vi.mocked(getEntity).mockResolvedValue({ ...NAMED, value: 'backup', type: 'user' } as never);
    mount('/entity/backup?type=user');
    expect((await screen.findByTestId('entity-icon')).getAttribute('data-type')).toBe('user');
  });

  it('wears the host icon on an address page', async () => {
    // NEGATIVE CONTROL: the icon follows the type.
    vi.mocked(getEntity).mockResolvedValue({ ...ADDRESS, host_key: null, machine_keys: [] } as never);
    mount('/entity/192.0.2.130');
    expect((await screen.findByTestId('entity-icon')).getAttribute('data-type')).toBe('host');
  });
});
