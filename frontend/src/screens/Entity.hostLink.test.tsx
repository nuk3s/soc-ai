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
