// A host name the dossier knows stopped on "the timeline is empty" with no way
// to the host page, under a crumb that said "Alerts / Entity" (dogfood
// 2026-10-01, H8, RO13). A name whose machine had no alias join had no link
// at all: /entity/files01 held findings and no way to the machine (2026-10-02,
// U5). The page now asks GET /hosts/resolve, which reads every name source.
import { act, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getEntity: vi.fn(),
  resolveMachine: vi.fn(),
  getObservations: vi.fn(),
  getLeads: vi.fn(),
}));

import { ApiError, getEntity, getLeads, getObservations, resolveMachine } from '../lib/api';
import { Entity } from './Entity';

const NAMED = {
  value: 'dc01',
  kind: 'host' as const,
  timeline: [],
  summary: { investigationCount: 0, huntFindingCount: 0, latestVerdict: null },
  host_ip: '192.0.2.10',
};

const noMachine = () => new ApiError('No machine holds this value.', 404, 'no_host');

const mount = (value: string) =>
  render(
    <MemoryRouter initialEntries={[`/entity/${value}`]}>
      <Routes>
        <Route path="/entity/:value" element={<Entity />} />
      </Routes>
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getEntity).mockReset();
  vi.mocked(resolveMachine).mockReset().mockRejectedValue(noMachine());
  vi.mocked(getObservations).mockReset().mockResolvedValue({ entity: 'dc01', days: 7, observations: [] });
  vi.mocked(getLeads).mockReset().mockResolvedValue([]);
});

describe('Entity — a name that belongs to a machine', () => {
  it('links the name to its machine page, in the header and in the empty timeline', async () => {
    // The entity read has no host join for this name. The machine read does.
    vi.mocked(getEntity).mockResolvedValue({ ...NAMED, value: 'files01', host_ip: null } as never);
    vi.mocked(resolveMachine).mockResolvedValue({
      key: 'agent:ea2d',
      primary_ip: '192.0.2.129',
      matched: 'name',
    });
    mount('files01');
    const link = await screen.findByTestId('entity-host-link');
    expect(resolveMachine).toHaveBeenCalledWith('files01');
    expect(link.getAttribute('href')).toBe('/hosts/agent%3Aea2d');
    expect(link.textContent).toBe('machine 192.0.2.129 →');
    expect(
      screen.getByRole('link', { name: 'Open the machine page for 192.0.2.129.' }).getAttribute('href'),
    ).toBe('/hosts/agent%3Aea2d');
  });

  it('keeps the host link of the entity read when no machine answers', async () => {
    vi.mocked(getEntity).mockResolvedValue(NAMED as never);
    mount('dc01');
    await waitFor(() => expect(resolveMachine).toHaveBeenCalled());
    const link = await screen.findByTestId('entity-host-link');
    // That page resolves the address to its machine.
    expect(link.getAttribute('href')).toBe('/hosts/192.0.2.10');
  });

  it('names the entity in the crumb', async () => {
    vi.mocked(getEntity).mockResolvedValue(NAMED as never);
    mount('dc01');
    expect((await screen.findByTestId('entity-crumb')).textContent).toBe('dc01');
  });

  it('offers no link for a name no machine answers to', async () => {
    // Negative control: a shared label or an account names no machine page.
    vi.mocked(getEntity).mockResolvedValue({ ...NAMED, value: 'ws01', host_ip: null } as never);
    mount('ws01');
    await screen.findByTestId('entity-type');
    await waitFor(() => expect(resolveMachine).toHaveBeenCalledWith('ws01'));
    // Let the 404 settle before the negative read.
    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });
    expect(screen.queryByTestId('entity-host-link')).toBeNull();
    expect(screen.queryByText(/Open the machine page/)).toBeNull();
  });
});
