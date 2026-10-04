// Bulk declare had no undo, and its bar sat at the top of the screen, out of
// sight for the lower rows (dogfood 2026-10-01, RO9). Undo removes what the
// last bulk declaration set and nothing else: an address that held a
// declaration before gets that value back.
//
// The list is one row per machine now, and a row carries no per-field lanes.
// The declare writes the primary address of each selected machine, and the
// value each address held before is read off its own dossier.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Dossier, DossierSummary, MachineRow, MachineSummary } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  listMachines: vi.fn(),
  getMachineSummary: vi.fn(),
  getDossier: vi.fn(),
  getDossierConflicts: vi.fn(),
  getDossierSummary: vi.fn(),
  getDossierRefreshStatus: vi.fn(),
  startDossierRefresh: vi.fn(),
  getMe: vi.fn(),
  bulkSetDossierOverride: vi.fn(),
  clearDossierOverride: vi.fn(),
  setDossierOverride: vi.fn(),
  listSavedViews: vi.fn(),
}));

import {
  bulkSetDossierOverride,
  clearDossierOverride,
  getDossier,
  getDossierConflicts,
  getDossierRefreshStatus,
  getDossierSummary,
  getMachineSummary,
  getMe,
  listMachines,
  listSavedViews,
  setDossierOverride,
} from '../lib/api';
import { Hosts } from './Hosts';

const machine = (key: string, ip: string): MachineRow => ({
  key,
  href: `/hosts/${encodeURIComponent(key)}`,
  name: null,
  name_source: null,
  names: [],
  primary_ip: ip,
  address_count: 1,
  addresses: [ip],
  container_count: 0,
  agent: null,
  role: { value: null, label: null, confidence: null, state: 'unknown', guess: null, stale_hours: null },
  events: 4,
  first_seen: null,
  last_seen: null,
  flags: { declared: false, conflict: false, broken: false, new: false, rebound: false },
});

/** The dossier of one address, with the criticality it holds now. */
const dossier = (ip: string, criticality: string | null): Dossier =>
  ({
    ip,
    found: true,
    fields: [
      {
        field: 'criticality',
        value: criticality,
        value_json: null,
        source: criticality ? 'operator' : null,
        confidence: criticality ? 1 : 0,
        strength: criticality ? 'strong' : 'none',
        reason: criticality ? null : 'no_signal',
        overridden: !!criticality,
        conflict_kind: null,
      },
    ],
  }) as unknown as Dossier;

const SUMMARY: MachineSummary = {
  machines: 2,
  addresses: 2,
  with_agent: 0,
  without_agent: 2,
  new_7d: 0,
  named: 0,
  unnamed: 2,
  roles: { unknown: 2 },
  needs_attention: 0,
  conflicts: 0,
  never_built: 0,
  last_sweep_at: new Date().toISOString(),
  stale_hours: null,
};

const CENSUS: DossierSummary = {
  hosts: 2,
  never_built: 0,
  named: 0,
  reporting: 0,
  conflicts: 0,
  roles: {},
  last_built_at: new Date().toISOString(),
  schedule_enabled: true,
};

beforeEach(() => {
  vi.mocked(listMachines)
    .mockReset()
    .mockResolvedValue({
      rows: [machine('ip:198.51.100.29', '198.51.100.29'), machine('mac:aa:bb:cc:dd:ee:33', '198.51.100.33')],
      total: 2,
      limit: 50,
      offset: 0,
      sort: 'last_seen',
      dir: 'desc',
    });
  vi.mocked(getMachineSummary).mockReset().mockResolvedValue(SUMMARY);
  // .29 held no declaration; .33 held "high".
  vi.mocked(getDossier)
    .mockReset()
    .mockImplementation(async (ip) => dossier(ip, ip === '198.51.100.33' ? 'high' : null));
  vi.mocked(getDossierConflicts).mockReset().mockResolvedValue({ pending: 0, rows: [] });
  vi.mocked(getDossierSummary).mockReset().mockResolvedValue(CENSUS);
  vi.mocked(getDossierRefreshStatus)
    .mockReset()
    .mockResolvedValue({ running: false, last_run: null, last_summary: null, note: null });
  vi.mocked(getMe).mockReset().mockResolvedValue({ username: 'root', role: 'admin', status: '' });
  vi.mocked(bulkSetDossierOverride)
    .mockReset()
    .mockResolvedValue({ updated: ['198.51.100.29', '198.51.100.33'], not_found: [], failed: [] });
  vi.mocked(clearDossierOverride).mockReset().mockResolvedValue({} as never);
  vi.mocked(setDossierOverride).mockReset().mockResolvedValue({} as never);
  vi.mocked(listSavedViews).mockReset().mockResolvedValue([]);
});

const mount = () =>
  render(
    <MemoryRouter initialEntries={['/hosts']}>
      <Hosts />
    </MemoryRouter>,
  );

async function declareLowOnBoth() {
  mount();
  fireEvent.click(await screen.findByLabelText(/select all hosts/i));
  fireEvent.change(await screen.findByDisplayValue('choose…'), { target: { value: 'low' } });
  fireEvent.click(screen.getByRole('button', { name: /declare \(2\)/i }));
}

describe('Hosts — bulk declare', () => {
  it('keeps the bulk bar on screen while rows are selected', async () => {
    mount();
    const toolbar = await screen.findByTestId('hosts-toolbar');
    expect(toolbar.className).not.toContain('sticky');
    fireEvent.click(await screen.findByLabelText(/select all hosts/i));
    await waitFor(() => expect(screen.getByTestId('hosts-toolbar').className).toContain('sticky'));
  });

  it('undoes the last bulk declaration and restores what each address held', async () => {
    await declareLowOnBoth();
    const undo = await screen.findByTestId('bulk-undo');
    expect(undo.textContent).toBe('Undo criticality "low" (2)');
    fireEvent.click(undo);

    // The address with no declaration before loses the one the bulk set.
    await waitFor(() => expect(clearDossierOverride).toHaveBeenCalledWith('198.51.100.29', 'criticality'));
    // Negative control: the address that was "high" gets "high" back. Clearing
    // it would remove a declaration the bulk never made.
    expect(setDossierOverride).toHaveBeenCalledWith('198.51.100.33', {
      field: 'criticality',
      value: 'high',
    });
    expect(clearDossierOverride).not.toHaveBeenCalledWith('198.51.100.33', 'criticality');
    await waitFor(() => expect(screen.queryByTestId('bulk-undo')).toBeNull());
  });

  it('leaves an address alone when its earlier value could not be read', async () => {
    // A failed read is not "no declaration". Undo would clear a value it
    // never saw, so the address keeps the bulk value and the note says so.
    vi.mocked(getDossier).mockImplementation(async (ip) => {
      if (ip === '198.51.100.33') throw new Error('503 Service Unavailable');
      return dossier(ip, null);
    });
    await declareLowOnBoth();
    const undo = await screen.findByTestId('bulk-undo');
    expect(undo.textContent).toBe('Undo criticality "low" (1)');
    fireEvent.click(undo);
    await waitFor(() => expect(clearDossierOverride).toHaveBeenCalledWith('198.51.100.29', 'criticality'));
    expect(clearDossierOverride).not.toHaveBeenCalledWith('198.51.100.33', 'criticality');
    expect(setDossierOverride).not.toHaveBeenCalled();
    expect(await screen.findByText(/1 machine kept the declaration/)).toBeTruthy();
  });
});
