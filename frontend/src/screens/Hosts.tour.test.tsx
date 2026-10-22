// The Hosts page tour: every anchor it names is on the page. An admin sees
// the bulk checkboxes, and an open disagreement shows the queue, so this
// render holds every anchor. A renamed or removed `data-tour` attribute
// fails here.
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { DossierSummary, MachineList, MachineRow, MachineSummary } from '../lib/types';

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
  listSavedViews: vi.fn(),
}));

import {
  getDossierConflicts,
  getDossierRefreshStatus,
  getDossierSummary,
  getMachineSummary,
  getMe,
  listMachines,
  listSavedViews,
} from '../lib/api';
import { HOSTS_TOUR } from '../tours/content';
import { missingAnchors } from '../tours/testing';
import { Hosts } from './Hosts';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const ago = (ms: number) => new Date(Date.now() - ms).toISOString();

const NO_FLAGS = { declared: false, conflict: false, broken: false, new: false, rebound: false };

const WEB: MachineRow = {
  key: 'agent:a1',
  href: '/hosts/agent%3Aa1',
  name: 'web01.example.test',
  name_source: 'agent',
  names: [{ value: 'web01.example.test', source: 'agent' }],
  primary_ip: '192.0.2.10',
  address_count: 2,
  addresses: ['192.0.2.10', '198.51.100.4'],
  container_count: 0,
  agent: { id: 'a1', name: 'web01', os: 'Ubuntu 24.04', last_report: ago(HOUR) },
  role: { value: 'server', label: 'server', confidence: 0.9, state: 'inferred', guess: null, stale_hours: null },
  events: 11158,
  first_seen: ago(30 * DAY),
  last_seen: ago(HOUR),
  flags: { ...NO_FLAGS, conflict: true },
};

const QUIET: MachineRow = {
  ...WEB,
  key: 'ip:192.0.2.20',
  href: '/hosts/ip%3A192.0.2.20',
  name: null,
  name_source: null,
  names: [],
  primary_ip: '192.0.2.20',
  address_count: 1,
  addresses: ['192.0.2.20'],
  agent: null,
  role: { value: null, label: null, confidence: 0.4, state: 'low_confidence', guess: 'printer', stale_hours: null },
  events: 12,
  first_seen: ago(3 * DAY),
  last_seen: ago(2 * HOUR),
  flags: NO_FLAGS,
};

const page = (rows: MachineRow[]): MachineList => ({
  rows,
  total: rows.length,
  limit: 50,
  offset: 0,
  sort: 'last_seen',
  dir: 'desc',
});

const SUMMARY: MachineSummary = {
  machines: 2,
  addresses: 3,
  with_agent: 1,
  without_agent: 1,
  new_7d: 1,
  named: 1,
  unnamed: 1,
  roles: { server: 1, low_confidence: 1, stale: 0, unknown: 0 },
  needs_attention: 0,
  conflicts: 1,
  never_built: 0,
  last_sweep_at: ago(2 * HOUR),
  stale_hours: null,
};

const CENSUS: DossierSummary = {
  hosts: 3,
  never_built: 0,
  named: 1,
  reporting: 1,
  conflicts: 1,
  roles: { server: 1 },
  last_built_at: ago(2 * HOUR),
  schedule_enabled: true,
};

beforeEach(() => {
  sessionStorage.clear();
  vi.mocked(listMachines).mockReset().mockResolvedValue(page([WEB, QUIET]));
  vi.mocked(getMachineSummary).mockReset().mockResolvedValue(SUMMARY);
  vi.mocked(getDossierSummary).mockReset().mockResolvedValue(CENSUS);
  vi.mocked(getDossierConflicts)
    .mockReset()
    .mockResolvedValue({
      pending: 1,
      rows: [
        {
          ip: '192.0.2.10',
          field: 'role',
          kind: 'mismatch',
          first_seen_at: ago(3 * DAY),
          observations: 4,
          last_prompted_at: null,
          prompt_count: 1,
          snoozed_until: null,
          operator_value: 'hypervisor',
          operator_value_json: null,
          inferred_value: 'server',
          inferred_value_json: null,
          identity_rebound_at: null,
          href: '/hosts/192.0.2.10',
        },
      ],
    });
  vi.mocked(getDossierRefreshStatus)
    .mockReset()
    .mockResolvedValue({ running: false, last_run: ago(2 * HOUR), last_summary: null, note: null });
  vi.mocked(getMe).mockReset().mockResolvedValue({ username: 'root', role: 'admin', status: '' });
  vi.mocked(listSavedViews).mockReset().mockResolvedValue([]);
});

describe('the Hosts page tour', () => {
  it('finds every anchor it names on the page', async () => {
    render(
      <MemoryRouter initialEntries={['/hosts']}>
        <Routes>
          <Route path="/hosts" element={<Hosts />} />
        </Routes>
      </MemoryRouter>,
    );
    await screen.findByRole('link', { name: 'web01.example.test, 192.0.2.10' });
    // The admin checkbox and the disagreement queue arrive with their reads.
    await screen.findByRole('checkbox', { name: 'Select every machine on this page' });
    await screen.findByText(/1 disagreement needs review/);

    expect(missingAnchors(HOSTS_TOUR)).toEqual([]);
    // The row anchor sits on the first row only.
    expect(document.querySelectorAll('[data-tour="hosts-row"]')).toHaveLength(1);
    expect(screen.getByTestId(`machine-row-${WEB.key}`).getAttribute('data-tour')).toBe('hosts-row');
  });
});
