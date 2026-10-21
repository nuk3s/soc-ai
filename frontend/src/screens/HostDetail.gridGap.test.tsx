// The host page names a grid gap inside the activity window (2026-10-19).
//
// The range grid was down for 93 hours. After it came back, the host charts
// and KPIs read the hole as a quiet host. The strip at the top of the activity
// section names each recorded gap that overlaps the 24h or 7d window.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { absoluteTime } from '../lib/timeRange';
import type {
  Dossier,
  DossierField,
  DossierFieldName,
  GridGap,
  HostActivity,
  MachineDetail,
} from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getDossier: vi.fn(),
  getMachine: vi.fn(),
  resolveMachine: vi.fn(),
  getHostActivity: vi.fn(),
  getDossierRefreshStatus: vi.fn(),
  getDossierSummary: vi.fn().mockResolvedValue({}),
  getMe: vi.fn(),
  getHostChat: vi.fn(),
  postHostChat: vi.fn(),
  clearHostChat: vi.fn(),
  getObservations: vi.fn(),
  getLeads: vi.fn(),
  getLeadCount: vi.fn(),
  getNeedsYou: vi.fn(),
  getGridGaps: vi.fn(),
}));

import {
  getDossier,
  getDossierRefreshStatus,
  getGridGaps,
  getHostActivity,
  getHostChat,
  getLeadCount,
  getLeads,
  getMachine,
  getMe,
  getNeedsYou,
  getObservations,
  resolveMachine,
} from '../lib/api';
import { HostDetail } from './HostDetail';

const PRIMARY = '192.0.2.10';
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const ago = (ms: number) => new Date(Date.now() - ms).toISOString();

const GAP: GridGap = {
  id: 1,
  source: 'sweep',
  plane: 'connection_rate',
  started_at: '2026-10-15T13:36:00Z',
  ended_at: '2026-10-15T14:21:00Z',
  open: false,
  duration_s: 2_700,
  detail: 'Documents stopped on most hosts of the connection_rate plane.',
};

const FIELD_NAMES: DossierFieldName[] = [
  'hostname',
  'mac',
  'os_family',
  'os_detail',
  'role',
  'services_offered',
  'management_plane',
  'domain_membership',
  'is_static_addressed',
  'activity_profile',
  'criticality',
  'policy_notes',
];

function field(name: DossierFieldName): DossierField {
  return {
    field: name,
    value: null,
    value_json: null,
    source: null,
    confidence: 0,
    strength: 'none',
    reason: 'no_signal',
    overridden: false,
    conflict_kind: null,
    evidence: {},
    observed_at: null,
    first_seen: null,
    last_run_at: null,
    retracted_at: null,
    operator_actor: null,
    operator_note: null,
    operator_set_at: null,
    inferred_value: null,
    inferred_value_json: null,
    inferred_confidence: null,
    inferred_source: null,
    conflict: null,
  };
}

function dossier(ip: string): Dossier {
  return {
    ip,
    found: true,
    fields: FIELD_NAMES.map((name) => field(name)),
    first_seen: ago(30 * DAY),
    last_seen: ago(HOUR),
    last_built_at: ago(2 * HOUR),
    last_observed_at: ago(HOUR),
    event_count: 3662,
    identity_rebound_at: null,
    build_error: null,
    override_count: 0,
    conflict_count: 0,
    reporting: false,
  };
}

const machine = (): MachineDetail => ({
  key: 'agent:ea2d',
  href: '/hosts/agent%3Aea2d',
  name: 'files01',
  name_source: 'agent',
  names: [{ value: 'files01', source: 'agent' }],
  primary_ip: PRIMARY,
  address_count: 1,
  addresses: [
    { ip: PRIMARY, kind: 'agent', primary: true, first_seen: ago(30 * DAY), last_seen: ago(HOUR), events: 3662 },
  ],
  container_count: 0,
  containers: [],
  agent: null,
  role: { value: null, label: null, confidence: null, state: 'unknown', guess: null, stale_hours: null },
  events: 3662,
  first_seen: ago(30 * DAY),
  last_seen: ago(HOUR),
  flags: { declared: false, conflict: false, broken: false, new: false, rebound: false },
  macs: [],
  merged_from: [],
  dossier: dossier(PRIMARY),
});

const activity = (): HostActivity => ({
  peers: [],
  volume: [],
  users: null,
  alerts_7d: 0,
  latest_investigation: null,
  peers_truncated: false,
  users_truncated: false,
});

beforeEach(() => {
  sessionStorage.clear();
  vi.mocked(getDossier).mockReset().mockImplementation(async (ip) => dossier(ip));
  vi.mocked(getMachine).mockReset().mockResolvedValue(machine());
  vi.mocked(resolveMachine)
    .mockReset()
    .mockResolvedValue({ key: 'agent:ea2d', primary_ip: PRIMARY, matched: 'address' });
  vi.mocked(getHostActivity).mockReset().mockResolvedValue(activity());
  vi.mocked(getDossierRefreshStatus)
    .mockReset()
    .mockResolvedValue({ running: false, last_run: null, last_summary: { errors: [] }, note: null });
  vi.mocked(getMe).mockReset().mockResolvedValue({ username: 'ana', role: 'analyst', status: '' });
  vi.mocked(getHostChat).mockReset().mockResolvedValue({ messages: [], pending: false });
  vi.mocked(getObservations).mockReset().mockResolvedValue({ entity: PRIMARY, days: 7, observations: [] });
  vi.mocked(getLeads).mockReset().mockResolvedValue([]);
  vi.mocked(getLeadCount)
    .mockReset()
    .mockImplementation(async (status = 'open', query) => ({ status, entity: query?.entity ?? null, total: 0 }));
  vi.mocked(getNeedsYou).mockReset().mockRejectedValue(new Error('offline'));
  vi.mocked(getGridGaps).mockReset().mockImplementation(async (window) => ({
    since: window.since,
    until: window.until ?? new Date().toISOString(),
    gaps: [GAP],
  }));
});

const mount = (path: string) =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/hosts/:key" element={<HostDetail />} />
      </Routes>
    </MemoryRouter>,
  );

// The strip and the Connections rate both read the gaps of the window.
const asked = (back: number) =>
  vi
    .mocked(getGridGaps)
    .mock.calls.some(([window]) => Math.abs(Date.now() - back - new Date(window.since).getTime()) < 60_000);

describe('the host page grid gap strip', () => {
  it('names the gap in the activity section', async () => {
    mount('/hosts/agent%3Aea2d');
    await screen.findByTestId('host-hero');
    expect((await screen.findByTestId('grid-gap')).textContent).toBe(
      `Most hosts sent no network flow documents from ${absoluteTime('2026-10-15T13:36:00Z')} to ${absoluteTime('2026-10-15T14:21:00Z')} (45 min). Counts in this window are incomplete.`,
    );
  });

  it('reads the gaps for the activity window', async () => {
    mount('/hosts/agent%3Aea2d');
    await screen.findByTestId('grid-gap-strip');
    expect(asked(DAY)).toBe(true);
    expect(asked(7 * DAY)).toBe(false);

    fireEvent.click(screen.getByRole('button', { name: '7d' }));
    await waitFor(() => expect(asked(7 * DAY)).toBe(true));
  });

  it('leaves the gap hours out of the Connections rate (V2-1)', async () => {
    const end = Math.floor(Date.now() / HOUR) * HOUR;
    // Four busy hours, then 20 hours of stray records inside a sweep gap.
    const volume = Array.from({ length: 24 }, (_, i) => ({
      ts: new Date(end - 24 * HOUR + i * HOUR).toISOString(),
      events: i < 4 ? 300 : 3,
    }));
    vi.mocked(getHostActivity).mockResolvedValue({
      ...activity(),
      volume,
      peers: [{ ip: '192.0.2.20', hostname: null, direction: 'out', ports: [443], events: 1, alerted: false }],
      window_end: new Date(end).toISOString(),
    });
    const recent: GridGap = {
      ...GAP,
      started_at: new Date(end - 20 * HOUR).toISOString(),
      ended_at: new Date(end).toISOString(),
      duration_s: 20 * 3_600,
    };
    vi.mocked(getGridGaps).mockImplementation(async (window) => ({
      since: window.since,
      until: new Date().toISOString(),
      gaps: [recent],
    }));
    mount('/hosts/agent%3Aea2d');
    await waitFor(() =>
      expect(screen.getByTestId('kpi-events-rate').textContent).toBe(
        '300 per hour in and out over the 4 hours with data',
      ),
    );
  });
});
