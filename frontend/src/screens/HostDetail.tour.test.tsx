// The host page tour: every anchor it names is on the page. The render has a
// grid gap in the activity window and a machine with no agent, so the gap
// strip and the why-care strip both show. A renamed or removed `data-tour`
// attribute fails here.
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
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
  listInvestigations: vi.fn(),
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
  listInvestigations,
  resolveMachine,
} from '../lib/api';
import { HOST_TOUR } from '../tours/content';
import { missingAnchors } from '../tours/testing';
import { HostDetail } from './HostDetail';

const PRIMARY = '192.0.2.10';
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const ago = (ms: number) => new Date(Date.now() - ms).toISOString();

// A closed gap two hours long, inside the default 24h window.
const GAP: GridGap = {
  id: 1,
  source: 'probe',
  plane: null,
  started_at: ago(6 * HOUR),
  ended_at: ago(4 * HOUR),
  open: false,
  duration_s: 2 * 3_600,
  detail: 'The grid did not answer.',
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

function field(name: DossierFieldName, over: Partial<DossierField> = {}): DossierField {
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
    ...over,
  };
}

function dossier(ip: string): Dossier {
  return {
    ip,
    found: true,
    fields: FIELD_NAMES.map((name) =>
      name === 'os_family'
        ? field(name, {
            value: 'linux',
            source: 'telemetry',
            confidence: 0.9,
            strength: 'strong',
            reason: null,
            observed_at: ago(2 * HOUR),
            last_run_at: ago(2 * HOUR),
          })
        : field(name),
    ),
    first_seen: ago(30 * DAY),
    last_seen: ago(HOUR),
    last_built_at: ago(2 * HOUR),
    last_observed_at: ago(HOUR),
    event_count: 3662,
    identity_rebound_at: null,
    build_error: null,
    override_count: 0,
    conflict_count: 0,
    // No agent reports, so the why-care strip says so.
    reporting: false,
  };
}

const machine = (): MachineDetail => ({
  key: 'agent:ea2d',
  href: '/hosts/agent%3Aea2d',
  name: 'files01.example.test',
  name_source: 'dns',
  names: [{ value: 'files01.example.test', source: 'dns' }],
  primary_ip: PRIMARY,
  address_count: 1,
  addresses: [
    { ip: PRIMARY, kind: 'network', primary: true, first_seen: ago(30 * DAY), last_seen: ago(HOUR), events: 3662 },
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
  peers: [{ ip: '198.51.100.20', hostname: null, direction: 'out', ports: [443], events: 40, alerted: false }],
  volume: [{ ts: ago(2 * HOUR), events: 40 }],
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
  vi.mocked(listInvestigations).mockReset().mockResolvedValue({
    rows: [],
    total: 0,
    running: 0,
    truePositives: 0,
    totalAll: 0,
    active: false,
    limit: 3,
    offset: 0,
  });
});

describe('the host page tour', () => {
  it('finds every anchor it names on the page', async () => {
    render(
      <MemoryRouter initialEntries={['/hosts/agent%3Aea2d']}>
        <Routes>
          <Route path="/hosts/:key" element={<HostDetail />} />
        </Routes>
      </MemoryRouter>,
    );
    await screen.findByTestId('host-hero');
    // The gap strip, the activity panels and the no-agent line arrive with
    // their own reads.
    await screen.findByTestId('grid-gap-strip');
    await screen.findByTestId('host-volume');
    await screen.findByTestId('host-no-agent');

    expect(missingAnchors(HOST_TOUR)).toEqual([]);
  });
});
