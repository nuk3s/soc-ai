// The host page, read from its first screen (dogfood 2026-10-06, hosts S2 to
// S4 and architecture change 4). The range attacker's page opened on "has
// appeared on the network. Nothing else is known about it yet." and "ALERTS
// 7D 0 · nothing fired", while lower on the page sat six alert verdicts and a
// hunted lead. These tests pin what the page says before the first scroll.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  Dossier,
  DossierField,
  DossierFieldName,
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
  listInvestigations: vi.fn(),
  setDossierOverride: vi.fn(),
  clearDossierOverride: vi.fn(),
}));

import {
  ApiError,
  getDossier,
  getDossierRefreshStatus,
  getHostActivity,
  getHostChat,
  getLeadCount,
  getLeads,
  getMachine,
  getMe,
  getNeedsYou,
  getObservations,
  clearDossierOverride,
  listInvestigations,
  resolveMachine,
  setDossierOverride,
} from '../lib/api';
import { absTime } from '../lib/timeRange';
import { HostDetail } from './HostDetail';

const PRIMARY = '192.0.2.10';

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

function dossier(
  ip: string,
  patch: Partial<Record<DossierFieldName, Partial<DossierField>>> = {},
  over: Partial<Dossier> = {},
): Dossier {
  return {
    ip,
    found: true,
    fields: FIELD_NAMES.map((name) => field(name, patch[name] ?? {})),
    first_seen: '2026-09-01T08:00:00Z',
    last_seen: '2026-10-01T09:00:00Z',
    last_built_at: '2026-10-01T06:00:00Z',
    last_observed_at: '2026-10-01T09:00:00Z',
    event_count: 3662,
    identity_rebound_at: null,
    build_error: null,
    override_count: 0,
    conflict_count: 0,
    reporting: false,
    ...over,
  };
}

const ago = (ms: number) => new Date(Date.now() - ms).toISOString();
const HOUR = 3_600_000;
const DAY = 24 * HOUR;

const machine = (over: Partial<MachineDetail> = {}): MachineDetail => ({
  key: 'agent:ea2d',
  href: '/hosts/agent%3Aea2d',
  name: 'files01',
  name_source: 'agent',
  names: [{ value: 'files01', source: 'agent' }],
  primary_ip: PRIMARY,
  address_count: 1,
  addresses: [
    { ip: PRIMARY, kind: 'agent', primary: true, first_seen: ago(30 * DAY), last_seen: ago(4 * DAY), events: 3662 },
  ],
  container_count: 0,
  containers: [],
  agent: null,
  role: { value: null, label: null, confidence: null, state: 'unknown', guess: null, stale_hours: null },
  events: 3662,
  first_seen: ago(30 * DAY),
  last_seen: ago(4 * DAY),
  flags: { declared: false, conflict: false, broken: false, new: false, rebound: false },
  macs: [],
  merged_from: [],
  dossier: dossier(PRIMARY),
  ...over,
});

const activity = (over: Partial<HostActivity> = {}): HostActivity => ({
  peers: [],
  volume: [],
  users: null,
  alerts_7d: 0,
  latest_investigation: null,
  peers_truncated: false,
  users_truncated: false,
  ...over,
});

const noMachine = () => new ApiError('No machine holds this value.', 404, 'no_host');

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

function Here() {
  const loc = useLocation();
  return <div data-testid="url">{`${loc.pathname}${loc.search}`}</div>;
}

const mount = (path: string) =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <Here />
      <Routes>
        <Route path="/hosts/:key" element={<HostDetail />} />
      </Routes>
    </MemoryRouter>,
  );

// ---------------------------------------------------------------------------
// S2: an address no machine holds
// ---------------------------------------------------------------------------

describe('HostDetail: an address the census never saw', () => {
  it('links the entity page, which lists what names the address', async () => {
    vi.mocked(resolveMachine).mockRejectedValue(noMachine());
    vi.mocked(getDossier).mockResolvedValue(
      dossier('192.0.2.226', {}, { found: false, first_seen: null, last_seen: null, last_built_at: null }),
    );
    mount('/hosts/192.0.2.226');
    const box = await screen.findByTestId('host-never-seen-entity');
    expect(within(box).getByRole('link').getAttribute('href')).toBe('/entity/192.0.2.226?view=entity');
  });

  it('offers no entity link on a host the census holds', async () => {
    // NEGATIVE CONTROL: the machine page is the answer for a machine.
    mount(`/hosts/agent%3Aea2d`);
    await screen.findByTestId('host-hero');
    await waitFor(() => expect(getHostActivity).toHaveBeenCalled());
    expect(screen.queryByTestId('host-never-seen-entity')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// S3 and architecture change 4: the first screen
// ---------------------------------------------------------------------------

const huntedLead = (id: number, over: Record<string, unknown> = {}) => ({
  id,
  status: 'open',
  formed_at: ago(6 * DAY),
  updated_at: ago(5 * DAY),
  entities: [['host', PRIMARY]],
  kinds: ['alert'],
  weight_at_formation: 1.0,
  scope_count: 1,
  hunt_id: `hunt-${id}`,
  hunt_status: 'complete',
  hunt_outcome_label: 'Threat findings',
  shadow: false,
  single_signal: false,
  observations: [],
  ...over,
});

const alertObservation = (id: number, verdict: string, bornMsAgo: number) => ({
  id,
  kind: 'alert',
  spec_id: 'alert',
  source: 'alert',
  shadow: false,
  summary: `Rule ${id}: ${verdict.replace(/_/g, ' ')}`,
  weight_now: 0.5,
  lead_id: 11,
  born_at: ago(bornMsAgo),
  occurrences: 1,
  read: true,
  verdict,
});

describe('HostDetail: the first screen leads with leads and verdicts', () => {
  beforeEach(() => {
    vi.mocked(getLeads).mockResolvedValue([
      huntedLead(11) as never,
      // A closed lead is history, not open work.
      huntedLead(4, { status: 'dismissed', hunt_outcome_label: 'No threat observed' }) as never,
    ]);
    vi.mocked(getObservations).mockResolvedValue({
      entity: PRIMARY,
      days: 7,
      observations: [
        ...[1, 2, 3, 4, 5].map((i) => alertObservation(i, 'true_positive', 5 * DAY + i * 60_000)),
        alertObservation(6, 'needs_more_info', 2 * DAY),
      ] as never,
    });
  });

  it('opens on the open lead, then the verdicts, then the identity', async () => {
    mount('/hosts/agent%3Aea2d');
    const lines = await screen.findByTestId('host-situation');
    await waitFor(() =>
      expect(within(lines).getAllByRole('listitem').map((li) => li.textContent)).toEqual([
        'Lead 11 waits on a decision. Its hunt found threats. all open leads',
        '5 true-positive alerts, 5 days ago. last 7 days',
        '1 alert needs more information, 2 days ago. last 7 days',
      ]),
    );
    expect(within(lines).getByRole('link', { name: /Lead 11/ }).getAttribute('href')).toBe('/leads/11');
    // The identity follows, and it does not claim that nothing is known.
    const sentence = screen.getByTestId('host-sentence').textContent ?? '';
    expect(sentence).toBe('files01 has no known role or system yet.');
    expect(sentence).not.toMatch(/Nothing else is known/);
    // The situation sits above the identity sentence.
    expect(
      lines.compareDocumentPosition(screen.getByTestId('host-sentence')) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });

  it('asks the server for the open leads on this host', async () => {
    mount('/hosts/agent%3Aea2d');
    await screen.findByTestId('host-situation');
    // The server filters before its row limit. The page read the newest 50
    // leads of the estate and kept the ones on this host, so an older lead
    // on the host never reached the hero.
    expect(getLeads).toHaveBeenCalledWith('open_or_hunting', { entity: PRIMARY, limit: 200 });
    expect(getLeadCount).toHaveBeenCalledWith('open_or_hunting', { entity: PRIMARY });
    expect(getLeads).not.toHaveBeenCalledWith('all');
  });

  it('counts every open lead on the host, past the rows it read', async () => {
    vi.mocked(getLeadCount).mockImplementation(async (status = 'open', query) => ({
      status,
      entity: query?.entity ?? null,
      total: status === 'open_or_hunting' ? 5 : 2,
    }));
    mount('/hosts/agent%3Aea2d');
    const lines = await screen.findByTestId('host-situation');
    await waitFor(() =>
      expect(within(lines).getByText('4 more open leads name this host.')).toBeTruthy(),
    );
  });

  it('states the sweep window on the event counts', async () => {
    vi.mocked(getMachine).mockResolvedValue(
      // A sweep of the last hour. An older sweep names its date.
      machine({ dossier: dossier(PRIMARY, {}, { lookback_days: 14, last_built_at: ago(HOUR) }) }),
    );
    mount('/hosts/agent%3Aea2d');
    expect((await screen.findByTestId('hero-events')).textContent).toBe('3,662 events in the last 14 days');
    const table = await screen.findByTestId('host-addresses');
    expect(within(table).getByRole('columnheader', { name: 'Events, last 14 days' })).toBeTruthy();
  });

  it('counts the alert verdicts under the Alerts card', async () => {
    mount('/hosts/agent%3Aea2d');
    const card = await screen.findByTestId('kpi-alerts');
    expect(card.textContent).toMatch(/Alerts raised · 7d/);
    expect((await within(card).findByTestId('kpi-alert-verdicts')).textContent).toBe(
      '6 alert verdicts on this host',
    );
    // The card says it does not follow the window buttons.
    expect(within(card).getByTestId('kpi-alerts-fixed').textContent).toBe('This card counts the last 7 days.');
    expect(card.getAttribute('title')).toMatch(/always counts 7 days/);
  });

  it('puts the leads and the observations above the peer graph', async () => {
    vi.mocked(getHostActivity).mockResolvedValue(
      activity({
        peers: [{ ip: '192.0.2.77', hostname: null, direction: 'out', ports: [443], events: 9, alerted: false }],
        latest_investigation: { id: '01INV', verdict: 'false_positive', ts: ago(DAY) },
      }),
    );
    mount('/hosts/agent%3Aea2d');
    const graph = await screen.findByTestId('host-peer-graph');
    const strip = await screen.findByTestId('leads-strip');
    const observations = screen.getByText(/Observations on this host/);
    expect(strip.compareDocumentPosition(graph) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(observations.compareDocumentPosition(graph) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    // The Peers header carries no verdict chip.
    expect(screen.queryByText('latest')).toBeNull();
    expect(screen.queryByRole('link', { name: /latest/ })).toBeNull();
  });
});

describe('HostDetail: nothing known is said only when nothing is known', () => {
  it('says "Nothing else is known" with no lead, no verdict and no identity', async () => {
    // NEGATIVE CONTROL for the test above: all three are empty here.
    mount('/hosts/agent%3Aea2d');
    await waitFor(() => expect(getObservations).toHaveBeenCalled());
    await waitFor(() =>
      expect(screen.getByTestId('host-sentence').textContent).toBe(
        'files01 is on the network. soc-ai knows no other fact about this host.',
      ),
    );
    expect(screen.queryByTestId('host-situation')).toBeNull();
    expect(screen.queryByTestId('kpi-alert-verdicts')).toBeNull();
  });
});

describe('HostDetail: the profile panel reads the setting', () => {
  it('says the host has too few events when profiles run', async () => {
    vi.mocked(getMachine).mockResolvedValue(
      machine({ dossier: dossier(PRIMARY, {}, { profile: [], profiles_enabled: true }) }),
    );
    mount('/hosts/agent%3Aea2d');
    const empty = await screen.findByTestId('profile-empty');
    expect(empty.textContent).toMatch(/^This host has too few events for a profile\./);
    expect(empty.textContent).not.toMatch(/Turn/);
  });

  it('says profiles are off when they are off', async () => {
    vi.mocked(getMachine).mockResolvedValue(
      machine({ dossier: dossier(PRIMARY, {}, { profile: [], profiles_enabled: false }) }),
    );
    mount('/hosts/agent%3Aea2d');
    expect((await screen.findByTestId('profile-empty')).textContent).toMatch(/Profiles are off/);
  });
});

// ---------------------------------------------------------------------------
// S4: the agent banner and the last-seen time agree with the header
// ---------------------------------------------------------------------------

describe('HostDetail: the agent banner agrees with the header', () => {
  it('says when a late agent last reported, and never that no agent reports', async () => {
    vi.mocked(getMachine).mockResolvedValue(
      machine({
        agent: { id: 'ea2d', name: 'files01', os: 'Oracle Linux 9', last_report: ago(4 * DAY) },
        dossier: dossier(PRIMARY, {}, { reporting: false }),
      }),
    );
    mount('/hosts/agent%3Aea2d');
    const late = await screen.findByTestId('host-agent-late');
    expect(late.textContent).toBe(
      'The agent last reported 4 days ago. The facts from the agent are as old as that report.',
    );
    expect(screen.queryByTestId('host-no-agent')).toBeNull();
    expect(screen.queryByText(/No agent reports from this machine/)).toBeNull();
    // The header names the same agent.
    expect(screen.getByTestId('hero-agent').textContent).toMatch(/agent files01/);
  });

  it('keeps the no-agent banner when no agent ever reported', async () => {
    // NEGATIVE CONTROL: no agent on the machine and no field from one.
    vi.mocked(getMachine).mockResolvedValue(machine({ agent: null, dossier: dossier(PRIMARY, {}, { reporting: false }) }));
    mount('/hosts/agent%3Aea2d');
    expect((await screen.findByTestId('host-no-agent')).textContent).toMatch(
      /^No agent reports from this machine\./,
    );
    expect(screen.queryByTestId('host-agent-late')).toBeNull();
  });

  it('shows no agent banner while the agent reports', async () => {
    vi.mocked(getMachine).mockResolvedValue(
      machine({
        agent: { id: 'ea2d', name: 'files01', os: null, last_report: ago(HOUR) },
        dossier: dossier(PRIMARY, {}, { reporting: true }),
      }),
    );
    mount('/hosts/agent%3Aea2d');
    await screen.findByTestId('host-hero');
    expect(screen.queryByTestId('host-agent-late')).toBeNull();
    expect(screen.queryByTestId('host-no-agent')).toBeNull();
  });
});

describe('HostDetail: one last-seen time', () => {
  it('gives the header and the primary address row the same time', async () => {
    const live = ago(2 * 60_000);
    vi.mocked(getHostActivity).mockResolvedValue(activity({ volume: [{ ts: live, events: 40 }] }));
    mount('/hosts/agent%3Aea2d');
    const row = await screen.findByTestId(`address-row-${PRIMARY}`);
    await waitFor(() => expect(screen.getByTestId('hero-last-seen').getAttribute('title')).toBe(absTime(live)));
    const cells = within(row).getAllByRole('cell');
    // Address, type, first seen, last seen, events, facts.
    expect(cells[3].getAttribute('title')).toBe(absTime(live));
  });

  it('keeps the sweep time when the live read saw nothing newer', async () => {
    // NEGATIVE CONTROL: an empty volume leaves both on the sweep stamp.
    const m = machine();
    vi.mocked(getMachine).mockResolvedValue(m);
    mount('/hosts/agent%3Aea2d');
    const row = await screen.findByTestId(`address-row-${PRIMARY}`);
    const sweep = m.addresses[0].last_seen;
    await waitFor(() => expect(getHostActivity).toHaveBeenCalled());
    expect(within(row).getAllByRole('cell')[3].getAttribute('title')).toBe(absTime(sweep));
  });
});

// ---------------------------------------------------------------------------
// W items on the host page: the windows of the cards, the sweep failure
// ---------------------------------------------------------------------------

describe('HostDetail: every card names its window', () => {
  it('names the profile window on the Services card and says the buttons do not change it', async () => {
    vi.mocked(getMachine).mockResolvedValue(
      machine({
        dossier: dossier(
          PRIMARY,
          {},
          {
            profile: [
              {
                dimension: 'served_ports',
                shape: 'categorical',
                coverage: 'measured',
                support_days: 30,
                window_days: 30,
                summary: '2 ports · 22, 443',
                top: [
                  ['22', 40],
                  ['443', 9],
                ],
              },
            ],
          },
        ),
      }),
    );
    mount('/hosts/agent%3Aea2d');
    const card = await screen.findByTestId('kpi-services');
    expect(card.textContent).toMatch(/^Services · 30d/);
    expect(card.getAttribute('title')).toMatch(/The 24h and 7d buttons do not change this card\.$/);
    // The two live cards follow the buttons and say the window they show.
    expect((await screen.findByTestId('kpi-users')).textContent).toMatch(/^Users · 24h/);
    expect(screen.getByTestId('kpi-events').textContent).toMatch(/^Connections · 24h/);
  });
});

describe('HostDetail: a failed build reads as a sentence', () => {
  it('turns the stored error into a sentence and keeps the string in the tooltip', async () => {
    vi.mocked(getMachine).mockResolvedValue(
      machine({ dossier: dossier(PRIMARY, {}, { build_error: `${PRIMARY}: TimeoutError:` }) }),
    );
    mount('/hosts/agent%3Aea2d');
    const error = await screen.findByTestId('host-build-error');
    expect(error.textContent).toBe(`The sweep could not read ${PRIMARY}: the grid timed out.`);
    expect(error.getAttribute('title')).toBe(`${PRIMARY}: TimeoutError:`);
    expect(error.textContent).not.toMatch(/TimeoutError/);
  });
});

describe('HostDetail: the role chip shows that it has a tooltip', () => {
  it('marks the chip and gives it the help pointer', async () => {
    vi.mocked(getMachine).mockResolvedValue(
      machine({
        role: { value: 'server', label: 'server', confidence: 0.8, state: 'inferred', guess: null, stale_hours: null },
      }),
    );
    mount('/hosts/agent%3Aea2d');
    const chip = await screen.findByTestId('hero-role');
    expect(within(chip).getByTestId('hero-role-more')).toBeTruthy();
    expect(chip.className).toContain('cursor-help');
    expect(chip.getAttribute('title')).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// Dogfood 2026-10-19, R4-D3 and R4-I1: the investigations of the machine
// ---------------------------------------------------------------------------

describe('HostDetail: the investigations of the machine', () => {
  const runs = (total: number, truePositives: number) => ({
    rows: [
      {
        id: '01INV',
        name: 'DCSync from a workstation',
        kind: 'suricata' as const,
        verdict: 'true_positive' as const,
        conf: 0.9,
        host: PRIMARY,
        status: 'complete' as const,
        when: '20d ago',
        ts: ago(20 * DAY),
      },
    ],
    total,
    running: 0,
    truePositives,
    totalAll: 40,
    active: false,
    limit: 3,
    offset: 0,
  });

  it('reads the machine key over all time and says the true positives in the hero', async () => {
    vi.mocked(listInvestigations).mockResolvedValue(runs(7, 6));
    mount('/hosts/agent%3Aea2d');
    expect((await screen.findByTestId('host-investigations-count')).textContent).toBe(
      '7 investigations name this host. 6 reached a true-positive verdict.',
    );
    expect(listInvestigations).toHaveBeenCalledWith({ entity: 'agent:ea2d', limit: 3 });
    const hero = await screen.findByTestId('host-hero');
    await waitFor(() =>
      expect(hero.textContent).toContain('6 investigations of this host reached a true-positive verdict.'),
    );
    expect(screen.getByTestId('host-investigations-all').getAttribute('href')).toBe(
      '/investigations?entity=agent%3Aea2d&entity_label=files01&range=all',
    );
  });

  it('adds no hero line when no investigation reached a true positive', async () => {
    // NEGATIVE CONTROL: the block keeps the count, the hero stays quiet.
    vi.mocked(listInvestigations).mockResolvedValue(runs(2, 0));
    mount('/hosts/agent%3Aea2d');
    await screen.findByTestId('host-investigations-count');
    expect(screen.getByTestId('host-hero').textContent).not.toContain('true-positive verdict');
  });
});

// ---------------------------------------------------------------------------
// Dogfood 2026-10-19, R4-D12, R4-D17 and R4-I4: a declaration and the window
// ---------------------------------------------------------------------------

describe('HostDetail: a declaration on one host', () => {
  const staleRole = dossier(PRIMARY, {
    role: { reason: 'stale', inferred_value: 'server', inferred_confidence: 0.9, last_run_at: ago(17 * DAY) },
  });
  const declared = dossier(PRIMARY, {
    role: {
      value: 'domain_controller',
      source: 'operator',
      reason: null,
      overridden: true,
      inferred_value: 'server',
      last_run_at: ago(17 * DAY),
    },
  });
  const staleMachine = machine({
    dossier: staleRole,
    role: { value: null, label: null, confidence: 0.9, state: 'stale', guess: 'server', stale_hours: 17 * 24 },
  });
  const declaredMachine = machine({
    dossier: declared,
    role: {
      value: 'domain_controller',
      label: 'domain controller',
      confidence: 1,
      state: 'declared',
      guess: null,
      stale_hours: null,
    },
  });

  beforeEach(() => {
    vi.mocked(getMe).mockResolvedValue({ username: 'root', role: 'admin', status: '' });
    vi.mocked(getMachine).mockReset().mockResolvedValueOnce(staleMachine).mockResolvedValue(declaredMachine);
    vi.mocked(setDossierOverride).mockReset().mockResolvedValue(declared);
    vi.mocked(clearDossierOverride).mockReset().mockResolvedValue(staleRole);
  });

  const declare = async () => {
    mount('/hosts/agent%3Aea2d');
    const facts = await screen.findByTestId('host-facts');
    const row = within(facts).getByTestId('field-role');
    fireEvent.click(await within(row).findByRole('button', { name: 'Edit Role' }));
    fireEvent.change(within(row).getByRole('combobox'), { target: { value: 'domain_controller' } });
    fireEvent.click(within(row).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(setDossierOverride).toHaveBeenCalled());
  };

  it('re-reads the machine, so the hero badge shows the declared role', async () => {
    await declare();
    await waitFor(() => expect(getMachine).toHaveBeenCalledTimes(2));
    expect((await screen.findByTestId('hero-role')).textContent).toContain('domain controller');
  });

  it('offers Undo, and Undo removes a new declaration', async () => {
    await declare();
    const note = await screen.findByTestId('declaration-undo');
    expect(note.textContent).toContain('Role declared: domain controller.');
    fireEvent.click(within(note).getByRole('button', { name: 'Undo' }));
    await waitFor(() => expect(clearDossierOverride).toHaveBeenCalledWith(PRIMARY, 'role'));
  });

  it('closes the Undo note on request', async () => {
    // NEGATIVE CONTROL: a closed note runs no write.
    await declare();
    const note = await screen.findByTestId('declaration-undo');
    fireEvent.click(within(note).getByRole('button', { name: 'Close the Undo note' }));
    expect(screen.queryByTestId('declaration-undo')).toBeNull();
    expect(clearDossierOverride).not.toHaveBeenCalled();
  });
});

describe('HostDetail: the activity window lives in the URL', () => {
  it('opens on the window the URL names', async () => {
    mount('/hosts/agent%3Aea2d?range=7d');
    await waitFor(() => expect(getHostActivity).toHaveBeenCalledWith(PRIMARY, '7d'));
  });

  it('writes the chosen window to the URL', async () => {
    mount('/hosts/agent%3Aea2d');
    await waitFor(() => expect(getHostActivity).toHaveBeenCalledWith(PRIMARY, '24h'));
    fireEvent.click(await screen.findByRole('button', { name: '7d' }));
    await waitFor(() => expect(screen.getByTestId('url').textContent).toContain('range=7d'));
    await waitFor(() => expect(getHostActivity).toHaveBeenCalledWith(PRIMARY, '7d'));
  });

  it('opens on 24h for a window it does not know', async () => {
    // NEGATIVE CONTROL: an odd value is no window.
    mount('/hosts/agent%3Aea2d?range=90d');
    await waitFor(() => expect(getHostActivity).toHaveBeenCalledWith(PRIMARY, '24h'));
  });
});
