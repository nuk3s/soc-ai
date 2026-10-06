// The host page is the machine page (dogfood 2026-10-02). A machine with
// three addresses was three pages that each told a third of the story. These
// tests pin the machine page:
//   * /hosts/<address> and /hosts/<name> resolve to the machine key and keep
//     the address in focus (old links, /entity redirects, bookmarks);
//   * a 404 from the resolve read keeps the "never seen" page of the address;
//   * the header names the machine, its name source, the agent or its
//     absence, the primary address and the role;
//   * the Addresses section lists every address with its type, and the
//     containers sit collapsed under it;
//   * the breadcrumb goes back to the list the operator came from.
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
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
}));

import {
  ApiError,
  getDossier,
  getDossierRefreshStatus,
  getHostActivity,
  getHostChat,
  getLeads,
  getMachine,
  getMe,
  getObservations,
  resolveMachine,
} from '../lib/api';
import { rememberListUrl } from '../lib/hostsList';
import { ShellProvider, useShell } from '../shell/ShellContext';
import { HostDetail } from './HostDetail';

const PRIMARY = '192.0.2.10';
const BRIDGE = '198.51.100.1';
const LEASE = '198.51.100.44';

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
    reporting: true,
    ...over,
  };
}

const ROLE_FIELD: Partial<DossierField> = {
  value: 'server',
  source: 'behaviour',
  confidence: 0.8,
  strength: 'strong',
  reason: null,
};

const MACHINE: MachineDetail = {
  key: 'agent:ea2d',
  href: '/hosts/agent%3Aea2d',
  name: 'files01',
  name_source: 'agent',
  names: [
    { value: 'files01', source: 'agent' },
    { value: 'files01.example.test', source: 'dns' },
  ],
  primary_ip: PRIMARY,
  address_count: 3,
  addresses: [
    { ip: PRIMARY, kind: 'agent', primary: true, first_seen: '2026-09-01T08:00:00Z', last_seen: '2026-10-01T09:00:00Z', events: 3662 },
    { ip: BRIDGE, kind: 'agent', primary: false, first_seen: '2026-09-02T08:00:00Z', last_seen: '2026-10-01T08:00:00Z', events: 12 },
    { ip: LEASE, kind: 'dhcp', primary: false, first_seen: '2026-09-20T08:00:00Z', last_seen: '2026-09-30T08:00:00Z', events: 40 },
  ],
  container_count: 2,
  containers: [
    { ip: '198.51.100.2', first_seen: null, last_seen: '2026-10-01T08:00:00Z', events: 5 },
    { ip: '198.51.100.3', first_seen: null, last_seen: '2026-10-01T08:00:00Z', events: 7 },
  ],
  agent: { id: 'ea2d', name: 'files01', os: 'Debian 12', last_report: new Date(Date.now() - 3_600_000).toISOString() },
  role: { value: 'server', label: 'server', confidence: 0.8, state: 'inferred', guess: null, stale_hours: null },
  events: 3714,
  first_seen: '2026-09-01T08:00:00Z',
  last_seen: '2026-10-01T09:00:00Z',
  flags: { declared: false, conflict: false, broken: false, new: false, rebound: false },
  macs: ['aa:bb:cc:dd:ee:01'],
  merged_from: [],
  dossier: dossier(PRIMARY, { role: ROLE_FIELD }),
};

const activity = (): HostActivity => ({
  peers: [],
  volume: [],
  users: null,
  alerts_7d: 0,
  latest_investigation: null,
  peers_truncated: false,
  users_truncated: false,
});

const noMachine = () => new ApiError('No machine holds this value.', 404, 'no_host');

beforeEach(() => {
  sessionStorage.clear();
  vi.mocked(getDossier).mockReset().mockImplementation(async (ip) => dossier(ip));
  vi.mocked(getMachine).mockReset().mockResolvedValue(MACHINE);
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
});

function Probe() {
  const loc = useLocation();
  const navigate = useNavigate();
  return (
    <>
      <div data-testid="url">{`${loc.pathname}${loc.search}`}</div>
      <button type="button" onClick={() => navigate(-1)}>
        history back
      </button>
    </>
  );
}

function ListStub() {
  const loc = useLocation();
  return <div data-testid="list">{`${loc.pathname}${loc.search}`}</div>;
}

const mount = (entries: Array<string | { pathname: string; search?: string; state?: unknown }>, index?: number) =>
  render(
    <MemoryRouter initialEntries={entries} initialIndex={index ?? entries.length - 1}>
      <Probe />
      <Routes>
        <Route path="/hosts" element={<ListStub />} />
        <Route path="/hosts/:key" element={<HostDetail />} />
      </Routes>
    </MemoryRouter>,
  );

const url = () => screen.getByTestId('url').textContent;

// ---------------------------------------------------------------------------

describe('HostDetail: an address or a name resolves to the machine', () => {
  it('replaces /hosts/<address> with the machine key and keeps the address in focus', async () => {
    mount([`/hosts/${BRIDGE}?field=role`]);
    await waitFor(() => expect(url()).toBe(`/hosts/agent%3Aea2d?field=role&address=${BRIDGE}`));
    expect(resolveMachine).toHaveBeenCalledWith(BRIDGE);
    expect(getMachine).toHaveBeenCalledWith('agent:ea2d');
    // The address in focus opens in the Addresses section, marked.
    const row = await screen.findByTestId(`address-row-${BRIDGE}`);
    expect(row.getAttribute('data-focus')).toBe('true');
    expect(await screen.findByTestId(`address-facts-${BRIDGE}`)).toBeTruthy();
    await waitFor(() => expect(getDossier).toHaveBeenCalledWith(BRIDGE));
  });

  it('replaces the URL, so Back skips the address URL', async () => {
    mount(['/hosts?role=server', `/hosts/${PRIMARY}`]);
    await screen.findByTestId('host-addresses');
    expect(url()).toBe(`/hosts/agent%3Aea2d?address=${PRIMARY}`);
    // A pushed redirect would put the address URL behind this entry, and Back
    // would land on it and redirect again.
    fireEvent.click(screen.getByRole('button', { name: 'history back' }));
    expect((await screen.findByTestId('list')).textContent).toBe('/hosts?role=server');
  });

  it('resolves a bare name and keeps no address focus', async () => {
    vi.mocked(resolveMachine).mockResolvedValue({ key: 'agent:ea2d', primary_ip: PRIMARY, matched: 'name' });
    mount(['/hosts/files01']);
    await waitFor(() => expect(url()).toBe('/hosts/agent%3Aea2d'));
    expect(resolveMachine).toHaveBeenCalledWith('files01');
  });

  it('keeps the "never seen" page of an address no machine holds', async () => {
    vi.mocked(resolveMachine).mockRejectedValue(noMachine());
    vi.mocked(getDossier).mockResolvedValue(
      dossier('192.0.2.200', {}, { found: false, first_seen: null, last_seen: null, last_built_at: null, last_observed_at: null, event_count: 0 }),
    );
    mount(['/hosts/192.0.2.200']);
    expect(await screen.findByTestId('host-never-seen')).toBeTruthy();
    expect(getDossier).toHaveBeenCalledWith('192.0.2.200');
    expect(getMachine).not.toHaveBeenCalled();
    expect(url()).toBe('/hosts/192.0.2.200');
  });

  it('shows the address alone, and says so, when no machine holds a swept address', async () => {
    vi.mocked(resolveMachine).mockRejectedValue(noMachine());
    mount(['/hosts/192.0.2.201']);
    expect(await screen.findByTestId('host-no-machine')).toBeTruthy();
    expect(screen.queryByTestId('host-addresses')).toBeNull();
  });

  it('says it could not find the machine when the resolve read fails, and shows the address', async () => {
    // A failed read is not "no machine". The page says it could not check.
    vi.mocked(resolveMachine).mockRejectedValue(new ApiError('503 Service Unavailable', 503));
    mount(['/hosts/192.0.2.202']);
    const notice = await screen.findByTestId('host-resolve-failed');
    expect(notice.textContent).toMatch(/could not find the machine/);
    expect(screen.queryByTestId('host-no-machine')).toBeNull();
    vi.mocked(resolveMachine).mockResolvedValue({ key: 'agent:ea2d', primary_ip: PRIMARY, matched: 'address' });
    fireEvent.click(within(notice).getByRole('button', { name: /retry/i }));
    await waitFor(() => expect(url()).toBe('/hosts/agent%3Aea2d?address=192.0.2.202'));
  });

  it('says it could not find the machine above a "never seen" page too', async () => {
    // "Never seen" is a fact about the address record. It is not proof that
    // no machine holds the address, and the machine read failed.
    vi.mocked(resolveMachine).mockRejectedValue(new ApiError('503 Service Unavailable', 503));
    vi.mocked(getDossier).mockResolvedValue(
      dossier('192.0.2.203', {}, { found: false, first_seen: null, last_seen: null, last_built_at: null, last_observed_at: null, event_count: 0 }),
    );
    mount(['/hosts/192.0.2.203']);
    expect(await screen.findByTestId('host-never-seen')).toBeTruthy();
    expect(screen.getByTestId('host-resolve-failed')).toBeTruthy();
  });

  it('follows a machine key that a merge retired', async () => {
    vi.mocked(getMachine).mockImplementation(async (key) => {
      if (key === 'mac:aa:bb:cc:dd:ee:01') throw noMachine();
      return MACHINE;
    });
    mount(['/hosts/mac%3Aaa%3Abb%3Acc%3Add%3Aee%3A01']);
    await waitFor(() => expect(url()).toBe('/hosts/agent%3Aea2d'));
    expect(resolveMachine).toHaveBeenCalledWith('aa:bb:cc:dd:ee:01');
    expect(await screen.findByTestId('host-addresses')).toBeTruthy();
  });

  it('reads a machine key straight, with no resolve read', async () => {
    mount(['/hosts/agent%3Aea2d']);
    await screen.findByTestId('host-addresses');
    expect(resolveMachine).not.toHaveBeenCalled();
    expect(getMachine).toHaveBeenCalledWith('agent:ea2d');
  });
});

describe('HostDetail: the machine header', () => {
  it('names the machine, the name source, the agent, the primary address and the role', async () => {
    mount(['/hosts/agent%3Aea2d']);
    expect((await screen.findByTestId('hero-name')).textContent).toBe('files01');
    expect(screen.getByTestId('hero-name-source').textContent).toBe('name from the agent');
    const agent = screen.getByTestId('hero-agent');
    expect(agent.textContent).toMatch(/agent files01/);
    expect(agent.textContent).toMatch(/Debian 12/);
    expect(agent.textContent).toMatch(/last report 1h ago/);
    expect(screen.getByTestId('hero-primary').textContent).toMatch(/primary address 192\.0\.2\.10/);
    expect(screen.getByTestId('hero-primary').textContent).toMatch(/and 2 more/);
    expect(screen.getByTestId('hero-role').textContent).toMatch(/server/);
    expect(screen.getByTestId('hero-role').textContent).toMatch(/inferred/);
    expect(screen.getByTestId('host-crumb-name').textContent).toBe('files01');
  });

  it('says when no agent reports from the machine', async () => {
    vi.mocked(getMachine).mockResolvedValue({ ...MACHINE, agent: null, name: null, name_source: null });
    mount(['/hosts/agent%3Aea2d']);
    expect((await screen.findByTestId('hero-agent')).textContent).toBe('No agent reports from this machine');
    expect(screen.getByTestId('hero-name').textContent).toBe(PRIMARY);
    expect(screen.getByTestId('hero-name-source').textContent).toBe('no name');
  });

  it('reads the activity, observations and chat of the primary address', async () => {
    mount(['/hosts/agent%3Aea2d']);
    await screen.findByTestId('host-addresses');
    await waitFor(() => expect(getHostActivity).toHaveBeenCalledWith(PRIMARY, '24h'));
    await waitFor(() => expect(getObservations).toHaveBeenCalledWith(PRIMARY, expect.anything()));
    expect(getHostChat).toHaveBeenCalledWith(PRIMARY);
    expect(screen.getByTestId('host-facts-address').textContent).toMatch(/primary address 192\.0\.2\.10/);
  });
});

describe('HostDetail: the Addresses section', () => {
  it('lists every address with its type, first and last seen, and events', async () => {
    mount(['/hosts/agent%3Aea2d']);
    const section = await screen.findByTestId('host-addresses');
    const rows = within(section).getAllByTestId(/^address-row-/);
    expect(rows.map((r) => r.getAttribute('data-testid'))).toEqual([
      `address-row-${PRIMARY}`,
      `address-row-${BRIDGE}`,
      `address-row-${LEASE}`,
    ]);
    expect(within(rows[0]).getByText('primary')).toBeTruthy();
    expect(within(rows[0]).getByText('agent')).toBeTruthy();
    expect(within(rows[2]).getByText('DHCP lease')).toBeTruthy();
    expect(within(rows[2]).getByText('40')).toBeTruthy();
  });

  it('opens the facts of one address on demand, with a link to its record', async () => {
    vi.mocked(getDossier).mockImplementation(async (ip) =>
      dossier(ip, { hostname: { value: 'files01-lease', source: 'telemetry', confidence: 0.8, strength: 'strong', reason: null } }),
    );
    mount(['/hosts/agent%3Aea2d']);
    await screen.findByTestId('host-addresses');
    expect(screen.queryByTestId(`address-facts-${LEASE}`)).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: `Show the facts for ${LEASE}` }));
    const facts = await screen.findByTestId(`address-facts-${LEASE}`);
    await within(facts).findByText('files01-lease');
    expect(getDossier).toHaveBeenCalledWith(LEASE);
    expect(within(facts).getByRole('link', { name: `Open the record for ${LEASE}` }).getAttribute('href')).toBe(
      `/hosts/${LEASE}?view=address`,
    );
  });

  it('keeps the containers in a collapsed section', async () => {
    mount(['/hosts/agent%3Aea2d']);
    const containers = await screen.findByTestId('host-containers');
    expect(containers.tagName).toBe('DETAILS');
    expect(containers.hasAttribute('open')).toBe(false);
    expect(within(containers).getByText('2 containers on this machine')).toBeTruthy();
  });

  it('opens the record of one address without resolving it away', async () => {
    mount([`/hosts/${LEASE}?view=address`]);
    expect(await screen.findByTestId('host-address-only')).toBeTruthy();
    expect(url()).toBe(`/hosts/${LEASE}?view=address`);
    expect(getDossier).toHaveBeenCalledWith(LEASE);
    expect(
      (await screen.findByRole('link', { name: 'Open the machine page' })).getAttribute('href'),
    ).toBe(`/hosts/agent%3Aea2d?address=${LEASE}`);
  });

  it('marks a field of the focused address there, and not on the primary facts', async () => {
    vi.mocked(getDossier).mockImplementation(async (ip) => dossier(ip, { role: ROLE_FIELD }));
    mount([`/hosts/agent%3Aea2d?address=${BRIDGE}&field=role`]);
    const facts = await screen.findByTestId(`address-facts-${BRIDGE}`);
    await waitFor(() =>
      expect(facts.querySelector('[data-field="role"]')?.getAttribute('data-highlight')).toBe('true'),
    );
    // The primary facts panel holds the role row too, and it is not marked:
    // the link named another address.
    const primaryRole = await screen.findByTestId('field-role');
    expect(primaryRole.getAttribute('data-highlight')).toBe('false');
  });

  it('marks the field on the primary facts when the link names the primary address', async () => {
    mount([`/hosts/agent%3Aea2d?address=${PRIMARY}&field=role`]);
    const primaryRole = await screen.findByTestId('field-role');
    expect(primaryRole.getAttribute('data-highlight')).toBe('true');
  });
});

describe('HostDetail: the way back to the list', () => {
  it('goes back in history when the list opened the page', async () => {
    mount(
      [
        { pathname: '/hosts', search: '?role=server&sort=name' },
        { pathname: '/hosts/agent%3Aea2d', state: { fromList: '/hosts?role=server&sort=name' } },
      ],
      1,
    );
    await screen.findByTestId('host-addresses');
    fireEvent.click(screen.getByTestId('hosts-crumb'));
    expect((await screen.findByTestId('list')).textContent).toBe('/hosts?role=server&sort=name');
  });

  it('opens the stored list URL when the page came from elsewhere', async () => {
    rememberListUrl('?agent=no&page=2');
    mount(['/hosts/agent%3Aea2d']);
    await screen.findByTestId('host-addresses');
    const crumb = screen.getByTestId('hosts-crumb');
    expect(crumb.getAttribute('href')).toBe('/hosts?agent=no&page=2');
    await act(async () => {
      fireEvent.click(crumb);
    });
    expect((await screen.findByTestId('list')).textContent).toBe('/hosts?agent=no&page=2');
  });

  it('keeps the list state through the resolve redirect', async () => {
    mount(
      [
        { pathname: '/hosts', search: '?q=files' },
        { pathname: `/hosts/${PRIMARY}`, state: { fromList: '/hosts?q=files' } },
      ],
      1,
    );
    await waitFor(() => expect(url()).toBe(`/hosts/agent%3Aea2d?address=${PRIMARY}`));
    await screen.findByTestId('host-addresses');
    fireEvent.click(screen.getByTestId('hosts-crumb'));
    expect((await screen.findByTestId('list')).textContent).toBe('/hosts?q=files');
  });
});

// The top bar read the raw key "agent:<uuid>" (range dogfood 2026-10-05, C5).
// The page reports the machine name to the shell, and takes it back when it
// leaves.
describe('HostDetail: the top bar name', () => {
  function CrumbProbe() {
    const { crumbName } = useShell();
    return <div data-testid="crumb-name">{crumbName ? `${crumbName.key}=${crumbName.name}` : 'none'}</div>;
  }

  function Leave() {
    const navigate = useNavigate();
    return (
      <button type="button" onClick={() => navigate('/hosts')}>
        leave
      </button>
    );
  }

  it('reports the machine name for its key and clears it on leave', async () => {
    render(
      <MemoryRouter initialEntries={['/hosts/agent%3Aea2d']}>
        <ShellProvider>
          <CrumbProbe />
          <Leave />
          <Routes>
            <Route path="/hosts" element={<ListStub />} />
            <Route path="/hosts/:key" element={<HostDetail />} />
          </Routes>
        </ShellProvider>
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByTestId('crumb-name').textContent).toBe('agent:ea2d=files01'));
    fireEvent.click(screen.getByRole('button', { name: 'leave' }));
    await waitFor(() => expect(screen.getByTestId('crumb-name').textContent).toBe('none'));
  });

  it('reports the primary address of a machine with no name', async () => {
    vi.mocked(getMachine).mockResolvedValue({ ...MACHINE, name: null, name_source: null });
    render(
      <MemoryRouter initialEntries={['/hosts/agent%3Aea2d']}>
        <ShellProvider>
          <CrumbProbe />
          <Routes>
            <Route path="/hosts/:key" element={<HostDetail />} />
          </Routes>
        </ShellProvider>
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(screen.getByTestId('crumb-name').textContent).toBe(`agent:ea2d=${PRIMARY}`),
    );
  });
});
