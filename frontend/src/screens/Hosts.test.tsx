// The host list: one row per MACHINE (dogfood 2026-10-02). The owner's words:
// "I am not convinced that the search works. The columns cannot be filtered or
// sorted. There is clearly an issue with hosts with multiple nics being
// displayed multiple times." These tests pin the rebuilt screen:
//   * a real table: column headers that sort both ways and say so with
//     aria-sort, header filters for role, agent and activity, and one tab
//     stop per row (plus the checkbox for an admin);
//   * one search box that asks the server over the whole census, debounced,
//     from page 1 in one request, and says that it reads every host;
//   * every control in the URL, so Back, reload and the breadcrumb return to
//     the same list;
//   * the cards and the role bar are links to the filters they count.
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { useLayoutEffect } from 'react';
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  Dossier,
  DossierConflicts,
  DossierList,
  DossierRow,
  DossierSummary,
  MachineList,
  MachineRow,
  MachineSummary,
} from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  listMachines: vi.fn(),
  getMachineSummary: vi.fn(),
  listDossiers: vi.fn(),
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
  bulkSetDossierOverride,
  getDossier,
  getDossierConflicts,
  getDossierRefreshStatus,
  getDossierSummary,
  getMachineSummary,
  getMe,
  listDossiers,
  listMachines,
  listSavedViews,
  startDossierRefresh,
} from '../lib/api';
import { listUrlToReturnTo } from '../lib/hostsList';
import { Hosts } from './Hosts';

// ---- fixtures ---------------------------------------------------------------

const UNKNOWN_ROLE = {
  value: null,
  label: null,
  confidence: null,
  state: 'unknown' as const,
  guess: null,
  stale_hours: null,
};

const NO_FLAGS = { declared: false, conflict: false, broken: false, new: false, rebound: false };

const machine = (key: string, over: Partial<MachineRow> = {}): MachineRow => ({
  key,
  href: `/hosts/${encodeURIComponent(key)}`,
  name: null,
  name_source: null,
  names: [],
  primary_ip: '192.0.2.99',
  address_count: 1,
  addresses: [over.primary_ip ?? '192.0.2.99'],
  container_count: 0,
  agent: null,
  role: UNKNOWN_ROLE,
  events: 4,
  first_seen: '2026-09-01T00:00:00+00:00',
  last_seen: '2026-10-01T11:00:00+00:00',
  flags: NO_FLAGS,
  ...over,
});

// A machine with seven addresses: one row, the primary address, "+6".
const PROXY = machine('agent:a1', {
  name: 'web01',
  name_source: 'agent',
  names: [{ value: 'web01', source: 'agent' }],
  primary_ip: '192.0.2.10',
  address_count: 7,
  addresses: ['192.0.2.10', '198.51.100.4', '198.51.100.5', '198.51.100.6', '198.51.100.7'],
  agent: { id: 'a1', name: 'web01', os: 'Ubuntu 24.04', last_report: '2026-10-01T10:00:00+00:00' },
  role: { value: 'server', label: 'server', confidence: 0.9, state: 'inferred', guess: null, stale_hours: null },
  events: 11158,
});

// No name, a role the resolver withheld.
const UNNAMED = machine('mac:aa:bb:cc:dd:ee:01', {
  primary_ip: '192.0.2.20',
  addresses: ['192.0.2.20'],
  role: {
    value: null,
    label: null,
    confidence: 0.4,
    state: 'low_confidence',
    guess: 'hypervisor',
    stale_hours: null,
  },
});

// A DNS name and a stale role.
const PRINTER = machine('ip:192.0.2.30', {
  name: 'printer.example.test',
  name_source: 'dns',
  primary_ip: '192.0.2.30',
  addresses: ['192.0.2.30'],
  role: { value: null, label: null, confidence: 0.8, state: 'stale', guess: 'iot', stale_hours: 200 },
});

const page = (rows: MachineRow[], total = rows.length, offset = 0): MachineList => ({
  rows,
  total,
  limit: 50,
  offset,
  sort: 'last_seen',
  dir: 'desc',
});

const SUMMARY: MachineSummary = {
  machines: 144,
  addresses: 205,
  with_agent: 12,
  without_agent: 132,
  new_7d: 4,
  named: 60,
  unnamed: 84,
  roles: { server: 20, workstation: 7, hypervisor: 0, low_confidence: 9, stale: 2, unknown: 103 },
  needs_attention: 5,
  conflicts: 2,
  never_built: 3,
  last_sweep_at: '2026-10-01T08:00:00+00:00',
  stale_hours: null,
};

// The same census under activity=active: the header menus read this one.
const ACTIVE_SUMMARY: MachineSummary = {
  ...SUMMARY,
  machines: 110,
  with_agent: 12,
  without_agent: 136,
  roles: { server: 16, workstation: 5, hypervisor: 0, low_confidence: 8, stale: 0, unknown: 81 },
};

// The address census: swept, schedule off.
const CENSUS: DossierSummary = {
  hosts: 337,
  never_built: 3,
  named: 55,
  reporting: 43,
  conflicts: 2,
  roles: { server: 20 },
  last_built_at: '2026-10-01T08:00:00+00:00',
  schedule_enabled: false,
};

const CONFLICTS: DossierConflicts = {
  pending: 2,
  rows: [
    {
      ip: '192.0.2.10',
      field: 'role',
      kind: 'mismatch',
      first_seen_at: '2026-09-03T09:00:00+00:00',
      observations: 7,
      last_prompted_at: null,
      prompt_count: 1,
      snoozed_until: null,
      operator_value: 'hypervisor',
      operator_value_json: null,
      inferred_value: 'server',
      inferred_value_json: null,
      identity_rebound_at: null,
      href: '/entity/192.0.2.10',
    },
    {
      ip: '192.0.2.20',
      field: 'services_offered',
      kind: 'mismatch',
      first_seen_at: '2026-09-04T09:00:00+00:00',
      observations: 3,
      last_prompted_at: null,
      prompt_count: 0,
      snoozed_until: null,
      operator_value: null,
      operator_value_json: ['ssh'],
      inferred_value: null,
      inferred_value_json: ['ssh', 'http'],
      identity_rebound_at: null,
      href: '/entity/192.0.2.20',
    },
  ],
};

beforeEach(() => {
  sessionStorage.clear();
  vi.mocked(listMachines).mockReset().mockResolvedValue(page([PROXY, UNNAMED, PRINTER]));
  vi.mocked(getMachineSummary).mockReset().mockResolvedValue(SUMMARY);
  vi.mocked(listDossiers).mockReset();
  vi.mocked(getDossier).mockReset();
  vi.mocked(getDossierConflicts).mockReset().mockResolvedValue({ pending: 0, rows: [] });
  vi.mocked(getDossierSummary).mockReset().mockResolvedValue(CENSUS);
  vi.mocked(getDossierRefreshStatus)
    .mockReset()
    .mockResolvedValue({ running: false, last_run: null, last_summary: null, note: null });
  vi.mocked(startDossierRefresh).mockReset();
  vi.mocked(getMe).mockReset().mockResolvedValue({ username: 'ana', role: 'analyst', status: '' });
  vi.mocked(bulkSetDossierOverride).mockReset().mockResolvedValue({ updated: [], not_found: [], failed: [] });
  vi.mocked(listSavedViews).mockReset().mockResolvedValue([]);
});

// ---- harness ----------------------------------------------------------------

/** The machine page stand-in: where the row link went, with a Back button. */
function HostStub() {
  const loc = useLocation();
  const navigate = useNavigate();
  return (
    <div>
      <div data-testid="here">{loc.pathname}</div>
      <div data-testid="here-state">{JSON.stringify(loc.state)}</div>
      <button type="button" onClick={() => navigate(-1)}>
        go back
      </button>
    </div>
  );
}

/** The machine page stand-in that does what the browser does when the long
 *  list leaves the pane: the pane is short now, so its scroll goes to 0 and a
 *  scroll event fires. It runs in a layout effect, before the list's passive
 *  unmount cleanup. */
function PaneResetStub() {
  useLayoutEffect(() => {
    const pane = document.querySelector<HTMLElement>('[data-testid="scroller"]');
    if (!pane) return;
    pane.scrollTop = 0;
    pane.dispatchEvent(new Event('scroll'));
  }, []);
  return <HostStub />;
}

function UrlProbe() {
  const loc = useLocation();
  return <div data-testid="url">{`${loc.pathname}${loc.search}`}</div>;
}

const mount = (url = '/hosts') =>
  render(
    <MemoryRouter initialEntries={[url]}>
      <UrlProbe />
      <Routes>
        <Route path="/hosts" element={<Hosts />} />
        <Route path="/hosts/:key" element={<HostStub />} />
      </Routes>
    </MemoryRouter>,
  );

/** The last query listMachines was called with. */
const lastQuery = () => vi.mocked(listMachines).mock.calls.slice(-1)[0][0]!;
const url = () => screen.getByTestId('url').textContent;
const rowOf = (m: MachineRow) => screen.getByTestId(`machine-row-${m.key}`);
const header = (name: string) => screen.getByRole('columnheader', { name: new RegExp(`^${name}`) });
const asAdmin = () =>
  vi.mocked(getMe).mockResolvedValue({ username: 'root', role: 'admin', status: '' });
/** The list has rendered: the web01 row's link is on screen. */
const ready = () => screen.findByRole('link', { name: 'web01, 192.0.2.10' });

// ---- the table --------------------------------------------------------------

describe('Hosts table: one row per machine', () => {
  it('is a real table with column headers', async () => {
    mount();
    await ready();
    const table = screen.getByRole('table');
    const headers = within(table)
      .getAllByRole('columnheader')
      .map((h) => (h.textContent ?? '').trim());
    expect(headers).toEqual(['Host', 'Address', 'Agent', 'Role', 'Events', 'First seen', 'Last seen']);
    // One row per machine: three machines, three body rows.
    expect(within(table).getAllByRole('row')).toHaveLength(4);
  });

  it('shows a machine with many addresses once, with the primary address and +N', async () => {
    mount();
    await ready();
    const row = rowOf(PROXY);
    expect(within(row).getByText('192.0.2.10')).toBeTruthy();
    const more = within(row).getByTestId('address-more');
    expect(more.textContent).toBe('+6');
    // The other addresses ride the tooltip. The API sends the first five, so
    // the rest are counted.
    expect(more.getAttribute('title')).toBe(
      '198.51.100.4, 198.51.100.5, 198.51.100.6, 198.51.100.7, and 2 more addresses',
    );
    // No other row repeats the machine.
    expect(screen.getAllByText('web01', { selector: 'a' })).toHaveLength(1);
  });

  it('names the machine and its name source, and says "no name" when there is none', async () => {
    mount();
    await ready();
    expect(within(rowOf(PROXY)).getByText('agent', { selector: 'div' })).toBeTruthy();
    expect(within(rowOf(PRINTER)).getByText('DNS')).toBeTruthy();
    expect(within(rowOf(UNNAMED)).getByText('no name')).toBeTruthy();
  });

  it('shows the agent name and OS, or "none"', async () => {
    mount();
    await ready();
    expect(within(rowOf(PROXY)).getByText('Ubuntu 24.04')).toBeTruthy();
    expect(within(rowOf(UNNAMED)).getByText('none')).toBeTruthy();
  });

  it('shows the role with its state from the wire', async () => {
    vi.mocked(listMachines).mockResolvedValue(
      page([PROXY, UNNAMED, PRINTER, machine('ip:192.0.2.40', { primary_ip: '192.0.2.40' })]),
    );
    mount();
    await ready();
    expect(within(rowOf(PROXY)).getByText('server')).toBeTruthy();
    expect(within(rowOf(PROXY)).getByText('inferred')).toBeTruthy();
    expect(within(rowOf(UNNAMED)).getByTestId('role-low-confidence').textContent).toBe(
      'low confidence: hypervisor',
    );
    expect(within(rowOf(PRINTER)).getByTestId('role-stale').textContent).toBe('stale 8d: IoT device');
    expect(screen.getByTestId('role-unknown').textContent).toBe('unknown');
  });

  it('gives each row one tab stop, a link to the machine page', async () => {
    mount();
    await ready();
    const row = rowOf(PROXY);
    const links = within(row).getAllByRole('link');
    expect(links).toHaveLength(1);
    expect(links[0].getAttribute('href')).toBe('/hosts/agent%3Aa1');
    // Nothing else in the row takes focus for an analyst.
    expect(within(row).queryAllByRole('button')).toHaveLength(0);
    expect(within(row).queryAllByRole('checkbox')).toHaveLength(0);
  });

  it('adds the checkbox as the second tab stop for an admin', async () => {
    asAdmin();
    mount();
    await screen.findByLabelText('Select web01');
    const row = rowOf(PROXY);
    expect(within(row).getAllByRole('link')).toHaveLength(1);
    expect(within(row).getAllByRole('checkbox')).toHaveLength(1);
  });

  it('opens the machine page from a row click', async () => {
    mount();
    await ready();
    fireEvent.click(within(rowOf(PRINTER)).getByText('stale 8d: IoT device'));
    expect((await screen.findByTestId('here')).textContent).toBe('/hosts/ip%3A192.0.2.30');
  });

  it('says the header count in machines and addresses', async () => {
    mount();
    await ready();
    await waitFor(() =>
      expect(screen.getByTestId('hosts-count').textContent).toBe('144 machines · 205 addresses'),
    );
  });
});

// ---- sorting ----------------------------------------------------------------

describe('Hosts sort: every header sorts, both ways', () => {
  it('lands on last seen, newest first, and says so with aria-sort', async () => {
    mount();
    await ready();
    expect(lastQuery()).toMatchObject({ sort: 'last_seen', dir: 'desc' });
    expect(header('Last seen').getAttribute('aria-sort')).toBe('descending');
    expect(header('Host').getAttribute('aria-sort')).toBe('none');
  });

  it('sorts on a header click, then toggles the direction', async () => {
    mount();
    await ready();
    fireEvent.click(within(header('Host')).getByRole('button', { name: /^Host/ }));
    await waitFor(() => expect(lastQuery()).toMatchObject({ sort: 'name', dir: 'asc' }));
    expect(header('Host').getAttribute('aria-sort')).toBe('ascending');
    expect(header('Last seen').getAttribute('aria-sort')).toBe('none');
    expect(url()).toBe('/hosts?sort=name');

    fireEvent.click(within(header('Host')).getByRole('button', { name: /^Host/ }));
    await waitFor(() => expect(lastQuery()).toMatchObject({ sort: 'name', dir: 'desc' }));
    expect(header('Host').getAttribute('aria-sort')).toBe('descending');
    expect(url()).toBe('/hosts?sort=name&dir=desc');
  });

  it('starts a count or a time column at the biggest, and an address at the lowest', async () => {
    mount();
    await ready();
    fireEvent.click(within(header('Events')).getByRole('button', { name: /^Events/ }));
    await waitFor(() => expect(lastQuery()).toMatchObject({ sort: 'events', dir: 'desc' }));
    fireEvent.click(within(header('Address')).getByRole('button', { name: /^Address/ }));
    await waitFor(() => expect(lastQuery()).toMatchObject({ sort: 'address', dir: 'asc' }));
  });

  it('resets the page to 1 in the same request', async () => {
    mount('/hosts?page=3');
    await waitFor(() => expect(lastQuery()).toMatchObject({ offset: 100 }));
    const before = vi.mocked(listMachines).mock.calls.length;
    fireEvent.click(within(header('Agent')).getByRole('button', { name: /^Agent/ }));
    await waitFor(() => expect(lastQuery()).toMatchObject({ sort: 'agent', offset: 0 }));
    expect(vi.mocked(listMachines).mock.calls.length).toBe(before + 1);
  });
});

// ---- header filters -----------------------------------------------------------

describe('Hosts header filters', () => {
  it('lists the roles machines hold, with counts, and the three buckets', async () => {
    mount();
    await ready();
    await waitFor(() => expect(getMachineSummary).toHaveBeenCalled());
    fireEvent.click(screen.getByRole('button', { name: 'Filter by role' }));
    const menu = await screen.findByRole('menu', { name: 'Role filter' });
    const roleGroup = within(menu).getByRole('group', { name: 'Role' });
    const items = within(roleGroup)
      .getAllByRole('menuitemradio')
      .map((i) => (i.textContent ?? '').replace(/\s+/g, ' ').trim());
    expect(items).toEqual([
      'any role',
      'server20',
      'workstation7',
      'low confidence9',
      'stale2',
      'unknown103',
    ]);
    // A role no machine holds is not offered.
    expect(within(menu).queryByText('hypervisor')).toBeNull();
  });

  it('counts each menu choice under the activity the list shows', async () => {
    // Dogfood 2026-10-02: the Role menu read "unknown 117" and the Agent menu
    // "without an agent 172" from the whole census. The default list keeps the
    // machines with events and showed 81 and 136.
    vi.mocked(getMachineSummary).mockImplementation((activity) =>
      Promise.resolve(activity === 'active' ? ACTIVE_SUMMARY : SUMMARY),
    );
    mount();
    await ready();
    await waitFor(() => expect(getMachineSummary).toHaveBeenCalledWith('active'));
    fireEvent.click(screen.getByRole('button', { name: 'Filter by role' }));
    const roleMenu = await screen.findByRole('menu', { name: 'Role filter' });
    const roleItems = within(within(roleMenu).getByRole('group', { name: 'Role' }))
      .getAllByRole('menuitemradio')
      .map((i) => (i.textContent ?? '').replace(/\s+/g, ' ').trim());
    // The stale bucket stays on offer at 0. A missing option reads as a
    // broken filter, and the count says the list is empty.
    expect(roleItems).toEqual(['any role', 'server16', 'workstation5', 'low confidence8', 'stale0', 'unknown81']);
    fireEvent.keyDown(document, { key: 'Escape' });
    fireEvent.click(screen.getByRole('button', { name: 'Filter by agent' }));
    expect(await screen.findByRole('menuitemradio', { name: /^without an agent/ })).toHaveProperty(
      'textContent',
      'without an agent136',
    );
    // The cards count every machine. They read the summary with no activity.
    expect(getMachineSummary).toHaveBeenCalledWith();
    expect(screen.getByTestId('sum-without-agent').textContent).toContain('132');
  });

  it('counts the menus over every machine when the list shows every machine', async () => {
    // NEGATIVE CONTROL: activity=all must not read the active counts.
    vi.mocked(getMachineSummary).mockImplementation((activity) =>
      Promise.resolve(activity === 'active' ? ACTIVE_SUMMARY : SUMMARY),
    );
    mount('/hosts?activity=all');
    await ready();
    await waitFor(() => expect(getMachineSummary).toHaveBeenCalled());
    fireEvent.click(screen.getByRole('button', { name: 'Filter by agent' }));
    expect(await screen.findByRole('menuitemradio', { name: /^without an agent/ })).toHaveProperty(
      'textContent',
      'without an agent132',
    );
    expect(getMachineSummary).not.toHaveBeenCalledWith('active');
  });

  it('filters on unknown, and the request names it', async () => {
    mount('/hosts?page=2');
    await ready();
    fireEvent.click(screen.getByRole('button', { name: 'Filter by role' }));
    fireEvent.click(await screen.findByRole('menuitemradio', { name: /^unknown/ }));
    await waitFor(() => expect(lastQuery()).toMatchObject({ role: 'unknown', offset: 0 }));
    expect(url()).toBe('/hosts?role=unknown');
    expect(screen.getByRole('button', { name: 'Filter by role' }).getAttribute('data-active')).toBe('true');
    expect(screen.getByRole('button', { name: /Remove the filter Role: unknown/ })).toBeTruthy();
  });

  it('opens the menu at the button, outside the clipped table panel', async () => {
    // The table panel clips its overflow. An absolute menu on a list with no
    // rows was cut off exactly when the operator needed to change a filter.
    vi.mocked(listMachines).mockResolvedValue(page([], 0));
    mount('/hosts?role=stale');
    await screen.findByText(/No machines match/);
    fireEvent.click(screen.getByRole('button', { name: 'Filter by role' }));
    const menu = await screen.findByRole('menu', { name: 'Role filter' });
    expect(menu.style.position).toBe('fixed');
    // Escape closes it.
    fireEvent.keyDown(document, { key: 'Escape' });
    await waitFor(() => expect(screen.queryByRole('menu')).toBeNull());
  });

  it('filters on the agent', async () => {
    mount();
    await ready();
    fireEvent.click(screen.getByRole('button', { name: 'Filter by agent' }));
    fireEvent.click(await screen.findByRole('menuitemradio', { name: /^without an agent/ }));
    await waitFor(() => expect(lastQuery()).toMatchObject({ agent: 'no' }));
    expect(url()).toBe('/hosts?agent=no');
  });

  it('filters on activity, and the default asks for machines with events', async () => {
    mount();
    await ready();
    expect(lastQuery()).toMatchObject({ activity: 'active' });
    fireEvent.click(screen.getByRole('button', { name: 'Filter by activity' }));
    fireEvent.click(await screen.findByRole('menuitemradio', { name: /^all machines/ }));
    await waitFor(() => expect(lastQuery()).toMatchObject({ activity: 'all' }));
    expect(url()).toBe('/hosts?activity=all');
  });

  it('filters on the declaration from the role menu', async () => {
    mount();
    await ready();
    fireEvent.click(screen.getByRole('button', { name: 'Filter by role' }));
    fireEvent.click(await screen.findByRole('menuitemradio', { name: 'declared by an operator' }));
    await waitFor(() => expect(lastQuery()).toMatchObject({ declared: 'yes' }));
  });

  it('removes a filter from its chip', async () => {
    mount('/hosts?role=server&agent=yes');
    await ready();
    fireEvent.click(screen.getByRole('button', { name: /Remove the filter With an agent/ }));
    await waitFor(() => expect(url()).toBe('/hosts?role=server'));
    expect(lastQuery().agent).toBeUndefined();
  });

  it('has no Show control and no Sort dropdown any more', async () => {
    // The Show control mixed the traffic filter with the declaration filter,
    // so the two could not combine (U14). The header filters replace it.
    mount();
    await ready();
    expect(screen.queryByLabelText('Show')).toBeNull();
    expect(screen.queryByLabelText('Sort')).toBeNull();
  });
});

// ---- search -----------------------------------------------------------------

describe('Hosts search', () => {
  it('asks the server over the whole census, debounced, in one request from page 1', async () => {
    mount('/hosts?page=2');
    await waitFor(() => expect(lastQuery()).toMatchObject({ offset: 50 }));
    const before = vi.mocked(listMachines).mock.calls.length;
    vi.mocked(listMachines).mockResolvedValue(page([PROXY], 1));

    fireEvent.change(screen.getByLabelText('Search hosts'), { target: { value: 'web' } });
    fireEvent.change(screen.getByLabelText('Search hosts'), { target: { value: 'web01' } });
    // Nothing until the debounce runs out.
    expect(vi.mocked(listMachines).mock.calls.length).toBe(before);

    await waitFor(() => expect(lastQuery()).toMatchObject({ q: 'web01', offset: 0, limit: 50 }));
    // One request for the search: the page reset rides in the same URL write.
    expect(vi.mocked(listMachines).mock.calls.length).toBe(before + 1);
    expect(url()).toBe('/hosts?q=web01');
    // The pager counts the matches.
    await waitFor(() => expect(screen.getByTestId('hosts-pager').textContent).toBe('1 to 1 of 1'));
  });

  it('says it searches all hosts while a query is set', async () => {
    mount('/hosts?q=web01');
    await ready();
    expect(screen.getByTestId('hosts-search-scope').textContent).toBe(
      'Searching all hosts. The activity filter does not apply to a search.',
    );
    // The quiet-machines note describes the activity filter, which the search
    // does not apply.
    expect(screen.queryByText(/hides quiet machines/i)).toBeNull();
  });

  it('says nothing about scope without a query', async () => {
    mount();
    await ready();
    expect(screen.queryByTestId('hosts-search-scope')).toBeNull();
    expect(screen.getByText(/hides quiet machines/i)).toBeTruthy();
  });

  it('says what the search reads when nothing matches', async () => {
    vi.mocked(listMachines).mockResolvedValue(page([], 0));
    mount('/hosts?q=files01');
    expect(await screen.findByText(/No machine matches "files01"/)).toBeTruthy();
  });
});

// ---- URL state --------------------------------------------------------------

describe('Hosts URL state', () => {
  it('reads every control from the URL', async () => {
    mount('/hosts?q=web01&sort=name&dir=desc&role=server&agent=yes&activity=all&seen=new&declared=yes&page=2');
    await ready();
    expect(vi.mocked(listMachines).mock.calls[0][0]).toEqual({
      q: 'web01',
      sort: 'name',
      dir: 'desc',
      role: 'server',
      agent: 'yes',
      activity: 'all',
      seen: 'new',
      declared: 'yes',
      limit: 50,
      offset: 50,
    });
    expect((screen.getByLabelText('Search hosts') as HTMLInputElement).value).toBe('web01');
  });

  it('returns to the same list on Back from the machine page', async () => {
    mount('/hosts?role=server&sort=name');
    await ready();
    fireEvent.click(within(rowOf(PROXY)).getByRole('link'));
    expect((await screen.findByTestId('here')).textContent).toBe('/hosts/agent%3Aa1');
    // The machine page learns that the list is the entry behind it.
    expect(screen.getByTestId('here-state').textContent).toBe(
      JSON.stringify({ fromList: '/hosts?role=server&sort=name' }),
    );

    const calls = vi.mocked(listMachines).mock.calls.length;
    fireEvent.click(screen.getByRole('button', { name: 'go back' }));
    await ready();
    expect(url()).toBe('/hosts?role=server&sort=name');
    await waitFor(() => expect(vi.mocked(listMachines).mock.calls.length).toBe(calls + 1));
    expect(lastQuery()).toMatchObject({ role: 'server', sort: 'name', dir: 'asc' });
  });

  it('remembers the list URL for the breadcrumb and a reload', async () => {
    mount('/hosts?agent=no&seen=new');
    await ready();
    expect(listUrlToReturnTo()).toBe('/hosts?agent=no&seen=new');
  });

  it('restores the scroll position after the rows load', async () => {
    sessionStorage.setItem(
      'soc-ai:hosts-list:scroll',
      JSON.stringify({ search: '?role=server', top: 640 }),
    );
    let resolveList: (v: MachineList) => void = () => {};
    vi.mocked(listMachines).mockImplementation(
      () => new Promise<MachineList>((r) => (resolveList = r)),
    );
    render(
      <MemoryRouter initialEntries={['/hosts?role=server']}>
        <div data-testid="scroller" style={{ overflowY: 'auto', height: '300px' }}>
          <Routes>
            <Route path="/hosts" element={<Hosts />} />
          </Routes>
        </div>
      </MemoryRouter>,
    );
    const scroller = screen.getByTestId('scroller');
    // Before the rows load, the page is too short to hold the old position.
    expect(scroller.scrollTop).toBe(0);
    await act(async () => {
      resolveList(page([PROXY, UNNAMED, PRINTER]));
    });
    await ready();
    await waitFor(() => expect(scroller.scrollTop).toBe(640));
  });

  it('keeps the position the row click saved when the pane resets before the unmount', async () => {
    // Dogfood 2026-10-02: the click saved {"top":1729}. The machine page took
    // the place of the long list, the pane went back to the top, and the
    // list's unmount cleanup 52 ms later wrote {"top":0} over the click.
    render(
      <MemoryRouter initialEntries={['/hosts?activity=all&page=2']}>
        <div data-testid="scroller" style={{ overflowY: 'auto', height: '300px' }}>
          <Routes>
            <Route path="/hosts" element={<Hosts />} />
            <Route path="/hosts/:key" element={<PaneResetStub />} />
          </Routes>
        </div>
      </MemoryRouter>,
    );
    await ready();
    const scroller = screen.getByTestId('scroller');
    scroller.scrollTop = 1729;
    fireEvent.scroll(scroller);
    fireEvent.click(within(rowOf(PROXY)).getByRole('link'));
    expect((await screen.findByTestId('here')).textContent).toBe('/hosts/agent%3Aa1');
    expect(JSON.parse(sessionStorage.getItem('soc-ai:hosts-list:scroll') ?? 'null')).toEqual({
      search: '?activity=all&page=2',
      top: 1729,
    });
    fireEvent.click(screen.getByRole('button', { name: 'go back' }));
    await ready();
    await waitFor(() => expect(scroller.scrollTop).toBe(1729));
  });

  it('saves the scroll position on an unmount that no row click started', async () => {
    // NEGATIVE CONTROL: the unmount still writes when no click saved first.
    const view = render(
      <MemoryRouter initialEntries={['/hosts?role=server']}>
        <div data-testid="scroller" style={{ overflowY: 'auto', height: '300px' }}>
          <Routes>
            <Route path="/hosts" element={<Hosts />} />
          </Routes>
        </div>
      </MemoryRouter>,
    );
    await ready();
    const scroller = screen.getByTestId('scroller');
    scroller.scrollTop = 300;
    fireEvent.scroll(scroller);
    view.unmount();
    expect(JSON.parse(sessionStorage.getItem('soc-ai:hosts-list:scroll') ?? 'null')).toEqual({
      search: '?role=server',
      top: 300,
    });
  });

  it('does not restore a scroll position saved for another list', async () => {
    sessionStorage.setItem(
      'soc-ai:hosts-list:scroll',
      JSON.stringify({ search: '?role=workstation', top: 640 }),
    );
    render(
      <MemoryRouter initialEntries={['/hosts?role=server']}>
        <div data-testid="scroller" style={{ overflowY: 'auto', height: '300px' }}>
          <Routes>
            <Route path="/hosts" element={<Hosts />} />
          </Routes>
        </div>
      </MemoryRouter>,
    );
    await ready();
    expect(screen.getByTestId('scroller').scrollTop).toBe(0);
  });
});

// ---- cards ------------------------------------------------------------------

describe('Hosts cards', () => {
  it('applies the filter a card counts', async () => {
    mount('/hosts?q=web01&role=server');
    await ready();
    fireEvent.click(await screen.findByTestId('card-with-agent'));
    await waitFor(() => expect(url()).toBe('/hosts?agent=yes&activity=all'));
    await waitFor(() => expect(lastQuery()).toMatchObject({ agent: 'yes', activity: 'all' }));
    expect(lastQuery().q).toBeUndefined();
    expect(lastQuery().role).toBeUndefined();
  });

  it('keeps the sort when a card applies its filter', async () => {
    mount('/hosts?sort=events');
    await ready();
    expect(screen.getByTestId('card-new').getAttribute('href')).toBe(
      '/hosts?sort=events&seen=new&activity=all',
    );
  });

  it('links a role bar segment to its role filter', async () => {
    mount();
    await ready();
    fireEvent.click(await screen.findByTestId('role-seg-unknown'));
    await waitFor(() => expect(lastQuery()).toMatchObject({ role: 'unknown', activity: 'all' }));
  });

  it('keeps the table when the summary fails', async () => {
    vi.mocked(getMachineSummary).mockRejectedValue(new Error('500 Internal Server Error'));
    mount();
    await ready();
    await waitFor(() =>
      expect(screen.getByTestId('hosts-summary').textContent).toMatch(/could not be read/i),
    );
    expect(screen.getByTestId('hosts-count').textContent).toMatch(/could not be read/i);
  });
});

// ---- quiet census, failures, first run ---------------------------------------

describe('Hosts empty states', () => {
  it('a real but quiet census is "no machines match", never "first run"', async () => {
    vi.mocked(listMachines).mockImplementation((q) =>
      Promise.resolve(q?.activity === 'active' ? page([], 0) : page([UNNAMED], 1)),
    );
    mount();
    expect(await screen.findByText(/No machines match the current filters/)).toBeTruthy();
    expect(screen.queryByText(/hasn't run yet/i)).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: /show all machines/i }));
    await waitFor(() => expect(lastQuery()).toMatchObject({ activity: 'all' }));
    await screen.findByText('no name');
  });

  it('a failed list fetch is an error with Retry, never the first-run panel', async () => {
    vi.mocked(getDossierSummary).mockResolvedValue({ ...CENSUS, hosts: 0 });
    vi.mocked(listMachines).mockRejectedValue(new Error('500 Internal Server Error'));
    mount();
    expect(await screen.findByText(/could not load the host list/i)).toBeTruthy();
    expect(screen.getByRole('button', { name: /retry/i })).toBeTruthy();
    expect(screen.queryByText(/hasn't run yet/i)).toBeNull();
    expect(screen.queryByText(/hides quiet machines/i)).toBeNull();
  });

  it('first run is one sentence and one action', async () => {
    asAdmin();
    vi.mocked(listMachines).mockResolvedValue(page([], 0));
    vi.mocked(getDossierSummary).mockResolvedValue({ ...CENSUS, hosts: 0, last_built_at: null });
    mount();
    expect(await screen.findByText(/hasn't run yet/i)).toBeTruthy();
    expect(screen.getByRole('button', { name: /run the first sweep/i })).toBeTruthy();
    expect(screen.queryByLabelText('Search hosts')).toBeNull();
    expect(screen.queryByTestId('hosts-summary')).toBeNull();
  });
});

// ---- the broken-builds view --------------------------------------------------

const brokenRow = (ip: string, over: Partial<DossierRow> = {}): DossierRow => ({
  ip,
  found: true,
  fields: [],
  first_seen: null,
  last_seen: null,
  last_built_at: null,
  last_observed_at: null,
  event_count: 0,
  identity_rebound_at: null,
  build_error: null,
  override_count: 0,
  conflict_count: 0,
  reporting: false,
  ...over,
});

describe('Hosts broken-builds view', () => {
  it('lists the addresses with no clean build, from the Needs attention card', async () => {
    const list: DossierList = {
      rows: [
        brokenRow('192.0.2.140', { build_error: 'elasticsearch: ConnectionTimeout', last_built_at: '2026-10-01T00:00:00+00:00' }),
        brokenRow('192.0.2.77'),
      ],
      total: 2,
      limit: 50,
      offset: 0,
    };
    vi.mocked(listDossiers).mockResolvedValue(list);
    mount('/hosts?health=broken');
    expect(await screen.findByText('192.0.2.140')).toBeTruthy();
    expect(vi.mocked(listDossiers).mock.calls[0][0]).toMatchObject({ health: 'broken', offset: 0 });
    expect(screen.getByText('never built')).toBeTruthy();
    expect(screen.getByText(/not getting through/i)).toBeTruthy();
    // The machine list is not asked for under this view.
    expect(listMachines).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: /show all machines/i }));
    await waitFor(() => expect(listMachines).toHaveBeenCalled());
  });
});

// ---- the disagreement queue ----------------------------------------------------

describe('Hosts conflicts queue', () => {
  it('opens from the Conflicts card link (?conflicts=1) with both claims', async () => {
    vi.mocked(getDossierConflicts).mockResolvedValue(CONFLICTS);
    mount('/hosts?conflicts=1');
    const link = await screen.findByText('192.0.2.10 · role');
    expect(link.getAttribute('href')).toBe('/hosts/192.0.2.10?field=role');
    expect(screen.getByText('["ssh","http"]')).toBeTruthy();
  });

  it('counts the open disagreements and reveals them on demand', async () => {
    vi.mocked(getDossierConflicts).mockResolvedValue(CONFLICTS);
    mount();
    const banner = await screen.findByRole('button', { name: /2 disagreements need review/i });
    expect(screen.queryByText('192.0.2.10 · role')).toBeNull();
    fireEvent.click(banner);
    expect(await screen.findByText('192.0.2.10 · role')).toBeTruthy();
  });
});

// ---- rebuild ------------------------------------------------------------------

describe('Hosts rebuild control', () => {
  it('is hidden from an analyst', async () => {
    mount();
    await ready();
    expect(screen.queryByRole('button', { name: /rebuild/i })).toBeNull();
  });

  it('says the master switch is off rather than pretending a sweep ran', async () => {
    asAdmin();
    vi.mocked(startDossierRefresh).mockResolvedValue({
      running: false,
      last_run: null,
      last_summary: null,
      note: 'dossier disabled',
    });
    mount();
    fireEvent.click(await screen.findByRole('button', { name: /rebuild/i }));
    const notice = await screen.findByRole('link', { name: /host dossier/i });
    expect(notice).toHaveAttribute('href', '/config#host-dossier');
  });
});

// ---- bulk declare --------------------------------------------------------------

const dossierWith = (ip: string, criticality: string | null): Dossier =>
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

describe('Hosts bulk declare', () => {
  it('offers no checkboxes to an analyst', async () => {
    mount();
    await ready();
    expect(screen.queryByLabelText(/select all hosts/i)).toBeNull();
  });

  it('declares on the primary address of every selected machine', async () => {
    asAdmin();
    vi.mocked(getDossier).mockImplementation(async (ip) => dossierWith(ip, null));
    vi.mocked(bulkSetDossierOverride).mockResolvedValue({
      updated: ['192.0.2.10', '192.0.2.20', '192.0.2.30'],
      not_found: [],
      failed: [],
    });
    mount();
    fireEvent.click(await screen.findByLabelText(/select all hosts/i));
    expect(await screen.findByText(/machines selected/i)).toBeTruthy();
    fireEvent.change(await screen.findByDisplayValue('choose…'), { target: { value: 'low' } });
    fireEvent.click(screen.getByRole('button', { name: /declare \(3\)/i }));
    await waitFor(() =>
      expect(vi.mocked(bulkSetDossierOverride)).toHaveBeenCalledWith(
        ['192.0.2.10', '192.0.2.20', '192.0.2.30'],
        { field: 'criticality', value: 'low' },
      ),
    );
    expect(await screen.findByText(/Declared criticality "low" on 3 of 3 machines/)).toBeTruthy();
  });

  it('names the addresses that failed and keeps them selected for a retry', async () => {
    asAdmin();
    vi.mocked(getDossier).mockImplementation(async (ip) => dossierWith(ip, null));
    vi.mocked(bulkSetDossierOverride).mockResolvedValue({
      updated: ['192.0.2.10'],
      not_found: ['192.0.2.30'],
      failed: [{ ip: '192.0.2.20', reason: 'SQLAlchemyError' }],
    });
    mount();
    fireEvent.click(await screen.findByLabelText(/select all hosts/i));
    fireEvent.change(await screen.findByDisplayValue('choose…'), { target: { value: 'high' } });
    fireEvent.click(screen.getByRole('button', { name: /declare \(3\)/i }));
    expect(await screen.findByText(/1 not swept yet: 192\.0\.2\.30/)).toBeTruthy();
    expect(screen.getByText(/1 failed: 192\.0\.2\.20\. Try those again/)).toBeTruthy();
    expect(screen.getByRole('button', { name: /declare \(2\)/i })).toBeTruthy();
  });

  it('constrains the bulk role to the vocabulary on the wire', async () => {
    asAdmin();
    vi.mocked(getDossierSummary).mockResolvedValue({ ...CENSUS, role_vocabulary: ['workstation', 'jump_host'] });
    mount();
    fireEvent.click(await screen.findByLabelText('Select web01'));
    fireEvent.change(await screen.findByDisplayValue('Criticality'), { target: { value: 'role' } });
    const control = (await screen.findByLabelText('Role to declare')) as HTMLSelectElement;
    await waitFor(() =>
      expect(Array.from(control.options).map((o) => o.value)).toEqual(['', 'jump_host', 'workstation']),
    );
  });
});
