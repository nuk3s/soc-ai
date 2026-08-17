// The host list is the front door to the host pages: one row per machine, the
// identity an operator glances at, and a flags column that says which rows
// want a human. The 2026-08-08 dogfood pass found it ranking noise first (the
// one host that mattered was row 41 of 41), spending two columns on dashes,
// and printing per-row confidence decimals nobody acts on. These tests pin the
// rebuilt shape:
//   * the landing order is IMPORTANCE — declared criticality, then named, then
//     any host a human has touched (the backend's sort=importance); ATTENTION —
//     broken, conflicted, declared, named — stays one click away in the control;
//   * criticality and the human-touch badges merge into one flags column, and
//     a broken build is finally findable (row marker + summary door +
//     ?health=broken filter);
//   * every filter/sort/pager control reaches the SERVER — the table is one
//     SQL page of a network that can be 5,000 hosts;
//   * an unresolved field renders as em-dash TEXT, never a link (the
//     /entity/%E2%80%94 defect);
//   * first run is one sentence and one action, not four zero tiles over a
//     live search box.
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  DossierConflicts,
  DossierFieldBrief,
  DossierFieldName,
  DossierList,
  DossierRow,
  DossierSummary,
} from '../lib/types';

const FIELDS: DossierFieldName[] = [
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

const brief = (
  field: DossierFieldName,
  over: Partial<DossierFieldBrief> = {},
): DossierFieldBrief => ({
  field,
  value: null,
  value_json: null,
  source: null,
  confidence: 0,
  strength: 'none',
  reason: 'no_signal',
  overridden: false,
  conflict_kind: null,
  ...over,
});

const host = (
  ip: string,
  over: Partial<DossierRow> = {},
  resolved: Partial<Record<DossierFieldName, Partial<DossierFieldBrief>>> = {},
): DossierRow => ({
  ip,
  found: true,
  fields: FIELDS.map((f) => brief(f, resolved[f] ?? {})),
  first_seen: '2026-08-01T00:00:00+00:00',
  last_seen: '2026-08-07T11:00:00+00:00',
  last_built_at: '2026-08-07T11:30:00+00:00',
  last_observed_at: '2026-08-07T11:00:00+00:00',
  event_count: 4,
  identity_rebound_at: null,
  build_error: null,
  override_count: 0,
  conflict_count: 0,
  reporting: false,
  ...over,
});

// A host a human has argued with: role declared, and the sweep still disagrees.
const BLUE = host(
  '192.168.10.8',
  { event_count: 8123, override_count: 2, conflict_count: 1, reporting: true },
  {
    role: {
      value: 'hypervisor',
      source: 'operator',
      confidence: 1,
      strength: 'strong',
      reason: null,
      overridden: true,
      conflict_kind: 'mismatch',
    },
    hostname: { value: 'blue', source: 'banner', confidence: 0.9, strength: 'strong', reason: null },
    criticality: {
      value: 'high',
      source: 'operator',
      confidence: 1,
      strength: 'strong',
      reason: null,
      overridden: true,
    },
  },
);

// The normal early-life row: found, but nothing has resolved yet.
const QUIET = host('192.168.10.9');

// The two health states the flags column must make findable (F3).
const BROKEN = host('192.168.10.140', {
  build_error: 'elasticsearch: ConnectionTimeout after 30s querying logs-* (window 14d)',
});
const NEVER_BUILT = host('192.168.10.77', { last_built_at: null });

const page = (rows: DossierRow[], total = rows.length, offset = 0): DossierList => ({
  rows,
  total,
  limit: 50,
  offset,
});

const CONFLICTS: DossierConflicts = {
  pending: 2,
  rows: [
    {
      ip: '192.168.10.8',
      field: 'role',
      kind: 'mismatch',
      first_seen_at: '2026-08-03T09:00:00+00:00',
      observations: 7,
      last_prompted_at: null,
      prompt_count: 1,
      snoozed_until: null,
      operator_value: 'hypervisor',
      operator_value_json: null,
      inferred_value: 'server',
      inferred_value_json: null,
      identity_rebound_at: null,
      href: '/entity/192.168.10.8',
    },
    {
      // The JSON-shaped case: both scalars are null and the answer rides in
      // the _json columns — a row reading only the scalars renders blank here.
      ip: '192.168.10.9',
      field: 'services_offered',
      kind: 'mismatch',
      first_seen_at: '2026-08-04T09:00:00+00:00',
      observations: 3,
      last_prompted_at: null,
      prompt_count: 0,
      snoozed_until: null,
      operator_value: null,
      operator_value_json: ['ssh'],
      inferred_value: null,
      inferred_value_json: ['ssh', 'http'],
      identity_rebound_at: null,
      href: '/entity/192.168.10.9',
    },
  ],
};

// A network far bigger than any page of it: none of these numbers could be
// derived from the two-row list fixture, which is the point.
const SUMMARY: DossierSummary = {
  hosts: 147,
  never_built: 3,
  named: 25,
  reporting: 13,
  conflicts: 2,
  roles: { server: 12, workstation: 30 },
  last_built_at: '2026-08-07T08:00:00+00:00',
  schedule_enabled: false,
};

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  listDossiers: vi.fn(),
  getDossierConflicts: vi.fn(),
  getDossierSummary: vi.fn(),
  getDossierRefreshStatus: vi.fn(),
  startDossierRefresh: vi.fn(),
  getMe: vi.fn(),
  bulkSetDossierOverride: vi.fn(),
}));

import {
  bulkSetDossierOverride,
  getDossierConflicts,
  getDossierRefreshStatus,
  getDossierSummary,
  getMe,
  listDossiers,
  startDossierRefresh,
} from '../lib/api';
import { roleAccent } from '../lib/hostColors';
import { Hosts } from './Hosts';

beforeEach(() => {
  vi.mocked(listDossiers).mockReset().mockResolvedValue(page([BLUE, QUIET]));
  vi.mocked(getDossierConflicts).mockReset().mockResolvedValue({ pending: 0, rows: [] });
  vi.mocked(getDossierSummary).mockReset().mockResolvedValue(SUMMARY);
  vi.mocked(getDossierRefreshStatus)
    .mockReset()
    .mockResolvedValue({ running: false, last_run: null, last_summary: null, note: null });
  vi.mocked(startDossierRefresh).mockReset();
  vi.mocked(getMe).mockReset().mockResolvedValue({ username: 'ana', role: 'analyst', status: '' });
  vi.mocked(bulkSetDossierOverride).mockReset().mockResolvedValue({ updated: [], not_found: [], failed: [] });
});

const mount = (url = '/hosts') =>
  render(
    <MemoryRouter initialEntries={[url]}>
      <Hosts />
    </MemoryRouter>,
  );

/** The last query object listDossiers was called with. */
const lastQuery = () => vi.mocked(listDossiers).mock.calls.slice(-1)[0][0];

/** One host's table row, reached from its address link. */
const rowFor = (ip: string) => screen.getByText(ip).closest('a')!.parentElement!.parentElement!;

describe('Hosts table', () => {
  it('calls the table what the nav, the breadcrumb and every other string call it', async () => {
    mount();
    expect(await screen.findByText(`Hosts · ${(2).toLocaleString()}`)).toBeTruthy();
    expect(screen.queryByText(/^Network/)).toBeNull();
  });

  it('renders identity per row — and not a single confidence decimal', async () => {
    mount();
    await screen.findByText('192.168.10.8');
    const row = rowFor('192.168.10.8');
    expect(within(row).getByText('hypervisor')).toBeTruthy();
    expect(within(row).getByText('blue')).toBeTruthy();
    expect(within(row).getByText((8123).toLocaleString())).toBeTruthy();
    // "0.63" vs "0.70" is not a distinction an analyst acts on in a table (F7).
    expect(row.textContent).not.toMatch(/0\.\d{2}/);
  });

  it('colours the role with the same accent the host page uses', async () => {
    mount();
    await screen.findByText('192.168.10.8');
    const role = within(rowFor('192.168.10.8')).getByText('hypervisor');
    expect(role.className).toContain(roleAccent('hypervisor'));
  });

  it('spells the role the same way in the row pill and the ROLES legend', async () => {
    // One screen, one value, two renderings: the pill printed the raw slug
    // (`network_device`) while the legend counting that very host printed the
    // friendly label ("network device"). Both read the label now, and the
    // stored slug stays one hover away on the pill's title.
    const SWITCH = host(
      '192.168.10.30',
      {},
      {
        role: {
          value: 'network_device',
          source: 'behaviour',
          confidence: 0.9,
          strength: 'strong',
          reason: null,
        },
      },
    );
    vi.mocked(listDossiers).mockResolvedValue(page([SWITCH]));
    vi.mocked(getDossierSummary).mockResolvedValue({
      ...SUMMARY,
      hosts: 1,
      roles: { network_device: 1 },
    });
    mount();
    await screen.findByText('192.168.10.30');

    const pill = within(rowFor('192.168.10.30')).getByTitle('network_device');
    expect(pill.textContent).toBe('network device');
    const legend = await screen.findByTestId('role-bar');
    expect(legend.textContent).toContain('network device');
    expect(legend.textContent).not.toContain('network_device');
  });

  it('merges criticality and the human-touch badges into one flags cell', async () => {
    mount();
    await screen.findByText('192.168.10.8');
    const row = rowFor('192.168.10.8');
    // Criticality is a word an operator declared — it renders as itself.
    expect(within(row).getByText('high')).toBeTruthy();
    expect(within(row).getByTitle(/2 fields declared/i)).toBeTruthy();
    expect(within(row).getByTitle(/disagrees/i).textContent).toContain('1');
    // The old CRITICALITY and LANES column headers are gone.
    expect(screen.queryByText('Lanes')).toBeNull();
    expect(screen.queryByText('Criticality')).toBeNull();
  });

  it('marks which rows the blind spots are NOT — agent coverage per row', async () => {
    // The REPORTING count used to aggregate ("no agent data on 32") with no
    // way to see which rows were the blind spots (F12). The wire now carries
    // `reporting` per host, so the flags cell can say it row by row.
    mount();
    await screen.findByText('192.168.10.8');
    expect(within(rowFor('192.168.10.8')).getByTitle(/reports its own logs/i)).toBeTruthy();
    expect(within(rowFor('192.168.10.9')).queryByTitle(/reports its own logs/i)).toBeNull();
  });

  it('marks a broken build on its row, with the stored error in reach', async () => {
    vi.mocked(listDossiers).mockResolvedValue(page([BROKEN, NEVER_BUILT]));
    mount();
    await screen.findByText('192.168.10.140');
    expect(
      within(rowFor('192.168.10.140')).getByTitle(/ConnectionTimeout/),
    ).toBeTruthy();
    // "Never looked" and "looked and it broke" are different states.
    expect(within(rowFor('192.168.10.77')).getByTitle(/never built/i)).toBeTruthy();
  });

  it('renders an unresolved field as quiet text, never a pivot link', async () => {
    mount();
    await screen.findByText('192.168.10.9');
    const dashes = screen.getAllByText('—');
    expect(dashes.length).toBeGreaterThan(0);
    // `/entity/%E2%80%94` — an entity page for a punctuation mark — is the bug
    // this pins. Emptiness is a matter of VALUE, not truthiness.
    for (const d of dashes) expect(d.closest('a')).toBeNull();
  });

  it('links each IP to its host page', async () => {
    mount();
    await screen.findByText('192.168.10.8');
    const hrefs = screen.getAllByRole('link').map((a) => a.getAttribute('href'));
    expect(hrefs).toContain('/hosts/192.168.10.8');
    expect(hrefs).toContain('/hosts/192.168.10.9');
  });

  it('speaks the analyst`s language, not the resolver`s', async () => {
    mount();
    await screen.findByText('192.168.10.8');
    const text = document.body.textContent ?? '';
    expect(text).not.toMatch(/\blanes?\b/i);
    expect(text).not.toMatch(/resolved on read/i);
    expect(text).not.toMatch(/\binference\b/i);
    // The subtitle is the user's version of the doctrine sentence.
    expect(text).toMatch(/your answers win/i);
  });
});

describe('Hosts ordering', () => {
  it('lands on importance — the named, graded hosts above the anonymous tail', async () => {
    // Dogfood B2a (2026-08-11): `attention` leads with "no clean build", which
    // on a real estate is nearly every host, so the whole first screen read
    // `HOST — ROLE —` and the crown jewels sat below the fold. The mock answers
    // the order it was ASKED for, so a screen that still asks for attention
    // renders the anonymous row first and fails the position assertion.
    vi.mocked(listDossiers).mockImplementation((q) =>
      Promise.resolve(
        q?.sort === 'importance'
          ? page([BLUE, QUIET, NEVER_BUILT])
          : page([NEVER_BUILT, QUIET, BLUE]),
      ),
    );
    mount();
    await screen.findByText('192.168.10.8');
    expect(lastQuery()).toMatchObject({ sort: 'importance' });

    const named = rowFor('192.168.10.8');
    const anonymous = rowFor('192.168.10.77');
    expect(named.compareDocumentPosition(anonymous) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('keeps needs-attention as an opt-in sort — broken hosts stay one click away', async () => {
    // The property the attention order was built for survives the demotion: it
    // is still in the control, and the ?health=broken door is untouched.
    mount();
    await screen.findByText('192.168.10.8');
    const sort = screen.getByLabelText('Sort') as HTMLSelectElement;
    expect([...sort.options].map((o) => o.value)).toContain('attention');
    fireEvent.change(sort, { target: { value: 'attention' } });
    await waitFor(() => expect(lastQuery()).toMatchObject({ sort: 'attention' }));
  });

  it('still offers the other orders, server-side', async () => {
    mount();
    await screen.findByText('192.168.10.8');
    fireEvent.change(screen.getByLabelText('Sort'), { target: { value: 'event_count' } });
    await waitFor(() => expect(lastQuery()).toMatchObject({ sort: 'event_count' }));
  });
});

describe('Hosts summary bar', () => {
  it('states the network, not the page it is sitting on', async () => {
    mount();
    await screen.findByText('192.168.10.8');
    expect(getDossierSummary).toHaveBeenCalled();
    const bar = screen.getByTestId('hosts-summary');
    expect(within(bar).getByText('147')).toBeTruthy();
    expect(bar.textContent).toMatch(/25 named/);
    // The table's own count still describes the page's match set, unchanged.
    expect(screen.getByText('1–2 of 2')).toBeTruthy();
  });

  it('sits above the disagreement queue and the table', async () => {
    vi.mocked(getDossierConflicts).mockResolvedValue(CONFLICTS);
    mount();
    const bar = await screen.findByTestId('hosts-summary');
    const banner = await screen.findByRole('button', { name: /disagreements need review/i });
    const panel = screen.getByText(/^Hosts · /);
    const follows = (node: Element) =>
      Boolean(bar.compareDocumentPosition(node) & Node.DOCUMENT_POSITION_FOLLOWING);
    expect(follows(banner)).toBe(true);
    expect(follows(panel)).toBe(true);
  });

  it('keeps the counts when the summary fails, without taking the table down', async () => {
    vi.mocked(getDossierSummary).mockRejectedValue(new Error('500 Internal Server Error'));
    mount();
    await screen.findByText('192.168.10.8');
    expect(screen.getByTestId('hosts-summary').textContent).toMatch(/could not be read/i);
    expect(within(rowFor('192.168.10.8')).getByText('hypervisor')).toBeTruthy();
  });

  it('dates the sweep once, from one clock', async () => {
    // The run line keeps the counters the bar has not got, and gives up its
    // clock — two "last sweep" ages from two different stamps was F6.
    vi.mocked(getMe).mockResolvedValue({ username: 'root', role: 'admin', status: '' });
    vi.mocked(getDossierRefreshStatus).mockResolvedValue({
      running: false,
      last_run: '2026-08-07T09:00:00+00:00',
      last_summary: { hosts_built: 147, fields_written: 1240 },
      note: null,
    });
    mount();
    const line = await screen.findByTestId('sweep-run-summary');
    expect(line.textContent).toMatch(/147 hosts built/);
    expect(line.textContent).toMatch(/1,240 fields written/);
    expect(line.textContent).not.toMatch(/ago/);
    expect(screen.getByTestId('hosts-summary').textContent).toMatch(/swept/i);
  });

  it('re-counts the network after a sweep finishes', async () => {
    vi.mocked(getMe).mockResolvedValue({ username: 'root', role: 'admin', status: '' });
    let running = true;
    vi.mocked(getDossierRefreshStatus).mockImplementation(async () => ({
      running,
      last_run: null,
      last_summary: null,
      note: null,
    }));

    vi.useFakeTimers();
    try {
      mount();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
      });
      expect(vi.mocked(getDossierSummary)).toHaveBeenCalledTimes(1);

      running = false;
      await act(async () => {
        await vi.advanceTimersByTimeAsync(5000);
      });
      expect(vi.mocked(getDossierSummary)).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('marks the counts stale when the post-sweep re-count fails, and keeps them', async () => {
    vi.mocked(getMe).mockResolvedValue({ username: 'root', role: 'admin', status: '' });
    let running = true;
    vi.mocked(getDossierRefreshStatus).mockImplementation(async () => ({
      running,
      last_run: null,
      last_summary: null,
      note: null,
    }));
    vi.mocked(getDossierSummary)
      .mockResolvedValueOnce(SUMMARY)
      .mockRejectedValue(new Error('503 Service Unavailable'));

    vi.useFakeTimers();
    try {
      mount();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
      });
      expect(within(screen.getByTestId('hosts-summary')).getByText('147')).toBeTruthy();

      running = false;
      await act(async () => {
        await vi.advanceTimersByTimeAsync(5000);
      });

      expect(within(screen.getByTestId('hosts-summary')).getByText('147')).toBeTruthy();
      expect(screen.getByTestId('hosts-summary').textContent).toMatch(/could not refresh/i);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('Hosts controls reach the server', () => {
  it('asks for one SQL page and pages forward by the page size', async () => {
    vi.mocked(listDossiers).mockResolvedValue(page([BLUE, QUIET], 120));
    mount();
    await screen.findByText('192.168.10.8');
    expect(lastQuery()).toMatchObject({ limit: 50, offset: 0 });
    expect(screen.getByText('1–50 of 120')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: /next/i }));
    await waitFor(() => expect(lastQuery()).toMatchObject({ offset: 50 }));
  });

  it('sends the search to the server, debounced, from the first page', async () => {
    vi.mocked(listDossiers).mockResolvedValue(page([BLUE, QUIET], 120));
    mount();
    await screen.findByText('192.168.10.8');
    fireEvent.click(screen.getByRole('button', { name: /next/i }));
    await waitFor(() => expect(lastQuery()).toMatchObject({ offset: 50 }));

    fireEvent.change(screen.getByPlaceholderText(/search/i), { target: { value: 'blue' } });
    await waitFor(() => expect(lastQuery()).toMatchObject({ q: 'blue', offset: 0 }));
  });

  it('sends the role and declared prefilters to the server', async () => {
    mount();
    await screen.findByText('192.168.10.8');

    fireEvent.change(screen.getByLabelText('Role'), { target: { value: 'workstation' } });
    await waitFor(() => expect(lastQuery()).toMatchObject({ role: 'workstation' }));

    fireEvent.change(screen.getByLabelText('Show'), { target: { value: 'operator' } });
    await waitFor(() => expect(lastQuery()).toMatchObject({ source: 'operator' }));
  });

  it('offers roles from the summary wire vocabulary, not just this page', async () => {
    // `printer` is a role no host on the page carries — it can only reach the
    // filter from the server's vocabulary. This is the F10 fix: the filter reads
    // the wire, so a new backend role is selectable without a frontend edit.
    vi.mocked(getDossierSummary).mockResolvedValue({
      ...SUMMARY,
      role_vocabulary: ['workstation', 'server', 'printer'],
    });
    mount();
    await screen.findByText('192.168.10.8');

    const roleSelect = screen.getByLabelText('Role') as HTMLSelectElement;
    const values = Array.from(roleSelect.options).map((o) => o.value);
    expect(values).toContain('printer');
    // And selecting it reaches the server like any other role.
    fireEvent.change(roleSelect, { target: { value: 'printer' } });
    await waitFor(() => expect(lastQuery()).toMatchObject({ role: 'printer' }));
  });
});

describe('Hosts broken-builds filter', () => {
  it('filters server-side from the summary door (?health=broken)', async () => {
    vi.mocked(listDossiers).mockResolvedValue(page([BROKEN, NEVER_BUILT]));
    mount('/hosts?health=broken');
    await screen.findByText('192.168.10.140');
    expect(lastQuery()).toMatchObject({ health: 'broken' });
    // The view names itself, so a shared link cannot read as the whole network.
    expect(screen.getByText(/not getting through/i)).toBeTruthy();
  });

  it('offers the way back to all hosts', async () => {
    vi.mocked(listDossiers).mockResolvedValue(page([BROKEN]));
    mount('/hosts?health=broken');
    await screen.findByText('192.168.10.140');
    fireEvent.click(screen.getByRole('button', { name: /show all hosts/i }));
    // The clear must land as a NEW server query without the filter — until the
    // refetch fires, the last call still carries health=broken.
    await waitFor(() => expect(lastQuery()?.health).toBeUndefined());
  });

  it('says when the broken view is empty rather than reading as first run', async () => {
    vi.mocked(listDossiers).mockResolvedValue(page([], 0));
    mount('/hosts?health=broken');
    expect(await screen.findByText(/no hosts match/i)).toBeTruthy();
    expect(screen.queryByText(/hasn't run yet/i)).toBeNull();
  });
});

describe('Hosts conflicts queue', () => {
  it('counts the open disagreements and reveals them read-only', async () => {
    vi.mocked(getDossierConflicts).mockResolvedValue(CONFLICTS);
    mount();
    const banner = await screen.findByRole('button', { name: /2 disagreements need review/i });
    expect(screen.queryByText('192.168.10.8 · role')).toBeNull();

    fireEvent.click(banner);
    const queue = (await screen.findByText('192.168.10.8 · role')).closest('div')!.parentElement!;
    // Both claims, so the operator can judge without opening the host.
    expect(within(queue).getByText('hypervisor')).toBeTruthy();
    expect(within(queue).getByText('server')).toBeTruthy();
    expect(within(queue).getByText(/7/)).toBeTruthy();
  });

  it('names a field in words, not schema keys', async () => {
    vi.mocked(getDossierConflicts).mockResolvedValue(CONFLICTS);
    mount('/hosts?conflicts=1');
    // services_offered is a column name; "services offered" is a fact.
    expect(await screen.findByText('192.168.10.9 · services offered')).toBeTruthy();
    expect(screen.queryByText(/services_offered/)).toBeNull();
  });

  it('reads the structured lanes for a JSON-shaped field', async () => {
    vi.mocked(getDossierConflicts).mockResolvedValue(CONFLICTS);
    mount('/hosts?conflicts=1');
    await screen.findByText('192.168.10.9 · services offered');
    expect(screen.getByText('["ssh"]')).toBeTruthy();
    expect(screen.getByText('["ssh","http"]')).toBeTruthy();
  });

  it('opens pre-revealed from the Dashboard nudge (?conflicts=1)', async () => {
    vi.mocked(getDossierConflicts).mockResolvedValue(CONFLICTS);
    mount('/hosts?conflicts=1');
    expect(await screen.findByText('192.168.10.8 · role')).toBeTruthy();
  });

  it('links a conflict to the host page, not the entity page', async () => {
    vi.mocked(getDossierConflicts).mockResolvedValue(CONFLICTS);
    mount('/hosts?conflicts=1');
    await screen.findByText('192.168.10.8 · role');
    const hrefs = screen.getAllByRole('link').map((a) => a.getAttribute('href'));
    expect(hrefs.some((h) => h?.startsWith('/entity/'))).toBe(false);
  });

  it('says nothing at all when the lanes agree', async () => {
    mount();
    await screen.findByText('192.168.10.8');
    expect(screen.queryByText(/disagreements? need review/i)).toBeNull();
  });
});

describe('Hosts rebuild control', () => {
  it('is hidden from an analyst — the route is admin-only', async () => {
    mount();
    await screen.findByText('192.168.10.8');
    expect(screen.queryByRole('button', { name: /rebuild/i })).toBeNull();
  });

  it('starts a sweep for an admin', async () => {
    vi.mocked(getMe).mockResolvedValue({ username: 'root', role: 'admin', status: '' });
    vi.mocked(startDossierRefresh).mockResolvedValue({
      running: true,
      last_run: null,
      last_summary: null,
      note: 'started',
    });
    mount();
    const btn = await screen.findByRole('button', { name: /rebuild/i });
    fireEvent.click(btn);
    await waitFor(() => expect(startDossierRefresh).toHaveBeenCalled());
  });

  it('says the master switch is off rather than pretending a sweep ran', async () => {
    vi.mocked(getMe).mockResolvedValue({ username: 'root', role: 'admin', status: '' });
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

describe('Hosts — first run', () => {
  beforeEach(() => {
    vi.mocked(listDossiers).mockResolvedValue(page([], 0));
    vi.mocked(getDossierSummary).mockResolvedValue({
      hosts: 0,
      never_built: 0,
      named: 0,
      reporting: 0,
      conflicts: 0,
      roles: {},
      last_built_at: null,
      schedule_enabled: false,
    });
  });

  it('is one sentence and one action, not four zero tiles over a live search box', async () => {
    vi.mocked(getMe).mockResolvedValue({ username: 'root', role: 'admin', status: '' });
    mount();
    expect(await screen.findByText(/hasn't run yet/i)).toBeTruthy();
    // One primary action for an admin…
    expect(screen.getByRole('button', { name: /run the first sweep/i })).toBeTruthy();
    // …one link to the schedule…
    expect(screen.getByRole('link', { name: /scheduled sweeps/i })).toHaveAttribute(
      'href',
      '/config#host-dossier',
    );
    // …and none of the working-screen furniture over zero rows (F9).
    expect(screen.queryByPlaceholderText(/search/i)).toBeNull();
    expect(screen.queryByLabelText('Sort')).toBeNull();
    expect(screen.queryByTestId('hosts-summary')).toBeNull();
  });

  it('runs the first sweep from the button', async () => {
    vi.mocked(getMe).mockResolvedValue({ username: 'root', role: 'admin', status: '' });
    vi.mocked(startDossierRefresh).mockResolvedValue({
      running: true,
      last_run: null,
      last_summary: null,
      note: 'started',
    });
    mount();
    fireEvent.click(await screen.findByRole('button', { name: /run the first sweep/i }));
    await waitFor(() => expect(startDossierRefresh).toHaveBeenCalled());
  });

  it('tells a non-admin who can, instead of offering a button that would 403', async () => {
    mount();
    expect(await screen.findByText(/hasn't run yet/i)).toBeTruthy();
    expect(screen.queryByRole('button', { name: /run the first sweep/i })).toBeNull();
    expect(screen.getByText(/an admin/i)).toBeTruthy();
  });
});


// ---------------------------------------------------------------------------
// Bulk select + declare (dogfood A4) — Hosts was the only list screen with no
// checkboxes at all, so tagging a subnet of unnamed machines was a
// one-at-a-time chore.
// ---------------------------------------------------------------------------

const asAdmin = () =>
  vi.mocked(getMe).mockResolvedValue({ username: 'root', role: 'admin', status: '' });

describe('Hosts bulk declare', () => {
  it('offers no checkboxes to an analyst, who could only be 403d for using them', async () => {
    mount();
    await screen.findByText('192.168.10.8');
    expect(screen.queryByLabelText(/^Select 192\.168\.10\.8$/)).toBeNull();
    expect(screen.queryByLabelText(/select all hosts/i)).toBeNull();
  });

  it('selects a row, and the toolbar says how many', async () => {
    asAdmin();
    mount();
    await screen.findByText('192.168.10.8');
    fireEvent.click(await screen.findByLabelText('Select 192.168.10.8'));
    expect(await screen.findByText(/host selected/i)).toBeTruthy();
  });

  it('selects every host on the page from the header box', async () => {
    asAdmin();
    mount();
    fireEvent.click(await screen.findByLabelText(/select all hosts/i));
    const strip = (await screen.findByText(/hosts selected/i)).parentElement!;
    expect(within(strip).getByText('2')).toBeTruthy();
  });

  it('writes the OPERATOR lane for every selected host, through the one declare path', async () => {
    asAdmin();
    vi.mocked(bulkSetDossierOverride).mockResolvedValue({
      updated: ['192.168.10.8', '192.168.10.9'],
      not_found: [],
      failed: [],
    });
    mount();
    fireEvent.click(await screen.findByLabelText(/select all hosts/i));
    fireEvent.change(await screen.findByDisplayValue('choose…'), { target: { value: 'low' } });
    fireEvent.click(screen.getByRole('button', { name: /declare \(2\)/i }));
    await waitFor(() =>
      expect(vi.mocked(bulkSetDossierOverride)).toHaveBeenCalledWith(
        ['192.168.10.8', '192.168.10.9'],
        { field: 'criticality', value: 'low' },
      ),
    );
    expect(await screen.findByText(/Declared criticality "low" on 2 of 2 hosts/)).toBeTruthy();
  });

  it('names the hosts the sweep has never seen rather than reporting a bare count', async () => {
    asAdmin();
    vi.mocked(bulkSetDossierOverride).mockResolvedValue({
      updated: ['192.168.10.8'],
      not_found: ['192.168.10.9'],
      failed: [],
    });
    mount();
    fireEvent.click(await screen.findByLabelText(/select all hosts/i));
    fireEvent.change(await screen.findByDisplayValue('choose…'), { target: { value: 'high' } });
    fireEvent.click(screen.getByRole('button', { name: /declare \(2\)/i }));
    expect(await screen.findByText(/1 of 2 hosts/)).toBeTruthy();
    expect(screen.getByText(/1 not swept yet \(192\.168\.10\.9\)/)).toBeTruthy();
    // The host that did not take it stays selected, so "try again" is one click.
    expect(screen.getByRole('button', { name: /declare \(1\)/i })).toBeTruthy();
  });

  it('declares a role, offering the vocabulary the screen already knows', async () => {
    asAdmin();
    vi.mocked(bulkSetDossierOverride).mockResolvedValue({
      updated: ['192.168.10.8'],
      not_found: [],
      failed: [],
    });
    mount();
    fireEvent.click(await screen.findByLabelText('Select 192.168.10.8'));
    fireEvent.change(await screen.findByDisplayValue('Criticality'), { target: { value: 'role' } });
    fireEvent.change(await screen.findByLabelText('Role to declare'), {
      target: { value: 'hypervisor' },
    });
    fireEvent.click(screen.getByRole('button', { name: /declare \(1\)/i }));
    await waitFor(() =>
      expect(vi.mocked(bulkSetDossierOverride)).toHaveBeenCalledWith(['192.168.10.8'], {
        field: 'role',
        value: 'hypervisor',
      }),
    );
  });

  it('constrains the bulk role to the vocabulary — a typo cannot become a role', async () => {
    // A free-text box here amplified one typo into N polluted hosts, and a role
    // is not a per-host label: `srever-typo-role` on three hosts became a
    // first-class bucket in the ROLES bar and an entry in the role facet, for
    // every user. The control is now the same shape as the criticality one
    // beside it — a closed list.
    asAdmin();
    mount();
    fireEvent.click(await screen.findByLabelText('Select 192.168.10.8'));
    fireEvent.change(await screen.findByDisplayValue('Criticality'), { target: { value: 'role' } });

    const roleControl = await screen.findByLabelText('Role to declare');
    expect(roleControl.tagName).toBe('SELECT');
    const values = Array.from((roleControl as HTMLSelectElement).options).map((o) => o.value);
    expect(values).toContain('server');
    expect(values).toContain('domain_controller');
    expect(values).not.toContain('srever-typo-role');
  });

  it('takes the bulk role list from the summary wire, like the filter does', async () => {
    // Same source as the role facet: a role the backend adds is declarable in
    // bulk without a frontend edit, and one it drops stops being offered.
    asAdmin();
    vi.mocked(getDossierSummary).mockResolvedValue({
      ...SUMMARY,
      role_vocabulary: ['workstation', 'jump_host'],
    });
    mount();
    fireEvent.click(await screen.findByLabelText('Select 192.168.10.8'));
    fireEvent.change(await screen.findByDisplayValue('Criticality'), { target: { value: 'role' } });

    const roleControl = (await screen.findByLabelText('Role to declare')) as HTMLSelectElement;
    const values = Array.from(roleControl.options).map((o) => o.value);
    expect(values).toEqual(['', 'jump_host', 'workstation']);
  });

  it('refuses to declare nothing', async () => {
    asAdmin();
    mount();
    fireEvent.click(await screen.findByLabelText('Select 192.168.10.8'));
    expect(screen.getByRole('button', { name: /declare \(1\)/i })).toBeDisabled();
  });

  it('bulk-tagging a subnet `low` does not reorder the list ahead of the named hosts', async () => {
    // The guard on this whole feature. Only `critical` and `high` rank above a
    // NAMED host in the importance order, so a pass tagging a rack of anonymous
    // printers `low` must not put 200 rows of `HOST —` in front of the domain
    // controller. The order is the SERVER's — the screen must re-ask for it
    // with the same sort and render what comes back, never re-sort a page.
    asAdmin();
    const named = host('192.0.2.5', {}, { hostname: { value: 'dc-01', source: 'banner', confidence: 0.95, strength: 'strong', reason: null } });
    const anon = [host('192.0.2.100'), host('192.0.2.101')];
    vi.mocked(listDossiers).mockResolvedValue(page([named, ...anon]));
    vi.mocked(bulkSetDossierOverride).mockResolvedValue({
      updated: ['192.0.2.100', '192.0.2.101'],
      not_found: [],
      failed: [],
    });
    mount();
    await screen.findByText('192.0.2.5');
    const order = () =>
      screen
        .getAllByRole('link')
        .map((a) => a.textContent ?? '')
        .filter((t) => t.startsWith('192.0.2.'));
    const before = order();
    expect(before[0]).toBe('192.0.2.5');

    fireEvent.click(await screen.findByLabelText('Select 192.0.2.100'));
    fireEvent.click(await screen.findByLabelText('Select 192.0.2.101'));
    fireEvent.change(await screen.findByDisplayValue('choose…'), { target: { value: 'low' } });
    fireEvent.click(screen.getByRole('button', { name: /declare \(2\)/i }));

    await waitFor(() => expect(vi.mocked(bulkSetDossierOverride)).toHaveBeenCalled());
    // The list is re-asked for with the landing sort untouched…
    await waitFor(() => expect(lastQuery()).toMatchObject({ sort: 'importance' }));
    // …and the named host is still first.
    await waitFor(() => expect(order()).toEqual(before));
  });
});


describe('Hosts bulk declare reports a partial batch', () => {
  it('names the hosts that failed and keeps them selected for a retry', async () => {
    // A mid-batch failure used to surface as a raw 500 with a stale list and no
    // hint that part of the selection had already been declared.
    asAdmin();
    vi.mocked(bulkSetDossierOverride).mockResolvedValue({
      updated: ['192.168.10.8'],
      not_found: [],
      failed: [{ ip: '192.168.10.9', reason: 'SQLAlchemyError' }],
    });
    mount();
    fireEvent.click(await screen.findByLabelText(/select all hosts/i));
    fireEvent.change(await screen.findByDisplayValue('choose…'), { target: { value: 'low' } });
    fireEvent.click(screen.getByRole('button', { name: /declare \(2\)/i }));

    expect(await screen.findByText(/1 of 2 hosts/)).toBeTruthy();
    expect(screen.getByText(/1 failed \(192\.168\.10\.9\) — try those again/)).toBeTruthy();
    expect(screen.getByRole('button', { name: /declare \(1\)/i })).toBeTruthy();
  });

  it('clears the selection when every host took the declaration', async () => {
    asAdmin();
    vi.mocked(bulkSetDossierOverride).mockResolvedValue({
      updated: ['192.168.10.8', '192.168.10.9'],
      not_found: [],
      failed: [],
    });
    mount();
    fireEvent.click(await screen.findByLabelText(/select all hosts/i));
    fireEvent.change(await screen.findByDisplayValue('choose…'), { target: { value: 'high' } });
    fireEvent.click(screen.getByRole('button', { name: /declare \(2\)/i }));
    await waitFor(() => expect(screen.queryByTestId('list-toolbar-selection')).toBeNull());
  });
});
