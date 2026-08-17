// The host page answers one question for an analyst who just clicked through
// from an alert: WHAT IS THIS MACHINE, AND WHAT DOES THAT MEAN FOR WHAT I'M
// LOOKING AT? The 2026-08-08 dogfood pass found the old page answering a
// different question ("what does the schema hold?") — twelve cards in storage
// order, eleven of them empty, the policy note 3,800px down. These tests pin
// the rebuilt shape:
//
//   * the page LEADS with a composed identity sentence and a why-care strip
//     (policy note verbatim, criticality, coverage caveat, open conflicts with
//     both claims and both resolutions inline);
//   * only KNOWN facts get rows; the unknowns collapse to one line;
//   * provenance is words ("reported by the agent on the box"), freshness is
//     relative, and the machinery vocabulary (lanes, rungs, confidence floats,
//     absolute stamps) lives behind the evidence drawer;
//   * a failed build is a red banner with the stored error, not an invisible
//     shrug.
//
// Layout assertions RENDER AND MEASURE — count elements, read textContent,
// compare document positions — because reasoning about JSX has already missed
// a doubled SVG label on this very feature.
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { absTime } from '../lib/timeRange';
import type {
  Dossier,
  DossierField,
  DossierFieldName,
  DossierRefreshStatus,
} from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getDossier: vi.fn(),
  getHostActivity: vi.fn(),
  setDossierOverride: vi.fn(),
  clearDossierOverride: vi.fn(),
  snoozeDossierConflict: vi.fn(),
  startDossierRefresh: vi.fn(),
  // The page reads the SWEEP's own health wherever it speaks for the sweep (the
  // never-seen panel, the failed-build banner). Admin-gated GET, so it must not
  // reach the network here either.
  getDossierRefreshStatus: vi.fn(),
  getMe: vi.fn(),
  // The declare editor's role datalist reads its vocabulary from the summary
  // wire; this mount GET must not reach the network. These tests are not about
  // it, so it resolves empty and the editor falls back to ROLE_VOCABULARY.
  getDossierSummary: vi.fn().mockResolvedValue({}),
  // The chat dock rides on this page now; its mount GET must not reach the
  // network (the shared setup rejects any unmocked fetch).
  getHostChat: vi.fn(),
  postHostChat: vi.fn(),
  clearHostChat: vi.fn(),
}));

import {
  ApiError,
  clearDossierOverride,
  getDossier,
  getDossierRefreshStatus,
  getHostActivity,
  getHostChat,
  getMe,
  setDossierOverride,
  snoozeDossierConflict,
  startDossierRefresh,
} from '../lib/api';
import { roleAccent, roleRail } from '../lib/hostColors';
import type { HostActivity } from '../lib/types';
import { peerGraph } from '../components/HostActivityRow';
import { alertsHref } from '../components/HostKpis';
import { HostDetail } from './HostDetail';

// TEST-NET-1 (RFC 5737). Never a lab address: this repo publishes to GitHub and
// the leak gate reads test fixtures too.
const IP = '192.0.2.10';

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

/** One resolved field, defaulting to the shape an unswept field has. */
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

/** A whole dossier: all twelve fields in backend render order, patched by name. */
function dossier(
  patch: Partial<Record<DossierFieldName, Partial<DossierField>>> = {},
  over: Partial<Dossier> = {},
): Dossier {
  const fields = FIELD_NAMES.map((name) => field(name, patch[name] ?? {}));
  return {
    ip: IP,
    found: true,
    fields,
    first_seen: '2026-07-01T08:00:00Z',
    last_seen: '2026-08-07T09:00:00Z',
    last_built_at: '2026-08-07T06:00:00Z',
    last_observed_at: '2026-08-07T09:00:00Z',
    event_count: 3662,
    identity_rebound_at: null,
    build_error: null,
    override_count: fields.filter((f) => f.overridden).length,
    conflict_count: fields.filter((f) => f.conflict != null).length,
    reporting: false,
    ...over,
  };
}

/** The common case: one fact (a role), eleven unknowns. 24 of the 41 seeded
 *  hosts in the dogfood pass looked like this — the honest distribution. */
const sparse = () =>
  dossier({
    role: {
      value: 'workstation',
      source: 'behaviour',
      confidence: 0.7,
      strength: 'strong',
      reason: null,
      observed_at: '2026-08-07T09:00:00Z',
      last_run_at: '2026-08-07T06:00:00Z',
      evidence: {
        behaviour: {
          strings: ['687 zeek.conn records from 3 distinct peers'],
          value: 'workstation',
          strength: 'strong',
          confidence: 0.7,
          last_seen: '2026-08-07T09:00:00Z',
        },
      },
    },
  });

/** The valuable case, shaped like the hypervisor the feature exists for. */
const rich = (over: Partial<Dossier> = {}) =>
  dossier(
    {
      hostname: {
        value: 'blue',
        source: 'hostlog',
        confidence: 0.95,
        strength: 'strong',
        reason: null,
        observed_at: '2026-08-07T09:00:00Z',
        inferred_source: 'hostlog',
        evidence: {
          hostlog: {
            strings: ['blue (from agent host log)'],
            value: 'blue',
            strength: 'strong',
            confidence: 0.95,
            last_seen: '2026-08-07T09:00:00Z',
          },
        },
      },
      os_family: { value: 'linux', source: 'banner', confidence: 0.9, strength: 'strong', reason: null },
      os_detail: {
        value: 'Proxmox VE 8.4 (Debian 12)',
        source: 'banner',
        confidence: 0.9,
        strength: 'strong',
        reason: null,
        observed_at: '2026-08-07T09:00:00Z',
      },
      role: {
        value: 'hypervisor',
        source: 'behaviour',
        confidence: 0.9,
        strength: 'strong',
        reason: null,
        observed_at: '2026-08-07T09:00:00Z',
        evidence: {
          behaviour: {
            strings: ['sustained responder on tcp/8006 (pve web), tcp/22 over 14d'],
            value: 'hypervisor',
            strength: 'strong',
            confidence: 0.9,
            last_seen: '2026-08-07T09:00:00Z',
          },
        },
      },
      services_offered: {
        value: 'tcp/8006, tcp/22',
        value_json: [
          { port: 8006, proto: 'tcp', count: 1893, service: null },
          { port: 22, proto: 'tcp', count: 411, service: null },
        ],
        source: 'behaviour',
        confidence: 0.9,
        strength: 'strong',
        reason: null,
      },
      management_plane: {
        // The REAL wire shape (confirmed off a running instance 2026-08-09):
        // scalar null, dict payload. The first rebuild pass was built against
        // a bare list and dumped this exact object as raw JSON on the one
        // host you would demo.
        value: null,
        value_json: { answers: true, ports: [22, 8006] },
        source: 'behaviour',
        confidence: 0.9,
        strength: 'strong',
        reason: null,
      },
      is_static_addressed: {
        value: 'yes',
        source: 'telemetry',
        confidence: 0.8,
        strength: 'weak',
        reason: null,
      },
      activity_profile: {
        value: 'busiest hours 02:00, 03:00, 14:00 UTC; no outbound remote access',
        value_json: {
          hour_of_day: { '2': 134, '3': 141, '14': 191 },
          busiest_hours: [2, 3, 14],
          orig_bytes_p50: 1420,
          orig_bytes_p95: 88132,
          resp_bytes_p50: 5120,
          resp_bytes_p95: 912456,
          distinct_ja3: 4,
          initiates_remote_access: false,
          remote_access_ports: [],
        },
        source: 'behaviour',
        confidence: 0.9,
        strength: 'strong',
        reason: null,
      },
      criticality: {
        value: 'critical',
        source: 'operator',
        confidence: 1,
        strength: 'strong',
        reason: null,
        overridden: true,
        operator_actor: 'ops-lead',
        operator_set_at: '2026-07-19T11:18:00Z',
      },
      policy_notes: {
        value:
          'No interactive SSH expected — API-token access only. Any SSH session INTO this host is suspect.',
        source: 'operator',
        confidence: 1,
        strength: 'strong',
        reason: null,
        overridden: true,
        operator_actor: 'ops-lead',
        operator_set_at: '2026-07-19T11:18:00Z',
      },
    },
    { event_count: 48213, reporting: true, ...over },
  );

/** The live half of the page. Defaults to the shape a quiet host with no host
 *  logs has — every field present, nothing asserted. */
function activity(over: Partial<HostActivity> = {}): HostActivity {
  return {
    peers: [],
    volume: [],
    users: null,
    alerts_7d: 0,
    latest_investigation: null,
    peers_truncated: false,
    users_truncated: false,
    ...over,
  };
}

/** A finished network sweep, with whatever summary the caller wants to test.
 *  `null` is the shape an older server (or a process that has not swept) sends;
 *  a clean run carries counters and an empty `errors`. */
const sweepStatus = (
  last_summary: Record<string, unknown> | null,
  running = false,
  last_run: string | null = '2026-08-14T02:00:00+00:00',
): DossierRefreshStatus => ({
  running,
  last_run,
  last_summary,
  note: null,
});

/** The healthy control: a sweep that ran, finished and read the whole network. */
const cleanSweep = (): DossierRefreshStatus =>
  sweepStatus({ hosts_built: 412, fields_written: 3100, errors: [] });

const mount = (url = `/hosts/${IP}`) =>
  render(
    <MemoryRouter initialEntries={[url]}>
      <Routes>
        <Route path="/hosts/:ip" element={<HostDetail />} />
      </Routes>
    </MemoryRouter>,
  );

/** The NON-admin sweep read: the closed sweep-health projection
 *  (GET /api/v1/dossiers/sweep-health), stubbed at the fetch boundary because
 *  the screen deliberately does not route it through lib/api (that file
 *  belongs to another branch). Only this one path answers; any other URL keeps
 *  the shared setup's unmocked-fetch failure, and the shared afterEach
 *  unstubs. */
const stubSweepHealth = (health: {
  running: boolean;
  degraded: boolean;
  last_run: string | null;
  error_count: number;
}) =>
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (!url.includes('/api/v1/dossiers/sweep-health')) {
        throw new Error(`Unmocked network call in test: ${init?.method ?? 'GET'} ${url}`);
      }
      return { ok: true, status: 200, json: async () => health } as Response;
    }),
  );

/** The row (or strip entry) for one field, as the analyst sees it. */
const row = async (name: DossierFieldName): Promise<HTMLElement> =>
  (await screen.findByTestId(`field-${name}`)) as HTMLElement;

/**
 * What a reader actually sees before clicking anything: the DOM minus the
 * contents of closed <details>. jsdom keeps collapsed drawer content in
 * textContent, so a naive read would "see" the evidence drawers too.
 */
function visibleText(root: HTMLElement): string {
  const clone = root.cloneNode(true) as HTMLElement;
  for (const details of Array.from(clone.querySelectorAll('details'))) {
    if (!details.hasAttribute('open')) {
      for (const child of Array.from(details.children)) {
        if (child.tagName.toLowerCase() !== 'summary') child.remove();
      }
    }
  }
  return clone.textContent ?? '';
}

beforeEach(() => {
  vi.mocked(getDossier).mockReset();
  vi.mocked(getHostActivity).mockReset();
  vi.mocked(setDossierOverride).mockReset();
  vi.mocked(clearDossierOverride).mockReset();
  vi.mocked(snoozeDossierConflict).mockReset();
  vi.mocked(startDossierRefresh).mockReset();
  // A sweep that ran, finished and read everything — the healthy control for
  // every test that is not about the sweep's health.
  vi.mocked(getDossierRefreshStatus).mockReset();
  vi.mocked(getDossierRefreshStatus).mockResolvedValue(cleanSweep());
  vi.mocked(getMe).mockReset();
  vi.mocked(getMe).mockResolvedValue({ username: 'root', role: 'admin', status: '' });
  // Identity and activity are two independent fetches; the tests that are about
  // the dossier get an activity call that succeeds and says nothing.
  vi.mocked(getHostActivity).mockResolvedValue(activity());
  // The chat dock mounts with the page and fetches its thread once; these
  // tests are not about it, so it gets an empty, idle thread.
  vi.mocked(getHostChat).mockReset();
  vi.mocked(getHostChat).mockResolvedValue({ messages: [], pending: false });
});

// ---------------------------------------------------------------------------
// Addresses the sweep cannot answer for
// ---------------------------------------------------------------------------

describe('HostDetail — an address the sweep has never seen', () => {
  const neverSeen = () =>
    dossier(
      {},
      {
        found: false,
        first_seen: null,
        last_seen: null,
        last_built_at: null,
        last_observed_at: null,
        event_count: 0,
      },
    );

  it('keeps the honest first sentence and loses the config keys', async () => {
    vi.mocked(getDossier).mockResolvedValue(neverSeen());
    mount();
    // The product's soul in one line — kept verbatim.
    expect(await screen.findByText(/different from "nothing notable"/i)).toBeTruthy();
    // Config keys quoted at an analyst were the F5 finding; they are gone.
    expect(screen.queryByText(/dossier_min_events/)).toBeNull();
    expect(screen.queryByText(/dossier_lookback_days/)).toBeNull();
    expect(screen.queryByText(/Couldn't load/i)).toBeNull();
  });

  it('answers "is this address even monitored?" and offers the sweep', async () => {
    vi.mocked(getDossier).mockResolvedValue(neverSeen());
    mount();
    expect(await screen.findByText(/ranges Security Onion monitors/i)).toBeTruthy();
    // One action for an admin: sweep now.
    expect(await screen.findByRole('button', { name: /sweep the network now/i })).toBeTruthy();
  });

  it('does not offer a non-admin a button that would 403', async () => {
    vi.mocked(getMe).mockResolvedValue({ username: 'ana', role: 'analyst', status: '' });
    vi.mocked(getDossier).mockResolvedValue(neverSeen());
    mount();
    await screen.findByText(/different from "nothing notable"/i);
    expect(screen.queryByRole('button', { name: /sweep the network now/i })).toBeNull();
  });

  it('names a path segment that is not an address at all', async () => {
    // The 404's hint is what request() surfaces as the Error message.
    vi.mocked(getDossier).mockRejectedValue(new Error('the dossier is keyed on IP addresses'));
    mount('/hosts/not-a-host');
    expect(await screen.findByText(/not an IP address/i)).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// The never-seen page speaks for the sweep, so it has to ask the sweep
// ---------------------------------------------------------------------------
//
// Degraded-grid sweep, 2026-08-14 (D5). An analyst on a sick grid pressed
// Refresh host, was told "Sweeping in the background — give it a minute, then
// reload this page", followed that instruction, and landed on a page that was
// byte-identical to the same page on a healthy estate: the sweep "has never
// seen this address", and "the next sweep will pick it up once it shows enough
// traffic". The sweep it had just started died blind against Elasticsearch. The
// sibling Hosts list said so for the same run; this page had never asked.
//
// The two halves of that copy are not the same kind of statement. "No record of
// this address" is a fact about the database and survives any outage. Everything
// after it describes the sweep as a sensor that looked and a sensor that will
// look again — and it is the promise, not the absence, that ends the
// investigation.
describe('HostDetail — a sweep that came back blind does not report an address as unseen', () => {
  const neverSeen = () =>
    dossier(
      {},
      {
        found: false,
        first_seen: null,
        last_seen: null,
        last_built_at: null,
        last_observed_at: null,
        event_count: 0,
      },
    );

  // The two claims under test, matched by the SAME regexes in both directions:
  // a negative assertion whose selector matches nothing in either state is not
  // evidence of anything.
  const NEVER_SEEN = /has never seen this address/i;
  const NEXT_SWEEP = /the next sweep will pick it up/i;

  /** What the sweep stores when it could not read the grid at all. */
  const BLIND = {
    hosts_built: 0,
    fields_written: 0,
    errors: [
      'census pass: ConnectionError querying logs-*',
      'host 192.0.2.10: ConnectionError querying logs-*',
    ],
  };

  /**
   * Wait for the page to have FINISHED asking after the sweep, and say what it
   * concluded. The healthy copy is also what renders while the status request is
   * still in flight, so a control that asserts it off the first paint asserts
   * nothing — it would pass just as happily against a blind sweep.
   */
  const settled = async (facet: 'blind' | 'running' | 'unreadable' | 'read' | 'unknown') => {
    const panel = await screen.findByTestId('host-never-seen');
    await waitFor(() => expect(panel.getAttribute('data-sweep')).toBe(facet));
    return panel;
  };

  it('drops both the unseen claim and the next-sweep promise after a blind sweep', async () => {
    vi.mocked(getDossier).mockResolvedValue(neverSeen());
    vi.mocked(getDossierRefreshStatus).mockResolvedValue(sweepStatus(BLIND));
    mount();
    await settled('blind');
    // The database fact survives — the page still answers the question it was
    // opened to answer.
    const lead = screen.getByTestId('host-never-seen-lead');
    expect(lead.textContent).toMatch(/no record of this address/i);
    // Neither claim about the sensor does.
    expect(lead.textContent).not.toMatch(NEVER_SEEN);
    expect(screen.queryByText(NEVER_SEEN)).toBeNull();
    expect(screen.queryByText(NEXT_SWEEP)).toBeNull();
  });

  it('says how the sweep failed, and how many ways', async () => {
    vi.mocked(getDossier).mockResolvedValue(neverSeen());
    vi.mocked(getDossierRefreshStatus).mockResolvedValue(sweepStatus(BLIND));
    mount();
    const note = await screen.findByTestId('host-sweep-blind');
    expect(note.textContent).toMatch(/2 errors/);
    // The strings, not only the count: half this channel is local
    // misconfiguration an operator can fix without touching Security Onion.
    expect(note.textContent).toMatch(/census pass: ConnectionError/);
  });

  it('counts the rest rather than printing an outage a hundred times', async () => {
    vi.mocked(getDossier).mockResolvedValue(neverSeen());
    vi.mocked(getDossierRefreshStatus).mockResolvedValue(
      sweepStatus({
        errors: [
          'census pass: ConnectionError querying logs-*',
          'host 192.0.2.10: ConnectionError querying logs-*',
          'host 192.0.2.11: ConnectionError querying logs-*',
          'host 192.0.2.12: ConnectionError querying logs-*',
        ],
      }),
    );
    mount();
    const note = await screen.findByTestId('host-sweep-blind');
    expect(note.textContent).toMatch(/2 more/);
  });

  // ---- The healthy controls. This copy is correct and useful, and replacing
  // it with a degraded banner on a working estate would be its own regression.

  it('keeps the never-seen explanation whole when the sweep read the network', async () => {
    vi.mocked(getDossier).mockResolvedValue(neverSeen());
    // The beforeEach default is a clean, finished sweep — stated here anyway,
    // because this test is the control the ones above are measured against.
    vi.mocked(getDossierRefreshStatus).mockResolvedValue(cleanSweep());
    mount();
    await settled('read');
    expect(screen.getByTestId('host-never-seen-lead').textContent).toMatch(NEVER_SEEN);
    expect(screen.getByText(NEXT_SWEEP)).toBeTruthy();
    expect(screen.queryByTestId('host-sweep-blind')).toBeNull();
  });

  it('keeps it whole when a healthy sweep left advisory notes', async () => {
    // `notes` is where a healthy run reports a truncated cap or a cadence
    // ceiling. A page that degraded on those would degrade every night.
    vi.mocked(getDossier).mockResolvedValue(neverSeen());
    vi.mocked(getDossierRefreshStatus).mockResolvedValue(
      sweepStatus({
        hosts_built: 412,
        errors: [],
        notes: ['census truncated at the 500-host cap'],
      }),
    );
    mount();
    await settled('read');
    expect(screen.getByTestId('host-never-seen-lead').textContent).toMatch(NEVER_SEEN);
    expect(screen.getByText(NEXT_SWEEP)).toBeTruthy();
  });

  it('keeps it whole when the server has no sweep record to offer', async () => {
    // An older server, or a process that has not swept since it started. No
    // record is not a record of failure.
    vi.mocked(getDossier).mockResolvedValue(neverSeen());
    vi.mocked(getDossierRefreshStatus).mockResolvedValue(sweepStatus(null));
    mount();
    await settled('read');
    expect(screen.getByTestId('host-never-seen-lead').textContent).toMatch(NEVER_SEEN);
    expect(screen.getByText(NEXT_SWEEP)).toBeTruthy();
  });

  it('lets a sweep in flight supersede the last one’s verdict', async () => {
    // A running sweep is about to answer the question the errors below it
    // answered last time, so the page waits for it rather than reporting a
    // verdict that is being overwritten — the same rule the Hosts list follows.
    vi.mocked(getDossier).mockResolvedValue(neverSeen());
    vi.mocked(getDossierRefreshStatus).mockResolvedValue(sweepStatus(BLIND, true));
    mount();
    await settled('running');
    expect(screen.getByTestId('host-sweep-running')).toBeTruthy();
    expect(screen.queryByTestId('host-sweep-blind')).toBeNull();
    // And the button is gone: clicking it would have collided with the sweep
    // already running and answered 'already running'.
    expect(screen.queryByRole('button', { name: /sweep the network now/i })).toBeNull();
  });

  it('reports the outcome of the sweep it started, without a reload', async () => {
    // The whole shape of D5: the click, the wait, and then the page telling the
    // analyst what happened instead of asking them to reload into copy that
    // could not have known.
    vi.mocked(getDossier).mockResolvedValue(neverSeen());
    vi.mocked(getDossierRefreshStatus).mockResolvedValue(cleanSweep());
    vi.mocked(startDossierRefresh).mockResolvedValue({
      running: true,
      last_run: null,
      last_summary: null,
      note: 'started',
    });
    mount();
    const button = await screen.findByRole('button', { name: /sweep the network now/i });
    // The sweep dies against the grid the moment it starts. A finished run
    // advances `last_run`, which is how the page tells the run it started from
    // the one it was looking at when it clicked.
    vi.mocked(getDossierRefreshStatus).mockResolvedValue(
      sweepStatus({ errors: ['refresh failed; see server logs'] }, false, '2026-08-14T02:41:00Z'),
    );
    fireEvent.click(button);
    await waitFor(() => expect(startDossierRefresh).toHaveBeenCalled());
    await settled('blind');
    expect(screen.getByTestId('host-sweep-blind')).toBeTruthy();
    expect(screen.queryByText(NEXT_SWEEP)).toBeNull();
    // The kickoff receipt has been superseded by the outcome, not left sitting
    // over it telling the analyst to give it a minute.
    expect(screen.queryByText(/sweeping in the background/i)).toBeNull();
  });

  it('discloses a dead sweep to a role that may not read the full record', async () => {
    // FLIPPED PIN (task #91). Until 2026-08-17 this test pinned the known-wrong
    // state under the name 'leaves the sweep unread for a role that may not
    // read it': GET /dossiers/refresh is admin-gated
    // (soc_ai/api/webui/routes_dossier.py), so an analyst got no sweep record
    // and this page fell back to the healthy explanation — the false all-clear
    // was narrower than it had been, but for a non-admin it was still there,
    // served precisely to the role least able to check. The pin's own docstring
    // asked whoever added an analyst-readable sweep-health route to come back
    // and flip it; that route is the closed projection at
    // GET /dossiers/sweep-health (running / degraded / last_run / error COUNT
    // — never the failure strings), and this is the flip.
    vi.mocked(getMe).mockResolvedValue({ username: 'ana', role: 'analyst', status: '' });
    vi.mocked(getDossier).mockResolvedValue(neverSeen());
    stubSweepHealth({
      running: false,
      degraded: true,
      last_run: '2026-08-14T02:41:00Z',
      error_count: 2,
    });
    mount();
    await settled('blind');
    // The database fact survives; neither claim about the sensor does.
    expect(screen.getByTestId('host-never-seen-lead').textContent).toMatch(
      /no record of this address/i,
    );
    expect(screen.queryByText(NEVER_SEEN)).toBeNull();
    expect(screen.queryByText(NEXT_SWEEP)).toBeNull();
    // The COUNT crosses the role boundary; the failure strings never do. The
    // negative selector is proven live by the admin tests above, where the
    // same regex DOES match the rendered strings.
    const note = screen.getByTestId('host-sweep-blind');
    expect(note.textContent).toMatch(/2 errors/);
    expect(screen.queryByText(/ConnectionError/)).toBeNull();
    expect(note.textContent).toMatch(/An admin can read what failed/i);
    // And the admin route was never asked — it could only have 403'd.
    expect(getDossierRefreshStatus).not.toHaveBeenCalled();
  });

  it('shows a non-admin the sweep in flight instead of the last verdict', async () => {
    vi.mocked(getMe).mockResolvedValue({ username: 'ana', role: 'analyst', status: '' });
    vi.mocked(getDossier).mockResolvedValue(neverSeen());
    stubSweepHealth({ running: true, degraded: false, last_run: null, error_count: 0 });
    mount();
    await settled('running');
    expect(screen.getByTestId('host-sweep-running')).toBeTruthy();
    expect(screen.queryByTestId('host-sweep-blind')).toBeNull();
    // Still no button that would 403.
    expect(screen.queryByRole('button', { name: /sweep the network now/i })).toBeNull();
  });

  it('keeps the never-seen explanation whole for a non-admin on a healthy estate', async () => {
    // The control, per role: the projection must only change what a DEGRADED
    // or RUNNING sweep shows. A healthy record read through it keeps the
    // genuine copy — including the next-sweep promise, which that record now
    // actually supports.
    vi.mocked(getMe).mockResolvedValue({ username: 'ana', role: 'analyst', status: '' });
    vi.mocked(getDossier).mockResolvedValue(neverSeen());
    stubSweepHealth({
      running: false,
      degraded: false,
      last_run: '2026-08-14T02:00:00+00:00',
      error_count: 0,
    });
    mount();
    await settled('read');
    expect(screen.getByTestId('host-never-seen-lead').textContent).toMatch(NEVER_SEEN);
    expect(screen.getByText(NEXT_SWEEP)).toBeTruthy();
    expect(screen.queryByTestId('host-sweep-blind')).toBeNull();
    expect(getDossierRefreshStatus).not.toHaveBeenCalled();
  });

  // ---- A promise the page prints has to hold for the sweep on screen, not
  // only for the one this tab happened to click.

  it('re-reads the host when a sweep it did not start finishes', async () => {
    // The running note comes off the server's status, so the page prints "this
    // page updates when it finishes" for ANY sweep in flight — including the
    // one an admin kicked off from the Hosts list a moment before clicking into
    // this host, and the one already running when they arrived. Following the
    // instruction and waiting has to work for those too, or the page is telling
    // someone to wait for an update it will never make.
    vi.useFakeTimers();
    try {
      vi.mocked(getDossier).mockResolvedValue(neverSeen());
      vi.mocked(getDossierRefreshStatus).mockResolvedValue(sweepStatus(null, true));
      mount();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
      });
      expect(screen.getByTestId('host-sweep-running')).toBeTruthy();
      const readsWhileRunning = vi.mocked(getDossier).mock.calls.length;

      // That sweep gets through and builds this very host.
      vi.mocked(getDossier).mockResolvedValue(dossier());
      vi.mocked(getDossierRefreshStatus).mockResolvedValue(
        sweepStatus({ hosts_built: 1, errors: [] }, false, '2026-08-14T03:00:00+00:00'),
      );
      // One poll interval carries the running → finished transition.
      await act(async () => {
        await vi.advanceTimersByTimeAsync(4001);
      });

      expect(vi.mocked(getDossier).mock.calls.length).toBeGreaterThan(readsWhileRunning);
      expect(screen.queryByTestId('host-never-seen')).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it('re-reads a host whose build failed when a sweep it watched finishes', async () => {
    // The same gap on the other panel that speaks for the sweep. Here the page
    // prints no promise, so the cost is quieter and worse: the red "the last
    // sweep failed on this host" banner and the stale facts under it survive
    // the sweep that just fixed them, on a page that was watching it run.
    vi.useFakeTimers();
    try {
      vi.mocked(getDossier).mockResolvedValue(
        dossier({}, { build_error: 'ConnectionError querying logs-*' }),
      );
      vi.mocked(getDossierRefreshStatus).mockResolvedValue(sweepStatus(null, true));
      mount();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
      });
      expect(screen.getByText(/The last sweep failed on this host/i)).toBeTruthy();

      vi.mocked(getDossier).mockResolvedValue(dossier());
      vi.mocked(getDossierRefreshStatus).mockResolvedValue(
        sweepStatus({ hosts_built: 1, errors: [] }, false, '2026-08-14T03:00:00+00:00'),
      );
      await act(async () => {
        await vi.advanceTimersByTimeAsync(4001);
      });

      expect(screen.queryByText(/The last sweep failed on this host/i)).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not re-read the host on a poll that changed nothing', async () => {
    // The control for the two above: the re-read is a response to a sweep
    // ENDING. A page that re-fetched the dossier on every status poll would put
    // a 4-second query loop on every never-seen host page left open. It passes
    // against the unfixed screen too — that is what a control is for; the
    // measurement it makes (a call count that does not move while one does move
    // above) is the part that is not free.
    vi.useFakeTimers();
    try {
      vi.mocked(getDossier).mockResolvedValue(neverSeen());
      vi.mocked(getDossierRefreshStatus).mockResolvedValue(sweepStatus(null, true));
      mount();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
      });
      const readsWhileRunning = vi.mocked(getDossier).mock.calls.length;
      // Three more polls, all still running.
      await act(async () => {
        await vi.advanceTimersByTimeAsync(12_001);
      });
      expect(vi.mocked(getDossier).mock.calls.length).toBe(readsWhileRunning);
      expect(screen.getByTestId('host-sweep-running')).toBeTruthy();
    } finally {
      vi.useRealTimers();
    }
  });

  // ---- The other lane. The sweep's record is a claim about the database; the
  // activity read is a live question put to the same grid, on the same page.

  it('says so when the live read this page also made came back 503', async () => {
    // The pre-click capture in `stalled`: the page's own
    // GET /dossiers/{ip}/activity took twelve seconds and 503'd, and not one
    // pixel changed. With no sweep record on a freshly restarted server, the
    // panel then reads exactly as it does on a healthy estate — while the grid
    // it is describing could not be read at all.
    vi.mocked(getDossier).mockResolvedValue(neverSeen());
    vi.mocked(getHostActivity).mockRejectedValue(
      new ApiError(
        'The Security Onion grid (Elasticsearch) is slow or unreachable — retry shortly',
        503,
      ),
    );
    vi.mocked(getDossierRefreshStatus).mockResolvedValue(sweepStatus(null));
    mount();
    await settled('read');
    const note = await screen.findByTestId('host-activity-unread');
    // The grid's own words, so the operator knows which system to go and look at.
    expect(note.textContent).toMatch(/slow or unreachable/i);
  });

  it('keeps the panel plain when the live read worked', async () => {
    // Control. A successful activity read on a never-seen host is a real
    // answer — no traffic, from a grid that answered — and it must not paint a
    // warning. The call assertion is the load-bearing half: an absence assertion
    // whose selector matches nothing in either state proves nothing, so this
    // pins that the lane RAN and still left the panel plain.
    vi.mocked(getDossier).mockResolvedValue(neverSeen());
    vi.mocked(getDossierRefreshStatus).mockResolvedValue(cleanSweep());
    mount();
    await settled('read');
    expect(getHostActivity).toHaveBeenCalled();
    expect(screen.queryByTestId('host-activity-unread')).toBeNull();
  });

  // ---- "We asked and it was clean" and "we could not ask" are different
  // answers, and only one of them supports a promise.

  it('does not promise a next sweep when it could not read the sweep at all', async () => {
    // Admin, so the page asks — and the read fails. Rendering the full healthy
    // copy here asserts the very thing the page just failed to check.
    vi.mocked(getDossier).mockResolvedValue(neverSeen());
    vi.mocked(getDossierRefreshStatus).mockRejectedValue(
      new ApiError('The sweep status could not be read', 503),
    );
    mount();
    await settled('unreadable');
    expect(screen.queryByText(NEXT_SWEEP)).toBeNull();
    expect(screen.queryByText(NEVER_SEEN)).toBeNull();
    // The database fact still stands, and the page still answers with it.
    expect(screen.getByTestId('host-never-seen-lead').textContent).toMatch(
      /no record of this address/i,
    );
    // Why it cannot say more, and the words the failure came with — an
    // operator told the page gave up wants to know on what.
    const hedge = screen.getByTestId('host-sweep-unreadable').textContent ?? '';
    expect(hedge).toMatch(/could not check how the last sweep went/i);
    expect(hedge).toMatch(/The sweep status could not be read/);
  });

  it('still offers the sweep when it could not read the last one', async () => {
    // Control for the one above, and the over-correction this batch is closest
    // to shipping: a failed GET /dossiers/refresh says nothing about the POST,
    // and an unreadable status is exactly when an operator wants to start a run
    // and watch it. Degrade the claim, not the screen.
    vi.mocked(getDossier).mockResolvedValue(neverSeen());
    vi.mocked(getDossierRefreshStatus).mockRejectedValue(
      new ApiError('The sweep status could not be read', 503),
    );
    mount();
    await settled('unreadable');
    expect(screen.getByRole('button', { name: /sweep the network now/i })).toBeTruthy();
    // And the panel is still a panel, not an error wall: the page answers the
    // question it was opened to answer.
    expect(screen.queryByText(/Couldn't load/i)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The identity sentence — the page's first line and whole point
// ---------------------------------------------------------------------------

describe('HostDetail — the identity sentence', () => {
  it('composes every known identity fact into one readable sentence', async () => {
    vi.mocked(getDossier).mockResolvedValue(rich());
    mount();
    const sentence = await screen.findByTestId('host-sentence');
    expect(sentence.textContent).toBe(
      'blue is a hypervisor running Proxmox VE 8.4 (Debian 12), at a fixed address, ' +
        'with admin interfaces on tcp/22, tcp/8006.',
    );
  });

  it('says one thing plainly on the common sparse host', async () => {
    vi.mocked(getDossier).mockResolvedValue(sparse());
    mount();
    expect((await screen.findByTestId('host-sentence')).textContent).toBe(
      `${IP} is a workstation.`,
    );
  });

  it('admits when nothing is known instead of rendering twelve empty boxes', async () => {
    vi.mocked(getDossier).mockResolvedValue(dossier());
    mount();
    expect((await screen.findByTestId('host-sentence')).textContent).toMatch(
      /nothing else is known about it yet/i,
    );
  });
});

// ---------------------------------------------------------------------------
// The hero: name, colour, coverage, freshness
// ---------------------------------------------------------------------------

describe('HostDetail — the hero banner', () => {
  it('leads with the name a human uses and keeps the address beside it', async () => {
    vi.mocked(getDossier).mockResolvedValue(rich());
    mount();
    expect((await screen.findByTestId('hero-name')).textContent).toBe('blue');
    expect(within(await screen.findByTestId('host-hero')).getByText(IP)).toBeTruthy();
  });

  it('falls back to the address when nothing has named the host', async () => {
    vi.mocked(getDossier).mockResolvedValue(dossier());
    mount();
    expect((await screen.findByTestId('hero-name')).textContent).toBe(IP);
  });

  it('wears the role family colour on chip and rail alike', async () => {
    vi.mocked(getDossier).mockResolvedValue(rich());
    mount();
    const chip = await screen.findByTestId('hero-role');
    expect(chip.textContent).toContain('hypervisor');
    expect(chip.className).toContain(roleAccent('hypervisor'));
    const hero = await screen.findByTestId('host-hero');
    const wearsTheRail = Array.from(hero.querySelectorAll('div')).some((el) =>
      el.className.split(' ').includes(roleRail('hypervisor')),
    );
    expect(wearsTheRail).toBe(true);
  });

  it('speaks freshness in relative time, keeping the wall clock in the tooltip', async () => {
    vi.mocked(getDossier).mockResolvedValue(rich());
    mount();
    const facts = await screen.findByTestId('hero-facts');
    // Four second-precision timestamps was the old header. Now: relative ages
    // a reader can feel, absolute times one hover away.
    expect(facts.textContent).toMatch(/first seen .*ago/i);
    expect(facts.textContent).toMatch(/last seen .*ago/i);
    expect(facts.textContent).toMatch(/swept .*ago/i);
    expect(facts.textContent).not.toMatch(/2026/);
    expect(facts.textContent).toContain('48,213 events');
    // "built from 433 events" beside "last built —" was the F3 giveaway; the
    // phrase is retired.
    expect(facts.textContent).not.toMatch(/built from/i);
    const withClock = Array.from(facts.querySelectorAll('[title]')).some((el) =>
      /2026/.test(el.getAttribute('title') ?? ''),
    );
    expect(withClock).toBe(true);
  });

  it('says "agent on box" when the machine reports on itself', async () => {
    vi.mocked(getDossier).mockResolvedValue(rich());
    mount();
    const chip = await screen.findByTestId('hero-agent');
    expect(chip.textContent).toMatch(/agent on box/i);
    // The claim names its evidence rather than asking for faith.
    expect(chip.getAttribute('title')).toContain('Hostname');
  });

  it('does not let an operator declaration uninstall the agent', async () => {
    // `source` reads 'operator' on an overridden field, but typing a hostname
    // does not stop the machine shipping logs. The wire's per-host `reporting`
    // flag is computed under the override, so the chip follows it.
    vi.mocked(getDossier).mockResolvedValue(
      dossier(
        {
          hostname: {
            value: 'pve-01',
            source: 'operator',
            confidence: 1,
            strength: 'strong',
            reason: null,
            overridden: true,
            operator_actor: 'ops-lead',
            operator_set_at: '2026-08-06T10:00:00Z',
            inferred_value: 'pve-a',
            inferred_confidence: 0.9,
            inferred_source: 'hostlog',
          },
        },
        { reporting: true },
      ),
    );
    mount();
    expect((await screen.findByTestId('hero-agent')).textContent).toMatch(/agent on box/i);
  });

  it('trusts the wire over the field guess when the agent has gone quiet', async () => {
    // The backend computes `reporting` through the resolver's staleness gates,
    // which the client does not hold. A field that once came from the agent's
    // logs proves the agent EXISTED — not that it still reports. A false
    // "agent on box" sends an analyst to grep host logs that stopped weeks
    // ago, which is the inverse of the false negative the flag exists to
    // prevent.
    vi.mocked(getDossier).mockResolvedValue(
      dossier(
        {
          hostname: {
            value: 'pve-01',
            source: 'hostlog',
            confidence: 0.9,
            strength: 'strong',
            reason: null,
            inferred_source: 'hostlog',
          },
        },
        { reporting: false },
      ),
    );
    mount();
    expect((await screen.findByTestId('hero-agent')).textContent).toMatch(/network-only view/i);
  });

  it('keeps the rebound warning ABOVE the identity it undermines', async () => {
    vi.mocked(getDossier).mockResolvedValue(rich({ identity_rebound_at: '2026-08-06T04:00:00Z' }));
    mount();
    const warning = await screen.findByRole('alert');
    expect(warning).toHaveTextContent(/different machine/i);
    const hero = await screen.findByTestId('host-hero');
    expect(warning.compareDocumentPosition(hero) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// The why-care strip
// ---------------------------------------------------------------------------

describe('HostDetail — the why-care strip', () => {
  it('carries the policy note verbatim, with its author, above the fold', async () => {
    vi.mocked(getDossier).mockResolvedValue(rich());
    mount();
    const briefing = await screen.findByTestId('host-briefing');
    // The sentence written to prevent the 08-05 incident sat ~3,800px down.
    // Now it is in the lead, word for word, with the person who wrote it.
    expect(
      within(briefing).getByText(/Any SSH session INTO this host is suspect/),
    ).toBeTruthy();
    expect(briefing.textContent).toMatch(/declared by ops-lead/i);
    expect(within(briefing).getByText('critical')).toBeTruthy();
  });

  it('renders the KPI cards first, the why-care strip directly under them', async () => {
    // The owner asked for KPIs/charts at the top; the why-care strip stays
    // high — hero, then the four cards, then the briefing, then facts.
    vi.mocked(getDossier).mockResolvedValue(rich());
    mount();
    const hero = await screen.findByTestId('host-hero');
    const kpis = await screen.findByTestId('kpi-services');
    const briefing = await screen.findByTestId('host-briefing');
    const facts = await screen.findByTestId('host-facts');
    const follows = (a: Element, b: Element) =>
      Boolean(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);
    expect(follows(hero, kpis)).toBe(true);
    expect(follows(kpis, briefing)).toBe(true);
    expect(follows(briefing, facts)).toBe(true);
  });

  it('translates "no agent" into what the analyst cannot see', async () => {
    vi.mocked(getDossier).mockResolvedValue(sparse());
    mount();
    const briefing = await screen.findByTestId('host-briefing');
    expect(briefing.textContent).toMatch(/processes, users and local logs/i);
    expect(briefing.textContent).toMatch(/network traffic/i);
    expect((await screen.findByTestId('hero-agent')).textContent).toMatch(/network-only view/i);
  });

  it('does not caveat coverage on a host whose agent reports', async () => {
    vi.mocked(getDossier).mockResolvedValue(rich());
    mount();
    const briefing = await screen.findByTestId('host-briefing');
    expect(briefing.textContent).not.toMatch(/processes, users and local logs/i);
  });
});

// ---------------------------------------------------------------------------
// The sparse page, measured
// ---------------------------------------------------------------------------

describe('HostDetail — the common case is one fact, not sixteen boxes of absence', () => {
  it('renders exactly one fact row and one collapsed unknown line', async () => {
    vi.mocked(getDossier).mockResolvedValue(sparse());
    mount();
    await screen.findByTestId('host-facts');
    expect(screen.getAllByTestId(/^field-/).length).toBe(1);
    const unknown = await screen.findByTestId('host-unknowns');
    expect(unknown.querySelector('details')?.hasAttribute('open')).toBe(false);
    // The one-line summary names the gaps without a card per gap.
    const summaryLine = unknown.querySelector('summary')?.textContent ?? '';
    expect(summaryLine).toMatch(/unknown/i);
    expect(summaryLine).toContain('MAC address');
    expect(summaryLine).toMatch(/\+\d+ more/);
  });

  it('offers no declare buttons until the reader asks for the unknowns', async () => {
    // Twelve "Declare a value" buttons on a page opened to READ was F1.
    vi.mocked(getDossier).mockResolvedValue(sparse());
    mount();
    const page = (await screen.findByTestId('host-facts')).ownerDocument.body;
    expect(visibleText(page)).not.toMatch(/declare a value/i);

    fireEvent.click(within(screen.getByTestId('host-unknowns')).getByText(/unknown/i));
    expect(
      within(screen.getByTestId('host-unknowns')).getAllByRole('button', {
        name: /declare a value/i,
      }).length,
    ).toBe(11);
  });

  it('never says "no build has evaluated this field yet"', async () => {
    vi.mocked(getDossier).mockResolvedValue(sparse());
    mount();
    await screen.findByTestId('host-facts');
    expect(document.body.textContent).not.toMatch(/no build has evaluated/i);
  });
});

// ---------------------------------------------------------------------------
// Language: the analyst's, not the data model's
// ---------------------------------------------------------------------------

describe('HostDetail — the machinery vocabulary stays off the glass', () => {
  it('shows no schema keys, rung names, lane talk or confidence floats by default', async () => {
    vi.mocked(getDossier).mockResolvedValue(rich());
    mount();
    await screen.findByTestId('host-facts');
    const seen = visibleText(document.body);
    // Schema keys (the raw key survives only in URLs and the API).
    for (const key of ['os_family', 'is_static_addressed', 'management_plane', 'activity_profile', 'policy_notes', 'services_offered']) {
      expect(seen).not.toContain(key);
    }
    // Internal nouns.
    expect(seen).not.toMatch(/\blanes?\b/i);
    expect(seen).not.toMatch(/\bbuilder\b/i);
    expect(seen).not.toMatch(/\brung\b/i);
    expect(seen).not.toMatch(/\binference\b/i);
    expect(seen).not.toMatch(/resolved on read/i);
    // A bare rung name as a chip.
    expect(seen).not.toMatch(/\bbehaviour\b/i);
    // Scores and strength labels belong in the drawer.
    expect(seen).not.toMatch(/0\.\d{2}/);
    expect(seen).not.toMatch(/\b(strong|weak)\b/i);
  });

  it('keeps the raw record one click away for whoever asks "says who?"', async () => {
    vi.mocked(getDossier).mockResolvedValue(rich());
    mount();
    const roleRow = await row('role');
    fireEvent.click(within(roleRow).getByText(/why\?/i));
    // The drawer is where the rung, the score, the stored strength and the
    // wall-clock stamps live — available, not ambient.
    expect(within(roleRow).getByText(/sustained responder on tcp\/8006/)).toBeTruthy();
    const drawer = roleRow.querySelector('details') as HTMLElement;
    expect(drawer.textContent).toContain('behaviour');
    expect(drawer.textContent).toContain('0.90');
    expect(drawer.textContent).toContain('strong');
  });
});

// ---------------------------------------------------------------------------
// What we know — the fact rows
// ---------------------------------------------------------------------------

describe('HostDetail — the fact rows', () => {
  it('gives each fact its value, its provenance in words, and a relative age', async () => {
    vi.mocked(getDossier).mockResolvedValue(rich());
    mount();
    const os = await row('os_detail');
    expect(within(os).getByText('Proxmox VE 8.4 (Debian 12)')).toBeTruthy();
    expect(os.textContent).toMatch(/read from a service banner/i);
    // textContent concatenates the row's nodes ("…agoEdit"), so anchor the
    // front of the word only.
    expect(os.textContent).toMatch(/\bago/);

    const role = await row('role');
    expect(role.textContent).toMatch(/inferred from its traffic/i);

    const name = await row('hostname');
    expect(name.textContent).toMatch(/reported by the agent on the box/i);
  });

  it('does not give criticality or the operator note a second row under the strip', async () => {
    // They lead the page; a copy in the table would be the same fact twice on
    // one screen — the duplication F6 counted six deep on conflicts.
    vi.mocked(getDossier).mockResolvedValue(rich());
    mount();
    await screen.findByTestId('host-facts');
    expect(screen.getAllByTestId('field-criticality').length).toBe(1);
    expect(screen.getAllByTestId('field-policy_notes').length).toBe(1);
    const facts = screen.getByTestId('host-facts');
    expect(within(facts).queryByTestId('field-criticality')).toBeNull();
    expect(within(facts).queryByTestId('field-policy_notes')).toBeNull();
  });

  it('renders ports as chips, never a comma-string split apart', async () => {
    vi.mocked(getDossier).mockResolvedValue(rich());
    mount();
    const services = await row('services_offered');
    expect(within(services).getByText('tcp/8006')).toBeTruthy();
    expect(within(services).getByText('tcp/22')).toBeTruthy();
  });

  it('renders the admin-interface payload as words, never raw JSON', async () => {
    // {"answers":true,"ports":[8006,8007,22]} rendered LITERALLY on the
    // flagship hypervisor in the 2026-08-09 dogfood pass — the one field shape
    // the first rebuild pass did not meet. F8 is not fixed until the demo host
    // shows no source code.
    vi.mocked(getDossier).mockResolvedValue(
      dossier({
        management_plane: {
          value: null,
          value_json: { answers: true, ports: [8006, 8007, 22] },
          source: 'behaviour',
          confidence: 0.9,
          strength: 'strong',
          reason: null,
        },
      }),
    );
    mount();
    const admin = await row('management_plane');
    expect(admin.textContent).toMatch(/answers on/i);
    expect(within(admin).getByText('tcp/8006')).toBeTruthy();
    expect(within(admin).getByText('tcp/8007')).toBeTruthy();
    expect(within(admin).getByText('tcp/22')).toBeTruthy();
    expect(visibleText(admin)).not.toContain('{"answers"');
    expect(visibleText(admin)).not.toContain('ports');
  });

  it('says "no admin interface answering" instead of a false-looking object', async () => {
    vi.mocked(getDossier).mockResolvedValue(
      dossier({
        management_plane: {
          value: null,
          value_json: { answers: false, ports: [] },
          source: 'behaviour',
          confidence: 0.7,
          strength: 'weak',
          reason: null,
        },
      }),
    );
    mount();
    const admin = await row('management_plane');
    expect(within(admin).getByText(/no admin interface answering/i)).toBeTruthy();
    expect(visibleText(admin)).not.toContain('{"answers"');
  });

  it('reads the same dict family on services offered before a host ships one', async () => {
    vi.mocked(getDossier).mockResolvedValue(
      dossier({
        services_offered: {
          value: null,
          value_json: { ports: [443] },
          source: 'behaviour',
          confidence: 0.9,
          strength: 'strong',
          reason: null,
        },
      }),
    );
    mount();
    const services = await row('services_offered');
    expect(within(services).getByText('tcp/443')).toBeTruthy();
    expect(visibleText(services)).not.toContain('{"ports"');
  });

  it('shows an overridden fact as the standing answer with its author and note', async () => {
    vi.mocked(getDossier).mockResolvedValue(
      dossier({
        hostname: {
          value: 'nas01',
          source: 'operator',
          confidence: 1,
          strength: 'strong',
          reason: null,
          overridden: true,
          operator_actor: 'ops-lead',
          operator_note: 'the TrueNAS box; DNS lags renames',
          operator_set_at: '2026-08-06T10:00:00Z',
          inferred_value: 'truenas',
          inferred_confidence: 0.8,
          inferred_source: 'telemetry',
        },
      }),
    );
    mount();
    const name = await row('hostname');
    expect(within(name).getByText('nas01')).toBeTruthy();
    expect(name.textContent).toMatch(/declared by ops-lead/i);
    // The note verbatim — the two-lane surface honesty this feature keeps.
    expect(within(name).getByText(/DNS lags renames/)).toBeTruthy();
    // The suppressed reading stays one click away, with its value.
    fireEvent.click(within(name).getByText(/why\?/i));
    expect(name.textContent).toMatch(/sweep's own reading/i);
    expect(name.textContent).toContain('truenas');
  });

  it('offers to remove a declaration, saying what will stand in its place', async () => {
    vi.mocked(getDossier).mockResolvedValue(
      dossier({
        hostname: {
          value: 'nas01',
          source: 'operator',
          confidence: 1,
          strength: 'strong',
          reason: null,
          overridden: true,
          operator_actor: 'ops-lead',
          operator_set_at: '2026-08-06T10:00:00Z',
          inferred_value: 'truenas',
          inferred_confidence: 0.8,
          inferred_source: 'telemetry',
        },
      }),
    );
    vi.mocked(clearDossierOverride).mockResolvedValue(dossier());
    mount();
    const name = await row('hostname');
    fireEvent.click(within(name).getByText(/why\?/i));
    const remove = within(name).getByRole('button', { name: /remove my declaration/i });
    // The label says what happens next — the sweep's answer stands.
    expect(remove.textContent).toContain('truenas');
    fireEvent.click(remove);
    await waitFor(() => expect(clearDossierOverride).toHaveBeenCalledWith(IP, 'hostname'));
  });

  it('says a removed note simply goes back to unknown when the sweep has nothing', async () => {
    // "Hand back to the builder" on a field the sweep never infers offered to
    // trade a value for nothing without saying so (F5).
    vi.mocked(getDossier).mockResolvedValue(rich());
    mount();
    const note = await screen.findByTestId('field-policy_notes');
    fireEvent.click(within(note).getByText(/why\?/i));
    const remove = within(note).getByRole('button', { name: /remove my declaration/i });
    expect(remove.textContent).toMatch(/back to unknown/i);
  });
});

// ---------------------------------------------------------------------------
// The traffic pattern — a sparkline, not source code
// ---------------------------------------------------------------------------

describe('HostDetail — the traffic pattern renders as a chart', () => {
  it('draws 24 hour buckets and speaks the byte shape with units', async () => {
    vi.mocked(getDossier).mockResolvedValue(rich());
    mount();
    const profile = await row('activity_profile');
    // Measured: one bar per hour of day.
    expect(profile.querySelectorAll('svg rect').length).toBe(24);
    expect(profile.textContent).toContain('typical request 1.4 KB');
    expect(profile.textContent).toContain('typical response 5 KB (up to 891 KB)');
    // The summary the builder already wrote stays the headline.
    expect(within(profile).getByText(/busiest hours 02:00, 03:00, 14:00 UTC/)).toBeTruthy();
  });

  it('keeps the raw JSON out of the default view', async () => {
    vi.mocked(getDossier).mockResolvedValue(rich());
    mount();
    const profile = await row('activity_profile');
    expect(visibleText(profile)).not.toContain('"0"');
    expect(visibleText(profile)).not.toContain('hour_of_day');
    expect(visibleText(profile)).not.toContain('912456');
  });
});

// ---------------------------------------------------------------------------
// The unknowns
// ---------------------------------------------------------------------------

describe('HostDetail — the unknown line tells the truth about why', () => {
  it('distinguishes never-checked, checked-and-nothing, stale and a thin lean', async () => {
    vi.mocked(getDossier).mockResolvedValue(
      dossier({
        role: { value: 'server', source: 'behaviour', confidence: 0.9, strength: 'strong', reason: null },
        hostname: { reason: 'no_signal', last_run_at: '2026-08-07T06:00:00Z' },
        mac: { reason: 'no_signal', last_run_at: null },
        os_family: { reason: 'stale', last_run_at: '2026-08-01T06:00:00Z' },
        domain_membership: {
          reason: 'low_confidence',
          inferred_value: 'CORP',
          inferred_confidence: 0.5,
          inferred_source: 'telemetry',
          last_run_at: '2026-08-07T06:00:00Z',
        },
      }),
    );
    mount();
    const unknowns = await screen.findByTestId('host-unknowns');
    fireEvent.click(within(unknowns).getByText(/unknown/i));
    expect(unknowns.textContent).toMatch(/checked — nothing found/i);
    expect(unknowns.textContent).toMatch(/not checked yet/i);
    expect(unknowns.textContent).toMatch(/too old to trust/i);
    expect(unknowns.textContent).toMatch(/possibly "CORP"/i);
  });

  it('declares a value from the unknown line and re-renders from the response', async () => {
    vi.mocked(getDossier).mockResolvedValue(sparse());
    vi.mocked(setDossierOverride).mockResolvedValue(
      dossier({
        hostname: {
          value: 'ws-lab-3',
          source: 'operator',
          confidence: 1,
          reason: null,
          overridden: true,
          operator_actor: 'root',
          operator_set_at: '2026-08-07T10:00:00Z',
        },
      }),
    );
    mount();
    const unknowns = await screen.findByTestId('host-unknowns');
    fireEvent.click(within(unknowns).getByText(/unknown/i));
    const nameEntry = within(unknowns).getByTestId('field-hostname');
    fireEvent.click(within(nameEntry).getByRole('button', { name: /declare a value/i }));
    fireEvent.change(within(nameEntry).getByLabelText(/value/i), {
      target: { value: ' ws-lab-3 ' },
    });
    fireEvent.click(within(nameEntry).getByRole('button', { name: /^save$/i }));
    await waitFor(() =>
      expect(setDossierOverride).toHaveBeenCalledWith(IP, { field: 'hostname', value: 'ws-lab-3' }),
    );
    // The response is the new page: hostname now leads the hero.
    expect((await screen.findByTestId('hero-name')).textContent).toBe('ws-lab-3');
  });

  it('offers the role vocabulary instead of a free-text trap', async () => {
    vi.mocked(getDossier).mockResolvedValue(dossier());
    mount();
    const unknowns = await screen.findByTestId('host-unknowns');
    fireEvent.click(within(unknowns).getByText(/unknown/i));
    const roleEntry = within(unknowns).getByTestId('field-role');
    fireEvent.click(within(roleEntry).getByRole('button', { name: /declare a value/i }));
    const input = within(roleEntry).getByLabelText(/value/i);
    // A datalist: the canonical vocabulary offered, free text still possible.
    const listId = input.getAttribute('list');
    expect(listId).toBeTruthy();
    const options = Array.from(
      roleEntry.querySelectorAll(`datalist#${listId} option`),
    ).map((o) => o.getAttribute('value'));
    expect(options).toContain('hypervisor');
    expect(options).toContain('workstation');
    expect(options).toContain('domain_controller');
  });

  it('refuses a blank declaration client-side, the way the server does', async () => {
    vi.mocked(getDossier).mockResolvedValue(sparse());
    mount();
    const unknowns = await screen.findByTestId('host-unknowns');
    fireEvent.click(within(unknowns).getByText(/unknown/i));
    const entry = within(unknowns).getByTestId('field-hostname');
    fireEvent.click(within(entry).getByRole('button', { name: /declare a value/i }));
    fireEvent.change(within(entry).getByLabelText(/value/i), { target: { value: '   ' } });
    fireEvent.click(within(entry).getByRole('button', { name: /^save$/i }));
    expect(await within(entry).findByText(/needs a value/i)).toBeTruthy();
    expect(setDossierOverride).not.toHaveBeenCalled();
  });

  it('refuses malformed JSON on a structured field before it reaches the API', async () => {
    vi.mocked(getDossier).mockResolvedValue(sparse());
    mount();
    const unknowns = await screen.findByTestId('host-unknowns');
    fireEvent.click(within(unknowns).getByText(/unknown/i));
    const entry = within(unknowns).getByTestId('field-services_offered');
    fireEvent.click(within(entry).getByRole('button', { name: /declare a value/i }));
    fireEvent.change(within(entry).getByLabelText(/value/i), { target: { value: '{not json' } });
    fireEvent.click(within(entry).getByRole('button', { name: /^save$/i }));
    expect(await within(entry).findByText(/not valid JSON/i)).toBeTruthy();
    expect(setDossierOverride).not.toHaveBeenCalled();
  });

  it('round-trips a structured edit through the JSON editor', async () => {
    vi.mocked(getDossier).mockResolvedValue(rich());
    vi.mocked(setDossierOverride).mockResolvedValue(
      dossier({
        services_offered: {
          value: null,
          value_json: [{ port: 443, proto: 'tcp', count: 0, service: 'https' }],
          source: 'operator',
          confidence: 1,
          reason: null,
          overridden: true,
          operator_actor: 'root',
          operator_set_at: '2026-08-07T10:00:00Z',
        },
      }),
    );
    mount();
    const services = await row('services_offered');
    fireEvent.click(within(services).getByRole('button', { name: /edit/i }));
    const editor = within(services).getByLabelText(/value/i);
    // Prefilled with what stands today, so an edit is an edit, not a retype.
    expect((editor as HTMLTextAreaElement).value).toContain('8006');
    fireEvent.change(editor, {
      target: { value: '[{"port": 443, "proto": "tcp", "count": 0, "service": "https"}]' },
    });
    fireEvent.click(within(services).getByRole('button', { name: /^save$/i }));
    await waitFor(() =>
      expect(setDossierOverride).toHaveBeenCalledWith(IP, {
        field: 'services_offered',
        value_json: [{ port: 443, proto: 'tcp', count: 0, service: 'https' }],
      }),
    );
  });

  it('asks how you know, not why the machinery is wrong', async () => {
    // "Why the builder is wrong here" assumed every declaration is a dispute.
    vi.mocked(getDossier).mockResolvedValue(sparse());
    mount();
    const unknowns = await screen.findByTestId('host-unknowns');
    fireEvent.click(within(unknowns).getByText(/unknown/i));
    const entry = within(unknowns).getByTestId('field-hostname');
    fireEvent.click(within(entry).getByRole('button', { name: /declare a value/i }));
    const note = within(entry).getByLabelText(/note/i);
    expect(note.getAttribute('placeholder')).toMatch(/how you know/i);
    expect(note.getAttribute('placeholder')).not.toMatch(/wrong/i);
  });

  it('hides the declare controls from a non-admin', async () => {
    vi.mocked(getMe).mockResolvedValue({ username: 'ana', role: 'analyst', status: '' });
    vi.mocked(getDossier).mockResolvedValue(sparse());
    mount();
    await screen.findByText(/read-only/i);
    const unknowns = screen.getByTestId('host-unknowns');
    fireEvent.click(within(unknowns).getByText(/unknown/i));
    expect(within(unknowns).queryByRole('button', { name: /declare a value/i })).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Disagreements: both claims, both buttons, one place
// ---------------------------------------------------------------------------

describe('HostDetail — an open disagreement leads the page', () => {
  const conflicted = () =>
    dossier({
      role: {
        value: 'hypervisor',
        source: 'operator',
        confidence: 1,
        strength: 'strong',
        reason: null,
        overridden: true,
        conflict_kind: 'mismatch',
        operator_actor: 'ops-lead',
        operator_set_at: '2026-08-01T10:00:00Z',
        inferred_value: 'server',
        inferred_confidence: 0.8,
        inferred_source: 'behaviour',
        evidence: {
          behaviour: {
            strings: ['sustained responder on tcp/8096 (jellyfin) over 14d'],
            value: 'server',
            strength: 'strong',
            confidence: 0.8,
            last_seen: '2026-08-07T09:00:00Z',
          },
        },
        conflict: {
          kind: 'mismatch',
          first_seen_at: '2026-08-02T06:00:00Z',
          observations: 5,
          last_prompted_at: '2026-08-05T06:00:00Z',
          prompt_count: 1,
          snoozed_until: null,
        },
      },
    });

  it('shows both claims and the sweep`s evidence at the decision point', async () => {
    vi.mocked(getDossier).mockResolvedValue(conflicted());
    mount();
    const card = await screen.findByTestId('conflict-role');
    // The whole argument in one place: yours, the sweep's, and why it thinks so.
    expect(card.textContent).toContain('hypervisor');
    expect(card.textContent).toContain('server');
    expect(card.textContent).toMatch(/seen 5 times/i);
    expect(card.textContent).toContain('sustained responder on tcp/8096 (jellyfin) over 14d');
    // Inside the why-care strip, before the tiles.
    const briefing = screen.getByTestId('host-briefing');
    expect(within(briefing).getByTestId('conflict-role')).toBeTruthy();
  });

  it('names the value each button will leave standing', async () => {
    vi.mocked(getDossier).mockResolvedValue(conflicted());
    mount();
    const card = await screen.findByTestId('conflict-role');
    // "Accept inference" never said what would be accepted.
    const accept = within(card).getByRole('button', { name: /use the sweep's answer/i });
    expect(accept.textContent).toContain('server');
    expect(within(card).getByRole('button', { name: /keep mine/i })).toBeTruthy();
  });

  it('replacing your declaration confirms first, then clears and re-renders', async () => {
    vi.mocked(getDossier).mockResolvedValue(conflicted());
    vi.mocked(clearDossierOverride).mockResolvedValue(
      dossier({
        role: {
          value: 'server',
          source: 'behaviour',
          confidence: 0.8,
          strength: 'strong',
          reason: null,
          inferred_value: 'server',
          inferred_confidence: 0.8,
          inferred_source: 'behaviour',
        },
      }),
    );
    mount();
    const card = await screen.findByTestId('conflict-role');
    fireEvent.click(within(card).getByRole('button', { name: /use the sweep's answer/i }));
    expect(clearDossierOverride).not.toHaveBeenCalled();
    fireEvent.click(within(card).getByRole('button', { name: /replace my declaration/i }));
    await waitFor(() => expect(clearDossierOverride).toHaveBeenCalledWith(IP, 'role'));
    // The conflict is gone from the strip and the sentence now says server.
    await waitFor(() => expect(screen.queryByTestId('conflict-role')).toBeNull());
    expect((await screen.findByTestId('host-sentence')).textContent).toContain('server');
  });

  it('keeping mine snoozes the conflict and shows the new deadline', async () => {
    vi.mocked(getDossier).mockResolvedValue(conflicted());
    const snoozed = conflicted();
    const roleField = snoozed.fields.find((f) => f.field === 'role')!;
    roleField.conflict = {
      ...roleField.conflict!,
      snoozed_until: '2026-10-01T06:00:00Z',
      prompt_count: 2,
    };
    vi.mocked(snoozeDossierConflict).mockResolvedValue(snoozed);
    mount();
    const card = await screen.findByTestId('conflict-role');
    fireEvent.click(within(card).getByRole('button', { name: /keep mine/i }));
    await waitFor(() => expect(snoozeDossierConflict).toHaveBeenCalledWith(IP, 'role'));
    const line = await screen.findByText(/asking again/i);
    expect(line.textContent).toContain(absTime('2026-10-01T06:00:00Z'));
  });

  it('surfaces the 409 reason instead of failing silently', async () => {
    vi.mocked(getDossier).mockResolvedValue(conflicted());
    vi.mocked(snoozeDossierConflict).mockRejectedValue(
      new Error("nothing currently disagrees with the 'role' override"),
    );
    mount();
    const card = await screen.findByTestId('conflict-role');
    fireEvent.click(within(card).getByRole('button', { name: /keep mine/i }));
    expect(await screen.findByText(/nothing currently disagrees/i)).toBeTruthy();
  });

  it('states the conflict once — no chorus of chips and banners', async () => {
    // Six statements of one disagreement was F6. The strip's card is the one
    // surface; nothing else on the page repeats the word.
    vi.mocked(getDossier).mockResolvedValue(conflicted());
    mount();
    await screen.findByTestId('conflict-role');
    const matches = visibleText(document.body).match(/disagree/gi) ?? [];
    expect(matches.length).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Build failures: visible, explained, actionable
// ---------------------------------------------------------------------------

describe('HostDetail — a failed build is a red banner, not an invisible shrug', () => {
  const broken = () =>
    dossier(
      {},
      {
        build_error: 'elasticsearch: ConnectionTimeout after 30s querying logs-* (window 14d)',
        last_built_at: null,
        event_count: 433,
      },
    );

  it('shows the stored error where the analyst will read it first', async () => {
    vi.mocked(getDossier).mockResolvedValue(broken());
    mount();
    const banners = await screen.findAllByRole('alert');
    const banner = banners.find((b) => /ConnectionTimeout/.test(b.textContent ?? ''));
    expect(banner).toBeTruthy();
    expect(banner!.textContent).toMatch(/last sweep failed/i);
  });

  it('offers an admin the retry on the spot', async () => {
    vi.mocked(getDossier).mockResolvedValue(broken());
    vi.mocked(startDossierRefresh).mockResolvedValue({
      running: true,
      last_run: null,
      last_summary: null,
      note: 'started',
    });
    mount();
    const banners = await screen.findAllByRole('alert');
    const banner = banners.find((b) => /ConnectionTimeout/.test(b.textContent ?? ''))!;
    fireEvent.click(within(banner).getByRole('button', { name: /sweep again/i }));
    await waitFor(() => expect(startDossierRefresh).toHaveBeenCalled());
    expect(await screen.findByText(/sweeping in the background/i)).toBeTruthy();
  });

  it('does not claim a build it never completed', async () => {
    // "built from 433 events" beside "last built —" was the F3 contradiction.
    vi.mocked(getDossier).mockResolvedValue(broken());
    mount();
    const facts = await screen.findByTestId('hero-facts');
    expect(facts.textContent).toMatch(/never successfully swept/i);
    expect(facts.textContent).not.toMatch(/built from/i);
  });
});

// ---------------------------------------------------------------------------
// Deep links from the conflicts queue and notifications
// ---------------------------------------------------------------------------

describe('HostDetail — deep link', () => {
  it('highlights the fact row named by ?field=', async () => {
    vi.mocked(getDossier).mockResolvedValue(sparse());
    mount(`/hosts/${IP}?field=role`);
    const target = await row('role');
    await waitFor(() => expect(target.getAttribute('data-highlight')).toBe('true'));
  });

  it('opens the unknown line when the linked field is unknown', async () => {
    vi.mocked(getDossier).mockResolvedValue(sparse());
    mount(`/hosts/${IP}?field=criticality`);
    const unknowns = await screen.findByTestId('host-unknowns');
    await waitFor(() =>
      expect(unknowns.querySelector('details')?.hasAttribute('open')).toBe(true),
    );
    expect(
      within(unknowns).getByTestId('field-criticality').getAttribute('data-highlight'),
    ).toBe('true');
  });
});

// ---------------------------------------------------------------------------
// A refresh that failed under a page that already has content
// ---------------------------------------------------------------------------

describe('HostDetail — a failed foreground refresh is marked, not swallowed', () => {
  const REFRESH_FAILED = /Refresh failed — still showing data from/i;

  /** The page's own Refresh, which re-reads THIS host. Driving the marker from
   *  a same-host refresh is deliberate: an earlier version of these tests
   *  reached it by navigating to a DIFFERENT host without a remount, which
   *  quietly pinned "one host's dossier rendered under another host's URL" as
   *  acceptable output. It is not — it only looked safe because AppShell keys
   *  its boundary on the pathname and so remounts on that route change. What
   *  the analyst actually does is press Refresh on the host they are reading. */
  const clickRefresh = () =>
    fireEvent.click(screen.getByRole('button', { name: /refresh host/i }));

  it('keeps the page and says the refresh failed', async () => {
    vi.mocked(getDossier).mockResolvedValueOnce(rich());
    mount();
    await screen.findByTestId('host-hero');
    expect(screen.queryByText(REFRESH_FAILED)).toBeNull();

    vi.mocked(getDossier).mockRejectedValueOnce(new Error('boom'));
    clickRefresh();

    // Still a page — not the alarm card, not a blank screen — and it now
    // carries the one thing it was missing: that it is not current.
    expect(await screen.findByText(REFRESH_FAILED)).toBeTruthy();
    expect(screen.getByTestId('host-hero')).toBeTruthy();
    expect(screen.queryByText(/Couldn't load/i)).toBeNull();
    // Still the host whose URL this is: what went stale is the reading, not
    // which machine is being read.
    expect(within(screen.getByTestId('host-hero')).getAllByText(/blue/i).length).toBeGreaterThan(0);
    // Nothing is polling this page, so nothing is coming on its own — and the
    // strip does not pretend otherwise.
    expect(screen.queryByText(/retrying/i)).toBeNull();
  });

  it('clears the marker when a refresh finally lands', async () => {
    vi.mocked(getDossier).mockResolvedValueOnce(rich());
    mount();
    await screen.findByTestId('host-hero');

    vi.mocked(getDossier).mockRejectedValueOnce(new Error('boom'));
    clickRefresh();
    await screen.findByText(REFRESH_FAILED);

    vi.mocked(getDossier).mockResolvedValueOnce(rich());
    fireEvent.click(screen.getByRole('button', { name: /^refresh$/i }));
    await waitFor(() => expect(screen.queryByText(REFRESH_FAILED)).toBeNull());
    expect(screen.getByTestId('host-hero')).toBeTruthy();
  });

  it('re-reads the host itself, not only its activity', async () => {
    // The page says "give it a minute, then reload this page" after a sweep,
    // and the only thing on it called Refresh used to re-read the activity
    // charts alone — so the identity half, which is what the sweep changes,
    // stayed exactly as stale as before the click.
    vi.mocked(getDossier).mockResolvedValue(rich());
    mount();
    await screen.findByTestId('host-hero');
    const dossierCalls = vi.mocked(getDossier).mock.calls.length;
    const activityCalls = vi.mocked(getHostActivity).mock.calls.length;

    clickRefresh();
    await waitFor(() => expect(vi.mocked(getDossier).mock.calls.length).toBe(dossierCalls + 1));
    expect(vi.mocked(getHostActivity).mock.calls.length).toBe(activityCalls + 1);
  });

  it('leaves the first-load 404 as the calm not-found state', async () => {
    // Nothing on screen to preserve, so the marker has no business appearing.
    vi.mocked(getDossier).mockRejectedValue(new ApiError('404 Not Found', 404));
    mount();
    expect(await screen.findByText(/No such host/i)).toBeTruthy();
    expect(screen.queryByText(REFRESH_FAILED)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The KPI strip (unchanged component, re-pinned against the new page)
// ---------------------------------------------------------------------------

describe('HostDetail — the KPI strip', () => {
  const busy = () =>
    activity({
      users: [
        { name: 'svc-backup', events: 12, last_seen: '2026-08-07T09:12:00Z' },
        { name: 'root', events: 3, last_seen: '2026-08-07T08:40:00Z' },
      ],
      volume: [
        { ts: '2026-08-07T08:00:00Z', events: 900 },
        { ts: '2026-08-07T09:00:00Z', events: 304 },
      ],
      alerts_7d: 3,
    });

  it('takes services from the sweep and users, events and alerts from the live grid', async () => {
    vi.mocked(getDossier).mockResolvedValue(rich());
    vi.mocked(getHostActivity).mockResolvedValue(busy());
    mount();
    expect(within(await screen.findByTestId('kpi-services')).getByText('2')).toBeTruthy();
    expect(within(await screen.findByTestId('kpi-users')).getByText('2')).toBeTruthy();
    expect(
      within(await screen.findByTestId('kpi-events')).getByText((1204).toLocaleString()),
    ).toBeTruthy();
    expect(within(await screen.findByTestId('kpi-alerts')).getByText('3')).toBeTruthy();
  });

  it('shows a dash, never a zero, for the numbers the grid could not answer', async () => {
    vi.mocked(getDossier).mockResolvedValue(rich());
    vi.mocked(getHostActivity).mockRejectedValue(
      new Error('The Security Onion grid (Elasticsearch) is slow or unreachable — retry shortly.'),
    );
    mount();
    expect(within(await screen.findByTestId('kpi-services')).getByText('2')).toBeTruthy();
    for (const kpi of ['kpi-users', 'kpi-events', 'kpi-alerts']) {
      expect(within(await screen.findByTestId(kpi)).getByText('—')).toBeTruthy();
    }
  });

  it('names the ports behind the service count', async () => {
    vi.mocked(getDossier).mockResolvedValue(rich());
    vi.mocked(getHostActivity).mockResolvedValue(busy());
    mount();
    const kpi = await screen.findByTestId('kpi-services');
    expect(kpi.textContent).toContain('tcp/8006');
    expect(kpi.textContent).toContain('tcp/22');
  });

  it('links the alert count to the alerts view, narrowed to this host', async () => {
    vi.mocked(getDossier).mockResolvedValue(rich());
    vi.mocked(getHostActivity).mockResolvedValue(busy());
    mount();
    const kpi = await screen.findByTestId('kpi-alerts');
    const link = within(kpi).getByRole('link');
    const href = alertsHref(IP);
    expect(link).toHaveAttribute('href', href);
    const params = new URLSearchParams(href.split('?')[1]);
    // The window and the ack scope match the count's definition: alerts_7d is
    // a fixed 7-day raw grid count with no ack join, against a screen that
    // defaults to 24h with acked groups hidden.
    expect(params.get('range')).toBe('7d');
    expect(params.get('hide_acked')).toBe('false');
    // The host scope rides ?q= as the product's own OQL OR-grouping — the
    // clause the Alerts screen validates server-side and shows as a chip.
    expect(params.get('q')).toBe(`(source.ip:${IP} OR destination.ip:${IP})`);
    expect(link.textContent).toMatch(/alerts for this host/i);
  });

  it('will not count services it has no answer for', async () => {
    vi.mocked(getDossier).mockResolvedValue(dossier());
    vi.mocked(getHostActivity).mockResolvedValue(busy());
    mount();
    expect(within(await screen.findByTestId('kpi-services')).getByText('—')).toBeTruthy();
  });

  it('draws the volume sparkline inside the Events card, dated to its window', async () => {
    vi.mocked(getDossier).mockResolvedValue(rich());
    vi.mocked(getHostActivity).mockResolvedValue(busy());
    mount();
    const events = await screen.findByTestId('kpi-events');
    const chart = events.querySelector('[data-testid="kpi-events-spark"]') as HTMLElement;
    expect(chart).toBeTruthy();
    expect(chart.querySelector('svg polyline')).toBeTruthy();
    // No axes — this is a shape, not a chart with a scale to misread…
    expect(chart.querySelectorAll('svg text').length).toBe(0);
    // …so the tooltip says which window (and whose peak) the shape describes.
    expect(chart.getAttribute('title')).toMatch(/24h/);
    expect(chart.getAttribute('title')).toMatch(/900/);
  });

  it('draws no sparkline over a dash or a silent host', async () => {
    // A line under '—' would claim a reading the grid never answered, and a
    // flat line over zero buckets would claim a quiet day was measured.
    vi.mocked(getDossier).mockResolvedValue(rich());
    vi.mocked(getHostActivity).mockRejectedValue(new Error('grid down'));
    mount();
    const events = await screen.findByTestId('kpi-events');
    expect(within(events).getByText('—')).toBeTruthy();
    expect(events.querySelector('[data-testid="kpi-events-spark"]')).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The activity row (unchanged component, re-pinned against the new page)
// ---------------------------------------------------------------------------

describe('HostDetail — the activity row', () => {
  const seeded = () =>
    activity({
      peers: [
        { ip: '192.168.10.1', hostname: 'gw', direction: 'both', ports: [53, 443], events: 1200, alerted: false },
        { ip: '198.51.100.7', hostname: null, direction: 'out', ports: [443], events: 4, alerted: true },
      ],
      volume: [
        { ts: '2026-08-07T08:00:00Z', events: 900 },
        { ts: '2026-08-07T09:00:00Z', events: 304 },
      ],
      users: [{ name: 'svc-backup', events: 12, last_seen: '2026-08-07T09:12:00Z' }],
      alerts_7d: 1,
    });

  it('draws the peers, named where the network knows a name', async () => {
    vi.mocked(getDossier).mockResolvedValue(dossier());
    vi.mocked(getHostActivity).mockResolvedValue(seeded());
    mount();
    const graph = await screen.findByTestId('host-peer-graph');
    expect(within(graph).getByText('gw')).toBeTruthy();
    expect(within(graph).getByText('198.51.100.7')).toBeTruthy();
  });

  it('draws an alerted peer differently from a quiet one', async () => {
    vi.mocked(getDossier).mockResolvedValue(dossier());
    vi.mocked(getHostActivity).mockResolvedValue(seeded());
    mount();
    const graph = await screen.findByTestId('host-peer-graph');
    const strokes = new Set(
      Array.from(graph.querySelectorAll('line')).map((l) => l.getAttribute('stroke')),
    );
    expect(strokes.size).toBe(2);
    const alerted = peerGraph(IP, seeded().peers).edges.filter((e) => e.kind === 'lateral');
    expect(alerted.length).toBe(1);
    expect(alerted[0].to).toBe('198.51.100.7');
  });

  it('labels a two-way alerted peer once, not twice on the same baseline', async () => {
    vi.mocked(getDossier).mockResolvedValue(dossier());
    vi.mocked(getHostActivity).mockResolvedValue(
      activity({
        peers: [
          { ip: '198.51.100.7', hostname: null, direction: 'both', ports: [443], events: 4, alerted: true },
        ],
      }),
    );
    mount();
    const graph = await screen.findByTestId('host-peer-graph');
    const labels = Array.from(graph.querySelectorAll('text')).filter(
      (t) => t.textContent === 'alerted',
    );
    expect(labels.length).toBe(1);
    expect(graph.querySelectorAll('line').length).toBe(2);
  });

  it('will not turn "no host logs in this window" into "nobody logged in"', async () => {
    vi.mocked(getDossier).mockResolvedValue(dossier());
    vi.mocked(getHostActivity).mockResolvedValue(activity({ users: null }));
    mount();
    const users = await screen.findByTestId('host-users');
    expect(within(users).getByText(/no host-log users in this window/i)).toBeTruthy();
    expect(within(users).getByText(/cannot tell the two apart/i)).toBeTruthy();
  });

  it('degrades only the live half when the grid is unreachable', async () => {
    vi.mocked(getDossier).mockResolvedValue(sparse());
    vi.mocked(getHostActivity).mockRejectedValue(
      new Error('The Security Onion grid (Elasticsearch) is slow or unreachable — retry shortly.'),
    );
    mount();
    const degraded = await screen.findByTestId('activity-degraded');
    expect(degraded).toHaveTextContent(/slow or unreachable/i);
    // The best copy on the page, said ONCE.
    const everything = document.body.textContent?.match(/comes from the network sweep/gi) ?? [];
    expect(everything.length).toBe(1);
    // The dossier half is still the point of the page.
    expect(screen.queryByText(/Couldn't load this host/i)).toBeNull();
    expect(await row('role')).toBeTruthy();
    expect(screen.queryByTestId('host-peer-graph')).toBeNull();
  });

  it('keeps the last good read when a refresh fails, and says it is old', async () => {
    vi.mocked(getDossier).mockResolvedValue(dossier());
    vi.mocked(getHostActivity).mockResolvedValueOnce(seeded());
    mount();
    expect(within(await screen.findByTestId('host-peer-graph')).getByText('gw')).toBeTruthy();

    vi.mocked(getHostActivity).mockRejectedValue(new Error('grid down'));
    fireEvent.click(screen.getByRole('button', { name: /refresh host/i }));

    const stale = await screen.findByTestId('activity-stale');
    expect(stale).toHaveTextContent(/grid down/i);
    expect(within(screen.getByTestId('host-peer-graph')).getByText('gw')).toBeTruthy();
    expect(within(screen.getByTestId('kpi-alerts')).getByText('1')).toBeTruthy();
    expect(screen.queryByTestId('activity-degraded')).toBeNull();
  });

  it('links the latest investigation and shows the verdict it reached', async () => {
    vi.mocked(getDossier).mockResolvedValue(dossier());
    vi.mocked(getHostActivity).mockResolvedValue(
      activity({
        peers: [
          { ip: '192.168.10.1', hostname: 'gw', direction: 'out', ports: [53], events: 90, alerted: false },
        ],
        latest_investigation: { id: 'inv-1', verdict: 'true_positive', ts: '2026-08-06T22:00:00Z' },
      }),
    );
    mount();
    const link = await screen.findByRole('link', { name: /latest/i });
    expect(link).toHaveAttribute('href', '/investigation/inv-1');
    expect(link).toHaveTextContent(/true positive/i);
  });

  it('says when the peer list it drew is a busiest-N, from the wire flag alone', async () => {
    // The backend states the cut (`peers_truncated`, decided from the pre-cut
    // length). The page must not re-infer it from list lengths against a
    // copied cap constant — which read exactly-cap lists as cut ones and went
    // quietly false whenever the cap moved.
    const twelve = Array.from({ length: 12 }, (_, i) => ({
      ip: `192.168.10.${i + 20}`,
      hostname: null,
      direction: 'out' as const,
      ports: [443],
      events: 100 - i,
      alerted: false,
    }));
    vi.mocked(getDossier).mockResolvedValue(dossier());
    vi.mocked(getHostActivity).mockResolvedValue(
      activity({ peers: twelve, peers_truncated: true }),
    );
    mount();
    const graph = await screen.findByTestId('host-peer-graph');
    expect(within(graph).getByText(/12 busiest peers/i)).toBeTruthy();
    // And the Events card's peer count reads as a floor for the same reason.
    expect((await screen.findByTestId('kpi-events')).textContent).toContain('12+ peers');
  });

  it('does not call a full-but-uncut peer list a busiest-N', async () => {
    const twelve = Array.from({ length: 12 }, (_, i) => ({
      ip: `192.168.10.${i + 20}`,
      hostname: null,
      direction: 'out' as const,
      ports: [443],
      events: 100 - i,
      alerted: false,
    }));
    vi.mocked(getDossier).mockResolvedValue(dossier());
    vi.mocked(getHostActivity).mockResolvedValue(
      activity({ peers: twelve, peers_truncated: false }),
    );
    mount();
    const graph = await screen.findByTestId('host-peer-graph');
    expect(within(graph).queryByText(/busiest peers/i)).toBeNull();
    expect((await screen.findByTestId('kpi-events')).textContent).toContain('12 peers');
  });

  it('marks a cut account list from the wire flag, not the length', async () => {
    vi.mocked(getDossier).mockResolvedValue(dossier());
    vi.mocked(getHostActivity).mockResolvedValue(
      activity({
        users: Array.from({ length: 10 }, (_, i) => ({
          name: `user-${i}`,
          events: 50 - i,
          last_seen: '2026-08-07T09:00:00Z',
        })),
        users_truncated: true,
      }),
    );
    mount();
    const users = await screen.findByTestId('host-users');
    expect(within(users).getByText(/10 busiest accounts/i)).toBeTruthy();
  });
});

describe('HostDetail — the activity window', () => {
  it('re-reads the grid for the window the analyst picked', async () => {
    vi.mocked(getDossier).mockResolvedValue(dossier());
    vi.mocked(getHostActivity).mockResolvedValue(activity());
    mount();
    await waitFor(() => expect(getHostActivity).toHaveBeenCalledWith(IP, '24h'));

    fireEvent.click(screen.getByRole('button', { name: '7d' }));
    await waitFor(() => expect(getHostActivity).toHaveBeenCalledWith(IP, '7d'));
    expect(await within(await screen.findByTestId('kpi-events')).findByText(/7d/i)).toBeTruthy();
  });

  it('keeps showing the old window until the new one has actually landed', async () => {
    vi.mocked(getDossier).mockResolvedValue(dossier());
    vi.mocked(getHostActivity).mockResolvedValueOnce(
      activity({ volume: [{ ts: '2026-08-07T09:00:00Z', events: 42 }] }),
    );
    mount();
    const events = await screen.findByTestId('kpi-events');
    expect(within(events).getByText('42')).toBeTruthy();
    expect(events.textContent).toContain('24h');

    vi.mocked(getHostActivity).mockReturnValue(new Promise<never>(() => {}));
    fireEvent.click(screen.getByRole('button', { name: '7d' }));
    await waitFor(() => expect(getHostActivity).toHaveBeenCalledWith(IP, '7d'));

    expect(within(events).getByText('42')).toBeTruthy();
    expect(events.textContent).toContain('24h');
    expect(events.textContent).not.toContain('7d');
    expect(screen.getByRole('button', { name: '7d' }).getAttribute('aria-pressed')).toBe('true');
  });

  it('hides the window controls on a page that has no activity to window', async () => {
    vi.mocked(getDossier).mockRejectedValue(new Error('boom'));
    mount();
    await screen.findByText(/Couldn't load this host/i);
    expect(screen.queryByRole('button', { name: /refresh host/i })).toBeNull();
  });
});
