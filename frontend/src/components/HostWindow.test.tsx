// The host page and its time filter (2026-10-14). The owner rule: a page
// filters everything by its time filter, unless the screen labels it
// otherwise in visible words. A hover title is not a label. The host page has
// a 24h and a 7d button. The sweep counts on it cover the dossier window, 14
// days by default, and the hero lines cover all open leads and the verdicts
// of the last 7 days. Each of them now says so on screen.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getDossier: vi.fn(),
}));

import type { EntityObservation, Lead } from '../lib/api';
import { sweepWindowWords } from '../lib/hostDossier';
import { leadLines, verdictLines } from '../lib/hostSituation';
import type { Dossier, DossierField, DossierFieldName, MachineDetail } from '../lib/types';
import { HostAddresses } from './HostAddresses';
import { FactRow } from './HostFacts';
import { HostHero } from './HostHero';

const IP = '192.0.2.10';
const DAY = 86_400_000;
const ago = (ms: number) => new Date(Date.now() - ms).toISOString();

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

const dossier = (over: Partial<Dossier> = {}): Dossier => ({
  ip: IP,
  found: true,
  fields: [field('hostname'), field('role')],
  first_seen: ago(30 * DAY),
  last_seen: ago(DAY),
  last_built_at: ago(DAY),
  last_observed_at: null,
  event_count: 3662,
  identity_rebound_at: null,
  build_error: null,
  override_count: 0,
  conflict_count: 0,
  reporting: false,
  ...over,
});

const machine = (over: Partial<MachineDetail> = {}): MachineDetail => ({
  key: 'agent:ea2d',
  href: '/hosts/agent%3Aea2d',
  name: 'files01',
  name_source: 'agent',
  names: [{ value: 'files01', source: 'agent' }],
  primary_ip: IP,
  address_count: 1,
  addresses: [{ ip: IP, kind: 'agent', primary: true, first_seen: ago(30 * DAY), last_seen: ago(DAY), events: 3662 }],
  container_count: 1,
  containers: [{ ip: '172.17.0.2', first_seen: ago(9 * DAY), last_seen: ago(DAY), events: 12 }],
  agent: null,
  role: { value: null, label: null, confidence: null, state: 'unknown', guess: null, stale_hours: null },
  events: 3662,
  first_seen: ago(30 * DAY),
  last_seen: ago(DAY),
  flags: { declared: false, conflict: false, broken: false, new: false, rebound: false },
  macs: [],
  merged_from: [],
  dossier: dossier(),
  ...over,
});

const lead = (id: number, over: Partial<Lead> = {}): Lead => ({
  id,
  status: 'open',
  formed_at: ago(DAY),
  updated_at: ago(DAY),
  entities: [['host', IP]],
  kinds: ['alert'],
  weight_at_formation: 1,
  scope_count: 1,
  hunt_id: null,
  shadow: false,
  single_signal: false,
  observations: [],
  ...over,
});

const verdict = (id: number, value: string, bornMsAgo: number): EntityObservation =>
  ({
    id,
    kind: 'alert',
    spec_id: 'alert',
    source: 'alert',
    shadow: false,
    summary: `Rule ${id}`,
    weight_now: 0.5,
    lead_id: null,
    born_at: ago(bornMsAgo),
    occurrences: 1,
    read: true,
    verdict: value,
  }) as EntityObservation;

describe('the hero event count states the sweep window', () => {
  it('reads the window from the dossier on the address hero', () => {
    render(<HostHero dossier={dossier({ lookback_days: 30 })} adminBlocked={false} />);
    expect(within(screen.getByTestId('hero-facts')).getByTestId('hero-events').textContent).toBe(
      '3,662 events in the last 30 days',
    );
  });

  it('reads the window from the dossier on the machine hero', () => {
    render(
      <MemoryRouter>
        <HostHero dossier={dossier({ lookback_days: 14 })} machine={machine()} adminBlocked={false} />
      </MemoryRouter>,
    );
    expect(screen.getByTestId('hero-events').textContent).toBe('3,662 events in the last 14 days');
  });

  it('names the sweep window when an older server sends no number', () => {
    render(<HostHero dossier={dossier()} adminBlocked={false} />);
    expect(screen.getByTestId('hero-events').textContent).toBe('3,662 events in the sweep window');
  });
});

describe('the address table states the sweep window', () => {
  it('heads the Events columns with the window', () => {
    render(
      <MemoryRouter>
        <HostAddresses machine={machine()} focusAddress={null} focusField={null} windowDays={14} />
      </MemoryRouter>,
    );
    const table = screen.getByTestId('host-addresses');
    expect(within(table).getAllByRole('columnheader', { name: 'Events, last 14 days' })).toHaveLength(2);
  });
});

describe('the port counts in the Why drawer state the sweep window', () => {
  const ports = field('services_offered', {
    value_json: [{ port: 389, proto: 'tcp', count: 1200, service: 'ldap' }],
    source: 'behaviour',
    confidence: 0.9,
    strength: 'strong',
    reason: null,
    evidence: { behaviour: { strings: ['answers 1 port'] } },
  });

  it('says which days the connection counts cover', () => {
    render(<FactRow ip={IP} f={ports} canDeclare={false} highlight={false} onApplied={vi.fn()} windowDays={14} />);
    const payload = screen.getByTestId('why-payload');
    expect(within(payload).getByTestId('why-payload-window').textContent).toBe(
      'The connection counts cover the last 14 days.',
    );
    expect(within(payload).getByText('· tcp/389 · ldap · 1,200 connections')).toBeTruthy();
  });

  it('adds no window line to a payload with no count', () => {
    // Negative control: a port list with no count states no window.
    const bare = field('services_offered', { ...ports, value_json: [{ port: 389, proto: 'tcp' }] });
    render(<FactRow ip={IP} f={bare} canDeclare={false} highlight={false} onApplied={vi.fn()} windowDays={14} />);
    expect(screen.queryByTestId('why-payload-window')).toBeNull();
  });
});

describe('the hero lines state their scope', () => {
  it('labels the lead lines all open leads and counts past the rows', () => {
    const lines = leadLines([lead(11), lead(12)], 6);
    expect(lines.map((l) => [l.text, l.scope])).toEqual([
      ['Lead 12 is new. It waits on a hunt or a decision.', 'all open leads'],
      ['5 more open leads name this host.', 'all open leads'],
    ]);
  });

  it('counts the rows when the server sends no total', () => {
    expect(leadLines([lead(11), lead(12)]).map((l) => l.text)).toEqual([
      'Lead 12 is new. It waits on a hunt or a decision.',
      '1 more open lead names this host.',
    ]);
  });

  it('labels the verdict lines with the last 7 days', () => {
    const lines = verdictLines([verdict(1, 'true_positive', 2 * DAY), verdict(2, 'needs_more_info', DAY)]);
    expect(lines.map((l) => l.scope)).toEqual(['last 7 days', 'last 7 days']);
  });

  it('renders the scope as visible text beside each line', () => {
    render(
      <HostHero
        dossier={dossier()}
        adminBlocked={false}
        situation={[
          { text: 'Lead 11 waits on a decision.', tone: 'info', scope: 'all open leads' },
          { text: '2 true-positive alerts, today.', tone: 'alarm', scope: 'last 7 days' },
        ]}
      />,
      { wrapper: MemoryRouter },
    );
    const scopes = within(screen.getByTestId('host-situation')).getAllByTestId('situation-scope');
    expect(scopes.map((s) => s.textContent)).toEqual(['all open leads', 'last 7 days']);
  });
});

// Dogfood 2026-10-19, R4-D10: "events in the last 14 days" labelled a count
// from a sweep 17 days old. An old sweep names its age.
describe('an old sweep names its age', () => {
  const builtAt = new Date(Date.now() - 17 * DAY).toISOString();

  it('labels the hero count by the sweep age', () => {
    render(<HostHero dossier={dossier({ lookback_days: 14, last_built_at: builtAt })} adminBlocked={false} />);
    expect(screen.getByTestId('hero-events').textContent).toBe(
      '3,662 events in the 14 days before the sweep 17d ago',
    );
  });

  it('labels the address table by the sweep age', () => {
    render(
      <MemoryRouter>
        <HostAddresses machine={machine()} focusAddress={null} focusField={null} windowDays={14} builtAt={builtAt} />
      </MemoryRouter>,
    );
    const table = screen.getByTestId('host-addresses');
    expect(
      within(table).getAllByRole('columnheader', { name: 'Events, 14 days before the sweep 17d ago' }),
    ).toHaveLength(2);
  });

  it('keeps the plain window for a sweep of the last day', () => {
    // NEGATIVE CONTROL: a fresh sweep counts the last 14 days.
    expect(sweepWindowWords(14, new Date(Date.now() - 3_600_000).toISOString())).toBe('last 14 days');
    expect(sweepWindowWords(null, builtAt)).toBe('window of the sweep 17d ago');
  });
});
