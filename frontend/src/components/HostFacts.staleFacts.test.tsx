// The facts panel of a domain controller with a 17-day-old sweep (dogfood
// 2026-10-19, R4-D11). The header said "8 of 12 facts · 8 from old or weak
// evidence". The panel showed ROLE alone and listed the other 7 as
// "Unknown". The Services card said "the sweep has no answer for this host"
// while the API held tcp/389, udp/53 and tcp/135.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { staleServicePorts } from '../screens/HostDetail';
import type { Dossier, DossierField, DossierFieldName } from '../lib/types';
import { HostFacts, HostUnknowns } from './HostFacts';
import { HostKpis } from './HostKpis';

const NAMES: DossierFieldName[] = [
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

const OLD = new Date(Date.now() - 17 * 86_400_000).toISOString();

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

const stale = (value: string, json: unknown = null): Partial<DossierField> => ({
  reason: 'stale',
  inferred_value: value,
  inferred_value_json: json,
  inferred_confidence: 0.9,
  inferred_source: 'hostlog',
  last_run_at: OLD,
});

const PORTS = [
  { port: 389, proto: 'tcp', count: 543, service: null },
  { port: 53, proto: 'udp', count: 300, service: null },
  { port: 135, proto: 'tcp', count: 90, service: null },
];

const dossier = (): Dossier => ({
  ip: '192.0.2.10',
  found: true,
  fields: NAMES.map((name) => {
    switch (name) {
      case 'hostname':
        return field(name, stale('dc01'));
      case 'os_family':
        return field(name, stale('windows'));
      case 'role':
        return field(name, stale('server'));
      case 'services_offered':
        return field(name, stale('tcp/389, udp/53, tcp/135', PORTS));
      default:
        return field(name);
    }
  }),
  first_seen: OLD,
  last_seen: OLD,
  last_built_at: OLD,
  last_observed_at: OLD,
  event_count: 10,
  identity_rebound_at: null,
  build_error: null,
  override_count: 0,
  conflict_count: 0,
  reporting: true,
});

describe('the facts panel shows old facts marked stale', () => {
  it('lists every stale guess as a row with its age', () => {
    render(<HostFacts dossier={dossier()} canDeclare={false} onApplied={() => {}} focusField={null} />);
    const facts = screen.getByTestId('host-facts');
    expect(within(facts).getByText('Facts')).toBeTruthy();
    expect(within(facts).getByTestId('withheld-hostname').textContent).toBe('dc01 · stale 17d ago');
    expect(within(facts).getByTestId('withheld-os_family').textContent).toBe('windows · stale 17d ago');
    expect(within(facts).getByTestId('withheld-role').textContent).toBe('server · stale 17d ago');
    expect(within(facts).getByTestId('withheld-services_offered').textContent).toBe(
      'tcp/389, udp/53, tcp/135 · stale 17d ago',
    );
    expect(screen.getByTestId('host-facts-count').textContent).toBe(
      '4 of 12 facts · 4 from old or weak evidence',
    );
  });

  it('keeps a stale guess out of the unknown line', () => {
    render(<HostUnknowns dossier={dossier()} canDeclare={false} onApplied={() => {}} focusField={null} />);
    const line = screen.getByTestId('host-unknowns').textContent ?? '';
    expect(line).not.toMatch(/Hostname/);
    expect(line).not.toMatch(/Services/i);
    // NEGATIVE CONTROL: a field with no guess stays unknown.
    expect(line).toMatch(/MAC address/);
  });
});

describe('a stale traffic pattern', () => {
  // Round 2 (V2-2): the row read "a traffic pattern · stale 17d ago" while the
  // stored guess was a sentence. The JSON is no port list, so the row reads the
  // sentence.
  it('reads the stored sentence of the guess', () => {
    const base = dossier();
    const sentence = 'Busiest hours 11:00, 20:00, 02:00 UTC. No outbound remote access';
    const withPattern: Dossier = {
      ...base,
      fields: base.fields.map((f) =>
        f.field === 'activity_profile'
          ? field('activity_profile', stale(sentence, { busiest_hours: [11, 20, 2] }))
          : f,
      ),
    };
    render(<HostFacts dossier={withPattern} canDeclare={false} onApplied={() => {}} focusField={null} />);
    expect(screen.getByTestId('withheld-activity_profile').textContent).toBe(
      `${sentence} · stale 17d ago`,
    );
  });
});

describe('the Services card shows the stale ports', () => {
  it('names the stale ports and their age', () => {
    const stalePorts = staleServicePorts(dossier());
    expect(stalePorts).toEqual({ ports: ['tcp/389', 'udp/53', 'tcp/135'], age: '17d ago' });
    render(
      <MemoryRouter>
        <HostKpis
          ip="192.0.2.10"
          services={stalePorts!.ports}
          servicesStale={stalePorts!.age}
          activity={null}
          state="ok"
          range="24h"
        />
      </MemoryRouter>,
    );
    const card = screen.getByTestId('kpi-services');
    expect(card.textContent).toContain('tcp/389, udp/53, tcp/135');
    expect(card.textContent).toContain('stale 17d ago');
  });

  it('says the sweep holds no services when there is no guess either', () => {
    // NEGATIVE CONTROL: no value, no guess.
    const d = dossier();
    d.fields = d.fields.map((f) => (f.field === 'services_offered' ? field('services_offered') : f));
    expect(staleServicePorts(d)).toBeNull();
    render(
      <MemoryRouter>
        <HostKpis ip="192.0.2.10" services={null} activity={null} state="ok" range="24h" />
      </MemoryRouter>,
    );
    expect(screen.getByTestId('kpi-services').textContent).toContain('the sweep holds no service data for this host');
  });
});
