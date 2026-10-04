// The host page surfaces the 2026-10-01 dogfood found wrong (H7, H9, H15,
// RO3, RO6, RO7, RO17). Each test pins one fix on the path the old code took.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getObservations: vi.fn(),
  clearDossierOverride: vi.fn(),
  setDossierOverride: vi.fn(),
}));

import { clearDossierOverride, getObservations } from '../lib/api';
import type { Dossier, DossierField, DossierFieldName, HostActivity, ProfileDimension } from '../lib/types';
import { newestActivity } from '../screens/HostDetail';
import { BehaviouralProfile } from './BehaviouralProfile';
import { FactRow } from './HostFacts';
import { HostHero } from './HostHero';
import { HostKpis } from './HostKpis';
import { HostObservations } from './HostObservations';

const IP = '192.0.2.10';
const DAY = 86_400_000;

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
  first_seen: new Date(Date.now() - 30 * DAY).toISOString(),
  last_seen: new Date(Date.now() - 8 * DAY).toISOString(),
  last_built_at: new Date(Date.now() - 8 * DAY).toISOString(),
  last_observed_at: null,
  event_count: 100,
  identity_rebound_at: null,
  build_error: null,
  override_count: 0,
  conflict_count: 0,
  reporting: false,
  ...over,
});

beforeEach(() => {
  vi.mocked(getObservations).mockReset();
  vi.mocked(clearDossierOverride).mockReset();
});

describe('last seen reads the live activity', () => {
  it('takes the newest volume bar over an 8-day-old sweep stamp', () => {
    const recent = new Date(Date.now() - 2 * 3_600_000).toISOString();
    const lastActivity = newestActivity([
      { ts: new Date(Date.now() - 20 * 3_600_000).toISOString(), events: 3000 },
      { ts: recent, events: 2400 },
      { ts: new Date(Date.now() - 3_600_000).toISOString(), events: 0 },
    ]);
    expect(lastActivity).toBe(recent);
    render(<HostHero dossier={dossier()} adminBlocked={false} lastActivity={lastActivity} />);
    expect(screen.getByTestId('hero-last-seen').textContent).toBe('last seen 2h ago');
  });

  it('keeps the sweep stamp when the live read has nothing', () => {
    // Negative control: no activity, no claim of recent life.
    render(<HostHero dossier={dossier()} adminBlocked={false} lastActivity={newestActivity([])} />);
    expect(screen.getByTestId('hero-last-seen').textContent).toBe('last seen 8d ago');
  });
});

describe('a blind baseline row says why', () => {
  const blind = (reason: string | null): ProfileDimension => ({
    dimension: 'process_names',
    shape: 'categorical',
    coverage: 'blind',
    coverage_reason: reason,
    support_days: 0,
    window_days: 30,
    summary: '',
    top: [],
  });

  it('prints the reason the server states', () => {
    render(
      <BehaviouralProfile
        profile={[blind('this host ships no endpoint process events. It ships host logs and osquery.')]}
      />,
    );
    expect(screen.getByTestId('behavioural-profile').textContent).toContain(
      'cannot be measured: this host ships no endpoint process events. It ships host logs and osquery.',
    );
  });
});

describe('the connections card names its unit', () => {
  it('states the in-and-out rate per hour beside the count', () => {
    const activity: HostActivity = {
      peers: [{ ip: '192.0.2.20', hostname: null, direction: 'out', ports: [443], events: 10, alerted: false }],
      volume: [{ ts: new Date().toISOString(), events: 5676 }],
      users: null,
      alerts_7d: 0,
      latest_investigation: null,
      peers_truncated: false,
      users_truncated: false,
    };
    render(
      <MemoryRouter>
        <HostKpis ip={IP} services={[]} activity={activity} state="ok" range="24h" />
      </MemoryRouter>,
    );
    expect(screen.getByTestId('kpi-events-rate').textContent).toBe('237 per hour in and out');
  });
});

describe('no observations links to Operate', () => {
  it('makes the Operate sentence a link to the catalog', async () => {
    vi.mocked(getObservations).mockResolvedValue({ entity: IP, days: 7, observations: [] });
    render(
      <MemoryRouter>
        <HostObservations entityKey={IP} />
      </MemoryRouter>,
    );
    const link = await screen.findByRole('link', { name: /operate shows the analytics/i });
    expect(link.getAttribute('href')).toBe('/operate#catalog');
  });
});

describe('a declared fact', () => {
  const declaredRole = field('role', {
    value: 'domain_controller',
    source: 'operator',
    confidence: 1,
    strength: 'strong',
    reason: null,
    overridden: true,
    operator_actor: 'admin',
    inferred_value: 'server',
    inferred_confidence: 0.5,
    inferred_source: 'behaviour',
    inference_reason: 'low_confidence',
    evidence: { behaviour: { strings: ['responds on tcp/53'], value: 'server', confidence: 0.5 } },
  });

  const mountRow = (f: DossierField, onApplied = vi.fn()) =>
    render(<FactRow ip={IP} f={f} canDeclare highlight={false} onApplied={onApplied} />);

  it('shows the declared role by its label, never the slug', () => {
    mountRow(declaredRole);
    const row = screen.getByTestId('field-role');
    expect(row.textContent).toContain('domain controller');
    expect(row.textContent).not.toContain('domain_controller');
  });

  it('states the real outcome of a removal, in the drawer and in the Edit form', async () => {
    const applied = vi.fn();
    vi.mocked(clearDossierOverride).mockResolvedValue(dossier());
    mountRow(declaredRole, applied);
    const outcome =
      "Remove my declaration. The sweep's answer, server at 0.50, then shows as a low-confidence guess.";
    expect(screen.getByRole('button', { name: outcome })).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Edit Role' }));
    const remove = screen.getByTestId('declare-remove-role');
    expect(remove.textContent).toBe(outcome);
    fireEvent.click(remove);
    await waitFor(() => expect(clearDossierOverride).toHaveBeenCalledWith(IP, 'role'));
    await waitFor(() => expect(applied).toHaveBeenCalled());
  });

  it('offers no Remove in the form of a field nobody declared', () => {
    // Negative control: there is no declaration to remove.
    mountRow(
      field('os_family', { value: 'windows', source: 'hostlog', confidence: 0.9, strength: 'strong', reason: null }),
    );
    fireEvent.click(screen.getByRole('button', { name: 'Edit Operating system' }));
    expect(screen.queryByTestId('declare-remove-os_family')).toBeNull();
  });

  it('renders a structured payload as rows in the Why drawer, never as JSON', () => {
    mountRow(
      field('services_offered', {
        value_json: [
          { port: 389, proto: 'tcp', count: 1200, service: 'ldap' },
          { port: 88, proto: 'tcp', count: 900 },
        ],
        source: 'behaviour',
        confidence: 0.9,
        strength: 'strong',
        reason: null,
        evidence: { behaviour: { strings: ['answers 2 ports'] } },
      }),
    );
    const payload = screen.getByTestId('why-payload');
    expect(within(payload).getByText('· tcp/389 · ldap · 1,200 connections')).toBeTruthy();
    expect(screen.getByTestId('field-services_offered').textContent).not.toContain('{"port"');
  });
});
