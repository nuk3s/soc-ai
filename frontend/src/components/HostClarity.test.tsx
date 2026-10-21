// The host page words an analyst could not read (dogfood 2026-10-06, hosts
// tier 3 and 4): status words with no legend, dataset names, the decay
// machinery, "shadow lead", numbers with no scale, a duplicate Note box, a
// facts counter that ignored inferred facts, "alert" twice on one lead card,
// a role chip with no sign of its tooltip, and three near-equal rates.
import { render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getLeads: vi.fn(),
  getNeedsYou: vi.fn(),
  getObservations: vi.fn(),
}));

import { getLeads, getNeedsYou, getObservations, type Lead } from '../lib/api';
import {
  confidencePhrase,
  factsCounter,
  identitySentence,
  plainEvidence,
  sentenceText,
} from '../lib/hostDossier';
import { CHIP_LEFT_TO_YOU, LEADS_NOTE_AUTO_HUNT } from '../lib/tooltips';
import type { DossierField, DossierFieldName, ProfileDimension } from '../lib/types';
import { BehaviouralProfile, collapsedRate, PROFILE_LEGEND } from './BehaviouralProfile';
import { DeclareEditor } from './HostFacts';
import { HostObservations } from './HostObservations';
import { LeadsStrip } from './LeadsStrip';

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

const fields = (patch: Partial<Record<DossierFieldName, Partial<DossierField>>> = {}) =>
  NAMES.map((n) => field(n, patch[n] ?? {}));

const STALE = (value: string): Partial<DossierField> => ({
  reason: 'stale',
  inferred_value: value,
  inferred_confidence: 0.9,
  last_run_at: new Date(Date.now() - 4 * 86_400_000).toISOString(),
});

describe('dataset names in words', () => {
  it('names a connection record without the log field', () => {
    expect(plainEvidence('responds on tcp/22 with 1,261 zeek.conn records from 1 distinct peers')).toBe(
      'responds on tcp/22 with 1,261 network connection records from 1 distinct peers',
    );
    expect(plainEvidence('names from zeek.dns and zeek.dhcp')).toBe('names from DNS lookups and DHCP leases');
  });

  it('leaves a line with no dataset name as it is', () => {
    // NEGATIVE CONTROL
    expect(plainEvidence('blue (from agent host log)')).toBe('blue (from agent host log)');
  });
});

describe('numbers with a scale', () => {
  it('states a confidence against its scale, with a word', () => {
    expect(confidencePhrase(0.5)).toBe('confidence 0.50 of 1.00, low');
    expect(confidencePhrase(0.7)).toBe('confidence 0.70 of 1.00, medium');
    expect(confidencePhrase(0.92)).toBe('confidence 0.92 of 1.00, high');
  });
});

describe('the facts counter and the identity sentence count inferred facts', () => {
  it('counts the withheld guesses on a host whose evidence went old', () => {
    const rich = fields({ role: STALE('security_appliance'), os_detail: STALE('Oracle Linux 9'), hostname: STALE('sensor01') });
    expect(factsCounter(rich)).toBe('3 of 12 facts · 3 from old or weak evidence');
  });

  it('counts confirmed facts alone when nothing is withheld', () => {
    // NEGATIVE CONTROL
    const plain = fields({ role: { value: 'server', reason: null, source: 'behaviour' } });
    expect(factsCounter(plain)).toBe('1 of 12 facts');
  });

  it('writes the identity from the guesses and says so', () => {
    const text = sentenceText(identitySentence({ ip: '192.0.2.5', fields: fields({ role: STALE('server'), os_detail: STALE('Oracle Linux 9') }) }));
    expect(text).toBe('192.0.2.5 is a server running Oracle Linux 9. Some of these facts come from old or weak evidence.');
    expect(text).not.toMatch(/Nothing else is known/);
  });

  it('reads the agent OS for a machine whose OS fields hold nothing', () => {
    const text = sentenceText(identitySentence({ ip: '192.0.2.5', fields: fields() }, 'files01', { os: 'Debian 12' }));
    expect(text).toBe('files01 is a machine running Debian 12.');
  });
});

describe('the behavioural profile', () => {
  const rate: ProfileDimension = {
    dimension: 'connection_rate',
    shape: 'numeric',
    coverage: 'measured',
    support_days: 21,
    window_days: 30,
    summary: 'started per hour, median · work 124 · off 124 · weekend 122',
    top: [],
  };

  it('states what each status word means', () => {
    render(<BehaviouralProfile profile={[rate]} />);
    const legend = screen.getByTestId('profile-legend').textContent ?? '';
    expect(legend).toBe(PROFILE_LEGEND);
    for (const word of ['measured:', 'learning:', 'blind:', 'stale:']) expect(legend).toContain(word);
  });

  it('collapses three near-equal rates into one with the three in the tooltip', () => {
    render(<BehaviouralProfile profile={[rate]} />);
    const row = screen.getByTestId('profile-rate-collapsed');
    expect(row.textContent).toBe('about 123 per hour at all times');
    expect(row.getAttribute('title')).toBe(rate.summary);
  });

  it('keeps three rates that differ', () => {
    // NEGATIVE CONTROL: a host idle at the weekend is a finding.
    expect(collapsedRate('started per hour, median · work 124 · off 30 · weekend 2')).toBeNull();
    expect(collapsedRate('started per hour, median · work 124')).toBeNull();
  });
});

describe('the observations panel', () => {
  beforeEach(() => {
    vi.mocked(getObservations).mockReset().mockResolvedValue({
      entity: '192.0.2.5',
      days: 7,
      observations: [
        {
          id: 1,
          kind: 'novel_served_port',
          spec_id: 'profile.ports',
          source: 'profile',
          shadow: false,
          summary: 'responds on tcp/22 with 40 zeek.conn records',
          weight_now: 0.4,
          lead_id: null,
          born_at: new Date().toISOString(),
          occurrences: 20,
          read: true,
        },
      ],
    });
  });

  it('says the decay in one plain sentence and names no dataset', async () => {
    render(
      <MemoryRouter>
        <HostObservations entityKey="192.0.2.5" />
      </MemoryRouter>,
    );
    expect(screen.getByTestId('observations-weight-note').textContent).toBe(
      'all sources · an observation counts half as much after 48 hours',
    );
    expect(await screen.findByText('responds on tcp/22 with 40 network connection records')).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/half-life|zeek\./);
    expect(screen.getByTestId('observation-sweeps-1').getAttribute('title')).toMatch(/It is not more severe\.$/);
  });
});

describe('the shadow lead definition', () => {
  it('defines a shadow lead where the note names one', () => {
    expect(LEADS_NOTE_AUTO_HUNT).toContain('A shadow lead comes from a shadow analytic.');
    expect(CHIP_LEFT_TO_YOU).toContain('A shadow lead comes from a shadow analytic.');
  });
});

describe('the operator note form', () => {
  it('has one box for the Operator note fact', () => {
    render(
      <DeclareEditor
        f={field('policy_notes')}
        busy={false}
        onSave={() => {}}
        onCancel={() => {}}
        onInvalid={() => {}}
      />,
    );
    expect(screen.getByLabelText(/Value for/)).toBeTruthy();
    expect(screen.queryByLabelText(/Note for/)).toBeNull();
  });

  it('keeps the Note box on any other fact', () => {
    // NEGATIVE CONTROL
    render(
      <DeclareEditor
        f={field('criticality')}
        busy={false}
        onSave={() => {}}
        onCancel={() => {}}
        onInvalid={() => {}}
      />,
    );
    expect(screen.getByLabelText(/Note for/)).toBeTruthy();
  });
});

describe('the lead card', () => {
  const lead = (over: Partial<Lead>): Lead => ({
    id: 10,
    status: 'open',
    formed_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    entities: [['host', '192.0.2.40']],
    kinds: ['alert'],
    weight_at_formation: 1.0,
    scope_count: 1,
    hunt_id: null,
    shadow: false,
    single_signal: false,
    observations: [
      {
        kind: 'alert',
        summary: 'Rule: true positive at 0.70',
        occurrences: 20,
        born_at: new Date().toISOString(),
        first_seen_at: null,
        source: 'alert',
        shadow: false,
      },
    ],
    ...over,
  });

  beforeEach(() => {
    vi.mocked(getNeedsYou).mockReset().mockRejectedValue(new Error('offline'));
  });

  it('says "alert" once, and gives the weight its scale', async () => {
    vi.mocked(getLeads).mockReset().mockResolvedValue([lead({})]);
    render(
      <MemoryRouter>
        <LeadsStrip status="all" />
      </MemoryRouter>,
    );
    const row = await screen.findByTestId('lead-10');
    expect(within(row).queryByTestId('lead-observation-source')).toBeNull();
    expect(within(row).getAllByText('alert')).toHaveLength(1);
    expect(within(row).getByText(/weight at formation 1\.00 · a lead forms at 0\.85/)).toBeTruthy();
  });

  it('keeps the source chip when no type chip says the word', async () => {
    // NEGATIVE CONTROL
    vi.mocked(getLeads).mockReset().mockResolvedValue([lead({ kinds: ['novel_destination'] })]);
    render(
      <MemoryRouter>
        <LeadsStrip status="all" />
      </MemoryRouter>,
    );
    const row = await screen.findByTestId('lead-10');
    await waitFor(() => expect(within(row).getByTestId('lead-observation-source').textContent).toBe('alert'));
  });
});
