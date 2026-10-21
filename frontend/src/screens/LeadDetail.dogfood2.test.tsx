import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LeadDetail } from './LeadDetail';

// The lead page after the second hunting dogfood (2026-10-06). Each block
// names the review item it holds.

vi.mock('../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../lib/api')>('../lib/api');
  return {
    ...actual,
    getLead: vi.fn(),
    getNeedsYou: vi.fn(),
    closeLeadAsPromoted: vi.fn(),
    keepLeadOpen: vi.fn(),
    getEvent: vi.fn(),
    resolveMachine: vi.fn(),
    getMachine: vi.fn(),
    listMachines: vi.fn(),
  };
});
import {
  closeLeadAsPromoted,
  getLead,
  getMachine,
  getNeedsYou,
  keepLeadOpen,
  listMachines,
  resolveMachine,
} from '../lib/api';
import { ShellProvider } from '../shell/ShellContext';

const LEAD = {
  id: 16,
  status: 'hunting',
  formed_at: '2026-09-30T10:00:00Z',
  updated_at: null,
  entities: [['host', '10.99.0.40']],
  kinds: ['catalog_match'],
  weight_at_formation: 1.0,
  weight_now: 0.9,
  scope_count: 1,
  hunt_id: 'H-16',
  hunt_status: 'complete',
  hunt_outcome: 'threats',
  hunt_outcome_label: 'Threat findings',
  shadow: false,
  single_signal: false,
  dismissed_reason: null,
  dismissed_note: null,
  dismissed_by: null,
  dismissed_at: null,
  investigation_id: null,
  dismiss_reasons: ['expected_for_role', 'other'],
  decisions: [],
  observations: [
    {
      id: 1,
      kind: 'catalog_match',
      spec_id: 'local-http-service-executes-id-command',
      summary: 'HTTP service executes id command: 10.99.0.40 (2 documents)',
      occurrences: 1,
      born_at: '2026-09-30T10:00:00Z',
      first_seen_at: '2026-09-30T10:00:00Z',
      source: 'catalog',
      shadow: false,
      weight_now: 0.9,
      birth_weight: 1.0,
      evidence: null,
    },
  ],
  hunts: [],
  promoted_findings: [
    {
      investigation_id: '01M48EPSK80EBWHBMZ5XH0SVZM',
      hunt_id: 'H-16',
      finding_ordinal: 1,
      finding_title: 'HTTP service executes id command as root',
      promoted_by: 'anonymous',
      promoted_at: '2026-10-06T09:00:00Z',
      status: 'complete',
      verdict: 'true_positive',
      confidence: 0.75,
    },
  ],
};

function mount() {
  return render(
    <MemoryRouter initialEntries={['/leads/16']}>
      <ShellProvider>
        <Routes>
          <Route path="/leads/:id" element={<LeadDetail />} />
        </Routes>
      </ShellProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.mocked(getLead).mockReset().mockResolvedValue(LEAD as never);
  vi.mocked(getNeedsYou).mockReset().mockResolvedValue({
    unread_shadow_hits: 0,
    leads_needing_decision: 1,
    total: 1,
    lead_auto_hunt: true,
  } as never);
  vi.mocked(closeLeadAsPromoted).mockReset().mockResolvedValue(LEAD as never);
  vi.mocked(keepLeadOpen).mockReset().mockResolvedValue(LEAD as never);
  vi.mocked(resolveMachine).mockReset().mockRejectedValue(new Error('no machine'));
  vi.mocked(listMachines).mockReset().mockResolvedValue({ rows: [], total: 0 } as never);
  vi.mocked(getMachine).mockReset();
});

describe('C8: the reasons sit in plain view', () => {
  const NEW = {
    ...LEAD,
    status: 'open',
    hunt_id: null,
    hunt_status: null,
    hunt_outcome: null,
    hunt_outcome_label: null,
    hunt_queued: false,
    promoted_findings: [],
  };

  it('states what a hunt does under the actions, and what "left to you" means', async () => {
    vi.mocked(getLead).mockResolvedValue(NEW as never);
    mount();
    expect((await screen.findByTestId('lead-actions-line')).textContent).toBe(
      'Hunt this lead. soc-ai investigates each threat finding of the hunt and shows the verdicts.',
    );
    expect(screen.getByTestId('lead-left-to-you-reason').textContent).toMatch(
      /^Auto-hunt starts no hunt here/,
    );
  });

  // Negative control: the hunted lead states the verb too, and offers no
  // control the line does not name.
  it('states the verb on a hunted lead, with no investigation control', async () => {
    mount();
    await screen.findByTestId('lead-status');
    expect(screen.getByTestId('lead-actions-line')).toBeTruthy();
    expect(screen.queryByRole('button', { name: /Open an investigation|Promote/ })).toBeNull();
  });

  it('marks an observation whose analytic was retired, with the date', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...LEAD,
      observations: [
        { ...LEAD.observations[0], shadow: true, analytic_retired_at: '2026-10-06T09:12:00Z' },
      ],
    } as never);
    mount();
    expect((await screen.findByTestId('observation-retired-1')).textContent).toBe(
      'analytic retired on 2026-10-06',
    );
    expect(within(screen.getByTestId('observation-1')).queryByText('shadow')).toBeNull();
  });
});

describe('W7: the lead title names the machine', () => {
  const MACHINE = {
    key: 'mac:aa',
    name: 'sr-router',
    primary_ip: '10.99.0.40',
    role: { value: 'server', label: 'server, DNS', confidence: 0.9, state: 'inferred', guess: null, stale_hours: null },
  };

  const row = (over: object = {}) =>
    ({ rows: [{ ...MACHINE, addresses: ['10.99.0.40'], ...over }], total: 1 }) as never;

  it('reads "Lead 16 · <name> · <address> · <role>"', async () => {
    vi.mocked(listMachines).mockResolvedValue(row());
    mount();
    await screen.findByTestId('lead-machine-name');
    const title = screen.getByRole('heading', { level: 1 });
    expect(title.textContent).toBe('Lead 16 · sr-router · 10.99.0.40 · server, DNS');
    expect(listMachines).toHaveBeenCalledWith(expect.objectContaining({ q: '10.99.0.40' }));
    // R3-D15: the resolve route answers 404 for an address no machine holds,
    // and the browser logged each one. The page reads the list instead.
    expect(resolveMachine).not.toHaveBeenCalled();
    expect(getMachine).not.toHaveBeenCalled();
    // R3-D15: the tab named no lead.
    expect(document.title).toBe('Lead 16 · soc·ai');
  });

  // Negative controls: a role held back as a guess, an address no machine
  // holds, and a machine whose address only starts with the lead's address.
  it('states no role the server holds back, and keeps the address alone when no machine holds it', async () => {
    vi.mocked(listMachines).mockResolvedValue(
      row({ role: { ...MACHINE.role, state: 'low_confidence', label: null, guess: 'server' } }),
    );
    const first = mount();
    await screen.findByTestId('lead-machine-name');
    expect(screen.queryByTestId('lead-machine-role')).toBeNull();
    first.unmount();
    vi.mocked(listMachines).mockResolvedValue({ rows: [], total: 0 } as never);
    const second = mount();
    await screen.findByTestId('lead-status');
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Lead 16 · 10.99.0.40');
    second.unmount();
    vi.mocked(listMachines).mockResolvedValue(
      row({ primary_ip: '10.99.0.41', addresses: ['10.99.0.41', '10.99.0.400'] }),
    );
    mount();
    await screen.findByTestId('lead-status');
    await waitFor(() => expect(listMachines).toHaveBeenCalled());
    expect(screen.queryByTestId('lead-machine-name')).toBeNull();
  });

  it('names the count a departure measures', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...LEAD,
      observations: [
        {
          ...LEAD.observations[0],
          kind: 'above_baseline',
          evidence: { baseline: { dimension: 'connection_rate', observed_count: 7 } },
        },
      ],
    } as never);
    mount();
    expect((await screen.findByTestId('observation-measures-1')).textContent).toBe(
      'It counts the network connections that this host starts in one hour.',
    );
  });
});

describe('a lead formed from a backtest replay', () => {
  it('carries a grey chip in the header', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...LEAD,
      promoted_findings: [],
      decisions: [
        {
          action: 'formed_from_backtest',
          at: '2026-10-06T08:00:00Z',
          by: 'soc-ai',
          reason: 'backtest_replay',
          note: 'This lead formed from a backtest replay.',
          hunt_id: null,
          investigation_id: null,
        },
      ],
    } as never);
    mount();
    expect((await screen.findByTestId('lead-backtest-chip')).textContent).toBe(
      'Formed from a backtest replay',
    );
  });

  // Negative control: a lead with no mark carries no chip.
  it('carries no chip on a live lead', async () => {
    mount();
    await screen.findByTestId('lead-status');
    expect(screen.queryByTestId('lead-backtest-chip')).toBeNull();
  });
});

describe('C2: the header says why this is a lead', () => {
  const day = 86_400_000;
  const at = (days: number) => new Date(Date.parse('2026-10-06T00:00:00Z') - days * day).toISOString();
  const RATE = {
    ...LEAD.observations[0],
    kind: 'above_baseline',
    spec_id: 'profile-connection-rate',
    source: 'profile',
    summary: 'The connection rate on Monday 04:00 is 7 per hour.',
    statistic: 'residual_z',
    statistic_value: 9.2,
    baseline_value: 0.5,
    evidence: { baseline: { dimension: 'connection_rate', observed_count: 7 } },
  };
  const LEAD7 = {
    ...LEAD,
    id: 7,
    kinds: ['above_baseline', 'off_hours'],
    promoted_findings: [],
    observations: [
      { ...RATE, id: 1, born_at: at(0), observed_at: at(0) },
      { ...RATE, id: 2, born_at: at(1), observed_at: at(1) },
      { ...RATE, id: 3, kind: 'off_hours', statistic: null, born_at: at(5), observed_at: at(5) },
      { ...RATE, id: 4, kind: 'off_hours', statistic: null, born_at: at(17.5), observed_at: at(17.5) },
    ],
  };

  it('states the observations by type, the entity and the span', async () => {
    vi.mocked(getLead).mockResolvedValue(LEAD7 as never);
    mount();
    expect((await screen.findByTestId('lead-why')).textContent).toBe(
      'Why this is a lead: 2 rate spikes and 2 off-hours sightings on one host in 18 days.',
    );
  });

  it('keeps the weights behind the Scoring toggle', async () => {
    vi.mocked(getLead).mockResolvedValue(LEAD7 as never);
    mount();
    await screen.findByTestId('lead-why');
    // Negative control: no weight is on screen before the toggle.
    expect(screen.queryByTestId('lead-meta')).toBeNull();
    expect(screen.queryByText(/weight now/)).toBeNull();
    expect(screen.queryByTestId('observation-weight-1')).toBeNull();
    const toggle = screen.getByRole('button', { name: 'Scoring' });
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    fireEvent.click(toggle);
    expect(screen.getByTestId('lead-meta').textContent).toContain('weight now 0.90');
    expect(screen.getByTestId('observation-weight-1').textContent).toBe(
      'weight 1.00 at first sighting, 0.90 now',
    );
    expect(screen.getByRole('button', { name: 'Hide scoring' }).getAttribute('aria-expanded')).toBe(
      'true',
    );
  });

  it('reads a z score as a multiple of the expected rate', async () => {
    vi.mocked(getLead).mockResolvedValue(LEAD7 as never);
    mount();
    const line = await screen.findByTestId('observation-statistic-1');
    expect(line.textContent).toBe('7 per hour against an expected 0.5. That is 14 times the expected rate.');
    expect(screen.queryByText(/residual z/)).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Scoring' }));
    expect(screen.getByTestId('observation-score-1').textContent).toContain('A residual z of 9.2');
  });
});

describe('S2: a promoted finding with a verdict comes back to its lead', () => {
  it('asks to close the lead on the investigation, with the verdict', async () => {
    mount();
    const strip = await screen.findByTestId('lead-verdict-strip');
    expect(strip.textContent).toContain(
      "An investigation holds this lead's evidence. Verdict: true positive 0.75. " +
        'Close the lead on this investigation?',
    );
    fireEvent.click(within(strip).getByRole('button', { name: 'Close the lead' }));
    await waitFor(() =>
      expect(closeLeadAsPromoted).toHaveBeenCalledWith(16, '01M48EPSK80EBWHBMZ5XH0SVZM'),
    );
  });

  it('records Keep open against the investigation', async () => {
    mount();
    const strip = await screen.findByTestId('lead-verdict-strip');
    fireEvent.click(within(strip).getByRole('button', { name: 'Keep open' }));
    await waitFor(() =>
      expect(keepLeadOpen).toHaveBeenCalledWith(16, '01M48EPSK80EBWHBMZ5XH0SVZM'),
    );
  });

  // The store keeps the word "promoted". The row names the act by its
  // control (owner, 2026-10-07).
  it('puts the investigation and the verdict on the timeline', async () => {
    mount();
    const row = await screen.findByTestId('lead-promoted-finding');
    expect(row.textContent).toContain(
      'anonymous opened an investigation on finding F2. Investigation 01M48EPSK80EBWHBMZ5XH0SVZM: true positive 0.75.',
    );
    expect(row.textContent).toContain('investigation opened');
    expect(row.textContent).not.toMatch(/promoted/i);
    const link = within(row).getByRole('link', { name: 'View investigation' });
    expect(link.getAttribute('href')).toBe('/investigation/01M48EPSK80EBWHBMZ5XH0SVZM');
  });

  // Negative controls: no verdict yet, an answer already given, a closed lead.
  it.each([
    [
      'a running investigation',
      {
        promoted_findings: [
          { ...LEAD.promoted_findings[0], status: 'running', verdict: null, confidence: null },
        ],
      },
    ],
    [
      'an answer already given',
      {
        decisions: [
          {
            action: 'kept_open',
            at: '2026-10-06T10:00:00Z',
            by: 'alice',
            reason: null,
            note: null,
            hunt_id: null,
            investigation_id: '01M48EPSK80EBWHBMZ5XH0SVZM',
          },
        ],
      },
    ],
    ['a promoted lead', { status: 'promoted', investigation_id: '01M48EPSK80EBWHBMZ5XH0SVZM' }],
  ])('does not ask over %s', async (_name, extra) => {
    vi.mocked(getLead).mockResolvedValue({ ...LEAD, ...extra } as never);
    mount();
    await screen.findByTestId('lead-status');
    expect(screen.queryByTestId('lead-verdict-strip')).toBeNull();
  });

  it('names a close on a finding verdict on the timeline', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...LEAD,
      status: 'promoted',
      investigation_id: '01M48EPSK80EBWHBMZ5XH0SVZM',
      decisions: [
        {
          action: 'promoted',
          at: '2026-10-06T10:00:00Z',
          by: 'alice',
          reason: 'finding_verdict',
          note: null,
          hunt_id: null,
          investigation_id: '01M48EPSK80EBWHBMZ5XH0SVZM',
        },
      ],
    } as never);
    mount();
    const rows = await screen.findAllByTestId('lead-decision');
    expect(rows[0].textContent).toContain(
      'alice closed the lead on the investigation of a hunt finding.',
    );
  });
});
