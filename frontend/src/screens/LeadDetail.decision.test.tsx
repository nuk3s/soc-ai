import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LeadDetail } from './LeadDetail';

// F5 (production review 2026-11-12). The lead page did not give the decision
// in one read. A lead with the pill "Hunted · No threat found" read "Hunt
// this lead. ..." under its title. "weight now 0.32" sat behind Scoring, and
// a lead forms at 0.85. The buttons and the nine dismissal reasons stated no
// effect. The page now opens with one state line, states one effect line for
// each button, states the effect of each reason, and marks a decayed weight.

vi.mock('../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../lib/api')>('../lib/api');
  return {
    ...actual,
    getLead: vi.fn(),
    getNeedsYou: vi.fn(),
    getHunt: vi.fn(),
    getEvent: vi.fn(),
    listMachines: vi.fn(),
  };
});
import { getHunt, getLead, getNeedsYou, listMachines } from '../lib/api';
import {
  DISMISS_REASON_COMMON,
  DISMISS_REASON_EFFECT,
  LEAD_ACTION_EFFECT,
  WEIGHT_DECAYED,
} from '../lib/tooltips';
import { DISMISS_REASONS, REASON_LABEL } from '../components/LeadsStrip';
import { ShellProvider } from '../shell/ShellContext';

const DAY = 86_400_000;
const ago = (days: number) => new Date(Date.now() - days * DAY).toISOString();

const obs = (id: number, kind: string, days: number) => ({
  id,
  kind,
  spec_id: 'prior-connection-rate',
  summary: 'The connection rate departed from the baseline.',
  occurrences: 1,
  born_at: ago(days),
  observed_at: ago(days),
  first_seen_at: ago(days),
  source: 'profile',
  shadow: true,
  weight_now: 0.1,
  birth_weight: 0.35,
  evidence: null,
});

/** Lead 12 of the review: hunted 39 days ago, clean, held, weight 0.32. */
const HUNTED = {
  id: 12,
  status: 'hunting',
  formed_at: ago(39),
  updated_at: ago(2),
  entities: [['host', '192.0.2.33']],
  kinds: ['below_baseline', 'novel_consumed_port'],
  weight_at_formation: 0.93,
  weight_now: 0.32,
  scope_count: 1,
  hunt_id: 'H-12',
  hunt_status: 'complete',
  hunt_outcome: 'clean',
  hunt_outcome_label: 'No threat found',
  hunt_count: 1,
  hunt_threat_count: 0,
  shadow: true,
  single_signal: false,
  dismissed_reason: null,
  dismissed_note: null,
  dismissed_by: null,
  dismissed_at: null,
  investigation_id: null,
  dismiss_reasons: DISMISS_REASONS,
  decisions: [],
  hold_reason: 'partial_read',
  hold_sentence: 'The hunt could not read all evidence.',
  observations: [
    obs(1, 'below_baseline', 2),
    obs(2, 'novel_consumed_port', 9),
    obs(3, 'above_baseline', 20),
    obs(4, 'above_baseline', 25),
    obs(5, 'above_baseline', 29.5),
  ],
  hunts: [
    {
      id: 'H-12',
      status: 'complete',
      outcome: 'clean',
      outcome_label: 'No threat found',
      threat_findings: 0,
      steps: 29,
      elapsed_sec: 300,
      started_at: ago(39.2),
      started_by: 'admin',
      answer: 'No malicious indication.',
      not_checked: ['No payload or container telemetry for AdGuard.'],
    },
  ],
  promoted_findings: [],
};

const NEW = {
  ...HUNTED,
  status: 'open',
  hunt_id: null,
  hunt_status: null,
  hunt_outcome: null,
  hunt_outcome_label: null,
  hunt_count: 0,
  hunt_queued: false,
  hold_reason: null,
  hold_sentence: null,
  weight_now: 1.2,
  hunts: [],
};

function mount() {
  return render(
    <MemoryRouter initialEntries={['/leads/12']}>
      <ShellProvider>
        <Routes>
          <Route path="/leads/:id" element={<LeadDetail />} />
        </Routes>
      </ShellProvider>
    </MemoryRouter>,
  );
}

const stateLine = async () => (await screen.findByTestId('lead-state-sentence')).textContent;

beforeEach(() => {
  vi.mocked(getLead).mockReset().mockResolvedValue(HUNTED as never);
  vi.mocked(getHunt).mockReset().mockRejectedValue(new Error('not read'));
  vi.mocked(getNeedsYou).mockReset().mockResolvedValue({
    unread_shadow_hits: 0,
    leads_needing_decision: 1,
    total: 1,
    lead_auto_hunt: true,
  } as never);
  vi.mocked(listMachines).mockReset().mockResolvedValue({
    rows: [
      {
        primary_ip: '192.0.2.33',
        addresses: ['192.0.2.33'],
        name: 'adguard2',
        role: { state: 'unknown', value: null, label: null },
      },
    ],
    total: 1,
  } as never);
});

describe('the state line', () => {
  it('states what was seen, on which host, what the hunt concluded and what the lead waits on', async () => {
    mount();
    await screen.findByTestId('lead-machine-name');
    expect(await stateLine()).toBe(
      'soc-ai saw 1 collapsed rate, 1 new outbound port and 3 rate spikes on adguard2 at ' +
        '192.0.2.33 in 28 days. The newest lead hunt ran 39 days ago and found no threat. ' +
        'The lead waits on your decision: dismiss it or hunt again.',
    );
  });

  it('is the first text under the header, before the definitions', async () => {
    mount();
    const line = await screen.findByTestId('lead-state-sentence');
    const legend = screen.getByTestId('lead-legend');
    expect(line.compareDocumentPosition(legend) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    const effects = screen.getByTestId('lead-action-effects');
    expect(line.compareDocumentPosition(effects) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('states that no hunt ran on a new lead, and who decides', async () => {
    vi.mocked(getLead).mockResolvedValue(NEW as never);
    mount();
    expect(await stateLine()).toContain(
      'No hunt ran on this lead. The lead waits on your decision: hunt it or dismiss it.',
    );
  });

  it('names auto-hunt on a lead whose hunt is queued', async () => {
    vi.mocked(getLead).mockResolvedValue({ ...NEW, shadow: false, hunt_queued: true } as never);
    mount();
    expect(await stateLine()).toContain(
      'No hunt ran on this lead. The lead waits on auto-hunt. Its hunt starts within a minute.',
    );
  });

  it('NEGATIVE CONTROL: claims no result while the hunt runs', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...HUNTED,
      hunt_status: 'running',
      hunt_outcome: null,
      hunt_outcome_label: null,
      hunts: [{ ...HUNTED.hunts[0], status: 'running', outcome: '', answer: '', not_checked: [] }],
    } as never);
    mount();
    const text = await stateLine();
    expect(text).toContain('A hunt runs on this lead now. The lead waits on the hunt.');
    expect(text).not.toContain('found no threat');
  });

  it('says a closed lead waits on nothing', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...HUNTED,
      status: 'dismissed',
      dismissed_reason: 'known_change',
      dismissed_by: 'jordan',
      dismissed_at: ago(1),
    } as never);
    mount();
    expect(await stateLine()).toContain('An analyst dismissed the lead. It waits on nothing.');
  });

  it('says a fleet condition lead waits on no decision', async () => {
    vi.mocked(getLead).mockResolvedValue({ ...NEW, status: 'fleet_condition', scope_count: 34 } as never);
    mount();
    expect(await stateLine()).toContain('The lead is a fleet condition. It waits on no decision.');
  });
});

describe('the repeats after the close', () => {
  const DISMISSED = {
    ...HUNTED,
    status: 'dismissed',
    dismissed_reason: 'known_change',
    dismissed_by: 'jordan',
    dismissed_at: ago(3),
  };

  it('states the count and the newest repeat of a closed lead, with the rule in the tooltip', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...DISMISSED,
      repeats_after_close: 4,
      last_repeat_at: new Date(Date.now() - 2 * 3_600_000).toISOString(),
    } as never);
    mount();
    const line = await screen.findByTestId('lead-repeats-after-close');
    expect(line.textContent).toBe('4 repeats after the close. Newest: 2h ago.');
    expect(line.getAttribute('title')).toContain('207 hours');
  });

  it('NEGATIVE CONTROL: prints no line for a closed lead with zero repeats', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...DISMISSED,
      repeats_after_close: 0,
      last_repeat_at: null,
    } as never);
    mount();
    await stateLine();
    expect(screen.queryByTestId('lead-repeats-after-close')).toBeNull();
  });
});

describe('one effect line for each button', () => {
  const effects = async () => {
    const box = await screen.findByTestId('lead-action-effects');
    return within(box)
      .getAllByTestId(/^lead-action-effect-/)
      .map((el) => el.textContent);
  };

  it('states the three buttons of a hunted lead, and no hunt verb the lead does not offer', async () => {
    mount();
    expect(await effects()).toEqual([
      LEAD_ACTION_EFFECT.readHunt,
      LEAD_ACTION_EFFECT.dismiss,
      LEAD_ACTION_EFFECT.huntAgain,
    ]);
    // NEGATIVE CONTROL: the page read "Hunt this lead. ..." over a lead that
    // was hunted already and offered no such button.
    expect(screen.queryByRole('button', { name: 'Hunt this lead' })).toBeNull();
    expect(screen.queryByTestId('lead-action-effect-hunt')).toBeNull();
    expect(screen.queryByText(/^Hunt this lead\./)).toBeNull();
  });

  it('states the two buttons of a new lead', async () => {
    vi.mocked(getLead).mockResolvedValue(NEW as never);
    mount();
    expect(await effects()).toEqual([LEAD_ACTION_EFFECT.hunt, LEAD_ACTION_EFFECT.dismiss]);
    expect(LEAD_ACTION_EFFECT.hunt).toBe(
      'Hunt this lead. soc-ai investigates each threat finding of the hunt and shows the verdicts.',
    );
  });

  it('states Hunt now on a lead whose hunt is queued', async () => {
    vi.mocked(getLead).mockResolvedValue({ ...NEW, shadow: false, hunt_queued: true } as never);
    mount();
    expect(await effects()).toEqual([LEAD_ACTION_EFFECT.dismiss, LEAD_ACTION_EFFECT.huntNow]);
  });

  it('states Reopen alone on a dismissed lead', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...HUNTED,
      status: 'dismissed',
      dismissed_reason: 'known_change',
      dismissed_at: ago(1),
    } as never);
    mount();
    expect(await effects()).toEqual([LEAD_ACTION_EFFECT.reopen]);
  });

  it('names the button at the start of each line', () => {
    const names: Record<keyof typeof LEAD_ACTION_EFFECT, string> = {
      hunt: 'Hunt this lead',
      huntNow: 'Hunt now',
      dismiss: 'Dismiss',
      viewHunt: 'View hunt',
      readHunt: 'Read hunt',
      huntAgain: 'Hunt again',
      reopen: 'Reopen',
      viewInvestigation: 'View investigation',
    };
    for (const [key, name] of Object.entries(names)) {
      expect(LEAD_ACTION_EFFECT[key as keyof typeof LEAD_ACTION_EFFECT].startsWith(`${name}. `)).toBe(true);
    }
  });
});

describe('the effect of each dismissal reason', () => {
  it('has one effect for every reason the server accepts', () => {
    for (const reason of DISMISS_REASONS) {
      expect(DISMISS_REASON_EFFECT[reason], reason).toMatch(/^Records /);
    }
    expect(Object.keys(DISMISS_REASON_EFFECT).sort()).toEqual([...DISMISS_REASONS].sort());
  });

  it('states that no reason changes a baseline, an analytic or a host', () => {
    // The backend stores the reason and counts it. It reads no reason to
    // change a thing (soc_ai/store/leads.py, soc_ai/hunting/ledger.py).
    expect(DISMISS_REASON_COMMON).toContain('Each reason closes the lead in the same way.');
    expect(DISMISS_REASON_COMMON).toContain('No reason changes a baseline, an analytic or a host.');
    expect(DISMISS_REASON_EFFECT.bad_baseline).toContain('The baseline does not change.');
    expect(DISMISS_REASON_EFFECT.bad_analytic_logic).toContain('The analytic keeps its status');
    expect(DISMISS_REASON_EFFECT.expected_for_role).toContain('The role of the host does not change.');
  });

  it('opens the form with the common line, then states the effect of the chosen reason', async () => {
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Dismiss' }));
    const effect = screen.getByTestId('dismiss-reason-effect');
    expect(effect.textContent).toBe(DISMISS_REASON_COMMON);
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'bad_baseline' } });
    expect(screen.getByTestId('dismiss-reason-effect').textContent).toBe(
      `${DISMISS_REASON_EFFECT.bad_baseline} ${DISMISS_REASON_COMMON}`,
    );
    // Each option carries its effect too, for a hover.
    const option = within(screen.getByLabelText('Reason')).getByRole('option', {
      name: REASON_LABEL.lab_host,
    });
    expect(option.getAttribute('title')).toBe(DISMISS_REASON_EFFECT.lab_host);
  });
});

describe('the mark of a decayed weight', () => {
  it('is in plain view when the live weight is under the weight a lead forms at', async () => {
    mount();
    const mark = await screen.findByTestId('lead-weight-decayed');
    expect(mark.textContent).toBe('weight decayed to 0.32 · a lead forms at 0.85');
    expect(mark.getAttribute('title')).toBe(WEIGHT_DECAYED);
    // The Scoring toggle is closed. The mark does not wait for it.
    expect(screen.queryByTestId('lead-meta')).toBeNull();
  });

  it('NEGATIVE CONTROL: is absent at the forming weight and above it', async () => {
    for (const weight_now of [0.85, 1.2]) {
      vi.mocked(getLead).mockResolvedValue({ ...HUNTED, weight_now } as never);
      const { unmount } = mount();
      await screen.findByTestId('lead-state-sentence');
      expect(screen.queryByTestId('lead-weight-decayed')).toBeNull();
      unmount();
    }
  });

  it('NEGATIVE CONTROL: is absent on a closed lead, which states no live weight', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...HUNTED,
      status: 'dismissed',
      dismissed_reason: 'known_change',
      dismissed_at: ago(1),
      weight_now: 0.1,
    } as never);
    mount();
    await screen.findByTestId('lead-state-sentence');
    expect(screen.queryByTestId('lead-weight-decayed')).toBeNull();
  });
});
