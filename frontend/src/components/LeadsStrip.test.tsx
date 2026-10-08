import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getLeads: vi.fn(),
  dismissLead: vi.fn(),
  huntLead: vi.fn(),
  promoteLead: vi.fn(),
  reopenLead: vi.fn(),
}));

import { dismissLead, getLeads, huntLead, promoteLead, reopenLead, type Lead } from '../lib/api';
import {
  ACTION_REOPEN,
  PILL_CLOSED_BY_HUNT,
  PILL_DISMISSED,
  PILL_HUNTED,
  PILL_IN_PROGRESS,
  PILL_NEW,
  PILL_PROMOTED,
  TAB_ALL,
  TAB_CLOSED,
  TAB_IN_PROGRESS,
  TAB_NEEDS_DECISION,
  WEIGHT_AT_FORMATION,
} from '../lib/tooltips';
import { outcomeLabel } from '../lib/labels';
import {
  DISMISS_REASONS,
  HUNT_CLEAN_REASON,
  HUNT_CLOSED_LABEL,
  LEAD_ACTION,
  LeadsStrip,
  REASON_LABEL,
  earlierThreat,
  leadState,
} from './LeadsStrip';

const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const LEAD: Lead = {
  id: 7,
  status: 'open',
  formed_at: iso(5 * HOUR),
  updated_at: iso(5 * HOUR),
  entities: [['host', '10.1.10.21']],
  kinds: ['novel_destination', 'off_hours', 'novel_consumed_port'],
  weight_at_formation: 1.066,
  scope_count: 1,
  hunt_id: null,
  shadow: true,
  single_signal: true,
  observations: [
    { kind: 'novel_destination', summary: 'first connection to 140.82.121.4', occurrences: 1, born_at: iso(29 * HOUR), first_seen_at: iso(29 * HOUR), source: 'alert', shadow: false },
    { kind: 'off_hours', summary: 'active at 19:00', occurrences: 1, born_at: iso(29 * HOUR), first_seen_at: iso(29 * HOUR), source: 'profile', shadow: false },
    { kind: 'novel_consumed_port', summary: 'first outbound on tcp/1234', occurrences: 3, born_at: iso(5 * HOUR), first_seen_at: iso(5 * HOUR), source: 'profile', shadow: false },
  ],
};

function LocationProbe() {
  const l = useLocation();
  return <div data-testid="loc">{l.pathname + l.search}</div>;
}

const mount = () =>
  render(
    <MemoryRouter>
      <LeadsStrip />
    </MemoryRouter>,
  );

/** The strip as the Hunts page mounts it: the tab lives in the address. */
const mountBound = (path = '/hunts') =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/hunts" element={<LeadsStrip paramBound />} />
      </Routes>
      <LocationProbe />
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getLeads).mockReset().mockResolvedValue([LEAD]);
  vi.mocked(dismissLead).mockReset().mockResolvedValue({} as never);
  vi.mocked(huntLead).mockReset().mockResolvedValue({ hunt_id: 'H-NEW' });
  vi.mocked(promoteLead).mockReset().mockResolvedValue({ investigation_id: 'INV-9' });
  vi.mocked(reopenLead).mockReset().mockResolvedValue({} as never);
});

describe('LeadsStrip', () => {
  it('puts the kinds on the chip, not behind a click', async () => {
    mount();
    const row = await screen.findByTestId('lead-7');
    expect(within(row).getByText('new destination')).toBeTruthy();
    expect(within(row).getByText('off hours')).toBeTruthy();
    expect(within(row).getByText('new outbound port')).toBeTruthy();
    expect(within(row).getByText(/weight at formation 1\.07/)).toBeTruthy();
    expect(within(row).getByText('10.1.10.21').getAttribute('href')).toBe('/hosts/10.1.10.21');
  });

  it('shows the observations that formed it, with repeats counted', async () => {
    mount();
    const row = await screen.findByTestId('lead-7');
    expect(within(row).getByText(/tcp\/1234/)).toBeTruthy();
    expect(within(row).getByText(/seen on 3 sweeps, first seen 5h ago/)).toBeTruthy();
    expect(within(row).queryByText(/seen 3 times/)).toBeNull();
  });

  // A stored summary ends in a stop. The line read "over 20 days., seen on 2 sweeps".
  it('drops the stop before the sweep count', async () => {
    vi.mocked(getLeads).mockResolvedValue([
      {
        ...LEAD,
        observations: [
          { ...LEAD.observations[2], summary: 'The baseline holds 4 values over 20 days.' },
        ],
      },
    ]);
    mount();
    const row = await screen.findByTestId('lead-7');
    expect(within(row).getByText(/over 20 days, seen on 3 sweeps/)).toBeTruthy();
    expect(row.textContent).not.toContain('days.,');
  });

  it('shows a shadow lead with its flag rather than hiding it', async () => {
    mount();
    const row = await screen.findByTestId('lead-7');
    expect(within(row).getByText('shadow')).toBeTruthy();
  });

  it('names a single-signal lead and the source of each observation', async () => {
    mount();
    const row = await screen.findByTestId('lead-7');
    expect(within(row).getByText('one signal, repeated')).toBeTruthy();
    expect(within(row).getByText('alert')).toBeTruthy();
  });

  it('states what is absent under the first tab', async () => {
    vi.mocked(getLeads).mockResolvedValue([]);
    mount();
    await waitFor(() => expect(screen.getByText(/No lead waits on a decision/)).toBeTruthy());
  });

  it('counts the leads that wait on a decision', async () => {
    mount();
    await waitFor(() => expect(screen.getByText(/· 1 needs a decision/)).toBeTruthy());
  });

  it('links each lead to its page and offers the hunt action', async () => {
    mount();
    const row = await screen.findByTestId('lead-7');
    expect(within(row).getByText('Lead 7').getAttribute('href')).toBe('/leads/7');
    expect(within(row).getByRole('button', { name: LEAD_ACTION.hunt })).toBeTruthy();
  });
});

// The word "shadow" had two meanings on this strip. The lead carried the chip
// whether or not a shadow analytic wrote anything on it, and an observation
// from an analytic in shadow carried the word "candidate", which is a status
// and not a source. Both readings told an analyst the wrong thing.
describe('a lead formed from a backtest replay', () => {
  it('carries a grey chip on the row', async () => {
    vi.mocked(getLeads).mockResolvedValue([LEAD, { ...LEAD, id: 8, formed_from_backtest: true }]);
    mount();
    const marked = await screen.findByTestId('lead-8');
    expect(within(marked).getByTestId('lead-backtest-chip-8').textContent).toBe(
      'Formed from a backtest replay',
    );
    // Negative control: a live lead carries no chip.
    expect(within(screen.getByTestId('lead-7')).queryByTestId('lead-backtest-chip-7')).toBeNull();
  });
});

describe('LeadsStrip shadow semantics', () => {
  it('leaves the shadow chip off a lead that holds no shadow observation', async () => {
    vi.mocked(getLeads).mockResolvedValue([{ ...LEAD, shadow: false }]);
    mount();
    const row = await screen.findByTestId('lead-7');
    expect(within(row).queryByText('shadow')).toBeNull();
  });

  it('reads a shadow observation as shadow and never as candidate', async () => {
    vi.mocked(getLeads).mockResolvedValue([
      {
        ...LEAD,
        shadow: true,
        observations: [
          {
            kind: 'catalog_match',
            summary: 'an analytic in shadow matched',
            occurrences: 1,
            born_at: iso(HOUR),
            first_seen_at: iso(HOUR),
            source: 'candidate',
            shadow: true,
          },
        ],
      },
    ]);
    mount();
    const row = await screen.findByTestId('lead-7');
    const observations = within(row).getByText(/an analytic in shadow matched/).parentElement!;
    expect(within(observations).queryByText('candidate')).toBeNull();
  });

  it('maps a legacy candidate source to catalog on a live observation', async () => {
    vi.mocked(getLeads).mockResolvedValue([
      {
        ...LEAD,
        observations: [
          {
            kind: 'catalog_match',
            summary: 'a live analytic matched',
            occurrences: 1,
            born_at: iso(HOUR),
            first_seen_at: iso(HOUR),
            source: 'candidate',
            shadow: false,
          },
        ],
      },
    ]);
    mount();
    const row = await screen.findByTestId('lead-7');
    expect(within(row).queryByText('candidate')).toBeNull();
    expect(within(row).getByText('catalog')).toBeTruthy();
  });

  it('says in the header that a lead starts no hunt by itself', async () => {
    mount();
    const note = await screen.findByTestId('leads-note');
    expect(note.textContent).toBe(
      'soc-ai records leads. It does not start a hunt from a lead by itself.',
    );
    expect(note.getAttribute('title')).toContain('An analyst starts every hunt from a lead');
  });
});

// The tabs read as modes. "Start a hunt" under New and "Open the hunt" under
// Hunting sounded like the same act. The tabs now name what the analyst must
// do, and the block opens on the one that waits.
describe('LeadsStrip tabs', () => {
  it('names the four tabs and opens on Needs decision', async () => {
    mount();
    await screen.findByTestId('lead-7');
    for (const label of ['Needs decision', 'In progress', 'Closed', 'All']) {
      expect(screen.getByRole('button', { name: label })).toBeTruthy();
    }
    expect(
      screen.getByRole('button', { name: 'Needs decision' }).getAttribute('aria-pressed'),
    ).toBe('true');
    await waitFor(() => expect(getLeads).toHaveBeenCalledWith('needs_decision'));
  });

  it('asks the server for each tab in its own word', async () => {
    mount();
    await screen.findByTestId('lead-7');
    fireEvent.click(screen.getByRole('button', { name: 'In progress' }));
    await waitFor(() => expect(getLeads).toHaveBeenCalledWith('in_progress'));
    fireEvent.click(screen.getByRole('button', { name: 'Closed' }));
    await waitFor(() => expect(getLeads).toHaveBeenCalledWith('closed'));
    fireEvent.click(screen.getByRole('button', { name: 'All' }));
    await waitFor(() => expect(getLeads).toHaveBeenCalledWith('all'));
  });

  it('states the legend under the tabs', async () => {
    mount();
    const legend = await screen.findByTestId('leads-legend');
    // F9: the legend said the analyst decides every close, and every lead on
    // prod read "closed by soc-ai". The words are true for both closers.
    expect(legend.textContent).toBe(
      'New: nobody has acted. In progress: a hunt is running. ' +
        'Hunted: the hunt finished, and the lead waits on a decision. ' +
        'Closed: an analyst dismissed the lead or opened an investigation on it, or a clean ' +
        'hunt closed it.',
    );
  });

  it('names both closers on the Closed tab and in its empty state', async () => {
    vi.mocked(getLeads).mockResolvedValue([]);
    mount();
    const tab = await screen.findByRole('button', { name: 'Closed' });
    expect(tab.getAttribute('title')).toMatch(/a clean hunt closed/);
    fireEvent.click(tab);
    await waitFor(() =>
      expect(screen.getByText(/no clean hunt closed one/)).toBeTruthy(),
    );
  });

  it('names what is absent under each tab', async () => {
    vi.mocked(getLeads).mockResolvedValue([]);
    mount();
    await waitFor(() => expect(screen.getByText(/No lead waits on a decision/)).toBeTruthy());
    fireEvent.click(screen.getByRole('button', { name: 'In progress' }));
    await waitFor(() => expect(screen.getByText(/No hunt is running on a lead/)).toBeTruthy());
    fireEvent.click(screen.getByRole('button', { name: 'Closed' }));
    await waitFor(() => expect(screen.getByText(/No closed leads/)).toBeTruthy());
  });

  it('states all three formation rules on the header', async () => {
    mount();
    const header = await screen.findByTestId('leads-heading');
    const title = header.getAttribute('title') ?? '';
    expect(title).toContain('A lead forms at a live weight of 0.85 across two or more types.');
    expect(title).toContain('A finding with no benign baseline forms alone.');
    expect(title).toContain('marked one signal, repeated');
  });
});

// On the Hunts page the tab lives in the address, so a reload keeps it and the
// Needs-you strip jumps straight to the leads that wait.
describe('LeadsStrip tabs in the address', () => {
  it('writes the tab to the address and drops the default again', async () => {
    mountBound();
    await screen.findByTestId('lead-7');
    fireEvent.click(screen.getByRole('button', { name: 'Closed' }));
    await waitFor(() => expect(screen.getByTestId('loc').textContent).toBe('/hunts?leads=closed'));
    fireEvent.click(screen.getByRole('button', { name: 'Needs decision' }));
    await waitFor(() => expect(screen.getByTestId('loc').textContent).toBe('/hunts'));
  });

  it('opens on the tab the address names', async () => {
    mountBound('/hunts?leads=all');
    await waitFor(() => expect(getLeads).toHaveBeenCalledWith('all'));
    expect(screen.getByRole('button', { name: 'All' }).getAttribute('aria-pressed')).toBe('true');
  });

  it('reads a tab the strip does not know as Needs decision', async () => {
    mountBound('/hunts?leads=nonsense');
    await waitFor(() => expect(getLeads).toHaveBeenCalledWith('needs_decision'));
  });

  it('carries an anchor the Needs-you strip can jump to', async () => {
    const { container } = mountBound();
    await screen.findByTestId('lead-7');
    expect(container.querySelector('#leads')).toBeTruthy();
  });
});

// "Dismiss" navigated to the lead page. An analyst clearing three benign leads
// left the strip three times and came back to it three times.
describe('LeadsStrip dismissal in place', () => {
  it('opens the reason form on the row and keeps the link to the page', async () => {
    mount();
    const row = await screen.findByTestId('lead-7');
    expect(within(row).getByText('Lead 7').getAttribute('href')).toBe('/leads/7');
    fireEvent.click(within(row).getByRole('button', { name: LEAD_ACTION.dismiss }));
    expect(within(row).getByLabelText('Reason')).toBeTruthy();
  });

  it('posts the reason and reads the leads again', async () => {
    mount();
    const row = await screen.findByTestId('lead-7');
    fireEvent.click(within(row).getByRole('button', { name: LEAD_ACTION.dismiss }));
    fireEvent.change(within(row).getByLabelText('Reason'), {
      target: { value: 'expected_for_role' },
    });
    fireEvent.change(within(row).getByPlaceholderText('Note, optional'), {
      target: { value: 'the backup agent' },
    });
    fireEvent.click(within(row).getByRole('button', { name: 'Confirm dismiss' }));
    await waitFor(() =>
      expect(dismissLead).toHaveBeenCalledWith(7, 'expected_for_role', 'the backup agent'),
    );
    await waitFor(() => expect(vi.mocked(getLeads).mock.calls.length).toBeGreaterThan(1));
  });

  it('will not post without a reason', async () => {
    mount();
    const row = await screen.findByTestId('lead-7');
    fireEvent.click(within(row).getByRole('button', { name: LEAD_ACTION.dismiss }));
    const confirm = within(row).getByRole('button', { name: 'Confirm dismiss' }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
  });
});

// The pill is the state. The tab is a filter. The actions follow the state.
describe('LeadsStrip state pills', () => {
  const RUNNING: Lead = { ...LEAD, id: 8, status: 'hunting', hunt_id: 'H-LEAD-1', hunt_status: 'running' };
  const HUNTED: Lead = {
    ...LEAD,
    id: 14,
    status: 'hunting',
    hunt_id: 'H-LEAD-4',
    hunt_status: 'complete',
    hunt_outcome_label: 'No threat observed',
  };
  const DISMISSED: Lead = { ...LEAD, id: 9, status: 'dismissed', dismissed_reason: 'expected_for_role' };
  const PROMOTED: Lead = { ...LEAD, id: 11, status: 'promoted', investigation_id: 'INV-7' };

  // S3: three earlier hunts found a threat and the newest found none. The
  // pill read the newest hunt alone and said "No threat observed".
  it('states the worst hunt outcome on record in the pill', async () => {
    vi.mocked(getLeads).mockResolvedValue([
      { ...HUNTED, hunt_outcome: 'clean', hunt_count: 4, hunt_threat_count: 3 },
    ]);
    mount();
    const row = await screen.findByTestId('lead-14');
    const pill = within(row).getByTestId('lead-status');
    expect(pill.textContent).toBe('Hunted · An earlier hunt found a threat');
    expect(pill.style.color).toBe('#f04438');
  });

  // Negative controls: no threat on record, and a newest hunt that found one.
  it.each([
    [{ hunt_outcome: 'clean', hunt_count: 2, hunt_threat_count: 0 }, 'Hunted · No threat found', 'ok'],
    [
      { hunt_outcome: 'threats', hunt_count: 2, hunt_threat_count: 2 },
      'Hunted · Threat found',
      'danger',
    ],
  ])('keeps the newest outcome when it is the worst on record (%#)', async (extra, words, tone) => {
    vi.mocked(getLeads).mockResolvedValue([{ ...HUNTED, ...extra }]);
    mount();
    const row = await screen.findByTestId('lead-14');
    const pill = within(row).getByTestId('lead-status');
    expect(pill.textContent).toBe(words);
    // The colour comes from lib/labels.ts. A threat is never green.
    expect(pill.style.color).toBe(tone === 'danger' ? '#f04438' : '#3fb950');
  });

  // The hunt routes send the public key threat_found. The rule compared the
  // lead store code 'threats' alone, so a newest hunt with a threat read as an
  // earlier one.
  it('reads the newest threat through lib/labels.ts in both vocabularies', () => {
    expect(earlierThreat({ hunt_outcome: 'threat_found', hunt_threat_count: 2 })).toBe(false);
    expect(earlierThreat({ hunt_outcome: 'threats', hunt_threat_count: 2 })).toBe(false);
    expect(earlierThreat({ hunt_outcome: 'no_threat', hunt_threat_count: 2 })).toBe(true);
    expect(earlierThreat({ hunt_outcome: 'clean', hunt_threat_count: 0 })).toBe(false);
    // The closure words are the label of the clean outcome.
    expect(HUNT_CLOSED_LABEL).toBe(`Closed. ${outcomeLabel('no_threat')}.`);
  });

  it('derives the state from the record', () => {
    expect(leadState(LEAD)).toBe('new');
    expect(leadState(RUNNING)).toBe('in_progress');
    expect(leadState(HUNTED)).toBe('hunted');
    expect(leadState(DISMISSED)).toBe('dismissed');
    expect(leadState(PROMOTED)).toBe('promoted');
  });

  it('reads a lead nobody has acted on as New, and offers two actions', async () => {
    mount();
    const row = await screen.findByTestId('lead-7');
    const pill = within(row).getByTestId('lead-status');
    expect(pill.textContent).toBe('New');
    expect(pill.getAttribute('title')).toBe(PILL_NEW);
    for (const action of [LEAD_ACTION.hunt, LEAD_ACTION.dismiss]) {
      expect(within(row).getByRole('button', { name: action })).toBeTruthy();
    }
    expect(LEAD_ACTION.hunt).toBe('Hunt this lead');
  });

  it('starts the hunt from the New pill', async () => {
    mount();
    const row = await screen.findByTestId('lead-7');
    fireEvent.click(within(row).getByRole('button', { name: LEAD_ACTION.hunt }));
    await waitFor(() => expect(huntLead).toHaveBeenCalledWith(7));
  });

  // The hunt investigates what it finds and brings back the verdicts, so a
  // lead offers no investigation of its own (owner, 2026-10-07). The row
  // offered "Promote" beside "Hunt", and the owner could not tell them apart.
  it('offers no investigation of its own, before or after the hunt', async () => {
    vi.mocked(getLeads).mockResolvedValue([LEAD, HUNTED]);
    mount();
    for (const id of ['lead-7', 'lead-14']) {
      const row = await screen.findByTestId(id);
      expect(
        within(row).queryByRole('button', { name: /Open an investigation|Promote/ }),
      ).toBeNull();
    }
    expect(promoteLead).not.toHaveBeenCalled();
  });

  it('reads a running hunt as In progress and offers only the hunt', async () => {
    vi.mocked(getLeads).mockResolvedValue([RUNNING]);
    mount();
    const row = await screen.findByTestId('lead-8');
    const pill = within(row).getByTestId('lead-status');
    expect(pill.textContent).toBe('In progress');
    expect(pill.getAttribute('title')).toBe(PILL_IN_PROGRESS);
    expect(within(row).getByText(LEAD_ACTION.viewHunt).getAttribute('href')).toBe('/hunts/H-LEAD-1');
    expect(within(row).queryByRole('button', { name: LEAD_ACTION.hunt })).toBeNull();
    expect(within(row).queryByRole('button', { name: LEAD_ACTION.dismiss })).toBeNull();
  });

  it('reads a finished hunt as Hunted, names the outcome and offers three actions', async () => {
    vi.mocked(getLeads).mockResolvedValue([HUNTED]);
    mount();
    const row = await screen.findByTestId('lead-14');
    const pill = within(row).getByTestId('lead-status');
    expect(pill.textContent).toBe('Hunted · No threat observed');
    expect(pill.getAttribute('title')).toBe(PILL_HUNTED);
    expect(within(row).getByText(LEAD_ACTION.readHunt).getAttribute('href')).toBe('/hunts/H-LEAD-4');
    for (const action of [LEAD_ACTION.dismiss, LEAD_ACTION.huntAgain]) {
      expect(within(row).getByRole('button', { name: action })).toBeTruthy();
    }
  });

  it('confirms a second hunt on a lead that already has one', async () => {
    vi.mocked(getLeads).mockResolvedValue([HUNTED]);
    mount();
    const row = await screen.findByTestId('lead-14');
    fireEvent.click(within(row).getByRole('button', { name: LEAD_ACTION.huntAgain }));
    expect(within(row).getByText(/A hunt on this lead already finished/)).toBeTruthy();
    expect(huntLead).not.toHaveBeenCalled();
    fireEvent.click(within(row).getByRole('button', { name: 'Start another hunt' }));
    await waitFor(() => expect(huntLead).toHaveBeenCalledWith(14));
  });

  // C9: the form chose "A benign repeat" after a clean hunt, and one click
  // then dismissed a lead with a reason the analyst had not read.
  it('opens the dismissal with no reason chosen after a hunt found no threat', async () => {
    vi.mocked(getLeads).mockResolvedValue([HUNTED]);
    mount();
    const row = await screen.findByTestId('lead-14');
    fireEvent.click(within(row).getByRole('button', { name: LEAD_ACTION.dismiss }));
    const select = within(row).getByLabelText('Reason') as HTMLSelectElement;
    expect(select.value).toBe('');
    expect(
      (within(row).getByRole('button', { name: 'Confirm dismiss' }) as HTMLButtonElement).disabled,
    ).toBe(true);
  });

  it('offers the four reasons an analyst uses besides the baseline ones', async () => {
    vi.mocked(getLeads).mockResolvedValue([HUNTED]);
    mount();
    const row = await screen.findByTestId('lead-14');
    fireEvent.click(within(row).getByRole('button', { name: LEAD_ACTION.dismiss }));
    const select = within(row).getByLabelText('Reason') as HTMLSelectElement;
    const words = Array.from(select.options).map((o) => o.textContent);
    for (const word of [
      'Authorized test or scan',
      'Duplicate of another lead or investigation',
      'The analytic logic is wrong',
      'Lab or test host',
    ]) {
      expect(words).toContain(word);
    }
    // Other stays last.
    expect(words[words.length - 1]).toBe('Other');
  });

  it('leaves the reason unchosen when the hunt found threats', async () => {
    vi.mocked(getLeads).mockResolvedValue([{ ...HUNTED, hunt_outcome_label: 'Threat findings' }]);
    mount();
    const row = await screen.findByTestId('lead-14');
    fireEvent.click(within(row).getByRole('button', { name: LEAD_ACTION.dismiss }));
    expect((within(row).getByLabelText('Reason') as HTMLSelectElement).value).toBe('');
  });

  it('reads a dismissed lead as Dismissed, names the reason and offers Reopen', async () => {
    vi.mocked(getLeads).mockResolvedValue([DISMISSED]);
    mount();
    const row = await screen.findByTestId('lead-9');
    const pill = within(row).getByTestId('lead-status');
    expect(pill.textContent).toBe('Dismissed');
    expect(pill.getAttribute('title')).toBe(PILL_DISMISSED);
    expect(within(row).getByText(/reason: Expected for this role/)).toBeTruthy();
    expect(within(row).queryByRole('button', { name: LEAD_ACTION.dismiss })).toBeNull();
    fireEvent.click(within(row).getByRole('button', { name: LEAD_ACTION.reopen }));
    await waitFor(() => expect(reopenLead).toHaveBeenCalledWith(9));
  });

  // The hit filter chips beside them carried a sentence each and the four lead
  // tabs carried none. A tab is a filter, and a filter with no sentence is one
  // an analyst guesses at.
  it('carries one sentence per tab', async () => {
    mount();
    await screen.findByTestId('leads-strip');
    expect(screen.getByRole('button', { name: 'Needs decision' }).getAttribute('title')).toBe(
      TAB_NEEDS_DECISION,
    );
    expect(screen.getByRole('button', { name: 'In progress' }).getAttribute('title')).toBe(
      TAB_IN_PROGRESS,
    );
    expect(screen.getByRole('button', { name: 'Closed' }).getAttribute('title')).toBe(TAB_CLOSED);
    expect(screen.getByRole('button', { name: 'All' }).getAttribute('title')).toBe(TAB_ALL);
  });

  it('reads a promoted lead as Promoted and links the investigation it became', async () => {
    vi.mocked(getLeads).mockResolvedValue([PROMOTED]);
    mount();
    const row = await screen.findByTestId('lead-11');
    const pill = within(row).getByTestId('lead-status');
    expect(pill.textContent).toBe('Promoted');
    expect(pill.getAttribute('title')).toBe(PILL_PROMOTED);
    expect(within(row).getByText(LEAD_ACTION.viewInvestigation).getAttribute('href')).toBe(
      '/investigation/INV-7',
    );
    expect(within(row).getByRole('button', { name: LEAD_ACTION.reopen })).toBeTruthy();
  });

  // A lead kept the id of an investigation the store no longer holds. The link
  // promised a page and landed on "No such investigation". A link goes to a
  // page, so where there is no page there is no link.
  it('says the investigation is gone instead of promising a page that answers 404', async () => {
    vi.mocked(getLeads).mockResolvedValue([{ ...PROMOTED, investigation_exists: false }]);
    mount();
    const row = await screen.findByTestId('lead-11');
    expect(within(row).getByText('The investigation no longer exists')).toBeTruthy();
    expect(within(row).queryByText(LEAD_ACTION.viewInvestigation)).toBeNull();
    expect(within(row).getByRole('button', { name: LEAD_ACTION.reopen })).toBeTruthy();
  });

  it('keeps the link when the server says nothing about the investigation', async () => {
    vi.mocked(getLeads).mockResolvedValue([PROMOTED]);
    mount();
    const row = await screen.findByTestId('lead-11');
    expect(within(row).getByText(LEAD_ACTION.viewInvestigation)).toBeTruthy();
    expect(within(row).queryByText('The investigation no longer exists')).toBeNull();
  });

  it('reads the one Reopen sentence the lead page reads', async () => {
    vi.mocked(getLeads).mockResolvedValue([DISMISSED]);
    mount();
    const row = await screen.findByTestId('lead-9');
    expect(
      within(row).getByRole('button', { name: LEAD_ACTION.reopen }).getAttribute('title'),
    ).toBe(ACTION_REOPEN);
  });

  // The chip said "weight at formation 1.00" and carried the sentence about
  // the weight NOW, which decays. A number that never moves wore the sentence
  // of a number that does.
  it('gives the formation weight its own sentence', async () => {
    mount();
    const row = await screen.findByTestId('lead-7');
    expect(within(row).getByText(/weight at formation/).getAttribute('title')).toBe(
      WEIGHT_AT_FORMATION,
    );
  });

  it('states the weight at formation on a closed lead and never a live weight', async () => {
    vi.mocked(getLeads).mockResolvedValue([PROMOTED]);
    mount();
    const row = await screen.findByTestId('lead-11');
    expect(within(row).getByText(/weight at formation 1\.07/)).toBeTruthy();
    expect(within(row).queryByText(/weight now/)).toBeNull();
  });
});

// One word for one thing: the shadow chip said one thing on the strip and
// another on the lead page.
describe('LeadsStrip shadow wording', () => {
  it('says on the shadow chip that no hunt starts from the lead', async () => {
    mount();
    const row = await screen.findByTestId('lead-7');
    expect(within(row).getByText('shadow').getAttribute('title')).toBe(
      'Recorded in shadow. No hunt starts from this lead by itself.',
    );
  });
});

// A user account is not a host. The strip linked every entity to the host
// dossier, which is keyed on an address and 404s a name.
describe('LeadsStrip user entities', () => {
  it('links a user entity to its entity page', async () => {
    vi.mocked(getLeads).mockResolvedValue([{ ...LEAD, id: 21, entities: [['user', 'svc_sql']] }]);
    mount();
    const row = await screen.findByTestId('lead-21');
    // The user carries its type, so a machine of the same name never opens.
    expect(within(row).getByRole('link', { name: 'svc_sql' }).getAttribute('href')).toBe(
      '/entity/svc_sql?type=user',
    );
  });

  it('links a host entity named by hostname to its entity page', async () => {
    vi.mocked(getLeads).mockResolvedValue([{ ...LEAD, id: 22, entities: [['host', 'ws-014']] }]);
    mount();
    const row = await screen.findByTestId('lead-22');
    expect(within(row).getByRole('link', { name: 'ws-014' }).getAttribute('href')).toBe(
      '/entity/ws-014',
    );
  });

  it('keeps an address on the host page', async () => {
    mount();
    const row = await screen.findByTestId('lead-7');
    expect(within(row).getByRole('link', { name: '10.1.10.21' }).getAttribute('href')).toBe(
      '/hosts/10.1.10.21',
    );
  });

  it('names the thing it is mounted on in the heading, and keeps its own tab', async () => {
    render(
      <MemoryRouter initialEntries={['/entity/svc_sql?leads=closed']}>
        <LeadsStrip entityKey="svc_sql" noun="entity" status="all" />
      </MemoryRouter>,
    );
    // The address of a host page describes the host, so the strip there does
    // not read the leads parameter of another screen.
    await waitFor(() => expect(getLeads).toHaveBeenCalledWith('all'));
  });
});

// The page holds the fold, because a Needs-you link opens this block before it
// scrolls there. The strip draws the chevron only when the page offers it.
describe('the fold', () => {
  const mountFolded = (collapsed: boolean) =>
    render(
      <MemoryRouter initialEntries={['/hunts']}>
        <LeadsStrip paramBound collapsed={collapsed} onToggleCollapsed={() => {}} />
      </MemoryRouter>,
    );

  it('keeps the heading, the count and the definition while it is folded', async () => {
    mountFolded(true);
    const heading = await screen.findByTestId('leads-heading');
    expect(heading.textContent).toContain('1 needs a decision');
    expect(screen.getByTestId('define-lead')).toBeTruthy();
    expect(screen.queryByTestId('lead-7')).toBeNull();
    // The tabs filter a list nobody can see.
    expect(screen.queryByRole('button', { name: 'Needs decision' })).toBeNull();
    expect(screen.queryByTestId('leads-legend')).toBeNull();
  });

  it('draws the rows and the tabs again when it is open', async () => {
    mountFolded(false);
    expect(await screen.findByTestId('lead-7')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Needs decision' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Collapse Leads' })).toBeTruthy();
  });

  it('carries no chevron on a host page, which offers no fold', async () => {
    mount();
    await screen.findByTestId('lead-7');
    expect(screen.queryByRole('button', { name: /^Collapse /})).toBeNull();
  });
});

describe('a lead the hunt closed', () => {
  const CLOSED_BY_HUNT: Lead = {
    ...LEAD,
    id: 21,
    status: 'dismissed',
    hunt_id: 'H-LEAD-21',
    hunt_status: 'complete',
    hunt_outcome_label: 'No threat observed',
    dismissed_reason: 'hunt_clean',
    dismissed_at: iso(2 * HOUR),
  };

  it('reads Closed with the sentence, names soc-ai, and offers Reopen only', async () => {
    vi.mocked(getLeads).mockResolvedValue([CLOSED_BY_HUNT]);
    mount();
    const row = await screen.findByTestId('lead-21');
    const pill = within(row).getByTestId('lead-status');
    expect(pill.textContent).toBe('Closed. No threat found.');
    expect(pill.getAttribute('title')).toBe(PILL_CLOSED_BY_HUNT);
    expect(pill.getAttribute('data-lead-state')).toBe('dismissed');
    expect(within(row).getByText('closed by soc-ai')).toBeTruthy();
    expect(within(row).queryByText(/reason:/)).toBeNull();
    expect(within(row).queryByText(/hunt_clean/)).toBeNull();
    expect(within(row).getByRole('button', { name: LEAD_ACTION.reopen })).toBeTruthy();
    expect(within(row).queryByRole('button', { name: LEAD_ACTION.dismiss })).toBeNull();
    expect(within(row).queryByRole('button', { name: LEAD_ACTION.huntAgain })).toBeNull();
  });

  it('keeps the analyst reasons the server accepts and never offers the closure as one', () => {
    expect(DISMISS_REASONS).toEqual([
      'expected_for_role',
      'known_change',
      'benign_repeat',
      'bad_baseline',
      'authorized_test',
      'duplicate',
      'bad_analytic_logic',
      'lab_host',
      'other',
    ]);
    expect(HUNT_CLEAN_REASON in REASON_LABEL).toBe(false);
  });

  it('reads every terminal hunt status as Hunted', () => {
    expect(leadState({ status: 'hunting', hunt_status: 'cancelled' })).toBe('hunted');
    expect(leadState({ status: 'hunting', hunt_status: 'interrupted' })).toBe('hunted');
    expect(leadState({ status: 'open', hunt_status: 'error', hunt_id: 'H-1' })).toBe('hunted');
  });
});
