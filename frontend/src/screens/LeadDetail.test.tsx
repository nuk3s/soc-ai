import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LeadDetail } from './LeadDetail';

vi.mock('../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../lib/api')>('../lib/api');
  return {
    ...actual,
    getLead: vi.fn(),
    getHunts: vi.fn(),
    huntLead: vi.fn(),
    dismissLead: vi.fn(),
    promoteLead: vi.fn(),
    reopenLead: vi.fn(),
    getEvent: vi.fn(),
  };
});
import { ApiError, getEvent, getHunts, getLead, huntLead, reopenLead } from '../lib/api';
import {
  ACTION_REOPEN,
  CHIP_ONE_SIGNAL,
  DEFINE_LEAD,
  LEAD_LEGEND,
  STATUS_COMPLETE,
  STATUS_COMPLETE_ROW,
  WEIGHT_AT_FORMATION,
  WEIGHT_NOW,
} from '../lib/tooltips';
import { ShellProvider } from '../shell/ShellContext';

const LEAD = {
  id: 12,
  status: 'open',
  formed_at: '2026-09-18T10:00:00Z',
  updated_at: null,
  entities: [['host', '10.1.2.3']],
  kinds: ['prior_no_baseline', 'off_hours'],
  weight_at_formation: 1.3,
  weight_now: 1.28,
  scope_count: 1,
  hunt_id: null,
  shadow: false,
  single_signal: false,
  dismissed_reason: null,
  dismissed_note: null,
  dismissed_by: null,
  dismissed_at: null,
  investigation_id: null,
  dismiss_reasons: ['expected_for_role', 'known_change', 'benign_repeat', 'bad_baseline', 'other'],
  observations: [
    {
      id: 1, kind: 'prior_no_baseline', spec_id: 'identity-4662-dcsync-nonmachine',
      summary: 'Directory replication requested by localuser, not a machine account',
      occurrences: 1, born_at: '2026-09-18T10:00:00Z', first_seen_at: '2026-09-18T10:00:00Z',
      source: 'catalog', shadow: false, weight_now: 1.0, birth_weight: 1.0,
      evidence: { sample_ids: ['7Kq2c1', '7Kq2c4'] },
    },
    {
      id: 2, kind: 'off_hours', spec_id: 'profile-activity-outside-measured-hours',
      summary: 'active around 03:00 UTC, outside the hours this host is normally active (14 events)',
      occurrences: 1, born_at: '2026-09-18T07:00:00Z', first_seen_at: '2026-09-18T07:00:00Z',
      source: 'profile', shadow: false, weight_now: 0.28, birth_weight: 0.3, evidence: null,
    },
  ],
};

const HUNT_ON_LEAD = {
  id: 'H-LEAD-1',
  objective: '[lead 12] Investigate 10.1.2.3. The lead formed from a finding and off hours.',
  kind: 'lead',
  status: 'complete',
  findingCount: 1,
  threatFindingCount: 1,
  outcome: 'threats',
  affectedHosts: 1,
  confidence: 0.8,
  startedBy: 'analyst',
  starter: 'lead',
  leadId: 12,
  when: '4m',
  ts: '2026-09-18T11:00:00Z',
  chatCount: 0,
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

beforeEach(() => {
  vi.mocked(getLead).mockReset().mockResolvedValue(LEAD as never);
  vi.mocked(getHunts).mockReset().mockResolvedValue([]);
  vi.mocked(huntLead).mockReset().mockResolvedValue({ hunt_id: 'H-NEW' });
  vi.mocked(reopenLead).mockReset().mockResolvedValue(LEAD as never);
  vi.mocked(getEvent).mockReset().mockResolvedValue({
    id: '7Kq2c1',
    dataset: 'windows.security',
    timestamp: '2026-09-18T10:00:00Z',
    source: { winlog: { event_id: 4662 } },
  });
});

describe('LeadDetail', () => {
  it('shows the entity, both weights, and the timeline with evidence ids', async () => {
    mount();
    await waitFor(() => expect(screen.getByText('10.1.2.3')).toBeTruthy());
    expect(screen.getByText(/weight now 1\.28/)).toBeTruthy();
    expect(screen.getByText(/at formation 1\.30/)).toBeTruthy();
    expect(screen.getByText(/Directory replication requested by/)).toBeTruthy();
    expect(screen.getByText('7Kq2c1')).toBeTruthy();
    expect(screen.getByText('catalog')).toBeTruthy();
    // The analytic id on an observation opens the analytic.
    const link = screen.getByText('identity-4662-dcsync-nonmachine').closest('a');
    expect(link?.getAttribute('href')).toBe(
      '/hunts?tab=analytics&open=identity-4662-dcsync-nonmachine',
    );
  });

  // The meta line held both weights under one sentence, and that sentence
  // described the weight now. The number that never moves wore it too.
  it('gives each weight on the meta line its own sentence', async () => {
    mount();
    expect((await screen.findByText(/weight now 1\.28/)).getAttribute('title')).toBe(WEIGHT_NOW);
    expect(screen.getByText(/at formation 1\.30/).getAttribute('title')).toBe(WEIGHT_AT_FORMATION);
  });

  // An alert verdict writes the observation, and an alert has no analytic. The
  // row linked its `spec_id` anyway, so `/hunts?tab=analytics&open=alert`
  // opened a drawer titled "alert / alert" reading "Could not read the
  // analytic". A link goes to a page; where there is nothing to open, the id is
  // text.
  it('leaves an observation with no analytic as text', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...LEAD,
      observations: [{ ...LEAD.observations[0], spec_id: 'alert', analytic_exists: false }],
    } as never);
    mount();
    const id = await screen.findByText('alert');
    expect(id.closest('a')).toBeNull();
  });

  it('keeps the link when the server says nothing about the analytic', async () => {
    mount();
    const link = (await screen.findByText('identity-4662-dcsync-nonmachine')).closest('a');
    expect(link?.getAttribute('href')).toBe(
      '/hunts?tab=analytics&open=identity-4662-dcsync-nonmachine',
    );
  });

  // The three screens that render a kind held three copies of the map, so one
  // kind read "finding" here and "analytic matched" on the strip.
  it('reads every kind from the one table', async () => {
    mount();
    await waitFor(() =>
      expect(screen.getAllByText('finding with no benign baseline').length).toBeGreaterThan(0),
    );
    expect(screen.getAllByText('off hours').length).toBeGreaterThan(0);
  });

  it('prefers the labels the API sends', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...LEAD,
      kind_labels: ['directory replication', 'outside measured hours'],
    } as never);
    mount();
    await waitFor(() => expect(screen.getByText('directory replication')).toBeTruthy());
    expect(screen.getByText('outside measured hours')).toBeTruthy();
  });

  it('offers the three actions on a new lead', async () => {
    mount();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Hunt' })).toBeTruthy());
    expect(screen.getByRole('button', { name: 'Promote' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Dismiss' })).toBeTruthy();
  });

  // The page uses the words the strip uses. "Start a hunt" here and "Hunt"
  // there read as two different acts on one lead.
  it('states the four states under the actions', async () => {
    mount();
    const legend = await screen.findByTestId('lead-legend');
    expect(legend.textContent).toBe(LEAD_LEGEND);
  });
});

// The page named one hunt, from `hunt_id`. A lead hunted twice showed the
// first hunt forever, and "Hunt this lead" started a third from a page that
// said nothing about the other two.
describe('LeadDetail hunts on the lead', () => {
  it('lists every hunt on the lead with its status and a link', async () => {
    vi.mocked(getHunts).mockResolvedValue([
      HUNT_ON_LEAD as never,
      { ...HUNT_ON_LEAD, id: 'H-LEAD-2', status: 'running', outcome: '' } as never,
      { ...HUNT_ON_LEAD, id: 'H-OTHER', leadId: 99 } as never,
    ]);
    vi.mocked(getLead).mockResolvedValue({ ...LEAD, status: 'hunting', hunt_id: 'H-LEAD-1' } as never);
    mount();
    const panel = await screen.findByTestId('lead-hunts');
    expect(within(panel).getByRole('link', { name: /H-LEAD-1/ }).getAttribute('href')).toBe(
      '/hunts/H-LEAD-1',
    );
    expect(within(panel).getByRole('link', { name: /H-LEAD-2/ })).toBeTruthy();
    expect(within(panel).queryByText(/H-OTHER/)).toBeNull();
    expect(within(panel).getByText('Running')).toBeTruthy();
    // The status word states what it means. "complete" was the raw API word.
    // The sentence names the count this row carries, not the findings COLUMN:
    // this page has no columns, and the hunt list's sentence said it did.
    expect(within(panel).getByText('Complete').getAttribute('title')).toBe(STATUS_COMPLETE_ROW);
    expect(within(panel).getByText('Complete').getAttribute('title')).not.toBe(STATUS_COMPLETE);
  });

  // A hunt is running, so the one act left is to follow it. The page offered
  // "Open the hunt", which reads as a second way to start one.
  it('links to the running hunt and offers nothing else', async () => {
    vi.mocked(getHunts).mockResolvedValue([HUNT_ON_LEAD as never]);
    vi.mocked(getLead).mockResolvedValue({
      ...LEAD,
      status: 'hunting',
      hunt_id: 'H-LEAD-1',
      hunt_status: 'running',
    } as never);
    mount();
    const link = await screen.findByRole('link', { name: 'View hunt' });
    expect(link.getAttribute('href')).toBe('/hunts/H-LEAD-1');
    expect(screen.queryByRole('button', { name: 'Hunt' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Hunt again' })).toBeNull();
  });

  it('puts a second hunt behind a confirm that names the first', async () => {
    vi.mocked(getHunts).mockResolvedValue([HUNT_ON_LEAD as never]);
    vi.mocked(getLead).mockResolvedValue({
      ...LEAD,
      status: 'hunting',
      hunt_id: 'H-LEAD-1',
      hunt_status: 'complete',
    } as never);
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Hunt again' }));
    expect(screen.getByText(/A hunt on this lead already exists/)).toBeTruthy();
    expect(huntLead).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Start another hunt' }));
    await waitFor(() => expect(huntLead).toHaveBeenCalledWith(12));
  });
});

// A dismissal is a decision on the record. The page showed it only while the
// lead was still dismissed, so a reopened lead read as though nobody had ever
// looked at it.
describe('LeadDetail dismissal and reopen', () => {
  const DISMISSED = {
    ...LEAD,
    status: 'dismissed',
    dismissed_reason: 'expected_for_role',
    dismissed_note: 'the backup agent runs at 03:00',
    dismissed_by: 'alice',
    dismissed_at: '2026-09-18T12:00:00Z',
  };

  it('keeps the dismissal on the timeline after a reopen, and names the reopen', async () => {
    vi.mocked(getLead).mockResolvedValue({ ...DISMISSED, status: 'open' } as never);
    mount();
    const event = await screen.findByTestId('lead-dismissal');
    expect(event.textContent).toContain('by alice');
    expect(event.textContent).toContain('Expected for this role');
    expect(event.textContent).toContain('the backup agent runs at 03:00');
    expect(event.textContent).toContain('Reopened.');
  });

  it('does not claim a reopen while the lead is still dismissed', async () => {
    vi.mocked(getLead).mockResolvedValue(DISMISSED as never);
    mount();
    const event = await screen.findByTestId('lead-dismissal');
    expect(event.textContent).not.toContain('Reopened.');
  });

  it('offers only Reopen on a dismissed lead', async () => {
    vi.mocked(getLead).mockResolvedValue(DISMISSED as never);
    mount();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Reopen' })).toBeTruthy());
    expect(screen.queryByRole('button', { name: 'Hunt' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Promote' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Dismiss' })).toBeNull();
  });

  // A promoted lead became an investigation. The page stated the work it
  // turned into in the meta line, under every other number.
  it('offers Reopen and the investigation on a promoted lead', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...LEAD,
      status: 'promoted',
      investigation_id: 'INV-1',
    } as never);
    mount();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Reopen' })).toBeTruthy());
    expect(
      screen.getByRole('link', { name: 'Open investigation' }).getAttribute('href'),
    ).toBe('/investigation/INV-1');
    expect(screen.queryByRole('button', { name: 'Hunt' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Dismiss' })).toBeNull();
  });

  // The lead kept the id of an investigation the store no longer holds, so the
  // link promised a page and landed on "No such investigation".
  it('says the investigation is gone rather than link to a page that is not there', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...LEAD,
      status: 'promoted',
      investigation_id: 'INV-1',
      investigation_exists: false,
    } as never);
    mount();
    expect(await screen.findByText('The investigation no longer exists')).toBeTruthy();
    expect(screen.queryByRole('link', { name: 'Open investigation' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Reopen' })).toBeTruthy();
  });

  it('posts the reopen and reads the lead again', async () => {
    vi.mocked(getLead).mockResolvedValue(DISMISSED as never);
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Reopen' }));
    await waitFor(() => expect(reopenLead).toHaveBeenCalledWith(12));
    await waitFor(() => expect(vi.mocked(getLead).mock.calls.length).toBeGreaterThan(1));
  });
});

// "1 types · 1 entities named" is a header that cannot count to one, beside
// numbers an analyst is asked to trust.
describe('LeadDetail counting', () => {
  it('agrees with its own numbers at one', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...LEAD,
      kinds: ['off_hours'],
      observations: [LEAD.observations[1]],
    } as never);
    mount();
    await waitFor(() => expect(screen.getByText(/1 type ·/)).toBeTruthy());
    expect(screen.getByText(/1 entity named/)).toBeTruthy();
    expect(screen.getByText('Timeline · 1 observation')).toBeTruthy();
  });

  it('names the entities and the ones that carry observations', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...LEAD,
      entities: [['host', '10.1.2.3'], ['host', '10.1.2.9']],
      scope_count: 1,
    } as never);
    mount();
    await waitFor(() => expect(screen.getByText(/2 entities named/)).toBeTruthy());
    expect(screen.getByText(/1 with observations/)).toBeTruthy();
  });
});

// An evidence id was a dashed chip that did nothing, then a link into the
// investigations search, which answers a different question. The id is the
// proof the analytic matched the right thing, so it opens the document.
describe('LeadDetail evidence ids', () => {
  it('opens the document behind each id', async () => {
    mount();
    fireEvent.click(await screen.findByRole('button', { name: '7Kq2c1' }));
    await waitFor(() => expect(getEvent).toHaveBeenCalledWith('7Kq2c1'));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('winlog.event_id')).toBeTruthy();
  });

  it('says the grid holds no document with an id that aged out', async () => {
    vi.mocked(getEvent).mockRejectedValue(new ApiError('gone', 404, 'event_not_found'));
    mount();
    fireEvent.click(await screen.findByRole('button', { name: '7Kq2c1' }));
    await waitFor(() =>
      expect(
        screen.getByText('The grid holds no document with this id. It may have aged out.'),
      ).toBeTruthy(),
    );
  });
});

// The status word on this page must be the word the strip filters on. A lead
// read "open" here, "Open" on the filter chip and "open" on the link beside
// it, and the same word carried a state and an instruction.
describe('LeadDetail lead taxonomy', () => {
  it('reads a status of open as New', async () => {
    mount();
    const chip = await screen.findByTestId('lead-status');
    expect(chip.textContent).toBe('New');
  });

  it('reads a lead under a hunt as In progress', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...LEAD,
      status: 'hunting',
      hunt_id: 'H-LEAD-1',
      hunt_status: 'running',
    } as never);
    mount();
    const chip = await screen.findByTestId('lead-status');
    expect(chip.textContent).toBe('In progress');
  });

  it('reads a dismissed lead as Dismissed and names its reason', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...LEAD,
      status: 'dismissed',
      dismissed_reason: 'expected_for_role',
      dismissed_by: 'alice',
      dismissed_at: '2026-09-18T12:00:00Z',
    } as never);
    mount();
    const chip = await screen.findByTestId('lead-status');
    expect(chip.textContent).toBe('Dismissed');
    // One word for one chip. The strip reads "reason: …" and the page read
    // "Closed: …", so one dismissal read two ways on two screens.
    expect(screen.getByTestId('lead-closed-reason').textContent).toBe(
      'reason: Expected for this role',
    );
  });

  // One sentence for one button. The strip said "back in the queue" and the
  // page said "back in the new list", which is two names for one place.
  it('says the same thing on Reopen as the strip does', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...LEAD,
      status: 'dismissed',
      dismissed_reason: 'expected_for_role',
    } as never);
    mount();
    expect(
      (await screen.findByRole('button', { name: 'Reopen' })).getAttribute('title'),
    ).toBe(ACTION_REOPEN);
  });

  it('reads a promoted lead as Promoted', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...LEAD,
      status: 'promoted',
      investigation_id: 'INV-1',
    } as never);
    mount();
    const chip = await screen.findByTestId('lead-status');
    expect(chip.textContent).toBe('Promoted');
  });
});


// A lead whose hunt had finished still read "Hunting" on its own page, and a
// closed lead still stated a live weight that moves and decides nothing.
describe('LeadDetail hunted leads', () => {
  const HUNTED = {
    ...LEAD,
    status: 'hunting',
    hunt_id: 'H-LEAD-1',
    hunt_status: 'complete',
    hunt_outcome_label: 'No threat observed',
  };

  it('reads a finished hunt as Hunted and carries the outcome in the pill', async () => {
    vi.mocked(getLead).mockResolvedValue(HUNTED as never);
    mount();
    const chip = await screen.findByTestId('lead-status');
    expect(chip.textContent).toBe('Hunted · No threat observed');
  });

  it('reads a running hunt as In progress', async () => {
    vi.mocked(getLead).mockResolvedValue({ ...HUNTED, hunt_status: 'running' } as never);
    mount();
    const chip = await screen.findByTestId('lead-status');
    expect(chip.textContent).toBe('In progress');
  });

  // A finished hunt is a lead waiting on an analyst. The four acts are read
  // the hunt, promote it, dismiss it, or hunt it again.
  it('offers the four acts on a hunted lead', async () => {
    vi.mocked(getLead).mockResolvedValue(HUNTED as never);
    vi.mocked(getHunts).mockResolvedValue([HUNT_ON_LEAD] as never);
    mount();
    const link = await screen.findByRole('link', { name: 'Read hunt' });
    expect(link.getAttribute('href')).toBe('/hunts/H-LEAD-1');
    expect(screen.getByRole('button', { name: 'Promote' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Hunt again' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
    expect((screen.getByLabelText('Reason') as HTMLSelectElement).value).toBe('benign_repeat');
  });
});

describe('LeadDetail weight', () => {
  it('states the weight at formation on a closed lead and never a live weight', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...LEAD,
      status: 'promoted',
      investigation_id: 'INV-1',
    } as never);
    mount();
    await waitFor(() => expect(screen.getByText(/at formation 1\.30/)).toBeTruthy());
    expect(screen.queryByText(/weight now/)).toBeNull();
  });

  // The sentence sits on the weight it describes, not on the whole line: the
  // line also holds the formation weight, which never moves.
  it('says on the meta strip how the live weight moves', async () => {
    mount();
    await screen.findByTestId('lead-meta');
    expect(screen.getByText(/weight now 1\.28/).getAttribute('title')).toBe(
      'The live weight decays with a 48 h half-life. A new sighting adds weight.',
    );
  });
});

describe('LeadDetail wording', () => {
  it('says what a single-signal lead is and where the weight stops', async () => {
    vi.mocked(getLead).mockResolvedValue({ ...LEAD, single_signal: true } as never);
    mount();
    const chip = await screen.findByText('one signal, repeated');
    expect(chip.getAttribute('title')).toBe(CHIP_ONE_SIGNAL);
  });

  it('says on the shadow chip that no hunt starts from the lead', async () => {
    vi.mocked(getLead).mockResolvedValue({ ...LEAD, shadow: true } as never);
    mount();
    const chip = await screen.findByText('shadow');
    expect(chip.getAttribute('title')).toBe(
      'Recorded in shadow. No hunt starts from this lead by itself.',
    );
  });

  // The page and the Hunts strip read one sentence for one noun. An analyst
  // who lands here from a link never saw the strip's line.
  it('says what a lead is, under the title', async () => {
    mount();
    const line = await screen.findByTestId('define-lead');
    expect(line.textContent).toContain(DEFINE_LEAD);
  });
});
