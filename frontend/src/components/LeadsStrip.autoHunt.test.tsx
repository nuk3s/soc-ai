// A lead starts its own hunt, and leads relate (design, 2026-09-22).
//
// The strip carried one story: a lead forms and waits for an analyst to hunt
// it. With auto-hunt on, a New lead waits on a loop that starts within a
// minute, and the analyst has nothing to do until the hunt finishes. A New
// pill over that lead is the false "this needs you" the Needs-you strip exists
// to prevent, so the pill, the actions, the legend and the note all change.
//
// The strip also names the leads that relate to the one on the row, because a
// coordinated attack across entities is several leads and no single one of
// them reads as a campaign.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getLeads: vi.fn(),
  getNeedsYou: vi.fn(),
  dismissLead: vi.fn(),
  huntLead: vi.fn(),
  promoteLead: vi.fn(),
  reopenLead: vi.fn(),
}));

import {
  getLeads,
  getNeedsYou,
  huntLead,
  promoteLead,
  type Lead,
  type NeedsYou,
} from '../lib/api';
import {
  ACTION_HUNT,
  CHIP_LEFT_TO_YOU,
  CHIP_RELATED,
  LEADS_NOTE_AUTO_HUNT,
  LEGEND_AUTO_HUNT,
  PILL_HUNT_QUEUED,
  PILL_NEW,
} from '../lib/tooltips';
import { LEAD_ACTION, LeadsStrip } from './LeadsStrip';

const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const LEAD: Lead = {
  id: 7,
  status: 'open',
  formed_at: iso(HOUR),
  updated_at: iso(HOUR),
  entities: [['host', '10.1.10.21']],
  kinds: ['catalog_match', 'off_hours'],
  weight_at_formation: 0.91,
  scope_count: 1,
  hunt_id: null,
  shadow: false,
  single_signal: false,
  observations: [],
};

const QUEUED: Lead = { ...LEAD, hunt_queued: true };

/** A lead whose hunt has finished. Promote is the act it offers. */
const HUNTED: Lead = {
  ...LEAD,
  status: 'hunting',
  hunt_id: 'H-DONE',
  hunt_status: 'complete',
  hunt_outcome_label: 'Threat findings',
};

/** The counts the strip reads the setting from. A server that sends no
 *  setting leaves the strip to read the queue, which is what it always did. */
const NEEDS_YOU: NeedsYou = {
  unread_shadow_hits: 0,
  leads_needing_decision: 1,
  total: 1,
};

const mount = () =>
  render(
    <MemoryRouter>
      <LeadsStrip />
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getLeads).mockReset().mockResolvedValue([QUEUED]);
  vi.mocked(getNeedsYou).mockReset().mockResolvedValue(NEEDS_YOU);
  vi.mocked(huntLead).mockReset().mockResolvedValue({ hunt_id: 'H-NEW' });
  vi.mocked(promoteLead).mockReset().mockResolvedValue({ investigation_id: 'INV-9' });
});

describe('a queued hunt on a new lead', () => {
  it('reads New · hunt queued and states that nothing waits on the analyst', async () => {
    mount();
    const row = await screen.findByTestId('lead-7');
    const pill = within(row).getByTestId('lead-status');
    expect(pill.textContent).toBe('New · hunt queued');
    expect(pill.getAttribute('title')).toBe(PILL_HUNT_QUEUED);
  });

  it('keeps the New pill and its own sentence when no hunt is queued', async () => {
    vi.mocked(getLeads).mockResolvedValue([LEAD]);
    mount();
    const row = await screen.findByTestId('lead-7');
    const pill = within(row).getByTestId('lead-status');
    expect(pill.textContent).toBe('New');
    expect(pill.getAttribute('title')).toBe(PILL_NEW);
  });

  // The act left to an analyst is to close the lead. Hunt is still there for
  // the case where the loop is behind, and it says so: "Hunt now" is a
  // different act from "Hunt this lead". The hunt investigates what it finds,
  // so the row offers no investigation of its own (owner, 2026-10-07).
  it('offers Dismiss, with Hunt now as the secondary act', async () => {
    mount();
    const row = await screen.findByTestId('lead-7');
    expect(within(row).getByRole('button', { name: LEAD_ACTION.dismiss })).toBeTruthy();
    expect(within(row).getByRole('button', { name: LEAD_ACTION.huntNow })).toBeTruthy();
    expect(within(row).queryByRole('button', { name: LEAD_ACTION.hunt })).toBeNull();
    expect(within(row).queryByRole('button', { name: /Open an investigation|Promote/ })).toBeNull();
  });

  it('starts the hunt from Hunt now rather than waiting for the loop', async () => {
    mount();
    const row = await screen.findByTestId('lead-7');
    fireEvent.click(within(row).getByRole('button', { name: LEAD_ACTION.huntNow }));
    await waitFor(() => expect(huntLead).toHaveBeenCalledWith(7));
  });

  // The legend is a taxonomy, and the taxonomy changes with the setting. With
  // auto-hunt off, New means "hunt it". With it on, New means "it is being
  // hunted".
  it('adds one sentence to the legend while a lead is queued', async () => {
    mount();
    const legend = await screen.findByTestId('leads-legend');
    expect(legend.textContent).toContain(LEGEND_AUTO_HUNT);
  });

  it('leaves the legend alone when no lead is queued', async () => {
    vi.mocked(getLeads).mockResolvedValue([LEAD]);
    mount();
    const legend = await screen.findByTestId('leads-legend');
    expect(legend.textContent).not.toContain(LEGEND_AUTO_HUNT);
  });

  // The standing note says soc-ai starts no hunt from a lead by itself. With
  // the loop running that is the opposite of the truth.
  it('replaces the note that says soc-ai starts no hunt', async () => {
    mount();
    const note = await screen.findByTestId('leads-note');
    expect(note.textContent).toBe(LEADS_NOTE_AUTO_HUNT);
  });

  it('keeps the standing note when no lead is queued', async () => {
    vi.mocked(getLeads).mockResolvedValue([LEAD]);
    mount();
    const note = await screen.findByTestId('leads-note');
    expect(note.textContent).toBe(
      'soc-ai records leads. It does not start a hunt from a lead by itself.',
    );
  });
});

// The loop takes every new lead but three: a shadow lead, a reopened lead and
// a lead with no documents. Such a lead reads New under a note that says its
// hunt is coming, and the hunt never comes.
describe('a lead the loop leaves to the analyst', () => {
  it('names it beside the pill while the setting is on', async () => {
    vi.mocked(getNeedsYou).mockResolvedValue({ ...NEEDS_YOU, lead_auto_hunt: true });
    vi.mocked(getLeads).mockResolvedValue([{ ...LEAD, hunt_queued: false }]);
    mount();
    const row = await screen.findByTestId('lead-7');
    const chip = await within(row).findByTestId('lead-left-to-you-7');
    expect(chip.textContent).toBe('left to you');
    expect(chip.getAttribute('title')).toBe(CHIP_LEFT_TO_YOU);
  });

  it('names nothing on a lead whose hunt the loop has taken', async () => {
    vi.mocked(getNeedsYou).mockResolvedValue({ ...NEEDS_YOU, lead_auto_hunt: true });
    mount();
    const row = await screen.findByTestId('lead-7');
    expect(within(row).queryByTestId('lead-left-to-you-7')).toBeNull();
  });

  // With the setting off the loop leaves every lead, so the chip says nothing
  // one lead does not share with all of them.
  it('names nothing while the setting is off', async () => {
    vi.mocked(getNeedsYou).mockResolvedValue({ ...NEEDS_YOU, lead_auto_hunt: false });
    vi.mocked(getLeads).mockResolvedValue([{ ...LEAD, hunt_queued: false }]);
    mount();
    const row = await screen.findByTestId('lead-7');
    expect(within(row).queryByTestId('lead-left-to-you-7')).toBeNull();
  });
});

// A lead offers no "Open an investigation" (owner, 2026-10-07). The hunt
// investigates what it finds and brings back the verdicts. The one manual
// control of that name sits on a finding with no investigation, on the hunt
// page. "Promote" beside "Hunt" read as two words for one act.
describe('a lead row offers no investigation of its own', () => {
  it('names the hunt "Hunt this lead" and says what a hunt returns', async () => {
    vi.mocked(getLeads).mockResolvedValue([LEAD]);
    mount();
    const row = await screen.findByTestId('lead-7');
    const hunt = within(row).getByRole('button', { name: 'Hunt this lead' });
    expect(hunt.getAttribute('title')).toBe(ACTION_HUNT);
    expect(within(row).queryByRole('button', { name: /Open an investigation|Promote/ })).toBeNull();
  });

  it('offers none on a hunted lead, and starts none', async () => {
    vi.mocked(getLeads).mockResolvedValue([HUNTED]);
    mount();
    const row = await screen.findByTestId('lead-7');
    expect(within(row).getByRole('link', { name: LEAD_ACTION.readHunt })).toBeTruthy();
    expect(within(row).getByRole('button', { name: LEAD_ACTION.dismiss })).toBeTruthy();
    expect(within(row).queryByRole('button', { name: /Open an investigation|Promote/ })).toBeNull();
    expect(promoteLead).not.toHaveBeenCalled();
  });
});

describe('the related leads chip', () => {
  it('counts them and links to the lead page that lists them', async () => {
    vi.mocked(getLeads).mockResolvedValue([{ ...LEAD, related_count: 2 }]);
    mount();
    const row = await screen.findByTestId('lead-7');
    const chip = within(row).getByTestId('lead-related-7');
    expect(chip.textContent).toBe('+2 related');
    expect(chip.getAttribute('href')).toBe('/leads/7');
    expect(chip.getAttribute('title')).toBe(CHIP_RELATED);
  });

  it('carries no chip when nothing relates to the lead', async () => {
    vi.mocked(getLeads).mockResolvedValue([{ ...LEAD, related_count: 0 }]);
    mount();
    const row = await screen.findByTestId('lead-7');
    expect(within(row).queryByTestId('lead-related-7')).toBeNull();
  });
});
