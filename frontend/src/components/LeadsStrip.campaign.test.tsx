// A lead of a campaign folds into the campaign (recommendation 3, 2026-11-16).
//
// Each observation of such a lead is an alert of an investigation that the
// campaign holds. The analyst decides on the campaign, so the row reads as
// handled by the campaign: the chip, one sentence, a neutral pill, no "hunt
// queued" and no "left to you".
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getLeads: vi.fn(),
  getNeedsYou: vi.fn(),
}));

import { getLeads, getNeedsYou, type Lead } from '../lib/api';
import { LEAD_OF_CAMPAIGN_TITLE } from '../lib/campaignWords';
import { PILL_HUNT_QUEUED } from '../lib/tooltips';
import { forbiddenWords } from '../test/analystWords';
import { LINK } from '../test/campaign';
import { DismissLeadForm, LEAD_ACTION, LeadsStrip, dismissReasonLabel } from './LeadsStrip';

const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const LEAD: Lead = {
  id: 7,
  status: 'open',
  formed_at: iso(3_600_000),
  updated_at: iso(3_600_000),
  entities: [['host', '192.0.2.20']],
  kinds: ['alert'],
  weight_at_formation: 0.91,
  scope_count: 1,
  hunt_id: null,
  shadow: false,
  single_signal: false,
  observations: [],
};

/** A lead of the campaign. An older lead loop could still mark it queued. */
const TAGGED: Lead = { ...LEAD, campaign: LINK, hunt_queued: true };

const mount = () =>
  render(
    <MemoryRouter>
      <LeadsStrip />
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getLeads).mockReset().mockResolvedValue([TAGGED]);
  vi.mocked(getNeedsYou)
    .mockReset()
    .mockResolvedValue({ unread_shadow_hits: 0, leads_needing_decision: 0, total: 0, lead_auto_hunt: true });
});

describe('a lead of a campaign on the leads strip', () => {
  it('wears the campaign chip and the sentence that sends the analyst to the campaign', async () => {
    mount();
    const row = await screen.findByTestId('lead-7');
    const chip = within(row).getByTestId('lead-campaign-chip-7');
    expect(chip).toHaveAttribute('href', '/campaigns/7');
    expect(within(row).getByTestId('lead-campaign-7')).toHaveTextContent(
      'Part of the campaign actor-a against web-1. Decide on the campaign.',
    );
  });

  it('reads no "hunt queued" and no "left to you", and its pill wears no color of work', async () => {
    mount();
    const row = await screen.findByTestId('lead-7');
    const pill = within(row).getByTestId('lead-status');
    expect(pill.textContent).toBe('New');
    expect(pill).toHaveAttribute('data-campaign', 'true');
    expect(pill.getAttribute('title')).toBe(LEAD_OF_CAMPAIGN_TITLE);
    expect(pill.style.color).not.toBe('rgb(75, 139, 245)');
    expect(within(row).queryByTestId('lead-left-to-you-7')).toBeNull();
    expect(row.textContent).not.toMatch(/hunt queued|left to you|waits on/i);
    // The hunt stays on offer, and it is no primary act: the decision is on the campaign.
    const hunt = within(row).getByRole('button', { name: LEAD_ACTION.hunt });
    expect(hunt.className).not.toContain('bg-accent');
    expect(forbiddenWords(row)).toEqual([]);
  });

  it('keeps no "left to you" off a lead of the campaign that the loop does not take', async () => {
    vi.mocked(getLeads).mockResolvedValue([{ ...TAGGED, hunt_queued: false }, { ...LEAD, id: 8, hunt_queued: true }]);
    mount();
    const row = await screen.findByTestId('lead-7');
    expect(within(row).queryByTestId('lead-left-to-you-7')).toBeNull();
  });

  it('NEGATIVE CONTROL: a lead of no campaign keeps "hunt queued" and its blue pill', async () => {
    vi.mocked(getLeads).mockResolvedValue([{ ...LEAD, hunt_queued: true }]);
    mount();
    const row = await screen.findByTestId('lead-7');
    const pill = within(row).getByTestId('lead-status');
    expect(pill.textContent).toBe('New · hunt queued');
    expect(pill.getAttribute('title')).toBe(PILL_HUNT_QUEUED);
    expect(within(row).queryByTestId('lead-campaign-chip-7')).toBeNull();
    expect(within(row).queryByTestId('lead-campaign-7')).toBeNull();
  });

  it('states the reason of a lead that closed with its campaign, and asks for no decision', async () => {
    vi.mocked(getLeads).mockResolvedValue([
      { ...TAGGED, status: 'dismissed', hunt_queued: false, dismissed_reason: 'campaign_closed' },
    ]);
    mount();
    const row = await screen.findByTestId('lead-7');
    expect(row).toHaveTextContent('reason: An analyst closed the campaign');
    expect(within(row).getByTestId('lead-campaign-chip-7')).toBeInTheDocument();
    expect(within(row).queryByTestId('lead-campaign-7')).toBeNull();
  });
});

describe('the reasons a campaign writes', () => {
  it('name the campaign decision', () => {
    expect(dismissReasonLabel('campaign_closed')).toBe('An analyst closed the campaign');
    expect(dismissReasonLabel('campaign_authorized')).toBe('An admin authorized the campaign');
    expect(dismissReasonLabel('known_change')).toBe('A known change');
  });

  it('are no reason of the dismiss form', () => {
    render(
      <MemoryRouter>
        <DismissLeadForm
          leadId={7}
          reasons={['known_change', 'campaign_closed', 'campaign_authorized']}
          onDone={() => {}}
        />
      </MemoryRouter>,
    );
    const options = screen.getAllByRole('option').map((o) => o.getAttribute('value'));
    expect(options).toEqual(['', 'known_change']);
  });
});

describe('leadsOutsideTabs with the leads of a campaign', () => {
  it('takes the leads of a campaign out of the leads that wait on a hunt', async () => {
    const { leadsOutsideTabs } = await import('./LeadsStrip');
    const counts = { all: 10, needs_decision: 2, in_progress: 1, closed: 3, fleet_condition: 1 };
    expect(leadsOutsideTabs(counts as never)).toBe(3);
    expect(leadsOutsideTabs(counts as never, 2)).toBe(1);
    // Never under 0: the counts are separate reads.
    expect(leadsOutsideTabs(counts as never, 9)).toBe(0);
  });

  it('states the leads of a campaign in words with no banned word', async () => {
    const { leadsOfCampaignNote } = await import('../lib/tooltips');
    expect(leadsOfCampaignNote(1)).toBe('1 lead waits on its campaign. The All tab lists it.');
    expect(leadsOfCampaignNote(4)).toBe('4 leads wait on their campaign. The All tab lists them.');
  });
});
