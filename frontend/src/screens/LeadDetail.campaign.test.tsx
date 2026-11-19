// The page of a lead of a campaign (recommendation 3, 2026-11-16). The
// analyst decides on the campaign, so the page names the campaign and asks
// for no decision on the lead.
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../lib/api')>('../lib/api');
  return {
    ...actual,
    getLead: vi.fn(),
    getHunts: vi.fn(),
    getNeedsYou: vi.fn(),
    getEvent: vi.fn(),
    getHunt: vi.fn(),
  };
});

import { getHunts, getLead, getNeedsYou } from '../lib/api';
import { forbiddenWords } from '../test/analystWords';
import { LINK } from '../test/campaign';
import { ShellProvider } from '../shell/ShellContext';
import { LeadDetail } from './LeadDetail';

const LEAD = {
  id: 12,
  status: 'open',
  formed_at: '2026-10-24T01:14:00Z',
  updated_at: null,
  entities: [['host', '192.0.2.20']],
  kinds: ['alert'],
  weight_at_formation: 1,
  weight_now: 1,
  scope_count: 1,
  hunt_id: null,
  shadow: false,
  single_signal: false,
  dismissed_reason: null,
  dismissed_note: null,
  dismissed_by: null,
  dismissed_at: null,
  investigation_id: null,
  // A server with the campaign reasons in its list still offers the analyst none of them.
  dismiss_reasons: ['known_change', 'other', 'campaign_closed', 'campaign_authorized'],
  observations: [],
};

const TAGGED = { ...LEAD, campaign: LINK, hunt_queued: true };

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
  vi.mocked(getLead).mockReset().mockResolvedValue(TAGGED as never);
  vi.mocked(getHunts).mockReset().mockResolvedValue([]);
  vi.mocked(getNeedsYou)
    .mockReset()
    .mockResolvedValue({ unread_shadow_hits: 0, leads_needing_decision: 0, total: 0, lead_auto_hunt: true });
});

describe('the page of a lead of a campaign', () => {
  it('names the campaign in the header and in the state line', async () => {
    mount();
    const sentence = await screen.findByTestId('lead-state-sentence');
    expect(sentence.textContent).toMatch(/Part of the campaign actor-a against web-1\. Decide on the campaign\.$/);
    expect(screen.getByTestId('lead-campaign-chip')).toHaveAttribute('href', '/campaigns/7');
  });

  it('reads no "hunt queued", no "waits on" and no "left to you"', async () => {
    mount();
    await screen.findByTestId('lead-state-sentence');
    expect(screen.getByTestId('lead-status').textContent).toBe('New');
    expect(screen.queryByTestId('lead-left-to-you')).toBeNull();
    // The header row, the state line and the notes of the actions. The legend of
    // the page below defines every state, and it is no word about this lead.
    const header = document.querySelector('[data-tour="lead-header"]') as HTMLElement;
    const parts = [header, screen.getByTestId('lead-state-sentence'), screen.getByTestId('lead-action-notes')];
    for (const part of parts) expect(part.textContent).not.toMatch(/hunt queued|waits on|left to you/i);
    // The flow names the hunts of the campaign, and offers no hunt as the next step.
    const step = screen.getByTestId('flow-step-hunt');
    expect(step).toHaveAttribute('data-state', 'not_yet');
    expect(step).toHaveTextContent('campaign');
    expect(within(step).queryByTestId('flow-control-hunt')).toBeNull();
    // The hunt stays on offer as a secondary act.
    expect(screen.getByRole('button', { name: 'Hunt this lead' }).className).not.toContain('bg-accent');
    expect(parts.flatMap(forbiddenWords)).toEqual([]);
  });

  it('offers no campaign reason in the dismiss form', async () => {
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Dismiss' }));
    const options = screen.getAllByRole('option').map((o) => o.getAttribute('value'));
    expect(options).toEqual(['', 'known_change', 'other']);
  });

  it('states the close of a lead that closed with its campaign', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...TAGGED,
      status: 'dismissed',
      hunt_queued: false,
      dismissed_reason: 'campaign_authorized',
      dismissed_by: 'system:campaign',
      dismissed_at: '2026-11-14T21:00:00Z',
    } as never);
    mount();
    const sentence = await screen.findByTestId('lead-state-sentence');
    expect(sentence.textContent).toMatch(/soc-ai closed the lead: an admin authorized the campaign\. It waits on nothing\.$/);
    expect(screen.getByTestId('lead-closed-reason')).toHaveTextContent('reason: An admin authorized the campaign');
  });

  it('NEGATIVE CONTROL: a lead of no campaign keeps its decision and its queued hunt', async () => {
    vi.mocked(getLead).mockResolvedValue({ ...LEAD, hunt_queued: true } as never);
    mount();
    const sentence = await screen.findByTestId('lead-state-sentence');
    expect(sentence.textContent).toMatch(/The lead waits on auto-hunt\. Its hunt starts within a minute\.$/);
    expect(screen.queryByTestId('lead-campaign-chip')).toBeNull();
    expect(screen.getByTestId('flow-step-hunt')).toHaveTextContent('queued');
  });
});

// Round 3 part 2 (W4). Lead 73 read "Its campaign is closed" and "reason: An
// analyst closed the campaign" beside the chip "Campaign 2 · Open". The words
// follow the state of the campaign at read time, and the lead stays closed.
describe('LeadDetail of a lead that closed with a campaign that opened again', () => {
  const CLOSED = {
    ...LEAD,
    status: 'dismissed',
    dismissed_reason: 'campaign_closed',
    dismissed_by: 'campaign',
    dismissed_at: '2026-11-17T14:29:00Z',
    campaign: { ...LINK, decision: null, state: 'open' },
    campaign_context: {
      id: 2,
      title: 'actor-a against web-1',
      decision: null,
      decided_at: null,
      decided_by: null,
      closed_with_campaign: true,
      closed_at: '2026-11-17T14:29:00Z',
      closed_by_decision: 'closed',
      closed_by: 'admin',
      reopened_at: '2026-11-18T13:02:28Z',
    },
  };

  it('states the close of the lead and the reopen of the campaign', async () => {
    vi.mocked(getLead).mockResolvedValue(CLOSED as never);
    mount();
    const line = await screen.findByTestId('lead-context-closed-with');
    expect(line).toHaveTextContent(
      'soc-ai closed this lead on 2026-11-17 14:29 UTC, when admin closed its campaign. The campaign opened again on 2026-11-18 13:02 UTC.',
    );
    expect(screen.getByTestId('lead-closed-reason')).toHaveTextContent(
      'reason: An analyst closed the campaign. The campaign opened again',
    );
    expect(screen.getByTestId('lead-state-sentence')).toHaveTextContent('The lead stays closed.');
    expect(screen.getByTestId('lead-context')).not.toHaveTextContent('Its campaign is closed');
    expect(forbiddenWords(screen.getByTestId('lead-context'))).toEqual([]);
  });

  it('control: a campaign that stays closed keeps the words of the close', async () => {
    vi.mocked(getLead).mockResolvedValue({
      ...CLOSED,
      campaign: { ...LINK, decision: 'closed', state: 'closed' },
      campaign_context: { ...CLOSED.campaign_context, decision: 'closed', decided_by: 'admin', reopened_at: null },
    } as never);
    mount();
    const line = await screen.findByTestId('lead-context-closed-with');
    expect(line).toHaveTextContent('soc-ai closed this lead on 2026-11-17 14:29 UTC, when admin closed its campaign.');
    expect(line).not.toHaveTextContent('opened again');
    expect(screen.getByTestId('lead-closed-reason')).toHaveTextContent(/^reason: An analyst closed the campaign$/);
  });
});
