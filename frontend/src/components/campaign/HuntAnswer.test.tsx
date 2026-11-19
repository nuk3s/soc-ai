// The answer of a hunt that read a campaign or a lead (LH2, LH3, 2026-11-17).
// The scheduled hunt of 2026-11-16 read campaign 2 and lead 73 and found no
// new event. Neither page showed it.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import type { CampaignHunt, CampaignHuntAnswer } from '../../lib/api';
import {
  authorizedPartSentence,
  closedWithCampaignSentence,
  huntAnswerMarkLabel,
  huntAnswerSentence,
  huntAnswerWord,
  huntAnswerWords,
  leadCampaignDecisionSentence,
} from '../../lib/campaignWords';
import { CAMPAIGN, EVENTS } from '../../test/campaign';
import { forbiddenWords } from '../../test/analystWords';
import { LeadCampaignContext, LeadOtherHunts } from '../LeadCampaignContext';
import { CampaignLeadsHunts } from './CampaignLeadsHunts';
import { CampaignTimeline } from './CampaignTimeline';
import { HuntAnswerLine } from './HuntAnswerLine';

const CLEAN: CampaignHuntAnswer = {
  huntId: '01HUNTREAD',
  huntAt: '2026-10-28T22:41:15Z',
  starter: 'schedule',
  outcome: 'no_new_event',
  findingOrdinal: null,
  findingTitle: null,
};
const NEW: CampaignHuntAnswer = {
  ...CLEAN,
  huntId: '01HUNTNEW',
  outcome: 'new_activity',
  findingOrdinal: 1,
  findingTitle: 'Web shell command on web-1.',
};

describe('the sentence of an answer', () => {
  it('states each outcome for a campaign and for a lead', () => {
    // SD4: the answer states its baseline, so it reads as no contradiction
    // beside a campaign that opened again for new activity.
    expect(huntAnswerSentence('campaign', CLEAN)).toBe(
      'The hunt of 2026-10-28 22:41 UTC read this campaign. It found no activity that the campaign does not hold.',
    );
    expect(huntAnswerSentence('campaign', { ...CLEAN, outcome: 'continues' })).toBe(
      'The hunt of 2026-10-28 22:41 UTC read this campaign and found the known activity of this campaign again.',
    );
    expect(huntAnswerSentence('campaign', NEW)).toBe(
      'The hunt of 2026-10-28 22:41 UTC read this campaign and found new activity: Web shell command on web-1.',
    );
    expect(huntAnswerSentence('lead', CLEAN)).toBe(
      'The hunt of 2026-10-28 22:41 UTC read this lead. It found no activity on its machines that the lead does not hold.',
    );
    expect(huntAnswerSentence('lead', NEW)).toBe(
      'The hunt of 2026-10-28 22:41 UTC read this lead and found a threat on a machine of this lead: Web shell command on web-1.',
    );
  });

  it('gives the sentence, the word and the mark from one function, and no surface reads "no new event"', () => {
    const clean = huntAnswerWords('campaign', CLEAN);
    expect(clean.word).toBe('Found no activity that the campaign does not hold');
    expect(clean.mark).toBe('Hunt: no activity that the campaign does not hold');
    expect(huntAnswerWord('lead', 'no_new_event')).toBe('Found no activity that the lead does not hold');
    expect(huntAnswerMarkLabel('no_new_event')).toBe(clean.mark);
    for (const subject of ['campaign', 'lead'] as const) {
      for (const outcome of ['new_activity', 'continues', 'no_new_event']) {
        const words = huntAnswerWords(subject, { ...CLEAN, outcome });
        expect(`${words.sentence} ${words.word} ${words.mark}`).not.toMatch(/no new event/i);
      }
    }
    // NEGATIVE CONTROL: the words of new activity and of known activity stay.
    expect(huntAnswerWord('campaign', 'new_activity')).toBe('Found new activity');
    expect(huntAnswerWord('campaign', 'continues')).toBe('Found the known activity again');
    expect(huntAnswerMarkLabel('new_activity')).toBe('Hunt: new activity');
  });

  it('states the decision of the campaign of a lead', () => {
    const at = '2026-10-29T01:01:12Z';
    expect(leadCampaignDecisionSentence({ decision: 'closed', decided_at: at })).toBe(
      'The analyst closed the campaign on 2026-10-29 01:01 UTC.',
    );
    expect(leadCampaignDecisionSentence({ decision: null, decided_at: null })).toBe(
      'The campaign waits for a decision of the analyst.',
    );
    // N4: the lead closes when it joins the decided campaign, days after the
    // decision. The line states the time of the close of the lead.
    expect(closedWithCampaignSentence({ decision: 'authorized', closed_at: '2026-11-17T09:30:00Z', closed_by: 'admin' })).toBe(
      'soc-ai closed this lead on 2026-11-17 09:30 UTC, when admin authorized the activity of its campaign.',
    );
    expect(closedWithCampaignSentence({ decision: 'closed', closed_at: '2026-11-17T09:30:00Z', closed_by: 'admin' })).toBe(
      'soc-ai closed this lead on 2026-11-17 09:30 UTC, when admin closed its campaign.',
    );
    // W4: the words follow the state of the campaign at read time. The
    // campaign holds no decision after the reopen, so the decision that
    // closed the lead comes from the server.
    expect(
      closedWithCampaignSentence({
        decision: null,
        closed_at: '2026-11-17T14:29:00Z',
        closed_by_decision: 'closed',
        closed_by: 'admin',
        reopened_at: '2026-11-18T13:02:28Z',
      }),
    ).toBe(
      'soc-ai closed this lead on 2026-11-17 14:29 UTC, when admin closed its campaign. The campaign opened again on 2026-11-18 13:02 UTC.',
    );
    // Negative control: an older server sends no time and no name, and the line claims none.
    expect(closedWithCampaignSentence({ decision: 'closed', closed_at: null })).toBe(
      'soc-ai closed this lead, when the analyst closed its campaign.',
    );
    expect(authorizedPartSentence({ label: 'The test of the lab', observations: 3 })).toBe(
      '3 observations of this lead are authorized activity: The test of the lab.',
    );
  });
});

describe('the answer on the campaign page', () => {
  it('reads one line with a mark and a link to the hunt', () => {
    render(
      <MemoryRouter>
        <HuntAnswerLine subject="campaign" answer={NEW} testId="answer" />
      </MemoryRouter>,
    );
    const line = screen.getByTestId('answer');
    expect(line).toHaveAttribute('data-outcome', 'new_activity');
    expect(within(line).getByRole('link', { name: 'Open the hunt' })).toHaveAttribute('href', '/hunts/01HUNTNEW');
    expect(forbiddenWords(line)).toEqual([]);
  });

  it('renders nothing with no answer', () => {
    const { container } = render(
      <MemoryRouter>
        <HuntAnswerLine subject="campaign" answer={null} testId="answer" />
      </MemoryRouter>,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('marks the newest answer on the timeline', () => {
    render(
      <CampaignTimeline
        events={EVENTS}
        members={CAMPAIGN.members}
        parties={CAMPAIGN.parties}
        ladder={CAMPAIGN.ladder}
        changes={[]}
        selection={null}
        onSelect={() => {}}
        answer={CLEAN}
      />,
    );
    const mark = screen.getAllByTestId('timeline-decision').find((m) => m.getAttribute('data-type') === 'hunt_answer');
    expect(mark).toBeDefined();
    expect(mark?.getAttribute('aria-label')).toBe(huntAnswerSentence('campaign', CLEAN));
  });

  it('lists the hunt that read the campaign with its answer in the fold', () => {
    const hunt: CampaignHunt = {
      id: '01HUNTREAD',
      starter: 'schedule',
      status: 'complete',
      startedAt: CLEAN.huntAt,
      findings: 9,
      threatFindings: 0,
      answer: 'no_new_event',
    };
    render(
      <MemoryRouter>
        <CampaignLeadsHunts
          leads={[]}
          hunts={[hunt]}
          changes={[]}
          firstEvent={CAMPAIGN.firstEvent}
          lastEvent={CAMPAIGN.lastEvent}
        />
      </MemoryRouter>,
    );
    expect(screen.getByTestId('campaign-hunt-answer-01HUNTREAD')).toHaveTextContent(
      'Found no activity that the campaign does not hold',
    );
  });
});

describe('the campaign and the answers on the lead page', () => {
  it('names the campaign, its decision, the close and the authorized observations', () => {
    render(
      <MemoryRouter>
        <LeadCampaignContext
          lead={{
            campaign_context: {
              id: 2,
              title: 'actor-a against web-1',
              decision: 'closed',
              decided_at: '2026-10-29T01:01:12Z',
              decided_by: 'admin',
              closed_with_campaign: true,
              closed_at: '2026-11-17T09:30:00Z',
              closed_by_decision: 'closed',
              closed_by: 'admin',
            },
            authorized: [{ label: 'The test of the lab', observations: 2 }],
            answers: [
              {
                hunt_id: '01HUNTREAD',
                hunt_at: CLEAN.huntAt,
                starter: 'schedule',
                outcome: 'no_new_event',
                finding_ordinal: null,
                finding_title: null,
              },
            ],
          }}
        />
      </MemoryRouter>,
    );
    const campaign = screen.getByTestId('lead-context-campaign');
    expect(campaign).toHaveTextContent(
      'This lead is part of campaign 2: actor-a against web-1. The analyst closed the campaign on 2026-10-29 01:01 UTC. soc-ai closed this lead on 2026-11-17 09:30 UTC, when admin closed its campaign.',
    );
    expect(within(campaign).getByRole('link', { name: 'actor-a against web-1' })).toHaveAttribute(
      'href',
      '/campaigns/2',
    );
    expect(screen.getByTestId('lead-context-authorized')).toHaveTextContent(
      '2 observations of this lead are authorized activity: The test of the lab.',
    );
    expect(screen.getByTestId('lead-hunt-answer')).toHaveTextContent(
      'The hunt of 2026-10-28 22:41 UTC read this lead. It found no activity on its machines that the lead does not hold.',
    );
    expect(forbiddenWords(screen.getByTestId('lead-context'))).toEqual([]);
  });

  it('states nothing for a lead with no campaign, no authorization and no answer', () => {
    const { container } = render(
      <MemoryRouter>
        <LeadCampaignContext lead={{ campaign_context: null, authorized: [], answers: [] }} />
      </MemoryRouter>,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('lists the other hunts that read the lead', () => {
    render(
      <MemoryRouter>
        <LeadOtherHunts
          answers={[
            {
              hunt_id: '01HUNTNEW',
              hunt_at: NEW.huntAt,
              starter: 'schedule',
              outcome: 'new_activity',
              finding_ordinal: 1,
              finding_title: 'Web shell command on web-1',
            },
          ]}
        />
      </MemoryRouter>,
    );
    const row = screen.getByTestId('lead-other-hunt-01HUNTNEW');
    expect(row).toHaveTextContent('Found new activity');
    expect(row).toHaveTextContent('Web shell command on web-1');
    expect(within(row).getByRole('link', { name: 'Scheduled hunt' })).toHaveAttribute('href', '/hunts/01HUNTNEW');
  });
});
