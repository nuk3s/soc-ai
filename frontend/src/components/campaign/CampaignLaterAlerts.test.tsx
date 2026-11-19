// The later alerts of a campaign (round 3, part 2). Production, 2026-11-19:
// campaign 2 stated its span to the last event of its investigations. The
// grid held 20 more alerts of 2 rules of the campaign between the same
// machines, the last at 15:08 UTC. Those alerts take the verdict of an
// earlier investigation and get no investigation of their own. Each surface
// now states the span to the later of the two times.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import type { CampaignDetail, CampaignHuntAnswer, CampaignSinceDecision } from '../../lib/api';
import {
  alertCounts,
  alertsFoldDetail,
  campaignLaterSentence,
  campaignSpan,
  eventsFacts,
  heldInvestigations,
  lastActivityOf,
  sinceLaterSentence,
} from '../../lib/campaignWords';
import {
  ACTOR,
  CAMPAIGN_WAITS,
  EVENTS,
  HOST_CAMPAIGNS,
  MEMBERS,
  PAIR,
  TARGET,
  THREAT_CAMPAIGN,
  pair,
} from '../../test/campaign';
import { ThreatCampaignRow } from '../ConfirmedThreats';
import { CampaignView } from './CampaignView';
import { HostCampaigns } from './HostCampaigns';

const LATER = '2026-10-29T15:08:41Z';
const RULE_ROW = PAIR.rules[0];
const view = (ui: React.ReactElement) => render(<MemoryRouter>{ui}</MemoryRouter>);

describe('the span of a campaign', () => {
  it('ends at the last activity', () => {
    const c = { firstEvent: '2026-10-24T01:11:00Z', lastEvent: '2026-10-28T13:12:00Z', lastActivity: LATER };
    expect(lastActivityOf(c)).toBe(LATER);
    expect(campaignSpan(c)).toBe('2026-10-24 01:11 to 2026-10-29 15:08 UTC');
  });

  it('ends at the last investigation event for an earlier server', () => {
    // NEGATIVE CONTROL: no lastActivity, the span of today.
    const c = { firstEvent: '2026-10-24T01:11:00Z', lastEvent: '2026-10-28T13:12:00Z' };
    expect(campaignSpan(c)).toBe('2026-10-24 01:11 to 2026-10-28 13:12 UTC');
    expect(campaignSpan({ ...c, lastActivity: null })).toBe('2026-10-24 01:11 to 2026-10-28 13:12 UTC');
  });

  it('states the later end in the header, the Confirmed threats row and the host page', () => {
    const campaign: CampaignDetail = { ...CAMPAIGN_WAITS, lastActivity: LATER };
    const { unmount } = view(<CampaignView campaign={campaign} />);
    expect(screen.getByTestId('campaign-period')).toHaveTextContent(/to 2026-10-29 15:08 UTC$/);
    unmount();
    const row = view(<ThreatCampaignRow c={{ ...THREAT_CAMPAIGN, lastActivity: LATER }} />);
    expect(screen.getByTestId('threat-campaign-meta')).toHaveTextContent(/to 2026-10-29 15:08 UTC$/);
    row.unmount();
    view(<HostCampaigns campaigns={[{ ...HOST_CAMPAIGNS[0], lastActivity: LATER }]} />);
    expect(screen.getByText(/to 2026-10-29 15:08 UTC/)).toBeInTheDocument();
  });
});

/** A campaign that an analyst closed and opened again, with no new investigation. */
const SINCE: CampaignSinceDecision = {
  earlier: { decision: 'closed', reason: 'test_over', label: 'Test that is over', note: null, noteKnown: true, by: 'casey', at: '2026-10-28T23:00:00Z' },
  cause: 'analyst',
  reopenedAt: '2026-10-29T16:00:00Z',
  reopenedBy: 'casey',
  boundary: '2026-10-28T23:00:00Z',
  boundarySource: 'basis',
  runIds: [],
  investigations: 0,
  verdicts: [],
  authorized: 0,
  actors: [],
  targets: [],
  rules: 0,
  firstEvent: null,
  lastEvent: null,
  stage: null,
  stageBefore: 'action',
  stageNow: 'action',
  stageRose: false,
  newMachines: [],
  laterAlerts: 20,
  laterRules: 2,
  laterLastAt: LATER,
};

describe('the later alert events since the decision', () => {
  it('states them in the words of the server', () => {
    // tests/test_campaign_later_alerts.py holds the same lines.
    expect(sinceLaterSentence(SINCE)).toBe(
      'The grid holds 20 later alert events of 2 rules until 2026-10-29 15:08 UTC. ' +
        'They take the verdict of the investigations of the campaign.',
    );
    expect(sinceLaterSentence({ ...SINCE, investigations: 1, laterAlerts: 1, laterRules: 1 })).toBe(
      'The grid holds 1 later alert event of 1 rule until 2026-10-29 15:08 UTC. It takes the verdict of these investigations.',
    );
  });

  it('shows the line in the banner of the campaign', () => {
    view(<CampaignView campaign={{ ...CAMPAIGN_WAITS, waitsSince: SINCE.reopenedAt, sinceDecision: SINCE }} />);
    expect(screen.getByTestId('campaign-since-later')).toHaveTextContent(/^The grid holds 20 later alert events of 2 rules/);
  });

  it('states no line with no later alert event or from an earlier server', () => {
    // NEGATIVE CONTROL: no count, a count of 0.
    const { laterAlerts: _a, laterRules: _r, laterLastAt: _l, ...earlier } = SINCE;
    expect(sinceLaterSentence(earlier)).toBeNull();
    expect(sinceLaterSentence({ ...SINCE, laterAlerts: 0 })).toBeNull();
    view(<CampaignView campaign={{ ...CAMPAIGN_WAITS, waitsSince: SINCE.reopenedAt, sinceDecision: earlier }} />);
    expect(screen.queryByTestId('campaign-since-later')).toBeNull();
  });
});

describe('one count for one fact on the campaign page', () => {
  it('names the alerts of the confirmed rules and of the other rules in the header and the fold', () => {
    // Production, 2026-11-19: the header read "1,118 alerts of 8 rules" and the
    // fold listed 10 rules with 1,198 alerts. The fold also lists the rules
    // that soc-ai did not confirm, so each surface names both counts.
    const events = {
      ...EVENTS,
      alerts: 1118,
      rules: 8,
      pairs: [
        pair(ACTOR.machineKey, TARGET.machineKey, {
          alerts: 1118,
          otherAlerts: 80,
          rules: [
            ...Array.from({ length: 8 }, (_v, i) => ({ ...RULE_ROW, name: `Example Rule ${i}`, verdict: 'true_positive' as const })),
            { ...RULE_ROW, name: 'Example Other Rule', alerts: 70, verdict: 'false_positive' as const },
            { ...RULE_ROW, name: 'Example Unjudged Rule', alerts: 10, verdict: 'not_judged' as const },
          ],
        }),
      ],
    };
    expect(alertCounts(events)).toEqual({ confirmedAlerts: 1118, confirmedRules: 8, otherAlerts: 80, otherRules: 2 });
    expect(eventsFacts(events)).toMatch(/^1,118 alerts of 8 confirmed rules\. soc-ai did not confirm 80 alerts of 2 other rules\. /);
    expect(alertsFoldDetail(events)).toBe('8 confirmed rules, 2 other rules');
    view(<CampaignView campaign={{ ...CAMPAIGN_WAITS, events }} />);
    expect(screen.getByTestId('campaign-facts')).toHaveTextContent('1,118 alerts of 8 confirmed rules.');
    expect(screen.getByTestId('fold-alerts-detail')).toHaveTextContent('8 confirmed rules, 2 other rules');
  });

  it('names only the confirmed rules when no other rule holds an alert', () => {
    // NEGATIVE CONTROL: no other rule, no second count.
    const events = { ...EVENTS, pairs: [pair(ACTOR.machineKey, TARGET.machineKey, { alerts: 47, otherAlerts: 0, rules: [{ ...RULE_ROW, verdict: 'true_positive' as const }] })] };
    expect(alertsFoldDetail(events)).toBe('3 confirmed rules');
    expect(eventsFacts(events)).not.toContain('did not confirm');
  });

  it('counts the investigations of the authorization line as the fold does', () => {
    // Production: "covers 24 of the 55 investigations" above "Investigations 54".
    // The 55 held a member whose verdict differs.
    const members = [...MEMBERS, { ...MEMBERS[0], runId: 'run-differs-2', verdictDiffers: true }];
    const held = heldInvestigations(members);
    expect(held).toBe(MEMBERS.filter((m) => !m.verdictDiffers).length);
    const authorization = { id: 9, label: 'Red team test', state: 'active' as const, expiresAt: '2026-11-20T09:00:00Z', memberRuns: 2 };
    view(<CampaignView campaign={{ ...CAMPAIGN_WAITS, members, authorizations: [authorization], authorization: null }} />);
    expect(screen.getByTestId('campaign-authorizations')).toHaveTextContent(`covers 2 of the ${held} investigations`);
    expect(screen.getByTestId('fold-investigations-count')).toHaveTextContent(String(held));
  });
});

describe('the answer of a hunt beside the later alert events', () => {
  const ANSWER: CampaignHuntAnswer = {
    huntId: '01HUNTEXAMPLE0000000000000',
    huntAt: '2026-10-29T14:41:00Z',
    starter: 'scheduled',
    outcome: 'no_new_event',
    findingOrdinal: null,
    findingTitle: null,
  };
  const later = { ...EVENTS, laterAlerts: 20, laterRules: 2, laterLastAt: LATER };

  it('states the later alert events after "no activity that the campaign does not hold"', () => {
    expect(campaignLaterSentence(later)).toBe(
      'The grid holds 20 later alert events of 2 rules until 2026-10-29 15:08 UTC. ' +
        'They take the verdict of the investigations of the campaign.',
    );
    view(<CampaignView campaign={{ ...CAMPAIGN_WAITS, events: later, answers: [ANSWER] }} />);
    const line = screen.getByTestId('campaign-hunt-answer');
    expect(line).toHaveTextContent(
      'It found no activity that the campaign does not hold. The grid holds 20 later alert events of 2 rules',
    );
    expect(screen.getByTestId('campaign-hunt-answer-later')).toBeInTheDocument();
  });

  it('states no later line with none, and none twice beside the banner', () => {
    // NEGATIVE CONTROL: no later alert event, and a reopened campaign whose banner states them.
    expect(campaignLaterSentence(EVENTS)).toBeNull();
    expect(campaignLaterSentence(null)).toBeNull();
    const { unmount } = view(<CampaignView campaign={{ ...CAMPAIGN_WAITS, answers: [ANSWER] }} />);
    expect(screen.getByTestId('campaign-hunt-answer')).not.toHaveTextContent('later alert');
    unmount();
    view(
      <CampaignView
        campaign={{ ...CAMPAIGN_WAITS, events: later, answers: [ANSWER], waitsSince: SINCE.reopenedAt, sinceDecision: SINCE }}
      />,
    );
    expect(screen.queryByTestId('campaign-hunt-answer-later')).toBeNull();
    expect(screen.getAllByText(/The grid holds 20 later alert events/)).toHaveLength(1);
  });
});
