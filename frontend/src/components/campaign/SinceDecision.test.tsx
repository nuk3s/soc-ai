// A campaign that opened again states the earlier decision and what is new
// since it (SD3). Production, 2026-11-18: campaign 2 opened again three days
// after a close, and the page read only "This campaign waits on your decision
// since ...". The words are the words of the server
// (tests/test_campaign_since_decision_api.py holds the same lines).
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import type { CampaignDetail, CampaignSinceDecision } from '../../lib/api';
import {
  sinceAuthorizationSentence,
  sinceCountSplitWords,
  sinceCountWords,
  sinceEarlierSentence,
  sinceNewSentence,
  sinceReopenHuntSentence,
  sinceReopenSentence,
  sinceSplitWords,
  sinceStageSentence,
  sinceThreatLine,
} from '../../lib/campaignWords';
import { forbiddenWords } from '../../test/analystWords';
import { CAMPAIGN_CLOSED, CAMPAIGN_WAITS, EVENTS, MEMBERS, PARTIES, THREAT_CAMPAIGN } from '../../test/campaign';
import { ThreatCampaignRow } from '../ConfirmedThreats';
import { CampaignTimeline } from './CampaignTimeline';
import { CampaignView } from './CampaignView';

/** The production example, with placeholder names. */
const SINCE: CampaignSinceDecision = {
  earlier: {
    decision: 'closed',
    reason: 'test_over',
    label: 'Test that is over',
    note: 'The red team ended the test.',
    noteKnown: true,
    by: 'casey',
    at: '2026-11-15T01:01:12Z',
  },
  cause: 'activity',
  reopenedAt: '2026-11-18T13:02:28Z',
  reopenedBy: null,
  boundary: '2026-10-28T22:44:56Z',
  boundarySource: 'basis',
  // Two new investigations of the table, and one whose verdict differs.
  runIds: ['run-shell', 'run-session', 'run-differs'],
  investigations: 3,
  verdicts: [
    { verdict: 'true_positive', count: 5 },
    { verdict: 'false_positive', count: 1 },
  ],
  authorized: 3,
  actors: [{ machineKey: 'agent:actor-a', name: 'actor-a', address: '192.0.2.10' }],
  targets: [{ machineKey: 'net:192.0.2.20', name: 'web-1', address: '192.0.2.20' }],
  rules: 4,
  firstEvent: '2026-11-18T12:55:10Z',
  lastEvent: '2026-11-18T13:12:17Z',
  stage: 'attempt',
  stageBefore: 'action',
  stageNow: 'action',
  stageRose: false,
  newMachines: [],
};

const REOPENED: CampaignDetail = { ...CAMPAIGN_WAITS, waitsSince: SINCE.reopenedAt, sinceDecision: SINCE };

const view = (ui: React.ReactElement) => render(<MemoryRouter>{ui}</MemoryRouter>);

describe('the words of what is new since the earlier decision', () => {
  it('states the reopen and the earlier close as the server does', () => {
    expect(sinceReopenSentence(SINCE)).toBe('Opened again on 2026-11-18 13:02 UTC by new activity.');
    expect(sinceEarlierSentence(SINCE)).toBe('casey closed it on 2026-11-15: Test that is over.');
    expect(sinceReopenSentence({ ...SINCE, cause: 'analyst', reopenedBy: 'morgan' })).toBe(
      'Opened again on 2026-11-18 13:02 UTC by morgan.',
    );
    expect(sinceReopenSentence({ ...SINCE, cause: 'revoked' })).toBe(
      'Opened again on 2026-11-18 13:02 UTC by a revoke of the authorization.',
    );
    expect(
      sinceEarlierSentence({ earlier: { ...SINCE.earlier, decision: 'authorized', label: 'Red team test' } }),
    ).toBe('casey authorized it on 2026-11-15: Red team test.');
    expect(sinceEarlierSentence({ earlier: { ...SINCE.earlier, decision: 'case' } })).toBe(
      'casey opened a case for it on 2026-11-15.',
    );
  });

  it('states the new facts, the stage and the count as the server does', () => {
    expect(sinceNewSentence(SINCE)).toBe(
      'New: 5 true positive investigations and 1 false positive from actor-a, 2026-11-18 12:55 to 13:12 UTC. An authorization holds 3.',
    );
    expect(sinceNewSentence({ ...SINCE, investigations: 0, verdicts: [], authorized: 0 })).toBe(
      'No investigation of the campaign has an event after 2026-10-28 22:44 UTC.',
    );
    expect(sinceStageSentence(SINCE)).toBe('The stage did not change.');
    expect(sinceStageSentence({ stageRose: true, stageBefore: 'attempt', stageNow: 'access' })).toBe(
      'The stage rose from Attempt to Access.',
    );
    expect(sinceCountWords({ ...SINCE, investigations: 6 })).toBe('6 new investigations since the close of 2026-11-15.');
    expect(sinceThreatLine({ ...SINCE, investigations: 6 })).toBe(
      'Opened again on 2026-11-18. 6 new investigations since the close of 2026-11-15: ' +
        '5 true positives and 1 false positive. An authorization holds 3.',
    );
    // W3: the split and the authorization are the words of the banner, as the server states them.
    expect(sinceSplitWords(SINCE)).toBe('5 true positives and 1 false positive');
    expect(
      sinceCountSplitWords({ ...SINCE, investigations: 6, outsideTruePositives: 2, outsideNames: ['ET RULE A'] }),
    ).toBe(
      '6 new investigations since the close of 2026-11-15: 5 true positives and 1 false positive. ' +
        'An authorization holds 3. It does not hold 2 true positives: ET RULE A.',
    );
    // NEGATIVE CONTROL: no new investigation, no split.
    expect(sinceCountSplitWords({ ...SINCE, investigations: 0, verdicts: [], authorized: 0 })).toBe(
      '0 new investigations since the close of 2026-11-15.',
    );
  });
});

describe('the authorization and the hunt of a reopen (W1)', () => {
  const HOLDING = { id: 7, label: 'Red team test', state: 'active', expiresAt: '2026-11-20T22:09:00Z', investigations: 3 };
  const OUTSIDE = { outsideTruePositives: 2, outsideNames: ['ET RULE A', 'Unlisted rules'], authorizations: [HOLDING] };

  it('names the true positives that the authorization does not hold, as the server does', () => {
    expect(sinceAuthorizationSentence({ ...SINCE, ...OUTSIDE })).toBe(
      'The authorization Red team test holds 3. It expires 2026-11-20 22:09 UTC. ' +
        'It does not hold 2 true positives: ET RULE A and Unlisted rules.',
    );
    expect(sinceNewSentence({ ...SINCE, ...OUTSIDE })).toBe(
      'New: 5 true positive investigations and 1 false positive from actor-a, 2026-11-18 12:55 to 13:12 UTC. ' +
        'The authorization Red team test holds 3. It expires 2026-11-20 22:09 UTC. ' +
        'It does not hold 2 true positives: ET RULE A and Unlisted rules.',
    );
    const authorized = { ...SINCE.earlier, decision: 'authorized' as const, label: 'Red team test' };
    expect(sinceAuthorizationSentence({ ...SINCE, ...OUTSIDE, earlier: authorized })).toBe(
      'An authorization holds 3. It does not hold 2 true positives: ET RULE A and Unlisted rules.',
    );
    const expired = { ...HOLDING, state: 'expired' };
    expect(
      sinceAuthorizationSentence({ ...SINCE, outsideTruePositives: 1, outsideNames: ['ET RULE A'], authorizations: [expired] }),
    ).toBe('An authorization holds 3. It does not hold 1 true positive: ET RULE A.');
    const two = [HOLDING, { ...HOLDING, id: 8, label: 'Scan window', investigations: 1 }];
    expect(
      sinceAuthorizationSentence({ ...SINCE, authorized: 4, outsideTruePositives: 1, outsideNames: ['ET RULE A'], authorizations: two }),
    ).toMatch(/No authorization holds 1 true positive: ET RULE A\.$/);
    const many = Array.from({ length: 7 }, (_, n) => `rule-${n}`);
    expect(
      sinceAuthorizationSentence({ ...SINCE, outsideTruePositives: 7, outsideNames: many, authorizations: [HOLDING] }),
    ).toMatch(/7 true positives: rule-0, rule-1, rule-2, rule-3, rule-4 and 2 more\.$/);
    // NEGATIVE CONTROL: no mark that holds, no authorization in the line.
    expect(sinceAuthorizationSentence({ ...SINCE, ...OUTSIDE, authorized: 0 })).toBe('');
    // An older server sends no new field: the line of before.
    expect(sinceAuthorizationSentence(SINCE)).toBe('An authorization holds 3.');
  });

  it('links the hunt of the reopen beside the newest hunt answer, in the bar', () => {
    const hunt = {
      id: 'hunt-reopen',
      startedAt: '2026-11-18T13:05:00Z',
      status: 'complete',
      outcome: '1 confirmed · 1 false positive · 0 not judged · of 2 threat findings',
    };
    expect(sinceReopenHuntSentence(hunt)).toBe(
      'The reopen started the hunt of 2026-11-18 13:05 UTC: 1 confirmed · 1 false positive · 0 not judged · of 2 threat findings.',
    );
    expect(sinceReopenHuntSentence({ ...hunt, status: 'running', outcome: null })).toBe(
      'The reopen started the hunt of 2026-11-18 13:05 UTC. The hunt runs.',
    );
    const answer = { huntId: 'hunt-schedule', huntAt: '2026-11-18T18:41:00Z', starter: 'schedule', outcome: 'no_new_event' as const, findingOrdinal: null, findingTitle: null };
    view(<CampaignView campaign={{ ...REOPENED, sinceDecision: { ...SINCE, reopenHunt: hunt }, answers: [answer] }} />);
    const bar = screen.getByTestId('campaign-decision');
    const line = within(bar).getByTestId('campaign-since-reopen-hunt');
    expect(line).toHaveTextContent(sinceReopenHuntSentence(hunt));
    expect(within(line).getByRole('link', { name: 'Open the hunt' })).toHaveAttribute('href', '/hunts/hunt-reopen');
    // The newest answer stands beside it, in the bar, and only once on the page.
    expect(within(bar).getByTestId('campaign-hunt-answer')).toHaveTextContent('The hunt of 2026-11-18 18:41 UTC read this campaign.');
    expect(screen.getAllByTestId('campaign-hunt-answer')).toHaveLength(1);
    expect(forbiddenWords(bar)).toEqual([]);
  });

  it('keeps the answer in the header for a campaign that never had a decision', () => {
    // NEGATIVE CONTROL: no banner, so the answer line stays under the bottom line.
    const answer = { huntId: 'hunt-schedule', huntAt: '2026-11-18T18:41:00Z', starter: 'schedule', outcome: 'no_new_event' as const, findingOrdinal: null, findingTitle: null };
    view(<CampaignView campaign={{ ...CAMPAIGN_WAITS, answers: [answer] }} />);
    expect(screen.queryByTestId('campaign-since-hunts')).toBeNull();
    expect(screen.getAllByTestId('campaign-hunt-answer')).toHaveLength(1);
  });
});

describe('the campaign page of a campaign that opened again', () => {
  it('states the earlier decision and the new facts above the line of the wait', () => {
    view(<CampaignView campaign={REOPENED} />);
    const bar = screen.getByTestId('campaign-decision');
    const since = within(bar).getByTestId('campaign-since');
    expect(within(since).getByTestId('campaign-since-chip')).toHaveTextContent('Opened again');
    expect(within(since).getByTestId('campaign-since-earlier')).toHaveTextContent(
      'Opened again on 2026-11-18 13:02 UTC by new activity. casey closed it on 2026-11-15: Test that is over. Note of the decision: The red team ended the test.',
    );
    expect(within(since).getByTestId('campaign-since-new')).toHaveTextContent(sinceNewSentence(SINCE));
    expect(within(since).getByTestId('campaign-since-stage')).toHaveTextContent('The stage did not change.');
    // The facts come before the line of the wait.
    const wait = within(bar).getByTestId('campaign-decision-state');
    expect(since.compareDocumentPosition(wait) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(wait).toHaveTextContent('This campaign waits on your decision since 2026-11-18 13:02 UTC.');
    expect(forbiddenWords(bar)).toEqual([]);
  });

  it('opens exactly the new investigations, each with the chip New', () => {
    view(<CampaignView campaign={REOPENED} />);
    fireEvent.click(screen.getByTestId('campaign-show-new'));
    expect(screen.getByTestId('members-new-only')).toHaveTextContent(
      'Showing the 3 new investigations since the close of 2026-11-15.',
    );
    const table = screen.getByTestId('campaign-members');
    const rows = within(table)
      .getAllByRole('row')
      .filter((r) => r.getAttribute('data-testid')?.startsWith('member-'));
    // NEGATIVE CONTROL: the count of the server equals the list that the control opens.
    expect(rows.map((r) => r.getAttribute('data-testid')?.replace('member-', '')).sort()).toEqual(
      [...SINCE.runIds].sort(),
    );
    expect(rows).toHaveLength(SINCE.investigations);
    for (const row of rows) expect(within(row).getByTestId('member-new')).toHaveTextContent('New');
    // "Show all investigations" gives back the table of the campaign.
    fireEvent.click(within(screen.getByTestId('members-new-only')).getByRole('button'));
    expect(screen.queryByTestId('members-new-only')).toBeNull();
    const all = within(screen.getByTestId('campaign-members')).getAllByRole('row');
    expect(all.filter((r) => r.getAttribute('data-testid')?.startsWith('member-'))).toHaveLength(
      MEMBERS.filter((m) => !m.verdictDiffers).length,
    );
    // An investigation with an event before the boundary carries no chip.
    expect(within(screen.getByTestId('member-run-actor')).queryByTestId('member-new')).toBeNull();
    expect(within(screen.getByTestId('member-run-shell')).getByTestId('member-new')).toBeInTheDocument();
  });

  it('states the link of a row in words, with the ids behind the link and in the hover (W5)', () => {
    view(<CampaignView campaign={REOPENED} />);
    fireEvent.click(screen.getByTestId('campaign-show-new'));
    const sentence = within(screen.getByTestId('member-run-session')).getByTestId('member-link-sentence');
    // The link column read "connection 1:abc=" and "investigation run-...".
    expect(sentence.textContent).not.toMatch(/1:abc=|run-seed/);
    expect(sentence).toHaveAttribute('title', 'Connection 1:abc=');
    const other = within(sentence).getByTestId('member-link-other');
    expect(other).toHaveAttribute('href', '/investigation/run-seed');
  });

  it('states no "since" for a campaign that never had a decision, nor for a closed one', () => {
    // NEGATIVE CONTROL: no earlier decision, no banner and no control.
    const { unmount } = view(<CampaignView campaign={CAMPAIGN_WAITS} />);
    expect(screen.queryByTestId('campaign-since')).toBeNull();
    expect(screen.queryByTestId('campaign-show-new')).toBeNull();
    unmount();
    // NEGATIVE CONTROL: a decision in force states none.
    view(<CampaignView campaign={{ ...CAMPAIGN_CLOSED, sinceDecision: null }} />);
    expect(screen.queryByTestId('campaign-since')).toBeNull();
  });

  it('marks the span after the earlier decision on the timeline', () => {
    const words = 'After 2026-10-28 22:44 UTC: the activity that the earlier close does not cover.';
    const { unmount } = view(
      <CampaignTimeline
        events={EVENTS}
        members={MEMBERS}
        parties={PARTIES}
        ladder={CAMPAIGN_WAITS.ladder}
        selection={null}
        onSelect={() => {}}
        since={{ boundary: SINCE.boundary, words }}
      />,
    );
    expect(screen.getByTestId('timeline-since')).toHaveAttribute('aria-label', words);
    unmount();
    view(
      <CampaignTimeline
        events={EVENTS}
        members={MEMBERS}
        parties={PARTIES}
        ladder={CAMPAIGN_WAITS.ladder}
        selection={null}
        onSelect={() => {}}
      />,
    );
    expect(screen.queryByTestId('timeline-since')).toBeNull();
  });
});

describe('the Confirmed threats row of a campaign that opened again', () => {
  it('states the reopen and the count of the new investigations in one line', () => {
    // The verdicts of the fixture count 6 new investigations.
    view(<ThreatCampaignRow c={{ ...THREAT_CAMPAIGN, sinceDecision: { ...SINCE, investigations: 6 } }} />);
    expect(screen.getByTestId('threat-campaign-since')).toHaveTextContent(
      'Opened again on 2026-11-18. 6 new investigations since the close of 2026-11-15: ' +
        '5 true positives and 1 false positive. An authorization holds 3.',
    );
  });

  it('states nothing of the kind for a campaign that never had a decision', () => {
    // NEGATIVE CONTROL.
    view(<ThreatCampaignRow c={THREAT_CAMPAIGN} />);
    expect(screen.queryByTestId('threat-campaign-since')).toBeNull();
  });
});
