// A rule decision as GET /rule-decisions/{ruleKey} answers it, from the API
// contract of round 3. The tests of the rule page and of the decision bar
// read it.
import { ruleKeyOf, type RuleDecisionDetail } from '../lib/api';

export const RULE_NAME = 'ET POLICY Example TLS client';
export const RULE_KEY = ruleKeyOf(RULE_NAME);

export function ruleDetail(over: Partial<RuleDecisionDetail> = {}): RuleDecisionDetail {
  return {
    ruleKey: RULE_KEY,
    ruleName: RULE_NAME,
    severity: 'high',
    readAt: '2026-11-14T11:58:00Z',
    gridAnswered: true,
    confident: {
      count: 470,
      reasons: [
        { code: 'high_stakes', label: 'The rule is high stakes', count: 468 },
        { code: 'auto_ack_failed', label: 'The automatic acknowledge failed', count: 2 },
      ],
      sources: 4,
      destinations: 2,
      firstEvent: '2026-11-10T03:00:00Z',
      lastEvent: '2026-11-14T09:00:00Z',
    },
    weak: {
      count: 1,
      reasons: [{ code: 'below_threshold', label: 'The confidence is under the limit', count: 1 }],
      sources: 1,
      destinations: 1,
      firstEvent: '2026-11-13T07:00:00Z',
      lastEvent: '2026-11-13T07:00:00Z',
    },
    machines: [
      { key: '192.0.2.10', name: 'ws-1', address: '192.0.2.10', role: 'source', count: 300 },
      { key: '198.51.100.7', name: 'web-1', address: '198.51.100.7', role: 'destination', count: 471 },
    ],
    // 2026-11-11 is a gap: the chart draws it as a day with no event.
    histogram: [
      { day: '2026-11-10', confident: 100, weak: 0 },
      { day: '2026-11-12', confident: 120, weak: 0 },
      { day: '2026-11-13', confident: 150, weak: 1 },
      { day: '2026-11-14', confident: 100, weak: 0 },
    ],
    samples: [
      {
        id: 'inv-a',
        eventAt: '2026-11-14T09:00:00Z',
        src: '192.0.2.10',
        dst: '198.51.100.7',
        confidence: 0.86,
        summary: 'The client fetched a known update file from the vendor host.',
        group: 'confident',
        reason: 'high_stakes',
      },
      {
        id: 'inv-b',
        eventAt: '2026-11-12T05:00:00Z',
        src: '192.0.2.11',
        dst: '198.51.100.7',
        confidence: 0.81,
        summary: 'The same client pattern repeats each hour.',
        group: 'confident',
        reason: 'auto_ack_failed',
      },
      {
        id: 'inv-c',
        eventAt: '2026-11-13T07:00:00Z',
        src: '192.0.2.12',
        dst: '198.51.100.7',
        confidence: 0.55,
        summary: 'The flow matches the update pattern, with one record missing.',
        group: 'weak',
        reason: 'below_threshold',
      },
    ],
    truePositives: [],
    openAlerts: 1204,
    standing: null,
    history: [],
    canStanding: true,
    canStandingWhy: null,
    investigationsHref: '/investigations?rule=ET%20POLICY%20Example%20TLS%20client&verdict=false_positive',
    ...over,
  };
}
