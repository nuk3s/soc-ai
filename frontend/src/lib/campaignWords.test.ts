import { describe, expect, it } from 'vitest';
import type { CampaignEvidence, CampaignLink } from './api';
import {
  JOIN_LABEL,
  LINK_LABEL,
  LINK_ORDER,
  STAGE_LABEL,
  STAGE_ORDER,
  STATUS_LABEL,
  TIER_LABEL,
  alertsOfRules,
  authorizationSentence,
  coverageSentence,
  detectionSentence,
  eventsFacts,
  falsePositiveSentence,
  linkSentence,
  moreWords,
  namedSentence,
  otherAlertsSentence,
  partyName,
  provedWords,
  recordsSentence,
  sessionTail,
  stageLabel,
  timelineNote,
} from './campaignWords';
import { EVENTS } from '../test/campaign';

const EVIDENCE: CampaignEvidence = {
  memberRunId: 'run-a1',
  machineKey: 'agent:actor-a',
  machineName: 'actor-a',
  artifact: 'CVE-2026-0001',
  communityId: '1:abc=',
  documentIds: ['doc-1'],
};

const member = (link: CampaignLink, evidence: Partial<CampaignEvidence> = {}) => ({
  link,
  evidence: { ...EVIDENCE, ...evidence },
});

describe('the label maps', () => {
  it('names each value of the vocabulary', () => {
    expect(STAGE_ORDER.map((s) => STAGE_LABEL[s])).toEqual([
      'Reconnaissance',
      'Attempt',
      'Access',
      'Action on the target',
      'Movement beyond the target',
    ]);
    expect(LINK_ORDER.map((l) => LINK_LABEL[l])).toEqual([
      'First confirmed attack',
      'Same connection',
      'Same attacking machine',
      'Same rule, CVE or request',
      'Same records',
      'The target then acted',
      'Named by the finding',
      'Included by an analyst',
    ]);
    expect(JOIN_LABEL).toEqual({ agent: 'agent report', dhcp: 'DHCP lease', network: 'network record' });
    expect(TIER_LABEL.scheduled_hunt).toBe('Scheduled hunt');
    expect(TIER_LABEL.lead_hunt).toBe('Lead hunt');
    expect(STATUS_LABEL.open).toBe('Open');
    expect(STATUS_LABEL.ended).toBe('Ended');
    expect(STATUS_LABEL.withdrawn).toBe('Withdrawn');
  });

  // NEGATIVE CONTROL: a value off the map reads as its own word.
  it('reads a new value as its own word', () => {
    expect(stageLabel('exfiltration' as never)).toBe('exfiltration');
  });
});

describe('linkSentence', () => {
  it('states the seed', () => {
    expect(linkSentence(member('seed'))).toBe(
      'This investigation is the first confirmed attack. It started the campaign.',
    );
  });

  it('states the shared connection', () => {
    expect(linkSentence(member('session'))).toBe(
      'This investigation shares the connection 1:abc= with the investigation run-a1.',
    );
  });

  it('names the other investigation by its label when the label is known', () => {
    const labels = { 'run-a1': 'ET EXPLOIT Example Upload Request' };
    expect(linkSentence(member('session'), {}, labels)).toBe(
      'This investigation shares the connection 1:abc= with the investigation "ET EXPLOIT Example Upload Request".',
    );
    expect(linkSentence(member('actor'), {}, labels)).toContain(
      'of the investigation "ET EXPLOIT Example Upload Request".',
    );
    // NEGATIVE CONTROL: an investigation that is not in the list keeps its id.
    expect(linkSentence(member('session'), {}, { other: 'x' })).toContain('with the investigation run-a1.');
  });

  it('states the same attacking machine and its nearest investigation', () => {
    expect(linkSentence(member('actor'))).toBe(
      'The attacking machine actor-a is the source of this investigation and of the investigation run-a1.',
    );
  });

  it('states the shared artifact', () => {
    expect(linkSentence(member('artifact'))).toBe(
      'This investigation shares CVE-2026-0001 with the investigation run-a1.',
    );
  });

  it('states the same records', () => {
    expect(linkSentence(member('documents'))).toBe(
      'Each record that this investigation cites is between machines of the campaign.',
    );
  });

  it('states that the target then acted', () => {
    expect(linkSentence(member('target_source', { machineName: 'web-1' }))).toBe(
      'web-1 is a target of the campaign. Then web-1 acted as the source of this investigation.',
    );
  });

  it('states the machines that a finding names', () => {
    const m = member('named_pair', { machineName: 'actor-a', memberRunId: 'r1' });
    expect(linkSentence(m, {}, { r1: 'File read on web-1' })).toBe(
      'The finding names actor-a and the target, and it cites no single record. The investigation "File read on web-1" proves an attack of actor-a on that target.',
    );
  });

  it('states an investigation that an analyst joined', () => {
    const m = member('included', { memberRunId: 'r1' });
    expect(linkSentence(m, {}, { r1: 'File read on web-1' })).toBe(
      'An analyst included this investigation in the campaign of the investigation "File read on web-1".',
    );
  });

  it('reads the machine name when the evidence names no machine', () => {
    const m = member('actor', { machineName: null, machineKey: 'agent:actor-b' });
    expect(linkSentence(m, { 'agent:actor-b': 'actor-b' })).toBe(
      'The attacking machine actor-b is the source of this investigation and of the investigation run-a1.',
    );
    // NEGATIVE CONTROL: with no machine name, the key stands.
    expect(linkSentence(m)).toBe(
      'The attacking machine agent:actor-b is the source of this investigation and of the investigation run-a1.',
    );
  });
});

describe('coverageSentence', () => {
  it('states the agent', () => {
    expect(coverageSentence({ hasAgent: true })).toBe('This machine has an agent.');
  });

  it('states what soc-ai cannot read without an agent', () => {
    expect(coverageSentence({ hasAgent: false })).toBe(
      'This machine has no agent. soc-ai cannot read processes or files on it.',
    );
  });
});

describe('detectionSentence', () => {
  it('states the tier and the time to the verdict', () => {
    expect(detectionSentence({ tier: 'alert', seconds: 199 })).toBe(
      'Alert saw it first. The verdict came 3m 19s after the event.',
    );
    expect(detectionSentence({ tier: 'lead_hunt', seconds: 7200 })).toBe(
      'Lead hunt saw it first. The verdict came 2h 00m after the event.',
    );
  });

  // NEGATIVE CONTROL: no span on record states no span.
  it('states the tier alone with no span', () => {
    expect(detectionSentence({ tier: 'analytic', seconds: null })).toBe('Analytic saw it first.');
  });
});

describe('the section sentences', () => {
  it('states an active authorization and another state', () => {
    const a = { id: 1, label: 'Red team test', state: 'active', expiresAt: '2026-11-20T09:00:00Z', memberRuns: 4 };
    expect(authorizationSentence(a, 6)).toBe(
      'The authorization Red team test covers 4 of the 6 investigations. It expires 2026-11-20 09:00 UTC.',
    );
    expect(authorizationSentence({ ...a, memberRuns: 1 }, 1)).toBe(
      'The authorization Red team test covers 1 of the 1 investigation. It expires 2026-11-20 09:00 UTC.',
    );
    expect(authorizationSentence({ ...a, state: 'expired' }, 6)).toBe(
      'The authorization Red team test is expired.',
    );
  });

  it('states a session after the two names', () => {
    const s = { port: 22, documents: 14, firstAt: '2026-10-23T03:10:00Z', lastAt: '2026-10-23T03:40:00Z' };
    expect(sessionTail(s)).toBe(' port 22: 14 documents, 2026-10-23 03:10 to 03:40 UTC.');
    // NEGATIVE CONTROL: no port states no port.
    expect(sessionTail({ ...s, port: null, documents: 1 })).toBe(
      ': 1 document, 2026-10-23 03:10 to 03:40 UTC.',
    );
  });

  it('states a named host', () => {
    expect(namedSentence({ value: 'cdn.example.test', documents: 3, documentIds: [] })).toBe(
      'cdn.example.test: named in 3 documents of the campaign. No stored document shows a target in a connection to it.',
    );
  });

  it('states the alerts from a target that soc-ai judged false positive', () => {
    expect(falsePositiveSentence(1041)).toBe(
      'soc-ai judged 1,041 alerts from a target as false positive. They are no part of the campaign.',
    );
    expect(falsePositiveSentence(1)).toBe(
      'soc-ai judged 1 alert from a target as false positive. It is no part of the campaign.',
    );
    expect(falsePositiveSentence(0)).toBe('');
  });

  it('names a machine and the rest of a list', () => {
    expect(partyName({ machineKey: 'agent:x', name: 'web-1', address: '192.0.2.10' })).toBe('web-1');
    expect(partyName({ machineKey: 'agent:x', name: null, address: '192.0.2.10' })).toBe('192.0.2.10');
    expect(partyName({ machineKey: 'agent:x', name: ' ', addresses: [] })).toBe('agent:x');
    expect(moreWords(4)).toBe('and 4 more');
    expect(moreWords(0)).toBe('');
  });
});

describe('the event words', () => {
  it('states the alerts of an arrow, the other alerts and the records', () => {
    expect(alertsOfRules(1072, 3)).toBe('1,072 alerts of 3 rules');
    expect(alertsOfRules(1, 1)).toBe('1 alert of 1 rule');
    expect(otherAlertsSentence(12)).toBe('soc-ai did not confirm 12 other alerts between these machines.');
    expect(otherAlertsSentence(1)).toBe('soc-ai did not confirm 1 other alert between these machines.');
    // NEGATIVE CONTROL: no other alert states nothing.
    expect(otherAlertsSentence(0)).toBe('');
    expect(recordsSentence(1840)).toBe('1,840 grid records between the two machines.');
    expect(provedWords('action')).toBe('soc-ai proved: Action on the target');
  });

  it('states the facts of the grid and of the stored events', () => {
    expect(eventsFacts(EVENTS)).toBe(
      '47 alerts of 3 rules. 1 hunt finding. 1,840 grid records between the machines.',
    );
    expect(eventsFacts({ ...EVENTS, alerts: 1, rules: 1, findings: 2, records: 1 })).toBe(
      '1 alert of 1 rule. 2 hunt findings. 1 grid record between the machines.',
    );
    expect(eventsFacts({ ...EVENTS, source: 'stored', alerts: 1200, records: null })).toBe(
      '1,200 alert events that the investigations hold. 1 hunt finding.',
    );
    expect(eventsFacts({ ...EVENTS, source: 'stored', alerts: 1, findings: 0 })).toBe(
      '1 alert event that the investigations hold. 0 hunt findings.',
    );
    // NEGATIVE CONTROL: no events, or a source of none, states no facts.
    expect(eventsFacts(undefined)).toBe('');
    expect(eventsFacts({ ...EVENTS, source: 'none' })).toBe('');
  });

  it('states the line above the timeline for each source', () => {
    expect(timelineNote('grid')).toBe(
      'The marks count the alert events of the grid. Times are in UTC. Drag across the chart to zoom in.',
    );
    expect(timelineNote('stored')).toBe(
      'soc-ai could not read the grid. The marks count the alert events that its investigations hold. ' +
        'Times are in UTC. Drag across the chart to zoom in.',
    );
    expect(timelineNote('none')).toBe('');
    expect(timelineNote(undefined)).toBe('');
  });
});
