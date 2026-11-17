import type {
  CampaignAuthorizationRecord,
  CampaignBeyondRun,
  CampaignChange,
  CampaignDetail,
  CampaignExcludedRun,
  CampaignEdge,
  CampaignEvents,
  CampaignHunt,
  CampaignLead,
  CampaignMember,
  CampaignPairEvents,
  CampaignParty,
  CampaignRelatedSession,
  HostCampaign,
  InvestigationCampaign,
  ThreatCampaign,
} from '../lib/api';

// One synthetic campaign for the tests of the campaign page and its graphics.
// The data is synthetic: placeholder addresses, names and rule names.
//
// actor-a acts on web-1 in four true positive investigations. Three of them
// sit within 32 minutes on 2026-10-24, the fourth is a finding four days
// later. A false positive on the session of the seed is a verdict that
// differs. 192.0.2.30 is a target beyond the first target, with no arrow.
//
// The grid holds 47 alert events of three confirmed rules between actor-a and
// web-1, and 12 alert events of two other rules. The timeline puts them in
// three buckets of ten minutes: 12 at 00:40, 31 at 01:10 and 4 at 22:40 on
// 2026-10-28, where the finding is.

export const ACTOR = { machineKey: 'agent:actor-a', name: 'actor-a', address: '192.0.2.10' };
export const TARGET = { machineKey: 'net:192.0.2.20', name: 'web-1', address: '192.0.2.20' };
export const BEYOND_KEY = 'net:192.0.2.30';

export const MEMBER: CampaignMember = {
  runId: 'run-seed',
  kind: 'alert',
  label: 'ET EXPLOIT PHP file upload',
  verdict: 'true_positive',
  impact: 'attempted',
  stage: 'attempt',
  link: 'seed',
  evidence: {
    memberRunId: null,
    machineKey: null,
    machineName: null,
    artifact: null,
    communityId: null,
    documentIds: [],
  },
  direction: 'forward',
  eventAt: '2026-10-24T01:11:05Z',
  finishedAt: '2026-10-24T01:14:24Z',
  tier: 'alert',
  sourceAddress: '192.0.2.10',
  targetAddress: '192.0.2.20',
  sourceKey: ACTOR.machineKey,
  targetKey: TARGET.machineKey,
  verdictDiffers: false,
  huntId: null,
};

/** A party with the fields a test does not care about filled in. */
export function party(over: Partial<CampaignParty> & Pick<CampaignParty, 'machineKey'>): CampaignParty {
  return {
    name: null,
    role: 'target',
    addresses: [],
    join: 'network',
    hasAgent: false,
    firstEvent: null,
    lastEvent: null,
    memberRuns: 1,
    beyond: false,
    ...over,
  };
}

/** An arrow with the fields a test does not care about filled in. */
export function edge(source: string, target: string, over: Partial<CampaignEdge> = {}): CampaignEdge {
  return {
    source,
    target,
    runs: 1,
    stage: 'attempt',
    firstAt: '2026-10-24T01:00:00Z',
    lastAt: '2026-10-24T02:00:00Z',
    beyond: false,
    fromDocuments: false,
    ...over,
  };
}

/** The events between two machines, with the fields a test does not care about filled in. */
export function pair(source: string, target: string, over: Partial<CampaignPairEvents> = {}): CampaignPairEvents {
  return {
    source,
    target,
    alerts: 1,
    otherAlerts: 0,
    records: null,
    firstAt: '2026-10-24T01:00:00Z',
    lastAt: '2026-10-24T02:00:00Z',
    rules: [],
    datasets: [],
    ...over,
  };
}

/** A related session between two parties. */
export function session(
  source: { machineKey: string; name: string | null },
  target: { machineKey: string; name: string | null },
  port: number,
  documents = 14,
): CampaignRelatedSession {
  return {
    source: { ...source, address: null },
    target: { ...target, address: null },
    port,
    dataset: 'zeek.conn',
    documents,
    firstAt: '2026-10-23T03:10:00Z',
    lastAt: '2026-10-23T03:40:00Z',
    documentIds: ['c1'],
  };
}

export const PARTIES: CampaignParty[] = [
  party({
    machineKey: TARGET.machineKey,
    name: 'web-1',
    addresses: ['192.0.2.20'],
    firstEvent: '2026-10-24T00:40:00Z',
    lastEvent: '2026-10-28T22:44:56Z',
    memberRuns: 4,
  }),
  party({
    machineKey: ACTOR.machineKey,
    name: 'actor-a',
    role: 'actor',
    addresses: ['192.0.2.10', '192.0.2.11'],
    join: 'agent',
    hasAgent: true,
    firstEvent: '2026-10-24T00:40:00Z',
    lastEvent: '2026-10-28T22:44:56Z',
    memberRuns: 4,
  }),
  party({
    machineKey: BEYOND_KEY,
    addresses: ['192.0.2.30'],
    join: 'dhcp',
    firstEvent: '2026-10-29T08:00:00Z',
    lastEvent: '2026-10-29T08:00:00Z',
    beyond: true,
  }),
];

export const MEMBERS: CampaignMember[] = [
  MEMBER,
  {
    ...MEMBER,
    runId: 'run-session',
    label: 'ET WEB PHP shell request',
    link: 'session',
    impact: null,
    stage: null,
    eventAt: '2026-10-24T01:12:00Z',
    evidence: { ...MEMBER.evidence, memberRunId: 'run-seed', communityId: '1:abc=' },
  },
  {
    ...MEMBER,
    runId: 'run-shell',
    kind: 'finding',
    label: 'Command execution through the web shell',
    impact: 'succeeded',
    stage: 'action',
    link: 'documents',
    tier: 'scheduled_hunt',
    huntId: 'hunt-9',
    eventAt: '2026-10-28T22:44:56Z',
  },
  {
    ...MEMBER,
    runId: 'run-actor',
    label: 'ET SCAN Nmap',
    link: 'actor',
    stage: 'reconnaissance',
    impact: null,
    eventAt: '2026-10-24T00:40:00Z',
    evidence: { ...MEMBER.evidence, memberRunId: 'run-seed', machineKey: ACTOR.machineKey },
  },
  {
    ...MEMBER,
    runId: 'run-differs',
    label: 'ET POLICY curl user agent',
    verdict: 'false_positive',
    link: 'session',
    verdictDiffers: true,
    eventAt: '2026-10-24T01:11:30Z',
    evidence: { ...MEMBER.evidence, memberRunId: 'run-seed', communityId: '1:abc=' },
  },
];

/** The events of actor-a against web-1: three confirmed rules, two others. */
export const PAIR: CampaignPairEvents = pair(ACTOR.machineKey, TARGET.machineKey, {
  alerts: 47,
  otherAlerts: 12,
  records: 1840,
  firstAt: '2026-10-24T00:40:00Z',
  lastAt: '2026-10-28T22:46:10Z',
  rules: [
    { name: 'ET POLICY curl user agent', alerts: 9, firstAt: '2026-10-24T01:11:30Z', lastAt: '2026-10-24T01:15:00Z', verdict: 'false_positive' },
    { name: 'ET SCAN Nmap', alerts: 12, firstAt: '2026-10-24T00:40:00Z', lastAt: '2026-10-24T00:48:00Z', verdict: 'true_positive' },
    { name: 'ET INFO HTTP request to a raw address', alerts: 3, firstAt: '2026-10-24T01:13:00Z', lastAt: '2026-10-24T01:14:00Z', verdict: 'not_judged' },
    { name: 'ET EXPLOIT PHP file upload', alerts: 30, firstAt: '2026-10-24T01:11:05Z', lastAt: '2026-10-24T01:19:40Z', verdict: 'true_positive' },
    { name: 'ET WEB PHP shell request', alerts: 5, firstAt: '2026-10-24T01:12:00Z', lastAt: '2026-10-28T22:46:10Z', verdict: 'true_positive' },
  ],
  datasets: [
    { name: 'zeek.conn', records: 1500 },
    { name: 'suricata.alert', records: 340 },
  ],
});

export const EVENTS: CampaignEvents = {
  source: 'grid',
  readAt: '2026-11-13T10:00:00Z',
  alerts: 47,
  rules: 3,
  findings: 1,
  records: 1840,
  pairs: [PAIR],
  timeline: {
    bucketSeconds: 600,
    lanes: [
      {
        machineKey: ACTOR.machineKey,
        buckets: [
          { at: '2026-10-24T00:40:00Z', alerts: 12 },
          { at: '2026-10-24T01:10:00Z', alerts: 31 },
          { at: '2026-10-28T22:40:00Z', alerts: 4 },
        ],
      },
    ],
  },
};

export const CAMPAIGN: CampaignDetail = {
  id: 7,
  title: 'actor-a against web-1',
  status: 'open',
  mergedInto: null,
  earlierCampaign: { id: 3, title: 'actor-a against web-1 in October' },
  bottomLine:
    'actor-a attacked web-1 from 2026-10-24 to 2026-10-28. Stage reached: Action on the target. No activity beyond the target.',
  stage: 'action',
  firstEvent: '2026-10-24T00:40:00Z',
  lastEvent: '2026-10-28T22:44:56Z',
  builtAt: '2026-11-13T10:00:00Z',
  stale: false,
  authorizations: [
    { id: 4, label: 'Red team test', state: 'active', expiresAt: '2026-11-20T09:00:00Z', memberRuns: 3 },
    { id: 5, label: 'Old test', state: 'revoked', expiresAt: '2026-11-01T09:00:00Z', memberRuns: 0 },
  ],
  ladder: [
    {
      stage: 'reconnaissance',
      reached: true,
      firstAt: '2026-10-24T00:40:00Z',
      members: 1,
      proofRunId: 'run-actor',
      proofDocumentId: null,
      headline: 'actor-a scanned web-1 for open ports.',
      evidence: null,
    },
    {
      stage: 'attempt',
      reached: true,
      firstAt: '2026-10-24T01:11:05Z',
      members: 1,
      proofRunId: 'run-seed',
      proofDocumentId: 'doc-1',
      headline: 'actor-a sent a PHP file upload to web-1.',
      evidence: { documentId: 'doc-1', label: 'ET EXPLOIT PHP file upload, 192.0.2.10 to 192.0.2.20', at: '2026-10-24T01:11:05Z' },
    },
    { stage: 'access', reached: false, firstAt: null, members: 0, proofRunId: null, proofDocumentId: null, headline: null, evidence: null },
    {
      stage: 'action',
      reached: true,
      firstAt: '2026-10-28T22:44:56Z',
      members: 1,
      proofRunId: 'run-shell',
      proofDocumentId: 'doc-3',
      headline: 'actor-a executed a command on web-1 through a web shell.',
      evidence: {
        documentId: 'doc-3',
        label: 'suricata.alert 192.0.2.10:51544 to 192.0.2.20:80 ET WEB PHP shell request uid=33(www-data) gid=33(www-data) groups=33(www-data)',
        at: '2026-10-28T22:44:56Z',
      },
    },
    { stage: 'movement', reached: false, firstAt: null, members: 0, proofRunId: null, proofDocumentId: null, headline: null, evidence: null },
  ],
  parties: PARTIES,
  waves: [],
  members: MEMBERS,
  related: {
    needsMoreInfo: [
      {
        runId: 'run-nmi',
        label: 'ET POLICY SSH session',
        finishedAt: '2026-10-23T03:40:00Z',
        sourceAddress: '192.0.2.10',
        targetAddress: '192.0.2.20',
      },
    ],
    sessions: [session(ACTOR, TARGET, 22)],
    named: [{ value: 'cdn.example.test', documents: 3, documentIds: ['d1'] }],
    falsePositiveFromTargets: 41,
  },
  detection: [
    { stage: 'action', tier: 'scheduled_hunt', runId: 'run-shell', eventAt: '2026-10-28T22:44:56Z', verdictAt: '2026-10-29T00:44:56Z', seconds: 7200 },
    { stage: 'attempt', tier: 'alert', runId: 'run-seed', eventAt: '2026-10-24T01:11:05Z', verdictAt: '2026-10-24T01:14:24Z', seconds: 199 },
  ],
  graph: {
    edges: [
      edge(ACTOR.machineKey, TARGET.machineKey, {
        runs: 4,
        alerts: 47,
        stage: 'action',
        firstAt: '2026-10-24T00:40:00Z',
        lastAt: '2026-10-28T22:44:56Z',
      }),
    ],
  },
  events: EVENTS,
};

/** The campaign of an investigation, as a row, an alert group, a finding and
 *  the investigation page carry it. */
export const LINK: InvestigationCampaign = {
  id: CAMPAIGN.id,
  title: CAMPAIGN.title,
  status: 'open',
  stage: 'action',
  differs: false,
};

/** The campaign of an investigation on a session of the campaign with a
 *  verdict that differs. */
export const LINK_DIFFERS: InvestigationCampaign = { ...LINK, differs: true };

/** The campaign as the confirmed threats panel reads it: a list row and the
 *  counts over its true positive investigations in the window. */
export const THREAT_CAMPAIGN: ThreatCampaign = {
  id: CAMPAIGN.id,
  title: CAMPAIGN.title,
  status: 'open',
  stage: 'action',
  actors: [ACTOR],
  targets: [TARGET],
  targetsMore: 0,
  firstEvent: CAMPAIGN.firstEvent,
  lastEvent: CAMPAIGN.lastEvent,
  members: 25,
  alerts: 47,
  investigations: 25,
  waiting: 21,
  authorized: 4,
};

/** The campaigns of web-1 as its host page reads them: a target of the
 *  campaign, and the actor of an ended one. */
export const HOST_CAMPAIGNS: HostCampaign[] = [
  { ...LINK, role: 'target', firstEvent: CAMPAIGN.firstEvent, lastEvent: CAMPAIGN.lastEvent, alerts: 47 },
  {
    id: 3,
    title: 'web-1 against db-1 in October',
    status: 'ended',
    stage: null,
    differs: false,
    role: 'both',
    firstEvent: '2026-10-02T08:00:00Z',
    lastEvent: '2026-10-02T09:30:00Z',
    alerts: null,
  },
];

/** The campaign as a server of an earlier release sends it: no events, no
 *  headline, no evidence and no alert count on an arrow. */
export function earlierCampaign(): CampaignDetail {
  const { events: _events, ...rest } = CAMPAIGN;
  return {
    ...rest,
    ladder: CAMPAIGN.ladder.map(({ headline: _h, evidence: _e, ...step }) => step),
    graph: { edges: CAMPAIGN.graph.edges.map(({ alerts: _a, ...e }) => e) },
  };
}

// ── Decisions ───────────────────────────────────────────────────────────────
//
// The campaign waits on a decision since its first event. The closed form
// holds the close of admin on 2026-11-14 and the acknowledgement that
// followed it. An older acknowledgement, of a close before the campaign opened
// again, must not count for the close that stands.

export const WAITS_SINCE = '2026-10-24T00:40:00Z';

/** The campaign with no decision: it waits on the analyst. */
export const CAMPAIGN_WAITS: CampaignDetail = {
  ...CAMPAIGN,
  decision: null,
  waitsSince: WAITS_SINCE,
  changes: [
    { id: 3, type: 'stage', at: '2026-10-28T22:50:00Z', detail: { from: 'attempt', to: 'action' } },
    { id: 2, type: 'party', at: '2026-10-24T01:20:00Z', detail: { names: ['db-1', 'mail-1'] } },
    { id: 1, type: 'formed', at: '2026-10-24T01:15:00Z', detail: {} },
  ],
};

export const CLOSE_AT = '2026-11-14T21:00:00Z';

/** The changes of the closed campaign, newest first. */
export const CLOSED_CHANGES: CampaignChange[] = [
  { id: 9, type: 'acknowledged', at: '2026-11-14T21:01:30Z', detail: { alerts: 1083, failed: 2 } },
  { id: 8, type: 'decided', at: CLOSE_AT, detail: { decision: 'closed', reason: 'test_over', by: 'admin' } },
  { id: 7, type: 'reopened', at: '2026-11-02T08:00:00Z', detail: { cause: 'activity' } },
  { id: 6, type: 'acknowledged', at: '2026-10-30T10:01:00Z', detail: { alerts: 40, failed: 0 } },
  { id: 5, type: 'decided', at: '2026-10-30T10:00:00Z', detail: { decision: 'closed', reason: 'accepted_risk', by: 'analyst-2' } },
  ...(CAMPAIGN_WAITS.changes ?? []),
];

/** The campaign that admin closed. */
export const CAMPAIGN_CLOSED: CampaignDetail = {
  ...CAMPAIGN,
  decision: { type: 'closed', reason: 'test_over', note: 'The red team test ended on 2026-11-14.', by: 'admin', at: CLOSE_AT },
  waitsSince: null,
  changes: CLOSED_CHANGES,
};

// ── The authorization on a campaign ─────────────────────────────────────────
//
// admin authorized the campaign on 2026-11-14 for actor-a and web-1. The
// expiry sits seven days after now, so the record stays in force whatever day
// the suite runs. Four investigations are inside. One investigation is
// outside: web-1 acted on 192.0.2.30, a machine that the record does not list.
// An analyst excluded one investigation.

export const AUTH_AT = '2026-11-14T21:00:00Z';
const DAY = 86_400_000;

/** An expiry `days` after now, as the server sends it. */
export function expiryIn(days: number): string {
  return new Date(Math.floor((Date.now() + days * DAY) / 60_000) * 60_000).toISOString();
}

export const AUTHORIZATION: CampaignAuthorizationRecord = {
  id: 11,
  label: 'Red team test',
  note: 'Ticket RT-42.',
  by: 'admin',
  at: AUTH_AT,
  startsAt: CAMPAIGN.firstEvent,
  expiresAt: expiryIn(7),
  state: 'active',
  machineKeys: [ACTOR.machineKey, TARGET.machineKey],
  inside: 4,
  outside: 1,
};

/** The investigation outside the authorization: web-1 against 192.0.2.30. */
export const BEYOND_MEMBER: CampaignMember = {
  ...MEMBER,
  runId: 'run-beyond',
  label: 'ET EXPLOIT SMB probe',
  link: 'target_source',
  stage: 'attempt',
  direction: 'beyond',
  eventAt: '2026-10-29T08:00:00Z',
  sourceAddress: '192.0.2.20',
  targetAddress: '192.0.2.30',
  sourceKey: TARGET.machineKey,
  targetKey: BEYOND_KEY,
  evidence: { ...MEMBER.evidence, machineKey: TARGET.machineKey, machineName: 'web-1' },
  authorized: false,
};

export const BEYOND_RUN: CampaignBeyondRun = {
  runId: BEYOND_MEMBER.runId,
  label: BEYOND_MEMBER.label,
  eventAt: BEYOND_MEMBER.eventAt,
  sourceKey: TARGET.machineKey,
  targetKey: BEYOND_KEY,
  why: 'target',
};

export const EXCLUDED_RUN: CampaignExcludedRun = {
  runId: 'run-excluded',
  label: 'ET INFO curl download',
  by: 'analyst-2',
  at: '2026-11-14T21:30:00Z',
  reason: 'A backup job of the operator.',
};

/** The campaign that admin authorized. */
export const CAMPAIGN_AUTHORIZED: CampaignDetail = {
  ...CAMPAIGN,
  authorizations: [],
  decision: { type: 'authorized', note: 'Ticket RT-42.', by: 'admin', at: AUTH_AT },
  waitsSince: null,
  authorization: AUTHORIZATION,
  members: [...MEMBERS.map((m) => (m.verdictDiffers ? m : { ...m, authorized: true })), BEYOND_MEMBER],
  graph: {
    edges: [
      ...CAMPAIGN.graph.edges,
      edge(TARGET.machineKey, BEYOND_KEY, {
        beyond: true,
        stage: 'attempt',
        firstAt: '2026-10-29T08:00:00Z',
        lastAt: '2026-10-29T08:00:00Z',
      }),
    ],
  },
  beyond: [BEYOND_RUN],
  excluded: [EXCLUDED_RUN],
  changes: [
    { id: 22, type: 'excluded', at: EXCLUDED_RUN.at, detail: { runId: EXCLUDED_RUN.runId, by: 'analyst-2' } },
    { id: 21, type: 'beyond', at: '2026-11-14T21:05:00Z', detail: { runId: BEYOND_RUN.runId, why: 'target' } },
    { id: 20, type: 'decided', at: AUTH_AT, detail: { decision: 'authorized', by: 'admin' } },
    ...(CAMPAIGN_WAITS.changes ?? []),
  ],
};

// ── The leads and the hunts of a campaign ───────────────────────────────────
//
// The seed formed lead 12 before the campaign existed, and the lead loop
// hunted it at 01:16 on 2026-10-24. Lead 13 is a second lead of the campaign:
// its observations are alerts of investigations that the campaign holds, so
// it has no hunt of its own. The schedule hunted on 2026-10-26. The stage
// change of 22:50 on 2026-10-28 started one campaign hunt. Lead 14 is on
// web-1 with an observation of another type: it is related and keeps normal
// handling.

export const CAMPAIGN_LEADS: CampaignLead[] = [
  { id: 12, title: 'Lead 12: actor-a on web-1', state: 'hunting', hunted: true, related: false },
  { id: 13, title: 'Lead 13: web-1', state: 'open', hunted: false, related: false },
  { id: 14, title: 'Lead 14: web-1 talks to a rare external address', state: 'open', hunted: false, related: true },
];

export const CAMPAIGN_HUNTS: CampaignHunt[] = [
  { id: 'hunt-stage', starter: 'campaign', status: 'complete', startedAt: '2026-10-28T22:52:00Z', findings: 2, threatFindings: 1 },
  { id: 'hunt-schedule', starter: 'schedule', status: 'complete', startedAt: '2026-10-26T06:00:00Z', findings: 4, threatFindings: 0 },
  { id: 'hunt-seed', starter: 'lead', status: 'complete', startedAt: '2026-10-24T01:16:00Z', findings: 3, threatFindings: 1 },
];

/** The campaign with its leads, its hunts and the changes that started them. */
export const CAMPAIGN_HUNTED: CampaignDetail = {
  ...CAMPAIGN_WAITS,
  leads: CAMPAIGN_LEADS,
  hunts: CAMPAIGN_HUNTS,
};

// ── The case of a campaign ──────────────────────────────────────────────────
//
// analyst-2 opened one Security Onion case for the campaign on 2026-11-15 at
// 09:00. soc-ai attached 21 alerts. The stage went from Attempt to Action
// later, and a new machine joined: soc-ai added one comment for each. The
// pending form asked for the case and could not read the answer. The failed
// form holds the refusal of Security Onion and no decision.

export const CASE_AT = '2026-11-15T09:00:00Z';
export const CASE_ID = 'case-0c41';
export const CASE_URL = 'https://so.example.test/#/case/case-0c41';

/** The campaign of a server that knows the case, with no case yet. */
export const CAMPAIGN_CASE_READY: CampaignDetail = { ...CAMPAIGN_WAITS, case: null };

export const CASE_CHANGES: CampaignChange[] = [
  { id: 34, type: 'case_comment', at: '2026-11-16T07:30:00Z', detail: { caseId: CASE_ID, for: 'party' } },
  { id: 33, type: 'case_comment', at: '2026-11-15T22:10:00Z', detail: { caseId: CASE_ID, for: 'stage' } },
  { id: 32, type: 'case', at: CASE_AT, detail: { caseId: CASE_ID, alerts: 21, by: 'analyst-2' } },
  { id: 31, type: 'case_intent', at: '2026-11-15T08:59:58Z', detail: { by: 'analyst-2' } },
  { id: 30, type: 'case_failed', at: '2026-11-15T08:40:00Z', detail: { reason: 'Security Onion answered 503' } },
  ...(CAMPAIGN_WAITS.changes ?? []),
];

/** The campaign with its one case. */
export const CAMPAIGN_CASE: CampaignDetail = {
  ...CAMPAIGN,
  decision: { type: 'case', note: 'Ticket IR-7.', by: 'analyst-2', at: CASE_AT },
  waitsSince: null,
  case: { id: CASE_ID, url: CASE_URL, openedAt: CASE_AT, by: 'analyst-2', alerts: 21, comments: 2, state: 'open', failure: null },
  changes: CASE_CHANGES,
};

/** The campaign whose request for a case has no readable answer. */
export const CAMPAIGN_CASE_PENDING: CampaignDetail = {
  ...CAMPAIGN_WAITS,
  case: { id: null, url: null, openedAt: CASE_AT, by: 'analyst-2', alerts: null, comments: 0, state: 'pending', failure: null },
};

/** The campaign whose case Security Onion refused. */
export const CAMPAIGN_CASE_FAILED: CampaignDetail = {
  ...CAMPAIGN_WAITS,
  case: {
    id: null,
    url: null,
    openedAt: CASE_AT,
    by: 'analyst-2',
    alerts: null,
    comments: 0,
    state: 'failed',
    failure: 'Security Onion answered 503',
  },
};
