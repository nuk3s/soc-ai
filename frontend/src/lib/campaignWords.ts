// ---------------------------------------------------------------------------
// The words of a campaign: one label for each stored value, and the sentences
// the campaign page builds from the structure.
//
// One map per value, so the list page, the campaign page and a later surface
// say the same word. The stored value stays in the API and in the address.
// ---------------------------------------------------------------------------

import { UNKNOWN } from '../components/Kpi';
import type {
  CampaignAuthorization,
  CampaignAuthorizationRecord,
  CampaignBeyondWhy,
  CampaignChange,
  CampaignChangeDetail,
  CampaignCloseScope,
  CampaignCloseReason,
  CampaignDecision,
  CampaignDetection,
  CampaignEvents,
  CampaignEventsSource,
  CampaignJoin,
  CampaignLink,
  CampaignMember,
  CampaignMemberKind,
  CampaignNamedHost,
  CampaignParty,
  CampaignRelatedSession,
  CampaignRole,
  CampaignStage,
  CampaignStatus,
  CampaignTier,
  HostCampaignRole,
  InvestigationCampaign,
} from './api';
import { plural } from './plural';
import { formatDuration, utcStamp, utcWindow } from './timeRange';

/** The five stages, lowest first. */
export const STAGE_ORDER: readonly CampaignStage[] = [
  'reconnaissance',
  'attempt',
  'access',
  'action',
  'movement',
];

export const STAGE_LABEL: Record<CampaignStage, string> = {
  reconnaissance: 'Reconnaissance',
  attempt: 'Attempt',
  access: 'Access',
  action: 'Action on the target',
  movement: 'Movement beyond the target',
};

/** The links in the order the engine tries them, the seed first. */
export const LINK_ORDER: readonly CampaignLink[] = [
  'seed',
  'session',
  'actor',
  'artifact',
  'documents',
  'target_source',
  'named_pair',
  'included',
];

export const LINK_LABEL: Record<CampaignLink, string> = {
  seed: 'First confirmed attack',
  session: 'Same connection',
  actor: 'Same attacking machine',
  artifact: 'Same rule, CVE or request',
  documents: 'Same records',
  target_source: 'The target then acted',
  named_pair: 'Named by the finding',
  included: 'Included by an analyst',
};

export const ROLE_LABEL: Record<CampaignRole, string> = {
  actor: 'Actor',
  target: 'Target',
};

/** The part a machine plays in a campaign, on its host page. */
export const HOST_ROLE_LABEL: Record<HostCampaignRole, string> = {
  actor: 'Actor',
  target: 'Target',
  both: 'Actor and target',
};

/** How soc-ai knows the machine behind an address. */
export const JOIN_LABEL: Record<CampaignJoin, string> = {
  agent: 'agent report',
  dhcp: 'DHCP lease',
  network: 'network record',
};

export const TIER_LABEL: Record<CampaignTier, string> = {
  alert: 'Alert',
  analytic: 'Analytic',
  scheduled_hunt: 'Scheduled hunt',
  lead_hunt: 'Lead hunt',
  hunt: 'Hunt',
};

export const STATUS_LABEL: Record<CampaignStatus, string> = {
  open: 'Open',
  ended: 'Ended',
  withdrawn: 'Withdrawn',
  merged: 'Merged',
};

/** The type of an investigation of the campaign. */
export const MEMBER_TYPE_LABEL: Record<CampaignMemberKind, string> = {
  alert: 'Alert',
  finding: 'Finding',
  lead: 'Lead',
};

/** The word for a value off its map: the stored word itself. A new value
 *  from a newer server reads as its own word and does not take the page down. */
function label<K extends string>(map: Record<K, string>, value: K): string {
  return map[value] ?? String(value);
}

export const stageLabel = (s: CampaignStage) => label(STAGE_LABEL, s);
export const linkLabel = (l: CampaignLink) => label(LINK_LABEL, l);
export const roleLabel = (r: CampaignRole) => label(ROLE_LABEL, r);
export const hostRoleLabel = (r: HostCampaignRole) => label(HOST_ROLE_LABEL, r);
export const joinLabel = (j: CampaignJoin) => label(JOIN_LABEL, j);
export const tierLabel = (t: CampaignTier) => label(TIER_LABEL, t);
export const statusLabel = (s: CampaignStatus) => label(STATUS_LABEL, s);
export const memberTypeLabel = (k: CampaignMemberKind) => label(MEMBER_TYPE_LABEL, k);

/** The name of a machine: its name, then its address, then its key. */
export function partyName(p: {
  machineKey: string;
  name: string | null;
  address?: string | null;
  addresses?: string[];
}): string {
  return p.name?.trim() || p.address || p.addresses?.[0] || p.machineKey;
}

/** Why the investigation is part of the campaign, in one or two sentences.
 *  `names` maps a machine key to the name of its machine, for evidence that
 *  names no machine. `labels` maps a run id to the label of that
 *  investigation: the sentence then names the other investigation by its
 *  label. An id tells the analyst nothing. */
export function linkSentence(
  member: Pick<CampaignMember, 'link' | 'evidence'>,
  names: Readonly<Record<string, string>> = {},
  labels: Readonly<Record<string, string>> = {},
): string {
  const e = member.evidence;
  const label = e.memberRunId ? labels[e.memberRunId]?.trim() : '';
  const other = label ? `"${label}"` : e.memberRunId || UNKNOWN;
  const machine =
    e.machineName?.trim() || (e.machineKey ? (names[e.machineKey] ?? e.machineKey) : UNKNOWN);
  switch (member.link) {
    case 'seed':
      return 'This investigation is the first confirmed attack. It started the campaign.';
    case 'session':
      return `This investigation shares the connection ${e.communityId || UNKNOWN} with the investigation ${other}.`;
    case 'actor':
      return `The attacking machine ${machine} is the source of this investigation and of the investigation ${other}.`;
    case 'artifact':
      return `This investigation shares ${e.artifact || UNKNOWN} with the investigation ${other}.`;
    case 'documents':
      return 'Each record that this investigation cites is between machines of the campaign.';
    case 'target_source':
      return `${machine} is a target of the campaign. Then ${machine} acted as the source of this investigation.`;
    case 'named_pair':
      return `The finding names ${machine} and the target, and it cites no single record. The investigation ${other} proves an attack of ${machine} on that target.`;
    case 'included':
      return `An analyst included this investigation in the campaign of the investigation ${other}.`;
    default:
      return '';
  }
}

/** What soc-ai can read on the machine. */
export function coverageSentence(party: Pick<CampaignParty, 'hasAgent'>): string {
  return party.hasAgent
    ? 'This machine has an agent.'
    : 'This machine has no agent. soc-ai cannot read processes or files on it.';
}

/** The tier that saw a stage first, and the time from the event to the
 *  verdict. A row with no span states the tier alone. */
export function detectionSentence(row: Pick<CampaignDetection, 'tier' | 'seconds'>): string {
  const first = `${tierLabel(row.tier)} saw it first.`;
  const span = formatDuration(row.seconds);
  return span ? `${first} The verdict came ${span} after the event.` : first;
}

/** One authorization line under the bottom line of a campaign. `total` is
 *  the count of the investigations of the campaign. */
export function authorizationSentence(a: CampaignAuthorization, total: number): string {
  if (a.state !== 'active') return `The authorization ${a.label} is ${a.state}.`;
  return (
    `The authorization ${a.label} covers ${a.memberRuns.toLocaleString()} of the ` +
    `${plural(total, 'investigation')}. It expires ${utcStamp(a.expiresAt)}.`
  );
}

/** The words of one session line after the two machine names, which the page
 *  renders as links: " port 22: 14 documents, 2026-10-23 03:10 to 03:40 UTC." */
export function sessionTail(s: Pick<CampaignRelatedSession, 'port' | 'documents' | 'firstAt' | 'lastAt'>): string {
  const port = s.port != null ? ` port ${s.port}` : '';
  return `${port}: ${plural(s.documents, 'document')}, ${utcWindow(s.firstAt, s.lastAt)}.`;
}

/** One named host under "Related, not proven". */
export function namedSentence(n: CampaignNamedHost): string {
  return (
    `${n.value}: named in ${plural(n.documents, 'document')} of the campaign. ` +
    'No stored document shows a target in a connection to it.'
  );
}

/** The alerts from a target that soc-ai judged false positive. Empty for none. */
export function falsePositiveSentence(count: number): string {
  if (count <= 0) return '';
  return count === 1
    ? 'soc-ai judged 1 alert from a target as false positive. It is no part of the campaign.'
    : `soc-ai judged ${plural(count, 'alert')} from a target as false positive. They are no part of the campaign.`;
}

export const alertsWords = (n: number) => plural(n, 'alert');
export const findingsWords = (n: number) => plural(n, 'finding');

/** The alerts of an arrow and the count of its rules: "47 alerts of 3 rules". */
export function alertsOfRules(alerts: number, rules: number): string {
  return `${alertsWords(alerts)} of ${plural(rules, 'rule')}`;
}

/** The alerts between two machines that no confirmed rule holds. Empty for none. */
export function otherAlertsSentence(n: number): string {
  return n > 0 ? `soc-ai did not confirm ${plural(n, 'other alert')} between these machines.` : '';
}

/** Every grid record between the two machines of an arrow. */
export function recordsSentence(n: number): string {
  return `${plural(n, 'grid record')} between the two machines.`;
}

/** The line of facts under the bottom line. Empty when the campaign holds no events. */
export function eventsFacts(events: CampaignEvents | null | undefined): string {
  if (!events) return '';
  const findings = `${plural(events.findings ?? 0, 'hunt finding')}.`;
  if (events.source === 'grid') {
    const records =
      typeof events.records === 'number'
        ? ` ${plural(events.records, 'grid record')} between the machines.`
        : '';
    return `${alertsOfRules(events.alerts ?? 0, events.rules ?? 0)}. ${findings}${records}`;
  }
  if (events.source === 'stored') {
    return `${plural(events.alerts ?? 0, 'alert event')} that the investigations hold. ${findings}`;
  }
  return '';
}

/** The line above the timeline. Empty for a source with no timeline. */
export function timelineNote(source: CampaignEventsSource | null | undefined): string {
  const tail = 'Times are in UTC. Drag across the chart to zoom in.';
  if (source === 'grid') return `The marks count the alert events of the grid. ${tail}`;
  if (source === 'stored') {
    return `soc-ai could not read the grid. The marks count the alert events that its investigations hold. ${tail}`;
  }
  return '';
}

/** The highest stage that a finding inside a mark proves. */
export function provedWords(stage: CampaignStage): string {
  return `soc-ai proved: ${stageLabel(stage)}`;
}

export const RELATED_EMPTY = 'soc-ai found no related investigation, session or host.';
export const VERDICT_STANDS = 'This investigation is on a session of the campaign. Its verdict stands.';
export const NOT_SEEN = 'Not seen';
export const BEYOND_MARK = 'Beyond the first target';
/** The link from a finding to the hunt that found it. */
export const VIEW_HUNT = 'View hunt';
/** The link from a reached stage to the investigation that proves it. */
export const VIEW_EVIDENCE = 'View the evidence';
/** The verdict cell of a rule that no investigation judged. */
export const NOT_JUDGED = 'Not judged';
export const CAMPAIGNS_EMPTY =
  'No campaign. A campaign forms from a true positive alert or finding with a known source machine and target machine.';

export const NO_PROVEN_STAGE = 'No proven stage';

/** The words of the stage meter: "Stage reached: Access, 3 of 5". A stage off
 *  the sequence, from a newer server, reads as its own word with no place. */
export function stageMeterWords(stage: CampaignStage | null | undefined): string {
  const head = stageReachedWords(stage);
  const place = stage ? STAGE_ORDER.indexOf(stage) : -1;
  return place < 0 ? head : `${head}, ${place + 1} of ${STAGE_ORDER.length}`;
}

/** The word on the chip of a row that is part of a campaign. */
export const CAMPAIGN_CHIP_WORD = 'Campaign';

/** The hover text of a row whose verdict differs from its campaign. */
export const CHIP_DIFFERS = 'Same session as this campaign. The verdict differs.';

/** The accessible name and the hover text of the campaign chip of a row: the
 *  title and the stage, and the differs sentence when the verdict differs. */
export function campaignChipWords(c: Pick<InvestigationCampaign, 'title' | 'stage' | 'differs'>): string {
  const head = `Campaign: ${c.title.trim()}. ${stageMeterWords(c.stage)}.`;
  return c.differs ? `${head} ${CHIP_DIFFERS}` : head;
}

/** The stage in words with no place: "Stage reached: Access". */
export function stageReachedWords(stage: CampaignStage | null | undefined): string {
  return stage ? `Stage reached: ${stageLabel(stage)}` : NO_PROVEN_STAGE;
}

/** The link from a page that names a campaign to the campaign page. */
export const OPEN_CAMPAIGN = 'Open the campaign';

/** The two halves of the sentence of the campaign strip, around the title:
 *  "Part of the campaign {title}." or, for a verdict that differs, "Same
 *  session as the campaign {title}. The verdict differs." */
export function campaignStripWords(differs: boolean): { before: string; after: string } {
  return differs
    ? { before: 'Same session as the campaign ', after: '. The verdict differs.' }
    : { before: 'Part of the campaign ', after: '.' };
}

/** "and 4 more" after the targets of a list row. Empty for none. */
export function moreWords(n: number): string {
  return n > 0 ? `and ${n} more` : '';
}

// ── Decisions ───────────────────────────────────────────────────────────────

/** The reasons of a close, in the order the dialog lists them. */
export const CLOSE_REASONS: readonly CampaignCloseReason[] = ['handled_outside', 'accepted_risk', 'test_over'];

export const CLOSE_REASON_LABEL: Record<CampaignCloseReason, string> = {
  handled_outside: 'Handled outside soc-ai',
  accepted_risk: 'Accepted risk',
  test_over: 'Test that is over',
};

export const closeReasonLabel = (r: CampaignCloseReason) => label(CLOSE_REASON_LABEL, r);

/** The button that opens the close dialog. */
export const CLOSE_ACTION = 'Close with a reason';
/** The button that clears a close. */
export const REOPEN_ACTION = 'Open again';
export const ACKNOWLEDGE_REST_ACTION = 'Acknowledge the remaining alerts';
/** What a press of Open again writes, stated before the press. */
export const REOPEN_CONFIRM =
  'Open again clears the close. The campaign then waits on your decision. soc-ai writes an audit record.';
export const DECISION_FAILED = 'soc-ai did not store the decision. Try again.';

/** The state line of a campaign with no decision. */
export function waitsSentence(since: string | null | undefined): string {
  return since
    ? `This campaign waits on your decision since ${utcStamp(since)}.`
    : 'This campaign waits on your decision.';
}

/** The state line of a decision: "admin closed this campaign on 2026-11-14
 *  21:00 UTC. Reason: Test that is over." */
export function decisionSentence(d: Pick<CampaignDecision, 'type' | 'reason' | 'by' | 'at'>): string {
  const who = d.by?.trim() || 'An analyst';
  const when = utcStamp(d.at);
  switch (d.type) {
    case 'closed': {
      const reason = d.reason ? ` Reason: ${closeReasonLabel(d.reason)}.` : '';
      return `${who} closed this campaign on ${when}.${reason}`;
    }
    case 'authorized':
      return `${who} authorized this campaign on ${when}.`;
    case 'case':
      return `${who} opened a Security Onion case for this campaign on ${when}.`;
    default:
      return `${who} decided on this campaign on ${when}.`;
  }
}

// ── The case of a campaign ──────────────────────────────────────────────────

/** The button that opens the dialog of the case. */
export const CASE_ACTION = 'Open one case';
/** The link to the page of the case in Security Onion. */
export const CASE_LINK = 'Open the case';
/** The button that clears a request whose answer soc-ai could not read. */
export const CASE_RETRY_ACTION = 'Try again';
/** The state line of a request whose answer soc-ai could not read. */
export const CASE_PENDING = 'soc-ai could not read the answer of Security Onion.';
export const CASE_PENDING_DETAIL =
  'The case can exist in Security Onion. soc-ai sends no second request while the answer is unknown.';
export const CASE_FAILED = 'Security Onion refused the case. soc-ai holds no case for this campaign.';
/** What a press of Open again writes on a campaign with a case. */
export const CASE_REOPEN_CONFIRM =
  'Open again clears the decision. The case stays in Security Onion, and a later Open one case finds it. The campaign then waits on your decision. soc-ai writes an audit record.';
export const CASE_RETRY_FAILED = 'soc-ai did not clear the request. Try again.';

/** The title of the case in Security Onion: "soc-ai campaign: {title}". */
export function caseTitleWords(title: string): string {
  return `soc-ai campaign: ${title.trim()}`;
}

/** What a press of Try again writes, stated before the press. */
export function caseRetryConfirm(title: string): string {
  return (
    'Look at the Cases page of Security Onion first. ' +
    `Press Try again only if no case has the title "${caseTitleWords(title)}". ` +
    'Try again clears the request and writes an audit record. You can then open the case again.'
  );
}

/** The state line of a campaign with a case: "A case is open in Security
 *  Onion since 2026-11-15 09:00 UTC, opened by analyst-2." */
export function caseOpenSentence(
  c: { openedAt?: string | null; by?: string | null } | null | undefined,
  decision?: Pick<CampaignDecision, 'by' | 'at'> | null,
): string {
  const who = c?.by?.trim() || decision?.by?.trim() || 'an analyst';
  return `A case is open in Security Onion since ${utcStamp(c?.openedAt || decision?.at || null)}, opened by ${who}.`;
}

/** The line of a request whose answer soc-ai could not read: when, and who asked. */
export function casePendingSince(c: { openedAt?: string | null; by?: string | null }): string {
  if (!c.openedAt) return '';
  const who = c.by?.trim();
  return who
    ? `${who} asked for the case on ${utcStamp(c.openedAt)}.`
    : `soc-ai asked for the case on ${utcStamp(c.openedAt)}.`;
}

/** The reason of a refused case: "Reason: Security Onion answered 500." */
export function caseFailureWords(failure: string | null | undefined): string {
  const text = failure?.trim();
  if (!text) return '';
  return `Reason: ${text}${/[.!?]$/.test(text) ? '' : '.'}`;
}

/** "21 alerts attached". */
export function caseAttachedWords(n: number): string {
  return `${plural(n, 'alert')} attached`;
}

/** "2 comments by soc-ai". */
export function caseCommentsWords(n: number): string {
  return `${plural(n, 'comment')} by soc-ai`;
}

// The dialog "Open one case". It shows the case as Security Onion holds it,
// and what the press writes, before the press.
export const CASE_TITLE = 'Open one case';
export const CASE_INTRO = 'The press writes one case to Security Onion. The box shows the case as Security Onion holds it.';
export const CASE_HELD_HEADING = 'The case in Security Onion';
export const CASE_READING = 'soc-ai counts the alerts for the case.';
export const CASE_UNREAD = 'soc-ai cannot count the alerts for the case.';
export const CASE_ALERTS_RULE =
  'soc-ai takes the alerts of the true positive alert investigations, the newest first, and at most 25.';
export const CASE_SKIPPED_HEADING = 'Skipped';
export const CASE_NOTE_TAIL = 'A note is optional. It goes into the description of the case.';
export const CASE_SUBMIT_EXISTING = 'Record the case';
export const CASE_OPEN_FAILED = 'soc-ai did not open the case. Try again.';

/** "21 alerts go on the case." A count soc-ai cannot read is no zero. */
export function caseAlertsSentence(n: number | null): string {
  if (n === null) return CASE_UNREAD;
  if (n === 0) return 'No alert goes on the case.';
  return n === 1 ? '1 alert goes on the case.' : `${n.toLocaleString()} alerts go on the case.`;
}

/** The line under a count that reached the cap of the server. */
export function caseCappedSentence(n: number): string {
  return `The campaign holds more alerts. The case takes the ${n.toLocaleString()} newest.`;
}

/** The alerts that the case skips, one sentence for each reason with a count. */
export function caseSkippedLines(s: { acknowledged: number; escalated: number; noAlert: number }): string[] {
  const out: string[] = [];
  if (s.acknowledged > 0) {
    out.push(s.acknowledged === 1 ? '1 alert is acknowledged.' : `${plural(s.acknowledged, 'alert')} are acknowledged.`);
  }
  if (s.escalated > 0) {
    out.push(s.escalated === 1 ? '1 alert is on a case.' : `${plural(s.escalated, 'alert')} are on a case.`);
  }
  if (s.noAlert > 0) {
    out.push(
      s.noAlert === 1
        ? '1 record is not a Security Onion alert.'
        : `${plural(s.noAlert, 'record')} are not Security Onion alerts.`,
    );
  }
  return out;
}

/** The case that the campaign holds already. */
export function caseExistingSentence(id: string): string {
  return `Security Onion holds the case ${id} of this campaign.`;
}

/** What the press of "Open one case" writes. `alerts` is the count of the
 *  scope, or null when soc-ai cannot read it. A campaign with a case gets no
 *  second one. */
export function caseWritesLines(alerts: number | null, existing: boolean): string[] {
  if (existing) {
    return [
      'The press opens no second case in Security Onion.',
      'soc-ai records the decision Case on the campaign and one audit record.',
    ];
  }
  const what =
    alerts === 0
      ? 'soc-ai writes one case with no alert and one audit record.'
      : `soc-ai writes one case, ${
          alerts === null ? 'the alerts that soc-ai can read' : alertsWords(alerts)
        } acknowledged and escalated, and one audit record.`;
  return [
    'The press writes to Security Onion.',
    what,
    'A higher stage or a new machine adds one comment to the case.',
    'A case changes no verdict.',
  ];
}

// ── The authorization on a campaign ─────────────────────────────────────────

/** The button that opens the dialog of an authorization. Admin only. */
export const AUTHORIZE_ACTION = 'Record authorized activity';
/** The button that revokes the authorization. */
export const REVOKE_ACTION = 'Revoke';
/** What a revoke writes, stated before the press. */
export const REVOKE_CONFIRM =
  'Revoke clears the mark of each investigation inside. The campaign then waits on your decision as one item. soc-ai writes an audit record.';
export const REASON_REQUIRED = 'A reason is required.';

/** True when the expiry is in the past at `now`, or the server states it. */
export function authorizationExpired(
  a: Pick<CampaignAuthorizationRecord, 'state' | 'expiresAt'>,
  now: number = Date.now(),
): boolean {
  if (a.state === 'expired') return true;
  const t = Date.parse(a.expiresAt);
  return !Number.isNaN(t) && t <= now;
}

/** The state line of an authorized campaign: "admin authorized this campaign
 *  on 2026-11-14 21:00 UTC: Red team test. It expires 2026-11-21 21:00 UTC." */
export function authorizedSentence(
  a: Pick<CampaignAuthorizationRecord, 'label' | 'by' | 'at' | 'expiresAt' | 'state'>,
  decision?: Pick<CampaignDecision, 'by' | 'at'> | null,
  now: number = Date.now(),
): string {
  const who = a.by?.trim() || decision?.by?.trim() || 'An analyst';
  const when = utcStamp(a.at || decision?.at || null);
  const label = a.label.trim();
  const head = label
    ? `${who} authorized this campaign on ${when}: ${label}.`
    : `${who} authorized this campaign on ${when}.`;
  if (a.state === 'revoked') return `${head} The authorization is revoked.`;
  return authorizationExpired(a, now)
    ? `${head} It expired ${utcStamp(a.expiresAt)}.`
    : `${head} It expires ${utcStamp(a.expiresAt)}.`;
}

/** "47 investigations inside". */
export function insideWords(n: number): string {
  return `${plural(n, 'investigation')} inside`;
}

// "Activity beyond the authorization": the one alarm of an authorized campaign.
export const BEYOND_TITLE = 'Activity beyond the authorization';
export const BEYOND_TAIL = 'Each one keeps normal handling. Its actions wait on you, and it raises its bell row.';
export const BEYOND_SHOW = 'Show the investigations';

/** "Activity beyond the authorization: 2 investigations." */
export function beyondSentence(n: number): string {
  return `${BEYOND_TITLE}: ${plural(n, 'investigation')}.`;
}

export const BEYOND_WHY_LABEL: Record<CampaignBeyondWhy, string> = {
  source: 'The source is not a listed machine.',
  target: 'The target is not a listed machine.',
  expired: 'The event is after the expiry of the authorization.',
  machine: 'The investigation names a machine that the authorization does not list.',
};

export const beyondWhyWords = (w: CampaignBeyondWhy) => label(BEYOND_WHY_LABEL, w);

/** The words of the graphics for an authorization. */
export const LISTED_MARK = 'Listed in the authorization';
export const OUTSIDE_MARK = 'Beyond the authorization';

/** The line of an arrow tooltip for the investigations outside. */
export function outsideLinkSentence(n: number): string {
  return `${OUTSIDE_MARK}: ${plural(n, 'investigation')}.`;
}

/** The name of the band of the period on the timeline. */
export function periodBandWords(label: string, startsAt: string, endsAt: string): string {
  const name = label.trim() ? `The period of the authorization ${label.trim()}` : 'The period of the authorization';
  return `${name}: ${utcWindow(startsAt, endsAt)}.`;
}

/** The word of the expiry beside its mark on the timeline. */
export function expiryMarkLabel(expired: boolean): string {
  return expired ? 'Expired' : 'Expires';
}

// Exclude, Include and Undo on the folds of the campaign page. Each one
// states what it writes before the press.
export const EXCLUDE_ACTION = 'Exclude';
export const EXCLUDE_CONFIRM =
  'Exclude takes this investigation out of the campaign. It then gets normal handling: its actions wait on you, and it is a Needs you item of its own. soc-ai writes an audit record.';
export const INCLUDE_ACTION = 'Include';
export const INCLUDE_CONFIRM =
  'Include joins this investigation to the campaign. The campaign then holds it. soc-ai writes an audit record.';
export const UNDO_ACTION = 'Undo';
export const UNDO_EXCLUDE_CONFIRM =
  'Undo clears the exclude. The campaign can hold this investigation again. soc-ai writes an audit record.';
export const UNDO_INCLUDE_CONFIRM =
  'Undo clears the include. The investigation then joins the campaign only by a link of its own. soc-ai writes an audit record.';
export const EXCLUDED_TITLE = 'Excluded';
export const AUTHORIZED_CHIP = 'Authorized';
export const AUTHORIZED_CHIP_TITLE = 'The authorization of the campaign covers this investigation.';
export const INCLUDED_CHIP = 'Included';
export const INCLUDED_CHIP_TITLE = 'An analyst included this investigation in the campaign.';
export const OVERRIDE_FAILED = 'soc-ai did not store the change. Try again.';

/** The line of one excluded investigation: "analyst-2 excluded it on
 *  2026-11-14 21:30 UTC. Reason: A backup job." */
export function excludedSentence(e: { by: string | null; at: string; reason: string }): string {
  const who = e.by?.trim() || 'An analyst';
  const reason = e.reason.trim();
  return `${who} excluded it on ${utcStamp(e.at)}.${reason ? ` Reason: ${reason}` : ''}${reason && !/[.!?]$/.test(reason) ? '.' : ''}`;
}

// The dialog "Record authorized activity". It states what the press writes
// before the press, and what stays loud as plainly as what goes quiet.
export const AUTHORIZE_TITLE = 'Record authorized activity';
export const AUTHORIZE_READING = 'soc-ai reads the machines and the investigations of the campaign.';
export const AUTHORIZE_ADMIN_ONLY = 'Only an admin can record authorized activity.';
export const AUTHORIZE_DRAFT_FAILED = 'soc-ai could not read the campaign for the authorization. Try again.';
export const AUTHORIZE_FAILED = 'soc-ai did not store the authorization. Try again.';
export const AUTHORIZE_NEEDS_BOTH = 'List at least one actor and one target.';
export const AUTHORIZE_LABEL_REQUIRED = 'A label is required.';
export const AUTHORIZE_LISTED = 'Listed';
export const AUTHORIZE_NOT_LISTED = 'Not listed. Its investigations stay loud.';
export const AUTHORIZE_QUIET_TAIL = 'Their actions stop waiting. They raise no bell row, no webhook and no lead.';
export const AUTHORIZE_LOUD_TAIL = 'Each one waits on you, raises its bell row and its webhook, and forms its lead.';
export const AUTHORIZE_LATER =
  'A later event between listed machines is inside until the expiry. Any other event is outside and stays loud.';
export const AUTHORIZE_WRITES = [
  'soc-ai stores the authorization on the campaign and an audit record.',
  'soc-ai marks each investigation inside. The campaign holds the decision Authorized.',
  'No verdict changes. The model never reads an authorization.',
] as const;

/** "47 investigations are inside. 21 of them wait on a decision today." */
export function insideSentence(inside: number, waiting: number): string {
  const head = inside === 1 ? '1 investigation is inside.' : `${plural(inside, 'investigation')} are inside.`;
  if (inside === 0) return head;
  return waiting === 1
    ? `${head} 1 of them waits on a decision today.`
    : `${head} ${waiting.toLocaleString()} of them wait on a decision today.`;
}

/** "2 are outside and stay loud." */
export function outsideSentence(outside: number): string {
  return outside === 1 ? '1 is outside and stays loud.' : `${outside.toLocaleString()} are outside and stay loud.`;
}

/** The line over the counts when the admin unlisted a machine: the server
 *  counts the scope with every machine listed. */
export const COUNTS_ALL_LISTED = 'The counts are for the scope with every machine listed.';

/** The investigations of the campaign with an unlisted machine as an end. */
export function unlistedSentence(n: number): string {
  if (n <= 0) return 'No investigation of the campaign has an unlisted machine as the source or the target.';
  return n === 1
    ? '1 investigation has an unlisted machine as the source or the target. It is outside and stays loud.'
    : `${plural(n, 'investigation')} have an unlisted machine as the source or the target. They are outside and stay loud.`;
}

/** "The period: 2026-10-24 00:40 UTC to 2026-11-21 21:00 UTC." */
export function authorizationPeriodSentence(startsAt: string, expiresAt: string): string {
  return `The period: ${utcStamp(startsAt)} to ${utcStamp(expiresAt)}. The period starts at the first event of the campaign.`;
}

/** The line under the expiry field. */
export function expiryLimitSentence(maxExpiresAt: string): string {
  return `The latest expiry is ${utcStamp(maxExpiresAt)}.`;
}

/** Rule 9: a stored authorization with a rule list that covers part of the campaign. */
export function earlierRecordSentence(e: { label: string; covers: number; of: number }): string {
  return `The authorization ${e.label} covers ${e.covers.toLocaleString()} of ${plural(e.of, 'investigation')}.`;
}

/** The dialog of an investigation sends the admin to its campaign. */
export const ON_CAMPAIGN_ACTION = 'Record it on the campaign';

/** Why the dialog of an investigation sends the admin to its campaign. */
export function onCampaignWords(title: string): string {
  return (
    `This investigation is part of the campaign ${title.trim()}. ` +
    'Record the authorization on the campaign. It lists the machines and covers the alert investigations and the finding investigations of the campaign.'
  );
}

/** The note of a decision, as the analyst wrote it. Empty for no note. */
export function decisionNote(note: string | null | undefined): string {
  const text = note?.trim();
  return text ? `Note: ${text}` : '';
}

/** The result of the acknowledgement that followed a close. */
export function acknowledgedSentence(d: Pick<CampaignChangeDetail, 'alerts' | 'failed'>): string {
  const done = `soc-ai acknowledged ${plural(d.alerts ?? 0, 'alert')} in Security Onion.`;
  const failed = d.failed ?? 0;
  return failed > 0 ? `${done} soc-ai could not acknowledge ${plural(failed, 'alert')}.` : done;
}

// The close dialog. It states what the press writes before the press.
export const CLOSE_TITLE = 'Close the campaign';
export const CLOSE_SUBMIT = 'Close the campaign';
export const REOPENS_SENTENCE = 'New activity opens this campaign again.';
export const NO_VERDICT_CHANGE = 'A close changes no verdict.';
export const NOTE_OPTIONAL = 'A note is optional.';
export const SCOPE_COUNTING = 'soc-ai counts the alerts that the close acknowledges.';
export const SCOPE_UNREAD = 'soc-ai cannot read the count.';
export const SCOPE_NONE = 'No alert of this campaign waits for an acknowledgement.';

/** The label of the acknowledgement box: "Acknowledge 1,083 alerts of 7
 *  rules in Security Onion". With no count, the label names no number. */
export function acknowledgeLabel(scope: Pick<CampaignCloseScope, 'alerts' | 'rules'>): string {
  if (scope.alerts === null) return 'Acknowledge the alerts of the confirmed rules in Security Onion';
  const rules = typeof scope.rules === 'number' ? ` of ${plural(scope.rules, 'rule')}` : '';
  return `Acknowledge ${alertsWords(scope.alerts)}${rules} in Security Onion`;
}

/** The line under a count that reached the cap of the server. */
export function scopeCappedSentence(alerts: number): string {
  return `The count stops at ${alertsWords(alerts)}. More alerts can exist.`;
}

/** What the press of the close writes. `alerts` is the count of the scope,
 *  or null when soc-ai cannot read it. */
export function closeWritesSentence(acknowledge: boolean, alerts: number | null): string {
  const head = 'soc-ai stores the close and an audit record.';
  if (!acknowledge) return head;
  const what = alerts === null ? 'the alerts of the confirmed rules' : alertsWords(alerts);
  return `${head} Then soc-ai acknowledges ${what} in Security Onion.`;
}

// The changes of a campaign: the Changes fold and the markers of the timeline.

/** The word of a decision, a reopen, a case or a comment of soc-ai beside
 *  its marker on the timeline. */
export function changeMarkLabel(c: Pick<CampaignChange, 'type' | 'detail'>): string {
  if (c.type === 'reopened') return c.detail?.cause === 'revoked' ? 'Revoked' : 'Opened again';
  if (c.type === 'case') return 'Case';
  if (c.type === 'case_comment') return 'Comment';
  switch (c.detail.decision) {
    case 'authorized':
      return 'Authorized';
    case 'case':
      return 'Case';
    default:
      return 'Closed';
  }
}

/** One change of a campaign in one or two sentences. A type from a newer
 *  server reads as its own word. */
export function changeSentence(
  c: Pick<CampaignChange, 'type' | 'detail'>,
  labels: Readonly<Record<string, string>> = {},
): string {
  const d = c.detail ?? {};
  const who = d.by?.trim() || 'An analyst';
  // The change names its investigation by its label. An id tells the analyst nothing.
  const named = d.runId && labels[d.runId]?.trim() ? `the investigation "${labels[d.runId].trim()}"` : 'an investigation';
  switch (c.type) {
    case 'formed':
      return 'soc-ai formed the campaign.';
    case 'stage':
      return d.from && d.to
        ? `The stage went from ${stageLabel(d.from)} to ${stageLabel(d.to)}.`
        : d.to
          ? `The campaign reached the stage ${stageLabel(d.to)}.`
          : 'The campaign reached a higher stage.';
    case 'party': {
      const names = (d.names ?? []).filter((n) => n.trim());
      if (names.length === 0) return 'A new machine joined the campaign.';
      return names.length === 1
        ? `A new machine joined the campaign: ${names[0]}.`
        : `${names.length} new machines joined the campaign: ${names.join(', ')}.`;
    }
    case 'decided':
      if (d.decision === 'authorized') return `${who} authorized the campaign.`;
      if (d.decision === 'case') return `${who} opened a Security Onion case for the campaign.`;
      // A close stores one of the three reasons. The map reads any other value as its own word.
      return `${who} closed the campaign.${d.reason ? ` Reason: ${closeReasonLabel(d.reason as CampaignCloseReason)}.` : ''}`;
    case 'reopened':
      switch (d.cause) {
        case 'activity':
          return 'A later event opened the campaign again.';
        case 'stage':
          return 'A higher stage opened the campaign again.';
        case 'party':
          return 'A new machine opened the campaign again.';
        case 'analyst':
          return `${who} opened the campaign again.`;
        case 'revoked':
          return `${who} revoked the authorization. The campaign waits on a decision again.`;
        default:
          return 'The campaign opened again.';
      }
    case 'acknowledged':
      return acknowledgedSentence(d);
    case 'beyond': {
      const head = `${named.charAt(0).toUpperCase()}${named.slice(1)} is beyond the authorization.`;
      return d.why ? `${head} ${beyondWhyWords(d.why)}` : head;
    }
    case 'excluded':
      return `${who} excluded ${named} from the campaign.`;
    case 'included':
      return `${who} included ${named} in the campaign.`;
    case 'case_intent':
      return d.by?.trim() ? `${d.by.trim()} asked Security Onion for one case.` : 'soc-ai asked Security Onion for one case.';
    case 'case': {
      const theCase = d.caseId?.trim() ? `the case ${d.caseId.trim()}` : 'a case';
      const alerts =
        typeof d.alerts === 'number' ? (d.alerts === 0 ? ' with no alert' : ` with ${alertsWords(d.alerts)}`) : '';
      return `${who} opened ${theCase} in Security Onion${alerts}.`;
    }
    case 'case_failed': {
      const reason = caseFailureWords(typeof d.reason === 'string' ? d.reason : null);
      return reason ? `Security Onion refused the case. ${reason}` : 'Security Onion refused the case.';
    }
    case 'case_comment': {
      const theCase = d.caseId?.trim() ? `the case ${d.caseId.trim()}` : 'the case';
      const what = d.for === 'stage' ? ' for a higher stage' : d.for === 'party' ? ' for a new machine' : '';
      return `soc-ai added a comment to ${theCase}${what}.`;
    }
    default:
      return String(c.type);
  }
}

/** The accessible name of a marker on the timeline: the time and the change. */
export function changeMarkWords(c: Pick<CampaignChange, 'type' | 'detail' | 'at'>): string {
  return `${utcStamp(c.at)}: ${changeSentence(c)}`;
}

/** The chip of the decision state on a list row. */
export const DECISION_CHIP_LABEL = {
  waits: 'Waits on you',
  closed: 'Closed',
  authorized: 'Authorized',
  case: 'Case',
} as const;

/** The day of a time in UTC: "2026-11-22". */
function utcDay(iso: string): string {
  const t = new Date(iso);
  return Number.isNaN(t.getTime()) ? iso : t.toISOString().slice(0, 10);
}

/** The word of the decision chip of an authorized campaign with its expiry:
 *  "Authorized, expires 2026-11-22" or "Authorization expired 2026-11-22".
 *  A revoked record clears the decision, so it reads as the plain word. */
export function authorizedChipLabel(
  a: Pick<CampaignAuthorizationRecord, 'expiresAt' | 'state'>,
  now: number = Date.now(),
): string {
  if (a.state === 'revoked') return DECISION_CHIP_LABEL.authorized;
  return authorizationExpired(a, now)
    ? `Authorization expired ${utcDay(a.expiresAt)}`
    : `Authorized, expires ${utcDay(a.expiresAt)}`;
}

/** The hover text of an authorized chip with its expiry. */
export function authorizedChipTitle(a: Pick<CampaignAuthorizationRecord, 'expiresAt' | 'state'>, now: number = Date.now()): string {
  return authorizationExpired(a, now)
    ? `The authorization of this campaign expired ${utcStamp(a.expiresAt)}. A later event is beyond it.`
    : `An authorization covers this campaign until ${utcStamp(a.expiresAt)}. An investigation beyond it keeps normal handling.`;
}

/** The alarm of a list row: "2 beyond the authorization". */
export function beyondCountWords(n: number): string {
  return `${n.toLocaleString()} beyond the authorization`;
}

/** The hover text of the alarm of a list row. */
export function beyondCountTitle(n: number): string {
  return n === 1
    ? '1 investigation is beyond the authorization. It keeps normal handling and waits on you.'
    : `${plural(n, 'investigation')} are beyond the authorization. Each one keeps normal handling and waits on you.`;
}

/** The hover text of the decision chip. */
export const DECISION_CHIP_TITLE = {
  waits: 'This campaign waits on your decision. Open the campaign to decide.',
  closed: 'An analyst closed this campaign. New activity opens it again.',
  authorized: 'An authorization covers this campaign. An investigation beyond it keeps normal handling.',
  case: 'A Security Onion case is open for this campaign.',
} as const;

/** The word of the decision chip of a campaign with a case: "Case since
 *  2026-11-15". With no time, the plain word. */
export function caseChipLabel(openedAt: string | null | undefined): string {
  return openedAt ? `${DECISION_CHIP_LABEL.case} since ${utcDay(openedAt)}` : DECISION_CHIP_LABEL.case;
}

/** The hover text of the decision chip of a campaign with a case. */
export function caseChipTitle(openedAt: string | null | undefined): string {
  return openedAt
    ? `A Security Onion case is open for this campaign since ${utcStamp(openedAt)}.`
    : DECISION_CHIP_TITLE.case;
}

/** The filter of the Campaigns list. */
export const FILTER_WAITS = 'Waits on you';
export const FILTER_ALL = 'All';
export const CAMPAIGNS_NONE_WAIT = 'No campaign waits on your decision.';

/** The note on an action card of an investigation that a campaign holds,
 *  around the title: "Part of the campaign {title}. Decide on the campaign." */
export const ACTION_CAMPAIGN_NOTE = { before: 'Part of the campaign ', after: '. Decide on the campaign.' } as const;

/** The sentence the strip adds for a closed campaign. */
export const STRIP_CLOSED = ' An analyst closed the campaign.';

// ── The leads and the hunts of a campaign ───────────────────────────────────

/** The fold of the leads and the hunts: what soc-ai did about the activity. */
export const LEADS_HUNTS_TITLE = 'Leads and hunts';
/** The tag of a lead whose every observation is an alert that the campaign holds. */
export const LEAD_OF_CAMPAIGN = 'Lead of this campaign';
/** The hover text of that tag. */
export const LEAD_OF_CAMPAIGN_TITLE =
  'Each observation of this lead is an alert of an investigation that the campaign holds. The lead closes with the campaign.';
/** The link from a row of the campaign page to a lead. */
export const OPEN_LEAD = 'Open the lead';
/** A lead of the campaign with no hunt of its own, while the campaign has hunts. */
export const LEAD_COVERED = 'The hunts of the campaign cover this lead.';
/** A lead with no hunt at all. The words of the lead page. */
export const LEAD_NOT_HUNTED = 'No hunt ran on this lead.';
/** A related lead is no lead of the campaign. */
export const RELATED_LEAD_NOTE = 'This lead keeps normal handling.';
export const LEADS_HEADING = 'Leads';
export const HUNTS_HEADING = 'Hunts';
export const HUNTS_LANE = 'Hunts';
export const CHANGES_LANE = 'Changes';
export const HUNT_MARKS_LABEL = 'The hunts of the campaign and the changes that can start a hunt, over time';

/** The line under a list of hunts that reached the cap of the server. */
export function huntsCapSentence(cap: number): string {
  return `The list shows the ${cap.toLocaleString()} newest hunts.`;
}

/** What started a hunt, by the class that the server stores. */
export const HUNT_STARTER_LABEL: Record<string, string> = {
  campaign: 'Campaign hunt',
  lead: 'Lead hunt',
  schedule: 'Scheduled hunt',
  analyst: 'Manual hunt',
  catalog: 'Catalog sweep',
};

/** The words for a starter. A value from a newer server reads "Hunt". */
export function huntStarterLabel(starter: string | null | undefined): string {
  return HUNT_STARTER_LABEL[starter ?? ''] ?? 'Hunt';
}

/** "2 findings, 1 threat finding", "4 findings, no threat finding", "No finding". */
export function huntFindingsWords(findings: number, threats: number): string {
  if (!(findings > 0)) return 'No finding';
  const threat = threats > 0 ? plural(threats, 'threat finding') : 'no threat finding';
  return `${plural(findings, 'finding')}, ${threat}`;
}

/** The words of one hunt, for its mark and its hover: "Campaign hunt,
 *  2026-10-28 22:52 UTC: 2 findings, 1 threat finding. Complete." */
export function huntMarkWords(
  h: { starter: string; startedAt: string | null; findings: number; threatFindings: number },
  status: string,
): string {
  return `${huntStarterLabel(h.starter)}, ${utcStamp(h.startedAt)}: ${huntFindingsWords(h.findings, h.threatFindings)}. ${status}.`;
}

/** The counts after the title of the fold: "2 leads, 3 hunts". */
export function leadsHuntsDetail(leads: number, hunts: number): string {
  return [leads > 0 ? plural(leads, 'lead') : null, hunts > 0 ? plural(hunts, 'hunt') : null]
    .filter(Boolean)
    .join(', ');
}

/** The line of a hunt finding that a campaign holds. */
export function heldFindingSentence(title: string): string {
  return `Held by the campaign ${title.trim()}: no new stage, no new machine, no later event.`;
}

/** The hover text of "Open an investigation" on a finding that a campaign holds. */
export const HELD_FINDING_OPEN_TITLE =
  'The campaign holds this finding. soc-ai opened no investigation for it. Open one by hand to check the finding again.';

/** The line of the header of a hunt of a campaign, around the title of the campaign. */
export const HUNT_ON_CHANGE = { before: 'soc-ai started this hunt on a change of the campaign ', after: '.' } as const;
export const HUNT_IN_CAMPAIGN = { before: 'This hunt is part of the campaign ', after: '.' } as const;
