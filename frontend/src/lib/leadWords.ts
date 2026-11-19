// ---------------------------------------------------------------------------
// The words of the lead page and the lead timeline.
//
// One file holds the sentences the lead surfaces build from the record, so the
// strip, the lead page and the hunt page that renders the timeline say one
// thing in one way.
// ---------------------------------------------------------------------------

import { ACTION_CAMPAIGN_NOTE } from './campaignWords';
import { huntOutcome, stoppedHuntWords } from './labels';
import { CLOSE_RULE_CLAUSE, isSystemActor } from './leadDecisions';
import { ago, utcStamp, utcWindow } from './timeRange';
import { VERDICT } from './tokens';
import type { Verdict } from './types';

/** A verdict and its confidence in the words of a sentence: "true positive
 *  0.75". The label comes from the one verdict table, in lower case. */
export function verdictWords(verdict: string | null, confidence: number | null): string {
  if (!verdict) return 'no verdict yet';
  const label = (VERDICT[verdict as Verdict]?.label ?? verdict.replace(/_/g, ' ')).toLowerCase();
  return confidence === null || confidence === undefined
    ? label
    : `${label} ${confidence.toFixed(2)}`;
}

/** The facts of a promoted hunt finding that the lead page states. */
export interface PromotedFindingFacts {
  investigation_id: string;
  finding_ordinal: number;
  promoted_by: string;
  status: string;
  verdict: string | null;
  confidence: number | null;
  /** The other findings of the hunt that read the same investigation. */
  shared_with?: number[];
}

/** "F2", "F2 and F4", "F2, F3 and F5": finding numbers from 0-based ordinals. */
function findingNumbers(ordinals: readonly number[]): string {
  const names = ordinals.map((o) => `F${o + 1}`);
  if (names.length <= 1) return names.join('');
  return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
}

/** The findings one promoted row covers: its own and those that share it. */
export function findingsCovered(p: { finding_ordinal: number; shared_with?: number[] }): number {
  return 1 + (p.shared_with ?? []).filter((o) => o !== p.finding_ordinal).length;
}


/** The state of the investigation of a promoted finding, after the colon. */
function investigationState(p: PromotedFindingFacts): string {
  if (p.verdict) return verdictWords(p.verdict, p.confidence);
  if (p.status === 'running' || p.status === 'queued') return 'running';
  return 'no verdict';
}

/** One timeline row for an investigation of a hunt finding: "alice opened
 *  an investigation on finding F2. Investigation 01M48EPSK80EBWHBMZ5XH0SVZM:
 *  true positive 0.75." The store keeps the word `promoted`. The row names
 *  the act by its control, "Open an investigation". The sentence carries the
 *  whole id. An eight-character cut hid the rest of it (owner, 2026-10-07). */
export function promotedFindingSentence(p: PromotedFindingFacts): string {
  // The hunt's own investigation is signed system:hunt. The page says soc-ai.
  const who = isSystemActor(p.promoted_by) ? 'soc-ai' : p.promoted_by || 'An analyst';
  // R3-D4: the hunt reuses one investigation for two findings on one subject.
  // The row named only the first, and the header counted one finding.
  const others = (p.shared_with ?? []).filter((o) => o !== p.finding_ordinal);
  const shared =
    others.length > 0
      ? `${findingNumbers(others)} ${others.length === 1 ? 'shares' : 'share'} this investigation. `
      : '';
  return (
    `${who} opened an investigation on finding F${p.finding_ordinal + 1}. ${shared}` +
    `Investigation ${p.investigation_id}: ${investigationState(p)}.`
  );
}

/** The promoted finding whose verdict the lead page asks about, or null.
 *
 *  The investigation of a finding from the lead's hunt reached a verdict, and
 *  the lead stayed in Needs you with Promote live. A second analyst could
 *  start a second investigation of the same evidence. The page asks once per
 *  investigation: a kept-open answer names the investigation it answered. */
export function verdictToDecide<P extends PromotedFindingFacts>(lead: {
  status: string;
  promoted_findings?: P[];
  decisions?: { action: string; investigation_id: string | null }[];
}): P | null {
  if (lead.status === 'dismissed' || lead.status === 'promoted') return null;
  const answered = new Set(
    (lead.decisions ?? [])
      .filter((d) => d.action === 'kept_open' && d.investigation_id)
      .map((d) => d.investigation_id as string),
  );
  return (
    (lead.promoted_findings ?? []).find(
      (p) => Boolean(p.verdict) && !answered.has(p.investigation_id),
    ) ?? null
  );
}

/** The text with one stop at its end. A note that ends in a stop read
 *  "log shipping.." when the sentence added its own. */
export function withStop(text: string): string {
  const t = text.trimEnd();
  if (!t) return t;
  return /[.!?]$/.test(t) ? t : `${t}.`;
}

// ---------------------------------------------------------------------------
// Times on the lead timeline. One zone, with its label.
//
// The timeline mixed three clocks: the text used local time ("Tuesday
// 00:00"), the query used UTC ("04:00Z"), and another row said "22:00 UTC".
// The summaries and the queries the server writes are in UTC, so the
// timeline states every time in UTC and says so.
// ---------------------------------------------------------------------------

// The two UTC helpers live in the one time formatter (timeRange.ts). They are
// re-exported here, so the lead surfaces keep their imports.
export { utcStamp, utcWindow } from './timeRange';

/** The facts of an observation that date it. */
export interface DatedObservation {
  born_at: string | null;
  observed_at?: string | null;
  evidence: Record<string, unknown> | null;
  rerun_query?: string | null;
}

const QUERY_WINDOW = /@timestamp:\["([^"]+)" TO "([^"]+)"\]/;

/** The window of the events an observation describes, or null.
 *
 *  An analytic hit states the first and the last matching document. A
 *  departure states its hours in the query that shows it again. An
 *  observation on lead 8 read "20d ago" over a query on the day before, and
 *  the two dates said different things. */
export function eventWindow(o: DatedObservation): { start: string; end: string } | null {
  const ev = o.evidence ?? {};
  if (typeof ev.first_seen === 'string' && typeof ev.last_seen === 'string') {
    return { start: ev.first_seen, end: ev.last_seen };
  }
  const m = (o.rerun_query ?? '').match(QUERY_WINDOW);
  return m ? { start: m[1], end: m[2] } : null;
}

/** The line that dates one observation by its events, in UTC. */
export function eventWindowText(o: DatedObservation): string {
  const w = eventWindow(o);
  if (w) return `Events ${utcWindow(w.start, w.end)}.`;
  if (o.observed_at) return `Event ${utcStamp(o.observed_at)}.`;
  return `Recorded ${utcStamp(o.born_at)}. No document time is on record.`;
}

/** The time a timeline row sorts on: the end of its event window, else the
 *  event time, else the record time. */
export function observationSortTime(o: DatedObservation): string | null {
  return eventWindow(o)?.end ?? o.observed_at ?? o.born_at;
}

// ---------------------------------------------------------------------------
// Why this is a lead, in one sentence.
//
// The header read "weight now 0.80 · at formation 1.30 rate spiked 0.80 of
// 1.70 off hours 0.00 of 1.70 · 1 type · 1 entity named". Those are the
// numbers of the scoring. The analyst asks what happened, on what, and over
// how long.
// ---------------------------------------------------------------------------

/** One observation type as a countable noun: [one, many]. */
const KIND_NOUN: Record<string, [string, string]> = {
  above_baseline: ['rate spike', 'rate spikes'],
  below_baseline: ['collapsed rate', 'collapsed rates'],
  off_hours: ['off-hours sighting', 'off-hours sightings'],
  novel_destination: ['new destination', 'new destinations'],
  novel_served_port: ['new served port', 'new served ports'],
  novel_consumed_port: ['new outbound port', 'new outbound ports'],
  novel_process: ['new process', 'new processes'],
  novel_process_pair: ['new process pair', 'new process pairs'],
  novel_binding: ['first logon', 'first logons'],
  rare_for_peers: ['value rare for its peers', 'values rare for their peers'],
  scope_count: ['condition on many hosts', 'conditions on many hosts'],
  estate_outlier: ['outlier against its peer group', 'outliers against their peer group'],
  alert: ['triaged alert', 'triaged alerts'],
  prior_no_baseline: ['finding with no benign baseline', 'findings with no benign baseline'],
  catalog_match: ['analytic match', 'analytic matches'],
  hunt_finding: ['promoted hunt finding', 'promoted hunt findings'],
  telemetry_silence: ['silent log source', 'silent log sources'],
  logon_chain: ['logon chain', 'logon chains'],
};

/** "2 rate spikes", "1 analytic match". An unknown type counts observations. */
export function kindCount(kind: string, n: number): string {
  const noun = KIND_NOUN[kind];
  if (noun) return `${n} ${n === 1 ? noun[0] : noun[1]}`;
  const word = kind.replace(/_/g, ' ');
  return `${n} ${word} ${n === 1 ? 'observation' : 'observations'}`;
}

/** "a, b and c". */
function andList(parts: string[]): string {
  if (parts.length <= 1) return parts.join('');
  return `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}`;
}

/** The noun for the entity kind of a lead: a host, or an account. */
function entityNoun(kind: string | undefined, n: number): string {
  const one = kind === 'user' ? 'account' : 'host';
  return n === 1 ? `one ${one}` : `${n} ${one}s`;
}

/** The entities a lead names, counted by what they are: "1 host", "2 hosts
 *  and 1 account". The header said "1 entity named", which is the data model
 *  talking. */
export function entityCountWords(entities: readonly (readonly string[])[]): string {
  const accounts = entities.filter((e) => e[0] === 'user').length;
  const hosts = entities.length - accounts;
  const parts: string[] = [];
  if (hosts > 0 || accounts === 0) parts.push(`${hosts} ${hosts === 1 ? 'host' : 'hosts'}`);
  if (accounts > 0) parts.push(`${accounts} ${accounts === 1 ? 'account' : 'accounts'}`);
  return parts.join(' and ');
}

/** The entities after the first, for "and 1 more host". The strip read "and
 *  1 host more" (R3 STE 7). A mix reads "3 more: 2 hosts and 1 account". */
export function moreEntityWords(entities: readonly (readonly string[])[]): string {
  const accounts = entities.filter((e) => e[0] === 'user').length;
  const hosts = entities.length - accounts;
  if (accounts === 0) return `${hosts} more ${hosts === 1 ? 'host' : 'hosts'}`;
  if (hosts === 0) return `${accounts} more ${accounts === 1 ? 'account' : 'accounts'}`;
  return `${entities.length} more: ${entityCountWords(entities)}`;
}

/** The span of the observations, as "in 18 days" or "in 5 hours". */
function spanWords(observations: readonly DatedObservation[]): string {
  const times: number[] = [];
  for (const o of observations) {
    const w = eventWindow(o);
    for (const at of [w?.start, w?.end, o.observed_at, o.born_at]) {
      const t = at ? Date.parse(at) : Number.NaN;
      if (Number.isFinite(t)) times.push(t);
    }
  }
  if (times.length === 0) return '';
  const hours = (Math.max(...times) - Math.min(...times)) / 3_600_000;
  if (hours < 24) {
    const h = Math.max(1, Math.ceil(hours));
    return ` in ${h} ${h === 1 ? 'hour' : 'hours'}`;
  }
  const days = Math.ceil(hours / 24);
  return ` in ${days} ${days === 1 ? 'day' : 'days'}`;
}

/** What soc-ai saw, and on which entity, in one sentence. Example: "soc-ai
 *  saw 2 rate spikes and 2 off-hours sightings on adguard2 at 192.0.2.33 in 18
 *  days." The counts are observations, by type, in the order the types first
 *  appear. `machineName` is the name of the machine behind the first entity,
 *  when the Hosts list holds one. A lead that names more entities states them
 *  in a second sentence. */
export function leadSeenSentence(
  lead: {
    entities: readonly (readonly string[])[];
    kinds: readonly string[];
    observations: readonly (DatedObservation & { kind: string })[];
  },
  machineName?: string | null,
): string {
  const [kind, key] = lead.entities[0] ?? [];
  const subject = !key
    ? entityNoun(kind, 1)
    : kind === 'user'
      ? `the account ${key}`
      : machineName && machineName !== key
        ? `${machineName} at ${key}`
        : key;
  const others = lead.entities.slice(1);
  const also = others.length > 0 ? ` The lead also names ${entityCountWords(others)}.` : '';
  const counts = new Map<string, number>();
  for (const o of lead.observations) counts.set(o.kind, (counts.get(o.kind) ?? 0) + 1);
  if (counts.size === 0) {
    const kinds = lead.kinds.map((k) => (KIND_NOUN[k] ? KIND_NOUN[k][1] : k.replace(/_/g, ' ')));
    return `This lead formed from ${andList(kinds) || 'observations that are gone'} on ${subject}.${also}`;
  }
  const parts = Array.from(counts, ([k, n]) => kindCount(k, n));
  return `soc-ai saw ${andList(parts)} on ${subject}${spanWords(lead.observations)}.${also}`;
}

/** What a hunt on a lead concluded, in the words that follow "The newest hunt"
 *  and "Hunt result:". The lead page and the lead card on the host page read
 *  this one map, so a card never reads "found a threat" beside a pill that
 *  reads "No threat confirmed" (dogfood 2026-11-17, b05). The server sends
 *  one outcome code for a lead: the verdicts decide once the hunt
 *  investigated its findings. */
export const LEAD_OUTCOME_WORDS: Readonly<Record<string, string>> = {
  threat_found: 'found a threat',
  threats_confirmed: 'confirmed a threat',
  no_threat: 'found no threat',
  no_threat_confirmed: 'confirmed no threat',
  no_answer: 'gave no answer',
};

/** The words of a hunt that stopped after it ran steps. One function in
 *  lib/labels.ts gives them to every surface. */
export { stoppedHuntWords };

/** The sentence of a newest hunt that did not finish: it stopped after its
 *  steps, or it could not run. */
function stoppedHuntSentence(h: { status: string; steps?: number }): string {
  const n = h.steps ?? 0;
  const steps = `${n} ${n === 1 ? 'step' : 'steps'}`;
  if (n > 0 && h.status === 'error') return `The newest lead hunt stopped with an error after ${steps}.`;
  if (n > 0 && h.status === 'cancelled') return `A cancel stopped the newest lead hunt after ${steps}.`;
  if (n > 0 && h.status === 'interrupted') return `A restart stopped the newest lead hunt after ${steps}.`;
  return 'The newest lead hunt could not run.';
}

/** What the newest lead hunt on a lead concluded, in one sentence. A hunt that
 *  runs, and a hunt that could not run, claim no result. `hunts` is newest
 *  first. A server that sends no list leaves the hunt the lead record names. */
export function leadHuntSentence(
  lead: {
    hunts?: readonly { status: string; outcome: string; started_at: string | null; steps?: number }[];
    hunt_id?: string | null;
    hunt_status?: string | null;
    hunt_outcome?: string | null;
    hunt_threat_count?: number;
  },
  now = Date.now(),
): string {
  const listed = lead.hunts?.[0];
  const newest = listed
    ? listed
    : lead.hunt_id || lead.hunt_status
      ? { status: lead.hunt_status ?? '', outcome: lead.hunt_outcome ?? '', started_at: null }
      : null;
  if (!newest) return 'No hunt ran on this lead.';
  const key = huntOutcome(newest);
  if (key === 'running') return 'A hunt runs on this lead now.';
  if (key === 'investigating') return 'The newest lead hunt investigates its findings now.';
  const threat = key === 'threat_found' || key === 'threats_confirmed';
  const earlier = !threat && (lead.hunt_threat_count ?? 0) > 0 ? ' An earlier hunt found a threat.' : '';
  if (key === 'could_not_run') return `${stoppedHuntSentence(newest)}${earlier}`;
  const ran = newest.started_at ? `The newest lead hunt ran ${agoWords(newest.started_at, now)}` : null;
  if (key === 'no_threat_gap') {
    return ran
      ? `${ran}. It found no threat and reported a visibility gap.${earlier}`
      : `The newest lead hunt found no threat and reported a visibility gap.${earlier}`;
  }
  if (key === null) {
    return ran
      ? `${ran}. Its result is not on record.${earlier}`
      : `The result of the newest lead hunt is not on record.${earlier}`;
  }
  return `${ran ? `${ran} and` : 'The newest lead hunt'} ${LEAD_OUTCOME_WORDS[key]}.${earlier}`;
}

/** The line of a lead that a campaign holds: "Part of the campaign {title}.
 *  Decide on the campaign." The action card of an investigation of the
 *  campaign states the same sentence. */
export function campaignLeadSentence(title: string): string {
  return `${ACTION_CAMPAIGN_NOTE.before}${title.trim()}${ACTION_CAMPAIGN_NOTE.after}`;
}

/** The close of a lead by its campaign, after "soc-ai closed the lead: ". */
const CAMPAIGN_CLOSE_WORDS: Record<string, string> = {
  campaign_closed: 'an analyst closed the campaign',
  campaign_authorized: 'an admin authorized the campaign',
};

/** What a lead waits on, from its state. `state` is the state the pill wears
 *  (components/LeadsStrip.tsx, leadState). */
export function leadWaitSentence(facts: {
  state: string;
  /** The title of the campaign that holds an open lead. The lead then waits
   *  on the decision on the campaign. */
  campaignTitle?: string | null;
  /** The reason a closed lead holds. A campaign writes its own reasons. */
  dismissedReason?: string | null;
  /** Auto-hunt holds the next move of a new lead. */
  queued?: boolean;
  /** An investigation of a hunt finding has a verdict the analyst must answer. */
  verdictToDecide?: boolean;
  /** soc-ai closed the lead: after a clean hunt, or on the verdicts of a hunt. */
  closedBySocAi?: boolean;
  /** The campaign that closed the lead opened again after the close (W4). */
  campaignReopened?: boolean;
}): string {
  const open = facts.state === 'new' || facts.state === 'in_progress' || facts.state === 'hunted';
  if (open && facts.campaignTitle) return campaignLeadSentence(facts.campaignTitle);
  const byCampaign = CAMPAIGN_CLOSE_WORDS[facts.dismissedReason ?? ''];
  if (facts.state === 'dismissed' && byCampaign) {
    // W4: the words follow the state of the campaign at read time.
    if (facts.campaignReopened) {
      return `soc-ai closed the lead: ${byCampaign}. The campaign opened again and waits on a decision. The lead stays closed.`;
    }
    return `soc-ai closed the lead: ${byCampaign}. It waits on nothing.`;
  }
  switch (facts.state) {
    case 'new':
      return facts.queued
        ? 'The lead waits on auto-hunt. Its hunt starts within a minute.'
        : 'The lead waits on your decision: hunt it or dismiss it.';
    case 'in_progress':
      return 'The lead waits on the hunt.';
    case 'hunted':
      return facts.verdictToDecide
        ? 'The lead waits on your decision: close it on the investigation or keep it open.'
        : 'The lead waits on your decision: dismiss it or hunt again.';
    case 'fleet_condition':
      return 'The lead is a fleet condition. It waits on no decision.';
    case 'dismissed':
      return facts.closedBySocAi
        ? 'soc-ai closed the lead. It waits on nothing.'
        : 'An analyst dismissed the lead. It waits on nothing.';
    case 'promoted':
      return facts.closedBySocAi
        ? 'soc-ai closed the lead. It waits on nothing.'
        : 'An investigation closed the lead. It waits on nothing.';
    default:
      return 'The lead waits on your decision.';
  }
}

/** The state of a lead in one line, for the top of the lead page: what
 *  soc-ai saw and on which entity, what the hunt concluded, and what the lead
 *  waits on. The page gave these in a pill, a helper line, two banners and a
 *  weight behind a toggle (review 2026-11-12, F5). */
export function leadStateSentence(
  lead: Parameters<typeof leadSeenSentence>[0] & Parameters<typeof leadHuntSentence>[0],
  facts: Parameters<typeof leadWaitSentence>[0] & { machineName?: string | null },
  now = Date.now(),
): string {
  return [
    leadSeenSentence(lead, facts.machineName),
    leadHuntSentence(lead, now),
    leadWaitSentence(facts),
  ].join(' ');
}

/** A run time as an analyst reads it: "under 1 min", "6 min", "1 h 5 min". */
export function runTime(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 60) return 'under 1 min';
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  return rest ? `${hours} h ${rest} min` : `${hours} h`;
}

/** A past time in words a sentence can carry: "5 minutes ago", "6 hours ago",
 *  "17 days ago". `ago()` writes "17d ago", which is a chip and not prose.
 *
 *  The count is the one `ago()` states: whole units, and days from 24 hours.
 *  These words rounded, and one hunt read "27 days ago" in the Hunt again
 *  confirm and "26d ago" in its row (dogfood 2026-10-19, V1-H5). */
export function agoWords(iso: string, now = Date.now()): string {
  const ms = now - new Date(iso).getTime();
  if (!Number.isFinite(ms) || ms < 60_000) return 'less than a minute ago';
  const unit = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'} ago`;
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 60) return unit(minutes, 'minute');
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return unit(hours, 'hour');
  return unit(Math.floor(hours / 24), 'day');
}

/** What the Hunt again confirm states about the next hunt (R3-I5). The
 *  confirm said nothing of the close, and the range lead closed on its own
 *  after a second hunt. */
export const HUNT_AGAIN_CLOSE = `soc-ai closes the lead when the new hunt finds no threat, or when ${CLOSE_RULE_CLAUSE}.`;

/** The two sentences of the Hunt again confirm about the hunt on record:
 *  when it ran and how long it took. The confirm said "A hunt on this lead
 *  already exists" and named no time. `run` is null when the record holds no
 *  run time. */
export function huntAgainWords(
  hunt: { started_at: string | null; elapsed_sec: number } | null | undefined,
  now = Date.now(),
): { head: string; run: string | null } {
  return {
    head: hunt?.started_at
      ? `This lead has a hunt from ${agoWords(hunt.started_at, now)}.`
      : 'This lead has a hunt.',
    run: hunt && hunt.elapsed_sec > 0 ? `That hunt ran ${runTime(hunt.elapsed_sec)}.` : null,
  };
}

/** The warning for a hunt older than the evidence, or null.
 *
 *  The only hunt on lead 7 ran 17 days ago, and two observations were six and
 *  twenty hours old. The banner said "The hunt could not read all evidence"
 *  and did not say that the hunt ran before the evidence arrived. An
 *  observation is newer than the hunt when soc-ai recorded it after the hunt
 *  started. */
export function staleHuntSentence(
  hunt: { status: string; started_at: string | null } | undefined,
  observations: readonly { born_at: string | null }[],
  now = Date.now(),
): string | null {
  if (!hunt?.started_at || hunt.status === 'running' || hunt.status === 'queued') return null;
  const started = new Date(hunt.started_at).getTime();
  if (!Number.isFinite(started)) return null;
  const newer = observations.filter(
    (o) => o.born_at !== null && new Date(o.born_at).getTime() > started,
  ).length;
  if (newer === 0) return null;
  const are = newer === 1 ? '1 observation is' : `${newer} observations are`;
  return `The hunt ran ${agoWords(hunt.started_at, now)}. ${are} newer than the hunt. Hunt again to read them.`;
}

/** The record of every hunt on a lead, in two sentences, or null for fewer
 *  than two hunts. One screen stated three things about one lead: a green
 *  "No threat observed" pill, "Closed. The hunt found no threat." on the
 *  timeline, and a banner about an earlier threat. The record states the
 *  count and the newest answer together. `hunts` is newest first. */
export function huntRecordSentence(
  hunts: readonly { status: string; outcome: string; steps?: number }[],
): string | null {
  if (hunts.length < 2) return null;
  // The outcome keys of lib/labels.ts. The lead store sends its own four codes
  // and the hunt routes send the five public ones; huntOutcome reads both.
  const keys = hunts.map((h) => huntOutcome(h));
  // A hunt that investigated its findings and confirmed one found a threat
  // too. One that refuted every finding did not.
  const threats = keys.filter((k) => k === 'threat_found' || k === 'threats_confirmed').length;
  const head = `${threats} of ${hunts.length} hunts found a threat.`;
  const newest = keys[0];
  let tail: string;
  if (newest === 'running') {
    tail = 'The newest lead hunt is running.';
  } else if (newest === 'investigating') {
    tail = 'The newest lead hunt investigates its findings.';
  } else if (hunts[0].status !== 'complete' || newest === 'could_not_run') {
    tail = stoppedHuntSentence(hunts[0]);
  } else if (newest === 'threats_confirmed') {
    tail = 'The newest lead hunt confirmed a threat.';
  } else if (newest === 'no_threat_confirmed') {
    tail = 'The newest lead hunt confirmed no threat.';
  } else if (newest === 'threat_found') {
    tail = 'The newest lead hunt found a threat.';
  } else {
    tail = 'The newest lead hunt found none.';
  }
  return `${head} ${tail}`;
}

// ---------------------------------------------------------------------------
// The hunt result on a lead row.
//
// The pill of a hunted lead states the outcome. A new lead, a closed lead and
// a fleet condition lead stated nothing about a hunt, and no row stated what
// the hunt said. Seven of eight open leads on production waited after a clean
// hunt and read the same as the one real item (review 2026-11-12, hunts F6).
// ---------------------------------------------------------------------------

/** The result of the hunts on one lead. `threat` also covers a newer hunt
 *  with no threat over an earlier hunt that found one. */
export type LeadHuntResultKey =
  | 'not_hunted'
  | 'running'
  | 'threat'
  | 'no_threat'
  | 'no_threat_gap'
  | 'no_answer'
  | 'failed'
  | 'unknown';

/** The words an earlier threat adds to a result that is not a threat. */
const EARLIER_THREAT_WORDS = 'An earlier hunt found a threat';

/** The hunt result of one lead, in the words the row prints after "Hunt
 *  result:". The four results are "found a threat", "found no threat", "hunt
 *  failed" and "not hunted". A hunt that still runs has no result, and a
 *  visibility gap is no clean answer, so each has its own words. */
export function leadHuntResult(lead: {
  hunt_id?: string | null;
  hunt_status?: string | null;
  hunt_outcome?: string | null;
  hunt_threat_count?: number;
}): { key: LeadHuntResultKey; words: string } {
  const earlier = (lead.hunt_threat_count ?? 0) > 0;
  // An earlier threat stays on the record under any newer result.
  const worst = (key: LeadHuntResultKey, words: string) =>
    earlier
      ? { key: 'threat' as const, words: `${words}. ${EARLIER_THREAT_WORDS}` }
      : { key, words };
  if (!lead.hunt_id && !lead.hunt_status) return worst('not_hunted', 'not hunted');
  const outcome = huntOutcome({ status: lead.hunt_status, outcome: lead.hunt_outcome });
  switch (outcome) {
    case 'running':
      return { key: 'running', words: 'the hunt runs now' };
    case 'investigating':
      return { key: 'running', words: 'the hunt investigates its findings' };
    case 'threat_found':
    case 'threats_confirmed':
      return { key: 'threat', words: LEAD_OUTCOME_WORDS[outcome] };
    case 'could_not_run':
      return worst('failed', 'hunt failed');
    case 'no_threat':
    case 'no_threat_confirmed':
      return worst('no_threat', LEAD_OUTCOME_WORDS[outcome]);
    case 'no_threat_gap':
      return worst('no_threat_gap', 'found no threat, with a visibility gap');
    case 'no_answer':
      return worst('no_answer', 'the hunt gave no answer');
    default:
      return worst('unknown', 'hunted, with no result on record');
  }
}

/** The line of a closed lead that observations joined after the close: "4
 *  repeats after the close. Newest: 2h ago." Null for an open lead and for a
 *  closed lead with no repeat. A true-positive alert of a rule the lead held
 *  joins the closed lead and starts no hunt, so without the line the repeats
 *  were out of sight (soc_ai.store.leads.repeats_after_close). */
export function repeatsAfterCloseLine(
  lead: { status: string; repeats_after_close?: number; last_repeat_at?: string | null },
  now = Date.now(),
): string | null {
  const n = lead.repeats_after_close ?? 0;
  if (n <= 0 || (lead.status !== 'dismissed' && lead.status !== 'promoted')) return null;
  const count = `${n.toLocaleString()} ${n === 1 ? 'repeat' : 'repeats'} after the close.`;
  return lead.last_repeat_at ? `${count} Newest: ${ago(lead.last_repeat_at, now)}.` : count;
}

/** The facts of one hunt on a lead that its label states. */
export interface LeadHuntFacts {
  status: string;
  steps: number;
  elapsed_sec: number;
  threat_findings: number;
}

/** The label of one hunt on a lead. The page labelled a hunt by its id, which
 *  says nothing an analyst can use. Example: "Lead hunt · 17 steps · 6 min ·
 *  0 threat findings". A running hunt states that it runs. */
export function leadHuntLabel(h: LeadHuntFacts): string {
  const steps = `${h.steps} ${h.steps === 1 ? 'step' : 'steps'}`;
  if (h.status === 'running' || h.status === 'queued') return `Lead hunt · ${steps} · running`;
  // A hunt that stopped after its steps states them in its outcome words.
  const parts = stoppedHuntWords(h) ? ['Lead hunt', runTime(h.elapsed_sec)] : ['Lead hunt', steps, runTime(h.elapsed_sec)];
  if (h.status === 'complete') {
    parts.push(`${h.threat_findings} threat ${h.threat_findings === 1 ? 'finding' : 'findings'}`);
  }
  return parts.join(' · ');
}
