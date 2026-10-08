// ---------------------------------------------------------------------------
// The words of the lead page and the lead timeline.
//
// One file holds the sentences the lead surfaces build from the record, so the
// strip, the lead page and the hunt page that renders the timeline say one
// thing in one way.
// ---------------------------------------------------------------------------

import { huntOutcome } from './labels';
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
  const who = p.promoted_by || 'An analyst';
  return (
    `${who} opened an investigation on finding F${p.finding_ordinal + 1}. ` +
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

/** A time on the timeline: "2026-10-05 04:12 UTC". */
export function utcStamp(iso: string | null | undefined): string {
  if (!iso) return 'no time on record';
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return iso;
  return `${at.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

/** An event window: "2026-10-05 04:00 to 05:00 UTC", or with both dates when
 *  the window crosses midnight. */
export function utcWindow(start: string, end: string): string {
  const a = new Date(start);
  const b = new Date(end);
  if (Number.isNaN(a.getTime()) || Number.isNaN(b.getTime())) return `${start} to ${end}`;
  const [aDay, aTime] = a.toISOString().slice(0, 16).split('T');
  const [bDay, bTime] = b.toISOString().slice(0, 16).split('T');
  if (a.getTime() === b.getTime()) return `${aDay} ${aTime} UTC`;
  return aDay === bDay
    ? `${aDay} ${aTime} to ${bTime} UTC`
    : `${aDay} ${aTime} to ${bDay} ${bTime} UTC`;
}

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

/** Why this is a lead, in one sentence. Example: "Why this is a lead: 2 rate
 *  spikes and 2 off-hours sightings on one host in 18 days." The counts are
 *  observations, by type, in the order the types first appear. */
export function leadWhySentence(lead: {
  entities: readonly (readonly string[])[];
  kinds: readonly string[];
  observations: readonly (DatedObservation & { kind: string })[];
}): string {
  const counts = new Map<string, number>();
  for (const o of lead.observations) counts.set(o.kind, (counts.get(o.kind) ?? 0) + 1);
  const on = entityNoun(lead.entities[0]?.[0], Math.max(1, lead.entities.length));
  if (counts.size === 0) {
    const kinds = lead.kinds.map((k) => (KIND_NOUN[k] ? KIND_NOUN[k][1] : k.replace(/_/g, ' ')));
    return `Why this is a lead: it formed from ${andList(kinds) || 'observations that are gone'} on ${on}.`;
  }
  const parts = Array.from(counts, ([kind, n]) => kindCount(kind, n));
  return `Why this is a lead: ${andList(parts)} on ${on}${spanWords(lead.observations)}.`;
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
 *  "17 days ago". `ago()` writes "17d ago", which is a chip and not prose. */
export function agoWords(iso: string, now = Date.now()): string {
  const ms = now - new Date(iso).getTime();
  if (!Number.isFinite(ms) || ms < 60_000) return 'less than a minute ago';
  const minutes = Math.round(ms / 60_000);
  if (minutes < 60) return `${minutes} ${minutes === 1 ? 'minute' : 'minutes'} ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} ${hours === 1 ? 'hour' : 'hours'} ago`;
  const days = Math.round(hours / 24);
  return `${days} days ago`;
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
  hunts: readonly { status: string; outcome: string }[],
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
    tail = 'The newest hunt is running.';
  } else if (newest === 'investigating') {
    tail = 'The newest hunt investigates its findings.';
  } else if (hunts[0].status !== 'complete' || newest === 'could_not_run') {
    tail = 'The newest hunt could not run.';
  } else if (newest === 'threats_confirmed') {
    tail = 'The newest hunt confirmed a threat.';
  } else if (newest === 'no_threat_confirmed') {
    tail = 'The newest hunt confirmed no threat.';
  } else if (newest === 'threat_found') {
    tail = 'The newest hunt found a threat.';
  } else {
    tail = 'The newest hunt found none.';
  }
  return `${head} ${tail}`;
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
  const parts = ['Lead hunt', steps, runTime(h.elapsed_sec)];
  if (h.status === 'complete') {
    parts.push(`${h.threat_findings} threat ${h.threat_findings === 1 ? 'finding' : 'findings'}`);
  }
  return parts.join(' · ');
}
