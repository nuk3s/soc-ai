// ---------------------------------------------------------------------------
// The statistic an observation stores, in words.
//
// An observation records the name of the statistic that departed, its value
// and the value of the baseline it departed from. The lead page and the host
// page state them here. The backend states the same names in
// soc_ai/hunting/wording.py (statistic_sentence) for the hunt the lead starts.
// ---------------------------------------------------------------------------

import { plural } from './plural';

/** A statistic as a reader reads it: 7.4, 12, or 0.25. */
export function statNumber(value: number): string {
  if (Math.abs(value - Math.round(value)) < 0.005) return String(Math.round(value));
  return Math.abs(value) < 1 ? value.toFixed(2) : value.toFixed(1);
}

/** One or two sentences for the statistic, or '' when the row stores none. */
export function statisticSentence(
  statistic: string | null | undefined,
  value: number | null | undefined,
  baseline: number | null | undefined,
): string {
  if (!statistic || value === null || value === undefined) return '';
  const v = statNumber(value);
  const b = baseline === null || baseline === undefined ? null : statNumber(baseline);
  switch (statistic) {
    case 'documents':
      return b === null
        ? `${plural(Math.round(value), 'document')} matched.`
        : `${plural(Math.round(value), 'document')} in the recent window. The set it is new to holds ${plural(Math.round(baseline as number), 'member')}.`;
    case 'hour_documents':
      return `${plural(Math.round(value), 'document')} in an hour with no activity in the baseline.`;
    case 'robust_z':
      return `A robust z of ${v} against a median of ${b ?? 'none'} per hour.`;
    case 'residual_z':
      return `A residual z of ${v} against an expected ${b ?? '0'} per hour for that hour of the week.`;
    case 'estate_hosts': {
      const held = Math.round(value);
      return `${held} of ${plural(Math.round(baseline ?? 0), 'profiled host')} ${
        held === 1 ? 'holds' : 'hold'
      } this member.`;
    }
    case 'peer_share': {
      const held = Math.round(value);
      return `${held} of ${plural(Math.round(baseline ?? 0), 'peer')} in the role ${
        held === 1 ? 'holds' : 'hold'
      } this member.`;
    }
    case 'hosts_departing':
      return `${plural(Math.round(value), 'host')} gained this member in one sweep.${
        b === null ? '' : ` ${plural(Math.round(baseline as number), 'host')} held it before.`
      }`;
    case 'plane_documents':
      return `${plural(Math.round(value), 'document')} from the log source in the hours it stopped.${
        b === null ? '' : ` The baseline expects ${b} in those hours.`
      }`;
    case 'chain_minutes':
      return `The attempt came ${v} ${v === '1' ? 'minute' : 'minutes'} after the session.${
        b === null
          ? ''
          : ` The host held ${plural(Math.round(baseline as number), 'learned outbound edge')}.`
      }`;
    default:
      return b === null ? `${statistic} ${v}.` : `${statistic} ${v} against a baseline of ${b}.`;
  }
}

/** What one profiled dimension counts, in one sentence, or ''.
 *
 *  Lead 7 said the baseline expects 0.5 per hour, and the host serves DNS at
 *  781 connections per hour. From the lead alone the analyst could not tell
 *  which count spiked. The entity fields are the ones the profile reads
 *  (soc_ai/dossier/profile.py): a rate counts the flows the host starts, and
 *  a served port counts the flows the host answers. */
export function dimensionMeasure(dimension: string | null | undefined): string {
  switch (dimension) {
    case 'connection_rate':
      return 'It counts the network connections that this host starts in one hour.';
    case 'active_hours':
      return 'It counts the hours of the day in which this host starts network connections.';
    case 'peers_out':
      return 'It tracks the addresses that this host connects to.';
    case 'consumed_ports':
      return 'It tracks the ports that this host connects to.';
    case 'served_ports':
      return 'It tracks the ports on which this host answers connections.';
    case 'dns_names':
      return 'It tracks the DNS names that this host asks for.';
    case 'process_names':
      return 'It tracks the processes that run on this host.';
    case 'process_parents':
      return 'It tracks the parent and child process pairs on this host.';
    case 'logon_users':
      return 'It tracks the users that log on to this host.';
    default:
      return '';
  }
}

/** True for a statistic that is a z score. The lead page keeps a z score
 *  behind its Scoring toggle and states the rate as a multiple. */
export function isZScore(statistic: string | null | undefined): boolean {
  return statistic === 'residual_z' || statistic === 'robust_z';
}

/** A rate departure as a multiple of the rate it departed from, or ''.
 *
 *  "A residual z of 9.2" asked the analyst to know what a residual z is. The
 *  same departure reads "7 per hour against an expected 0.5. That is 14 times
 *  the expected rate." `observed` is the count in the hour that departed. A
 *  residual z departs from the expected count of its hour of the week, and a
 *  robust z from the median per hour. */
export function rateMultipleSentence(
  statistic: string | null | undefined,
  observed: number | null | undefined,
  baseline: number | null | undefined,
): string {
  if (!isZScore(statistic)) return '';
  if (observed === null || observed === undefined || !Number.isFinite(observed)) return '';
  if (baseline === null || baseline === undefined || !(baseline > 0)) return '';
  const against = statistic === 'residual_z' ? 'an expected' : 'a median of';
  const of = statistic === 'residual_z' ? 'the expected rate' : 'the median';
  const ratio = observed / baseline;
  const multiple =
    ratio >= 1
      ? `${ratio >= 10 ? Math.round(ratio) : ratio.toFixed(1)} times ${of}`
      : `${ratio.toFixed(2)} of ${of}`;
  // Two decimals at most, and no trailing zero: "0.5", not "0.50".
  const short = (n: number) => String(Number(n.toFixed(2)));
  return `${short(observed)} per hour against ${against} ${short(baseline)}. That is ${multiple}.`;
}

/** The objective that asks the console to run one observation's query. */
export function rerunObjective(
  query: string,
  entity: string,
  departure: { dimension?: string | null; member?: string | null } = {},
): string {
  // W6: the objective is in the analyst's words. It named the agent's tool
  // and a tool argument: "Run this OQL query with t_query_events_oql ... Set
  // time_range_minutes ...". The objective is the brief, and the agent picks
  // its own tools.
  const window = queryWindowWords(query);
  const subject = rerunSubject(departure.dimension ?? null, departure.member ?? null, entity);
  return `${subject}${window ? ` ${window}` : ''}. The query below shows the events.\n\n${query}`;
}

/** The link that opens the console composer with that objective filled in. */
export function rerunHref(
  query: string,
  entity: string,
  departure: { dimension?: string | null; member?: string | null } = {},
): string {
  return `/hunts?new=1&objective=${encodeURIComponent(rerunObjective(query, entity, departure))}`;
}

const QUERY_TIME_RANGE = /@timestamp:\["([^"]+)" TO "([^"]+)"\]/;

/** "between 04:00 and 05:00 UTC on 2026-10-05", from the window in the query,
 *  or '' when the query states none. */
export function queryWindowWords(query: string): string {
  const m = query.match(QUERY_TIME_RANGE);
  if (!m) return '';
  const a = new Date(m[1]);
  const b = new Date(m[2]);
  if (Number.isNaN(a.getTime()) || Number.isNaN(b.getTime())) return '';
  const [aDay, aTime] = a.toISOString().slice(0, 16).split('T');
  const [bDay, bTime] = b.toISOString().slice(0, 16).split('T');
  return aDay === bDay
    ? `between ${aTime} and ${bTime} UTC on ${aDay}`
    : `between ${aDay} ${aTime} and ${bDay} ${bTime} UTC`;
}

/** What the analyst asks the hunt to explain, by the dimension that departed. */
function rerunSubject(dimension: string | null, member: string | null, entity: string): string {
  const m = member ?? '';
  switch (dimension) {
    case 'connection_rate':
    case 'active_hours':
      return `Explain the connections from ${entity}`;
    case 'served_ports':
      return m ? `Explain the connections to port ${m} on ${entity}` : `Explain the connections to ${entity}`;
    case 'consumed_ports':
      return m ? `Explain the connections from ${entity} to port ${m}` : `Explain the connections from ${entity}`;
    case 'peers_out':
      return m ? `Explain the connections from ${entity} to ${m}` : `Explain the connections from ${entity}`;
    case 'dns_names':
      return m ? `Explain the DNS queries from ${entity} for ${m}` : `Explain the DNS queries from ${entity}`;
    case 'process_names':
      return m ? `Explain the process ${m} on ${entity}` : `Explain the processes on ${entity}`;
    case 'process_parents':
      return m ? `Explain the process pair ${m} on ${entity}` : `Explain the process pairs on ${entity}`;
    case 'logon_users':
      return m ? `Explain the logons of ${m} on ${entity}` : `Explain the logons on ${entity}`;
    default:
      return `Explain the events for ${entity}`;
  }
}
