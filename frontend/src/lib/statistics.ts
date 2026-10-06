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
      return `${plural(Math.round(value), 'document')} on the silent plane in the silent hours.${
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

/** The objective that asks the console to run one observation's query. */
export function rerunObjective(query: string, entity: string): string {
  return (
    `Run this OQL query with t_query_events_oql and explain the result for ${entity}. ` +
    `Set time_range_minutes to cover the time range in the query.\n\n${query}`
  );
}

/** The link that opens the console composer with that objective filled in. */
export function rerunHref(query: string, entity: string): string {
  return `/hunts?new=1&objective=${encodeURIComponent(rerunObjective(query, entity))}`;
}
