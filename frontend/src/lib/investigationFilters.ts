import type { InvestigationRow } from './types';

/** Every value the Investigations Verdict filter accepts — the settled verdicts
 * plus the synthetic 'pipeline_error' (rows that reached no usable verdict: an
 * E1.2 fallback, or a run that died outright). Single source for the deep-link
 * parser below; the MultiSelect labels live with the screen.
 *
 * 'untriaged' is deliberately absent. This list holds investigation ROWS, and a
 * detection group nobody has investigated has no row — nor can it get one while
 * it stays untriaged — so the filter was empty by construction and the table
 * renders an untriaged verdict as a bare em-dash, never a pill. Untriaged work
 * belongs on /alerts, which counts the same unit (groups) off the same
 * endpoint. A run INTERRUPTED by a restart is reached through the Status
 * filter's Interrupted option; a run that died is under 'pipeline_error'. */
export const VERDICT_FILTER_VALUES: readonly string[] = [
  'true_positive',
  'false_positive',
  'needs_more_info',
  'inconclusive',
  'pipeline_error',
];

/** The two halves of a pipeline-error set, as the server names them.
 *
 * 'live' is the tile's predicate: produced nothing usable, not dismissed, not
 * superseded. 'handled' is the complement. The split cannot be a SQL column
 * because "superseded" is a fact about an alert's whole run group, so the
 * server decides it per row and counts the partition it returns. */
export const ERROR_STATE_VALUES: readonly string[] = ['live', 'handled'];

/** Deep-link target for the Dashboard's "N pipeline errors" KPI.
 *
 * It carries `errors=live` because the KPI counts the runs that still need a
 * retry and the plain verdict filter does not: the tile went nine, eight, seven
 * while the list it opened sat at twenty, with a run dismissed seconds earlier
 * rendered exactly like a counted one (dogfood 2026-09-07, D2). */
export const PIPELINE_ERRORS_URL = '/investigations?verdict=pipeline_error&errors=live';

/**
 * Initial Verdict filter from a location.search — lets the Dashboard KPI link
 * land on /investigations pre-filtered (?verdict=pipeline_error, comma-separated
 * for multiple). Unknown values are dropped so a mangled URL can't wedge the
 * filter into a state the MultiSelect can't display or clear.
 */
/** Query params from a `location.search` OR a whole path+query string, so the
 *  parsers can be pointed straight at PIPELINE_ERRORS_URL to check the two
 *  sides of the deep-link contract agree. */
function params(search: string): URLSearchParams {
  const at = search.indexOf('?');
  return new URLSearchParams(at >= 0 ? search.slice(at) : search);
}

export function verdictFilterFromSearch(search: string): string[] {
  const raw = params(search).get('verdict');
  if (!raw) return [];
  return raw
    .split(',')
    .map((v) => v.trim())
    .filter((v) => VERDICT_FILTER_VALUES.includes(v));
}

/**
 * Which half of a pipeline-error set a location.search asks for, or null.
 *
 * Unknown values are dropped rather than passed through, matching
 * `verdictFilterFromSearch`: a mangled deep link degrades to the broader query
 * instead of wedging the list behind a filter nothing can clear.
 */
export function errorStateFromSearch(search: string): string | null {
  const raw = params(search).get('errors');
  return raw && ERROR_STATE_VALUES.includes(raw) ? raw : null;
}

/**
 * Runs that produced no usable verdict and that the operator has NOT dismissed.
 * The Dashboard KPI counts these.
 *
 * Two shapes qualify. `fallback` is the E1.2 case: the pipeline failed, wrote a
 * placeholder needs_more_info and marked the report. `noVerdict` is a run that
 * died outright, with no verdict and no report to mark. That is the shape the
 * count used to miss entirely, and the reason 188 dead runs on a deployed
 * instance were never mentioned by any surface in the product.
 *
 * A dismissed run stays listed historically (visible under the Pipeline-error
 * filter); the ack only silences the dashboard nag. Superseded runs
 * (isPrimary === false — a newer run for the same alert reached a real verdict)
 * don't count either: re-running IS the fix, so the error is resolved without
 * needing an explicit dismiss.
 */
export function livePipelineErrors(rows: InvestigationRow[]): InvestigationRow[] {
  return rows.filter(
    (r) => (r.fallback || r.noVerdict) && !r.errorDismissed && r.isPrimary !== false,
  );
}
