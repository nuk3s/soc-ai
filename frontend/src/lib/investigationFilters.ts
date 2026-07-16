import type { InvestigationRow } from './types';

/** Every value the Investigations Verdict filter accepts — the real verdicts
 * plus the synthetic 'pipeline_error' (E1.2 fallback rows). Single source for
 * the deep-link parser below; the MultiSelect labels live with the screen. */
export const VERDICT_FILTER_VALUES: readonly string[] = [
  'true_positive',
  'false_positive',
  'needs_more_info',
  'inconclusive',
  'untriaged',
  'pipeline_error',
];

/** Deep-link target for the Dashboard's "N pipeline errors" KPI. */
export const PIPELINE_ERRORS_URL = '/investigations?verdict=pipeline_error';

/**
 * Initial Verdict filter from a location.search — lets the Dashboard KPI link
 * land on /investigations pre-filtered (?verdict=pipeline_error, comma-separated
 * for multiple). Unknown values are dropped so a mangled URL can't wedge the
 * filter into a state the MultiSelect can't display or clear.
 */
export function verdictFilterFromSearch(search: string): string[] {
  const raw = new URLSearchParams(search).get('verdict');
  if (!raw) return [];
  return raw
    .split(',')
    .map((v) => v.trim())
    .filter((v) => VERDICT_FILTER_VALUES.includes(v));
}

/**
 * Pipeline-error runs the operator has NOT yet dismissed — the Dashboard KPI
 * counts these. A dismissed run stays a fallback historically (visible under
 * the Pipeline-error filter); the ack only silences the dashboard nag.
 * Superseded runs (isPrimary === false — a newer run for the same alert
 * reached a real verdict) don't count either: re-running IS the fix, so the
 * error is resolved without needing an explicit dismiss.
 */
export function livePipelineErrors(rows: InvestigationRow[]): InvestigationRow[] {
  return rows.filter((r) => r.fallback && !r.errorDismissed && r.isPrimary !== false);
}
