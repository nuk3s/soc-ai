// The Dashboard's "N pipeline errors" KPI links to /investigations?verdict=pipeline_error.
// These helpers are the two sides of that contract: the KPI's live count
// (fallback runs the operator has NOT dismissed) and the Investigations screen's
// deep-link filter parsing (unknown values dropped, never wedging the filter).
import { describe, expect, it } from 'vitest';
import {
  PIPELINE_ERRORS_URL,
  VERDICT_FILTER_VALUES,
  errorStateFromSearch,
  livePipelineErrors,
  verdictFilterFromSearch,
} from './investigationFilters';
import type { InvestigationRow } from './types';

const row = (over: Partial<InvestigationRow>): InvestigationRow => ({
  id: 'INV-1',
  name: 'ET X',
  kind: 'suricata',
  verdict: 'needs_more_info',
  conf: 0.3,
  host: '10.0.0.9',
  status: 'complete',
  when: '1m ago',
  ...over,
});

describe('livePipelineErrors', () => {
  it('counts only fallback rows the operator has not dismissed', () => {
    const rows = [
      row({ id: 'live', fallback: true }),
      row({ id: 'live-explicit', fallback: true, errorDismissed: false }),
      row({ id: 'acked', fallback: true, errorDismissed: true }),
      row({ id: 'normal', fallback: false }),
      row({ id: 'no-flag' }),
    ];
    expect(livePipelineErrors(rows).map((r) => r.id)).toEqual(['live', 'live-explicit']);
  });

  it('is empty when every error is dismissed', () => {
    expect(livePipelineErrors([row({ fallback: true, errorDismissed: true })])).toEqual([]);
  });

  it('excludes superseded (non-primary) fallback runs — a successful re-run IS the fix', () => {
    const rows = [
      row({ id: 'superseded', fallback: true, isPrimary: false }),
      row({ id: 'still-live', fallback: true, isPrimary: true }),
      row({ id: 'implicit-primary', fallback: true }),
    ];
    expect(livePipelineErrors(rows).map((r) => r.id)).toEqual(['still-live', 'implicit-primary']);
  });
});

describe('verdictFilterFromSearch', () => {
  it('parses the Dashboard deep link', () => {
    expect(verdictFilterFromSearch('?verdict=pipeline_error')).toEqual(['pipeline_error']);
  });

  it('supports comma-separated values', () => {
    expect(verdictFilterFromSearch('?verdict=pipeline_error,true_positive')).toEqual([
      'pipeline_error',
      'true_positive',
    ]);
  });

  it('drops unknown values so a mangled URL cannot wedge the filter', () => {
    expect(verdictFilterFromSearch('?verdict=bogus')).toEqual([]);
    expect(verdictFilterFromSearch('?verdict=bogus,true_positive')).toEqual(['true_positive']);
  });

  // 'untriaged' names a unit this list cannot hold: an alert group nobody has
  // investigated has no investigation ROW, and cannot get one while it stays
  // untriaged. The filter was therefore empty by construction — and the table
  // renders an untriaged verdict as a bare em-dash, never a pill, so it never
  // even matched something an operator could point at. Untriaged work lives on
  // /alerts (same endpoint, same unit); stale bookmarks degrade to "no filter".
  it('no longer accepts untriaged — that unit lives on the Alerts screen', () => {
    expect(VERDICT_FILTER_VALUES).not.toContain('untriaged');
    expect(verdictFilterFromSearch('?verdict=untriaged')).toEqual([]);
    expect(verdictFilterFromSearch('?verdict=untriaged,pipeline_error')).toEqual([
      'pipeline_error',
    ]);
  });

  it('returns no filter without the param', () => {
    expect(verdictFilterFromSearch('')).toEqual([]);
    expect(verdictFilterFromSearch('?other=1')).toEqual([]);
  });
});

describe('livePipelineErrors, runs that died without a verdict', () => {
  // The deployed instance held 188 rows in this state: status 'error', no
  // verdict, no report, so `fallback` was never stamped and the KPI that counts
  // `fallback` saw none of them.
  it('counts a failed run with no verdict', () => {
    const rows = [
      row({ id: 'died', status: 'error', verdict: 'untriaged', noVerdict: true }),
      row({ id: 'fallback', fallback: true }),
    ];
    expect(livePipelineErrors(rows).map((r) => r.id)).toEqual(['died', 'fallback']);
  });

  it('drops a dismissed failure, because a dismissed one stays dismissed', () => {
    const rows = [
      row({ id: 'acked', status: 'error', noVerdict: true, errorDismissed: true }),
      row({ id: 'live', status: 'error', noVerdict: true }),
    ];
    expect(livePipelineErrors(rows).map((r) => r.id)).toEqual(['live']);
  });

  it('drops a superseded failure, because a later run reached a verdict', () => {
    const rows = [
      row({ id: 'superseded', status: 'error', noVerdict: true, isPrimary: false }),
      row({ id: 'live', status: 'error', noVerdict: true, isPrimary: true }),
    ];
    expect(livePipelineErrors(rows).map((r) => r.id)).toEqual(['live']);
  });

  // Negative control: a healthy list grows no count. Cancelled and interrupted
  // runs are not failures: one was asked for, the other is re-huntable. An
  // errored run that DID reach a verdict has an answer to read.
  it('counts nothing on a healthy list', () => {
    const rows = [
      row({ id: 'fp', status: 'complete', verdict: 'false_positive' }),
      row({ id: 'tp', status: 'complete', verdict: 'true_positive' }),
      row({ id: 'stopped', status: 'cancelled', verdict: 'untriaged' }),
      row({ id: 'orphan', status: 'interrupted', verdict: 'untriaged' }),
      row({ id: 'late', status: 'error', verdict: 'false_positive' }),
    ];
    expect(livePipelineErrors(rows)).toEqual([]);
  });
});

// The tile promised a number its own list could not reproduce: the count
// excluded dismissed and superseded runs and the list excluded neither, so the
// tile went nine, eight, seven while the list sat at twenty (dogfood
// 2026-09-07, D2). The deep link now names the partition, and the server
// applies it to the rows AND the header count.
describe('the pipeline-error deep link names what the tile counted', () => {
  it('asks for the runs that still need a retry', () => {
    expect(errorStateFromSearch(PIPELINE_ERRORS_URL)).toBe('live');
    expect(verdictFilterFromSearch(PIPELINE_ERRORS_URL)).toEqual(['pipeline_error']);
  });

  it('reads handled as well, so the excluded rows stay reachable', () => {
    expect(errorStateFromSearch('?verdict=pipeline_error&errors=handled')).toBe('handled');
  });

  it('drops an unknown value rather than wedging the list', () => {
    expect(errorStateFromSearch('?verdict=pipeline_error&errors=bogus')).toBeNull();
    expect(errorStateFromSearch('?verdict=pipeline_error')).toBeNull();
    expect(errorStateFromSearch('')).toBeNull();
  });
});
