// The Dashboard's "N pipeline errors" KPI links to /investigations?verdict=pipeline_error.
// These helpers are the two sides of that contract: the KPI's live count
// (fallback runs the operator has NOT dismissed) and the Investigations screen's
// deep-link filter parsing (unknown values dropped, never wedging the filter).
import { describe, expect, it } from 'vitest';
import { livePipelineErrors, verdictFilterFromSearch } from './investigationFilters';
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
    expect(verdictFilterFromSearch('?verdict=bogus,untriaged')).toEqual(['untriaged']);
  });

  it('returns no filter without the param', () => {
    expect(verdictFilterFromSearch('')).toEqual([]);
    expect(verdictFilterFromSearch('?other=1')).toEqual([]);
  });
});
