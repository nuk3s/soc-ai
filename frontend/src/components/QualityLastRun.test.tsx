// L3 (review 2026-11-12): the Status card "Verdict quality · Open" landed on
// four settings and no result. Settings > Quality opens with the last
// evaluation result in sentences. Every time is an offset from Date.now().
import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getQualityTrend: vi.fn(),
}));

import { type QualityPoint, type QualityTrend, getQualityTrend } from '../lib/api';
import { QualityLastRun, agreementSentence, lastRunSentences, synthSentence } from './QualityLastRun';

const HOUR = 3_600_000;

function point(over: Partial<QualityPoint> = {}): QualityPoint {
  return {
    id: 7,
    ts: new Date(Date.now() - 5 * HOUR).toISOString(),
    mode: 'graded',
    n_ok: 18,
    n_error: 2,
    agreement_rate: 0.7,
    n_yes: null,
    n_partial: null,
    n_no: null,
    n_classified: null,
    fallback_rate: 0,
    error_rate: 0.1,
    latency_p50_ms: 60_000,
    verdict_counts: {},
    alarmed: false,
    alarm_reasons: [],
    batch_dir: null,
    verdict_agree: 14,
    verdict_compared: 17,
    synth: [{ scenario_id: 'php2shell', outcome: 'caught', verdict: 'true_positive', confidence: 0.9 }],
    n_unfinished: 0,
    ...over,
  };
}

const trend = (points: QualityPoint[], over: Partial<QualityTrend['freshness']> = {}): QualityTrend => ({
  points,
  freshness: {
    latest_ts: points[points.length - 1]?.ts ?? null,
    scheduled: true,
    stale: false,
    last_attempt_at: null,
    last_exit_code: null,
    last_detail: null,
    ...over,
  },
});

beforeEach(() => {
  vi.mocked(getQualityTrend).mockReset();
});

describe('QualityLastRun', () => {
  it('states when the last run was, the runs, the agreement and the synthetic true positive', async () => {
    vi.mocked(getQualityTrend).mockResolvedValue(trend([point({ id: 6, n_ok: 1 }), point()]));
    render(<QualityLastRun />);
    expect((await screen.findByTestId('quality-last-run-text')).textContent).toBe(
      'The last evaluation ran 5h ago. 18 of 20 runs completed. ' +
        'The model and the Oracle stated the same verdict on 14 of 17 alerts. ' +
        'The model found the synthetic true positive.',
    );
  });

  it('says that agreement is not measured, with the cause, when the Oracle did not grade', () => {
    const p = point({
      verdict_agree: null,
      verdict_compared: null,
      not_measured: 'Agreement is not measured. The Oracle quota ran out on 18 runs.',
    });
    expect(agreementSentence(p)).toBe('Agreement is not measured. The Oracle quota ran out on 18 runs.');
  });

  it('names a missed plant and a plant that was not measured', () => {
    expect(
      synthSentence(
        point({
          synth: [
            { scenario_id: 'a', outcome: 'missed' },
            { scenario_id: 'b', outcome: 'not_measured', cause: 'The grid refused the plant' },
          ],
        }),
      ),
    ).toBe(
      'The model missed 1 of 2 synthetic true positives. The synthetic true positive is not measured. The grid refused the plant.',
    );
  });

  it('states the alarm, the runs that did not finish and a stale result', () => {
    const sentences = lastRunSentences(
      trend([point({ n_unfinished: 2, alarmed: true, alarm_reasons: ['5 of 20 eval runs errored'] })], { stale: true }),
    );
    expect(sentences).toContain('18 of 20 runs completed. 2 runs did not finish.');
    expect(sentences).toContain('An alarm is on. 5 of 20 eval runs errored.');
    expect(sentences).toContain('This result is older than two scheduled runs.');
  });

  it('says that no result exists on a console with no run', async () => {
    // NEGATIVE CONTROL: no point is no result. It never reads as a clean one.
    vi.mocked(getQualityTrend).mockResolvedValue(trend([], { scheduled: false }));
    render(<QualityLastRun />);
    expect((await screen.findByTestId('quality-last-run-text')).textContent).toBe(
      'The quality evaluation has no result on this console. Turn on the nightly evaluation in the settings below.',
    );
  });
});
