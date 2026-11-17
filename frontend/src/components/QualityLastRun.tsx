import { type QualityPoint, type QualityTrend, getQualityTrend } from '../lib/api';
import { absTime, ago } from '../lib/timeRange';
import { useAsync } from '../lib/useAsync';
import { LoadingInline } from './States';

// ---------------------------------------------------------------------------
// The last evaluation result, in plain words, at the top of Settings > Quality.
//
// The Status card "Verdict quality · Open" landed on four settings under
// "ADVANCED (4)" and no result: no date, no sample, no agreement and no
// alarm state (review 2026-11-12). The panel now opens with the last point of
// GET /api/v1/quality/trend in sentences.
// ---------------------------------------------------------------------------

function runs(n: number): string {
  return n === 1 ? '1 run' : `${n} runs`;
}

/** The sentence about the planted true positives of one point, or null. */
export function synthSentence(p: QualityPoint): string | null {
  const plants = p.synth ?? [];
  if (plants.length === 0) return p.synth_note || null;
  const caught = plants.filter((s) => s.outcome === 'caught').length;
  const missed = plants.filter((s) => s.outcome === 'missed').length;
  const open = plants.filter((s) => s.outcome !== 'caught' && s.outcome !== 'missed');
  const parts: string[] = [];
  if (plants.length === 1) {
    if (caught) parts.push('The model found the synthetic true positive.');
    if (missed) parts.push('The model missed the synthetic true positive.');
  } else {
    if (caught) parts.push(`The model found ${caught} of ${plants.length} synthetic true positives.`);
    if (missed) parts.push(`The model missed ${missed} of ${plants.length} synthetic true positives.`);
  }
  if (open.length > 0) {
    const cause = open.find((s) => s.cause)?.cause;
    const what =
      open.length === 1 ? 'The synthetic true positive is not measured.' : `${open.length} synthetic true positives are not measured.`;
    parts.push(cause ? `${what} ${cause.trim().replace(/\.?$/, '.')}` : what);
  }
  return parts.join(' ');
}

/** The sentence about verdict agreement on the real alerts, or null. */
export function agreementSentence(p: QualityPoint): string | null {
  const compared = p.verdict_compared ?? null;
  if (compared != null && compared > 0) {
    const agree = p.verdict_agree ?? 0;
    return `The model and the Oracle stated the same verdict on ${agree} of ${compared} alerts.`;
  }
  // The grader lost every grade: the sentence opens "Agreement is not
  // measured." and names the cause.
  if (p.not_measured) return p.not_measured;
  if (compared === 0) return 'Verdict agreement is not measured. The Oracle stated no verdict to compare.';
  return null;
}

/** The sentences of the last evaluation result. */
export function lastRunSentences(trend: QualityTrend): string[] {
  const p = trend.points[trend.points.length - 1];
  if (!p) {
    const f = trend.freshness;
    const first = 'The quality evaluation has no result on this console.';
    if (f.last_attempt_at && f.last_detail) return [first, `The last attempt ran ${ago(f.last_attempt_at)}. ${f.last_detail}`];
    return [first, f.scheduled ? 'The nightly evaluation is on.' : 'Turn on the nightly evaluation in the settings below.'];
  }
  const out = [`The last evaluation ran ${ago(p.ts)}.`];
  const total = p.n_ok + p.n_error;
  let done = `${p.n_ok} of ${runs(total)} completed.`;
  if ((p.n_unfinished ?? 0) > 0) done += ` ${runs(p.n_unfinished ?? 0)} did not finish.`;
  out.push(done);
  const agreement = agreementSentence(p);
  if (agreement) out.push(agreement);
  const synth = synthSentence(p);
  if (synth) out.push(synth);
  if (p.alarmed) {
    const reason = p.alarm_reasons[0];
    out.push(reason ? `An alarm is on. ${reason.trim().replace(/\.?$/, '.')}` : 'An alarm is on.');
  }
  if (trend.freshness.stale) out.push('This result is older than two scheduled runs.');
  return out;
}

export function QualityLastRun() {
  const { data, error, loading } = useAsync<QualityTrend>(getQualityTrend, []);
  const latest = data?.points[data.points.length - 1];
  return (
    <div
      data-testid="quality-last-run"
      className="mb-2.5 rounded-card border border-border bg-surface-1 px-[15px] py-3 text-[12.5px] leading-[1.55] text-text-2"
      style={{ textWrap: 'pretty' }}
    >
      <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-faint">Last evaluation</div>
      {loading && !data ? (
        <LoadingInline>Reading the last evaluation</LoadingInline>
      ) : error && !data ? (
        <span className="text-dim">The console could not read the last evaluation result.</span>
      ) : data ? (
        <p data-testid="quality-last-run-text" title={latest ? absTime(latest.ts) : undefined}>
          {lastRunSentences(data).join(' ')}
        </p>
      ) : null}
    </div>
  );
}
