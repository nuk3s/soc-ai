import { AlertTriangle, CheckCircle2, History, Loader2, Play, ShieldCheck, Square } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { Panel } from '../components/Panel';
import { ErrorState } from '../components/States';
import {
  type Health,
  type HealthComponent,
  cancelBacktest,
  getBacktest,
  getBacktestById,
  getBacktestRuns,
  getHealth,
  startBacktest,
} from '../lib/api';
import { verdictLabel, verdictMeta } from '../lib/labels';
import { absoluteTime, ago } from '../lib/timeRange';
import { useAsync } from '../lib/useAsync';
import type {
  Backtest as BacktestData,
  BacktestConfusion,
  BacktestRow,
  BacktestRunSummary,
  HumanDisposition,
  SocVerdict,
} from '../lib/types';

// ---------------------------------------------------------------------------
// Backtest — "prove it on my last N days". Point soc-ai at a historical window
// of alerts an analyst ALREADY dispositioned in Security Onion, replay its
// triage over a diverse sample, and report how its verdicts compare to the
// human's REAL disposition. The single most convincing adoption artifact: not
// marketing numbers — the operator's own alerts. Read-only.
// ---------------------------------------------------------------------------

const WINDOWS = [
  { label: '7 days', days: 7 },
  { label: '14 days', days: 14 },
  { label: '30 days', days: 30 },
];
const SAMPLES = [10, 20, 30, 50];
const SEVERITIES = [
  { label: 'Any severity', value: '' },
  { label: 'High and above', value: 'high' },
  { label: 'Critical only', value: 'critical' },
];

// The words and colours of a verdict come from lib/labels.ts, the map every
// screen reads. This page said "Needs info" where the others said "Needs more
// info". `no_verdict` is this page's own bucket and reads as "No verdict".
const VERDICT_LABEL: Record<SocVerdict, string> = {
  true_positive: verdictLabel('true_positive'),
  false_positive: verdictLabel('false_positive'),
  needs_more_info: verdictLabel('needs_more_info'),
  inconclusive: verdictLabel('inconclusive'),
  no_verdict: 'No verdict',
};
const VERDICT_COLOR: Record<SocVerdict, string> = {
  true_positive: verdictMeta('true_positive').color,
  false_positive: verdictMeta('false_positive').color,
  needs_more_info: verdictMeta('needs_more_info').color,
  inconclusive: verdictMeta('inconclusive').color,
  no_verdict: verdictMeta('untriaged').color,
};
const DISPOSITION_LABEL: Record<HumanDisposition, string> = {
  true_positive: 'Escalated (TP)',
  false_positive: 'Acknowledged (FP)',
};

const SOC_ORDER: SocVerdict[] = [
  'true_positive',
  'false_positive',
  'needs_more_info',
  'inconclusive',
  'no_verdict',
];

function pct(x: number): string {
  return `${Math.round(x * 100)}%`;
}

/** The share of acknowledged alerts soc-ai called a false positive. An older
 *  server sends it under its old name only. */
function fpAgreement(m: { fp_agreement_rate?: number; fp_reduction: number }): number {
  return m.fp_agreement_rate ?? m.fp_reduction;
}

// The probe's own state. The type in lib/api.ts predates the field.
type ProbedComponent = HealthComponent & { state?: string };

/** True when the probe says the dependency cannot serve a backtest. A slow
 *  answer still serves one. A probe that ran out of its budget is treated as
 *  down, as the probe itself says. An older server sends no state. */
function isDown(c: ProbedComponent | null | undefined): boolean {
  if (!c) return false;
  if (c.state) return c.state === 'down' || c.kind === 'timeout';
  return !c.ok;
}

/** Why a backtest cannot run now, or null. Each replay reads the grid and
 *  asks the model, so a run against a dead dependency only records failures
 *  (dogfood 2026-10-19, H1-D13). An unknown state does not block. */
function backtestBlockedReason(h: Health | null): string | null {
  if (!h) return null;
  const grid = isDown(h.es as ProbedComponent);
  const model = isDown(h.llm as ProbedComponent);
  if (!grid && !model) return null;
  const which =
    grid && model
      ? 'The grid and the model gateway are down.'
      : grid
        ? 'The grid is down.'
        : 'The model gateway is down.';
  return `${which} A backtest needs the grid and the model gateway.`;
}

/** The cost of the next run, in the words of the confirm (R5-I9). The server
 *  caps the sample, and a window can hold fewer alerts, so the count is a
 *  ceiling. The time is the count times the median replay time. A running
 *  backtest has a Cancel control, so the confirm no longer warns of none. */
function backtestCostText(
  sampleSize: number,
  maxSample: number | null | undefined,
  secondsPerAlert: number | null | undefined,
): string {
  const n = maxSample ? Math.min(sampleSize, maxSample) : sampleSize;
  const parts = [
    `This backtest runs up to ${n} investigation${n === 1 ? '' : 's'} by the model.`,
  ];
  if (secondsPerAlert && secondsPerAlert > 0) {
    const minutes = Math.max(1, Math.round((n * secondsPerAlert) / 60));
    parts.push(`It takes about ${minutes} minute${minutes === 1 ? '' : 's'}.`);
  }
  return parts.join(' ');
}

// ---------------------------------------------------------------------------

export function Backtest() {
  const [windowDays, setWindowDays] = useState(30);
  const [sampleSize, setSampleSize] = useState(20);
  const [minSeverity, setMinSeverity] = useState('');
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  // Poll the current/last backtest ONLY while a run is active; when it settles
  // the same shape carries the stored results and there's nothing to poll for.
  // useAsync captures pauseWhen at setup, so consult a ref that tracks `active`.
  const activeRef = useRef(false);
  const { data, loading, error } = useAsync<BacktestData>(getBacktest, [reloadKey], {
    refetchInterval: 2500,
    pauseWhen: () => !activeRef.current,
  });

  const running = !!data?.active;
  activeRef.current = running;

  // The grid and the model gateway, as the header pill reads them. A run
  // against a dead dependency records one failure per alert, so the page
  // refuses to start one (H1-D13).
  const health = useAsync<Health>(getHealth, [], { refetchInterval: 30_000 });
  const blocked = backtestBlockedReason(health.data);
  // The cost confirm is open (R5-I9).
  const [confirming, setConfirming] = useState(false);
  // The focus opens on Cancel: Enter on "Start backtest" started a run of
  // about 42 minutes (verify 2026-10-20, V3-N6). Cancel and Escape return
  // the focus to "Run backtest". The page body held it.
  const runButton = useRef<HTMLButtonElement>(null);
  const confirmCancel = useRef<HTMLButtonElement>(null);
  const focusRun = useRef(false);
  const closeConfirm = () => {
    focusRun.current = true;
    setConfirming(false);
  };
  useEffect(() => {
    if (confirming) {
      confirmCancel.current?.focus();
    } else if (focusRun.current) {
      focusRun.current = false;
      runButton.current?.focus();
    }
  }, [confirming]);
  // The stored runs. Read again when a run starts or ends (R5-I10).
  const runs = useAsync(() => getBacktestRuns(), [reloadKey, running]);
  // An older run the operator opened from the list. Null shows the latest.
  const [viewId, setViewId] = useState<string | null>(null);
  const viewed = useAsync<BacktestData | null>(
    () => (viewId ? getBacktestById(viewId) : Promise.resolve(null)),
    [viewId],
  );
  const viewing = viewId !== null && viewId !== data?.backtest_id;
  // The cancel of the running backtest (R5-I9). The server holds the request,
  // so `data.cancel_requested` is what says a stop is pending.
  const [cancelOpen, setCancelOpen] = useState(false);
  const [cancelSending, setCancelSending] = useState(false);
  const [cancelError, setCancelError] = useState<string | null>(null);
  useEffect(() => {
    // A new run replaces whatever older run was open.
    if (running) setViewId(null);
    // A cancel confirm or refusal belongs to the run it was about.
    setCancelOpen(false);
    setCancelError(null);
  }, [running]);
  const finishedSoFar = (data?.replayed ?? 0) + (data?.failed ?? 0);
  const sendCancel = () => {
    const id = data?.backtest_id;
    if (!id || cancelSending) return;
    setCancelOpen(false);
    setCancelSending(true);
    setCancelError(null);
    cancelBacktest(id)
      .then(() => setReloadKey((k) => k + 1))
      .catch((e: unknown) =>
        setCancelError(e instanceof Error ? e.message : 'The request to cancel the backtest failed.'),
      )
      .finally(() => setCancelSending(false));
  };

  // A run is `active` from the moment the sampling query goes out — before a
  // backtest row exists and before there is anything to replay. Rendering that
  // as "Replaying 0 dispositioned alerts… / 0 / 0 replayed" states a finished
  // replay of nothing, which is the shape of a clean empty result; against a
  // grid that answered nothing it read as "there was nothing to compare" rather
  // than "we were blind". Nothing here can tell those apart, so it claims
  // neither: it names the phase the run is actually in, and the sampling read's
  // own outcome (a 503, or the note below) is what says whether the grid
  // answered.
  const sampling = running && !data?.backtest_id;

  // What the screen renders below: a stored run (a score, or one that was cut
  // short), or the empty panel. It matters here because the empty panel is where
  // the status note used to be shown — and it is the one branch that does NOT
  // render once the console has history, which is every console after its first
  // backtest. A run that failed in its sampling read has no results of its own,
  // so without this its note landed under a completed run's score and was never
  // drawn: the failure was invisible behind last week's number.
  const storedRun =
    !!data &&
    ((!!data.results && data.status === 'complete') ||
      data.status === 'error' ||
      data.status === 'cancelled');

  const launch = () => {
    if (starting || running || blocked) return;
    setConfirming(false);
    setViewId(null);
    setStarting(true);
    setStartError(null);
    startBacktest({ windowDays, sampleSize, minSeverity: minSeverity || undefined })
      .then((s) => {
        // A refused attempt comes back on GET /backtest too, beside the stored
        // run, so a reload draws it in its own panel. Any other non-active
        // status (already running) carries only the POST's note.
        if (s.refused) setReloadKey((k) => k + 1);
        else if (!s.active) setStartError(s.note ?? 'The backtest did not start.');
        else setReloadKey((k) => k + 1);
      })
      .catch((e: unknown) =>
        setStartError(e instanceof Error ? e.message : 'The request to start the backtest failed.'),
      )
      .finally(() => setStarting(false));
  };

  return (
    <div className="px-[22px] pb-[60px] pt-5">
      {/* page header */}
      <div className="mb-5">
        <div className="flex items-center gap-2">
          <History size={19} className="text-accent" />
          <div className="text-[20px] font-semibold tracking-[-.015em]">Backtest</div>
        </div>
        <div className="mt-0.5 max-w-[720px] text-[13px] text-dim">
          Measure soc-ai on your own alerts. soc-ai replays its triage over a sample of alerts that
          your analysts already closed in Security Onion. soc-ai then compares its verdicts with
          the verdicts of your analysts. An escalated alert counts as a true positive. An
          acknowledged alert counts as a false positive. soc-ai reads Security Onion and writes
          nothing back.
        </div>
      </div>

      {/* run form */}
      <Panel className="mb-5 p-4">
        <div className="mb-3 text-[13px] font-semibold">New backtest</div>
        <div className="flex flex-wrap items-end gap-4">
          <Field label="Window">
            <select
              value={windowDays}
              onChange={(e) => setWindowDays(Number(e.target.value))}
              disabled={running}
              className="rounded-control border border-border-input bg-bg px-3 py-2 text-[13px] text-text outline-none focus:border-accent disabled:opacity-50"
            >
              {WINDOWS.map((w) => (
                <option key={w.days} value={w.days}>
                  Last {w.label}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Sample size">
            <select
              value={sampleSize}
              onChange={(e) => setSampleSize(Number(e.target.value))}
              disabled={running}
              className="rounded-control border border-border-input bg-bg px-3 py-2 text-[13px] text-text outline-none focus:border-accent disabled:opacity-50"
            >
              {SAMPLES.map((n) => (
                <option key={n} value={n}>
                  {n} alerts
                </option>
              ))}
            </select>
          </Field>
          <Field label="Minimum severity">
            <select
              value={minSeverity}
              onChange={(e) => setMinSeverity(e.target.value)}
              disabled={running}
              className="rounded-control border border-border-input bg-bg px-3 py-2 text-[13px] text-text outline-none focus:border-accent disabled:opacity-50"
            >
              {SEVERITIES.map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </select>
          </Field>
          <button
            ref={runButton}
            onClick={() => setConfirming(true)}
            disabled={starting || running || !!blocked || confirming}
            title={blocked ?? undefined}
            className="flex items-center gap-1.5 rounded-control bg-accent px-[15px] py-2 text-[13px] font-semibold text-white hover:bg-accent-deep disabled:cursor-not-allowed disabled:opacity-50"
          >
            {starting || running ? (
              <Loader2 size={15} className="animate-spin" />
            ) : (
              <Play size={15} />
            )}
            {running ? 'Running' : starting ? 'Starting' : 'Run backtest'}
          </button>
        </div>
        {blocked && !running && (
          <div role="status" className="mt-2.5 text-[12px] text-warn">
            {blocked}
          </div>
        )}
        {confirming && !running && (
          <div
            data-testid="backtest-confirm"
            role="group"
            aria-label="Confirm the backtest"
            onKeyDown={(e) => {
              if (e.key === 'Escape') {
                e.stopPropagation();
                closeConfirm();
              }
            }}
            className="mt-3 flex flex-wrap items-center gap-2.5 rounded-control border border-border-strong bg-surface-2 px-3 py-2.5"
          >
            <span className="min-w-[240px] flex-1 text-[12.5px] text-text-2">
              {backtestCostText(sampleSize, data?.max_sample, data?.estimate?.seconds_per_alert)}
            </span>
            <button
              onClick={launch}
              disabled={starting || !!blocked}
              className="rounded-control bg-accent px-[13px] py-1.5 text-[12px] font-semibold text-white hover:bg-accent-deep disabled:cursor-not-allowed disabled:opacity-50"
            >
              Start backtest
            </button>
            <button
              ref={confirmCancel}
              onClick={closeConfirm}
              className="rounded-control border border-border-strong px-[13px] py-1.5 text-[12px] font-semibold text-dim hover:text-text"
            >
              Cancel
            </button>
          </div>
        )}
        <div className="mt-2.5 text-[11.5px] text-faint">
          {[
            'Each sampled alert is one investigation by the model.',
            data?.max_sample
              ? `The server caps the sample at ${data.max_sample} alerts.`
              : 'The server caps the sample size.',
            'soc-ai samples only the alerts that your analysts closed.',
          ].join(' ')}
        </div>
        {startError && <div className="mt-2 text-[12px] text-danger">{startError}</div>}
      </Panel>

      {/* live progress */}
      {running && data && (
        <Panel className="mb-5 p-4">
          {sampling ? (
            <div data-testid="backtest-sampling">
              <div className="mb-1 flex items-center gap-2 text-[13px] font-semibold text-accent">
                <Loader2 size={15} className="animate-spin" />
                soc-ai reads Security Onion for the alerts your analysts closed
              </div>
              <div className="text-[12px] text-dim">
                soc-ai has replayed no alert yet. soc-ai still samples the window.
              </div>
            </div>
          ) : (
            <>
              <div className="mb-2 flex items-center gap-2 text-[13px] font-semibold text-accent">
                <Loader2 size={15} className="animate-spin" />
                soc-ai replays {data.total} closed alert{data.total === 1 ? '' : 's'}
              </div>
              <ProgressBar done={data.replayed + data.failed} total={data.total} />
              <div className="mt-2 text-[12px] text-dim">
                {data.replayed + data.failed} / {data.total} replayed
                {data.current && (
                  <span className="text-faint">
                    {' '}
                    · soc-ai investigates <span className="text-text-2">{data.current}</span>
                  </span>
                )}
                {data.failed > 0 && (
                  <span className="text-warn"> · {data.failed} failed</span>
                )}
              </div>
              <CancelControl
                pending={!!data.cancel_requested}
                open={cancelOpen}
                sending={cancelSending}
                finished={finishedSoFar}
                error={cancelError}
                onOpen={() => {
                  setCancelError(null);
                  setCancelOpen(true);
                }}
                onConfirm={sendCancel}
                onKeep={() => setCancelOpen(false)}
              />
            </>
          )}
        </Panel>
      )}

      {/* The newest attempt, when it started no run. Drawn on its own, above
          the older run, so the old score is not read as today's answer. */}
      {!running && data?.refused && (
        <div
          data-testid="backtest-refused"
          role="status"
          className="mb-3 rounded-card border border-border bg-surface-2 px-4 py-3 text-[12px]"
        >
          <div className="mb-1 flex items-center gap-1.5 font-semibold text-warn">
            <AlertTriangle size={13} /> The last backtest attempt did not run
          </div>
          <div className="text-text-2">{data.refused.hint}</div>
          {storedRun && (
            <div className="mt-1 text-faint">The result below is from an earlier run.</div>
          )}
        </div>
      )}

      {/* The newest attempt's outcome, when what follows is an OLDER run. */}
      {!running && storedRun && data?.note && (
        <div
          data-testid="backtest-note"
          className="mb-3 rounded-card border border-border bg-surface-2 px-4 py-2.5 text-[12px] text-warn"
        >
          {data.note}
        </div>
      )}

      {/* the stored runs, when there is more than the one on screen */}
      {runs.data && runs.data.runs.length > 1 && (
        <PastRuns
          runs={runs.data.runs}
          shownId={viewing ? viewId : (data?.backtest_id ?? null)}
          onOpen={(id) => setViewId(id === data?.backtest_id ? null : id)}
        />
      )}

      {/* results / errors / empty */}
      {viewing ? (
        <div data-testid="backtest-viewed">
          <div className="mb-3 flex flex-wrap items-center gap-2.5 rounded-card border border-border bg-surface-2 px-4 py-2.5 text-[12px] text-text-2">
            <span className="flex-1">
              This is an earlier run.{' '}
              {viewed.data?.finished_at
                ? `It finished at ${absoluteTime(viewed.data.finished_at)}.`
                : ''}
            </span>
            <button
              onClick={() => setViewId(null)}
              className="rounded-control border border-border-strong px-[11px] py-1 text-[11.5px] font-semibold text-dim hover:text-text"
            >
              Show the latest run
            </button>
          </div>
          {viewed.error ? (
            <ErrorState error={viewed.error} onRetry={viewed.refetch} />
          ) : viewed.data?.results && viewed.data.status === 'complete' ? (
            <Results data={viewed.data} />
          ) : viewed.data?.status === 'error' ? (
            <InterruptedRun data={viewed.data} />
          ) : viewed.data?.status === 'cancelled' ? (
            <CancelledRun data={viewed.data} />
          ) : viewed.data ? (
            <Panel className="p-6 text-center text-[13px] text-faint">
              This run has no result yet.
            </Panel>
          ) : null}
        </div>
      ) : error && !data ? (
        <ErrorState error={error} onRetry={() => setReloadKey((k) => k + 1)} />
      ) : data?.results && data.status === 'complete' ? (
        <Results data={data} />
      ) : data?.status === 'error' ? (
        <InterruptedRun data={data} />
      ) : data?.status === 'cancelled' && !running ? (
        <CancelledRun data={data} />
      ) : !running && !loading ? (
        <div data-testid="backtest-empty">
          <Panel className="p-8 text-center text-[13px] text-faint">
            {data?.refused
              ? 'soc-ai has no earlier backtest result.'
              : data?.note
              ? data.note
              : 'No backtest yet. Select a window above and run a backtest. The report compares the verdicts of soc-ai with the dispositions of your analysts.'}
          </Panel>
        </div>
      ) : null}
    </div>
  );
}

// ---------------------------------------------------------------------------

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-[11px] uppercase tracking-[.05em] text-dim">{label}</span>
      {children}
    </label>
  );
}

/** A backtest that did not finish measuring.
 *
 * The report an owner uses to decide whether to adopt the product must never
 * price an outage as a model regression. A run that lost the grid mid-replay
 * used to finalize `complete` with every unreadable replay counted as a
 * disagreement — "soc-ai disagrees with human analysts 90% of the time" when the
 * truth was the sensor was blind for 18 of 20 replays. Those runs now land as
 * `error` and stop here: the coverage is stated, the score is not. */
/** The stored runs, newest first (R5-I10). Each row opens its report. */
function PastRuns({
  runs,
  shownId,
  onOpen,
}: {
  runs: BacktestRunSummary[];
  shownId: string | null;
  onOpen: (id: string) => void;
}) {
  return (
    <Panel className="mb-5">
      <div className="border-b border-border px-4 py-3 text-[13px] font-semibold">Past runs</div>
      <ul data-testid="backtest-runs" className="max-h-[260px] overflow-y-auto">
        {runs.map((r) => {
          const shown = r.backtest_id === shownId;
          const when = r.finished_at ?? r.started_at;
          return (
            <li
              key={r.backtest_id}
              className={`flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-border px-4 py-2 text-[12px] last:border-0 ${shown ? 'bg-surface-2' : ''}`}
            >
              <span className="min-w-[150px] text-text-2">{when ? absoluteTime(when) : 'No date'}</span>
              <span className="text-dim">
                {r.listed ? 'Listed alerts' : r.window_days ? `${r.window_days}-day window` : ''}
              </span>
              <span className="text-dim">
                {r.sampled ?? 0} alert{r.sampled === 1 ? '' : 's'}
              </span>
              <span className="flex-1 font-semibold text-text-2">{runScore(r)}</span>
              <button
                onClick={() => onOpen(r.backtest_id)}
                disabled={shown}
                className="rounded-control border border-border-strong px-[11px] py-1 text-[11.5px] font-semibold text-dim hover:text-text disabled:cursor-default disabled:opacity-60"
              >
                {shown ? 'Shown' : 'Open'}
              </button>
            </li>
          );
        })}
      </ul>
    </Panel>
  );
}

/** The headline of one stored run. A run that did not complete has no score,
 *  and a run with no escalated alert has no agreement to measure. */
function runScore(r: BacktestRunSummary): string {
  if (r.status === 'running') return 'Running';
  if (r.status === 'cancelled') return 'Cancelled';
  if (r.status !== 'complete' || r.agreement_rate === null) return 'No score';
  if (r.human_tp === 0) return 'Agreement not measurable';
  return `${pct(r.agreement_rate)} agreement`;
}

/** The Cancel control of a running backtest (R5-I9). The stop is
 *  cooperative: the alert in flight finishes, and no new alert starts. */
function CancelControl({
  pending,
  open,
  sending,
  finished,
  error,
  onOpen,
  onConfirm,
  onKeep,
}: {
  pending: boolean;
  open: boolean;
  sending: boolean;
  finished: number;
  error: string | null;
  onOpen: () => void;
  onConfirm: () => void;
  onKeep: () => void;
}) {
  if (pending) {
    return (
      <div role="status" className="mt-2.5 flex items-center gap-1.5 text-[12px] text-warn">
        <Loader2 size={13} className="animate-spin" />
        soc-ai stops the backtest after the current alert.
      </div>
    );
  }
  return (
    <div className="mt-2.5">
      {open ? (
        <div
          data-testid="backtest-cancel-confirm"
          role="group"
          aria-label="Confirm the cancel"
          onKeyDown={(e) => {
            if (e.key === 'Escape') {
              e.stopPropagation();
              onKeep();
            }
          }}
          className="flex flex-wrap items-center gap-2.5 rounded-control border border-border-strong bg-surface-2 px-3 py-2.5"
        >
          <span className="min-w-[240px] flex-1 text-[12.5px] text-text-2">
            Stop the backtest after the current alert. soc-ai keeps the {finished} result
            {finished === 1 ? '' : 's'} so far.
          </span>
          <button
            autoFocus
            onClick={onConfirm}
            disabled={sending}
            className="rounded-control border border-warn px-[13px] py-1.5 text-[12px] font-semibold text-warn hover:bg-[rgba(245,166,35,.1)] disabled:cursor-not-allowed disabled:opacity-50"
          >
            Stop the backtest
          </button>
          <button
            onClick={onKeep}
            className="rounded-control border border-border-strong px-[13px] py-1.5 text-[12px] font-semibold text-dim hover:text-text"
          >
            Keep running
          </button>
        </div>
      ) : (
        <button
          onClick={onOpen}
          disabled={sending}
          className="flex items-center gap-1.5 rounded-control border border-border-strong px-[11px] py-1 text-[11.5px] font-semibold text-dim hover:text-text disabled:cursor-not-allowed disabled:opacity-50"
        >
          <Square size={11} />
          Cancel backtest
        </button>
      )}
      {error && (
        <div role="alert" className="mt-1.5 text-[12px] text-danger">
          {error}
        </div>
      )}
    </div>
  );
}

/** A run an operator cancelled (R5-I9). It keeps the results of the alerts
 *  it finished, and states where it stopped before the score. */
function CancelledRun({ data }: { data: BacktestData }) {
  const r = data.results;
  const after = r?.cancel?.after ?? data.sampled ?? 0;
  const of = r?.cancel?.of ?? data.total;
  const decided = r?.completion?.decided ?? r?.metrics.counts.decided ?? r?.rows.length ?? 0;
  const scored = !!r && r.rows.length > 0 && decided > 0 && !r.completion?.degraded;
  return (
    <div data-testid="backtest-cancelled">
      <div className="mb-3 flex items-center gap-1.5 rounded-card border border-border bg-surface-2 px-4 py-2.5 text-[12px] font-semibold text-warn">
        <Square size={12} />
        Cancelled after {after} of {of} alerts.
      </div>
      {scored ? (
        <Results data={data} />
      ) : (
        <Panel className="p-6 text-center text-[13px] text-faint">
          {after === 0
            ? 'There is no score to report. No alert finished before the cancel.'
            : `There is no score to report. Only ${decided} of ${after} finished replays produced a verdict.`}
        </Panel>
      )}
    </div>
  );
}

function InterruptedRun({ data }: { data: BacktestData }) {
  const c = data.results?.completion;
  return (
    <div data-testid="backtest-interrupted">
      <Panel className="p-6 text-center text-[13px] text-danger">
        {c
          ? `This backtest stopped early. Only ${c.decided} of ${c.total} replays produced a verdict.`
          : 'The last backtest did not finish. Check the service logs. Run the backtest again.'}
        {c && (
          <div className="mt-1.5 text-[12px] text-faint">
            soc-ai could not replay the remaining {c.no_verdict}. There is no score to report.
            This is an infrastructure result. Check the grid. Run the backtest again.
          </div>
        )}
      </Panel>
    </div>
  );
}

function ProgressBar({ done, total }: { done: number; total: number }) {
  const p = total ? Math.min(100, Math.round((100 * done) / total)) : 0;
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-3">
      <div
        className="h-full rounded-full bg-accent transition-[width] duration-300"
        style={{ width: `${p}%` }}
      />
    </div>
  );
}

function Results({ data }: { data: BacktestData }) {
  const r = data.results!;
  const m = r.metrics;
  const missed = m.missed_tp;
  // With no escalated alert in the sample there is no true positive to agree
  // on or to miss. "100%" and "none missed" over zero incidents was a false
  // all-clear (fleet 2026-10-01, H6).
  const noEscalated = m.counts.human_tp === 0;

  return (
    <>
      {/* When this backtest actually ran — without it the results read as
          current no matter how stale they are (dogfood 2026-07-15). */}
      {data.finished_at && (
        <div className="mb-3 text-[12px] text-faint" data-testid="backtest-ran-at">
          Ran {ago(data.finished_at)}, at {absoluteTime(data.finished_at)}
        </div>
      )}
      {/* Coverage before score. A rate over rows soc-ai never judged is not a
          statement about soc-ai, so say how many it judged first. */}
      {r.completion && r.completion.no_verdict > 0 && (
        <div
          data-testid="backtest-partial-coverage"
          className="mb-3 rounded-card border border-border bg-surface-2 px-4 py-2.5 text-[12px] text-warn"
        >
          soc-ai replayed {r.completion.decided} of {r.completion.total} sampled alerts. The
          other {r.completion.no_verdict} produced no verdict. The rates below exclude them. They
          are missing coverage.
        </div>
      )}

      {/* headline metric cards */}
      <div className="mb-5 grid grid-cols-1 gap-3 md:grid-cols-3">
        {noEscalated ? (
          <MetricCard
            label="Agreement with analysts"
            value="Not measurable"
            sub="No escalated alert in the window. Agreement is not measurable."
            color="#8b94a3"
            small
          />
        ) : (
          <MetricCard
            label="Agreement with analysts"
            value={pct(m.agreement_rate)}
            sub={`${m.counts.agreements} of ${m.counts.decided ?? m.counts.total} replayed verdicts matched the analyst verdict`}
            color="#4b8bf5"
          />
        )}
        {/* An agreement figure. Auto-acknowledge also needs the confidence
            threshold, a retrieval, a resolved citation and a low-stakes
            alert, and a replay records none of those, so this is not what
            auto-acknowledge would clear (R5-D13). */}
        <MetricCard
          label="False-positive agreement"
          value={pct(fpAgreement(m))}
          sub={`soc-ai called ${m.counts.fp_cleared} of ${m.counts.human_fp_decided ?? m.counts.human_fp} acknowledged alerts a false positive.`}
          color="#3fb950"
        />
        <MissedTpCard missed={missed} humanTp={m.counts.human_tp} rows={r.missed_tp_rows} />
      </div>

      {/* confusion matrix */}
      <Panel className="mb-5 p-4">
        <div className="mb-3 text-[13px] font-semibold">Confusion matrix</div>
        <ConfusionTable confusion={r.confusion} />
        {m.n_needs_more_info > 0 && (
          <div className="mt-2 text-[11.5px] text-faint">
            soc-ai returned {VERDICT_LABEL.needs_more_info} on {m.n_needs_more_info} alert
            {m.n_needs_more_info === 1 ? '' : 's'}. Each one counts as a non-match.
          </div>
        )}
      </Panel>

      {/* per-alert table */}
      <Panel className="mb-4">
        <div className="border-b border-border px-4 py-3 text-[13px] font-semibold">
          Per-alert comparison
          <span className="ml-2 text-[12px] font-normal text-dim">
            {data.requested != null && data.requested !== data.sampled
              ? `${data.requested} requested · `
              : ''}
            {data.sampled} replayed · window {data.params?.window_days}d
            {data.params?.min_severity ? ` · ≥ ${data.params.min_severity}` : ''}
          </span>
          {data.skipped_reason && (
            <div data-testid="backtest-skipped" className="mt-1 text-[11.5px] font-normal text-faint">
              {data.skipped_reason}
            </div>
          )}
        </div>
        <RowsTable rows={r.rows} />
      </Panel>

      {/* proxy caveat */}
      <div className="rounded-card border border-border bg-surface-2 px-4 py-3 text-[11.5px] leading-relaxed text-faint">
        <span className="font-semibold text-dim">How soc-ai derives ground truth:</span> {r.caveat}
      </div>
    </>
  );
}

function MetricCard({
  label,
  value,
  sub,
  color,
  small = false,
}: {
  label: string;
  value: string;
  sub: string;
  color: string;
  small?: boolean;
}) {
  return (
    <Panel className="px-4 py-3.5">
      <div className="text-[11px] uppercase tracking-[.05em] text-dim">{label}</div>
      <div
        className={`mt-1 font-semibold tabular-nums ${small ? 'text-[20px] leading-[45px]' : 'text-[30px]'}`}
        style={{ color }}
      >
        {value}
      </div>
      <div className="mt-1 text-[11.5px] text-faint">{sub}</div>
    </Panel>
  );
}

/** The number a skeptic cares about most: real incidents soc-ai would have
 * called benign. Red when > 0, green "0 missed" when none. */
function MissedTpCard({
  missed,
  humanTp,
  rows,
}: {
  missed: number;
  humanTp: number;
  rows: BacktestRow[];
}) {
  if (humanTp === 0) {
    return (
      <MetricCard
        label="Missed true positives"
        value="Not measurable"
        sub="No escalated alert in the window. soc-ai had no true positive to miss."
        color="#8b94a3"
        small
      />
    );
  }
  const safe = missed === 0;
  const color = safe ? '#3fb950' : '#f04438';
  const bg = safe ? 'rgba(63,185,80,.07)' : 'rgba(240,68,56,.08)';
  const border = safe ? 'rgba(63,185,80,.32)' : 'rgba(240,68,56,.40)';
  return (
    <div
      className="rounded-panel border px-4 py-3.5"
      style={{ background: bg, borderColor: border }}
    >
      <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-[.05em]" style={{ color }}>
        {safe ? <ShieldCheck size={13} /> : <AlertTriangle size={13} />}
        Missed true positives
      </div>
      <div className="mt-1 flex items-baseline gap-2">
        <div className="text-[30px] font-semibold tabular-nums" style={{ color }}>
          {missed}
        </div>
        {safe && (
          <span className="flex items-center gap-1 text-[12px] font-semibold text-success">
            <CheckCircle2 size={13} /> none missed
          </span>
        )}
      </div>
      <div className="mt-1 text-[11.5px]" style={{ color: safe ? '#7ea88a' : '#e88' }}>
        {safe
          ? humanTp === 1
            ? 'soc-ai did not call the one escalated alert a false positive.'
            : `soc-ai called none of the ${humanTp} escalated alerts a false positive.`
          : `soc-ai called ${missed} escalated alert${missed === 1 ? '' : 's'} a false positive. A missed true positive is the most serious error.`}
      </div>
      {!safe && rows.length > 0 && (
        <ul className="mt-2 space-y-0.5 text-[11.5px]" style={{ color: '#e88' }}>
          {rows.slice(0, 4).map((row) => (
            <li key={row.alert_id} className="break-words" title={row.rule_name || row.alert_id}>
              • {row.rule_name || row.alert_id}
            </li>
          ))}
          {rows.length > 4 && <li className="text-faint">+ {rows.length - 4} more</li>}
        </ul>
      )}
    </div>
  );
}

function ConfusionTable({ confusion }: { confusion: BacktestConfusion }) {
  const dispositions: HumanDisposition[] = ['true_positive', 'false_positive'];
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[520px] border-collapse text-[12.5px]">
        <thead>
          <tr className="text-dim">
            <th className="px-2 py-1.5 text-left font-semibold">Analyst ↓ / soc-ai →</th>
            {SOC_ORDER.map((v) => (
              <th key={v} className="px-2 py-1.5 text-right font-semibold" style={{ color: VERDICT_COLOR[v] }}>
                {VERDICT_LABEL[v]}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {dispositions.map((disp) => (
            <tr key={disp} className="border-t border-border">
              <td className="px-2 py-1.5 font-semibold text-text-2">{DISPOSITION_LABEL[disp]}</td>
              {SOC_ORDER.map((v) => {
                const n = confusion[disp]?.[v] ?? 0;
                // The diagonal (agreement) cells are the ones we want to be big.
                const agree = disp === v;
                return (
                  <td
                    key={v}
                    className="px-2 py-1.5 text-right tabular-nums"
                    style={{
                      color: n === 0 ? '#7d8896' : agree ? '#3fb950' : '#cdd5e0',
                      fontWeight: agree && n > 0 ? 600 : 400,
                    }}
                  >
                    {n}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RowsTable({ rows }: { rows: BacktestRow[] }) {
  if (rows.length === 0) {
    return <div className="px-4 py-8 text-center text-[13px] text-faint">The table has no rows.</div>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] border-collapse text-[12.5px]">
        <thead>
          <tr className="border-b border-border text-[11px] uppercase tracking-[.04em] text-dim">
            <th className="px-4 py-2 text-left font-semibold">Rule</th>
            <th className="px-4 py-2 text-left font-semibold">Analyst disposition</th>
            <th className="px-4 py-2 text-left font-semibold">soc-ai verdict</th>
            <th className="px-4 py-2 text-right font-semibold">Match</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const verdict: SocVerdict = row.soc_ai_verdict ?? 'no_verdict';
            return (
              <tr key={row.alert_id} className="border-b border-border last:border-0">
                <td className="max-w-[280px] break-words px-4 py-2 text-text" title={row.rule_name}>
                  {/* The replay behind the verdict (R5-I10). */}
                  {row.investigation_id ? (
                    <Link
                      to={`/investigation/${encodeURIComponent(row.investigation_id)}`}
                      className="text-text underline decoration-border-strong underline-offset-2 hover:text-accent hover:decoration-accent"
                    >
                      {row.rule_name || row.alert_id}
                    </Link>
                  ) : (
                    row.rule_name || row.alert_id
                  )}
                </td>
                <td className="px-4 py-2" style={{ color: VERDICT_COLOR[row.human_disposition] }}>
                  {DISPOSITION_LABEL[row.human_disposition]}
                </td>
                <td className="px-4 py-2" style={{ color: VERDICT_COLOR[verdict] }}>
                  {VERDICT_LABEL[verdict]}
                </td>
                <td className="px-4 py-2 text-right">
                  {row.match ? (
                    <CheckCircle2
                      size={15}
                      role="img"
                      aria-label="Match"
                      className="ml-auto text-success"
                    />
                  ) : (
                    <AlertTriangle
                      size={15}
                      role="img"
                      aria-label="No match"
                      className="ml-auto text-danger"
                    />
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
