import { AlertTriangle, CheckCircle2, History, Loader2, Play, ShieldCheck } from 'lucide-react';
import { useRef, useState } from 'react';
import { Panel } from '../components/Panel';
import { ErrorState } from '../components/States';
import { getBacktest, startBacktest } from '../lib/api';
import { useAsync } from '../lib/useAsync';
import type {
  Backtest as BacktestData,
  BacktestConfusion,
  BacktestRow,
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
  { label: 'High & up', value: 'high' },
  { label: 'Critical only', value: 'critical' },
];

const VERDICT_LABEL: Record<SocVerdict, string> = {
  true_positive: 'True positive',
  false_positive: 'False positive',
  needs_more_info: 'Needs info',
  inconclusive: 'Inconclusive',
  no_verdict: 'No verdict',
};
const VERDICT_COLOR: Record<SocVerdict, string> = {
  true_positive: '#f04438',
  false_positive: '#7ba893',
  needs_more_info: '#f5a623',
  inconclusive: '#d29922',
  no_verdict: '#6b7484',
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

  const launch = () => {
    if (starting || running) return;
    setStarting(true);
    setStartError(null);
    startBacktest({ windowDays, sampleSize, minSeverity: minSeverity || undefined })
      .then(() => setReloadKey((k) => k + 1))
      .catch((e: unknown) =>
        setStartError(e instanceof Error ? e.message : 'Could not start the backtest.'),
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
          Prove it on your own last-N-days alerts. soc-ai replays its triage over a sample of
          alerts your analysts already dispositioned in Security Onion, then reports how its
          verdicts compare to your team's real calls — escalated&nbsp;=&nbsp;true positive,
          acknowledged&nbsp;=&nbsp;false positive. Read-only; nothing is written back to SO.
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
          <Field label="Min severity">
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
            onClick={launch}
            disabled={starting || running}
            className="flex items-center gap-1.5 rounded-control bg-accent px-[15px] py-2 text-[13px] font-semibold text-white hover:bg-accent-deep disabled:cursor-not-allowed disabled:opacity-50"
          >
            {starting || running ? (
              <Loader2 size={15} className="animate-spin" />
            ) : (
              <Play size={15} />
            )}
            {running ? 'Running…' : starting ? 'Starting…' : 'Run backtest'}
          </button>
        </div>
        <div className="mt-2.5 text-[11.5px] text-faint">
          Each sampled alert is a full LLM investigation — sample size is capped server-side.
          Only alerts your analysts actually dispositioned are sampled.
        </div>
        {startError && <div className="mt-2 text-[12px] text-danger">{startError}</div>}
      </Panel>

      {/* live progress */}
      {running && data && (
        <Panel className="mb-5 p-4">
          <div className="mb-2 flex items-center gap-2 text-[13px] font-semibold text-accent">
            <Loader2 size={15} className="animate-spin" />
            Replaying {data.total} dispositioned alert{data.total === 1 ? '' : 's'}…
          </div>
          <ProgressBar done={data.replayed + data.failed} total={data.total} />
          <div className="mt-2 text-[12px] text-dim">
            {data.replayed + data.failed} / {data.total} replayed
            {data.current && (
              <span className="text-faint">
                {' '}
                · investigating <span className="text-text-2">{data.current}</span>
              </span>
            )}
            {data.failed > 0 && (
              <span className="text-warn"> · {data.failed} failed</span>
            )}
          </div>
        </Panel>
      )}

      {/* results / errors / empty */}
      {error && !data ? (
        <ErrorState error={error} onRetry={() => setReloadKey((k) => k + 1)} />
      ) : data?.results && data.status === 'complete' ? (
        <Results data={data} />
      ) : data?.status === 'error' ? (
        <Panel className="p-6 text-center text-[13px] text-danger">
          The last backtest failed to complete. Check the service logs and try again.
        </Panel>
      ) : !running && !loading ? (
        <Panel className="p-8 text-center text-[13px] text-faint">
          {data?.note
            ? data.note
            : 'No backtest yet. Configure a window above and run one to see how soc-ai’s verdicts compare to your analysts’ real dispositions.'}
        </Panel>
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

  return (
    <>
      {/* headline metric cards */}
      <div className="mb-5 grid grid-cols-1 gap-3 md:grid-cols-3">
        <MetricCard
          label="Agreement with analysts"
          value={pct(m.agreement_rate)}
          sub={`${m.counts.agreements} of ${m.counts.total} verdicts matched the human call`}
          color="#4b8bf5"
        />
        <MetricCard
          label="False-positive toil cleared"
          value={pct(m.fp_reduction)}
          sub={`${m.counts.fp_cleared} of ${m.counts.human_fp} acknowledged alerts soc-ai would auto-clear`}
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
            soc-ai hedged ({VERDICT_LABEL.needs_more_info}) on {m.n_needs_more_info} alert
            {m.n_needs_more_info === 1 ? '' : 's'} — counted as a non-match.
          </div>
        )}
      </Panel>

      {/* per-alert table */}
      <Panel className="mb-4">
        <div className="border-b border-border px-4 py-3 text-[13px] font-semibold">
          Per-alert comparison
          <span className="ml-2 text-[12px] font-normal text-dim">
            {data.sampled} replayed · window {data.params?.window_days}d
            {data.params?.min_severity ? ` · ≥ ${data.params.min_severity}` : ''}
          </span>
        </div>
        <RowsTable rows={r.rows} />
      </Panel>

      {/* proxy caveat */}
      <div className="rounded-card border border-border bg-surface-2 px-4 py-3 text-[11.5px] leading-relaxed text-faint">
        <span className="font-semibold text-dim">How ground truth is derived:</span> {r.caveat}
      </div>
    </>
  );
}

function MetricCard({
  label,
  value,
  sub,
  color,
}: {
  label: string;
  value: string;
  sub: string;
  color: string;
}) {
  return (
    <Panel className="px-4 py-3.5">
      <div className="text-[11px] uppercase tracking-[.05em] text-dim">{label}</div>
      <div className="mt-1 text-[30px] font-semibold tabular-nums" style={{ color }}>
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
          ? `soc-ai agreed on every one of the ${humanTp} escalated incident${humanTp === 1 ? '' : 's'}.`
          : `real incident${missed === 1 ? '' : 's'} soc-ai called false positive — the critical safety miss.`}
      </div>
      {!safe && rows.length > 0 && (
        <ul className="mt-2 space-y-0.5 text-[11.5px]" style={{ color: '#e88' }}>
          {rows.slice(0, 4).map((row) => (
            <li key={row.alert_id} className="truncate">
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
                      color: n === 0 ? '#5b6473' : agree ? '#3fb950' : '#cdd5e0',
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
    return <div className="px-4 py-8 text-center text-[13px] text-faint">No rows.</div>;
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
                <td className="max-w-[280px] truncate px-4 py-2 text-text" title={row.rule_name}>
                  {row.rule_name || row.alert_id}
                </td>
                <td className="px-4 py-2" style={{ color: VERDICT_COLOR[row.human_disposition] }}>
                  {DISPOSITION_LABEL[row.human_disposition]}
                </td>
                <td className="px-4 py-2" style={{ color: VERDICT_COLOR[verdict] }}>
                  {VERDICT_LABEL[verdict]}
                </td>
                <td className="px-4 py-2 text-right">
                  {row.match ? (
                    <CheckCircle2 size={15} className="ml-auto text-success" />
                  ) : (
                    <AlertTriangle size={15} className="ml-auto text-danger" />
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
