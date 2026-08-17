// Quality card (I4): the nightly micro-eval trend on the dashboard.
//
// Sparkline decision: recharts stays OUT of this card on purpose. It is only
// imported by HuntVisuals today, so the Dashboard route chunk carries no
// charting library — pulling recharts in for a 40px line would bloat the most
// visited chunk in the app. A hand-rolled <polyline> is ~20 lines, and its
// coordinate math is a pure exported function (`sparklinePoints`) so vitest
// can pin it without rendering SVG.
//
// Honesty rules the layout: every point is labeled with the MODE that measured
// it ("oracle graded" vs "locally measured" — different instruments, never
// blended on one line), the sparkline only plots the current mode's points,
// and the y-domain is FIXED to 0..1 so autoscaling can't amplify one-alert
// noise into a dramatic-looking cliff. Same rule drives the two things a bare
// rate can't say: the grade composition behind it (`gradeBreakdown`) and, on an
// alarm, where the oracle critiques that would settle it actually live
// (`EvidencePath`). Both come from columns added in migration 0026 and are NULL
// on older rows, so both render as nothing at all rather than as a zero or a
// dead link.
//
// The same honesty rule governs the ALARM strip, whose identity fields arrived
// in migration 0027 — see the "alarm identity" section below for what the card
// was getting wrong (one latched sentence for every condition, forever).

import { Activity, Copy, X } from 'lucide-react';
import { useState } from 'react';
import type { QualityPoint } from '../lib/api';
import { dismissNotification, getDismissed } from '../lib/notifications';
import { absTime } from '../lib/timeRange';
import { LoadingState } from './States';

// ---- pure seams (unit-tested in QualityCard.test.tsx) -----------------------

/**
 * Map a series of 0..1 rates onto SVG polyline coordinates.
 *
 * Fixed 0..1 y-domain (see header note); values are clamped defensively so a
 * malformed rate can't draw outside the box. A single point is duplicated
 * across the full width so "one night of history" still renders as a visible
 * flat line instead of an invisible dot.
 */
export function sparklinePoints(
  values: number[],
  width: number,
  height: number,
  pad = 2,
): string {
  if (values.length === 0) return '';
  const vs = values.length === 1 ? [values[0], values[0]] : values;
  const innerW = width - pad * 2;
  const innerH = height - pad * 2;
  const step = innerW / (vs.length - 1);
  return vs
    .map((raw, i) => {
      const v = Math.min(1, Math.max(0, raw));
      const x = pad + i * step;
      const y = pad + (1 - v) * innerH;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');
}

export interface QualitySeries {
  mode: 'local' | 'graded';
  /** What the line IS — shown next to the sparkline so it's never ambiguous. */
  label: string;
  /** True when lower values are better (fallback rate) — flips the sub-copy. */
  lowerIsBetter: boolean;
  values: number[];
}

/**
 * Pick the one honest series to plot from a mixed trend.
 *
 * The latest point's mode wins; only same-mode points join the line (a graded
 * agreement rate and a local fallback rate are different instruments). Graded
 * mode plots agreement (higher = better); local mode plots the fallback rate
 * (lower = better) — the strongest zero-egress degradation proxy the nightly
 * records. Points missing the metric (e.g. a graded run where the oracle
 * classified nothing) are skipped rather than faked as 0.
 */
export function seriesFor(points: QualityPoint[]): QualitySeries | null {
  if (points.length === 0) return null;
  const mode = points[points.length - 1].mode;
  const same = points.filter((p) => p.mode === mode);
  if (mode === 'graded') {
    return {
      mode,
      label: 'agreement',
      lowerIsBetter: false,
      values: same.map((p) => p.agreement_rate).filter((v): v is number => v !== null),
    };
  }
  return {
    mode,
    label: 'fallback rate',
    lowerIsBetter: true,
    values: same.map((p) => p.fallback_rate).filter((v): v is number => v !== null),
  };
}

export function pct(v: number | null): string {
  return v === null ? '—' : `${Math.round(v * 100)}%`;
}

/**
 * Spell out the grades behind `agreement_rate`, or null when there are none.
 *
 * The rate is `n_yes / n_classified`, and a `partial` critique ("right verdict,
 * thin reasoning") sits in that denominator but not the numerator — so a bare
 * "60%" reads identically whether two runs were under-argued or two were flat
 * wrong. Those call for different responses (tune the prompt vs. investigate a
 * regression), hence the composition.
 *
 * Returns null rather than zeros for the two cases that are NOT evidence:
 * pre-migration-0026 rows, where the counts were never recorded and can't be
 * recovered, and local-mode rows, where no oracle graded anything. Rendering
 * "0 agree" for either would state a fact the server never asserted.
 *
 * Zero terms are dropped so the common clean night reads "5 agree" — except the
 * numerator, which is kept even at 0 because "0 agree · 5 disagree" is the
 * single most important thing this card can say.
 */
export function gradeBreakdown(p: QualityPoint): string | null {
  // n_yes gates the whole line (it is the numerator); n_classified must also be
  // a real denominator, which is what excludes local mode's honest 0/0.
  if (p.n_yes === null || !p.n_classified) return null;
  // Truthiness on the other two is deliberate: it drops a 0 AND a null, and the
  // four columns are written as a set, so a null here can only mean a row we
  // have no counts for anyway.
  const parts = [`${p.n_yes} agree`];
  if (p.n_partial) parts.push(`${p.n_partial} partial`);
  if (p.n_no) parts.push(`${p.n_no} disagree`);
  return parts.join(' · ');
}

// ---- alarm identity (migration 0027) ---------------------------------------
//
// The banner used to be a LATCH: the latest snapshot's `alarmed` flag lit it,
// so ONE alarmed run shouted "Last run tripped the regression alarm" for up to
// 24h — and kept shouting the same sentence while the condition simply stayed
// true, with no exit except running another eval (another chance to alarm).
// Worse, an `error_ceiling` alarm ("the eval itself errored") wore the
// verdict-quality headline, and an operator read a dead pipeline as regressed
// verdicts. The server now records WHICH condition and SINCE WHEN, which is
// everything the three fixes below need: honest headline, ongoing vs new, and
// a dismissal that can be scoped to one condition instead of one render.

/** The one code that is NOT about verdict quality: the eval errored out, so
 * nothing was graded. "The grader could not run" and "verdicts got worse" need
 * different responses, so they must not share a headline. */
const CODE_ERROR_CEILING = 'error_ceiling';

/** localStorage id prefix. Namespaced like the bell's ids (`inv:`, `approval:`)
 * because it shares that dismissed-id set — see `dismissIdFor`. */
const DISMISS_PREFIX = 'quality-alarm:';

export interface AlarmBanner {
  /** `pipeline` = eval health (nothing was graded); `quality` = verdict quality
   * regressed. Pre-0027 rows are `quality`: that is the banner they have today
   * and this change must not re-classify a row the server never re-shaped. */
  kind: 'quality' | 'pipeline';
  headline: string;
  /** The pipeline half of a MIXED alarm, rendered as its own line beneath the
   * quality banner. Both conditions are true and each needs its own response,
   * so neither may be blended into the other's sentence. Null otherwise. */
  pipelineNote: string | null;
  /** True when the condition predates the latest run — "still true", not "just
   * happened". */
  ongoing: boolean;
  /** Consecutive trailing runs on this condition. Counted within the fetched
   * window (30 points), so a very long-running condition reads as "at least"
   * this many — the `since` date, which the server computed, is the load-bearing
   * fact and the count is only there to convey persistence. */
  runs: number;
  /** Persistence id for the dismiss control, or null when the row carries no
   * alarm identity (pre-0027) — nothing to key on means no dismiss offered. */
  dismissId: string | null;
}

/** Count the trailing points that share `key` (the run of the current condition). */
function trailingRuns(points: QualityPoint[], key: string): number {
  let n = 0;
  for (let i = points.length - 1; i >= 0; i--) {
    // A clean point has a null key, so a clean night naturally ends the run:
    // the same code raised again afterwards is a NEW condition, not this one.
    if ((points[i].alarm_key ?? null) !== key) break;
    n++;
  }
  return n;
}

/**
 * The dismissal key: the condition AND the instance of it.
 *
 * `alarm_key` alone would be wrong in the direction that costs an incident —
 * dismissing "agreement_drop" once would suppress every future agreement drop
 * forever, including one raised months later after a clean stretch. `alarm_since`
 * alone would be wrong the other way: it changes on every re-raise but says
 * nothing about which condition it belongs to.
 *
 * Together they name one instance. The server holds `alarm_since` STEADY while
 * a condition persists and moves it only on a fresh transition, so a dismissal
 * sticks for exactly as long as the operator's judgement about it holds: the
 * banner stays gone while the same condition stays true, and a genuinely new
 * alarm — different code, or the same code raised again — arrives undismissed.
 */
function dismissIdFor(latest: QualityPoint): string | null {
  const key = latest.alarm_key ?? null;
  if (!key) return null;
  // `alarm_since` is always set alongside the key by the server; the fallback
  // is defensive, and deliberately fails toward re-showing (a per-run id) rather
  // than toward hiding an alarm forever.
  return `${DISMISS_PREFIX}${key}@${latest.alarm_since ?? latest.ts}`;
}

/**
 * What the alarm strip should say, or null when the latest run is clean.
 *
 * A pure seam so the headline rules can be pinned without rendering: they are
 * where the dishonesty lived, not in the markup.
 */
export function alarmBanner(points: QualityPoint[]): AlarmBanner | null {
  if (points.length === 0) return null;
  const latest = points[points.length - 1];
  if (!latest.alarmed) return null;

  // Empty covers BOTH "clean" and "pre-0027 row". Only the second can reach
  // here, and it means the server never recorded which condition fired — so
  // every branch below falls back to today's banner rather than guessing.
  const codes = latest.alarm_codes ?? [];
  // No Array.prototype.includes concerns here, but indexOf keeps it uniform
  // with the rest of the file's ES2020 vocabulary.
  const hasPipeline = codes.indexOf(CODE_ERROR_CEILING) !== -1;
  const pipelineOnly = hasPipeline && codes.length === 1;

  const since = latest.alarm_since ?? null;
  const key = latest.alarm_key ?? null;
  const startedAt = since ? Date.parse(since) : NaN;
  const ranAt = Date.parse(latest.ts);
  // Strictly earlier: on the run that RAISED the alarm the server writes the
  // same instant into both, and that run genuinely is news.
  const ongoing = !Number.isNaN(startedAt) && !Number.isNaN(ranAt) && startedAt < ranAt;
  const runs = key ? trailingRuns(points, key) : 0;

  const errored = latest.n_error;
  const total = latest.n_ok + latest.n_error;
  const ongoingClause = `ongoing since ${absTime(since)} (${runs} run${runs === 1 ? '' : 's'})`;

  if (pipelineOnly) {
    return {
      kind: 'pipeline',
      headline: ongoing
        ? `Eval pipeline failing — ${ongoingClause}`
        : `Eval pipeline failing — ${errored} of ${total} eval runs errored`,
      pipelineNote: null, // the headline is already the pipeline sentence
      ongoing,
      runs,
      dismissId: dismissIdFor(latest),
    };
  }

  return {
    kind: 'quality',
    headline: ongoing
      ? `Regression alarm — ${ongoingClause}`
      : 'Last run tripped the regression alarm',
    pipelineNote: hasPipeline
      ? `Eval pipeline also failing — ${errored} of ${total} eval runs errored.`
      : null,
    ongoing,
    runs,
    dismissId: dismissIdFor(latest),
  };
}

// ---- presentation -----------------------------------------------------------

function ModeBadge({ mode }: { mode: 'local' | 'graded' }) {
  const graded = mode === 'graded';
  return (
    <span
      className="rounded-pill border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[.05em]"
      style={{
        color: graded ? '#4b8bf5' : '#8b94a3',
        borderColor: graded ? 'rgba(75,139,245,.4)' : 'rgba(139,148,163,.4)',
      }}
    >
      {graded ? 'oracle graded' : 'locally measured'}
    </span>
  );
}

function Sparkline({ values, alarmed }: { values: number[]; alarmed: boolean }) {
  const W = 220;
  const H = 36;
  const pts = sparklinePoints(values, W, H);
  if (!pts) return null;
  const color = alarmed ? '#f04438' : '#4b8bf5';
  // No Array.at(): the app's tsconfig lib predates es2022.
  const coords = pts.split(' ');
  const last = coords[coords.length - 1]?.split(',');
  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      className="mt-2 h-9 w-full"
      preserveAspectRatio="none"
      role="img"
      aria-label="quality trend sparkline"
    >
      <polyline points={pts} fill="none" stroke={color} strokeWidth={1.5} />
      {last && <circle cx={Number(last[0])} cy={Number(last[1])} r={2.5} fill={color} />}
    </svg>
  );
}

/**
 * The eval bundle behind an alarm, as a path an operator can act on.
 *
 * Shown as plain text and not a link because nothing serves these bundles over
 * HTTP: `batch_dir` is a directory on the soc-ai host (inside the container's
 * `soc_ai_evals` volume). An anchor here would promise a click that can't work,
 * so the affordance is "copy it and paste it into a shell" instead.
 *
 * The copy button only appears where `navigator.clipboard` exists — it is
 * undefined in insecure contexts, and a plain-http LAN install would otherwise
 * get a button that silently does nothing. The path stays selectable either
 * way, so nothing is lost.
 */
function EvidencePath({ path }: { path: string }) {
  const [copied, setCopied] = useState(false);
  const canCopy = typeof navigator !== 'undefined' && !!navigator.clipboard;

  const copy = () => {
    navigator.clipboard
      .writeText(path)
      .then(() => {
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1500);
      })
      .catch(() => {});
  };

  return (
    <div
      data-testid="quality-evidence"
      className="mt-2 border-t pt-1.5"
      style={{ borderColor: 'rgba(240,68,56,.2)' }}
    >
      <div className="text-[10.5px] text-faint">
        Oracle critiques behind this alarm — a path on the soc-ai host, not a link:
      </div>
      <div className="mt-0.5 flex items-start gap-1.5">
        <code className="min-w-0 flex-1 break-all font-mono text-[11px] text-mono-amber">
          {path}
        </code>
        {canCopy && (
          <button
            onClick={copy}
            aria-label="Copy path"
            title="Copy path"
            className="flex flex-none items-center gap-1 text-[10.5px] text-accent hover:underline"
          >
            <Copy size={11} />
            {copied ? 'Copied' : 'Copy'}
          </button>
        )}
      </div>
    </div>
  );
}

/**
 * Card body (the parent owns the Panel + header, like EnrichmentPanel).
 *
 * `error` renders the admin hint — the trend is admin-gated server-side, so a
 * non-admin session's 403 is expected, not a failure. On the public demo the
 * gate refuses admin reads outright (SOC_AI_DEMO), and there is no admin to sign
 * in as, so `demo` swaps the hint for a neutral "not shown in the demo" line —
 * never a scary error card. The empty state names the exact command to schedule,
 * because an empty trend means the nightly has simply never run here.
 */
export function QualityCard({
  points,
  error,
  loading,
  demo = false,
}: {
  points: QualityPoint[];
  error: Error | null;
  loading: boolean;
  /** True on the public demo, where admin reads are 403 by design — degrade to a
   * neutral line rather than an admin-login prompt that can't be followed. */
  demo?: boolean;
}) {
  // The bell's dismissal mechanism, reused rather than re-implemented: one
  // localStorage set of ids in lib/notifications, read at mount and written
  // through a helper that survives blocked storage. Read once into state so the
  // click re-renders — an id the set has never seen (a new alarm) is not in it,
  // so a new condition surfaces without any reset step.
  const [dismissedIds, setDismissedIds] = useState(() => getDismissed());

  if (error) {
    return (
      <div className="px-[15px] py-3.5 text-[12px] leading-[1.5] text-faint">
        {demo
          ? 'Quality history is an admin-only view — not shown in the demo.'
          : 'Sign in as an admin to view quality history.'}
      </div>
    );
  }
  if (points.length === 0) {
    return loading ? (
      <LoadingState label="Loading…" />
    ) : (
      <div className="px-[15px] py-3.5 text-[12.5px] leading-[1.6] text-dim">
        No quality history yet — use <span className="font-semibold text-text-2">Run now</span>{' '}
        above, or enable the nightly eval in Config → Quality.{' '}
        <span className="text-faint">
          (Host cron via{' '}
          <code className="rounded bg-surface-3 px-1 font-mono text-[11px]">
            soc-ai eval-nightly
          </code>{' '}
          still works — see docs/DOCKER.md.)
        </span>
      </div>
    );
  }

  const latest = points[points.length - 1];
  const series = seriesFor(points);
  const headline = latest.mode === 'graded' ? latest.agreement_rate : latest.fallback_rate;
  const headlineLabel = latest.mode === 'graded' ? 'agreement' : 'fallback rate';
  const breakdown = gradeBreakdown(latest);
  const alarm = alarmBanner(points);
  // Hoisted to a const so it narrows inside the click handler below (a property
  // read would not).
  const dismissId = alarm?.dismissId ?? null;
  const alarmHidden = dismissId !== null && dismissedIds.has(dismissId);
  const dismissAlarm = (id: string) => {
    // Writes to the shared dismissed-id set, which also broadcasts the bell's
    // re-read event. Harmless (no notification carries a `quality-alarm:` id, so
    // nothing in the bell changes) and worth one redundant poll to keep exactly
    // one dismissal mechanism in the app rather than a second half of one.
    dismissNotification(id);
    setDismissedIds((prev) => new Set(prev).add(id));
  };
  // Amber, not red: the eval pipeline being down is an operational fault to
  // repair, while a verdict-quality regression is a finding to adjudicate.
  const tone =
    alarm?.kind === 'pipeline'
      ? { fg: '#f5a623', border: 'rgba(245,166,35,.35)', bg: 'rgba(245,166,35,.08)' }
      : { fg: '#f04438', border: 'rgba(240,68,56,.35)', bg: 'rgba(240,68,56,.08)' };

  return (
    <div className="px-[15px] py-3.5">
      <div className="flex items-center justify-between gap-2">
        <ModeBadge mode={latest.mode} />
        <span className="flex items-center gap-1 text-[10.5px] text-faint">
          <Activity size={11} />
          {points.length} run{points.length === 1 ? '' : 's'}
        </span>
      </div>

      <div className="mt-2.5 flex items-baseline gap-2">
        <span
          className="text-[24px] font-semibold leading-none tabular-nums"
          style={{ color: latest.alarmed ? '#f04438' : '#e6e9ef' }}
        >
          {pct(headline)}
        </span>
        <span className="text-[11.5px] text-dim">{headlineLabel}</span>
      </div>
      {/* Directly under the rate, and absent (not blank) on rows that carry no
          counts — so a pre-0026 row keeps exactly the layout it had before. */}
      {breakdown && (
        <div
          data-testid="quality-grade-counts"
          className="mt-1 text-[11.5px] text-dim"
          title="A partial critique — right verdict, thin reasoning — counts against the rate exactly as hard as a disagreement."
        >
          {breakdown}
        </div>
      )}
      <div className="mt-1 text-[11.5px] text-dim">
        {latest.n_ok} ok · {latest.n_error} err · error {pct(latest.error_rate)}
        {latest.mode === 'graded' && <> · fallback {pct(latest.fallback_rate)}</>}
      </div>

      {series && series.values.length > 0 && (
        <>
          <Sparkline values={series.values} alarmed={latest.alarmed} />
          <div className="mt-0.5 text-[10.5px] text-faint">
            {series.label}
            {series.lowerIsBetter ? ' · lower is better' : ''} · fixed 0–100% scale
          </div>
        </>
      )}

      {/* Dismissing hides THIS strip and nothing else — the rate, the counts and
          the trend above are the record, and an operator who has read an alarm
          still needs to see the numbers it was about. */}
      {alarm && !alarmHidden && (
        <div
          role="alert"
          className="mt-2.5 rounded-card border px-2.5 py-2 text-[11.5px] leading-[1.5]"
          style={{ borderColor: tone.border, background: tone.bg }}
        >
          <div className="flex items-start justify-between gap-2">
            <div className="font-semibold" style={{ color: tone.fg }}>
              {alarm.headline}
            </div>
            {dismissId && (
              <button
                onClick={() => dismissAlarm(dismissId)}
                aria-label="Dismiss alarm"
                title="Hide this alarm. It comes back if the condition changes or is raised again."
                className="flex-none text-faint hover:text-text-2"
              >
                <X size={12} />
              </button>
            )}
          </div>
          {alarm.kind === 'pipeline' && (
            <div className="mt-0.5 text-dim">
              The eval errored before it produced verdicts to judge — pipeline health, not verdict
              quality.
            </div>
          )}
          {latest.alarm_reasons.map((r) => (
            <div key={r} className="mt-0.5 text-dim">
              {r}
            </div>
          ))}
          {/* A second, separate line rather than a blended headline: on a mixed
              alarm both statements are true and each has its own fix. */}
          {alarm.pipelineNote && (
            <div
              data-testid="quality-pipeline-note"
              className="mt-1.5 border-t pt-1.5 font-semibold"
              style={{ borderColor: tone.border, color: '#f5a623' }}
            >
              {alarm.pipelineNote}
            </div>
          )}
          {latest.batch_dir && <EvidencePath path={latest.batch_dir} />}
        </div>
      )}
    </div>
  );
}
