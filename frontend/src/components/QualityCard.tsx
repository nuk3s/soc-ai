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
// noise into a dramatic-looking cliff.

import { Activity } from 'lucide-react';
import type { QualityPoint } from '../lib/api';
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
 * Card body (the parent owns the Panel + header, like EnrichmentPanel).
 *
 * `error` renders the admin hint — the trend is admin-gated server-side, so a
 * non-admin session's 403 is expected, not a failure. The empty state names
 * the exact command to schedule, because an empty trend means the nightly has
 * simply never run here.
 */
export function QualityCard({
  points,
  error,
  loading,
}: {
  points: QualityPoint[];
  error: Error | null;
  loading: boolean;
}) {
  if (error) {
    return (
      <div className="px-[15px] py-3.5 text-[12px] leading-[1.5] text-faint">
        Sign in as an admin to view quality history.
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

      {latest.alarmed && (
        <div
          role="alert"
          className="mt-2.5 rounded-card border px-2.5 py-2 text-[11.5px] leading-[1.5]"
          style={{ borderColor: 'rgba(240,68,56,.35)', background: 'rgba(240,68,56,.08)' }}
        >
          <div className="font-semibold" style={{ color: '#f04438' }}>
            Last run tripped the regression alarm
          </div>
          {latest.alarm_reasons.map((r) => (
            <div key={r} className="mt-0.5 text-dim">
              {r}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
