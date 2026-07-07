import { Wrench } from 'lucide-react';

import { KIND, SEVERITY, VERDICT } from '../lib/tokens';
import type { DetectionKind, Severity, Verdict } from '../lib/types';

// ---- "In development" badge — marks features that aren't wired up yet -------
export function DevBadge({ label = 'In development' }: { label?: string }) {
  return (
    <span
      className="inline-flex flex-none items-center rounded-chip border px-1.5 py-px text-[9.5px] font-semibold uppercase tracking-[.04em]"
      style={{ color: '#f5a623', borderColor: 'rgba(245,166,35,.35)', background: 'rgba(245,166,35,.08)' }}
    >
      {label}
    </span>
  );
}

// ---- Detection kind badge (mono uppercase pill) ----------------------------
export function KindBadge({ kind }: { kind: DetectionKind }) {
  const k = KIND[kind];
  return (
    <span
      className="flex-none rounded-chip border px-1.5 py-0.5 font-mono text-[9.5px] font-semibold uppercase tracking-[.04em]"
      style={{ color: k.color, background: k.bg, borderColor: k.border }}
    >
      {kind}
    </span>
  );
}

// ---- Severity dot + label --------------------------------------------------
export function SeverityTag({ sev }: { sev: Severity }) {
  const s = SEVERITY[sev];
  return (
    <span className="inline-flex items-center gap-1.5 text-[11.5px] font-semibold" style={{ color: s.color }}>
      <span
        className="h-[7px] w-[7px] rounded-[2px]"
        style={{ background: s.color, boxShadow: `0 0 7px ${s.glow}` }}
      />
      {s.label}
    </span>
  );
}

// ---- soc·ai verdict pill ---------------------------------------------------
interface VerdictPillProps {
  verdict: Verdict;
  conf?: number | null;
  inherited?: boolean;
  /** large = the verdict card hero pill (uppercase, glow) */
  large?: boolean;
  /** set false to hide the inline confidence number (grid rows show conf in its own column) */
  showConf?: boolean;
  /** set false to hide the inline " · inherited" text (compact list rows — dashed border + tooltip already convey it) */
  showInherited?: boolean;
}
export function VerdictPill({ verdict, conf, inherited, large, showConf = true, showInherited = true }: VerdictPillProps) {
  const v = VERDICT[verdict];
  return (
    <span
      className={
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded-pill border font-semibold ' +
        (large
          ? 'px-3 py-[5px] text-[12.5px] uppercase tracking-[.01em]'
          : 'px-[9px] py-[2.5px] text-[11.5px]')
      }
      style={{
        color: v.color,
        background: v.bg,
        borderColor: v.border,
        borderStyle: inherited ? 'dashed' : 'solid',
      }}
    >
      <span
        className="h-1.5 w-1.5 rounded-full"
        style={{ background: v.color, boxShadow: large ? `0 0 8px ${v.color}` : undefined }}
      />
      {v.label}
      {inherited && showInherited && ' · inherited'}
      {showConf && conf != null && (
        <span className="font-mono opacity-80">{conf.toFixed(2)}</span>
      )}
    </span>
  );
}

// ---- pipeline-error chip (E1.2) --------------------------------------------
// A needs_more_info run that FAILED before reaching a verdict (model truncation,
// gateway 5xx) — NOT a genuine "needs more info". Rendered in slate/red with a
// wrench so an analyst reads it as "infra broke, retry", not "dig deeper". Used
// in place of the amber Needs-info VerdictPill on the Alerts + Investigations
// rows, and as a filterable status.
export function PipelineErrorChip({ hint, large }: { hint?: string | null; large?: boolean }) {
  return (
    <span
      className={
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded-pill border font-semibold ' +
        (large ? 'px-3 py-[5px] text-[12.5px] uppercase tracking-[.01em]' : 'px-[9px] py-[2.5px] text-[11.5px]')
      }
      style={{ color: '#fca5a5', background: 'rgba(240,68,56,.09)', borderColor: 'rgba(240,68,56,.35)' }}
      title={hint ?? 'This run failed before reaching a verdict — re-run it'}
    >
      <Wrench size={large ? 12 : 10} strokeWidth={2.5} />
      Pipeline error
    </span>
  );
}

// ---- source / apply badges (config) ---------------------------------------
export function SourceBadge({ source }: { source: 'db' | 'env' }) {
  const db = source === 'db';
  return (
    <span
      className="rounded-chip border px-1.5 py-[1.5px] font-mono text-[9.5px] font-semibold uppercase"
      style={
        db
          ? { color: '#4b8bf5', background: 'rgba(75,139,245,.1)', borderColor: 'rgba(75,139,245,.3)' }
          : { color: '#f5a623', background: 'rgba(245,166,35,.1)', borderColor: 'rgba(245,166,35,.3)' }
      }
    >
      {source}
    </span>
  );
}

export function ApplyBadge({ apply }: { apply: 'hot-apply' | 'restart' }) {
  return (
    <span
      className="rounded-chip border border-border-input bg-surface-3 px-1.5 py-[1.5px] font-mono text-[9.5px] font-semibold uppercase"
      style={{ color: apply === 'hot-apply' ? '#3fb950' : '#f5a623' }}
    >
      {apply}
    </span>
  );
}

// ---- status dot (investigations / hunts) ----------------------------------
interface StatusTagProps {
  color: string;
  label: string;
  pulse?: boolean;
}
export function StatusTag({ color, label, pulse }: StatusTagProps) {
  return (
    <span className="inline-flex items-center gap-1.5 text-[11.5px]" style={{ color }}>
      <span
        className={'h-1.5 w-1.5 rounded-full ' + (pulse ? 'animate-pulseDot' : '')}
        style={{ background: color }}
      />
      {label}
    </span>
  );
}
