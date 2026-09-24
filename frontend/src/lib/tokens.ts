// ---------------------------------------------------------------------------
// Semantic color/label metadata maps. Components inline these computed values
// (rgba washes, glows) where Tailwind can't express a runtime value; static
// classes still come from tailwind.config tokens elsewhere.
// ---------------------------------------------------------------------------

import { CHIP_CATALOG_RUN, TYPE_LEAD, TYPE_MANUAL, TYPE_SCHEDULE } from './tooltips';
import type { DetectionKind, HuntKind, Severity, Verdict } from './types';

export interface SevMeta {
  label: string;
  color: string;
  glow: string;
}
// The single canonical severity ramp for the whole app — bars, chips, status
// dots, and SVG node fills. Green is deliberately absent: it means success /
// clean everywhere else, so a green severity is a color-scan hazard. Hunt
// charts derive their colors from this map (see HuntVisuals / HuntDetail)
// instead of the old second ramp whose "low" was green.
export const SEVERITY: Record<Severity, SevMeta> = {
  critical: { label: 'Critical', color: '#f04438', glow: 'rgba(240,68,56,.6)' },
  high: { label: 'High', color: '#f79009', glow: 'rgba(247,144,9,.55)' },
  medium: { label: 'Medium', color: '#eab308', glow: 'rgba(234,179,8,.45)' },
  low: { label: 'Low', color: '#6b87a8', glow: 'rgba(107,135,168,.4)' },
  info: { label: 'Info', color: '#8b949e', glow: 'rgba(139,148,158,.35)' },
  // No severity on the document. Off the ramp on purpose — a muted violet-grey
  // that belongs to none of the four rungs, so a colour scan cannot read it as
  // a position between them. SeverityTag draws its dot hollow for the same
  // reason. See the Severity union in lib/types.ts.
  unknown: { label: 'Unknown', color: '#9a8fb0', glow: 'rgba(154,143,176,.3)' },
};

export interface VerdictMeta {
  label: string;
  color: string;
  bg: string;
  border: string;
  wash: string;
}
export const VERDICT: Record<Verdict, VerdictMeta> = {
  true_positive: { label: 'True positive', color: '#f04438', bg: 'rgba(240,68,56,.10)', border: 'rgba(240,68,56,.32)', wash: 'rgba(240,68,56,.07)' },
  false_positive: { label: 'False positive', color: '#7ba893', bg: 'rgba(123,168,147,.10)', border: 'rgba(123,168,147,.32)', wash: 'rgba(123,168,147,.07)' },
  needs_more_info: { label: 'Needs info', color: '#f5a623', bg: 'rgba(245,166,35,.10)', border: 'rgba(245,166,35,.32)', wash: 'rgba(245,166,35,.07)' },
  // Self-consistency vote didn't converge — "the model couldn't decide", a
  // terminal hedge distinct from needs_more_info's "needs YOUR input" amber.
  // Gold matches the interrupted/warning tone used elsewhere (#d29922).
  inconclusive: { label: 'Inconclusive', color: '#d29922', bg: 'rgba(210,153,34,.10)', border: 'rgba(210,153,34,.32)', wash: 'rgba(210,153,34,.07)' },
  untriaged: { label: 'Untriaged', color: '#6b7484', bg: 'rgba(107,116,132,.08)', border: 'rgba(107,116,132,.25)', wash: 'rgba(107,116,132,.05)' },
};

export interface KindMeta {
  color: string;
  bg: string;
  border: string;
}
// 'hunt' covers a finding PROMOTED out of a hunt into a full investigation —
// distinct from the three detection-fired kinds above it (pink, not a shade
// of any of them, so a promoted row never reads as a stray Suricata/Sigma hit).
export const KIND: Record<DetectionKind, KindMeta> = {
  suricata: { color: '#4b8bf5', bg: 'rgba(75,139,245,.1)', border: 'rgba(75,139,245,.3)' },
  sigma: { color: '#a472f0', bg: 'rgba(164,114,240,.1)', border: 'rgba(164,114,240,.3)' },
  notice: { color: '#2dd4bf', bg: 'rgba(45,212,191,.1)', border: 'rgba(45,212,191,.3)' },
  hunt: { color: '#f472b6', bg: 'rgba(244,114,182,.1)', border: 'rgba(244,114,182,.3)' },
  // Alerts with no rule name, grouped by dataset. Slate: the badge says what
  // the row is missing, and dressing that in a detector's colour would imply a
  // detector produced it.
  unnamed: { color: '#94a3b8', bg: 'rgba(148,163,184,.1)', border: 'rgba(148,163,184,.3)' },
  // An alert from a dataset the feed does not map to a detector. Amber-slate:
  // adjacent to 'unnamed' because both say what the row is missing, and a
  // shade of no detector's colour because none of them made it.
  alert: { color: '#b0a08a', bg: 'rgba(176,160,138,.1)', border: 'rgba(176,160,138,.3)' },
};

// How a hunt came to exist. 'chat' is the storage kind for anything an analyst
// typed and 'manual' is what they read (HuntDetail already renders it so);
// 'triggered' reads as 'catalog' because the declarative hunt catalog is the
// only thing that triggers one today. Teal for the clock-driven kind, purple
// for the rule-driven one — the same hues notice/sigma wear on the alert list,
// which is what each kind most resembles.
export interface HuntKindMeta extends KindMeta {
  label: string;
  /** Tooltip: the one line an analyst needs to know what produced the row. */
  title: string;
}
// The sentences are the ones in lib/tooltips.ts, not copies of them. The badge
// and the type chip each held their own wording, so one type read "Started from
// a lead" on the row and "Hunts started from a lead" on the chip above it.
export const HUNT_KIND: Record<HuntKind, HuntKindMeta> = {
  chat: {
    label: 'manual',
    title: TYPE_MANUAL,
    color: '#94a3b8', bg: 'rgba(148,163,184,.1)', border: 'rgba(148,163,184,.3)',
  },
  scheduled: {
    label: 'scheduled',
    title: TYPE_SCHEDULE,
    color: '#2dd4bf', bg: 'rgba(45,212,191,.1)', border: 'rgba(45,212,191,.3)',
  },
  triggered: {
    label: 'catalog',
    title: CHIP_CATALOG_RUN,
    color: '#a472f0', bg: 'rgba(164,114,240,.1)', border: 'rgba(164,114,240,.3)',
  },
  lead: {
    label: 'lead',
    title: TYPE_LEAD,
    color: '#f79009', bg: 'rgba(247,144,9,.1)', border: 'rgba(247,144,9,.3)',
  },
};

// Timeline-group colors for the investigation steps.
export const TIMELINE_GROUP_COLOR: Record<string, string> = {
  'Prefetch & pivots': '#4b8bf5',
  'Indicator enrichment': '#a472f0',
  'Tool calls': '#2dd4bf',
  Decision: '#f79009',
  Validators: '#3fb950',
  Oracle: '#e0a83a',
};

export function tint(hex: string, a = 0.12): string {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgba(${r},${g},${b},${a})`;
}
