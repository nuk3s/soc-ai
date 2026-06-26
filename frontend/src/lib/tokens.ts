// ---------------------------------------------------------------------------
// Semantic color/label metadata maps. Components inline these computed values
// (rgba washes, glows) where Tailwind can't express a runtime value; static
// classes still come from tailwind.config tokens elsewhere.
// ---------------------------------------------------------------------------

import type { DetectionKind, Severity, Verdict } from './types';

export interface SevMeta {
  label: string;
  color: string;
  glow: string;
}
export const SEVERITY: Record<Severity, SevMeta> = {
  critical: { label: 'Critical', color: '#f04438', glow: 'rgba(240,68,56,.6)' },
  high: { label: 'High', color: '#f79009', glow: 'rgba(247,144,9,.55)' },
  medium: { label: 'Medium', color: '#eab308', glow: 'rgba(234,179,8,.45)' },
  low: { label: 'Low', color: '#6b87a8', glow: 'rgba(107,135,168,.4)' },
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
  untriaged: { label: 'Untriaged', color: '#6b7484', bg: 'rgba(107,116,132,.08)', border: 'rgba(107,116,132,.25)', wash: 'rgba(107,116,132,.05)' },
};

export interface KindMeta {
  color: string;
  bg: string;
  border: string;
}
export const KIND: Record<DetectionKind, KindMeta> = {
  suricata: { color: '#4b8bf5', bg: 'rgba(75,139,245,.1)', border: 'rgba(75,139,245,.3)' },
  sigma: { color: '#a472f0', bg: 'rgba(164,114,240,.1)', border: 'rgba(164,114,240,.3)' },
  notice: { color: '#2dd4bf', bg: 'rgba(45,212,191,.1)', border: 'rgba(45,212,191,.3)' },
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
