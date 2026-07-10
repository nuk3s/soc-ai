// Verdict-mix formatting for the runbook-promotion panel: turns a promotable
// rule's verdict tallies into the compact "8 FP · 1 TP" line shown next to the
// "Draft it" button. A pure seam (extracted from Runbooks.tsx) so the display
// contract is unit-testable without mounting the screen.
import type { PromotableRule } from './api';

/** Short badge label per verdict bucket (the SOC-conventional initialisms). */
const BUCKETS: Array<{ key: 'false_positive' | 'true_positive' | 'needs_more_info'; label: string }> = [
  { key: 'false_positive', label: 'FP' },
  { key: 'true_positive', label: 'TP' },
  { key: 'needs_more_info', label: 'NMI' },
];

/**
 * "8 FP · 1 TP" — zero buckets are omitted (an all-FP rule reads as exactly
 * that, not "8 FP · 0 TP · 0 NMI" noise). All-zero input (shouldn't happen —
 * discovery requires ≥3 investigations) degrades to an honest "no verdicts".
 */
export function formatVerdictMix(
  rule: Pick<PromotableRule, 'false_positive' | 'true_positive' | 'needs_more_info'>,
): string {
  const parts = BUCKETS.filter(({ key }) => rule[key] > 0).map(
    ({ key, label }) => `${rule[key]} ${label}`,
  );
  return parts.length ? parts.join(' · ') : 'no verdicts';
}

/** Human label for the dominant verdict chip ("mostly FP" / "mostly TP" …). */
export function dominantVerdictLabel(dominant: string): string {
  const short =
    dominant === 'false_positive' ? 'FP' : dominant === 'true_positive' ? 'TP' : 'NMI';
  return `mostly ${short}`;
}
