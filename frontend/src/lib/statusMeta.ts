import type { InvestigationRow } from './types';

// Shared display metadata for an investigation's lifecycle status — colour,
// label and whether the dot pulses. Single source of truth so the Dashboard and
// Investigations list (and any future surface) never drift.
export const INV_STATUS: Record<
  InvestigationRow['status'],
  { color: string; label: string; pulse: boolean }
> = {
  complete: { color: '#3fb950', label: 'Complete', pulse: false },
  running: { color: '#4b8bf5', label: 'Investigating', pulse: true },
  awaiting: { color: '#f5a623', label: 'Awaiting decision', pulse: true },
  error: { color: '#f04438', label: 'Error', pulse: false },
  cancelled: { color: '#8b949e', label: 'Cancelled', pulse: false },
  interrupted: { color: '#8b949e', label: 'Interrupted', pulse: false },
};
