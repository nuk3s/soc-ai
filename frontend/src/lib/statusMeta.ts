import type { HuntStatus, InvestigationRow } from './types';

// Shared display metadata for an investigation's lifecycle status — colour,
// label and whether the dot pulses. Single source of truth so the Dashboard and
// Investigations list (and any future surface) never drift.
export const INV_STATUS: Record<
  InvestigationRow['status'],
  { color: string; label: string; pulse: boolean }
> = {
  complete: { color: '#3fb950', label: 'Complete', pulse: false },
  running: { color: '#4b8bf5', label: 'Investigating', pulse: true },
  error: { color: '#f04438', label: 'Error', pulse: false },
  cancelled: { color: '#8b949e', label: 'Cancelled', pulse: false },
  interrupted: { color: '#8b949e', label: 'Interrupted', pulse: false },
};

// Same idea for a hunt's lifecycle status — shared by the Hunt Console list and
// the hunt detail page so the two surfaces never drift.
export const HUNT_STATUS: Record<
  HuntStatus,
  { label: string; color: string; pulse?: boolean }
> = {
  running: { label: 'Running', color: '#4b8bf5', pulse: true },
  complete: { label: 'Complete', color: '#3fb950' },
  error: { label: 'Error', color: '#f85149' },
  cancelled: { label: 'Cancelled', color: '#8b949e' },
  interrupted: { label: 'Interrupted', color: '#d29922' },
};
