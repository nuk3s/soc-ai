import type { HuntStatus } from './types';

// The status pill of the hunt page. The pill names the stop: Cancelled,
// Interrupted or Error. Every list reads statusMeta() from lib/labels.ts, where
// the three stops read "Failed".
export const HUNT_STATUS: Record<
  HuntStatus,
  { label: string; color: string; pulse?: boolean }
> = {
  running: { label: 'Running', color: '#4b8bf5', pulse: true },
  // The report landed and the investigations of the findings run.
  investigating: { label: 'Investigating', color: '#4b8bf5', pulse: true },
  complete: { label: 'Complete', color: '#3fb950' },
  error: { label: 'Error', color: '#f85149' },
  cancelled: { label: 'Cancelled', color: '#8b949e' },
  interrupted: { label: 'Interrupted', color: '#d29922' },
};
