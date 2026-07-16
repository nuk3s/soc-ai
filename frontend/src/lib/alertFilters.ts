import type { AlertGroup } from './types';

/**
 * Optimistic hide for drawer-initiated group acks. The ES aggregation behind
 * the alerts feed takes seconds-to-minutes to reflect a fresh ack, so a group
 * the analyst just acknowledged would otherwise sit in the queue looking
 * un-acked after a successful "Executed ✓" (dogfood 2026-07-15). `ackedAt`
 * maps rule name → epoch-ms of the session-local ack; a group whose latest
 * event is NEWER than the ack re-surfaces (new events → new decision).
 */
export function hideOptimisticallyAcked(
  groups: AlertGroup[],
  ackedAt: Record<string, number>,
  hideAcked: boolean,
): AlertGroup[] {
  if (!hideAcked) return groups;
  return groups.filter((g) => {
    const at = ackedAt[g.name];
    if (!at) return true;
    const latest = g.latestTs ? Date.parse(g.latestTs) : Number.NaN;
    return Number.isFinite(latest) && latest > at;
  });
}
