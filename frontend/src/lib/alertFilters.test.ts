// Optimistic hide after a drawer-initiated group ack: the acked group leaves
// the queue immediately (ES needs seconds-to-minutes to reflect the ack in the
// aggregation), but NEW events arriving after the ack re-surface it.
import { describe, expect, it } from 'vitest';
import { hideOptimisticallyAcked } from './alertFilters';
import type { AlertGroup } from './types';

const group = (over: Partial<AlertGroup>): AlertGroup =>
  ({
    id: 'es-1',
    name: 'ET TEST Rule',
    kind: 'suricata',
    sev: 'low',
    count: 3,
    verdict: 'false_positive',
    conf: 0.9,
    latest: '1m ago',
    inherited: false,
    events: [],
    ...over,
  }) as AlertGroup;

describe('hideOptimisticallyAcked', () => {
  const ackedAt = { 'ET TEST Rule': Date.parse('2026-07-15T12:00:00Z') };

  it('hides a just-acked group while Hide acknowledged is on', () => {
    const gs = [group({ latestTs: '2026-07-15T11:00:00Z' })];
    expect(hideOptimisticallyAcked(gs, ackedAt, true)).toEqual([]);
  });

  it('keeps the group when new events arrived after the ack', () => {
    const gs = [group({ latestTs: '2026-07-15T12:30:00Z' })];
    expect(hideOptimisticallyAcked(gs, ackedAt, true)).toHaveLength(1);
  });

  it('never hides when Hide acknowledged is off', () => {
    const gs = [group({ latestTs: '2026-07-15T11:00:00Z' })];
    expect(hideOptimisticallyAcked(gs, ackedAt, false)).toHaveLength(1);
  });

  it('ignores groups that were never acked this session', () => {
    const gs = [group({ name: 'ET OTHER Rule', latestTs: '2026-07-15T11:00:00Z' })];
    expect(hideOptimisticallyAcked(gs, ackedAt, true)).toHaveLength(1);
  });

  it('hides a group with no latestTs (cannot prove newer events)', () => {
    const gs = [group({ latestTs: undefined })];
    expect(hideOptimisticallyAcked(gs, ackedAt, true)).toEqual([]);
  });
});
