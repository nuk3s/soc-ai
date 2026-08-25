import { describe, expect, it } from 'vitest';
import type { AlertEvent } from './types';
import { MIN_BUCKET, bucketEvents } from './alertEventBuckets';

const ev = (over: Partial<AlertEvent> = {}): AlertEvent => ({
  id: `id-${Math.random().toString(36).slice(2)}`,
  src: '192.168.10.1', dst: '192.168.10.15', host: '—',
  sev: 'high', ts: '2026-08-22T07:30:26Z', ago: '8m',
  inheritedReason: 'inherited 2d ago', invId: 'inv-1',
  ...over,
});

describe('bucketEvents', () => {
  it('collapses a consecutive run of identical events into one bucket', () => {
    const buckets = bucketEvents([ev(), ev(), ev(), ev(), ev()]);
    expect(buckets).toHaveLength(1);
    expect(buckets[0].events).toHaveLength(5);
  });
  it('does not merge across a key change, and preserves order', () => {
    const buckets = bucketEvents([ev(), ev(), ev({ dst: '192.168.9.22' }), ev(), ev()]);
    expect(buckets.map((b) => b.events.length)).toEqual([2, 1, 2]);
  });
  it('a different provenance splits the bucket even with identical endpoints', () => {
    expect(bucketEvents([ev(), ev({ invId: 'inv-2', inheritedReason: null, investigated: true })])).toHaveLength(2);
  });
  it('records the time span (list is newest-first: last item is oldest)', () => {
    const [b] = bucketEvents([ev({ ts: 'T3' }), ev({ ts: 'T2' }), ev({ ts: 'T1' })]);
    expect(b.last).toBe('T3');
    expect(b.first).toBe('T1');
  });
  it('MIN_BUCKET is the collapse threshold the UI keys on', () => {
    expect(MIN_BUCKET).toBe(3);
  });
});
