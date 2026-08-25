import type { AlertEvent } from './types';

/** A consecutive run of events indistinguishable on every rendered column. */
export interface EventBucket {
  /** Representative event (the newest — input is newest-first). */
  head: AlertEvent;
  events: AlertEvent[];
  /** Oldest ts in the bucket (span start when rendered "first–last"). */
  first?: string;
  /** Newest ts in the bucket. */
  last?: string;
}

/** Runs shorter than this render as plain rows — collapsing pairs saves
 *  nothing and would churn every existing small-fixture test. */
export const MIN_BUCKET = 3;

// Everything the expanded row DISPLAYS, minus the timestamp: two events with
// the same key are visually identical rows today.
const keyOf = (ev: AlertEvent): string =>
  [
    ev.src, ev.dst, ev.port ?? '', ev.sev ?? '', ev.host, ev.hostIp ?? '',
    ev.investigated ? 'direct' : ev.inheritedReason ? 'inherited' : 'none',
    ev.invId ?? '',
  ].join('|');

/**
 * Collapse consecutive identical events (same endpoints, severity, host and
 * verdict provenance) into buckets, preserving order. Consecutive-run rather
 * than global grouping: a flood is contiguous in a newest-first list, and
 * interleaved distinct events must stay where they are on the timeline.
 */
export function bucketEvents(events: AlertEvent[]): EventBucket[] {
  const out: EventBucket[] = [];
  for (const ev of events) {
    const prev = out[out.length - 1];
    if (prev && keyOf(prev.head) === keyOf(ev)) prev.events.push(ev);
    else out.push({ head: ev, events: [ev] });
  }
  for (const b of out) {
    b.last = b.events[0]?.ts;
    b.first = b.events[b.events.length - 1]?.ts;
  }
  return out;
}
