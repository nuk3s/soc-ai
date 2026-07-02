import type { CustomRange } from '../components/TimeRangeFilter';

// Shared time-range helpers so every page filters by the same presets the
// TimeRangeFilter offers (and the backend's TIME_RANGES). Presets are
// "<n><unit>" where unit is one of m, h, d; 'custom' uses an explicit from/to.

const UNIT_MS: Record<string, number> = { m: 60_000, h: 3_600_000, d: 86_400_000 };

/** Resolve a range preset (or custom) to an inclusive [from, to] in epoch ms. */
export function rangeBounds(range: string, custom?: CustomRange | null, now = Date.now()): {
  from: number;
  to: number;
} {
  if (range === 'custom' && custom?.from && custom?.to) {
    return { from: new Date(custom.from).getTime(), to: new Date(custom.to).getTime() };
  }
  const m = /^(\d+)([mhd])$/.exec(range);
  const span = m ? Number(m[1]) * (UNIT_MS[m[2]] ?? UNIT_MS.h) : 24 * UNIT_MS.h;
  return { from: now - span, to: now };
}

/** True when an ISO timestamp falls within the selected range. Empty ts = keep. */
export function inRange(ts: string | undefined, range: string, custom?: CustomRange | null): boolean {
  if (!ts) return true;
  const t = new Date(ts).getTime();
  if (Number.isNaN(t)) return true;
  const { from, to } = rangeBounds(range, custom);
  return t >= from && t <= to;
}
