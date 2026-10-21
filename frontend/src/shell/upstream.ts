/** The health of one upstream, in the console's words. A dependency that is
 *  up and late, overloaded or partial is "degraded". One that does not answer
 *  is "down". The top bar pill said "3 degraded" in amber over three refused
 *  connections (dogfood 2026-10-19, H1-D8). */
export type UpstreamState = 'ok' | 'degraded' | 'down';

const DEGRADED_KINDS = new Set(['slow', 'overloaded', 'partial']);

export function upstreamState(c: { ok: boolean; kind?: string }): UpstreamState {
  if (c.ok) return 'ok';
  return DEGRADED_KINDS.has(c.kind ?? '') ? 'degraded' : 'down';
}

export const UPSTREAM_COLOR: Record<UpstreamState, string> = {
  ok: '#3fb950',
  degraded: '#f5a623',
  down: '#f04438',
};
