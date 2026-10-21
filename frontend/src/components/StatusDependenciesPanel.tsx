import { Network } from 'lucide-react';
import { Link } from 'react-router-dom';

import { getHealth, type Health, type HealthComponent } from '../lib/api';
import { absoluteTime, agoWords } from '../lib/timeRange';
import { tint } from '../lib/tokens';
import { useAsync } from '../lib/useAsync';
import { Panel, PanelHeader } from './Panel';
import { Freshness, LoadingState } from './States';

// ---------------------------------------------------------------------------
// Dependencies on the Status page: Security Onion, Elasticsearch and the model
// gateway (H1-D14, R5-I4).
//
// Status showed no dependency state at all. On a fresh install with all three
// dead it rendered green analytics rows and nothing about the grid, and the
// header pill's popover was the only place that said so.
//
// Reads GET /health, the same cached probe the header pill reads, on the
// page's 5-minute cadence. The loader never rejects: a failed read comes back
// as a value and every row turns "unknown". useAsync keeps the last-good data
// through a failed BACKGROUND poll, so a loader that rejected would leave an
// "up" row standing over a read that failed. That is the false all-clear this
// panel exists to end.
// ---------------------------------------------------------------------------

export type DepState = 'up' | 'slow' | 'down' | 'unknown';

export interface DepRow {
  key: 'so' | 'es' | 'llm';
  name: string;
  state: DepState;
  /** The reason in plain words. */
  reason: string;
  /** The probe's own sentence, for a row that is not up. Null when there is
   *  nothing to add. */
  detail: string | null;
}

/** One read of GET /health, failed or not. */
export type HealthRead = { ok: true; health: Health } | { ok: false };

// The wire carries `state` and `elapsed_ms` on each leg and `checked_at` on
// the envelope. The shared Health type names none of them, and this panel adds
// no field to it.
type Leg = HealthComponent & { state?: string; elapsed_ms?: number };

export const SETTINGS_HREF = '/config#danger-zone';

const DEPS: { key: DepRow['key']; name: string }[] = [
  { key: 'so', name: 'Security Onion' },
  { key: 'es', name: 'Elasticsearch' },
  { key: 'llm', name: 'Model gateway' },
];

// The probe's failure class, in plain words (soc_ai.webui.probes and
// routes_meta._bounded_probe). An unclassified failure keeps the generic line.
const DOWN_REASON: Record<string, string> = {
  refused: 'soc-ai cannot connect to it.',
  timeout: 'It did not answer in time.',
  overloaded: 'It is overloaded and refuses some requests.',
  partial: 'It reads only part of the grid.',
  unreadable: 'It answers. No events index pattern is set.',
};

function legRow(key: DepRow['key'], name: string, leg: Leg | null | undefined): DepRow {
  if (leg == null) {
    return { key, name, state: 'unknown', reason: 'This server does not report it.', detail: null };
  }
  if (leg.ok) {
    const ms = typeof leg.elapsed_ms === 'number' ? leg.elapsed_ms : null;
    return {
      key,
      name,
      state: 'up',
      reason: ms === null ? 'It answers.' : `It answered in ${ms} ms.`,
      detail: null,
    };
  }
  const kind = typeof leg.kind === 'string' ? leg.kind : '';
  // A leg that answered late is "slow". A leg that ran out of its budget also
  // carries state "slow" on the wire, with kind "timeout", and soc-ai treats
  // it as down. Its own detail says so.
  if (leg.state === 'slow' && kind === 'slow') {
    return {
      key,
      name,
      state: 'slow',
      reason: 'It answers slowly. A result can arrive late.',
      detail: leg.detail || null,
    };
  }
  return {
    key,
    name,
    state: 'down',
    reason: DOWN_REASON[kind] ?? 'The health check failed.',
    detail: leg.detail || null,
  };
}

/** The three rows, in a fixed order. A failed read makes each row unknown. */
export function depRows(read: HealthRead): DepRow[] {
  if (!read.ok) {
    return DEPS.map(({ key, name }) => ({
      key,
      name,
      state: 'unknown',
      reason: 'soc-ai could not read the health check.',
      detail: null,
    }));
  }
  const h = read.health as Health & Record<string, Leg | null | undefined>;
  return DEPS.map(({ key, name }) => legRow(key, name, h[key]));
}

export async function readHealth(): Promise<HealthRead> {
  try {
    return { ok: true, health: await getHealth() };
  } catch {
    return { ok: false };
  }
}

export const DEP_COLOR: Record<DepState, string> = {
  up: '#3fb950',
  slow: '#f5a623',
  down: '#f85149',
  unknown: '#8b949e',
};

function StateChip({ state }: { state: DepState }) {
  const color = DEP_COLOR[state];
  return (
    <span
      className="inline-flex w-fit items-center gap-1.5 rounded-chip border px-1.5 py-px text-[11px] font-semibold"
      style={{ color, borderColor: tint(color, 0.4), background: tint(color, 0.09) }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
      {state}
    </span>
  );
}

function checkedLine(health: Health): string | null {
  const at = (health as Health & { checked_at?: unknown }).checked_at;
  if (typeof at !== 'string' || !at) return null;
  const words = agoWords(at);
  return words === 'now'
    ? 'The last health check ran less than a minute ago.'
    : `The last health check ran ${words}.`;
}

export function StatusDependenciesPanel() {
  const read = useAsync(readHealth, [], { refetchInterval: 300_000 });
  const data = read.data;
  const rows = data ? depRows(data) : null;
  const checked = data && data.ok ? checkedLine(data.health) : null;
  const checkedAt = data && data.ok ? (data.health as Health & { checked_at?: string }).checked_at : null;
  return (
    <Panel className="md:col-span-2">
      <PanelHeader
        icon={<Network size={16} />}
        title="Dependencies"
        right={<Freshness at={read.lastUpdated} />}
      />
      {!rows ? (
        <LoadingState label="Reading the health check" />
      ) : (
        <>
          <ul className="divide-y divide-border">
            {rows.map((r) => (
              <li
                key={r.key}
                data-testid="status-dependency"
                className="flex flex-col gap-1.5 px-[15px] py-2.5 text-[13px] md:grid md:grid-cols-[160px_88px_1fr_auto] md:items-baseline md:gap-3"
              >
                <span data-part="name" className="font-semibold text-text-2">
                  {r.name}
                </span>
                <StateChip state={r.state} />
                <div className="min-w-0">
                  <div className="text-text-2">{r.reason}</div>
                  {r.detail && (
                    <div className="mt-0.5 break-words font-mono text-[10.5px] leading-[1.5] text-faint">
                      {r.detail}
                    </div>
                  )}
                </div>
                <Link
                  to={SETTINGS_HREF}
                  aria-label={`Open the ${r.name} connection settings`}
                  className="w-fit text-[12px] text-accent hover:underline"
                >
                  Connection settings
                </Link>
              </li>
            ))}
          </ul>
          <div className="border-t border-border px-[15px] py-2.5 text-[11.5px] leading-[1.55] text-faint">
            soc-ai reads the grid and calls the model gateway. A row that is not up names the
            reason. {checked && <span title={absoluteTime(checkedAt ?? null)}>{checked}</span>}
          </div>
        </>
      )}
    </Panel>
  );
}
