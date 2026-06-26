import { useState } from 'react';
import type { IdentifierRow } from '../lib/api';
import { Toggle } from './Controls';
import { EmptyState } from './States';

// ---------------------------------------------------------------------------
// ManagedList — renders the managed identifier rows for ONE kind (suffix /
// host / cidr). Kind-agnostic: increment 3 reuses it verbatim for a 'cidr'
// group. Each row shows the value (mono), a source tag badge, optional
// provenance from `evidence`, and right-aligned controls: an Active toggle per
// row (always-on env/reserved rows render the toggle ON + disabled/locked),
// plus Remove for manual rows. An inline "+ add" input appends a manual
// identifier.
// ---------------------------------------------------------------------------

interface ManagedListProps {
  title: string;
  rows: IdentifierRow[];
  onAdd: (value: string) => void;
  onSetActive: (id: number, active: boolean) => void;
  onRemove: (id: number) => void;
  addPlaceholder?: string;
}

/** Compact a large count: 9200 → "9.2k", 1_300_000 → "1.3M". */
function compactCount(n: number): string {
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(n % 1000 === 0 ? 0 : 1)}k`;
  return `${(n / 1_000_000).toFixed(n % 1_000_000 === 0 ? 0 : 1)}M`;
}

/** Best-effort short date from an ISO-ish timestamp; falls back to the raw string. */
function shortDate(value: string): string {
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleDateString();
}

/** "31 hosts · 9.2k events · last 6/20/2026" from a detected row's evidence. */
function provenanceLine(row: IdentifierRow): string | null {
  const ev = row.evidence;
  if (!ev) return null;
  const parts: string[] = [];
  if (typeof ev.host_count === 'number') {
    parts.push(`${compactCount(ev.host_count)} host${ev.host_count === 1 ? '' : 's'}`);
  }
  if (typeof ev.event_count === 'number') {
    parts.push(`${compactCount(ev.event_count)} events`);
  }
  if (typeof ev.last_seen === 'string' && ev.last_seen) {
    parts.push(`last ${shortDate(ev.last_seen)}`);
  }
  return parts.length ? parts.join(' · ') : null;
}

type TagTone = { label: string; color: string; bg: string; border: string };

/** Map a row's source to its tag badge. State is shown by the Active toggle. */
function rowTag(row: IdentifierRow): TagTone {
  if (!row.mutable) {
    // always-on env / reserved — neutral "reserved" chip.
    return {
      label: 'always-on',
      color: '#94a3b8',
      bg: 'rgba(148,163,184,.1)',
      border: 'rgba(148,163,184,.28)',
    };
  }
  if (row.source === 'manual') {
    return { label: 'manual', color: '#3fb950', bg: 'rgba(34,197,94,.1)', border: 'rgba(34,197,94,.3)' };
  }
  return { label: 'auto-detected', color: '#4b8bf5', bg: 'rgba(75,139,245,.1)', border: 'rgba(75,139,245,.3)' };
}

function Tag({ tone }: { tone: TagTone }) {
  return (
    <span
      className="flex-none rounded-chip border px-1.5 py-[1.5px] text-[9.5px] font-semibold uppercase tracking-[.04em]"
      style={{ color: tone.color, background: tone.bg, borderColor: tone.border }}
    >
      {tone.label}
    </span>
  );
}

const ctrlBtn =
  'rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-[5px] text-[11.5px] font-semibold text-text hover:border-accent disabled:opacity-40 disabled:cursor-not-allowed';

export function ManagedList({
  title,
  rows,
  onAdd,
  onSetActive,
  onRemove,
  addPlaceholder,
}: ManagedListProps) {
  const [value, setValue] = useState('');

  const submit = () => {
    const v = value.trim();
    if (!v) return;
    onAdd(v);
    setValue('');
  };

  return (
    <div className="mb-3">
      <div className="mb-1.5 text-[12.5px] font-semibold text-text-2">{title}</div>
      <div className="overflow-hidden rounded-card border border-border bg-surface-1">
        {rows.length === 0 ? (
          <EmptyState>No {title.toLowerCase()} yet.</EmptyState>
        ) : (
          rows.map((row) => {
            const tone = rowTag(row);
            const prov = provenanceLine(row);
            const active = row.state === 'active';
            return (
              <div
                key={row.id ?? `static:${row.value}`}
                className="flex items-center gap-3 border-b border-border-faint px-[15px] py-[11px] last:border-0"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={
                        'truncate font-mono text-[12.5px] ' + (active ? 'text-text' : 'text-faint')
                      }
                    >
                      {row.value}
                    </span>
                    <Tag tone={tone} />
                  </div>
                  {prov && <div className="mt-1 text-[11.5px] text-faint">{prov}</div>}
                </div>
                <div className="flex flex-none items-center gap-2">
                  <div className="flex flex-col items-end gap-0.5">
                    <Toggle
                      on={row.mutable ? active : true}
                      disabled={!row.mutable}
                      onChange={(next) => row.id != null && onSetActive(row.id, next)}
                      label={`Active — ${row.value}`}
                    />
                    {!row.mutable && <span className="text-[10px] text-faint">always on</span>}
                  </div>
                  {row.mutable && row.source === 'manual' && row.id != null && (
                    <button
                      onClick={() => onRemove(row.id as number)}
                      className="rounded-[7px] border px-[11px] py-[5px] text-[11.5px] font-semibold text-danger hover:bg-[rgba(240,68,56,.12)]"
                      style={{ borderColor: 'rgba(240,68,56,.3)' }}
                    >
                      Remove
                    </button>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* + add inline input */}
      <div className="mt-2 flex items-center gap-2">
        <input
          placeholder={addPlaceholder ?? 'add value…'}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') submit();
          }}
          className="w-[240px] rounded-control border border-border-input bg-bg px-3 py-1.5 font-mono text-[12.5px] text-text outline-none focus:border-accent"
        />
        <button onClick={submit} disabled={!value.trim()} className={ctrlBtn}>
          + add
        </button>
      </div>
    </div>
  );
}
