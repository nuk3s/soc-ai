import { useMemo, useState } from 'react';
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
//
// Long lists (a real sensor grid detects hundreds of hostnames) opt into three
// extra affordances — `searchable`, `pageSize` and `bulk`. All three are off by
// default so a call site that passes none renders exactly what it always did.
// ---------------------------------------------------------------------------

interface ManagedListProps {
  title: string;
  rows: IdentifierRow[];
  onAdd: (value: string) => void;
  onSetActive: (id: number, active: boolean) => void;
  onRemove: (id: number) => void;
  /**
   * Dismiss a DETECTED suggestion for good (terminal — the row vanishes from the
   * list). Distinct from muting (keep-but-unused). Only wired for detected rows;
   * manual rows keep the DELETE-backed Remove control.
   */
  onDismiss?: (id: number) => void;
  addPlaceholder?: string;
  /** Render a filter box above the list (case-insensitive substring on value). */
  searchable?: boolean;
  /**
   * Render at most this many (filtered) rows, with a "Show all N" row-button to
   * expand. Collapses again whenever the filter text changes.
   */
  pageSize?: number;
  /**
   * Enable per-row selection + a bulk action bar. The component owns the
   * selection only; every action delegates to these callbacks (no API calls
   * here) and the selection is cleared once one fires.
   */
  bulk?: {
    onSetActiveMany: (ids: number[], active: boolean) => void;
    onDismissMany?: (ids: number[]) => void;
  };
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

const bulkBtn =
  'rounded-[7px] border border-border-strong bg-surface-3 px-[9px] py-[3px] text-[11px] font-semibold text-dim hover:border-accent hover:text-text';

const dangerBtn =
  'rounded-[7px] border px-[9px] py-[3px] text-[11px] font-semibold text-danger hover:bg-[rgba(240,68,56,.12)]';

export function ManagedList({
  title,
  rows,
  onAdd,
  onSetActive,
  onRemove,
  onDismiss,
  addPlaceholder,
  searchable,
  pageSize,
  bulk,
}: ManagedListProps) {
  const [value, setValue] = useState('');
  // Inline "click twice to confirm" for a dismiss — keyed by row id so a mis-click
  // never nukes a suggestion on the first press. Cleared on the next render cycle
  // that removes the row (the list refetches after the mutation resolves).
  const [pendingDismiss, setPendingDismiss] = useState<number | null>(null);
  const [filter, setFilter] = useState('');
  const [expanded, setExpanded] = useState(false);
  const [selected, setSelected] = useState<ReadonlySet<number>>(() => new Set());
  const [pendingBulkDismiss, setPendingBulkDismiss] = useState(false);

  // Filter first, then page: "show all" expands the matches, not the whole list.
  const query = filter.trim().toLowerCase();
  const filtered = useMemo(
    () => (query ? rows.filter((r) => r.value.toLowerCase().includes(query)) : rows),
    [rows, query],
  );
  const pageable = pageSize != null && filtered.length > pageSize;
  const visible = pageable && !expanded ? filtered.slice(0, pageSize) : filtered;

  // The effective selection is re-derived from the CURRENT rows every render, so
  // ids that vanish on a refetch (dismissed elsewhere, removed) drop out instead
  // of being handed back to the API by the next bulk action. Row order in, row
  // order out.
  const selectedIds = useMemo(
    () =>
      rows
        .filter((r) => r.mutable && r.id != null && selected.has(r.id))
        .map((r) => r.id as number),
    [rows, selected],
  );
  const selectedCount = selectedIds.length;

  const shownIds = visible
    .filter((r) => r.mutable && r.id != null)
    .map((r) => r.id as number);
  const allShownSelected = shownIds.length > 0 && shownIds.every((id) => selected.has(id));

  const clearSelection = () => {
    setSelected(new Set());
    setPendingBulkDismiss(false);
  };

  const toggleRow = (id: number) => {
    setPendingBulkDismiss(false);
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // "Select all shown" reaches exactly the visible (filtered + paged) mutable
  // rows — never a row the operator cannot currently see.
  const toggleAllShown = () => {
    setPendingBulkDismiss(false);
    setSelected((prev) => {
      const next = new Set(prev);
      for (const id of shownIds) {
        if (allShownSelected) next.delete(id);
        else next.add(id);
      }
      return next;
    });
  };

  const submit = () => {
    const v = value.trim();
    if (!v) return;
    onAdd(v);
    setValue('');
  };

  return (
    <div className="mb-3">
      <div className="mb-1.5 text-[12.5px] font-semibold text-text-2">{title}</div>

      {searchable && (
        <div className="mb-1.5 flex items-center gap-2.5">
          <input
            placeholder="Filter…"
            value={filter}
            onChange={(e) => {
              setFilter(e.target.value);
              // A new filter means a new result set — re-collapse to pageSize.
              setExpanded(false);
            }}
            className="w-[240px] rounded-control border border-border-input bg-bg px-3 py-1.5 font-mono text-[12.5px] text-text outline-none focus:border-accent"
          />
          {query !== '' && (
            <span className="text-[11.5px] text-faint">
              {`${filtered.length} of ${rows.length} shown`}
            </span>
          )}
        </div>
      )}

      {bulk && (shownIds.length > 0 || selectedCount > 0) && (
        <div className="mb-1.5 flex flex-wrap items-center gap-2.5 rounded-card border border-border bg-surface-2 px-[15px] py-[7px]">
          <label className="flex cursor-pointer items-center gap-2 text-[11.5px] text-dim">
            <input
              type="checkbox"
              aria-label="Select all shown"
              checked={allShownSelected}
              onChange={toggleAllShown}
              className="h-3.5 w-3.5 flex-none accent-accent"
            />
            Select all shown
          </label>
          {selectedCount > 0 && (
            <>
              <span className="text-[11.5px] font-semibold text-text-2">
                {selectedCount} selected
              </span>
              <div className="ml-auto flex items-center gap-1.5">
                <button
                  className={bulkBtn}
                  onClick={() => {
                    bulk.onSetActiveMany(selectedIds, true);
                    clearSelection();
                  }}
                >
                  Enable
                </button>
                <button
                  className={bulkBtn}
                  onClick={() => {
                    bulk.onSetActiveMany(selectedIds, false);
                    clearSelection();
                  }}
                >
                  Disable
                </button>
                {bulk.onDismissMany &&
                  (pendingBulkDismiss ? (
                    <>
                      <button
                        className={dangerBtn}
                        style={{ borderColor: 'rgba(240,68,56,.3)' }}
                        onClick={() => {
                          bulk.onDismissMany?.(selectedIds);
                          clearSelection();
                        }}
                      >
                        Confirm dismiss ({selectedCount})
                      </button>
                      <button className={bulkBtn} onClick={() => setPendingBulkDismiss(false)}>
                        Cancel
                      </button>
                    </>
                  ) : (
                    <button
                      className={bulkBtn}
                      title="Dismiss — remove these suggestions for good (re-add manually to restore)"
                      onClick={() => setPendingBulkDismiss(true)}
                    >
                      Dismiss ({selectedCount})
                    </button>
                  ))}
              </div>
            </>
          )}
        </div>
      )}

      <div className="overflow-hidden rounded-card border border-border bg-surface-1">
        {rows.length === 0 ? (
          <EmptyState>No {title.toLowerCase()} yet.</EmptyState>
        ) : filtered.length === 0 ? (
          <EmptyState>Nothing matches “{filter.trim()}”.</EmptyState>
        ) : (
          <>
          {visible.map((row) => {
            const rowId = row.id;
            const tone = rowTag(row);
            const prov = provenanceLine(row);
            const active = row.state === 'active';
            return (
              <div
                key={row.id ?? `static:${row.value}`}
                className="flex items-center gap-3 border-b border-border-faint px-[15px] py-[11px] last:border-0"
              >
                {/* Only a mutable row with a real id can be acted on in bulk;
                    the rest keep a spacer so every value stays in one column. */}
                {bulk &&
                  (row.mutable && rowId != null ? (
                    <input
                      type="checkbox"
                      aria-label={`Select ${row.value}`}
                      checked={selected.has(rowId)}
                      onChange={() => toggleRow(rowId)}
                      className="h-3.5 w-3.5 flex-none accent-accent"
                    />
                  ) : (
                    <span aria-hidden="true" className="h-3.5 w-3.5 flex-none" />
                  ))}
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
                  {/* Manual rows: hard DELETE (backend 409s on a detected id). */}
                  {row.mutable && row.source === 'manual' && row.id != null && (
                    <button
                      onClick={() => onRemove(row.id as number)}
                      className="rounded-[7px] border px-[11px] py-[5px] text-[11.5px] font-semibold text-danger hover:bg-[rgba(240,68,56,.12)]"
                      style={{ borderColor: 'rgba(240,68,56,.3)' }}
                    >
                      Remove
                    </button>
                  )}
                  {/* Detected rows: dismiss the suggestion for good (mute keeps it,
                      dismiss hides it). Two-press inline confirm. */}
                  {onDismiss && row.mutable && row.source === 'detected' && row.id != null && (
                    pendingDismiss === row.id ? (
                      <div className="flex items-center gap-1.5">
                        <button
                          onClick={() => {
                            onDismiss(row.id as number);
                            setPendingDismiss(null);
                          }}
                          className="rounded-[7px] border px-[11px] py-[5px] text-[11.5px] font-semibold text-danger hover:bg-[rgba(240,68,56,.12)]"
                          style={{ borderColor: 'rgba(240,68,56,.3)' }}
                        >
                          Confirm
                        </button>
                        <button
                          onClick={() => setPendingDismiss(null)}
                          className="rounded-[7px] border border-border-strong bg-surface-3 px-[9px] py-[5px] text-[11.5px] font-semibold text-dim hover:text-text"
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <button
                        onClick={() => setPendingDismiss(row.id as number)}
                        title="Dismiss — remove this suggestion for good (re-add manually to restore)"
                        className="rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-[5px] text-[11.5px] font-semibold text-dim hover:border-accent hover:text-text"
                      >
                        Dismiss
                      </button>
                    )
                  )}
                </div>
              </div>
            );
          })}
          {/* Full-width last row: the truncated tail is one press away. The row
              above keeps its own border-b, so this reads as one more row. */}
          {pageable && (
            <button
              onClick={() => setExpanded((prev) => !prev)}
              className="w-full px-[15px] py-[9px] text-center text-[11.5px] font-semibold text-dim hover:bg-surface-2 hover:text-text"
            >
              {expanded ? `Show first ${pageSize}` : `Show all ${filtered.length}`}
            </button>
          )}
          </>
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
