import { Check, ChevronDown, ChevronRight, CornerDownRight, MessageSquare, RefreshCw, Trash2, X } from 'lucide-react';
import { Fragment, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { KindBadge, VerdictPill } from '../components/Badges';
import { FlowBadge } from '../components/FlowBadge';
import { MultiSelect } from '../components/MultiSelect';
import { TimeRangeFilter, type CustomRange } from '../components/TimeRangeFilter';
import { inRange } from '../lib/timeRange';
// Shared with the Dashboard — single source of truth for status colour/label/pulse.
import { INV_STATUS as STATUS } from '../lib/statusMeta';
import { Checkbox } from '../components/Controls';
import { ErrorState, LoadingState } from '../components/States';
import { deleteInvestigation, getInvestigations, rehuntInvestigations } from '../lib/api';
import { useAsync } from '../lib/useAsync';
import type { InvestigationRow, Verdict } from '../lib/types';

const GRID = '28px 1fr 150px 90px 120px 110px 120px 44px';


type SortKey = 'name' | 'verdict' | 'conf' | 'host' | 'status' | 'when';
type SortDir = 'asc' | 'desc';

const VERDICT_ORDER: Record<Verdict, number> = {
  true_positive: 0,
  false_positive: 1,
  needs_more_info: 2,
  untriaged: 3,
};

const STATUS_ORDER: Record<InvestigationRow['status'], number> = {
  running: 0,
  awaiting: 1,
  error: 2,
  interrupted: 3,
  cancelled: 4,
  complete: 5,
};

function cmpRows(a: InvestigationRow, b: InvestigationRow, key: SortKey, dir: SortDir): number {
  let result = 0;
  switch (key) {
    case 'name':
      result = a.name.localeCompare(b.name);
      break;
    case 'verdict':
      result = VERDICT_ORDER[a.verdict] - VERDICT_ORDER[b.verdict];
      break;
    case 'conf':
      result = (a.conf ?? -1) - (b.conf ?? -1);
      break;
    case 'host':
      result = (a.host ?? '').localeCompare(b.host ?? '');
      break;
    case 'status':
      result = STATUS_ORDER[a.status] - STATUS_ORDER[b.status];
      break;
    case 'when':
      // Sort by raw ISO timestamp for correct chronological order; fall back to
      // empty string (treats missing ts as oldest) if the field is absent.
      result = (a.ts ?? '').localeCompare(b.ts ?? '');
      break;
  }
  return dir === 'asc' ? result : -result;
}

export function Investigations() {
  const navigate = useNavigate();
  const [reloadKey, setReloadKey] = useState(0);
  const { data, loading, error } = useAsync(getInvestigations, [reloadKey], {
    refetchInterval: 10000, // live status (running → complete) without a reload
  });

  const [filterVerdicts, setFilterVerdicts] = useState<string[]>([]);
  const [filterStatuses, setFilterStatuses] = useState<string[]>([]);
  const [range, setRange] = useState('24h');
  const [custom, setCustom] = useState<CustomRange | null>(null);
  const [sort, setSort] = useState<{ key: SortKey; dir: SortDir }>({ key: 'when', dir: 'desc' });
  const [groupBy, setGroupBy] = useState<'none' | 'detection'>('none');
  // Alert ids whose earlier (non-primary) runs are expanded inline.
  const [expandedAlerts, setExpandedAlerts] = useState<Record<string, boolean>>({});

  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [rehunting, setRehunting] = useState(false);
  const [rehuntMsg, setRehuntMsg] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);

  const rows = data ?? [];
  const running = rows.filter((r) => r.status === 'running').length;
  const tps = rows.filter((r) => r.verdict === 'true_positive').length;

  // Apply filters then sort
  const visible = rows
    .filter((r) => inRange(r.ts, range, custom))
    .filter((r) => !filterVerdicts.length || filterVerdicts.includes(r.verdict))
    .filter((r) => !filterStatuses.length || filterStatuses.includes(r.status))
    .sort((a, b) => cmpRows(a, b, sort.key, sort.dir));

  // Cluster retries of the SAME alert: surface the canonical (primary) run and
  // tuck earlier/errored/cancelled re-runs under it, so the one that WORKED is
  // never buried under a pile of failed attempts. Retries reveal inline on demand.
  const retriesByAlert = new Map<string, InvestigationRow[]>();
  for (const r of visible) {
    if (r.isPrimary === false && r.alertId) {
      const arr = retriesByAlert.get(r.alertId) ?? [];
      arr.push(r);
      retriesByAlert.set(r.alertId, arr);
    }
  }
  const primaries = visible.filter((r) => r.isPrimary !== false);

  // When grouping, cluster rows by detection name (keeping the user's sort within
  // each group) and precompute per-group counts for the headers.
  const displayRows =
    groupBy === 'detection'
      ? [...primaries].sort(
          (a, b) =>
            (a.name || '').localeCompare(b.name || '') || cmpRows(a, b, sort.key, sort.dir),
        )
      : primaries;
  const groupCounts = new Map<string, number>();
  if (groupBy === 'detection') {
    for (const r of displayRows) {
      const k = r.name || '(unnamed detection)';
      groupCounts.set(k, (groupCounts.get(k) ?? 0) + 1);
    }
  }

  const toggleSort = (key: SortKey) => {
    setSort((prev) =>
      prev.key === key
        ? { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' }
        : { key, dir: 'asc' }
    );
  };

  const caret = (key: SortKey) => {
    if (sort.key !== key) return null;
    return <span className="ml-0.5 text-accent">{sort.dir === 'asc' ? '↑' : '↓'}</span>;
  };

  const headerCls = (key: SortKey) =>
    'cursor-pointer select-none hover:text-text ' +
    (sort.key === key ? 'text-text' : '');

  // Selection helpers
  const visibleIds = visible.map((r) => r.id);
  const selCount = Object.values(selected).filter(Boolean).length;
  const allVisibleSelected =
    visibleIds.length > 0 && visibleIds.every((id) => selected[id]);
  const someVisibleSelected = visibleIds.some((id) => selected[id]);

  const toggleSelectAll = () => {
    if (allVisibleSelected) {
      // Deselect all visible
      setSelected((prev) => {
        const next = { ...prev };
        visibleIds.forEach((id) => delete next[id]);
        return next;
      });
    } else {
      setSelected((prev) => {
        const next = { ...prev };
        visibleIds.forEach((id) => (next[id] = true));
        return next;
      });
    }
  };

  const handleRehunt = async () => {
    const ids = Object.keys(selected).filter((k) => selected[k]);
    if (!ids.length) return;
    setRehunting(true);
    setRehuntMsg(null);
    try {
      const result = await rehuntInvestigations(ids);
      const n = result.started.length;
      const s = result.skipped.length;
      const parts = [`Started ${n} re-investigation${n !== 1 ? 's' : ''}`];
      if (s > 0) parts.push(`${s} skipped`);
      setRehuntMsg(parts.join(' · '));
      setSelected({});
      setReloadKey((k) => k + 1);
    } catch (err) {
      setRehuntMsg(`Re-investigate failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setRehunting(false);
    }
  };

  // Per-row delete (the discoverable path): a hover trash icon arms an inline
  // confirm in the row, then deletes just that investigation.
  const deleteOne = async (id: string) => {
    setRehuntMsg(null);
    try {
      await deleteInvestigation(id);
      setRehuntMsg('Investigation deleted');
    } catch {
      setRehuntMsg('Delete failed — cancel a running investigation first, or admin only');
    }
    setPendingDelete(null);
    setReloadKey((k) => k + 1);
  };

  const handleDelete = async () => {
    const ids = Object.keys(selected).filter((k) => selected[k]);
    if (!ids.length) return;
    setDeleting(true);
    setRehuntMsg(null);
    let ok = 0;
    let failed = 0;
    for (const id of ids) {
      try {
        await deleteInvestigation(id);
        ok += 1;
      } catch {
        failed += 1; // running (cancel first) or not admin
      }
    }
    setRehuntMsg(
      `Deleted ${ok} investigation${ok !== 1 ? 's' : ''}` +
        (failed ? ` · ${failed} failed (cancel a running one first, or admin only)` : '')
    );
    setSelected({});
    setConfirmDelete(false);
    setDeleting(false);
    setReloadKey((k) => k + 1);
  };

  return (
    <div className="px-[22px] pb-[60px] pt-5">
      <div className="text-[20px] font-semibold tracking-[-.015em]">Investigations</div>
      <div className="mb-4 mt-0.5 text-[13px] text-dim">
        {rows.length} investigations · {running} in progress · {tps} true positive
      </div>

      {/* filter bar + bulk action */}
      <div className="mb-3.5 flex flex-wrap items-center gap-2">
        <TimeRangeFilter
          value={range}
          custom={custom}
          onChange={(v, r) => {
            setRange(v);
            if (r) setCustom(r);
          }}
        />
        <MultiSelect
          label="Verdict"
          options={[
            { value: 'true_positive', label: 'True positive' },
            { value: 'false_positive', label: 'False positive' },
            { value: 'needs_more_info', label: 'Needs more info' },
            { value: 'untriaged', label: 'Untriaged' },
          ]}
          value={filterVerdicts}
          onChange={setFilterVerdicts}
        />
        <MultiSelect
          label="Status"
          options={[
            { value: 'complete', label: 'Complete' },
            { value: 'running', label: 'Investigating' },
            { value: 'awaiting', label: 'Awaiting decision' },
            { value: 'error', label: 'Error' },
            { value: 'interrupted', label: 'Interrupted' },
            { value: 'cancelled', label: 'Cancelled' },
          ]}
          value={filterStatuses}
          onChange={setFilterStatuses}
        />
        <button
          onClick={() => setGroupBy((g) => (g === 'detection' ? 'none' : 'detection'))}
          title="Group investigations by detection rule"
          className={
            'rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold ' +
            (groupBy === 'detection'
              ? 'border-accent text-accent'
              : 'border-border-strong text-dim hover:text-text')
          }
        >
          Group by detection{groupBy === 'detection' ? ' ✓' : ''}
        </button>

        {selCount > 0 && (
          <>
            <div className="h-4 w-px bg-border-strong" />
            <span className="text-[12.5px] text-dim">
              <span className="font-mono text-accent">{selCount}</span> selected
            </span>
            <button
              disabled={rehunting}
              onClick={() => { void handleRehunt(); }}
              className="flex items-center gap-1.5 rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold text-[#cfe0ff] disabled:opacity-50"
              style={{ background: 'rgba(75,139,245,.14)', borderColor: 'rgba(75,139,245,.4)' }}
            >
              <RefreshCw size={12} className={rehunting ? 'animate-spin' : ''} />
              {rehunting ? 'Starting…' : `Re-investigate (${selCount})`}
            </button>
            {confirmDelete ? (
              <>
                <button
                  disabled={deleting}
                  onClick={() => { void handleDelete(); }}
                  className="flex items-center gap-1.5 rounded-[7px] border border-danger px-[11px] py-1.5 text-[12.5px] font-semibold text-danger disabled:opacity-50"
                >
                  <Trash2 size={12} />
                  {deleting ? 'Deleting…' : `Confirm delete (${selCount})`}
                </button>
                <button
                  onClick={() => setConfirmDelete(false)}
                  className="rounded-[7px] border border-border-strong bg-transparent px-[11px] py-1.5 text-[12.5px] font-semibold text-dim hover:text-text"
                >
                  Cancel
                </button>
              </>
            ) : (
              <button
                onClick={() => setConfirmDelete(true)}
                title="Delete the selected investigations (admin)"
                className="flex items-center gap-1.5 rounded-[7px] border border-border-strong bg-transparent px-[11px] py-1.5 text-[12.5px] font-semibold text-dim hover:border-danger hover:text-danger"
              >
                <Trash2 size={12} /> Delete
              </button>
            )}
            <button
              onClick={() => setSelected({})}
              className="rounded-[7px] border border-border-strong bg-transparent px-[11px] py-1.5 text-[12.5px] font-semibold text-dim hover:border-danger hover:text-danger"
            >
              Clear
            </button>
          </>
        )}

        {rehuntMsg && (
          <span className="text-[12.5px] text-text-2">{rehuntMsg}</span>
        )}
      </div>

      <div className="overflow-hidden rounded-card border border-border bg-surface-1">
        <div
          className="grid gap-2.5 border-b border-border bg-surface-2 px-3.5 py-[9px] text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint"
          style={{ gridTemplateColumns: GRID }}
        >
          <div className="flex items-center" onClick={(e) => e.stopPropagation()}>
            <Checkbox
              checked={allVisibleSelected}
              indeterminate={!allVisibleSelected && someVisibleSelected}
              onChange={toggleSelectAll}
              title="Select all visible"
            />
          </div>
          <div className={headerCls('name')} onClick={() => toggleSort('name')}>
            Detection{caret('name')}
          </div>
          <div className={headerCls('verdict')} onClick={() => toggleSort('verdict')}>
            Verdict{caret('verdict')}
          </div>
          <div className={headerCls('conf')} onClick={() => toggleSort('conf')}>
            Conf{caret('conf')}
          </div>
          <div className={headerCls('host')} onClick={() => toggleSort('host')}>
            Source → Dest{caret('host')}
          </div>
          <div className={headerCls('status')} onClick={() => toggleSort('status')}>
            Status{caret('status')}
          </div>
          <div className={headerCls('when')} onClick={() => toggleSort('when')}>
            When{caret('when')}
          </div>
          <div />
        </div>

        {loading && <LoadingState />}
        {error && <div className="p-3"><ErrorState error={error} /></div>}
        {!loading && !error && rows.length === 0 && (
          <div className="px-4 py-10 text-center text-[13px] text-faint">No investigations yet.</div>
        )}
        {!loading && !error && rows.length > 0 && visible.length === 0 && (
          <div className="px-4 py-10 text-center text-[13px] text-faint">No investigations match the selected filters.</div>
        )}
        {displayRows.map((r, i) => {
          const st = STATUS[r.status] ?? STATUS.error;
          const retries = retriesByAlert.get(r.alertId ?? '') ?? [];
          const expanded = !!expandedAlerts[r.alertId ?? ''];
          const groupName = r.name || '(unnamed detection)';
          const showHeader =
            groupBy === 'detection' &&
            (i === 0 || (displayRows[i - 1].name || '(unnamed detection)') !== groupName);
          return (
            <Fragment key={r.id}>
              {showHeader && (
                <div className="flex items-center gap-2 border-b border-border bg-surface-2 px-3.5 py-2 text-[12px] font-semibold text-text-2">
                  <span className="min-w-0 truncate">{groupName}</span>
                  <span className="font-mono text-[11px] text-faint">{groupCounts.get(groupName)}</span>
                </div>
              )}
              <div
                onClick={() => navigate(`/investigation/${r.id}`, { state: { from: '/investigations' } })}
              className="group grid cursor-pointer items-center gap-2.5 border-b border-border-faint px-3.5 py-[11px] hover:bg-surface-hover"
              style={{ gridTemplateColumns: GRID }}
            >
              <div
                className="flex items-center"
                onClick={(e) => {
                  e.stopPropagation();
                  setSelected((prev) => ({ ...prev, [r.id]: !prev[r.id] }));
                }}
              >
                <Checkbox
                  checked={!!selected[r.id]}
                  title="Select"
                />
              </div>
              <div className="flex min-w-0 items-center gap-[9px]">
                <KindBadge kind={r.kind} />
                <span className="min-w-0 flex-1 truncate text-[13px] font-medium">{r.name}</span>
                {retries.length > 0 && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setExpandedAlerts((prev) => ({ ...prev, [r.alertId ?? '']: !prev[r.alertId ?? ''] }));
                    }}
                    title={`${retries.length} earlier run${retries.length === 1 ? '' : 's'} of this alert`}
                    className="flex flex-none items-center gap-[3px] rounded-badge border border-border-2 bg-surface-2 px-[6px] py-[2px] font-mono text-[10.5px] text-faint hover:text-text-2"
                  >
                    {expanded ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
                    {retries.length} earlier
                  </button>
                )}
                {(r.chatCount ?? 0) > 0 && (
                  <span
                    className="flex flex-none items-center gap-[4px] rounded-badge border border-border-2 bg-surface-2 px-[6px] py-[2px] font-mono text-[10.5px] text-accent"
                    title={`${r.chatCount} chat message${r.chatCount === 1 ? '' : 's'}`}
                  >
                    <MessageSquare size={10} />
                    {r.chatCount}
                  </span>
                )}
              </div>
              {/* Only a finished run has a verdict. For running/awaiting/error/
                  cancelled/interrupted rows the Status column carries the state —
                  an "untriaged" pill there reads as a contradiction. */}
              <div>{r.verdict === 'untriaged' ? <span className="text-faint">—</span> : <VerdictPill verdict={r.verdict} />}</div>
              <div className="font-mono text-[12.5px] text-text-2">{r.conf != null ? r.conf.toFixed(2) : '—'}</div>
              <div className="min-w-0 overflow-hidden"><FlowBadge src={r.host === '—' ? null : r.host} dst={r.dst} /></div>
              <div>
                <span className="inline-flex items-center gap-1.5 text-[11.5px]" style={{ color: st.color }}>
                  <span className={'h-1.5 w-1.5 rounded-full ' + (st.pulse ? 'animate-pulseDot' : '')} style={{ background: st.color }} />
                  {st.label}
                </span>
              </div>
              <div className="font-mono text-[12px] text-dim">{r.when}</div>
              <div className="flex justify-end" onClick={(e) => e.stopPropagation()}>
                {pendingDelete === r.id ? (
                  <div className="flex items-center gap-1.5">
                    <button onClick={() => { void deleteOne(r.id); }} title="Confirm delete" className="flex text-danger hover:opacity-80">
                      <Check size={14} />
                    </button>
                    <button onClick={() => setPendingDelete(null)} title="Cancel" className="flex text-faint hover:text-text">
                      <X size={14} />
                    </button>
                  </div>
                ) : (
                  <button
                    onClick={() => setPendingDelete(r.id)}
                    title="Delete investigation"
                    className="flex text-faint opacity-0 transition-opacity hover:text-danger group-hover:opacity-100"
                  >
                    <Trash2 size={13} />
                  </button>
                )}
              </div>
              </div>
              {expanded &&
                retries.map((rt) => {
                  const rtSt = STATUS[rt.status] ?? STATUS.error;
                  return (
                    <div
                      key={rt.id}
                      onClick={() => navigate(`/investigation/${rt.id}`, { state: { from: '/investigations' } })}
                      className="group grid cursor-pointer items-center gap-2.5 border-b border-border-faint bg-surface-2/30 px-3.5 py-[8px] hover:bg-surface-hover"
                      style={{ gridTemplateColumns: GRID }}
                    >
                      <div />
                      <div className="flex min-w-0 items-center gap-[7px] pl-3 text-faint">
                        <CornerDownRight size={12} className="flex-none" />
                        <span className="truncate text-[12px]">earlier run</span>
                      </div>
                      <div>{rt.verdict === 'untriaged' ? <span className="text-faint">—</span> : <VerdictPill verdict={rt.verdict} />}</div>
                      <div className="font-mono text-[12px] text-faint">{rt.conf != null ? rt.conf.toFixed(2) : '—'}</div>
                      <div className="min-w-0 overflow-hidden opacity-70"><FlowBadge src={rt.host === '—' ? null : rt.host} dst={rt.dst} /></div>
                      <div>
                        <span className="inline-flex items-center gap-1.5 text-[11px]" style={{ color: rtSt.color }}>
                          <span className="h-1.5 w-1.5 rounded-full" style={{ background: rtSt.color }} />
                          {rtSt.label}
                        </span>
                      </div>
                      <div className="font-mono text-[12px] text-faint">{rt.when}</div>
                      <div className="flex justify-end" onClick={(e) => e.stopPropagation()}>
                        {pendingDelete === rt.id ? (
                          <div className="flex items-center gap-1.5">
                            <button onClick={() => { void deleteOne(rt.id); }} title="Confirm delete" className="flex text-danger hover:opacity-80">
                              <Check size={14} />
                            </button>
                            <button onClick={() => setPendingDelete(null)} title="Cancel" className="flex text-faint hover:text-text">
                              <X size={14} />
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => setPendingDelete(rt.id)}
                            title="Delete this run"
                            className="flex text-faint opacity-0 transition-opacity hover:text-danger group-hover:opacity-100"
                          >
                            <Trash2 size={12} />
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}
            </Fragment>
          );
        })}
      </div>
    </div>
  );
}
