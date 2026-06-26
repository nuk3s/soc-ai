import { MessageSquare, RefreshCw } from 'lucide-react';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { KindBadge, VerdictPill } from '../components/Badges';
import { MultiSelect } from '../components/MultiSelect';
import { Checkbox } from '../components/Controls';
import { ErrorState, LoadingState } from '../components/States';
import { getInvestigations, rehuntInvestigations } from '../lib/api';
import { useAsync } from '../lib/useAsync';
import type { InvestigationRow, Verdict } from '../lib/types';

const GRID = '28px 1fr 150px 90px 120px 110px 120px';

const STATUS: Record<InvestigationRow['status'], { color: string; label: string; pulse: boolean }> = {
  complete: { color: '#3fb950', label: 'Complete', pulse: false },
  running: { color: '#4b8bf5', label: 'Investigating', pulse: true },
  awaiting: { color: '#f5a623', label: 'Awaiting decision', pulse: true },
  error: { color: '#f04438', label: 'Error', pulse: false },
};

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
  complete: 3,
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
  const { data, loading, error } = useAsync(getInvestigations, [reloadKey]);

  const [filterVerdicts, setFilterVerdicts] = useState<string[]>([]);
  const [filterStatuses, setFilterStatuses] = useState<string[]>([]);
  const [sort, setSort] = useState<{ key: SortKey; dir: SortDir }>({ key: 'when', dir: 'desc' });

  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [rehunting, setRehunting] = useState(false);
  const [rehuntMsg, setRehuntMsg] = useState<string | null>(null);

  const rows = data ?? [];
  const running = rows.filter((r) => r.status === 'running').length;
  const tps = rows.filter((r) => r.verdict === 'true_positive').length;

  // Apply filters then sort
  const visible = rows
    .filter((r) => !filterVerdicts.length || filterVerdicts.includes(r.verdict))
    .filter((r) => !filterStatuses.length || filterStatuses.includes(r.status))
    .sort((a, b) => cmpRows(a, b, sort.key, sort.dir));

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

  return (
    <div className="px-[22px] pb-[60px] pt-5">
      <div className="text-[20px] font-semibold tracking-[-.015em]">Investigations</div>
      <div className="mb-4 mt-0.5 text-[13px] text-dim">
        {rows.length} investigations · {running} in progress · {tps} true positive
      </div>

      {/* filter bar + bulk action */}
      <div className="mb-3.5 flex flex-wrap items-center gap-2">
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
          ]}
          value={filterStatuses}
          onChange={setFilterStatuses}
        />

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
            Host{caret('host')}
          </div>
          <div className={headerCls('status')} onClick={() => toggleSort('status')}>
            Status{caret('status')}
          </div>
          <div className={headerCls('when')} onClick={() => toggleSort('when')}>
            When{caret('when')}
          </div>
        </div>

        {loading && <LoadingState />}
        {error && <div className="p-3"><ErrorState error={error} /></div>}
        {!loading && !error && rows.length === 0 && (
          <div className="px-4 py-10 text-center text-[13px] text-faint">No investigations yet.</div>
        )}
        {!loading && !error && rows.length > 0 && visible.length === 0 && (
          <div className="px-4 py-10 text-center text-[13px] text-faint">No investigations match the selected filters.</div>
        )}
        {visible.map((r) => {
          const st = STATUS[r.status] ?? STATUS.complete;
          return (
            <div
              key={r.id}
              onClick={() => navigate(`/investigation/${r.id}`, { state: { from: '/investigations' } })}
              className="grid cursor-pointer items-center gap-2.5 border-b border-border-faint px-3.5 py-[11px] hover:bg-surface-hover"
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
              <div><VerdictPill verdict={r.verdict} /></div>
              <div className="font-mono text-[12.5px] text-text-2">{r.conf != null ? r.conf.toFixed(2) : '—'}</div>
              <div className="font-mono text-[12px] text-mono-amber">{r.host}</div>
              <div>
                <span className="inline-flex items-center gap-1.5 text-[11.5px]" style={{ color: st.color }}>
                  <span className={'h-1.5 w-1.5 rounded-full ' + (st.pulse ? 'animate-pulseDot' : '')} style={{ background: st.color }} />
                  {st.label}
                </span>
              </div>
              <div className="font-mono text-[12px] text-dim">{r.when}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
