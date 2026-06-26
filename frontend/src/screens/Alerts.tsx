import { ArrowUpRight, Check, ChevronRight, Filter, Sparkles, X, Zap } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { KindBadge, SeverityTag, VerdictPill } from '../components/Badges';
import { Checkbox } from '../components/Controls';
import { Drawer } from '../components/Drawer';
import { MultiSelect } from '../components/MultiSelect';
import { TimeRangeFilter, type CustomRange } from '../components/TimeRangeFilter';
import { ErrorState, LoadingState, Spinner } from '../components/States';
import {
  type AlertQuery,
  type AutoTriageStatus,
  ackEvents,
  ackGroup,
  assignAlert,
  getAlertGroupEvents,
  getAlerts,
  getAutoTriageStatus,
  getInvestigation,
  getRepresentative,
  startAutoTriage,
  startHunt,
} from '../lib/api';
import { useAsync } from '../lib/useAsync';
import type { AlertEvent, AlertGroup, Investigation as Inv, Severity } from '../lib/types';
import { useShell } from '../shell/ShellContext';
import { Investigation } from './Investigation';

type ViewId = 'myqueue' | 'critical' | 'decision' | 'all';
type Density = 'comfortable' | 'compact';
type SortKey = 'count' | 'detection' | 'sev' | 'verdict' | 'conf' | 'latest';
type SortDir = 'asc' | 'desc';

// checkbox  count  DETECTION      sev   verdict  conf  owner  latest  actions
const GRID = '28px 48px minmax(180px,1fr) 110px 132px 56px 40px 76px 88px';

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const VERDICT_RANK: Record<string, number> = { true_positive: 4, false_positive: 3, needs_more_info: 2, untriaged: 1 };

/** Derive 1-2 char avatar initials from a username or token:<name> string. */
function toInitials(owner: string): string {
  const name = owner.startsWith('token:') ? owner.slice(6) : owner;
  // Split on dot, underscore, hyphen, or space
  const parts = name.split(/[._\-\s]+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return name.slice(0, 2).toUpperCase();
}

function cmpGroups(a: AlertGroup, b: AlertGroup, key: SortKey, dir: SortDir): number {
  let result = 0;
  switch (key) {
    case 'count':
      result = a.count - b.count;
      break;
    case 'detection':
      result = a.name.localeCompare(b.name);
      break;
    case 'sev':
      result = (SEV_RANK[a.sev] ?? 0) - (SEV_RANK[b.sev] ?? 0);
      break;
    case 'verdict':
      result = (VERDICT_RANK[a.verdict] ?? 0) - (VERDICT_RANK[b.verdict] ?? 0);
      break;
    case 'conf':
      // null sorts last in either direction
      if (a.conf == null && b.conf == null) result = 0;
      else if (a.conf == null) result = 1;
      else if (b.conf == null) result = -1;
      else result = a.conf - b.conf;
      break;
    case 'latest':
      // ISO strings sort chronologically; empty string sorts last
      result = (a.latestTs ?? '').localeCompare(b.latestTs ?? '');
      break;
  }
  return dir === 'asc' ? result : -result;
}

function matchView(g: AlertGroup, view: ViewId): boolean {
  switch (view) {
    case 'myqueue':
      return !!g.owner && g.owner !== '';
    case 'critical':
      return g.sev === 'critical';
    case 'decision':
      return g.verdict === 'needs_more_info' || g.verdict === 'untriaged';
    default:
      return true;
  }
}

export function Alerts() {
  const { triageNonce } = useShell();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [reloadKey, setReloadKey] = useState(0);
  const [filterTime, setFilterTime] = useState('24h');
  const [customRange, setCustomRange] = useState<CustomRange | null>(null);
  const [filterSevs, setFilterSevs] = useState<string[]>([]); // [] = all
  const [filterVerdicts, setFilterVerdicts] = useState<string[]>([]); // [] = all
  const [hideAcked, setHideAcked] = useState(true);

  const alertQuery: AlertQuery = {
    ...(filterTime === 'custom' && customRange
      ? { range: 'custom', from: customRange.from, to: customRange.to }
      : { range: filterTime }),
    hideAcked: hideAcked || undefined,
  };
  const { data: groups, loading, error } = useAsync(
    () => getAlerts(alertQuery),
    [filterTime, customRange?.from, customRange?.to, hideAcked, reloadKey]
  );

  const view = (searchParams.get('view') as ViewId) || 'all';
  const drawerId = searchParams.get('drawer');

  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  // Events live behind a lazy fetch — pulled the first time a group is expanded.
  const [groupEvents, setGroupEvents] = useState<Record<string, AlertEvent[]>>({});
  const [eventsLoading, setEventsLoading] = useState<Record<string, boolean>>({});
  const [starting, setStarting] = useState<AlertGroup | null>(null);
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [selEvents, setSelEvents] = useState<Record<string, boolean>>({});
  const [ackingEvents, setAckingEvents] = useState(false);
  const [density, setDensity] = useState<Density>('comfortable');
  const [sort, setSort] = useState<{ key: SortKey; dir: SortDir }>({ key: 'sev', dir: 'desc' });

  // ---- group-ack strip ---------------------------------------------------
  const [ackMsg, setAckMsg] = useState<string | null>(null);
  const ackMsgTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [acking, setAcking] = useState(false);
  const [ackingCount, setAckingCount] = useState(0);
  const [ackingAlertTotal, setAckingAlertTotal] = useState(0);
  const showAckMsg = (m: string) => {
    setAckMsg(m);
    if (ackMsgTimer.current) clearTimeout(ackMsgTimer.current);
    ackMsgTimer.current = setTimeout(() => setAckMsg(null), 7000);
  };

  // ---- group-hunt reason strip -------------------------------------------
  const [huntReason, setHuntReason] = useState<string | null>(null);
  const huntReasonTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const showHuntReason = (m: string) => {
    setHuntReason(m);
    if (huntReasonTimer.current) clearTimeout(huntReasonTimer.current);
    huntReasonTimer.current = setTimeout(() => setHuntReason(null), 12000);
  };
  // Track which group rows are currently resolving their representative event.
  const [huntGroupPending, setHuntGroupPending] = useState<Record<string, boolean>>({});

  // ---- auto-triage strip -------------------------------------------------
  const [triaging, setTriaging] = useState(false);
  const [pct, setPct] = useState(0);
  const [triageStatus, setTriageStatus] = useState<AutoTriageStatus | null>(null);
  const [triageMsg, setTriageMsg] = useState<string | null>(null);
  const triageTimer = useRef<ReturnType<typeof setInterval> | null>(null);
  const triageMsgTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Severity floor for the global sweep button ("High and up" by default).
  const [triageFloor, setTriageFloor] = useState<string>('high');

  const showTriageMsg = (m: string) => {
    setTriageMsg(m);
    if (triageMsgTimer.current) clearTimeout(triageMsgTimer.current);
    triageMsgTimer.current = setTimeout(() => setTriageMsg(null), 7000);
  };

  // A one-line summary of how a batch landed — never let it finish silently.
  const triageSummary = (s: AutoTriageStatus): string => {
    const parts = [`${s.hunted} triaged`];
    if (s.skipped) parts.push(`${s.skipped} skipped`);
    if (s.failed) parts.push(`${s.failed} failed`);
    return parts.join(' · ');
  };

  // Pass alertIds to triage exactly that selection; omit for the global sweep.
  // minSeverity only applies to the global sweep (ignored when alertIds given).
  const startTriage = (alertIds?: string[], minSeverity?: string) => {
    setTriaging(true);
    setPct(0);
    setTriageMsg(null);
    if (triageTimer.current) clearInterval(triageTimer.current);
    const finish = (msg: string | null) => {
      if (triageTimer.current) clearInterval(triageTimer.current);
      setPct(100);
      setTimeout(() => setTriaging(false), 900);
      setReloadKey((k) => k + 1); // pull in the verdicts the batch produced
      if (msg) showTriageMsg(msg);
    };
    const poll = () => {
      getAutoTriageStatus()
        .then((s) => {
          // skipped never enters the worker, so progress is processed/total.
          const done = s.hunted + s.failed;
          setPct(s.total ? Math.round((100 * done) / s.total) : 0);
          setTriageStatus(s);
          if (!s.active) finish(triageSummary(s));
        })
        .catch(() => finish('Auto-triage status check failed'));
    };
    startAutoTriage(alertIds?.length ? { alertIds } : { minSeverity })
      .then((s) => {
        if (!s.active) {
          // nothing to hunt, or the batch already wrapped up — show why
          finish(s.note || (s.total ? triageSummary(s) : 'Nothing to triage'));
          return;
        }
        // Refresh the list ~1.5 s after start so rows flip to "Triaging…"
        // before investigations have completed (the finish() bump handles verdicts).
        setTimeout(() => setReloadKey((k) => k + 1), 1500);
        triageTimer.current = setInterval(poll, 2000);
      })
      .catch(() => {
        setTriaging(false);
        showTriageMsg('Auto-triage failed to start');
      });
  };

  // kick off triage when the shell requests it (command palette / bulk bar)
  const lastNonce = useRef(triageNonce);
  useEffect(() => {
    if (triageNonce !== lastNonce.current) {
      lastNonce.current = triageNonce;
      startTriage(undefined, triageFloor);
    }
  }, [triageNonce]);

  useEffect(() => () => {
    if (triageTimer.current) clearInterval(triageTimer.current);
    if (triageMsgTimer.current) clearTimeout(triageMsgTimer.current);
    if (ackMsgTimer.current) clearTimeout(ackMsgTimer.current);
    if (huntReasonTimer.current) clearTimeout(huntReasonTimer.current);
  }, []);

  // Reset row expansion + cached events when the time window changes.
  useEffect(() => {
    setExpanded({});
    setGroupEvents({});
    setEventsLoading({});
  }, [filterTime, customRange?.from, customRange?.to]);

  const setView = (v: ViewId) => {
    searchParams.set('view', v);
    setSearchParams(searchParams, { replace: true });
  };
  const openDrawer = (id: string) => {
    setStarting(null);
    searchParams.set('drawer', id);
    setSearchParams(searchParams);
  };
  const closeDrawer = () => {
    setStarting(null);
    searchParams.delete('drawer');
    setSearchParams(searchParams);
    setReloadKey((k) => k + 1); // refresh verdict badges after a look
  };

  // Open the existing report behind a group, or start a new investigation.
  // For a new hunt the drawer opens IMMEDIATELY in a "starting" state (no list
  // flash), then swaps to the real investigation once it's created.
  const hunt = (g: AlertGroup) => {
    if (g.invId) {
      openDrawer(g.invId);
      return;
    }
    setStarting(g);
    startHunt(g.id)
      .then((invId) => openDrawer(invId))
      .catch(() => setStarting(null));
  };

  // Hunt the most-representative event in a collapsed group (most-common-flow
  // selection). Calls /alerts/representative, then /hunt, then opens the drawer.
  // Shows the selection rationale in a dismissible strip so the operator knows
  // which event was chosen and why.
  const huntGroup = (g: AlertGroup) => {
    setHuntGroupPending((s) => ({ ...s, [g.id]: true }));
    getRepresentative(g, alertQuery)
      .then((rep) => {
        showHuntReason(`Hunting representative: ${rep.reason}`);
        setStarting(g);
        return startHunt(rep.alert_id);
      })
      .then((invId) => openDrawer(invId))
      .catch(() => setStarting(null))
      .finally(() => setHuntGroupPending((s) => ({ ...s, [g.id]: false })));
  };

  const toggleExpand = (g: AlertGroup) => {
    const opening = !expanded[g.id];
    setExpanded((s) => ({ ...s, [g.id]: !s[g.id] }));
    // Fetch this group's events the first time it's opened.
    if (opening && groupEvents[g.id] === undefined && !eventsLoading[g.id]) {
      setEventsLoading((s) => ({ ...s, [g.id]: true }));
      getAlertGroupEvents(g, alertQuery)
        .then((evs) => setGroupEvents((s) => ({ ...s, [g.id]: evs })))
        .catch(() => setGroupEvents((s) => ({ ...s, [g.id]: [] })))
        .finally(() => setEventsLoading((s) => ({ ...s, [g.id]: false })));
    }
  };

  const ownerOf = (g: AlertGroup) => g.owner ?? '';
  const visible = (groups ?? [])
    .filter((g) => matchView(g, view))
    .filter((g) => !filterSevs.length || filterSevs.includes(g.sev))
    .filter((g) => !filterVerdicts.length || filterVerdicts.includes(g.verdict))
    .sort((a, b) => cmpGroups(a, b, sort.key, sort.dir));

  const toggleSort = (key: SortKey) => {
    setSort((s) => ({ key, dir: s.key === key && s.dir === 'desc' ? 'asc' : 'desc' }));
  };
  const caret = (key: SortKey) => {
    if (sort.key !== key) return null;
    return <span className="ml-0.5 text-accent">{sort.dir === 'asc' ? '↑' : '↓'}</span>;
  };
  const hdrCls = (key: SortKey) =>
    'cursor-pointer select-none hover:text-text ' + (sort.key === key ? 'text-text' : '');
  const visIds = visible.map((g) => g.id);
  const allSelected = visIds.length > 0 && visIds.every((id) => selected[id]);
  const selCount = Object.keys(selected).filter((k) => selected[k]).length;
  const selectedEventIds = Object.entries(selEvents).filter(([, v]) => v).map(([k]) => k);
  const rowPad = density === 'compact' ? '7px 14px' : '11px 14px';

  const toggleSelectAll = () => {
    setSelected((s) => {
      const next = { ...s };
      const all = visIds.every((id) => next[id]);
      visIds.forEach((id) => {
        if (all) delete next[id];
        else next[id] = true;
      });
      return next;
    });
  };

  const counts = {
    myqueue: (groups ?? []).filter((g) => !!g.owner && g.owner !== '').length,
    critical: (groups ?? []).filter((g) => g.sev === 'critical').length,
    decision: (groups ?? []).filter((g) => g.verdict === 'needs_more_info' || g.verdict === 'untriaged').length,
    all: (groups ?? []).length,
  };
  const untriaged = (groups ?? []).filter((g) => g.verdict === 'untriaged').length;
  const totalEvents = (groups ?? []).reduce((a, g) => a + g.count, 0);

  const TABS: Array<{ id: ViewId; label: string; count: number }> = [
    { id: 'myqueue', label: 'My queue', count: counts.myqueue },
    { id: 'critical', label: 'Critical', count: counts.critical },
    { id: 'decision', label: 'Needs decision', count: counts.decision },
    { id: 'all', label: 'All', count: counts.all },
  ];

  return (
    <div className="px-[22px] pb-[60px] pt-5">
      {/* header */}
      <div className="mb-4 flex items-end gap-3.5">
        <div>
          <div className="text-[20px] font-semibold tracking-[-.015em]">Alerts</div>
          <div className="mt-0.5 text-[13px] text-dim">
            {untriaged} untriaged · {counts.all} detections · {totalEvents} events in window
          </div>
        </div>
        <div className="flex-1" />
        <div className="flex items-center gap-0">
          <select
            value={triageFloor}
            onChange={(e) => setTriageFloor(e.target.value)}
            disabled={triaging}
            className="rounded-l-control border border-r-0 border-border-strong bg-surface-3 px-2.5 py-2 text-[12.5px] text-dim focus:outline-none focus:ring-1 focus:ring-accent disabled:opacity-50"
            title="Auto-triage severity floor"
          >
            <option value="critical">Critical only</option>
            <option value="high">High and up</option>
            <option value="medium">Medium and up</option>
            <option value="low">Low and up</option>
          </select>
          <button
            onClick={() => startTriage(undefined, triageFloor)}
            disabled={triaging}
            className="flex items-center gap-1.5 rounded-r-control border border-border-strong bg-surface-3 px-[13px] py-2 text-[13px] font-semibold text-text hover:border-accent hover:bg-[#141b25] disabled:opacity-50"
          >
            <span className="flex" style={{ color: '#facc15' }}><Zap size={14} /></span> Auto-triage
          </button>
        </div>
      </div>

      {/* live triage strip */}
      {triaging && (
        <div
          className="relative mb-3.5 flex items-center gap-[13px] overflow-hidden rounded-card border px-3.5 py-[11px]"
          style={{ borderColor: 'rgba(75,139,245,.35)', background: 'linear-gradient(90deg,rgba(75,139,245,.10),rgba(75,139,245,.02))' }}
        >
          <div className="absolute left-0 top-0 h-0.5 w-[40%] animate-scanline" style={{ background: 'linear-gradient(90deg,transparent,#4b8bf5,transparent)' }} />
          <Spinner size={15} />
          <div className="text-[13px] font-semibold">
            Auto-triaging
            {triageStatus?.severities?.length ? ` ${triageStatus.severities.join(', ')}` : ''}
            …
          </div>
          <div className="font-mono text-[12px] text-dim">
            {(() => {
              const s = triageStatus;
              const done = s ? s.hunted + s.skipped + s.failed : 0;
              const total = s ? s.total : 0;
              const parts: string[] = [`${done}/${total} hunted`];
              if (s && s.skipped) parts.push(`${s.skipped} skipped`);
              if (s && s.failed) parts.push(`${s.failed} failed`);
              if (s && s.tool_calls) parts.push(`${s.tool_calls} tool calls`);
              if (s && s.current) parts.push(s.current);
              return parts.join(' · ');
            })()}
          </div>
          <div className="flex-1" />
          <div className="font-mono text-[12px] font-semibold text-accent">{pct}%</div>
        </div>
      )}

      {/* triage result — so a batch never finishes silently */}
      {!triaging && triageMsg && (
        <div
          className="mb-3.5 flex items-center gap-2.5 rounded-card border px-3.5 py-2.5 text-[13px]"
          style={{ borderColor: 'rgba(75,139,245,.30)', background: 'rgba(75,139,245,.06)' }}
        >
          <span className="flex" style={{ color: '#facc15' }}><Zap size={13} /></span>
          <span className="font-semibold text-text-2">{triageMsg}</span>
          <div className="flex-1" />
          <button onClick={() => setTriageMsg(null)} className="flex text-dim hover:text-text" aria-label="Dismiss">
            <X size={14} />
          </button>
        </div>
      )}

      {/* ack in-progress banner */}
      {acking && (
        <div
          className="mb-3.5 flex items-center gap-2.5 rounded-card border px-3.5 py-2.5 text-[13px]"
          style={{ borderColor: 'rgba(34,197,94,.30)', background: 'rgba(34,197,94,.06)' }}
        >
          <Spinner size={14} />
          <span className="font-semibold text-text-2">Acknowledging {ackingCount} group{ackingCount !== 1 ? 's' : ''} ({ackingAlertTotal} alert{ackingAlertTotal !== 1 ? 's' : ''}) in Security Onion…</span>
        </div>
      )}

      {/* ack result strip */}
      {!acking && ackMsg && (
        <div
          className="mb-3.5 flex items-center gap-2.5 rounded-card border px-3.5 py-2.5 text-[13px]"
          style={{ borderColor: 'rgba(34,197,94,.30)', background: 'rgba(34,197,94,.06)' }}
        >
          <span className="font-semibold text-text-2">{ackMsg}</span>
          <div className="flex-1" />
          <button onClick={() => setAckMsg(null)} className="flex text-dim hover:text-text" aria-label="Dismiss">
            <X size={14} />
          </button>
        </div>
      )}

      {/* group-hunt representative reason strip */}
      {huntReason && (
        <div
          className="mb-3.5 flex items-center gap-2.5 rounded-card border px-3.5 py-2.5 text-[13px]"
          style={{ borderColor: 'rgba(139,92,246,.35)', background: 'rgba(139,92,246,.07)' }}
        >
          <span className="flex flex-shrink-0" style={{ color: '#a78bfa' }}><Sparkles size={13} /></span>
          <span className="font-semibold text-text-2">{huntReason}</span>
          <div className="flex-1" />
          <button onClick={() => setHuntReason(null)} className="flex text-dim hover:text-text" aria-label="Dismiss">
            <X size={14} />
          </button>
        </div>
      )}

      {/* saved-view tabs */}
      <div className="mb-3.5 flex items-center gap-0.5 border-b border-border">
        {TABS.map((t) => {
          const active = view === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setView(t.id)}
              className="-mb-px flex items-center gap-1.5 px-[13px] py-2 text-[13px]"
              style={{
                fontWeight: active ? 600 : 500,
                color: active ? '#e6e9ef' : '#8b94a3',
                borderBottom: `2px solid ${active ? '#4b8bf5' : 'transparent'}`,
              }}
            >
              {t.label}
              <span
                className="rounded-chip px-1.5 py-px font-mono text-[10.5px] text-dim"
                style={{ background: active ? '#141b25' : '#11161e' }}
              >
                {t.count}
              </span>
            </button>
          );
        })}
      </div>

      {/* filter bar */}
      <div className="mb-3.5 flex flex-wrap items-center gap-2">
        <TimeRangeFilter
          value={filterTime}
          custom={customRange}
          onChange={(v, r) => {
            setFilterTime(v);
            if (r) setCustomRange(r);
          }}
        />
        <MultiSelect
          label="Severity"
          icon={<Filter size={13} />}
          options={[
            { value: 'critical', label: 'Critical' },
            { value: 'high', label: 'High' },
            { value: 'medium', label: 'Medium' },
            { value: 'low', label: 'Low' },
          ]}
          value={filterSevs}
          onChange={setFilterSevs}
        />
        <MultiSelect
          label="Verdict"
          icon={<Filter size={13} />}
          options={[
            { value: 'untriaged', label: 'Untriaged' },
            { value: 'true_positive', label: 'True positive' },
            { value: 'false_positive', label: 'False positive' },
            { value: 'needs_more_info', label: 'Needs more info' },
          ]}
          value={filterVerdicts}
          onChange={setFilterVerdicts}
        />
        <button
          onClick={() => setHideAcked((v) => !v)}
          title="Hide acknowledged and escalated groups"
          className="flex items-center gap-1.5 rounded-control border px-[11px] py-[7px] text-[12.5px] font-semibold transition-colors"
          style={
            hideAcked
              ? { borderColor: 'rgba(34,197,94,.5)', background: 'rgba(34,197,94,.10)', color: '#4ade80' }
              : { borderColor: 'var(--color-border-2, #23314a)', background: 'var(--color-surface-1, #111827)', color: 'var(--color-dim, #8b94a3)' }
          }
        >
          <Check size={12} />
          Hide acknowledged
        </button>
        <div className="flex-1" />
        {/* density toggle */}
        <div className="flex overflow-hidden rounded-[7px] border border-border-2">
          <button
            onClick={() => setDensity('comfortable')}
            title="Comfortable"
            className="flex items-center px-2 py-1.5"
            style={{ color: density !== 'compact' ? '#e6e9ef' : '#5b6473', background: density !== 'compact' ? '#141b25' : 'transparent' }}
          >
            <svg width={15} height={15} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round"><path d="M4 7h16M4 12h16M4 17h16" /></svg>
          </button>
          <button
            onClick={() => setDensity('compact')}
            title="Compact"
            className="flex items-center border-l border-border-2 px-2 py-1.5"
            style={{ color: density === 'compact' ? '#e6e9ef' : '#5b6473', background: density === 'compact' ? '#141b25' : 'transparent' }}
          >
            <svg width={15} height={15} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round"><path d="M4 5h16M4 9h16M4 13h16M4 17h16M4 21h16" /></svg>
          </button>
        </div>
        <div className="flex items-center gap-1.5 text-[12.5px] text-dim">
          Sort <span className="font-mono font-semibold text-text">{sort.key} {sort.dir === 'asc' ? '↑' : '↓'}</span>
        </div>
      </div>

      {/* bulk action bar */}
      {(selCount > 0 || selectedEventIds.length > 0) && (
        <div className="mb-3 flex animate-fadeUp items-center gap-[9px] rounded-card border border-accent-deep bg-[#0d1726] px-[13px] py-2">
          <span className="text-[12.5px] font-semibold text-text-2">
            {selCount > 0 && (
              <>
                <span className="font-mono text-accent">{selCount}</span> group{selCount !== 1 ? 's' : ''}
                {' · '}
                <span className="font-mono text-accent">
                  {(groups ?? []).filter((g) => selected[g.id]).reduce((s, g) => s + (g.count || 0), 0)}
                </span> alerts
              </>
            )}
            {selCount > 0 && selectedEventIds.length > 0 && <span className="mx-1 text-faint">·</span>}
            {selectedEventIds.length > 0 && <><span className="font-mono text-accent">{selectedEventIds.length}</span> event{selectedEventIds.length !== 1 ? 's' : ''}</>}
          </span>
          <div className="h-4 w-px bg-[#23314a]" />
          <button
            onClick={() => {
              const groupIds = Object.keys(selected).filter((k) => selected[k]);
              const allIds = [...groupIds, ...selectedEventIds];
              if (!allIds.length) return;
              startTriage(allIds);
              setSelected({});
              setSelEvents({});
            }}
            className="flex items-center gap-1.5 rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold text-[#cfe0ff]"
            style={{ background: 'rgba(75,139,245,.14)', borderColor: 'rgba(75,139,245,.4)' }}
          >
            <span className="flex" style={{ color: '#facc15' }}><Zap size={13} /></span> Auto-triage
          </button>
          <button
            onClick={() => {
              const selectedGroups = (groups ?? []).filter((g) => selected[g.id]);
              if (!selectedGroups.length) return;
              const n = selectedGroups.length;
              // allSettled: a single assign failing must not silently drop the rest.
              // Keep failed groups selected so the analyst can retry them.
              Promise.allSettled(selectedGroups.map((g) => assignAlert(g.name)))
                .then((outcomes) => {
                  const failedIds = outcomes
                    .map((o, i) => (o.status === 'rejected' ? selectedGroups[i].id : null))
                    .filter((id): id is string => id !== null);
                  const ok = n - failedIds.length;
                  setSelected((s) => {
                    const next: Record<string, boolean> = {};
                    for (const id of failedIds) if (s[id]) next[id] = true;
                    return next;
                  });
                  if (failedIds.length) {
                    showAckMsg(`Assigned ${ok} of ${n} group${n !== 1 ? 's' : ''} · ${failedIds.length} failed — still selected, click Assign to me to retry`);
                  } else {
                    showAckMsg(`Assigned ${ok} group${ok !== 1 ? 's' : ''} to you`);
                  }
                  setReloadKey((k) => k + 1);
                });
            }}
            className="rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-1.5 text-[12.5px] font-semibold text-text hover:border-accent"
          >
            Assign to me
          </button>
          <button
            onClick={() => {
              const selectedGroups = (groups ?? []).filter((g) => selected[g.id]);
              if (!selectedGroups.length) return;
              const n = selectedGroups.length;
              const alertTotal = selectedGroups.reduce((s, g) => s + (g.count || 0), 0);
              setAckingCount(n);
              setAckingAlertTotal(alertTotal);
              setAcking(true);
              // allSettled: one group failing must not wipe the whole batch. Keep
              // failed groups selected so the analyst can retry them.
              Promise.allSettled(selectedGroups.map((g) => ackGroup(g, alertQuery)))
                .then((outcomes) => {
                  const failedIds: string[] = [];
                  let totalAcked = 0;
                  let totalFailed = 0;
                  let okGroups = 0;
                  let anyCapped = false;
                  outcomes.forEach((o, i) => {
                    if (o.status === 'fulfilled') {
                      okGroups += 1;
                      totalAcked += o.value.acked;
                      totalFailed += o.value.failed;
                      if (o.value.capped) anyCapped = true;
                    } else {
                      failedIds.push(selectedGroups[i].id);
                    }
                  });
                  const failedGroups = failedIds.length;
                  // Clear only the groups that succeeded; retain failed ones for retry.
                  setSelected((s) => {
                    const next: Record<string, boolean> = {};
                    for (const id of failedIds) if (s[id]) next[id] = true;
                    return next;
                  });
                  const parts = [`Acknowledged ${totalAcked} alert${totalAcked !== 1 ? 's' : ''} across ${okGroups} group${okGroups !== 1 ? 's' : ''}`];
                  if (totalFailed) parts.push(`${totalFailed} event${totalFailed !== 1 ? 's' : ''} failed`);
                  if (failedGroups) parts.push(`${failedGroups} group${failedGroups !== 1 ? 's' : ''} failed — still selected, click Acknowledge to retry`);
                  showAckMsg(parts.join(' · ') + (anyCapped ? ' — some groups exceeded the 200-event cap, click Acknowledge again to finish.' : ''));
                  setReloadKey((k) => k + 1);
                })
                .finally(() => setAcking(false));
            }}
            className="rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-1.5 text-[12.5px] font-semibold text-text hover:border-success-btn-border hover:text-success"
          >
            {(() => {
              const sg = (groups ?? []).filter((g) => selected[g.id]);
              const n = sg.length;
              const a = sg.reduce((s, g) => s + (g.count || 0), 0);
              return n > 0 ? `Acknowledge ${n} group${n !== 1 ? 's' : ''} · ${a} alert${a !== 1 ? 's' : ''}` : 'Acknowledge';
            })()}
          </button>
          {selectedEventIds.length > 0 && (
            <button
              disabled={ackingEvents}
              onClick={async () => {
                setAckingEvents(true);
                try {
                  await ackEvents(selectedEventIds);
                  setSelEvents({});
                  setReloadKey((k) => k + 1);
                } finally {
                  setAckingEvents(false);
                }
              }}
              className="rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-1.5 text-[12.5px] font-semibold text-text hover:border-success-btn-border hover:text-success disabled:opacity-50"
            >
              {ackingEvents ? 'Acking…' : `Ack ${selectedEventIds.length} event${selectedEventIds.length !== 1 ? 's' : ''}`}
            </button>
          )}
          <button onClick={() => { setSelected({}); setSelEvents({}); }} className="rounded-[7px] border border-border-strong bg-transparent px-[11px] py-1.5 text-[12.5px] font-semibold text-dim hover:border-danger hover:text-danger">
            Dismiss
          </button>
          <div className="flex-1" />
          <button onClick={() => { setSelected({}); setSelEvents({}); }} className="text-[12px] text-dim hover:text-text">Clear</button>
        </div>
      )}

      {/* table */}
      <div className="overflow-x-auto overflow-y-hidden rounded-card border border-border bg-surface-1">
        {/* header */}
        <div
          className="grid items-center gap-2.5 border-b border-border bg-surface-2 px-3.5 py-[9px] text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint"
          style={{ gridTemplateColumns: GRID, minWidth: 720 }}
        >
          <div className="flex items-center">
            <Checkbox checked={allSelected} onClick={toggleSelectAll} title="Select all" />
          </div>
          <div className={`text-right ${hdrCls('count')}`} onClick={() => toggleSort('count')}>
            Count{caret('count')}
          </div>
          <div className={hdrCls('detection')} onClick={() => toggleSort('detection')}>
            Detection{caret('detection')}
          </div>
          <div className={hdrCls('sev')} onClick={() => toggleSort('sev')}>
            Severity{caret('sev')}
          </div>
          <div className={hdrCls('verdict')} onClick={() => toggleSort('verdict')}>
            soc·ai verdict{caret('verdict')}
          </div>
          <div className={`text-right ${hdrCls('conf')}`} onClick={() => toggleSort('conf')}>
            Conf{caret('conf')}
          </div>
          <div>Owner</div>
          <div className={hdrCls('latest')} onClick={() => toggleSort('latest')}>
            Latest{caret('latest')}
          </div>
          <div />
        </div>

        {loading && !groups && <LoadingState label="Loading detections…" />}
        {error && <div className="p-3"><ErrorState error={error} /></div>}
        {!loading && !error && visible.length === 0 && (
          <div className="px-4 py-10 text-center text-[13px] text-faint">No detections match this view.</div>
        )}

        {visible.map((g) => {
          const isExp = !!expanded[g.id];
          const owner = ownerOf(g);
          const seld = !!selected[g.id];
          return (
            <div key={g.id}>
              <div
                onClick={() => toggleExpand(g)}
                className="grid cursor-pointer items-center gap-2.5 border-b border-border-faint hover:bg-surface-hover"
                style={{ gridTemplateColumns: GRID, minWidth: 720, padding: rowPad }}
              >
                {(() => {
                  const loadedEvs = groupEvents[g.id] ?? [];
                  const loadedIds = loadedEvs.map((ev) => ev.id).filter(Boolean) as string[];
                  const evSelCount = loadedIds.filter((id) => selEvents[id]).length;
                  const evIndeterminate = evSelCount > 0 && evSelCount < loadedIds.length;
                  return (
                    <div className="flex items-center">
                      <Checkbox
                        checked={seld}
                        indeterminate={evIndeterminate}
                        onClick={(e) => {
                          e.stopPropagation();
                          const turning = !seld;
                          setSelected((s) => {
                            const next = { ...s };
                            if (next[g.id]) delete next[g.id];
                            else next[g.id] = true;
                            return next;
                          });
                          setSelEvents((prev) => {
                            const next = { ...prev };
                            if (turning) {
                              (groupEvents[g.id] ?? []).forEach((ev) => { if (ev.id) next[ev.id] = true; });
                            } else {
                              (groupEvents[g.id] ?? []).forEach((ev) => { if (ev.id) delete next[ev.id]; });
                            }
                            return next;
                          });
                        }}
                      />
                    </div>
                  );
                })()}
                <div className="text-right font-mono text-[13px] font-semibold text-text-2">{g.count}</div>
                <div className="flex min-w-0 items-center gap-[9px]">
                  <span className="flex text-faint transition-transform" style={{ transform: isExp ? 'rotate(90deg)' : 'rotate(0deg)' }}>
                    <ChevronRight size={13} />
                  </span>
                  <KindBadge kind={g.kind} />
                  <span className="min-w-0 flex-1 truncate text-[13.5px] font-medium">{g.name}</span>
                  {(g.ackedCount ?? 0) > 0 && (
                    <span
                      title={`${g.ackedCount} acknowledged`}
                      className="inline-flex flex-shrink-0 items-center gap-[3px] rounded-chip border px-[5px] py-[2px] font-mono text-[10px] font-semibold"
                      style={{ borderColor: 'rgba(34,197,94,.35)', background: 'rgba(34,197,94,.08)', color: '#4ade80' }}
                    >
                      <Check size={9} strokeWidth={2.5} />
                      {g.ackedCount}
                    </span>
                  )}
                  {(g.escalatedCount ?? 0) > 0 && (
                    <span
                      title={`${g.escalatedCount} escalated`}
                      className="inline-flex flex-shrink-0 items-center gap-[3px] rounded-chip border px-[5px] py-[2px] font-mono text-[10px] font-semibold"
                      style={{ borderColor: 'rgba(251,146,60,.35)', background: 'rgba(251,146,60,.08)', color: '#fb923c' }}
                    >
                      <ArrowUpRight size={9} strokeWidth={2.5} />
                      {g.escalatedCount}
                    </span>
                  )}
                </div>
                <div><SeverityTag sev={g.sev} /></div>
                <div className="min-w-0 overflow-hidden" title={g.inheritedReason ?? undefined}>
                  {g.triaging ? (
                    <span className="inline-flex items-center gap-1.5 rounded-chip border border-[rgba(251,191,36,.35)] bg-[rgba(251,191,36,.10)] px-2 py-[3px] text-[11px] font-semibold text-[#fbbf24]">
                      <Spinner size={10} color="#fbbf24" />
                      Triaging…
                    </span>
                  ) : (
                    <VerdictPill verdict={g.verdict} conf={g.conf} inherited={g.inherited} showConf={false} showInherited={false} />
                  )}
                </div>
                <div className="text-right font-mono text-[12px] text-dim">
                  {g.conf != null ? g.conf.toFixed(2) : '—'}
                </div>
                <div className="flex items-center">
                  {owner ? (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        assignAlert(g.name, true).then(() => setReloadKey((k) => k + 1));
                      }}
                      title={`Assigned to ${owner} — click to unassign`}
                      className="flex h-[25px] w-[25px] items-center justify-center rounded-full border border-border-strong bg-[#1a2330] text-[9.5px] font-bold text-[#b9c2cf] hover:border-danger hover:text-danger"
                    >
                      {toInitials(owner)}
                    </button>
                  ) : (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        assignAlert(g.name).then(() => setReloadKey((k) => k + 1));
                      }}
                      title="Assign to me"
                      className="flex h-[25px] w-[25px] items-center justify-center rounded-full border-[1.5px] border-dashed border-border-strong text-[14px] leading-none text-faint hover:border-accent hover:text-accent"
                    >
                      +
                    </button>
                  )}
                </div>
                <div className="font-mono text-[12px] text-dim">{g.latest}</div>
                <div className="flex items-center justify-end gap-1">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      huntGroup(g);
                    }}
                    disabled={!!huntGroupPending[g.id]}
                    title="Hunt the most-representative event in this group"
                    aria-label="Hunt with AI"
                    className="inline-flex items-center gap-1 rounded-badge border px-[7px] py-[3px] font-sans text-[11px] font-semibold disabled:opacity-50"
                    style={{ borderColor: 'rgba(139,92,246,.35)', background: 'rgba(139,92,246,.07)', color: '#a78bfa' }}
                  >
                    <Sparkles size={11} />
                    {huntGroupPending[g.id] ? '…' : 'Hunt'}
                  </button>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      openDrawer(g.invId ?? g.id);
                    }}
                    aria-label="Open investigation"
                    className="flex rounded-chip p-[3px] text-faint hover:bg-[#141b25] hover:text-accent"
                  >
                    <ArrowUpRight size={13} />
                  </button>
                </div>
              </div>

              {/* expanded events (lazy-loaded on first open) */}
              {isExp && (
                <div className="animate-fadeUp-slow border-b border-border-faint bg-bg pb-1.5 pt-1">
                  {eventsLoading[g.id] && (
                    <div className="py-2.5 pl-[50px] font-mono text-[11.5px] text-faint">Loading events…</div>
                  )}
                  {!eventsLoading[g.id] && (groupEvents[g.id]?.length ?? 0) === 0 && (
                    <div className="py-2.5 pl-[50px] font-mono text-[11.5px] text-faint">No events in window.</div>
                  )}
                  {(groupEvents[g.id] ?? []).map((ev, i) => (
                    <div
                      key={ev.id ?? i}
                      className="grid items-center gap-2.5 py-[7px] pl-[36px] pr-3.5 font-mono text-[11.5px] hover:bg-surface-2"
                      style={{ gridTemplateColumns: '16px 52px 70px 1fr 140px 132px' }}
                    >
                      {/* per-event checkbox */}
                      <div onClick={(e) => e.stopPropagation()}>
                        <Checkbox
                          checked={!!(ev.id && selEvents[ev.id])}
                          onChange={(checked) => {
                            if (!ev.id) return;
                            setSelEvents((prev) => ({ ...prev, [ev.id!]: checked }));
                          }}
                          onClick={(e) => e.stopPropagation()}
                        />
                      </div>
                      {/* time */}
                      <div className="text-faint" title={ev.ts ?? ''}>{ev.ago ?? ''}</div>
                      {/* severity */}
                      <div><SeverityTag sev={(ev.sev ?? 'low') as Severity} /></div>
                      {/* src → dst:port */}
                      <div className="flex min-w-0 items-center gap-1.5 truncate">
                        <span className="text-mono-green">{ev.src}</span>
                        <span className="text-ghost">→</span>
                        <span className="text-mono-amber">{ev.dst}</span>
                        {ev.port != null && (
                          <span className="text-faint">:{ev.port}</span>
                        )}
                      </div>
                      {/* host + provenance badge */}
                      <div className="flex min-w-0 items-center gap-1.5 truncate">
                        <span className="truncate text-dim">{ev.host}</span>
                        {ev.investigated ? (
                          <span
                            title="This exact event was investigated"
                            className="inline-flex flex-shrink-0 items-center rounded-chip border px-[5px] py-[2px] font-mono text-[9.5px] font-semibold"
                            style={{ borderColor: 'rgba(34,197,94,.35)', background: 'rgba(34,197,94,.08)', color: '#4ade80' }}
                          >
                            investigated
                          </span>
                        ) : ev.inheritedReason ? (
                          <span
                            title={ev.inheritedReason}
                            className="inline-flex flex-shrink-0 cursor-help items-center rounded-chip border px-[5px] py-[2px] font-mono text-[9.5px] font-semibold"
                            style={{ borderColor: 'rgba(148,163,184,.25)', background: 'rgba(148,163,184,.07)', color: '#94a3b8' }}
                          >
                            inherited ↑
                          </span>
                        ) : null}
                      </div>
                      {/* hunt button */}
                      <div className="flex justify-end">
                        <button
                          onClick={() => hunt(g)}
                          className="inline-flex items-center gap-1.5 rounded-badge border px-[9px] py-[3px] font-sans text-[11px] font-semibold text-accent"
                          style={{ borderColor: 'rgba(75,139,245,.3)', background: 'rgba(75,139,245,.07)' }}
                        >
                          <Sparkles size={12} />
                          {g.invId ? 'Open report' : 'Hunt with AI'}
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div className="mt-2.5 font-mono text-[12px] text-faint">
        {counts.all} detections · grouped · click a row to expand events
      </div>

      {/* investigation drawer */}
      <AlertDrawer
        drawerId={drawerId}
        starting={starting}
        onClose={closeDrawer}
        navigateToPermalink={(id) => navigate(`/investigation/${id}`, { state: { from: '/alerts' } })}
        onReHunt={openDrawer}
        onComplete={() => setReloadKey((k) => k + 1)}
      />
    </div>
  );
}

function AlertDrawer({
  drawerId,
  starting,
  onClose,
  navigateToPermalink,
  onReHunt,
  onComplete,
}: {
  drawerId: string | null;
  starting: AlertGroup | null;
  onClose: () => void;
  navigateToPermalink: (id: string) => void;
  onReHunt: (id: string) => void;
  onComplete: () => void;
}) {
  const [tick, setTick] = useState(0);
  const { data: inv, loading, error } = useAsync<Inv | null>(
    () => (drawerId ? getInvestigation(drawerId) : Promise.resolve(null)),
    [drawerId, tick]
  );

  // Poll a running investigation until it lands a verdict; refresh the alert
  // list once it completes so the verdict badge updates without a manual reload.
  const wasRunning = useRef(false);
  useEffect(() => {
    if (inv?.status === 'investigating') {
      wasRunning.current = true;
      const t = setTimeout(() => setTick((x) => x + 1), 2500);
      return () => clearTimeout(t);
    }
    // Terminal: a verdict landed ('complete') OR the run was reaped/interrupted
    // ('error'). Either way, stop polling and refresh the list so the row badge
    // reflects the final state instead of a stale "investigating".
    if ((inv?.status === 'complete' || inv?.status === 'error') && wasRunning.current) {
      wasRunning.current = false;
      onComplete();
    }
  }, [inv, tick, onComplete]);

  const isStarting = !!starting && !drawerId;

  return (
    <Drawer
      open={!!drawerId || isStarting}
      onClose={onClose}
      header={
        <>
          <span className="rounded-chip border px-1.5 py-0.5 font-mono text-[9.5px] font-semibold uppercase" style={{ color: '#4b8bf5', background: 'rgba(75,139,245,.1)', borderColor: 'rgba(75,139,245,.3)' }}>
            {inv?.kind ?? starting?.kind ?? 'suricata'}
          </span>
          <div className="flex-1 truncate text-[14px] font-semibold">{inv?.name ?? starting?.name ?? 'Investigation'}</div>
          {inv && (
            <button
              onClick={() => navigateToPermalink(inv.id)}
              className="flex items-center gap-1.5 text-[12px] text-dim hover:text-accent"
            >
              <ArrowUpRight size={13} /> Permalink
            </button>
          )}
          <button onClick={onClose} aria-label="Close" className="flex p-[3px] text-faint hover:text-text">
            <X size={16} />
          </button>
        </>
      }
    >
      {isStarting && <LoadingState label={`Starting investigation on ${starting?.name}…`} />}
      {drawerId && loading && !inv && <LoadingState label="Loading investigation…" />}
      {error && <div className="p-4"><ErrorState error={error} /></div>}
      {inv && <Investigation inv={inv} layout="drawer" onReHunt={onReHunt} onVerdictApplied={() => setTick((x) => x + 1)} />}
    </Drawer>
  );
}
