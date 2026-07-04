import { Activity, ArrowUpRight, Crosshair, Database, ShieldAlert, ShieldCheck, WifiOff, X } from 'lucide-react';
import { type ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { KindBadge, StatusTag, VerdictPill } from '../components/Badges';
import { FlowBadge } from '../components/FlowBadge';
import { INV_STATUS } from '../lib/statusMeta';
import { Panel, PanelHeader } from '../components/Panel';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { TimeRangeFilter, type CustomRange } from '../components/TimeRangeFilter';
import {
  type AlertQuery,
  type AutoTriageStatus,
  type DataSource,
  type Health,
  getAlerts,
  getAutoTriageStatus,
  getDataSources,
  getHealth,
  getInvestigations,
} from '../lib/api';
import { VERDICT } from '../lib/tokens';
import type { AlertGroup, Severity, Verdict } from '../lib/types';
import { useAsync } from '../lib/useAsync';

// Status presentation mirrors the Investigations screen so a verdict reads the

const SEV_META: Record<Severity, { label: string; color: string }> = {
  critical: { label: 'Critical', color: '#f04438' },
  high: { label: 'High', color: '#f79009' },
  medium: { label: 'Medium', color: '#eab308' },
  low: { label: 'Low', color: '#6b87a8' },
};
const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];
// Outcome order: most-actionable first.
const VERDICT_ORDER: Verdict[] = ['true_positive', 'needs_more_info', 'inconclusive', 'false_positive', 'untriaged'];

interface Metrics {
  events: number;
  groups: number;
  verdict: Record<Verdict, number>;
  sev: Record<Severity, number>;
  triaging: number;
}

function computeMetrics(groups: AlertGroup[]): Metrics {
  const verdict: Record<Verdict, number> = {
    true_positive: 0,
    false_positive: 0,
    needs_more_info: 0,
    inconclusive: 0,
    untriaged: 0,
  };
  const sev: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let events = 0;
  let triaging = 0;
  for (const g of groups) {
    events += g.count || 0;
    sev[g.sev] = (sev[g.sev] ?? 0) + 1;
    // A group with a live investigation is "in flight", not "awaiting triage".
    // It still reads verdict=untriaged in the DB until the run lands, so counting
    // it as untriaged is what inflated "Awaiting triage" above the running count.
    if (g.triaging) {
      triaging += 1;
      continue;
    }
    verdict[g.verdict] = (verdict[g.verdict] ?? 0) + 1;
  }
  return { events, groups: groups.length, verdict, sev, triaging };
}

// ---- small building blocks -------------------------------------------------

function StatCard({
  label,
  value,
  sub,
  color = '#e6e9ef',
  icon,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  color?: string;
  icon?: ReactNode;
}) {
  return (
    <Panel className="px-4 py-3.5">
      <div className="flex items-start justify-between">
        <div className="text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">{label}</div>
        {icon && (
          <span className="flex" style={{ color }}>
            {icon}
          </span>
        )}
      </div>
      <div className="mt-2 text-[27px] font-semibold leading-none tabular-nums" style={{ color }}>
        {value}
      </div>
      {sub && <div className="mt-1.5 text-[11.5px] leading-[1.4] text-dim">{sub}</div>}
    </Panel>
  );
}

function VerdictBreakdown({ verdict, total }: { verdict: Record<Verdict, number>; total: number }) {
  return (
    <div className="px-[15px] py-3.5">
      <div className="flex h-2.5 w-full overflow-hidden rounded-pill bg-surface-3">
        {VERDICT_ORDER.map((v) =>
          verdict[v] ? (
            <div
              key={v}
              title={`${VERDICT[v].label}: ${verdict[v]}`}
              style={{ width: `${(verdict[v] / total) * 100}%`, background: VERDICT[v].color }}
            />
          ) : null,
        )}
      </div>
      <div className="mt-3.5 grid grid-cols-2 gap-2 sm:grid-cols-4">
        {VERDICT_ORDER.map((v) => (
          <div
            key={v}
            className="flex items-center justify-between gap-2 rounded-card border border-border-faint px-2.5 py-2"
          >
            <VerdictPill verdict={v} showConf={false} />
            <span
              className="font-mono text-[15px] font-semibold tabular-nums"
              style={{ color: VERDICT[v].color }}
            >
              {verdict[v] || 0}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function SeverityBreakdown({ sev, total }: { sev: Record<Severity, number>; total: number }) {
  return (
    <div className="border-t border-border-faint px-[15px] py-3.5">
      <div className="mb-2.5 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
        By severity
      </div>
      <div className="flex flex-col gap-2">
        {SEV_ORDER.map((s) => {
          const n = sev[s] || 0;
          const meta = SEV_META[s];
          return (
            <div key={s} className="flex items-center gap-3">
              <span
                className="flex w-[58px] flex-none items-center gap-1.5 text-[11.5px] font-semibold"
                style={{ color: meta.color }}
              >
                <span className="h-[7px] w-[7px] flex-none rounded-[2px]" style={{ background: meta.color }} />
                {meta.label}
              </span>
              <div className="h-1.5 flex-1 overflow-hidden rounded-pill bg-surface-3">
                <div
                  className="h-full rounded-pill"
                  style={{ width: total ? `${(n / total) * 100}%` : 0, background: meta.color }}
                />
              </div>
              <span className="w-7 flex-none text-right font-mono text-[12px] tabular-nums text-dim">{n}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function AutoTriagePanel({ s, loading }: { s: AutoTriageStatus | null; loading: boolean }) {
  if (!s) return loading ? <LoadingState label="Checking…" /> : <EmptyState>No investigation activity.</EmptyState>;
  const done = s.hunted + s.skipped + s.failed;
  const pct = s.total ? Math.round((done / s.total) * 100) : 0;
  if (s.active) {
    return (
      <div className="px-[15px] py-3.5">
        <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
          <StatusTag color="#4b8bf5" label="Running" pulse />
          <span className="font-mono text-[12px] text-dim">
            {done}/{s.total} · {s.tool_calls} tool calls
          </span>
        </div>
        <div className="mt-2.5 h-2 w-full overflow-hidden rounded-pill bg-surface-3">
          <div className="h-full rounded-pill bg-accent transition-[width] duration-500" style={{ width: `${pct}%` }} />
        </div>
        {s.current && <div className="mt-2 truncate font-mono text-[11px] text-faint">{s.current}</div>}
      </div>
    );
  }
  return (
    <div className="px-[15px] py-3.5 text-[12.5px] leading-[1.5] text-dim">
      {s.finished_at ? (
        <>
          Last batch ·{' '}
          <span className="font-semibold text-text">{s.hunted}</span> investigated
          {s.skipped ? `, ${s.skipped} skipped` : ''}
          {s.failed ? `, ${s.failed} failed` : ''}.
        </>
      ) : (
        'Idle — no auto-investigate batch has run yet.'
      )}
    </div>
  );
}

function EnrichmentPanel({
  sources,
  error,
  loading,
  onManage,
}: {
  sources: DataSource[];
  error: Error | null;
  loading: boolean;
  onManage: () => void;
}) {
  if (error) {
    return (
      <div className="px-[15px] py-3.5 text-[12px] leading-[1.5] text-faint">
        Sign in as an admin to view enrichment posture.
      </div>
    );
  }
  if (!sources.length) {
    return loading ? <LoadingState label="Loading…" /> : <EmptyState>No data sources.</EmptyState>;
  }
  const local = sources.filter((s) => s.category === 'Local feed');
  const online = sources.filter((s) => s.category === 'Online lookup');
  const localPresent = local.filter((s) => s.present).length;
  const onlineOn = online.filter((s) => s.enabled).length;

  const Row = ({ label, value, color }: { label: string; value: string; color: string }) => (
    <div className="flex items-center justify-between border-b border-border-faint px-[15px] py-2.5 last:border-0">
      <span className="text-[12.5px] text-dim">{label}</span>
      <span className="text-[12.5px] font-semibold" style={{ color }}>
        {value}
      </span>
    </div>
  );

  return (
    <div>
      <Row
        label="Local feeds"
        value={`${localPresent}/${local.length} present`}
        color={localPresent === local.length ? '#3fb950' : '#f5a623'}
      />
      <Row
        label="Online enrichment"
        value={onlineOn > 0 ? `${onlineOn} enabled` : 'off · zero-egress'}
        color={onlineOn > 0 ? '#4b8bf5' : '#8b94a3'}
      />
      <button
        onClick={onManage}
        className="flex w-full items-center gap-1 px-[15px] py-2.5 text-left text-[12px] font-semibold text-accent hover:bg-surface-3"
      >
        Manage data sources
        <ArrowUpRight size={13} />
      </button>
    </div>
  );
}

// A dependency that's down, in operator terms. The `detail` comes verbatim from
// the (secret-free) backend probe; `label` humanizes which upstream it is.
interface DownDep {
  key: 'es' | 'llm';
  label: string;
  detail: string;
}

// Which of the health components are unreachable — drives the connection banner.
// Only ES + LLM are treated as blocking dependencies (PCAP is optional/advisory).
function downDeps(h: Health | null): DownDep[] {
  if (!h) return [];
  const out: DownDep[] = [];
  if (!h.es.ok) out.push({ key: 'es', label: 'Security Onion (Elasticsearch)', detail: h.es.detail });
  if (!h.llm.ok) out.push({ key: 'llm', label: 'AI gateway (LLM)', detail: h.llm.detail });
  return out;
}

// ---- screen ----------------------------------------------------------------

export function Dashboard() {
  const navigate = useNavigate();
  const [range, setRange] = useState('24h');
  const [custom, setCustom] = useState<CustomRange | null>(null);
  const rangeLabel = range === 'custom' ? 'custom range' : `last ${range}`;
  const alertQuery: AlertQuery =
    range === 'custom' && custom ? { range: 'custom', from: custom.from, to: custom.to } : { range };
  // KPI cards aren't a live console — a 30s cadence keeps the counts fresh
  // without hammering ES aggregation on every idle dashboard.
  const alerts = useAsync(() => getAlerts(alertQuery), [range, custom?.from, custom?.to], {
    refetchInterval: 30_000,
  });
  // Poll fast while activity is live, THROTTLE (not fully pause) when idle. A
  // hard pause deadlocked: the only thing that re-armed the "active" ref was a
  // non-skipped poll, but every idle tick was skipped — so a run started from
  // the scheduler or another tab never surfaced on this "live overview". Letting
  // roughly every Nth idle tick through keeps it live at a slow cadence.
  const idleThrottle = (activeRef: { current: boolean }, tickRef: { current: number }, everyN: number) => () => {
    if (activeRef.current) {
      tickRef.current = 0;
      return false; // active → never skip
    }
    tickRef.current = (tickRef.current + 1) % everyN;
    return tickRef.current !== 0; // idle → run only every Nth tick
  };
  const invsActiveRef = useRef(false);
  const invsTick = useRef(0);
  const invs = useAsync(getInvestigations, [], {
    refetchInterval: 10_000,
    pauseWhen: idleThrottle(invsActiveRef, invsTick, 3), // ~30s when idle
  });
  const triageActiveRef = useRef(false);
  const triageTick = useRef(0);
  const triage = useAsync(getAutoTriageStatus, [], {
    refetchInterval: 5_000,
    pauseWhen: idleThrottle(triageActiveRef, triageTick, 6), // ~30s when idle
  });
  triageActiveRef.current = !!triage.data?.active;
  const sources = useAsync(getDataSources, [], { refetchInterval: 60_000 });
  // Upstream reachability — polled on mount + every 30s so a down dependency
  // (ES / gateway) surfaces as a banner instead of a wall of empty widgets.
  // Errors resolve to null (health data is null) → no banner, so a transient
  // /health hiccup can't itself raise a false "not connected" alarm.
  const health = useAsync(getHealth, [], { refetchInterval: 30_000 });
  // Which down deps the operator has dismissed this session (by key). A dep that
  // recovers then fails again re-shows: dismissal is cleared once it's healthy.
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());
  const down = downDeps(health.data ?? null);
  const banners = down.filter((d) => !dismissed.has(d.key));
  // Re-arm the banner for a dep once it recovers: prune any dismissed key that
  // is no longer down, so a later re-failure shows the banner again. Keyed on
  // the current down set so it only runs when reachability actually changes.
  const downKeys = down.map((d) => d.key).join(',');
  useEffect(() => {
    setDismissed((prev) => {
      if (!prev.size) return prev;
      const next = new Set([...prev].filter((k) => downKeys.split(',').includes(k)));
      return next.size === prev.size ? prev : next;
    });
  }, [downKeys]);

  const groups = useMemo(() => alerts.data ?? [], [alerts.data]);
  const rows = useMemo(() => invs.data ?? [], [invs.data]);
  invsActiveRef.current = rows.some((r) => r.status === 'running');
  const m = useMemo(() => computeMetrics(groups), [groups]);
  // Recent = real triage activity. Cancelled/interrupted runs are noise (a stop
  // press or a restart cut them off, no verdict) — keep them off the overview.
  const recent = useMemo(
    () =>
      [...rows]
        .filter((r) => r.status !== 'cancelled' && r.status !== 'interrupted')
        .sort((a, b) => (b.ts ?? '').localeCompare(a.ts ?? ''))
        .slice(0, 7),
    [rows],
  );
  const running = rows.filter((r) => r.status === 'running').length;

  const a = (n: number): string => (alerts.data ? n.toLocaleString() : alerts.error ? '—' : '…');
  const i = (n: number): string => (invs.data ? n.toLocaleString() : invs.error ? '—' : '…');

  return (
    <div className="px-[22px] pb-[60px] pt-5">
      {/* Connection banner — a down dependency (ES / gateway) is surfaced
          prominently above content, styled like the Alerts.tsx danger strips.
          Dismissible; re-shows if the dep recovers then fails again. */}
      {banners.map((d) => (
        <div
          key={d.key}
          role="alert"
          className="mb-3.5 flex items-start gap-2.5 rounded-card border px-3.5 py-2.5 text-[13px]"
          style={{ borderColor: 'rgba(240,68,56,.35)', background: 'rgba(240,68,56,.08)' }}
        >
          <span className="mt-px flex flex-shrink-0" style={{ color: '#f04438' }}>
            <WifiOff size={15} />
          </span>
          <div className="min-w-0 flex-1">
            <div className="font-semibold text-text-2">{d.label} not reachable</div>
            <div className="mt-0.5 break-words text-[12px] leading-[1.5] text-dim">{d.detail}</div>
          </div>
          <button
            onClick={() => setDismissed((s) => new Set(s).add(d.key))}
            className="mt-px flex text-dim hover:text-text"
            aria-label="Dismiss"
          >
            <X size={14} />
          </button>
        </div>
      ))}

      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <div className="text-[20px] font-semibold tracking-[-.015em]">Dashboard</div>
          <div className="mt-0.5 text-[13px] text-dim">Live investigation overview · {rangeLabel}</div>
        </div>
        <span className="mb-1 flex items-center gap-1.5 text-[11.5px] text-faint">
          <span className="h-1.5 w-1.5 animate-pulseDot rounded-full bg-success" />
          live
        </span>
      </div>

      {/* filter bar — TimeRangeFilter sits first, matching Alerts & Investigations */}
      <div className="mb-4 mt-3 flex flex-wrap items-center gap-2">
        <TimeRangeFilter
          value={range}
          custom={custom}
          onChange={(v, r) => {
            setRange(v);
            if (r) setCustom(r);
          }}
        />
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard
          label={`Events · ${range}`}
          value={a(m.events)}
          sub={`${a(m.groups)} detection groups`}
          color="#4b8bf5"
          icon={<Activity size={16} />}
        />
        <StatCard
          label="Awaiting investigation"
          value={a(m.verdict.untriaged)}
          sub={
            triage.data?.active
              ? `auto-investigate running · ${triage.data.hunted}/${triage.data.total}`
              : m.verdict.untriaged > 0
                ? 'auto-investigate idle'
                : 'queue clear'
          }
          color="#f5a623"
          icon={<ShieldAlert size={16} />}
        />
        <StatCard
          label={`True positives · ${range}`}
          value={a(m.verdict.true_positive)}
          sub={`${a(m.verdict.needs_more_info)} need more info`}
          color="#f04438"
          icon={<ShieldCheck size={16} />}
        />
        <StatCard
          label="Investigations running"
          value={i(running)}
          sub={triage.data?.active ? 'auto-investigate active' : `${i(rows.length)} total`}
          color="#2dd4bf"
          icon={<Crosshair size={16} />}
        />
      </div>

      {/* main grid */}
      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* left: outcomes + recent investigations */}
        <div className="flex flex-col gap-4 lg:col-span-2">
          <Panel>
            <PanelHeader
              icon={<Activity size={15} />}
              title="Investigation outcomes"
              right={<span className="text-[11.5px] text-faint">{a(m.groups)} groups</span>}
            />
            {alerts.loading && !alerts.data ? (
              <LoadingState />
            ) : alerts.error ? (
              <div className="p-3.5">
                <ErrorState error={alerts.error} />
              </div>
            ) : m.groups === 0 ? (
              <EmptyState>All quiet — no alerts in the last 24 hours.</EmptyState>
            ) : (
              <>
                <VerdictBreakdown verdict={m.verdict} total={m.groups} />
                <SeverityBreakdown sev={m.sev} total={m.groups} />
              </>
            )}
          </Panel>

          <Panel>
            <PanelHeader
              icon={<Crosshair size={15} />}
              title="Recent investigations"
              right={
                <button
                  onClick={() => navigate('/investigations')}
                  className="flex items-center gap-1 text-[12px] font-semibold text-accent hover:underline"
                >
                  View all
                  <ArrowUpRight size={13} />
                </button>
              }
            />
            {invs.loading && !invs.data ? (
              <LoadingState />
            ) : invs.error ? (
              <div className="p-3.5">
                <ErrorState error={invs.error} />
              </div>
            ) : recent.length === 0 ? (
              <EmptyState>No investigations yet — investigate an alert to start one.</EmptyState>
            ) : (
              <div>
                {recent.map((r) => {
                  const st = INV_STATUS[r.status];
                  return (
                    <button
                      key={r.id}
                      onClick={() => navigate(`/investigation/${r.id}`)}
                      className="flex w-full items-center gap-3 border-b border-border-faint px-[15px] py-2.5 text-left last:border-0 hover:bg-surface-3"
                    >
                      <KindBadge kind={r.kind} />
                      <span className="min-w-0 flex-[1.4] truncate text-[13px] font-medium">{r.name}</span>
                      {/* Flow mirrors the Investigations column fix: a real minimum
                          so two full IPv4s + the arrow fit, growing with spare width
                          while the rule name shrinks — the old fixed 150px clipped
                          the destination to a fragment. */}
                      <span className="hidden min-w-[230px] flex-1 overflow-hidden sm:block">
                        <FlowBadge src={r.host === '—' ? null : r.host} dst={r.dst} className="text-[11px]" />
                      </span>
                      <span className="flex-none">
                        {/* A running/awaiting/errored row has no verdict yet — the
                            status tag carries that. Showing an "untriaged" pill
                            beside "Investigating" reads as a contradiction. */}
                        {r.verdict !== 'untriaged' && <VerdictPill verdict={r.verdict} conf={r.conf} />}
                      </span>
                      <span className="hidden w-[120px] flex-none md:block">
                        <StatusTag color={st.color} label={st.label} pulse={st.pulse} />
                      </span>
                      <span className="hidden w-[64px] flex-none text-right font-mono text-[10.5px] text-faint lg:block">
                        {r.when}
                      </span>
                    </button>
                  );
                })}
              </div>
            )}
          </Panel>
        </div>

        {/* right: live activity + enrichment posture */}
        <div className="flex flex-col gap-4">
          <Panel>
            <PanelHeader icon={<Activity size={15} />} title="Auto-Investigate" />
            <AutoTriagePanel s={triage.data} loading={triage.loading && !triage.data} />
          </Panel>

          <Panel>
            <PanelHeader icon={<Database size={15} />} title="Enrichment posture" />
            <EnrichmentPanel
              sources={sources.data?.sources ?? []}
              error={sources.error}
              loading={sources.loading && !sources.data}
              onManage={() => navigate('/config#data-sources')}
            />
          </Panel>
        </div>
      </div>
    </div>
  );
}
