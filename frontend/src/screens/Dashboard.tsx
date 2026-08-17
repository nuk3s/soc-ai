import { Activity, ArrowUpRight, Crosshair, Database, Gauge, Server, ShieldAlert, ShieldCheck, WifiOff, X } from 'lucide-react';
import { type ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { KindBadge, PipelineErrorChip, StatusTag, VerdictPill } from '../components/Badges';
import { FlowBadge } from '../components/FlowBadge';
import { GeneralChatPanel } from '../components/GeneralChatPanel';
import { QualityCard } from '../components/QualityCard';
import { INV_STATUS } from '../lib/statusMeta';
import { Panel, PanelHeader } from '../components/Panel';
import { EmptyState, ErrorState, Freshness, LoadingState, StaleNotice } from '../components/States';
import { TimeRangeFilter, type CustomRange } from '../components/TimeRangeFilter';
import { demoBlocked, useDemo } from '../lib/demo';
import {
  type AlertQuery,
  type AutoTriageStatus,
  type DataSource,
  type Health,
  type HealthComponent,
  getAbout,
  getAlerts,
  getAutoTriageStatus,
  getDataSources,
  getDossierConflicts,
  getHealth,
  getDetectionTuningSummary,
  getQualityEvalStatus,
  getQualityTrend,
  listInvestigations,
  startQualityEval,
} from '../lib/api';
import { PIPELINE_ERRORS_URL, livePipelineErrors } from '../lib/investigationFilters';
import { formatSkipReasons } from '../lib/skipReasons';
import { rangeToSinceUntil } from '../lib/timeRange';
import { VERDICT } from '../lib/tokens';
import type { AlertGroup, InvestigationRow, Severity, Verdict } from '../lib/types';
import { useAsync } from '../lib/useAsync';

// Status presentation mirrors the Investigations screen so a verdict reads the

const SEV_META: Record<Severity, { label: string; color: string }> = {
  critical: { label: 'Critical', color: '#f04438' },
  high: { label: 'High', color: '#f79009' },
  medium: { label: 'Medium', color: '#eab308' },
  low: { label: 'Low', color: '#6b87a8' },
  info: { label: 'Info', color: '#8b949e' },
};
// info is intentionally omitted from the display order — the Dashboard breakdown
// shows the four actionable severities; info exists only to satisfy the ramp.
const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];
// Outcome order: most-actionable first.
const VERDICT_ORDER: Verdict[] = ['true_positive', 'needs_more_info', 'inconclusive', 'false_positive', 'untriaged'];

/**
 * Where a verdict tile lands. Four settled verdicts are investigation OUTCOMES,
 * so they open the Investigations list. 'untriaged' is not an outcome — it
 * counts alert GROUPS with no standing investigation, and such a group has no
 * investigation row to show (nor can it get one while it stays untriaged), so
 * /investigations?verdict=untriaged was empty by construction: the tile read
 * "1" and the destination read "no investigations" (prod 2026-08-07).
 *
 * It goes to /alerts instead — same endpoint (GET /alerts), same unit, so the
 * destination count is provably the tile's count — and it is where the operator
 * can start the investigation. Both carried params are load-bearing: Alerts
 * defaults to range=24h with hide_acked ON, while this screen counts the
 * operator's chosen range with acked groups INCLUDED. Drop either and a 7d
 * dashboard, or a fully-acked untriaged group, still lands on an empty list.
 */
function verdictDestination(v: Verdict, range: string, custom: CustomRange | null): string {
  if (v !== 'untriaged') return `/investigations?verdict=${v}`;
  const p = new URLSearchParams({ verdict: 'untriaged' });
  if (range === 'custom' && custom) {
    p.set('range', 'custom');
    p.set('from', custom.from);
    p.set('to', custom.to);
  } else {
    p.set('range', range);
  }
  p.set('hide_acked', 'false');
  return `/alerts?${p}`;
}

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
  const sev: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
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
    // A pipeline fallback (E1.2) reads verdict=needs_more_info in the DB but the
    // pipeline never reasoned to it (model truncation / gateway 5xx). Excluding
    // it from the NMI bucket keeps the "need more info" KPI honest — those are
    // infra failures to retry, counted separately as "pipeline errors" below.
    if (g.fallback) continue;
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

function VerdictBreakdown({
  verdict,
  total,
  onSelect,
}: {
  verdict: Record<Verdict, number>;
  total: number;
  onSelect: (v: Verdict) => void;
}) {
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
          <button
            key={v}
            type="button"
            onClick={() => onSelect(v)}
            // Untriaged has no investigations to show — say where it actually
            // goes, so the tooltip stops promising a list that can't exist.
            title={
              v === 'untriaged'
                ? 'Show these detections on the Alerts list — where you can start the investigation'
                : `Show ${VERDICT[v].label} investigations`
            }
            className="flex items-center justify-between gap-2 rounded-card border border-border-faint px-2.5 py-2 text-left transition-colors hover:border-accent"
          >
            <VerdictPill verdict={v} showConf={false} />
            <span
              className="font-mono text-[15px] font-semibold tabular-nums"
              style={{ color: VERDICT[v].color }}
            >
              {verdict[v] || 0}
            </span>
          </button>
        ))}
      </div>
    </div>
  );
}

function SeverityBreakdown({
  sev,
  total,
  onSelect,
}: {
  sev: Record<Severity, number>;
  total: number;
  onSelect: (s: Severity) => void;
}) {
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
            <button
              key={s}
              type="button"
              onClick={() => onSelect(s)}
              title={`Show ${meta.label ?? s} alerts`}
              className="flex items-center gap-3 rounded-card text-left transition-colors hover:bg-surface-2"
            >
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
            </button>
          );
        })}
      </div>
    </div>
  );
}

/** A sweep that could not read the grid, said plainly.
 *
 * The failure this exists to prevent: with the sensor blind, planning read
 * nothing, so this tile rendered "Last batch · 0 investigated" — an outage shown
 * to the analyst as a fully-drained queue, indistinguishable from a calm night,
 * for as long as the grid stayed down. Key off `degraded`, never off a zero:
 * "found nothing" and "could not look" are the same numbers. */
function AutoTriageDegradedNote({ s }: { s: AutoTriageStatus }) {
  const n = s.grid_errors?.length ?? 0;
  return (
    <div data-testid="autotriage-degraded" className="mb-2">
      <StatusTag color="#d29922" label="Sweep degraded" />
      <div className="mt-1 text-[12.5px] leading-[1.5] text-dim">
        The Security Onion grid could not be read
        {n ? ` for ${n} of this sweep's queries` : ''} — the backlog is unknown, not clear.
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
        {s.degraded && <AutoTriageDegradedNote s={s} />}
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
  // Read nothing at all: the note IS the whole answer, and "0 investigated"
  // underneath it would only re-offer the false all-clear in smaller type.
  if (s.degraded && s.total === 0) {
    return (
      <div className="px-[15px] py-3.5">
        <AutoTriageDegradedNote s={s} />
      </div>
    );
  }
  return (
    <div data-testid="autotriage-summary" className="px-[15px] py-3.5 text-[12.5px] leading-[1.5] text-dim">
      {/* Half-blind but productive: the sweep really did investigate what it
          could reach, so the note goes ABOVE that record rather than erasing
          it — under-claiming real work is its own kind of wrong report. */}
      {s.degraded && <AutoTriageDegradedNote s={s} />}
      {s.finished_at ? (
        <>
          Last batch ·{' '}
          <span className="font-semibold text-text">{s.hunted}</span> investigated
          {s.skipped ? `, ${s.skipped} skipped` : ''}
          {s.failed ? `, ${s.failed} failed` : ''}.
          {/* WHY were they skipped — the bare count told the analyst nothing. */}
          {s.skipped > 0 && formatSkipReasons(s.skipped_reasons) && (
            <div className="mt-1 font-mono text-[11px] text-faint">
              {formatSkipReasons(s.skipped_reasons)}
            </div>
          )}
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
  demo = false,
}: {
  sources: DataSource[];
  error: Error | null;
  loading: boolean;
  onManage: () => void;
  /** True on the public demo, where admin reads are 403 by design — degrade to a
   * neutral line rather than an admin-login prompt that can't be followed. */
  demo?: boolean;
}) {
  if (error) {
    return (
      <div className="px-[15px] py-3.5 text-[12px] leading-[1.5] text-faint">
        {demo
          ? 'Enrichment posture is an admin-only view — not shown in the demo.'
          : 'Sign in as an admin to view enrichment posture.'}
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
// the (secret-free) backend probe; `label` humanizes which upstream it is, and
// `headline` says which kind of trouble it is in.
interface DownDep {
  key: 'es' | 'llm';
  label: string;
  detail: string;
  headline: string;
}

// The probe's failure class, when it could name one. Optional on the wire: an
// unclassified failure omits it, and a server older than the field never sends
// it — both keep the generic headline below.
function depKind(c: HealthComponent): string {
  const kind = (c as HealthComponent & { kind?: unknown }).kind;
  return typeof kind === 'string' ? kind : '';
}

// The headline has to name the failure the probe actually met. This banner read
// "<dep> not reachable" for every one of them, including a grid answering 429
// directly above its own circuit-breaker detail line (dogfood 2026-08-14, D9): a
// 429 is a REPLY — the grid is up, shedding load, and the request will succeed
// once it recovers. "Not reachable" sends a 3am analyst to check connectivity,
// firewalls and whether the manager is down, none of which is the fault.
function depHeadline(label: string, kind: string): string {
  if (kind === 'overloaded') return `${label} overloaded — retryable`;
  if (kind === 'partial') return `${label} reads are incomplete`;
  return `${label} not reachable`;
}

// Which of the health components are unreachable — drives the connection banner.
// Only ES + LLM are treated as blocking dependencies (PCAP is optional/advisory).
function downDeps(h: Health | null): DownDep[] {
  if (!h) return [];
  const out: DownDep[] = [];
  const dep = (key: 'es' | 'llm', label: string, c: HealthComponent): DownDep => ({
    key,
    label,
    detail: c.detail,
    headline: depHeadline(label, depKind(c)),
  });
  if (!h.es.ok) out.push(dep('es', 'Security Onion (Elasticsearch)', h.es));
  if (!h.llm.ok) out.push(dep('llm', 'AI gateway (LLM)', h.llm));
  return out;
}

// ---- screen ----------------------------------------------------------------

export function Dashboard() {
  const navigate = useNavigate();
  const demo = useDemo(); // read-only demo: eval-run shows a note, never POST
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
  // The recent sample for the overview list, on the live 10s poll. The
  // pipeline-error KPI used to ride this same fetch (a second, 500-row page
  // every tick), but that number changes only a few times a day, so it now
  // polls on its own slow cadence below.
  const fetchDashboardInvestigations = async (): Promise<{
    recent: InvestigationRow[];
    active: boolean;
  }> => {
    const recent = await listInvestigations({ limit: 100 });
    return { recent: recent.rows, active: recent.active };
  };
  const invs = useAsync(fetchDashboardInvestigations, [], {
    refetchInterval: 10_000,
    pauseWhen: idleThrottle(invsActiveRef, invsTick, 3), // ~30s when idle
  });
  // Pipeline-error KPI, split onto its OWN 300s poll (like the tuning/dossier
  // nudges below): the count changes a few times a day, so refetching up to 500
  // rows on the 10s overview cadence was ~100 KB transferred-and-discarded every
  // idle poll — the class the review flagged (id dashboard-pipeline-kpi-500-rows).
  // The KPI must be THE SAME QUERY its deep link opens (?verdict=pipeline_error,
  // widened to 30d by the Investigations screen — rangeToSinceUntil('30d') is
  // that widening's own code path). It counts ROWS, not `total`, because its two
  // exclusions (dismissed, superseded) are per-row facts the SQL count does not
  // carry — so it can only count as far as one page (limit 500, the server cap)
  // reaches, and `total` tells it when it has run out of page.
  // TODO(backend): a server-side count_pipeline_errors applying the
  // errorDismissed/superseded exclusions in SQL would drop the 500-row page
  // entirely — a separate MR, out of scope for this frontend batch.
  const fetchPipelineErrors = async (): Promise<{ rows: InvestigationRow[]; total: number }> => {
    const pipeErr = await listInvestigations({
      verdict: ['pipeline_error'],
      ...rangeToSinceUntil('30d'),
      limit: 500,
    });
    return { rows: pipeErr.rows, total: pipeErr.total };
  };
  const pipeErr = useAsync(fetchPipelineErrors, [], { refetchInterval: 300_000 });
  const triageActiveRef = useRef(false);
  const triageTick = useRef(0);
  const triage = useAsync(getAutoTriageStatus, [], {
    refetchInterval: 5_000,
    pauseWhen: idleThrottle(triageActiveRef, triageTick, 6), // ~30s when idle
  });
  triageActiveRef.current = !!triage.data?.active;
  const sources = useAsync(getDataSources, [], { refetchInterval: 60_000 });
  // Pending mute recommendations — a slow-moving, ES-aggregation-backed count;
  // 5 min keeps the nudge fresh without hammering the tuning analysis. Errors
  // (incl. 403 for non-admin analysts) resolve to no data → panel hidden.
  const tuning = useAsync(getDetectionTuningSummary, [], { refetchInterval: 300_000 });
  // Open host-dossier disagreements — the same nudge shape as the tuning
  // summary above, and just as slow-moving (a conflict only accrues when a
  // sweep runs), so the same 5 min cadence. Ask for one row: `pending` is the
  // whole queue's count either way, and the rows themselves belong on /hosts.
  const dossier = useAsync(() => getDossierConflicts(1), [], { refetchInterval: 300_000 });
  const dossierPending = dossier.data?.pending ?? 0;
  // Quality trend — one point per NIGHTLY run, so a slow cadence is plenty;
  // 60s only exists to catch a manually-triggered eval-nightly without a
  // hard page refresh.
  const [qualityReload, setQualityReload] = useState(0);
  const quality = useAsync(getQualityTrend, [qualityReload], { refetchInterval: 60_000 });
  // "Run eval now" — kicks the same single-flight micro-eval the in-app
  // scheduler and the CLI use, then polls until the run lands so the new
  // trend point appears without a reload. Real LLM runs → minutes, so the
  // button reflects the in-flight state the whole time.
  const [evalRunning, setEvalRunning] = useState(false);
  const [evalNote, setEvalNote] = useState<string | null>(null);
  // False once the Dashboard unmounts. The run-eval poll loop checks it each
  // iteration so navigating away stops the 5s polling (and its setState on an
  // unmounted component) instead of running for up to 30 min.
  const evalAliveRef = useRef(true);
  useEffect(() => {
    evalAliveRef.current = true;
    return () => { evalAliveRef.current = false; };
  }, []);
  const runEvalNow = () => {
    if (evalRunning) return;
    const blocked = demoBlocked(demo);
    if (blocked) { setEvalNote(blocked); return; } // demo: no doomed write
    setEvalRunning(true);
    setEvalNote(null);
    startQualityEval()
      .then(async () => {
        // n real investigations at concurrency 1 — poll generously (30 min cap).
        for (let i = 0; i < 360; i++) {
          await new Promise((r) => setTimeout(r, 5_000));
          if (!evalAliveRef.current) return; // unmounted — stop polling
          const s = await getQualityEvalStatus().catch(() => null);
          if (s && !s.running) {
            if (s.last_exit_code !== 0 && s.last_detail) setEvalNote(s.last_detail);
            break;
          }
        }
        if (!evalAliveRef.current) return;
        setQualityReload((k) => k + 1);
      })
      .catch((e) => { if (evalAliveRef.current) setEvalNote(e instanceof Error ? e.message : 'could not start the eval'); })
      .finally(() => { if (evalAliveRef.current) setEvalRunning(false); });
  };
  // Upstream reachability — polled on mount + every 30s so a down dependency
  // (ES / gateway) surfaces as a banner instead of a wall of empty widgets.
  // Errors resolve to null (health data is null) → no banner, so a transient
  // /health hiccup can't itself raise a false "not connected" alarm.
  const health = useAsync(getHealth, [], { refetchInterval: 30_000 });
  // The Dashboard assistant's kill switch, read from /about (one mount GET; a
  // flip takes effect on the next load). Gating on a SETTLED probe is the point:
  // rendering the panel optimistically would fire a GET /chat that 403s on
  // exactly the deployments that switched the assistant off. A failed probe
  // fails OPEN — the setting defaults on, so an /about hiccup must not delete
  // the feature.
  const about = useAsync(getAbout, []);
  const chatEnabled =
    (!!about.data || !!about.error) && about.data?.general_chat_enabled !== false;
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
  const rows = useMemo(() => invs.data?.recent ?? [], [invs.data]);
  // Server truth over the whole store, not the fetched sample: a run outside
  // the newest 100 must still keep the fast poll cadence alive.
  invsActiveRef.current = invs.data?.active ?? false;
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
  // Pipeline errors (E1.2): runs whose needs_more_info is a failure fallback
  // (model truncation / gateway 5xx), excluded from the NMI KPI above. Counted
  // over the DEEP LINK'S OWN QUERY (fetchDashboardInvestigations), so the tile
  // counts the same query the list runs; livePipelineErrors then applies the
  // KPI's documented exclusions — dismissed errors (the Dismiss button's whole
  // effect) and superseded runs (re-running IS the fix). The clicked list still
  // SHOWS those excluded rows, as history; the tile counts what needs acting on.
  const pipelineErrorRows = pipeErr.data?.rows ?? [];
  const pipelineErrors = livePipelineErrors(pipelineErrorRows).length;
  // Those exclusions are why the tile counts rows rather than reading `total`,
  // and why it can only count as far as the page reaches. `total` is the whole
  // match set, so total > rows.length means the server truncated and the count
  // below is a FLOOR — rendered "N+" rather than left to read as exact. A
  // multi-hour gateway outage against auto-triage puts hundreds of fallbacks in
  // a 30-day window, so 500 is reachable, and an unmarked 500 beside a list
  // header reading "1–500 of 812" is the same tile-vs-list disagreement this
  // KPI was just moved onto the shared query to end.
  const pipelineErrorsTruncated = (pipeErr.data?.total ?? 0) > pipelineErrorRows.length;

  const a = (n: number): string => (alerts.data ? n.toLocaleString() : alerts.error ? '—' : '…');
  const i = (n: number): string => (invs.data ? n.toLocaleString() : invs.error ? '—' : '…');
  // Is this KPI row still showing counts from a grid that has since gone dark?
  // A failed BACKGROUND poll keeps the last-good data on screen and never sets
  // `error` — deliberate, so a blip doesn't blank a working console — which
  // means a grid that dies with the tab open leaves these numbers frozen with
  // nothing dating them (review of batch A, 2026-08-14). Two consecutive misses
  // is the house line between a blip and a surface that has stopped being live;
  // Hosts, Hunts, Notifications and Investigations all mark stale at the same
  // count, so the reader learns one marker rather than five.
  //
  // Keyed on the ALERTS read, not on `health.es`: a degraded probe alongside a
  // successful alerts read means that read proved itself (the client raises on
  // a partial one), and disclaiming a count the grid did answer is the
  // over-correction — the screen would go permanently uncertain on a grid with
  // one chronically red shard nowhere near these queries.
  const alertsStale = alerts.failCount >= 2;

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
            <div className="font-semibold text-text-2">{d.headline}</div>
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
          <div className="flex items-baseline gap-3">
            <div className="text-[20px] font-semibold tracking-[-.015em]">Dashboard</div>
            <Freshness at={alerts.lastUpdated} />
          </div>
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

      {/* The counts below are the last ones the grid answered, and both ways of
          losing the next read leave them frozen with nothing on the screen
          dating them: a poll loop that has stopped landing, and a refresh the
          analyst asked for and did not get (useAsync keeps prior data through a
          foreground failure, deliberately — an error arriving after the data
          must not take it away, which on a range change means counts read for
          the last 24h sitting under a header that now says 1h). Same marker the
          list screens use, so it says WHEN the numbers are from and offers the
          retry, without blanking a row that is still the best account of the
          network anyone has. */}
      {alertsStale ? (
        <StaleNotice since={alerts.lastUpdated} onRefresh={alerts.refetch} className="mb-3" />
      ) : alerts.error && alerts.data ? (
        <StaleNotice
          since={alerts.lastUpdated}
          onRefresh={alerts.refetch}
          reason="refresh-failed"
          retrying
          className="mb-3"
        />
      ) : null}

      {/* KPI row — the landing screen's headline. It used to open below the
          full-width chat composer, which took the largest above-the-fold band
          and pushed both the tiles and the outcomes chart under it (dogfood
          B2b, 2026-08-11): the assistant outranking the answer the analyst
          opened the app for. The chat now leads the right-hand rail. */}
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
            // The failed-read branch comes FIRST, ahead of every count-derived
            // caption. `untriaged` is 0 after a failed fetch exactly as it is on
            // a drained queue, so the caption fell through to "queue clear"
            // under an honest em-dash value (dogfood 2026-08-14, D3): "—" says
            // unknown, "queue clear" says safe, and during an outage those are
            // opposite statements. The rule is the one the Auto-Investigate tile
            // already follows thirty lines up — key off degraded, never off a
            // zero — and it is only "clear" when a successful read returned none.
            //
            // A grid that dies with the tab open takes the second branch: the
            // poll loop keeps the last-good count on screen and never sets
            // `error`, so the caption went on calling a queue clear that was
            // last read minutes ago, under a red banner saying the grid was
            // down. Last-known is not current, and "clear" is a claim about now.
            alerts.error
              ? 'backlog unknown — the grid read failed'
              : alertsStale
                ? 'backlog unknown — the grid stopped answering'
                : triage.data?.active
                  ? `auto-investigate running · ${triage.data.hunted}/${triage.data.total}`
                  : !alerts.data
                    ? 'checking the queue…'
                    : m.verdict.untriaged > 0
                      ? (
                          // This used to read "auto-investigate idle", which blamed
                          // the sweep and sent the operator to the scheduler config.
                          // The sweep is not necessarily idle — the group may simply
                          // be outside its queue (below the severity floor, already
                          // acked, schedule off), and this screen cannot tell which.
                          // So it makes no claim about the sweep at all and offers
                          // the one thing it knows: where to triage it by hand.
                          <button
                            onClick={() => navigate(verdictDestination('untriaged', range, custom))}
                            title="Show these detections on the Alerts list"
                            className="cursor-pointer text-left underline decoration-dim/50 underline-offset-2 hover:decoration-dim"
                          >
                            triage from Alerts
                          </button>
                        )
                      : 'queue clear'
          }
          color="#f5a623"
          icon={<ShieldAlert size={16} />}
        />
        <StatCard
          label={`True positives · ${range}`}
          value={a(m.verdict.true_positive)}
          sub={
            <>
              {a(m.verdict.needs_more_info)} need more info
              {pipelineErrors > 0 && (
                <>
                  {' · '}
                  <button
                    onClick={() => navigate(PIPELINE_ERRORS_URL)}
                    title={
                      pipelineErrorsTruncated
                        ? `at least ${pipelineErrors.toLocaleString()} runs to retry — more matched than one page holds, so open the list for the full set`
                        : 'Show these runs on the Investigations list — open one to see the error and dismiss it'
                    }
                    className="cursor-pointer underline decoration-[rgba(252,165,165,.45)] underline-offset-2 hover:decoration-[#fca5a5]"
                    style={{ color: '#fca5a5' }}
                  >
                    {pipelineErrors.toLocaleString()}
                    {pipelineErrorsTruncated ? '+' : ''} pipeline error
                    {pipelineErrors === 1 && !pipelineErrorsTruncated ? '' : 's'}
                  </button>
                </>
              )}
            </>
          }
          color={m.verdict.true_positive > 0 ? '#f04438' : '#8b949e'}
          icon={<ShieldCheck size={16} />}
        />
        <StatCard
          label="Investigations running"
          value={i(running)}
          sub={triage.data?.active ? 'auto-investigate active' : `of ${i(rows.length)} recent investigations`}
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
                <ErrorState error={alerts.error} onRetry={alerts.refetch} label="the dashboard" />
              </div>
            ) : m.groups === 0 ? (
              <EmptyState>All quiet — no alerts in the last 24 hours.</EmptyState>
            ) : (
              <>
                <VerdictBreakdown
                  verdict={m.verdict}
                  total={m.groups}
                  onSelect={(v) => navigate(verdictDestination(v, range, custom))}
                />
                <SeverityBreakdown
                  sev={m.sev}
                  total={m.groups}
                  onSelect={(sv) => navigate(`/alerts?sev=${sv}`)}
                />
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
                      {/* Detection name + flow share one slot. Below `lg` they
                          STACK — name on its own line, endpoints under it —
                          because side by side they cannot both fit: the flow
                          carries a 230px floor (two full IPv4s + the arrow, the
                          Investigations column fix) and at 900px that left the
                          name about one character wide, rendering
                          "SURICATA │ E… │ 192.0.2.70 → 10.0.0.40" (dogfood,
                          2026-08-12) — a row that names no detection. Stacking
                          is what lets the endpoints yield the WIDTH without
                          being dropped: both stay legible, the row just costs a
                          second line at narrow sizes. At `lg`+ it is a row
                          again with the same 1.4 : 1 split as before (the
                          wrapper's 2.4 is their sum), so the wide layout is
                          byte-for-byte the one that shipped. */}
                      <span className="flex min-w-0 flex-[2.4] flex-col gap-0.5 lg:flex-row lg:items-center lg:gap-3">
                        <span
                          title={r.name}
                          className="min-w-0 truncate text-[13px] font-medium lg:flex-[1.4]"
                        >
                          {r.name}
                        </span>
                        {/* Still dropped below `sm`, as before: on a phone-width
                            column the second line is itself too narrow to hold
                            two IPv4s, and the name wants the whole row. */}
                        <span className="hidden min-w-0 overflow-hidden sm:block lg:min-w-[230px] lg:flex-1">
                          <FlowBadge src={r.host === '—' ? null : r.host} dst={r.dst} className="text-[11px]" />
                        </span>
                      </span>
                      <span className="flex-none">
                        {/* A running/awaiting/errored row has no verdict yet — the
                            status tag carries that. Showing an "untriaged" pill
                            beside "Investigating" reads as a contradiction. A
                            fallback (E1.2) replaces the amber NMI pill with the
                            pipeline-error chip, matching the Investigations list. */}
                        {r.fallback ? (
                          <PipelineErrorChip />
                        ) : (
                          r.verdict !== 'untriaged' && <VerdictPill verdict={r.verdict} conf={r.conf} />
                        )}
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

        {/* right: the assistant, then live activity + enrichment posture.
            Below `lg` the grid collapses to one column and source order IS
            reading order, so this rail reads AFTER the outcomes chart and the
            recent-investigations list. That is deliberate. An earlier pass gave
            the rail `order-first` to keep the chat near the top, but that
            promoted the whole rail — chat, Auto-Investigate, quality, posture —
            above the analyst's numbers, so at 900px the outcomes chart opened
            below the fold (dogfood, 2026-08-12): the same defect the demotion
            was meant to fix, one panel further down. The chat is not buried by
            reading in source order — it is the very next thing after the two
            number surfaces, and those two are the reason the screen exists. At
            `lg`+ the columns sit side by side and order is moot. */}
        <div className="flex flex-col gap-4">
          {/* Ask soc-ai — the Dashboard assistant. This slot used to hold a box
              that prefilled the Hunt Console's objective and navigated, which
              turned every question into a multi-minute background job ("a cheap
              copy-paste of the hunt page", owner 2026-08-06). It now ANSWERS
              here, and proposes a hunt — for the analyst to confirm — when a
              question needs a sweep. Rail-width and second in the reading order
              rather than full-width and first: the analyst's numbers lead, and
              the box is still the first thing in the column they reach for. */}
          {chatEnabled && <GeneralChatPanel />}

          <Panel>
            <PanelHeader icon={<Activity size={15} />} title="Auto-Investigate" />
            <AutoTriagePanel s={triage.data} loading={triage.loading && !triage.data} />
          </Panel>

          <Panel>
            <PanelHeader
              icon={<Gauge size={15} />}
              title="Verdict quality"
              right={
                // Hidden when the trend itself failed (non-admin session) —
                // the run endpoint is admin-gated like the trend.
                !quality.error ? (
                  <button
                    onClick={runEvalNow}
                    disabled={evalRunning}
                    title="Run the quality micro-eval now — the same run the nightly schedule performs (real investigations; takes minutes)"
                    className="flex items-center gap-1 text-[12px] font-semibold text-accent hover:underline disabled:opacity-60"
                  >
                    {evalRunning ? 'Evaluating…' : 'Run now'}
                  </button>
                ) : undefined
              }
            />
            <QualityCard
              points={quality.data?.points ?? []}
              error={quality.error}
              loading={quality.loading && !quality.data}
              demo={demo}
            />
            {evalNote && (
              <div className="px-[15px] pb-2.5 text-[12px]" style={{ color: '#f5a623' }}>
                {evalNote}
              </div>
            )}
          </Panel>

          <Panel>
            <PanelHeader icon={<Database size={15} />} title="Enrichment posture" />
            <EnrichmentPanel
              sources={sources.data?.sources ?? []}
              error={sources.error}
              loading={sources.loading && !sources.data}
              onManage={() => navigate('/config#data-sources')}
              demo={demo}
            />
          </Panel>

          {/* Detection-tuning nudge: pending mute recommendations lived unseen in
              Config while auto-investigate kept paying for runs on the same
              benign rules (dogfood 2026-07-15). Admin-gated endpoint — a 403 or
              zero pending simply hides the panel. */}
          {(tuning.data?.pending ?? 0) > 0 && (
            <Panel>
              <PanelHeader icon={<Gauge size={15} />} title="Detection tuning" />
              <div className="flex items-center justify-between gap-3 px-[15px] py-3">
                <div className="text-[13px] text-text-2">
                  <span className="font-semibold" style={{ color: '#f5a623' }}>
                    {tuning.data!.pending} mute suggestion{tuning.data!.pending === 1 ? '' : 's'}
                  </span>{' '}
                  pending — noisy rules with zero true positives keep consuming
                  investigations.
                </div>
                <button
                  onClick={() => navigate('/config#detection-tuning')}
                  className="flex flex-none items-center gap-1 text-[12px] font-semibold text-accent hover:underline"
                >
                  Review
                  <ArrowUpRight size={13} />
                </button>
              </div>
            </Panel>
          )}

          {/* Host-dossier nudge: the sweep keeps concluding something other than
              what an operator declared, and only the operator can settle it. The
              link seeds ?conflicts=1 so the queue arrives OPEN — the host
              table is not what this count is about. Admin-gated endpoint, so a
              403 or an empty queue simply hides the panel. */}
          {dossierPending > 0 && (
            <Panel>
              <PanelHeader icon={<Server size={15} />} title="Host dossier" />
              <div className="flex items-center justify-between gap-3 px-[15px] py-3">
                <div className="text-[13px] text-text-2">
                  <span className="font-semibold" style={{ color: '#f5a623' }}>
                    {dossierPending} disagreement{dossierPending === 1 ? '' : 's'}
                  </span>{' '}
                  need{dossierPending === 1 ? 's' : ''} review — the sweep keeps observing something
                  other than what was declared.
                </div>
                <button
                  onClick={() => navigate('/hosts?conflicts=1')}
                  className="flex flex-none items-center gap-1 text-[12px] font-semibold text-accent hover:underline"
                >
                  Review
                  <ArrowUpRight size={13} />
                </button>
              </div>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
