import { ArrowUpRight, Check, ChevronRight, Filter, Sparkles, X, Zap } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { KindBadge, PipelineErrorChip, SeverityTag, VerdictPill } from '../components/Badges';
import { FlowBadge } from '../components/FlowBadge';
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
  cancelHunt,
  escalateGroup,
  getAlertGroupEvents,
  getAlerts,
  getAutoTriageStatus,
  getInvestigation,
  getMe,
  getRepresentative,
  startAutoTriage,
  startHunt,
  stopAutoTriage,
} from '../lib/api';
import { useAsync } from '../lib/useAsync';
import { type SortDir, useSort } from '../lib/useSort';
import type {
  AlertEvent,
  AlertGroup,
  Investigation as Inv,
  Severity,
  TriageState,
} from '../lib/types';
import { useShell } from '../shell/ShellContext';
import { Investigation } from './Investigation';

type ViewId = 'mine' | 'inreview' | 'critical' | 'decision' | 'all';
type Density = 'comfortable' | 'compact';
type SortKey = 'count' | 'detection' | 'sev' | 'verdict' | 'conf' | 'latest';

// checkbox  DETECTION (name + flow, subtle count)  sev  verdict  conf  owner  last-seen  actions
// The GROUP row is intentionally LEAN — the per-alert detail (each event's own
// timestamp + the time of the investigation it ran/inherited from) lives on the
// expanded event rows, where an analyst actually needs it. The old dedicated
// "Fired" column and the copyable short-id chip were removed as noise; the fire
// count is now a subtle inline chip and `actions` is wide enough that the primary
// button never overlaps the "Last seen" column.
const GRID = '28px minmax(240px,1fr) 104px 136px 48px 40px 100px 128px';

// Per-alert (expanded) event row: checkbox | alert time (abs+rel) | sev |
// src→dst:port | host | verdict provenance (+ when) | investigate. Each row now
// carries the alert's OWN timestamp AND the investigation's timestamp.
const EVENT_GRID = '16px 132px 56px minmax(150px,1fr) 116px 172px 92px';

// Page size for an expanded group's events ("Load more" pulls one page at a time).
const EVENTS_PAGE_SIZE = 50;

// Auto-triage skip-reason codes (webui/autotriage.py planner) → friendly text.
// Unknown codes fall through to the raw code so a new backend reason is surfaced
// rather than silently dropped.
const TRIAGE_SKIP_REASONS: Record<string, string> = {
  already_triaged: 'already triaged',
  running: 'in-flight',
  inherited: 'covered by a prior verdict',
  no_ip: 'no source/dest IP',
  not_found: 'not found',
};

// " (8 already triaged, 3 in-flight, 1 no source/dest IP)" — the per-reason
// breakdown of a batch's skip count, or "" when the backend didn't carry one.
function triageSkipDetail(s: AutoTriageStatus): string {
  const reasons = s.skipped_reasons;
  if (!reasons) return '';
  const parts = Object.entries(reasons)
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1])
    .map(([code, n]) => `${n} ${TRIAGE_SKIP_REASONS[code] ?? code}`);
  return parts.length ? ` (${parts.join(', ')})` : '';
}

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
// inconclusive sorts with needs_more_info: both are terminal non-committed
// verdicts that still need an analyst decision.
const VERDICT_RANK: Record<string, number> = { true_positive: 6, false_positive: 5, needs_more_info: 4, inconclusive: 3, untriaged: 1 };
// A row that is actively being investigated has no verdict yet (still "untriaged"
// in the DB) but should not interleave with genuinely-untriaged rows when sorting
// by verdict — rank it just above untriaged so triaging rows cluster together.
const TRIAGING_RANK = 2;
const verdictRank = (g: AlertGroup): number => (g.triaging ? TRIAGING_RANK : VERDICT_RANK[g.verdict] ?? 0);

/** Derive 1-2 char avatar initials from a username or token:<name> string. */
function toInitials(owner: string): string {
  const name = owner.startsWith('token:') ? owner.slice(6) : owner;
  // Split on dot, underscore, hyphen, or space
  const parts = name.split(/[._\-\s]+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return name.slice(0, 2).toUpperCase();
}

// Triage-state chip styling (E2.3). "unassigned" is the ABSENCE of an owner
// (state null) — rendered faint; the three real states carry their own colour:
// owned=accent, in_review=amber, done=green.
const STATE_LABEL: Record<TriageState, string> = {
  owned: 'Owned',
  in_review: 'In review',
  done: 'Done',
};
const STATE_CLS: Record<TriageState, string> = {
  owned: 'border-accent/40 bg-accent/10 text-accent',
  in_review: 'border-amber-400/40 bg-amber-400/10 text-amber-300',
  done: 'border-emerald-400/40 bg-emerald-400/10 text-emerald-300',
};

/** A compact triage-state chip. `null` → the faint "Unassigned" pill. */
function StateChip({ state }: { state?: TriageState | null }) {
  if (!state) {
    return (
      <span className="inline-flex items-center rounded-pill border border-border-strong px-1.5 py-px text-[9.5px] font-semibold uppercase tracking-wide text-faint">
        Unassigned
      </span>
    );
  }
  return (
    <span
      className={`inline-flex items-center rounded-pill border px-1.5 py-px text-[9.5px] font-semibold uppercase tracking-wide ${STATE_CLS[state]}`}
    >
      {STATE_LABEL[state]}
    </span>
  );
}

/** A compact, glanceable clock time for an event row ("14:23:05"). The full
 * date-time is exposed via the cell's title. */
function clockTime(iso?: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

/** The verdict-provenance chip for a single event row: whether this exact event
 * was investigated (green) or inherited a verdict (grey), AND WHEN that
 * investigation ran. Clickable when it has an investigation to open. Renders a
 * faint dash when the event has no verdict yet. `investigated` takes strict
 * priority over `inheritedReason` so a re-run's fresh direct verdict never shows
 * the stale "inherited" chip (dogfood #3). */
function ProvenanceBadge({ ev, onOpen }: { ev: AlertEvent; onOpen: (id: string) => void }) {
  const when = ev.investigatedAt
    ? `${ev.investigatedAt} ago`
    : inheritedWhen(ev.inheritedReason) ?? null;
  const kind = ev.investigated ? 'investigated' : ev.inheritedReason ? 'inherited' : null;
  if (!kind) return <span className="text-faint">—</span>;
  const green = kind === 'investigated';
  const label = when ? `${kind} ${when}` : kind;
  const tone = green
    ? { borderColor: 'rgba(34,197,94,.35)', background: 'rgba(34,197,94,.08)', color: '#4ade80' }
    : { borderColor: 'rgba(148,163,184,.25)', background: 'rgba(148,163,184,.07)', color: '#94a3b8' };
  const title = ev.inheritedReason ?? 'This exact event was investigated — open the report';
  const cls =
    'inline-flex min-w-0 max-w-full items-center gap-0.5 truncate rounded-chip border px-[6px] py-[2px] font-mono text-[9.5px] font-semibold';
  if (ev.invId) {
    return (
      <button
        type="button"
        onClick={(e) => { e.stopPropagation(); onOpen(ev.invId!); }}
        title={title}
        className={`${cls} hover:brightness-125`}
        style={tone}
      >
        <span className="truncate">{label}</span>
        <ArrowUpRight size={9} strokeWidth={2.5} className="flex-shrink-0" />
      </button>
    );
  }
  return (
    <span title={title} className={`${cls} cursor-help`} style={tone}>
      <span className="truncate">{label}</span>
    </span>
  );
}

/** Secondary, subtle red hint next to a group's standing verdict chip (E2.1):
 * the last RE-RUN of this rule crashed (error/cancelled/interrupted) or fell
 * back, while the real verdict still stands. Answers the "stayed at Needs Info"
 * mystery — the verdict chip stays primary; this is a quiet warning. */
function LastRetryHint({ attempt }: { attempt: NonNullable<AlertGroup['lastAttempt']> }) {
  // "fallback" reads as "failed" for the operator; the other statuses name the
  // terminal state directly ("error"/"cancelled"/"interrupted").
  const label = attempt.status === 'fallback' ? 'failed' : attempt.status;
  return (
    <span
      title={`The last re-run of this detection ${attempt.status === 'fallback' ? 'failed (pipeline fallback)' : `ended in ${attempt.status}`} ${attempt.ago} ago — the standing verdict is from an earlier run. Retry it.`}
      className="flex min-w-0 items-center truncate font-mono text-[10.5px] font-semibold text-danger"
    >
      <span className="truncate">· last retry {label} {attempt.ago} ago</span>
    </span>
  );
}

/** Format an ISO timestamp as a human-readable absolute time for a tooltip.
 * Falls back to the raw string if it isn't parseable. */
function absTime(iso?: string): string | undefined {
  if (!iso) return undefined;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

/** Pull a compact "12m ago" fragment out of the enriched inheritedReason
 * ("Inherited — investigated 12m ago on X→Y (investigation …)") for the inline
 * hint. Returns null when no relative-time fragment is present. */
function inheritedWhen(reason?: string | null): string | null {
  if (!reason) return null;
  const m = reason.match(/(\d+\s*[smhdw](?:in|ec|our|ay)?s?)\s+ago/i);
  return m ? `${m[1]} ago` : null;
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
      result = verdictRank(a) - verdictRank(b);
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

function matchView(g: AlertGroup, view: ViewId, me: string): boolean {
  switch (view) {
    case 'mine':
      // "Mine" = owned by the current user (E2.3). Falls back to "any owner"
      // when the current user is unknown (getMe failed) so the tab still filters.
      return me ? g.owner === me : !!g.owner && g.owner !== '';
    case 'inreview':
      return g.state === 'in_review';
    case 'critical':
      return g.sev === 'critical';
    case 'decision':
      // Non-committed verdicts: NMI + inconclusive (terminal hedges) + untriaged.
      return g.verdict === 'needs_more_info' || g.verdict === 'inconclusive' || g.verdict === 'untriaged';
    default:
      return true;
  }
}

export function Alerts() {
  const { triageNonce, paletteOpen } = useShell();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [reloadKey, setReloadKey] = useState(0);
  const [filterTime, setFilterTime] = useState('24h');
  const [customRange, setCustomRange] = useState<CustomRange | null>(null);
  const [filterSevs, setFilterSevs] = useState<string[]>([]); // [] = all
  const [filterVerdicts, setFilterVerdicts] = useState<string[]>([]); // [] = all
  const [hideAcked, setHideAcked] = useState(true);
  // Current username — the "Mine" filter matches g.owner against it, and the
  // row actions use it to decide whose assignment they are toggling. Empty until
  // getMe resolves (falls back to "any owner" for the filter until then).
  const [me, setMe] = useState('');
  useEffect(() => {
    getMe()
      .then((m) => setMe(m.username))
      .catch(() => {
        /* keep empty — the "Mine" filter degrades to "any owner" */
      });
  }, []);

  const alertQuery: AlertQuery = {
    ...(filterTime === 'custom' && customRange
      ? { range: 'custom', from: customRange.from, to: customRange.to }
      : { range: filterTime }),
    hideAcked: hideAcked || undefined,
  };
  const view = (searchParams.get('view') as ViewId) || 'all';
  const drawerId = searchParams.get('drawer');
  const { data: groups, loading, error } = useAsync(
    () => getAlerts(alertQuery),
    [filterTime, customRange?.from, customRange?.to, hideAcked, reloadKey],
    {
      refetchInterval: 10000, // keep the grid + verdict/status badges live without a reload
      // Pause the 10s ES aggregation while an investigation drawer is open, so
      // the grid doesn't churn under the analyst; resumes on close.
      pauseWhen: () => !!drawerId,
    }
  );

  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  // Events live behind a lazy fetch — pulled the first time a group is expanded.
  const [groupEvents, setGroupEvents] = useState<Record<string, AlertEvent[]>>({});
  const [eventsLoading, setEventsLoading] = useState<Record<string, boolean>>({});
  // Per-group "Load more" state: whether another page likely exists, and whether
  // a follow-up page is currently fetching.
  const [eventsMore, setEventsMore] = useState<Record<string, boolean>>({});
  const [eventsLoadingMore, setEventsLoadingMore] = useState<Record<string, boolean>>({});
  const [starting, setStarting] = useState<AlertGroup | null>(null);
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [selEvents, setSelEvents] = useState<Record<string, boolean>>({});
  const [ackingEvents, setAckingEvents] = useState(false);
  const [density, setDensity] = useState<Density>('comfortable');

  // ---- keyboard-first triage (E2.5) --------------------------------------
  // Index of the keyboard-focused group row within the visible list; -1 = none.
  // Vim-style j/k (+ arrows) move it, o/Enter open, a/e/i act, x selects.
  const [focusedIndex, setFocusedIndex] = useState(-1);
  const [keyHelpOpen, setKeyHelpOpen] = useState(false);
  // Per-row element refs so the focused row can be scrolled into view as focus
  // moves. Keyed by group id; stale keys are harmless (a WeakMap-ish plain map).
  const rowRefs = useRef<Record<string, HTMLDivElement | null>>({});
  // Shared sort mechanics; clicking a new column here starts it descending.
  const { sort, toggleSort, caret, headerCls: hdrCls } = useSort<SortKey>(
    { key: 'sev', dir: 'desc' },
    'desc',
  );

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
  // When the backend carries a per-reason skip breakdown (E2.2), spell it out
  // ("12 skipped: 8 already triaged, 3 in-flight, 1 no source/dest IP") instead
  // of a bare count so an operator can see WHY work was skipped.
  const triageSummary = (s: AutoTriageStatus): string => {
    const parts = [`${s.hunted} investigated`];
    if (s.skipped) parts.push(`${s.skipped} skipped${triageSkipDetail(s)}`);
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
        .catch(() => finish('Bulk Investigate status check failed'));
    };
    startAutoTriage(alertIds?.length ? { alertIds } : { minSeverity })
      .then((s) => {
        if (!s.active) {
          // nothing to hunt, or the batch already wrapped up — show why
          finish(s.note || (s.total ? triageSummary(s) : 'Nothing to investigate'));
          return;
        }
        // Surface the backend's start note up-front (e.g. "triaging 6 selected
        // (2 already triaged)") so a partial selection isn't a mystery.
        if (s.note) showTriageMsg(s.note);
        // Refresh the list ~1.5 s after start so rows flip to "Triaging…"
        // before investigations have completed (the finish() bump handles verdicts).
        setTimeout(() => setReloadKey((k) => k + 1), 1500);
        triageTimer.current = setInterval(poll, 2000);
      })
      .catch(() => {
        setTriaging(false);
        showTriageMsg('Bulk Investigate failed to start');
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

  // Reset row expansion + cached events when the query that produced them
  // changes. hideAcked is part of alertQuery, so a per-group event page fetched
  // with the old value is stale under the new filter — clear it too, else an
  // expanded group shows acknowledged events after "Hide acknowledged" is on.
  useEffect(() => {
    setExpanded({});
    setGroupEvents({});
    setEventsLoading({});
    setEventsMore({});
    setEventsLoadingMore({});
  }, [filterTime, customRange?.from, customRange?.to, hideAcked]);

  const setView = (v: ViewId) => {
    searchParams.set('view', v);
    setSearchParams(searchParams, { replace: true });
  };
  const openDrawer = (id: string) => {
    setStarting(null);
    searchParams.set('drawer', id);
    setSearchParams(searchParams);
  };
  // Stable so AlertDrawer's poll-timer effect (dep: onComplete) doesn't reset
  // every parent re-render.
  const onDrawerComplete = useCallback(() => setReloadKey((k) => k + 1), []);
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
      .catch((err: unknown) => {
        setStarting(null);
        // e.g. 409 hunt_in_progress — tell the operator a hunt is already
        // running for this alert instead of silently doing nothing.
        showTriageMsg(err instanceof Error ? err.message : 'Could not start the investigation');
      });
  };

  // Investigate ONE exact event from an expanded group row (not the group's
  // representative). Opens the existing investigation when this event already
  // has one; otherwise starts a hunt on this event's own es_id. Falls back to
  // the group only when the event carries no id.
  const huntEvent = (g: AlertGroup, ev: AlertEvent) => {
    if (ev.invId) {
      openDrawer(ev.invId);
      return;
    }
    if (!ev.id) {
      hunt(g);
      return;
    }
    setStarting(g);
    startHunt(ev.id)
      .then((invId) => openDrawer(invId))
      .catch((err: unknown) => {
        setStarting(null);
        showTriageMsg(err instanceof Error ? err.message : 'Could not start the investigation');
      });
  };

  // Hunt the most-representative event in a collapsed group (most-common-flow
  // selection). Calls /alerts/representative, then /hunt, then opens the drawer.
  // Shows the selection rationale in a dismissible strip so the operator knows
  // which event was chosen and why.
  const huntGroup = (g: AlertGroup) => {
    setHuntGroupPending((s) => ({ ...s, [g.id]: true }));
    getRepresentative(g, alertQuery)
      .then((rep) => {
        showHuntReason(`Investigating representative: ${rep.reason}`);
        setStarting(g);
        return startHunt(rep.alert_id);
      })
      .then((invId) => openDrawer(invId))
      .catch(() => setStarting(null))
      .finally(() => setHuntGroupPending((s) => ({ ...s, [g.id]: false })));
  };

  // Acknowledge a single group (keyboard `a`) — reuses the same ackGroup write
  // path + ack strip as the bulk bar, scoped to one detection.
  const ackOneGroup = (g: AlertGroup) => {
    setAckingCount(1);
    setAckingAlertTotal(g.count || 0);
    setAcking(true);
    ackGroup(g, alertQuery)
      .then((r) => {
        const parts = [`Acknowledged ${r.acked} alert${r.acked !== 1 ? 's' : ''} in ${g.name}`];
        if (r.failed) parts.push(`${r.failed} event${r.failed !== 1 ? 's' : ''} failed`);
        showAckMsg(parts.join(' · ') + (r.capped ? ' — group exceeded the 200-event cap, press a again to finish.' : ''));
        setReloadKey((k) => k + 1);
      })
      .catch(() => showAckMsg(`Failed to acknowledge ${g.name}`))
      .finally(() => setAcking(false));
  };

  // Escalate a single group to a Security Onion case (keyboard `e`) — reuses
  // the escalateGroup write path; result surfaces in the ack strip.
  const escalateOneGroup = (g: AlertGroup) => {
    escalateGroup(g, alertQuery)
      .then((r) => {
        showAckMsg(`Escalated ${r.escalated} of ${r.total} event${r.total !== 1 ? 's' : ''} in ${g.name} to a case`);
        setReloadKey((k) => k + 1);
      })
      .catch(() => showAckMsg(`Failed to escalate ${g.name}`));
  };

  // Toggle a single group's selection (keyboard `x`) into the same `selected`
  // map the checkboxes + bulk bar use.
  const toggleSelectGroup = (g: AlertGroup) => {
    setSelected((s) => {
      const next = { ...s };
      if (next[g.id]) delete next[g.id];
      else next[g.id] = true;
      return next;
    });
  };

  const toggleExpand = (g: AlertGroup) => {
    const opening = !expanded[g.id];
    setExpanded((s) => ({ ...s, [g.id]: !s[g.id] }));
    // Fetch this group's first page of events the first time it's opened.
    if (opening && groupEvents[g.id] === undefined && !eventsLoading[g.id]) {
      setEventsLoading((s) => ({ ...s, [g.id]: true }));
      getAlertGroupEvents(g, alertQuery, { size: EVENTS_PAGE_SIZE, offset: 0 })
        .then((evs) => {
          setGroupEvents((s) => ({ ...s, [g.id]: evs }));
          // A full page implies there may be more — show "Load more".
          setEventsMore((s) => ({ ...s, [g.id]: evs.length >= EVENTS_PAGE_SIZE }));
        })
        .catch(() => setGroupEvents((s) => ({ ...s, [g.id]: [] })))
        .finally(() => setEventsLoading((s) => ({ ...s, [g.id]: false })));
    }
  };

  // Fetch the next page of a group's events and append it. Hides "Load more"
  // once a returned page is short (no further pages).
  const loadMoreEvents = (g: AlertGroup) => {
    if (eventsLoadingMore[g.id]) return;
    const offset = groupEvents[g.id]?.length ?? 0;
    setEventsLoadingMore((s) => ({ ...s, [g.id]: true }));
    getAlertGroupEvents(g, alertQuery, { size: EVENTS_PAGE_SIZE, offset })
      .then((evs) => {
        setGroupEvents((s) => ({ ...s, [g.id]: [...(s[g.id] ?? []), ...evs] }));
        setEventsMore((s) => ({ ...s, [g.id]: evs.length >= EVENTS_PAGE_SIZE }));
      })
      .catch(() => setEventsMore((s) => ({ ...s, [g.id]: false })))
      .finally(() => setEventsLoadingMore((s) => ({ ...s, [g.id]: false })));
  };

  const ownerOf = (g: AlertGroup) => g.owner ?? '';

  // ── E2.3 triage-state actions ──────────────────────────────────────────
  // Each reuses the one /alerts/assign endpoint (assignAlert), then refreshes
  // the list so the chip/owner update. Assign-to-me and release both change
  // ownership; mark-in-review / mark-done only move the state on an owned rule.
  const assignToMe = (g: AlertGroup) =>
    assignAlert(g.name).then(() => setReloadKey((k) => k + 1));
  const release = (g: AlertGroup) =>
    assignAlert(g.name, true).then(() => setReloadKey((k) => k + 1));
  const setTriage = (g: AlertGroup, state: TriageState) =>
    assignAlert(g.name, false, state).then(() => setReloadKey((k) => k + 1));

  // The Verdict filter carries a synthetic 'pipeline_error' value (E1.2): a
  // fallback group matches it regardless of its (needs_more_info) verdict, and —
  // since the chip REPLACES the NMI pill — a fallback group is NOT matched by
  // selecting 'needs_more_info' alone.
  const matchesVerdict = (g: AlertGroup): boolean => {
    if (!filterVerdicts.length) return true;
    if (filterVerdicts.includes('pipeline_error') && g.fallback) return true;
    if (g.fallback) return false;
    return filterVerdicts.includes(g.verdict);
  };
  const visible = useMemo(
    () =>
      (groups ?? [])
        .filter((g) => matchView(g, view, me))
        .filter((g) => !filterSevs.length || filterSevs.includes(g.sev))
        .filter(matchesVerdict)
        .sort((a, b) => cmpGroups(a, b, sort.key, sort.dir)),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [groups, view, me, filterSevs, filterVerdicts, sort],
  );

  const visIds = visible.map((g) => g.id);
  const allSelected = visIds.length > 0 && visIds.every((id) => selected[id]);

  // ---- keyboard-first triage (E2.5): clamp + global handler ---------------
  // Keep focusedIndex inside the (possibly changed) visible range: none when the
  // list is empty, else clamp into bounds. Runs whenever the visible set changes.
  useEffect(() => {
    setFocusedIndex((i) => {
      if (visible.length === 0) return -1;
      if (i < 0) return -1; // stay "unfocused" until the user presses j/k
      return Math.min(i, visible.length - 1);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visible.length]);

  // Scroll the keyboard-focused row into view as focus moves.
  useEffect(() => {
    if (focusedIndex < 0) return;
    const g = visible[focusedIndex];
    if (!g) return;
    rowRefs.current[g.id]?.scrollIntoView({ block: 'nearest' });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusedIndex]);

  // Global keydown for row navigation + actions. Active ONLY when: the command
  // palette is CLOSED (paletteOpen from the shell — the single shared signal, no
  // DOM sniffing), focus is not in an input/textarea/[contenteditable], and no
  // Cmd/Ctrl/Alt modifier is held. The palette owns `/` and Cmd+K; this owns
  // j/k/o/a/e/i/x/?/Enter/Arrows — they can never both fire because a closed
  // palette is a hard precondition here and an open one short-circuits.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      // `?` help is closable from anywhere (Esc), but ALL shortcuts (incl. the
      // help toggle) require the palette closed + focus outside an input.
      if (paletteOpen) return;
      const el = e.target as HTMLElement | null;
      const tag = el?.tagName ?? '';
      if (/INPUT|TEXTAREA|SELECT/.test(tag) || el?.isContentEditable) return;

      // The cheatsheet overlay owns Esc while it's open.
      if (keyHelpOpen) {
        if (e.key === 'Escape') {
          e.preventDefault();
          setKeyHelpOpen(false);
        }
        return;
      }

      // Shift is allowed (needed for `?`); Cmd/Ctrl/Alt are not — leave those to
      // the browser / palette.
      if (e.metaKey || e.ctrlKey || e.altKey) return;

      // `?` (Shift+/) opens the cheatsheet — check before the plain-key branch.
      if (e.key === '?') {
        e.preventDefault();
        setKeyHelpOpen(true);
        return;
      }

      const n = visible.length;
      if (n === 0) return;

      const move = (delta: number) => {
        e.preventDefault();
        setFocusedIndex((i) => {
          if (i < 0) return delta > 0 ? 0 : n - 1;
          return Math.min(n - 1, Math.max(0, i + delta)); // clamp, no wrap
        });
      };

      switch (e.key) {
        case 'j':
        case 'ArrowDown':
          move(1);
          return;
        case 'k':
        case 'ArrowUp':
          move(-1);
          return;
      }

      // The remaining actions operate on the focused group; no-op gracefully
      // when nothing is focused or the row vanished under a refresh.
      const g = focusedIndex >= 0 ? visible[focusedIndex] : undefined;
      if (!g) return;

      switch (e.key) {
        case 'o':
        case 'Enter':
          e.preventDefault();
          // Same action as the row's primary button: open an existing report or
          // investigate the representative event.
          if (g.invId) openDrawer(g.invId);
          else huntGroup(g);
          return;
        case 'a':
          e.preventDefault();
          ackOneGroup(g);
          return;
        case 'e':
          e.preventDefault();
          escalateOneGroup(g);
          return;
        case 'i':
          e.preventDefault();
          // Investigate — open the live/existing run or start one (huntGroup).
          if (g.invId) openDrawer(g.invId);
          else huntGroup(g);
          return;
        case 'x':
          e.preventDefault();
          toggleSelectGroup(g);
          return;
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [paletteOpen, keyHelpOpen, visible, focusedIndex]);
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

  const { counts, untriaged, totalEvents } = useMemo(() => {
    const gs = groups ?? [];
    return {
      counts: {
        // "Mine" = owned by the current user (falls back to "any owner" until
        // getMe resolves, matching matchView's fallback so the count is honest).
        mine: gs.filter((g) => (me ? g.owner === me : !!g.owner && g.owner !== '')).length,
        inreview: gs.filter((g) => g.state === 'in_review').length,
        critical: gs.filter((g) => g.sev === 'critical').length,
        decision: gs.filter((g) => g.verdict === 'needs_more_info' || g.verdict === 'inconclusive' || g.verdict === 'untriaged').length,
        all: gs.length,
      },
      untriaged: gs.filter((g) => g.verdict === 'untriaged').length,
      totalEvents: gs.reduce((a, g) => a + g.count, 0),
    };
  }, [groups, me]);

  const TABS: Array<{ id: ViewId; label: string; count: number }> = [
    { id: 'mine', label: 'Mine', count: counts.mine },
    { id: 'inreview', label: 'In review', count: counts.inreview },
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
            title="Bulk investigate severity floor"
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
            <span className="flex" style={{ color: '#facc15' }}><Zap size={14} /></span> Bulk Investigate
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
            Bulk investigating
            {triageStatus?.severities?.length ? ` ${triageStatus.severities.join(', ')}` : ''}
            …
          </div>
          <div className="font-mono text-[12px] text-dim">
            {(() => {
              const s = triageStatus;
              const done = s ? s.hunted + s.skipped + s.failed : 0;
              const total = s ? s.total : 0;
              const parts: string[] = [`${done}/${total} investigated`];
              if (s && s.skipped) parts.push(`${s.skipped} skipped`);
              if (s && s.failed) parts.push(`${s.failed} failed`);
              if (s && s.tool_calls) parts.push(`${s.tool_calls} tool calls`);
              if (s && s.current) parts.push(s.current);
              return parts.join(' · ');
            })()}
          </div>
          <div className="flex-1" />
          <button
            onClick={() => {
              void stopAutoTriage().catch(() => {});
            }}
            title="Stop after the current investigation finishes"
            className="flex items-center gap-1 rounded-[6px] border border-border-strong px-2 py-1 text-[11.5px] font-semibold text-dim hover:border-danger hover:text-danger"
          >
            <X size={12} /> Stop
          </button>
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
            { value: 'inconclusive', label: 'Inconclusive' },
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
            <span className="flex" style={{ color: '#facc15' }}><Zap size={13} /></span> Bulk Investigate
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
          <div className={`text-right ${hdrCls('latest')}`} onClick={() => toggleSort('latest')}>
            Last seen{caret('latest')}
          </div>
          <div />
        </div>

        {loading && !groups && <LoadingState label="Loading detections…" />}
        {error && <div className="p-3"><ErrorState error={error} /></div>}
        {!loading && !error && visible.length === 0 && (
          <div className="px-4 py-10 text-center text-[13px] text-faint">No detections match this view.</div>
        )}

        {visible.map((g, rowIdx) => {
          const isExp = !!expanded[g.id];
          const owner = ownerOf(g);
          const seld = !!selected[g.id];
          const kbFocused = rowIdx === focusedIndex;
          return (
            <div key={g.id} ref={(el) => { rowRefs.current[g.id] = el; }}>
              <div
                onClick={() => toggleExpand(g)}
                className={`relative grid cursor-pointer items-center gap-2.5 border-b border-border-faint hover:bg-surface-hover${
                  kbFocused ? ' bg-surface-hover ring-1 ring-inset ring-accent' : ''
                }`}
                style={{ gridTemplateColumns: GRID, minWidth: 720, padding: rowPad }}
              >
                {/* keyboard-focus accent bar (E2.5) */}
                {kbFocused && (
                  <span className="pointer-events-none absolute inset-y-0 left-0 w-[3px] bg-accent" aria-hidden="true" />
                )}
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
                <div className="flex min-w-0 items-center gap-[9px]">
                  <span className="flex text-faint transition-transform" style={{ transform: isExp ? 'rotate(90deg)' : 'rotate(0deg)' }}>
                    <ChevronRight size={13} />
                  </span>
                  <KindBadge kind={g.kind} />
                  <div className="flex min-w-0 flex-1 flex-col gap-px">
                    <div className="flex min-w-0 items-center gap-1.5">
                      <span className="truncate text-[13.5px] font-medium">{g.name}</span>
                      {g.count > 1 && (
                        <span
                          className="flex-shrink-0 font-mono text-[10.5px] text-faint"
                          title={`Fired ${g.count.toLocaleString()} times in window — expand to see each event`}
                        >
                          ×{g.count.toLocaleString()}
                        </span>
                      )}
                    </div>
                    {(g.src || g.dst) && (
                      <div className="flex min-w-0 items-center">
                        <FlowBadge src={g.src} dst={g.dst} className="text-[10.5px]" />
                      </div>
                    )}
                  </div>
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
                <div className="flex min-w-0 items-center gap-1.5 overflow-hidden">
                  {g.triaging ? (
                    // Clickable so the analyst can open the LIVE investigation
                    // straight from the grid (invId now points at the running run).
                    <button
                      type="button"
                      disabled={!g.invId}
                      onClick={(e) => {
                        e.stopPropagation();
                        if (g.invId) openDrawer(g.invId);
                      }}
                      title={g.invId ? 'Open the in-progress investigation' : undefined}
                      className="inline-flex items-center gap-1.5 rounded-chip border border-[rgba(251,191,36,.35)] bg-[rgba(251,191,36,.10)] px-2 py-[3px] text-[11px] font-semibold text-[#fbbf24] enabled:hover:bg-[rgba(251,191,36,.18)] disabled:cursor-default"
                    >
                      <Spinner size={10} color="#fbbf24" />
                      Investigating…
                    </button>
                  ) : g.fallback ? (
                    // Pipeline fallback (E1.2): the standing verdict came from a
                    // run that FAILED before reaching a verdict (model truncation,
                    // gateway 5xx). Show the distinct pipeline-error chip (not the
                    // amber NMI pill) and open the run so the analyst can re-run it.
                    <button
                      type="button"
                      disabled={!g.invId}
                      onClick={(e) => {
                        e.stopPropagation();
                        if (g.invId) openDrawer(g.invId);
                      }}
                      title="Standing verdict is a pipeline error — open the run to re-run it"
                      className="flex min-w-0 items-center rounded-pill text-left enabled:hover:opacity-90 disabled:cursor-default"
                    >
                      <PipelineErrorChip />
                    </button>
                  ) : g.inherited ? (
                    // Inherited verdict: make the whole thing a link to the source
                    // investigation (when + which is in the enriched reason), so the
                    // analyst can see WHERE this verdict came from and jump to it.
                    <button
                      type="button"
                      disabled={!g.invId}
                      onClick={(e) => {
                        e.stopPropagation();
                        if (g.invId) openDrawer(g.invId);
                      }}
                      title={g.inheritedReason ?? 'Verdict inherited from a prior investigation of this detection'}
                      className="group/inh flex min-w-0 items-center gap-1.5 rounded-pill text-left enabled:hover:opacity-90 disabled:cursor-default"
                    >
                      <VerdictPill verdict={g.verdict} conf={g.conf} inherited showConf={false} showInherited={false} />
                      <span className="flex min-w-0 items-center gap-0.5 truncate font-mono text-[10.5px] text-faint group-enabled/inh:group-hover/inh:text-accent">
                        <span className="truncate">
                          · inherited{inheritedWhen(g.inheritedReason) ? ` ${inheritedWhen(g.inheritedReason)}` : ''}
                        </span>
                        {g.invId && <ArrowUpRight size={10} className="flex-shrink-0" />}
                      </span>
                    </button>
                  ) : (
                    <VerdictPill verdict={g.verdict} conf={g.conf} inherited={false} showConf={false} showInherited={false} />
                  )}
                  {/* E2.1: a later re-run failed on top of the standing verdict —
                      a secondary red hint; the verdict chip above stays primary.
                      Backend nulls this for triaging + fallback-standing rows. */}
                  {g.lastAttempt && <LastRetryHint attempt={g.lastAttempt} />}
                  {/* E2.3: the human triage state (owned / in review / done). Only
                      shown once a rule has an owner — an unassigned rule renders no
                      chip here (the dashed "+" in the Owner cell is the affordance). */}
                  {g.owner && <StateChip state={g.state} />}
                </div>
                <div className="text-right font-mono text-[12px] text-dim">
                  {g.conf != null ? g.conf.toFixed(2) : '—'}
                </div>
                <div className="flex items-center">
                  {owner ? (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        release(g);
                      }}
                      title={`Assigned to ${owner} — click to release`}
                      className="flex h-[25px] w-[25px] items-center justify-center rounded-full border border-border-strong bg-[#1a2330] text-[9.5px] font-bold text-[#b9c2cf] hover:border-danger hover:text-danger"
                    >
                      {toInitials(owner)}
                    </button>
                  ) : (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        assignToMe(g);
                      }}
                      title="Assign to me"
                      className="flex h-[25px] w-[25px] items-center justify-center rounded-full border-[1.5px] border-dashed border-border-strong text-[14px] leading-none text-faint hover:border-accent hover:text-accent"
                    >
                      +
                    </button>
                  )}
                </div>
                <div
                  className="text-right font-mono text-[12.5px] font-medium text-text-2"
                  title={absTime(g.latestTs) ?? g.latest}
                >
                  {g.latest || '—'}
                </div>
                <div className="flex items-center justify-end gap-1.5">
                  {/* E2.3 triage-state actions: only on an OWNED row. "Review"
                      moves owned → in_review; "Done" marks it done (from owned or
                      in_review); the owner avatar in the Owner cell releases it.
                      Hidden entirely on an unassigned row (assign first). */}
                  {g.owner && g.state !== 'in_review' && g.state !== 'done' && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setTriage(g, 'in_review');
                      }}
                      aria-label="Mark in review"
                      title="Mark this detection as in review"
                      className="inline-flex items-center rounded-badge border border-amber-400/40 bg-amber-400/10 px-[9px] py-[3px] font-sans text-[11px] font-semibold text-amber-300 hover:brightness-125"
                    >
                      Review
                    </button>
                  )}
                  {g.owner && g.state !== 'done' && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setTriage(g, 'done');
                      }}
                      aria-label="Mark done"
                      title="Mark this detection's triage as done"
                      className="inline-flex items-center rounded-badge border border-emerald-400/40 bg-emerald-400/10 px-[9px] py-[3px] font-sans text-[11px] font-semibold text-emerald-300 hover:brightness-125"
                    >
                      Done
                    </button>
                  )}
                  {/* E2.1: the last re-run failed — offer an explicit RETRY that
                      re-investigates the group's representative event (reuses the
                      existing hunt path), so the analyst can act without opening
                      the stale report first. Only when there IS a failed retry and
                      no live run in flight. */}
                  {g.lastAttempt && !g.triaging && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        huntGroup(g);
                      }}
                      disabled={!!huntGroupPending[g.id]}
                      aria-label="Retry investigation"
                      title="Last re-run failed — re-investigate the representative event"
                      className="inline-flex items-center gap-1 rounded-badge border px-[9px] py-[3px] font-sans text-[11px] font-semibold disabled:opacity-50"
                      style={{ borderColor: 'rgba(239,68,68,.4)', background: 'rgba(239,68,68,.08)', color: '#f87171' }}
                    >
                      {huntGroupPending[g.id] ? <Spinner size={11} color="#f87171" /> : <Zap size={11} />}
                      Retry
                    </button>
                  )}
                  {g.invId || g.triaging ? (
                    // A report exists (or one is in flight) — one clean "Open" action.
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        openDrawer(g.invId ?? g.id);
                      }}
                      aria-label="Open investigation"
                      title="Open the investigation report"
                      className="inline-flex items-center gap-1 rounded-badge border border-border-input px-[9px] py-[3px] font-sans text-[11px] font-semibold text-accent hover:border-accent hover:bg-[#141b25]"
                    >
                      Open report
                      <ArrowUpRight size={12} />
                    </button>
                  ) : (
                    // No report yet — investigate the group's representative event.
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        huntGroup(g);
                      }}
                      disabled={!!huntGroupPending[g.id]}
                      title="Investigate the most-representative event in this group"
                      aria-label="Investigate"
                      className="inline-flex items-center gap-1 rounded-badge border px-[9px] py-[3px] font-sans text-[11px] font-semibold disabled:opacity-50"
                      style={{ borderColor: 'rgba(139,92,246,.35)', background: 'rgba(139,92,246,.07)', color: '#a78bfa' }}
                    >
                      {huntGroupPending[g.id] ? <Spinner size={11} color="#a78bfa" /> : <Sparkles size={11} />}
                      Investigate
                    </button>
                  )}
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
                      style={{ gridTemplateColumns: EVENT_GRID }}
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
                      {/* this alert's OWN timestamp: clock time + relative age */}
                      <div className="flex min-w-0 flex-col leading-tight" title={absTime(ev.ts) ?? ev.ts ?? ''}>
                        <span className="truncate text-text-2">{clockTime(ev.ts) || '—'}</span>
                        {ev.ago && <span className="text-[10px] text-faint">{ev.ago} ago</span>}
                      </div>
                      {/* severity */}
                      <div><SeverityTag sev={(ev.sev ?? 'low') as Severity} /></div>
                      {/* src → dst:port — each endpoint pivots to its entity page */}
                      <div className="flex min-w-0 items-center gap-1.5 truncate">
                        {ev.src ? (
                          <span
                            className="cursor-pointer text-mono-green hover:underline"
                            onClick={() => navigate(`/entity/${encodeURIComponent(ev.src)}`)}
                            title={`Pivot to ${ev.src}`}
                          >
                            {ev.src}
                          </span>
                        ) : (
                          <span className="text-mono-green">{ev.src}</span>
                        )}
                        <span className="text-ghost">→</span>
                        {ev.dst ? (
                          <span
                            className="cursor-pointer text-mono-amber hover:underline"
                            onClick={() => navigate(`/entity/${encodeURIComponent(ev.dst)}`)}
                            title={`Pivot to ${ev.dst}`}
                          >
                            {ev.dst}
                          </span>
                        ) : (
                          <span className="text-mono-amber">{ev.dst}</span>
                        )}
                        {ev.port != null && (
                          <span className="text-faint">:{ev.port}</span>
                        )}
                      </div>
                      {/* host — pivots to its entity page */}
                      {ev.host ? (
                        <div
                          className="cursor-pointer truncate text-dim hover:text-text hover:underline"
                          title={`Pivot to ${ev.host}`}
                          onClick={() => navigate(`/entity/${encodeURIComponent(ev.host)}`)}
                        >
                          {ev.host}
                        </div>
                      ) : (
                        <div className="truncate text-dim" title={ev.host}>{ev.host}</div>
                      )}
                      {/* verdict provenance + WHEN the investigation ran/inherited */}
                      <div className="flex min-w-0 items-center">
                        <ProvenanceBadge ev={ev} onOpen={openDrawer} />
                      </div>
                      {/* investigate this exact event */}
                      <div className="flex justify-end">
                        <button
                          onClick={() => huntEvent(g, ev)}
                          className="inline-flex items-center gap-1.5 rounded-badge border px-[9px] py-[3px] font-sans text-[11px] font-semibold text-accent"
                          style={{ borderColor: 'rgba(75,139,245,.3)', background: 'rgba(75,139,245,.07)' }}
                        >
                          <Sparkles size={12} />
                          {ev.invId ? 'Open' : 'Investigate'}
                        </button>
                      </div>
                    </div>
                  ))}
                  {!eventsLoading[g.id] && eventsMore[g.id] && (
                    <div className="py-1.5 pl-[36px] pr-3.5">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          loadMoreEvents(g);
                        }}
                        disabled={eventsLoadingMore[g.id]}
                        className="inline-flex items-center gap-1.5 rounded-badge border border-border-input px-[9px] py-[3px] font-mono text-[11px] font-semibold text-dim hover:text-text disabled:opacity-60"
                        style={{ background: 'rgba(148,163,184,.06)' }}
                      >
                        {eventsLoadingMore[g.id] ? <Spinner size={11} /> : <ChevronRight size={12} className="rotate-90" />}
                        {eventsLoadingMore[g.id] ? 'Loading…' : 'Load more'}
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div className="mt-2.5 font-mono text-[12px] text-faint">
        {counts.all} detections · grouped · click a row to expand events
      </div>

      {/* keyboard cheatsheet (E2.5) — `?` opens; Esc / backdrop closes */}
      {keyHelpOpen && <KeyHelpOverlay onClose={() => setKeyHelpOpen(false)} />}

      {/* investigation drawer */}
      <AlertDrawer
        drawerId={drawerId}
        starting={starting}
        onClose={closeDrawer}
        navigateToPermalink={(id) => navigate(`/investigation/${id}`, { state: { from: '/alerts' } })}
        onReHunt={openDrawer}
        onComplete={onDrawerComplete}
      />
    </div>
  );
}

// ── keyboard cheatsheet overlay (E2.5) ──────────────────────────────────────
// A small centered card + backdrop reusing the command-palette overlay styling.
// Lists the Alerts-only row shortcuts AND the global ones (`/`, Cmd+K, `?`) so
// one panel maps the whole keyboard surface. Closable via Esc (handled by the
// Alerts keydown effect) or a backdrop click.
const KEY_HELP: Array<{ keys: string; label: string }> = [
  { keys: 'j / k', label: 'Move focus down / up' },
  { keys: '↓ / ↑', label: 'Move focus down / up' },
  { keys: 'o  ↵', label: 'Open the focused detection' },
  { keys: 'a', label: 'Acknowledge the focused group' },
  { keys: 'e', label: 'Escalate the focused group to a case' },
  { keys: 'i', label: 'Investigate the focused group' },
  { keys: 'x', label: 'Select / deselect the focused group' },
  { keys: '/', label: 'Search — open the command palette' },
  { keys: '⌘K', label: 'Toggle the command palette' },
  { keys: '?', label: 'Show this shortcut help' },
  { keys: 'esc', label: 'Close help / palette / drawer' },
];

function KeyHelpOverlay({ onClose }: { onClose: () => void }) {
  return (
    <>
      <div onClick={onClose} className="fixed inset-0 z-[60] bg-[rgba(4,6,9,.55)] backdrop-blur-[2px]" />
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Keyboard shortcuts"
        className="fixed left-1/2 top-1/2 z-[61] -translate-x-1/2 -translate-y-1/2 animate-fadeUp overflow-hidden rounded-panel-lg border border-border-input bg-surface-card shadow-palette"
        style={{ width: 'min(440px,92vw)' }}
      >
        <div className="flex items-center justify-between border-b border-border-2 px-4 py-[13px]">
          <span className="text-[14px] font-semibold text-text">Keyboard shortcuts</span>
          <button onClick={onClose} aria-label="Close" className="flex text-faint hover:text-text">
            <X size={15} />
          </button>
        </div>
        <div className="max-h-[60vh] overflow-y-auto p-2">
          {KEY_HELP.map((k) => (
            <div key={k.keys + k.label} className="flex items-center gap-3 rounded-control px-2.5 py-[7px]">
              <kbd className="min-w-[42px] rounded-[4px] border border-border-input bg-surface-3 px-1.5 py-px text-center font-mono text-[11px] text-text-2">
                {k.keys}
              </kbd>
              <span className="text-[13px] text-dim">{k.label}</span>
            </div>
          ))}
        </div>
        <div className="border-t border-border-2 px-4 py-[9px] font-mono text-[10.5px] text-faint">
          Row shortcuts act on the highlighted detection · typing in a filter never triggers them
        </div>
      </div>
    </>
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
  const [cancelling, setCancelling] = useState(false);
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
    if (
      (inv?.status === 'complete' || inv?.status === 'error' || inv?.status === 'cancelled') &&
      wasRunning.current
    ) {
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
          {inv?.status === 'investigating' && (
            <button
              disabled={cancelling}
              onClick={() => {
                setCancelling(true);
                void cancelHunt(inv.id)
                  .then(() => setTick((x) => x + 1))
                  .catch(() => {})
                  .finally(() => setCancelling(false));
              }}
              className="flex items-center gap-1.5 text-[12px] text-dim hover:text-danger disabled:opacity-50"
            >
              <X size={13} /> {cancelling ? 'Cancelling…' : 'Cancel'}
            </button>
          )}
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
