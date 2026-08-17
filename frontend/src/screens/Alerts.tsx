import { ArrowUpRight, Check, ChevronRight, Filter, Sparkles, X, Zap } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { KindBadge, PipelineErrorChip, SeverityTag, VerdictPill } from '../components/Badges';
import { FlowBadge } from '../components/FlowBadge';
import { Checkbox } from '../components/Controls';
import { ListToolbar } from '../components/ListToolbar';
import { useListSelection } from '../lib/useListSelection';
import { useSavedViews } from '../lib/useSavedViews';
import { Drawer } from '../components/Drawer';
import { MultiSelect } from '../components/MultiSelect';
import { TimeRangeFilter, type CustomRange } from '../components/TimeRangeFilter';
import { ErrorState, Freshness, LoadingState, Spinner } from '../components/States';
import { hideOptimisticallyAcked } from '../lib/alertFilters';
import {
  type AlertQuery,
  type AutoTriageStatus,
  ApiError,
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
import { DEMO_ACTION_NOTE, demoBlocked, useDemo } from '../lib/demo';
import { plural } from '../lib/plural';
import { useToast } from '../lib/toast';
import { useAsync } from '../lib/useAsync';
import { isEditableTarget, nextFocusIndex, resolveTriageKey } from '../lib/triageKeys';
import { type SortDir, useSort } from '../lib/useSort';
import type {
  AlertEvent,
  AlertGroup,
  Investigation as Inv,
  SavedViewQuery,
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
// count is now a subtle inline chip. `actions` fits Done + "Open report" on one
// line and the cell flex-wraps, so an owned row's third button drops BELOW
// instead of overlapping the "Last seen" column.
const GRID = '28px minmax(240px,1fr) 104px 136px 48px 40px 100px 170px';

// Per-alert (expanded) event row: checkbox | alert time (abs+rel) | sev |
// src→dst:port | host (+ its address) | verdict provenance (+ when) |
// investigate. Each row now carries the alert's OWN timestamp AND the
// investigation's timestamp. The sev column fits the widest label ("Critical") —
// narrower and the tag bleeds into the src endpoint with zero gap. The host
// column stacks its second line (the endpoint agent's IP, host detections only)
// rather than taking a column of its own: it is absent on every flow alert, so a
// column would be empty on the common case.
const EVENT_GRID = '16px 132px 76px minmax(150px,1fr) 116px 172px 92px';

// Page size for an expanded group's events ("Load more" pulls one page at a time).
const EVENTS_PAGE_SIZE = 50;

// Auto-triage skip-reason codes (webui/autotriage.py planner) → friendly text.
// An entry earns its place only if the planner emits the code AND the wording
// beats the humanized fallback below. "no_ip" fails the first test: it was
// retired when _cluster_events stopped DROPPING alerts that carry no
// source/destination IP, and keeping its label would have gone on advertising a
// behaviour (endpoint-shaped detections discarded every sweep) the product no
// longer has. "not_found" failed the second — its label read "not found", which
// is character-for-character what the fallback already produces.
const TRIAGE_SKIP_REASONS: Record<string, string> = {
  already_triaged: 'already triaged',
  running: 'in-flight',
  inherited: 'covered by a prior verdict',
};

// " (8 already triaged, 3 in-flight)" — the per-reason breakdown of a batch's
// skip count, or "" when the backend didn't carry one.
//
// An unmapped code is humanized rather than printed raw: a new backend reason is
// surfaced instead of silently dropped, and a RETIRED one (a historical status
// row can still hold "no_ip") reads as words, not as wire format.
function triageSkipDetail(s: AutoTriageStatus): string {
  const reasons = s.skipped_reasons;
  if (!reasons) return '';
  const parts = Object.entries(reasons)
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1])
    .map(([code, n]) => `${n} ${TRIAGE_SKIP_REASONS[code] ?? code.replace(/_/g, ' ')}`);
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

// ---- deep-link seeding ------------------------------------------------------
// Allow-lists for the URL-seeded filters. A value outside its set is DROPPED,
// not applied: a filter the on-screen control can't display is one the operator
// can't clear, so a mangled or stale bookmark would silently hide rows with no
// visible way back.
const SEV_LINK_VALUES = new Set(['critical', 'high', 'medium', 'low']);
/** Exactly the Verdict MultiSelect's options below. 'pipeline_error' is
 * deliberately absent even though matchesVerdict() understands it — this
 * screen's MultiSelect offers no such option, so a link carrying it would set a
 * filter with no checkbox to un-tick. */
const VERDICT_LINK_VALUES = new Set([
  'untriaged',
  'true_positive',
  'false_positive',
  'needs_more_info',
  'inconclusive',
]);
/** TimeRangeFilter's presets, themselves pinned to the backend's TIME_RANGES
 * (alerts_query.py). An unknown ?range= would query a window the backend
 * rejects and leave the segmented control with nothing highlighted. */
const RANGE_LINK_VALUES = new Set(['15m', '1h', '4h', '24h', '3d', '7d', '30d']);

/**
 * Filter state carried in on the URL. The Dashboard's severity bars land here
 * on ?sev=, and its Untriaged tile on ?verdict=&range=&hide_acked= — that tile
 * counts alert GROUPS with no standing investigation, the unit only this screen
 * lists. The range/hide_acked params are load-bearing rather than decorative:
 * this screen defaults to 24h with acked groups hidden, while the Dashboard
 * counts the operator's chosen range with them included, so a link without them
 * lands on a list that structurally cannot hold the group just counted.
 *
 * Read off the router's search params rather than window.location so seeding
 * survives a basename (the SPA is served under /app).
 */
// This screen's own defaults, named once so a saved view that omits a facet can
// restore the default rather than an arbitrary empty value. `hideAcked` is ON
// by default (see seedFromLink's `!== 'false'`), which is exactly the default a
// partial apply used to flip off.
const DEFAULT_VIEW: ViewId = 'all';
const DEFAULT_RANGE = '24h';
const DEFAULT_HIDE_ACKED = true;

function seedFromLink(params: URLSearchParams): {
  sevs: string[];
  verdicts: string[];
  range: string | null;
  custom: CustomRange | null;
  hideAcked: boolean;
  q: string | null;
} {
  const list = (raw: string | null, allowed: Set<string>): string[] =>
    raw
      ? raw
          .split(',')
          .map((v) => v.trim())
          .filter((v) => allowed.has(v))
      : [];
  const range = params.get('range');
  const from = params.get('from');
  const to = params.get('to');
  // 'custom' is only honoured with BOTH endpoints — a bare ?range=custom would
  // ask the backend for a window with no bounds.
  const custom = range === 'custom' && from && to ? { from, to } : null;
  return {
    sevs: list(params.get('sev'), SEV_LINK_VALUES),
    verdicts: list(params.get('verdict'), VERDICT_LINK_VALUES),
    range: custom ? 'custom' : range && RANGE_LINK_VALUES.has(range) ? range : null,
    custom,
    // Only an explicit ?hide_acked=false turns the toggle off; absent or
    // mangled keeps this screen's default ON.
    hideAcked: params.get('hide_acked') !== 'false',
    // An OQL filter clause — the host page's Alerts KPI narrows this screen to
    // one host with it (`(source.ip:x OR destination.ip:x)`). Passed to the
    // backend verbatim, where the OQL trust boundary (parse + field whitelist)
    // validates it; a bad clause is the server's named 400, not a silent list.
    // Honouring the param is the point: a deep link this screen ignored would
    // land a host-scoped count on a network-wide list — the untriaged-tile
    // defect this file's header describes.
    q: (params.get('q') ?? '').trim() || null,
  };
}

/** Stable per-detection identity for client-side row state (expansion,
 * selection, keyboard focus, refs). The backend sets `g.id` to the NEWEST
 * event's ES `_id`, which changes on every 10s poll as new events land —
 * keying row state on it orphans that state each refresh (an expanded group
 * collapses, a ticked checkbox drops). kind+name is the identity every write
 * path already addresses a group by (ackGroup / assignAlert take `g.name`).
 * `g.id` is kept only as the representative-event payload for a new hunt. */
const groupKey = (g: AlertGroup): string => `${g.kind}:${g.name}`;

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

/** A compact triage-state chip. `null` → the faint "Unassigned" pill.
 * flex-none + nowrap: these short labels must never be truncated or broken
 * mid-word — in a tight cell the whole chip wraps below instead. */
function StateChip({ state }: { state?: TriageState | null }) {
  if (!state) {
    return (
      <span className="inline-flex flex-none items-center whitespace-nowrap rounded-pill border border-border-strong px-1.5 py-px text-[9.5px] font-semibold uppercase tracking-wide text-faint">
        Unassigned
      </span>
    );
  }
  return (
    <span
      className={`inline-flex flex-none items-center whitespace-nowrap rounded-pill border px-1.5 py-px text-[9.5px] font-semibold uppercase tracking-wide ${STATE_CLS[state]}`}
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

/** The entity an event-table cell may pivot to, or null when there is nothing
 * to pivot to.
 *
 * The backend does not send null for a missing endpoint or host — it sends the
 * EM-DASH placeholder it wants displayed. That string is truthy, so the obvious
 * `ev.host ? <link> : <text>` guard made every absent value a live link to
 * `/entity/%E2%80%94`, an entity page for a punctuation mark. Emptiness here is
 * a matter of VALUE, not truthiness, and host-shaped detections (no source.ip,
 * no destination.ip) hit it on two cells out of three. */
const PLACEHOLDER = '—';
function pivotTarget(value?: string | null): string | null {
  const v = value?.trim();
  return v && v !== PLACEHOLDER ? v : null;
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
  const { paletteOpen, modalOpen } = useShell();
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();
  const [reloadKey, setReloadKey] = useState(0);
  // Deep-link seed (see seedFromLink). Recomputed each render, but only the
  // first render's value reaches the useState calls below — after that the
  // controls own the filters.
  const seed = seedFromLink(searchParams);
  // Demo content is rebased to "now" but still spans a couple of hours; widen the
  // default window so nothing the seed shipped ages out of view. The /demo-status
  // probe resolves async (demo is false on first render), so widen via an effect
  // when it flips rather than in the useState initializer, which only runs once —
  // otherwise a hard-refresh straight to /alerts keeps the 24h default. demo flips
  // once, early, before any user pick, so this never clobbers a manual choice.
  const demo = useDemo();
  const [filterTime, setFilterTime] = useState(seed.range ?? DEFAULT_RANGE);
  // Frozen at mount: an explicit ?range= IS an operator choice (made on the
  // Dashboard), so the demo widening above must not overwrite it.
  const rangeFromLink = useRef(seed.range != null);
  useEffect(() => {
    if (demo && !rangeFromLink.current) setFilterTime('30d');
  }, [demo]);
  const [customRange, setCustomRange] = useState<CustomRange | null>(seed.custom);
  const [filterSevs, setFilterSevs] = useState<string[]>(seed.sevs); // [] = all
  const [filterVerdicts, setFilterVerdicts] = useState<string[]>(seed.verdicts); // [] = all
  const [hideAcked, setHideAcked] = useState(seed.hideAcked);
  // The deep-linked OQL filter. Seeded once like the rest; cleared from its
  // own chip in the filter bar (which also drops ?q= from the URL, so a reload
  // does not resurrect a filter the analyst just dismissed).
  const [filterQ, setFilterQ] = useState<string | null>(seed.q);
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
    // In alertQuery (not a one-off param) so the lazy event pages and the
    // representative pick fetched under this filter stay scoped to the same
    // set the rows on screen came from.
    q: filterQ || undefined,
  };
  const view = (searchParams.get('view') as ViewId) || 'all';
  const drawerId = searchParams.get('drawer');
  // useAsync captures pauseWhen at setup and can't see `drawerId` there (it's
  // not in the deps below), so track it in a ref and let pauseWhen consult
  // that instead — same gotcha/pattern as Investigations.tsx, Hunts.tsx, etc.
  const drawerOpenRef = useRef(false);
  drawerOpenRef.current = !!drawerId;
  const { data: groups, loading, error, lastUpdated, refetch } = useAsync(
    () => getAlerts(alertQuery),
    [filterTime, customRange?.from, customRange?.to, hideAcked, filterQ, reloadKey],
    {
      refetchInterval: 10000, // keep the grid + verdict/status badges live without a reload
      // Pause the 10s ES aggregation while an investigation drawer is open, so
      // the grid doesn't churn under the analyst; resumes on close.
      pauseWhen: () => drawerOpenRef.current,
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
  const [selEvents, setSelEvents] = useState<Record<string, boolean>>({});
  // How much is selected right now, readable from the filter-change effect
  // without making that effect depend on (and re-run for) every tick.
  const selectedRef = useRef(0);
  const [ackingEvents, setAckingEvents] = useState(false);
  const [density, setDensity] = useState<Density>('comfortable');

  // ---- keyboard-first triage (E2.5) --------------------------------------
  // Index of the keyboard-focused group row within the visible list; -1 = none.
  // Vim-style j/k (+ arrows) move it, o/Enter open, a/e/i act, x selects.
  // Keyboard focus is tracked by STABLE group key, not list index: the 10s poll
  // re-sorts `visible` and can insert new groups above the focused row, so an
  // index would silently re-point at a DIFFERENT detection between polls (`a`/`e`
  // would then ack/escalate the wrong group). The index is derived from the key
  // each render below; focus drops when the focused row leaves the list.
  const [focusedKey, setFocusedKey] = useState<string | null>(null);
  const [keyHelpOpen, setKeyHelpOpen] = useState(false);
  // Per-row element refs so the focused row can be scrolled into view as focus
  // moves. Keyed by group id; stale keys are harmless (a WeakMap-ish plain map).
  const rowRefs = useRef<Record<string, HTMLDivElement | null>>({});
  // Shared sort mechanics; clicking a new column here starts it descending.
  const { sort, toggleSort, caret, headerCls: hdrCls } = useSort<SortKey>(
    { key: 'sev', dir: 'desc' },
    'desc',
  );

  // Results (ack / triage batch summaries) go to the app-wide toaster instead of
  // stacking dismissible strips in this header.
  const { toast } = useToast();

  // ---- group-ack strip ---------------------------------------------------
  const [acking, setAcking] = useState(false);
  const [ackingCount, setAckingCount] = useState(0);
  const [ackingAlertTotal, setAckingAlertTotal] = useState(0);
  const showAckMsg = (m: string) =>
    toast({ message: m, tone: m === DEMO_ACTION_NOTE ? 'info' : 'success' });

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
  const triageTimer = useRef<ReturnType<typeof setInterval> | null>(null);
  // Severity floor for the global sweep button ("High and up" by default).
  const [triageFloor, setTriageFloor] = useState<string>('high');

  const showTriageMsg = (m: string) => toast({ message: m, tone: 'info' });

  // Why a start that never landed is reported the way it is.
  //
  // "Bulk Investigate failed to start" is a claim about the SERVER, and only a
  // server that answered can support it. An ApiError means the API responded
  // and refused: its message is the wire's `detail.hint`, the sentence written
  // for the analyst ("…retry shortly"), which the old toast dropped — leaving a
  // failure that named no cause and no next step. Anything else is a transport
  // failure with NO response at all: api.ts's 20s client budget fired, or the
  // network dropped. On a stalled grid that is exactly what happens — the
  // browser aborts the POST at 20s while the backend goes on running the sweep
  // it already accepted — so "failed to start" is not merely vague there, it is
  // false, and it invites a second click and a duplicate sweep over the same
  // alerts. Unknown is not failure: report that we got no answer, and point at
  // the surface that does know.
  // Close a sentence somebody else wrote. Both halves of this report end by
  // quoting one: the wire's `detail.hint`, or api.ts's transport message. How
  // they are punctuated is not ours to decide — api.ts's network failure is a
  // QUESTION ("…is the soc-ai API reachable?") — so add the full stop only when
  // the author left the sentence open, and never restyle one they closed.
  const endSentence = (s: string): string => {
    const text = s.trim();
    return /[.!?…]$/.test(text) ? text : `${text}.`;
  };
  const triageStartFailure = (err: unknown): string => {
    // The server's sentence, or the transport's.
    const detail = err instanceof Error ? err.message.trim() : '';
    if (err instanceof ApiError) {
      return `Bulk Investigate was refused. ${endSentence(
        detail || `The API answered ${err.status}`,
      )}`;
    }
    // The next step leads here, because it is the part that stops a duplicate
    // sweep; the transport's own words follow it.
    return (
      'No answer to Bulk Investigate — the sweep may have started anyway, so check the ' +
      `Auto-Investigate tile on the Dashboard before starting another. ${endSentence(
        detail || 'The request did not complete',
      )}`
    );
  };

  // The durable half of that report. The toast is the notice; this strip is the
  // record, and it stays until the next attempt — a click that failed used to
  // leave no trace at all once the 6s toast expired. It cannot collide with the
  // in-progress activity slot below: a failed start means `triaging` is false,
  // and any new attempt clears this first.
  const [triageError, setTriageError] = useState<string | null>(null);

  // A one-line summary of how a batch landed — never let it finish silently.
  // When the backend carries a per-reason skip breakdown (E2.2), spell it out
  // ("12 skipped (8 already triaged, 3 in-flight, 1 covered by a prior
  // verdict)") instead of a bare count so an operator can see WHY work was
  // skipped.
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
    setTriageError(null);
    setPct(0);
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
      .catch((err: unknown) => {
        setTriaging(false);
        const msg = triageStartFailure(err);
        setTriageError(msg);
        // 'danger', so the toaster's own rule applies and it persists until
        // dismissed. As an 'info' it inherited the 6s auto-dismiss and was gone
        // from the screen before an analyst who looked away had read it.
        toast({ message: msg, tone: 'danger' });
      });
  };

  // Kick off triage when the command palette requests it. The palette carries
  // the intent in the navigation STATE (not a shell nonce): Alerts is code-split
  // and the palette navigates here before this screen mounts, so a nonce bumped
  // pre-mount is seeded away and never observed. A location.state flag arrives on
  // the mount navigation (and on a repeat request while already here, which gets
  // a fresh location.key), and is cleared immediately so a refresh or Back can't
  // re-fire it.
  useEffect(() => {
    if ((location.state as { autoTriage?: boolean } | null)?.autoTriage) {
      startTriage(undefined, triageFloor);
      navigate(location.pathname + location.search, { replace: true, state: {} });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.key]);

  useEffect(() => () => {
    if (triageTimer.current) clearInterval(triageTimer.current);
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
    // The cached event pages these ids came from were just discarded, so any
    // per-event selection now points at rows that are off-screen and may fall
    // outside the new window — clear it too, else the bulk bar keeps offering
    // "Ack N events" against ES ids the analyst can no longer see (F59).
    setSelEvents({});
    // The same argument applies to GROUPS, and more sharply. A group selection
    // is a `kind:name` KEY, but every bulk action resolves it against the
    // CURRENT `groups` array to get the representative event id — so a group
    // that falls outside the new filter keeps inflating the strip's count while
    // contributing nothing to the action it appears to be part of. That is the
    // count lying about the work, which is the whole disease this screen keeps
    // catching. Unlike the paged lists, this screen refetches its entire result
    // set on a filter change, so there is no legitimate off-page selection to
    // preserve here.
    //
    // This is ALSO what lets the filter row stay on screen during a selection.
    // The row used to be hidden while selecting, which prevented a stranded
    // selection structurally — by removing the controls. That cure cost Hunts
    // its only filter and blanked a live search term, so the guarantee is made
    // here instead: change a filter and the selection is dropped, out loud.
    if (selectedRef.current > 0) {
      showAckMsg('Filter changed — selection cleared');
    }
    sel.clear();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filterTime, customRange?.from, customRange?.to, hideAcked, filterQ]);

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

  // Session-local record of drawer-initiated group acks (rule → epoch ms).
  // The ES agg lags a fresh ack by seconds-to-minutes, so hide the group
  // optimistically; a group whose latest event postdates the ack re-surfaces.
  const [optimisticAcked, setOptimisticAcked] = useState<Record<string, number>>({});
  const onDrawerAcked = useCallback((ruleName: string) => {
    setOptimisticAcked((m) => ({ ...m, [ruleName]: Date.now() }));
    setReloadKey((k) => k + 1);
  }, []);
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
    const gk = groupKey(g);
    setHuntGroupPending((s) => ({ ...s, [gk]: true }));
    getRepresentative(g, alertQuery)
      .then((rep) => {
        showHuntReason(`Investigating representative: ${rep.reason}`);
        setStarting(g);
        return startHunt(rep.alert_id);
      })
      .then((invId) => openDrawer(invId))
      .catch(() => setStarting(null))
      .finally(() => setHuntGroupPending((s) => ({ ...s, [gk]: false })));
  };

  // Acknowledge a single group (keyboard `a`) — reuses the same ackGroup write
  // path + ack strip as the bulk bar, scoped to one detection.
  const ackOneGroup = (g: AlertGroup) => {
    const blocked = demoBlocked(demo);
    if (blocked) { showAckMsg(blocked); return; } // demo: no doomed write
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
    const blocked = demoBlocked(demo);
    if (blocked) { showAckMsg(blocked); return; } // demo: no doomed write
    escalateGroup(g, alertQuery)
      .then((r) => {
        showAckMsg(`Escalated ${r.escalated} of ${r.total} event${r.total !== 1 ? 's' : ''} in ${g.name} to a case`);
        setReloadKey((k) => k + 1);
      })
      .catch(() => showAckMsg(`Failed to escalate ${g.name}`));
  };

  // Toggle a single group's selection (keyboard `x`) into the same `selected`
  // map the checkboxes + bulk bar use.
  const toggleSelectGroup = (g: AlertGroup) => sel.toggle(groupKey(g));

  const toggleExpand = (g: AlertGroup) => {
    const gk = groupKey(g);
    const opening = !expanded[gk];
    setExpanded((s) => ({ ...s, [gk]: !s[gk] }));
    // Fetch this group's first page of events the first time it's opened.
    if (opening && groupEvents[gk] === undefined && !eventsLoading[gk]) {
      setEventsLoading((s) => ({ ...s, [gk]: true }));
      getAlertGroupEvents(g, alertQuery, { size: EVENTS_PAGE_SIZE, offset: 0 })
        .then((evs) => {
          setGroupEvents((s) => ({ ...s, [gk]: evs }));
          // A full page implies there may be more — show "Load more".
          setEventsMore((s) => ({ ...s, [gk]: evs.length >= EVENTS_PAGE_SIZE }));
        })
        .catch(() => setGroupEvents((s) => ({ ...s, [gk]: [] })))
        .finally(() => setEventsLoading((s) => ({ ...s, [gk]: false })));
    }
  };

  // Fetch the next page of a group's events and append it. Hides "Load more"
  // once a returned page is short (no further pages).
  const loadMoreEvents = (g: AlertGroup) => {
    const gk = groupKey(g);
    if (eventsLoadingMore[gk]) return;
    const offset = groupEvents[gk]?.length ?? 0;
    setEventsLoadingMore((s) => ({ ...s, [gk]: true }));
    getAlertGroupEvents(g, alertQuery, { size: EVENTS_PAGE_SIZE, offset })
      .then((evs) => {
        setGroupEvents((s) => ({ ...s, [gk]: [...(s[gk] ?? []), ...evs] }));
        setEventsMore((s) => ({ ...s, [gk]: evs.length >= EVENTS_PAGE_SIZE }));
      })
      .catch(() => setEventsMore((s) => ({ ...s, [gk]: false })))
      .finally(() => setEventsLoadingMore((s) => ({ ...s, [gk]: false })));
  };

  const ownerOf = (g: AlertGroup) => g.owner ?? '';

  // ── E2.3 triage-state actions ──────────────────────────────────────────
  // Each reuses the one /alerts/assign endpoint (assignAlert), then refreshes
  // the list so the chip/owner update. Assign-to-me and release both change
  // ownership; mark-in-review / mark-done only move the state on an owned rule.
  // Demo blocks every /alerts/assign write; the note lands on the shared ack strip.
  const assignToMe = (g: AlertGroup) => {
    const blocked = demoBlocked(demo);
    if (blocked) { showAckMsg(blocked); return; }
    assignAlert(g.name)
      .then(() => setReloadKey((k) => k + 1))
      .catch(() => showAckMsg(`Failed to assign ${g.name}`));
  };
  const release = (g: AlertGroup) => {
    const blocked = demoBlocked(demo);
    if (blocked) { showAckMsg(blocked); return; }
    assignAlert(g.name, true)
      .then(() => setReloadKey((k) => k + 1))
      .catch(() => showAckMsg(`Failed to release ${g.name}`));
  };
  const setTriage = (g: AlertGroup, state: TriageState) => {
    const blocked = demoBlocked(demo);
    if (blocked) { showAckMsg(blocked); return; }
    assignAlert(g.name, false, state)
      .then(() => setReloadKey((k) => k + 1))
      .catch(() => showAckMsg(`Failed to update ${g.name}`));
  };

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
      hideOptimisticallyAcked(groups ?? [], optimisticAcked, hideAcked)
        .filter((g) => matchView(g, view, me))
        .filter((g) => !filterSevs.length || filterSevs.includes(g.sev))
        .filter(matchesVerdict)
        .sort((a, b) => cmpGroups(a, b, sort.key, sort.dir)),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [groups, view, me, filterSevs, filterVerdicts, sort, optimisticAcked, hideAcked],
  );

  const visIds = visible.map(groupKey);
  // The shared selection hook. Keyed by the STABLE group key, not the list
  // index, for the same reason keyboard focus is: the 10s poll reorders rows
  // under the analyst's cursor.
  const sel = useListSelection(visIds);
  const allSelected = sel.allVisibleSelected;
  // Resolve the focused row from its stable key (see focusedKey). -1 when the
  // key is null or the row is no longer visible — the keyboard layer then no-ops
  // its row actions gracefully.
  const focusedIndex = focusedKey ? visible.findIndex((g) => groupKey(g) === focusedKey) : -1;

  // ---- keyboard-first triage (E2.5): global handler -----------------------
  // (No clamp effect needed: focusedIndex is derived from focusedKey each render,
  // so a vanished or re-sorted focused row is reconciled automatically.)

  // Scroll the keyboard-focused row into view as focus moves.
  useEffect(() => {
    if (focusedIndex < 0) return;
    const g = visible[focusedIndex];
    if (!g) return;
    rowRefs.current[groupKey(g)]?.scrollIntoView({ block: 'nearest' });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusedIndex]);

  // Global keydown for row navigation + actions. Active ONLY when: the command
  // palette is CLOSED (paletteOpen from the shell — the single shared signal, no
  // DOM sniffing), focus is not in an input/textarea/[contenteditable], and no
  // Cmd/Ctrl/Alt modifier is held. The palette owns `/` and Cmd+K; this owns
  // j/k/o/a/e/i/x/?/Enter/Arrows — they can never both fire because a closed
  // palette is a hard precondition here and an open one short-circuits.
  //
  // The guard order + key table live in the PURE `resolveTriageKey` (see
  // lib/triageKeys.ts, unit-tested); this effect is only the adapter: build
  // the context from component state, preventDefault on anything ours, and
  // dispatch to the local handlers.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      // An open investigation drawer is a modal surface — its own Esc handler
      // closes it. Row shortcuts (a/e/x/o/i/j/k) must not act on the list behind
      // it, so short-circuit the whole layer while the drawer is open (the same
      // precondition the palette establishes for these keys).
      if (drawerId) return;
      const g = focusedIndex >= 0 ? visible[focusedIndex] : undefined;
      const action = resolveTriageKey(e, {
        paletteOpen,
        modalOpen,
        keyHelpOpen,
        targetIsEditable: isEditableTarget(e.target as HTMLElement | null),
        rowCount: visible.length,
        hasFocusedRow: g !== undefined,
      });
      if (!action) return; // not ours — leave the key to the browser/palette
      e.preventDefault();
      switch (action.kind) {
        case 'close-help':
          setKeyHelpOpen(false);
          return;
        case 'open-help':
          setKeyHelpOpen(true);
          return;
        case 'move': {
          const nextIdx = nextFocusIndex(focusedIndex, action.delta, visible.length);
          setFocusedKey(visible[nextIdx] ? groupKey(visible[nextIdx]) : null);
          return;
        }
      }
      // Row actions: resolveTriageKey only emits these with hasFocusedRow, so
      // `g` is defined here — the check is for TypeScript narrowing.
      if (!g) return;
      switch (action.kind) {
        case 'open':
        case 'investigate':
          // Same action as the row's primary button: open an existing report or
          // investigate the representative event.
          if (g.invId) openDrawer(g.invId);
          else huntGroup(g);
          return;
        case 'ack':
          ackOneGroup(g);
          return;
        case 'escalate':
          escalateOneGroup(g);
          return;
        case 'toggle-select':
          toggleSelectGroup(g);
          return;
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [paletteOpen, modalOpen, keyHelpOpen, visible, focusedIndex, drawerId]);
  const selCount = sel.count;
  const selectedEventIds = Object.entries(selEvents).filter(([, v]) => v).map(([k]) => k);
  const hasSelection = selCount > 0 || selectedEventIds.length > 0;
  const rowPad = density === 'compact' ? '7px 14px' : '11px 14px';

  // The selection is a PARTITION, computed once and used by every surface that
  // speaks about it — the strip, the Acknowledge label, and both bulk actions.
  //
  // Ticking a group's checkbox also ticks every LOADED event under it, so the
  // expanded rows agree with the header box. Those event ids are already
  // covered by the group, so counting them a second time is double counting:
  // two expanded groups plus three loose events used to print "2 groups · 10
  // events" and submit twelve ids for five things' worth of work. `looseEvents`
  // is the events NOT already covered by a selected group, and it is what the
  // count, the button label and the request all use.
  //
  // `alertsInWindow` is the groups' whole-window fire count — hundreds, often —
  // so it is labelled as such rather than sat next to a loaded-event count as
  // if the two were the same kind of number.
  const selectedGroups = (groups ?? []).filter((g) => sel.isSelected(groupKey(g)));
  const coveredEventIds = new Set(
    selectedGroups.flatMap(
      (g) => ((groupEvents[groupKey(g)] ?? []).map((ev) => ev.id).filter(Boolean) as string[]),
    ),
  );
  const looseEventIds = selectedEventIds.filter((id) => !coveredEventIds.has(id));
  selectedRef.current = selCount + selectedEventIds.length;
  const alertsInWindow = selectedGroups.reduce((n, g) => n + (g.count || 0), 0);

  const toggleSelectAll = () => sel.toggleAll();

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

  // Unknown is not zero. Every number on this screen is derived from `groups`,
  // which is an empty array both before the first load lands and after a failed
  // one — so the header, the view chips and the footer each printed a literal 0
  // for a count the screen never obtained. On a down grid that put
  // "0 untriaged · 0 detections · 0 events in window" directly above this
  // screen's own "Couldn't load this view" card: a false all-clear, which is the
  // one thing worse than a loud error, sitting on the top line a tired analyst
  // scans first. Same convention (and the same shape) as the Dashboard's stat
  // cards: the real number once we have data — INCLUDING a genuine 0, because a
  // quiet shift is a real and common answer — an em-dash for a number we asked
  // for and did not get, an ellipsis while we are still asking. Keyed off
  // `groups`, not off `error`, so stale rows left on screen by a failed
  // background poll keep counts that describe the rows actually rendered.
  const num = (n: number): string => (groups ? n.toLocaleString() : error ? '—' : '…');
  const countOf = (n: number, one: string, many = `${one}s`): string =>
    groups ? plural(n, one, many) : `${num(n)} ${many}`;
  // A chip badge is one glyph wide with no room for that distinction, so an
  // uncounted view carries NO badge rather than a confident "0" one.
  const chipCount = (n: number): number | undefined => (groups ? n : undefined);

  const TABS: Array<{ id: ViewId; label: string; count: number | undefined }> = [
    { id: 'mine', label: 'Mine', count: chipCount(counts.mine) },
    { id: 'inreview', label: 'In review', count: chipCount(counts.inreview) },
    { id: 'critical', label: 'Critical', count: chipCount(counts.critical) },
    { id: 'decision', label: 'Needs decision', count: chipCount(counts.decision) },
    { id: 'all', label: 'All', count: chipCount(counts.all) },
  ];

  // Saved views sit beside the preset tabs in the same chip row: a preset is a
  // view this screen ships with, a saved view is one the analyst named, and
  // there is no reason for them to look like different mechanisms.
  const savedQuery: SavedViewQuery = {
    view,
    sevs: filterSevs,
    verdicts: filterVerdicts,
    hideAcked,
    range: filterTime,
    custom: customRange,
  };
  const views = useSavedViews('alerts', savedQuery, (saved) => {
    // A TOTAL apply: every facet the view names is set, and every facet it does
    // NOT name goes back to this screen's own default — not to an arbitrary
    // empty value. The half-and-half version set view/range only when present
    // while hard-resetting sevs/verdicts/custom, and `!!saved.hideAcked` forced
    // the ON-by-default hide-acked OFF for any view saved before that key
    // existed. A saved view that silently unhides acknowledged alerts is worse
    // than no saved views.
    setView(typeof saved.view === 'string' ? (saved.view as ViewId) : DEFAULT_VIEW);
    setFilterSevs(Array.isArray(saved.sevs) ? (saved.sevs as string[]) : []);
    setFilterVerdicts(Array.isArray(saved.verdicts) ? (saved.verdicts as string[]) : []);
    setHideAcked(typeof saved.hideAcked === 'boolean' ? saved.hideAcked : DEFAULT_HIDE_ACKED);
    setFilterTime(typeof saved.range === 'string' ? saved.range : DEFAULT_RANGE);
    setCustomRange((saved.custom as CustomRange | null) ?? null);
  });

  return (
    <div className="px-[22px] pb-[60px] pt-5">
      {/* header */}
      <div className="mb-4 flex items-end gap-3.5">
        <div>
          <div className="flex items-baseline gap-3">
            <div className="text-title">Alerts</div>
            <Freshness at={lastUpdated} />
          </div>
          <div className="mt-0.5 text-[13px] text-dim">
            {num(untriaged)} untriaged · {countOf(counts.all, 'detection')} ·{' '}
            {countOf(totalEvents, 'event')} in window
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

      {/* The last Bulk Investigate that never started, kept beside the control
          that started it until the next attempt. Mutually exclusive with the
          activity slot below by construction, so the header height stays
          bounded. */}
      {triageError && (
        <div
          role="alert"
          className="mb-3.5 flex items-start gap-2.5 rounded-card border px-3.5 py-2.5 text-[13px]"
          style={{ borderColor: 'rgba(240,68,56,.35)', background: 'rgba(240,68,56,.08)' }}
        >
          <span className="mt-px flex flex-shrink-0 text-danger"><Zap size={15} /></span>
          <div className="min-w-0 flex-1 break-words leading-[1.5] text-text-2">{triageError}</div>
          <button
            onClick={() => setTriageError(null)}
            aria-label="Dismiss"
            className="mt-px flex flex-shrink-0 text-dim hover:text-text"
          >
            <X size={14} />
          </button>
        </div>
      )}

      {/* Activity slot — capacity 1. Only IN-PROGRESS screen work renders here;
          results go to the toaster. Both jobs at once show as two lines in ONE
          bordered strip, never two stacked strips (the header height is bounded
          by construction). */}
      {(triaging || acking) && (
        <div
          className="relative mb-3.5 flex flex-col gap-2 overflow-hidden rounded-card border px-3.5 py-[11px]"
          style={{ borderColor: 'rgba(75,139,245,.35)', background: 'linear-gradient(90deg,rgba(75,139,245,.10),rgba(75,139,245,.02))' }}
        >
          {triaging && (
            <div className="absolute left-0 top-0 h-0.5 w-[40%] animate-scanline" style={{ background: 'linear-gradient(90deg,transparent,#4b8bf5,transparent)' }} />
          )}
          {triaging && (
            <div className="flex items-center gap-[13px]">
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
          {acking && (
            <div className="flex items-center gap-2.5 text-[13px]">
              <Spinner size={14} />
              <span className="font-semibold text-text-2">Acknowledging {ackingCount} group{ackingCount !== 1 ? 's' : ''} ({ackingAlertTotal} alert{ackingAlertTotal !== 1 ? 's' : ''}) in Security Onion…</span>
            </div>
          )}
        </div>
      )}

      {/* The shared list toolbar. The preset tabs became chips in its view row
          so they read as the same mechanism as a saved view — one is a view
          this screen ships with, the other one the analyst named. The selection
          strip takes the facet row's slot, which is where that behaviour came
          from in the first place. */}
      <ListToolbar
        presets={TABS.map((t) => ({ id: t.id, label: t.label, count: t.count, active: view === t.id }))}
        onPreset={(id) => {
          setView(id as ViewId);
          views.clearActive();
        }}
        views={views.views}
        activeViewId={views.activeViewId}
        onApplyView={views.onApplyView}
        onDeleteView={views.onDeleteView}
        onSaveView={views.onSaveView}
        viewError={views.error}
        trailing={
          <>
            {/* density toggle */}
            <div className="flex overflow-hidden rounded-[7px] border border-border-2">
              <button
                onClick={() => setDensity('comfortable')}
                title="Comfortable"
                aria-label="Comfortable density"
                aria-pressed={density !== 'compact'}
                className="flex items-center px-2 py-1.5"
                style={{ color: density !== 'compact' ? '#e6e9ef' : '#7d8896', background: density !== 'compact' ? '#141b25' : 'transparent' }}
              >
                <svg width={15} height={15} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round"><path d="M4 7h16M4 12h16M4 17h16" /></svg>
              </button>
              <button
                onClick={() => setDensity('compact')}
                title="Compact"
                aria-label="Compact density"
                aria-pressed={density === 'compact'}
                className="flex items-center border-l border-border-2 px-2 py-1.5"
                style={{ color: density === 'compact' ? '#e6e9ef' : '#7d8896', background: density === 'compact' ? '#141b25' : 'transparent' }}
              >
                <svg width={15} height={15} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round"><path d="M4 5h16M4 9h16M4 13h16M4 17h16M4 21h16" /></svg>
              </button>
            </div>
            <div className="flex items-center gap-1.5 text-[12.5px] text-dim">
              Sort <span className="font-mono font-semibold text-text">{sort.key} {sort.dir === 'asc' ? '↑' : '↓'}</span>
            </div>
          </>
        }
        selection={
          hasSelection
            ? {
                count: selCount + looseEventIds.length,
                offPageCount: sel.offPageCount,
                onClearOffPage: sel.clearOffPage,
                onClear: () => {
                  sel.clear();
                  setSelEvents({});
                },
                summary: (
                  <span className="font-semibold text-text-2">
                    {selCount > 0 && (
                      <>
                        <span className="font-mono text-accent">{selCount}</span> group{selCount !== 1 ? 's' : ''}
                        <span
                          className="ml-1 text-[11.5px] font-normal text-faint"
                          title="How many times the selected detections fired in the current window. Acknowledging a group covers all of them."
                        >
                          ({alertsInWindow.toLocaleString()} alert{alertsInWindow !== 1 ? 's' : ''} in window)
                        </span>
                      </>
                    )}
                    {selCount > 0 && looseEventIds.length > 0 && <span className="mx-1 text-faint">·</span>}
                    {looseEventIds.length > 0 && (
                      <>
                        <span className="font-mono text-accent">{looseEventIds.length}</span>{' '}
                        {selCount > 0 ? 'more ' : ''}event{looseEventIds.length !== 1 ? 's' : ''}
                      </>
                    )}
                  </span>
                ),
                actions: (
                  <>
                  <button
                    onClick={() => {
                      // Map the selected STABLE group keys back to each group's CURRENT
                      // representative event id (fresh from the latest poll) — that id is
                      // what the triage backend resolves, not the kind:name key.
                      const groupIds = selectedGroups.map((g) => g.id);
                      // looseEventIds, NOT selectedEventIds: an event under a
                      // selected group is already covered by that group's id,
                      // and sending both investigates the same thing twice.
                      const allIds = [...groupIds, ...looseEventIds];
                      if (!allIds.length) return;
                      startTriage(allIds);
                      sel.clear();
                      setSelEvents({});
                    }}
                    className="flex items-center gap-1.5 rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold text-[#cfe0ff]"
                    style={{ background: 'rgba(75,139,245,.14)', borderColor: 'rgba(75,139,245,.4)' }}
                  >
                    <span className="flex" style={{ color: '#facc15' }}><Zap size={13} /></span> Bulk Investigate
                  </button>
                  <button
                    onClick={() => {
                      if (!selectedGroups.length) return;
                      const blocked = demoBlocked(demo);
                      if (blocked) { showAckMsg(blocked); return; } // demo: no doomed write
                      const n = selectedGroups.length;
                      // allSettled: a single assign failing must not silently drop the rest.
                      // Keep failed groups selected so the analyst can retry them.
                      Promise.allSettled(selectedGroups.map((g) => assignAlert(g.name)))
                        .then((outcomes) => {
                          const failedIds = outcomes
                            .map((o, i) => (o.status === 'rejected' ? groupKey(selectedGroups[i]) : null))
                            .filter((id): id is string => id !== null);
                          const ok = n - failedIds.length;
                          sel.select(failedIds);
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
                      if (!selectedGroups.length) return;
                      const blocked = demoBlocked(demo);
                      if (blocked) { showAckMsg(blocked); return; } // demo: no doomed write (before setAcking so the strip shows)
                      const n = selectedGroups.length;
                      const alertTotal = alertsInWindow;
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
                              failedIds.push(groupKey(selectedGroups[i]));
                            }
                          });
                          const failedGroups = failedIds.length;
                          // Clear only the groups that succeeded; retain failed ones for retry.
                          sel.select(failedIds);
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
                    {selectedGroups.length > 0
                      ? `Acknowledge ${selectedGroups.length} group${selectedGroups.length !== 1 ? 's' : ''} · ${alertsInWindow.toLocaleString()} alert${alertsInWindow !== 1 ? 's' : ''}`
                      : 'Acknowledge'}
                  </button>
                  {looseEventIds.length > 0 && (
                    <button
                      disabled={ackingEvents}
                      onClick={async () => {
                        const blocked = demoBlocked(demo);
                        if (blocked) { showAckMsg(blocked); return; } // demo: no doomed write
                        setAckingEvents(true);
                        try {
                          await ackEvents(looseEventIds);
                          setSelEvents({});
                          setReloadKey((k) => k + 1);
                        } finally {
                          setAckingEvents(false);
                        }
                      }}
                      className="rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-1.5 text-[12.5px] font-semibold text-text hover:border-success-btn-border hover:text-success disabled:opacity-50"
                    >
                      {ackingEvents ? 'Acking…' : `Ack ${looseEventIds.length} event${looseEventIds.length !== 1 ? 's' : ''}`}
                    </button>
                  )}
                  </>
                ),
              }
            : undefined
        }
      >
        <TimeRangeFilter
          value={filterTime}
          custom={customRange}
          onChange={(v, r) => {
            setFilterTime(v);
            if (r) setCustomRange(r);
            views.clearActive();
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
          onChange={(v) => {
            setFilterSevs(v);
            views.clearActive();
          }}
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
          onChange={(v) => {
            setFilterVerdicts(v);
            views.clearActive();
          }}
        />
        <button
          onClick={() => {
            setHideAcked((v) => !v);
            views.clearActive();
          }}
          title="Hide acknowledged and escalated groups"
          className="flex items-center gap-1.5 rounded-control border px-[11px] py-[7px] text-[12.5px] font-semibold transition-colors"
          style={
            hideAcked
              ? { borderColor: 'rgba(34,197,94,.5)', background: 'rgba(34,197,94,.10)', color: '#4ade80' }
              : { borderColor: '#1c232e', background: '#0b0e13', color: '#8b94a3' } // border-2 / surface-1 / dim
          }
        >
          <Check size={12} />
          Hide acknowledged
        </button>
        {/* The deep-linked OQL filter, VISIBLE and dismissable. A list narrowed
            by an invisible filter reads as the whole network having only these
            detections — the chip is what keeps the narrowing honest. */}
        {filterQ && (
          <span
            data-testid="alerts-q-chip"
            title="Only detections matching this filter (a host page deep-link). The backend validates the clause; clear it to see every detection."
            className="flex max-w-[420px] items-center gap-1.5 rounded-control border border-accent/40 bg-accent/10 px-[10px] py-[7px] text-[12px] text-accent"
          >
            <Filter size={12} className="flex-none" />
            <span className="min-w-0 truncate font-mono text-[11.5px]">{filterQ}</span>
            <button
              onClick={() => {
                setFilterQ(null);
                views.clearActive();
                // Drop ?q= from the URL too: a reload must not resurrect a
                // filter the analyst just dismissed.
                const next = new URLSearchParams(searchParams);
                next.delete('q');
                setSearchParams(next, { replace: true });
              }}
              aria-label="Clear the alert filter"
              className="flex flex-none items-center hover:text-text"
            >
              <X size={12} />
            </button>
          </span>
        )}
      </ListToolbar>

      {/* Group-hunt (pivot) representative reason — a subtle 12px annotation
          attached beneath the context row, not a standalone strip (DESIGN Q4). */}
      {huntReason && (
        <div className="-mt-2 mb-3.5 flex items-center gap-1.5 text-[12px] text-dim">
          <span className="flex flex-shrink-0" style={{ color: '#a78bfa' }}><Sparkles size={12} /></span>
          <span className="min-w-0 truncate">{huntReason}</span>
          <button
            onClick={() => setHuntReason(null)}
            className="flex-shrink-0 text-faint hover:text-text"
          >
            Clear
          </button>
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
            <Checkbox checked={allSelected} onClick={toggleSelectAll} title="Select all" aria-label="Select all detections" />
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
        {/* The card's own remedy is "retry shortly" — so give it something to
            click. Without onRetry, acting on that advice meant reloading the
            whole page, while the Dashboard's card for the same outage has had a
            Retry button all along. */}
        {error && <div className="p-3"><ErrorState error={error} onRetry={refetch} /></div>}
        {!loading && !error && visible.length === 0 && (
          <div className="px-4 py-10 text-center text-[13px] text-faint">No detections match this view.</div>
        )}

        {visible.map((g, rowIdx) => {
          const gk = groupKey(g);
          const isExp = !!expanded[gk];
          const owner = ownerOf(g);
          const seld = sel.isSelected(gk);
          const kbFocused = rowIdx === focusedIndex;
          return (
            <div key={gk} ref={(el) => { rowRefs.current[gk] = el; }}>
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
                  const loadedEvs = groupEvents[gk] ?? [];
                  const loadedIds = loadedEvs.map((ev) => ev.id).filter(Boolean) as string[];
                  const evSelCount = loadedIds.filter((id) => selEvents[id]).length;
                  const evIndeterminate = evSelCount > 0 && evSelCount < loadedIds.length;
                  return (
                    <div className="flex items-center">
                      <Checkbox
                        checked={seld}
                        indeterminate={evIndeterminate}
                        aria-label={`Select ${g.name}`}
                        onClick={(e) => {
                          e.stopPropagation();
                          const turning = !seld;
                          sel.toggle(gk);
                          setSelEvents((prev) => {
                            const next = { ...prev };
                            if (turning) {
                              (groupEvents[gk] ?? []).forEach((ev) => { if (ev.id) next[ev.id] = true; });
                            } else {
                              (groupEvents[gk] ?? []).forEach((ev) => { if (ev.id) delete next[ev.id]; });
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
                {/* flex-wrap (not overflow-hidden): the E2.3 StateChip drops to
                    a second line in this fixed-width cell rather than clipping
                    at the column edge ("OWN…", "IN REV…"). */}
                <div className="flex min-w-0 flex-wrap items-center gap-1.5">
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
                {/* flex-wrap keeps the action pills INSIDE this cell: when an
                    owned row shows all three (Review/Done/Open report) the
                    overflow wraps to a second line below, never left into the
                    "Last seen" column; each button is nowrap so its own label
                    can't break mid-word. */}
                <div className="flex flex-wrap items-center justify-end gap-1.5">
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
                      className="inline-flex items-center whitespace-nowrap rounded-badge border border-amber-400/40 bg-amber-400/10 px-[9px] py-[3px] font-sans text-[11px] font-semibold text-amber-300 hover:brightness-125"
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
                      className="inline-flex items-center whitespace-nowrap rounded-badge border border-emerald-400/40 bg-emerald-400/10 px-[9px] py-[3px] font-sans text-[11px] font-semibold text-emerald-300 hover:brightness-125"
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
                      disabled={!!huntGroupPending[gk]}
                      aria-label="Retry investigation"
                      title="Last re-run failed — re-investigate the representative event"
                      className="inline-flex items-center gap-1 whitespace-nowrap rounded-badge border px-[9px] py-[3px] font-sans text-[11px] font-semibold disabled:opacity-50"
                      style={{ borderColor: 'rgba(239,68,68,.4)', background: 'rgba(239,68,68,.08)', color: '#f87171' }}
                    >
                      {huntGroupPending[gk] ? <Spinner size={11} color="#f87171" /> : <Zap size={11} />}
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
                      className="inline-flex items-center gap-1 whitespace-nowrap rounded-badge border border-border-input px-[9px] py-[3px] font-sans text-[11px] font-semibold text-accent hover:border-accent hover:bg-[#141b25]"
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
                      disabled={!!huntGroupPending[gk]}
                      title="Investigate the most-representative event in this group"
                      aria-label="Investigate"
                      className="inline-flex items-center gap-1 whitespace-nowrap rounded-badge border px-[9px] py-[3px] font-sans text-[11px] font-semibold disabled:opacity-50"
                      style={{ borderColor: 'rgba(139,92,246,.35)', background: 'rgba(139,92,246,.07)', color: '#a78bfa' }}
                    >
                      {huntGroupPending[gk] ? <Spinner size={11} color="#a78bfa" /> : <Sparkles size={11} />}
                      Investigate
                    </button>
                  )}
                </div>
              </div>

              {/* expanded events (lazy-loaded on first open) */}
              {isExp && (
                <div className="animate-fadeUp-slow border-b border-border-faint bg-bg pb-1.5 pt-1">
                  {eventsLoading[gk] && (
                    <div className="py-2.5 pl-[50px] font-mono text-[11.5px] text-faint">Loading events…</div>
                  )}
                  {!eventsLoading[gk] && (groupEvents[gk]?.length ?? 0) === 0 && (
                    <div className="py-2.5 pl-[50px] font-mono text-[11.5px] text-faint">No events in window.</div>
                  )}
                  {(groupEvents[gk] ?? []).map((ev, i) => {
                    // Resolved once per row: which of these are real values and
                    // which are the backend's "—" placeholder (see pivotTarget).
                    const srcPivot = pivotTarget(ev.src);
                    const dstPivot = pivotTarget(ev.dst);
                    const hostPivot = pivotTarget(ev.host);
                    const hostIpPivot = pivotTarget(ev.hostIp);
                    return (
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
                      {/* src → dst:port — each endpoint pivots to its entity page.
                          The backend sends BARE endpoints (the pivot value); the
                          destination port renders exactly once here, hugging the
                          dst (inside the same span group, outside the flex gap). */}
                      <div className="flex min-w-0 items-center gap-1.5 truncate">
                        {srcPivot ? (
                          <span
                            className="cursor-pointer text-mono-green hover:underline"
                            onClick={() => navigate(`/entity/${encodeURIComponent(srcPivot)}`)}
                            title={`Pivot to ${srcPivot}`}
                          >
                            {ev.src}
                          </span>
                        ) : (
                          <span className="text-mono-green">{ev.src}</span>
                        )}
                        <span className="text-ghost">→</span>
                        <span className="flex min-w-0 items-center truncate">
                          {dstPivot ? (
                            <span
                              className="cursor-pointer truncate text-mono-amber hover:underline"
                              onClick={() => navigate(`/entity/${encodeURIComponent(dstPivot)}`)}
                              title={`Pivot to ${dstPivot}`}
                            >
                              {ev.dst}
                            </span>
                          ) : (
                            <span className="text-mono-amber">{ev.dst}</span>
                          )}
                          {ev.port != null && (
                            <span className="text-faint">:{ev.port}</span>
                          )}
                        </span>
                      </div>
                      {/* The machine the detection fired ON: name, and beneath it
                          the endpoint agent's own address when the backend could
                          resolve one. It lives HERE and not in the flow cell on
                          purpose — a host-shaped detection observed no
                          connection, and rendering the address as an endpoint
                          would invent one. On a flow alert hostIp is absent and
                          this collapses back to the single name line. Both lines
                          pivot independently; for a host detection the address is
                          the only pivot the row has. */}
                      <div className="flex min-w-0 flex-col leading-tight">
                        {hostPivot ? (
                          <span
                            className="cursor-pointer truncate text-dim hover:text-text hover:underline"
                            title={`Pivot to ${hostPivot}`}
                            onClick={() => navigate(`/entity/${encodeURIComponent(hostPivot)}`)}
                          >
                            {ev.host}
                          </span>
                        ) : (
                          <span className="truncate text-dim">{ev.host}</span>
                        )}
                        {hostIpPivot && (
                          <span
                            className="cursor-pointer truncate text-[10px] text-faint hover:text-dim hover:underline"
                            title={`Pivot to ${hostIpPivot}`}
                            onClick={() => navigate(`/entity/${encodeURIComponent(hostIpPivot)}`)}
                          >
                            {hostIpPivot}
                          </span>
                        )}
                      </div>
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
                    );
                  })}
                  {!eventsLoading[gk] && eventsMore[gk] && (
                    <div className="py-1.5 pl-[36px] pr-3.5">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          loadMoreEvents(g);
                        }}
                        disabled={eventsLoadingMore[gk]}
                        className="inline-flex items-center gap-1.5 rounded-badge border border-border-input px-[9px] py-[3px] font-mono text-[11px] font-semibold text-dim hover:text-text disabled:opacity-60"
                        style={{ background: 'rgba(148,163,184,.06)' }}
                      >
                        {eventsLoadingMore[gk] ? <Spinner size={11} /> : <ChevronRight size={12} className="rotate-90" />}
                        {eventsLoadingMore[gk] ? 'Loading…' : 'Load more'}
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
        {countOf(counts.all, 'detection')} · grouped · click a row to expand events
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
        onAcked={onDrawerAcked}
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
  onAcked,
}: {
  drawerId: string | null;
  starting: AlertGroup | null;
  onClose: () => void;
  navigateToPermalink: (id: string) => void;
  onReHunt: (id: string) => void;
  onComplete: () => void;
  onAcked?: (ruleName: string) => void;
}) {
  const [tick, setTick] = useState(0);
  const [cancelling, setCancelling] = useState(false);
  const demo = useDemo(); // demo: cancel is demo-blocked — don't offer it
  const { data: inv, loading, error, refetch } = useAsync<Inv | null>(
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
          {inv?.status === 'investigating' && !demo && (
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
      {error && <div className="p-4"><ErrorState error={error} onRetry={refetch} /></div>}
      {inv && <Investigation inv={inv} layout="drawer" onReHunt={onReHunt} onVerdictApplied={() => setTick((x) => x + 1)} onAcked={onAcked} />}
    </Drawer>
  );
}
