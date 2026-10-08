import {
  AlertTriangle,
  Check,
  ChevronDown,
  ChevronRight,
  CornerDownRight,
  RefreshCw,
  Trash2,
  X,
} from "lucide-react";
import { Fragment, useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { PipelineErrorChip, VerdictPill } from "../components/Badges";
import { isBacktestReplay } from "../components/BacktestReplayChip";
import { FlowBadge } from "../components/FlowBadge";
import { RowTags, TAGS_COLUMN, TagsHeader } from "../components/RowTags";
import { ListToolbar } from "../components/ListToolbar";
import { MultiSelect } from "../components/MultiSelect";
import {
  TimeRangeFilter,
  type CustomRange,
} from "../components/TimeRangeFilter";
import { confidenceText, statusDetail, statusMeta } from "../lib/labels";
import {
  ago,
  agoFromLabel,
  rangeToSinceUntil,
  timeLabel,
} from "../lib/timeRange";
import { Checkbox } from "../components/Controls";
import {
  EmptyState,
  ErrorState,
  Freshness,
  LoadingState,
  StaleNotice,
} from "../components/States";
import {
  deleteInvestigation,
  listInvestigations,
  rehuntInvestigations,
} from "../lib/api";
import {
  errorStateFromSearch,
  verdictFilterFromSearch,
} from "../lib/investigationFilters";
import { plural } from "../lib/plural";
import { CHIP_RUN_CLASS } from "../lib/tooltips";
import { demoBlocked, useDemo } from "../lib/demo";
import { useAsync } from "../lib/useAsync";
import { useListSelection } from "../lib/useListSelection";
import { useSavedViews } from "../lib/useSavedViews";
import { type SortDir, useSort } from "../lib/useSort";
import type {
  InvestigationRow,
  RehuntResult,
  SavedViewQuery,
  Verdict,
} from "../lib/types";

// Raw rehunt skip-reason codes (routes_investigations.py::bulk_rehunt) → friendly
// text. Unknown codes fall through to the raw code so a new backend reason is
// never silently swallowed.
const REHUNT_SKIP_REASONS: Record<string, string> = {
  not_found: "not found",
  no_alert: "no alert to hunt",
  could_not_start: "could not start",
  // Defense in depth — the checkbox for a promoted finding is disabled, so
  // this code should be unreachable from the UI, but a server refusal still
  // deserves a readable reason if it ever fires (e.g. a stale selection).
  hunt_kind: "promoted finding. Re-promote it from the hunt page",
};
const rehuntSkipReason = (code: string): string =>
  REHUNT_SKIP_REASONS[code] ?? code;

/**
 * The per-alert latest-run fields the list endpoint carries (`latestRunId`,
 * `latestRunStatus`, `latestRunWhen` — routes_investigations.py). Declared here
 * because `InvestigationRow` lives in lib/types.ts, which this change does not
 * own; fold them onto the shared interface and drop this widening.
 */
type WithLatestRun = InvestigationRow & {
  latestRunId?: string;
  latestRunStatus?: string;
  latestRunWhen?: string;
};

// How a run that reached no verdict is described when it is somebody ELSE's
// newest run — the phrasing on the row that outlived it. One word for the
// three stops, the word the Status column uses. The chip title names the
// cause.
const LATEST_RUN_FAILURE: Record<string, string> = {
  error: "newest run failed",
  cancelled: "newest run failed",
  interrupted: "newest run failed",
};

/**
 * What happened to this row's alert AFTER this row, when that is worth saying.
 *
 * A re-investigation that dies leaves the older complete run as the alert's
 * representative one — the right rule, it stops failed retries burying the run
 * that landed a verdict, but it meant a re-run started against a down grid
 * vanished into a bare "N earlier" chip while the row went on showing the old
 * healthy verdict (dogfood D8, 2026-08-14). Three re-runs died and the list
 * read calm.
 *
 * Null in the ordinary case — this run IS its alert's newest — and null on a
 * server that predates the fields, which is not the same as "nothing failed"
 * but is the only honest thing an older payload supports. The newest run can
 * only be a run that reached no verdict here: a running or complete one would
 * have taken primacy and be this row.
 */
function latestRunFailure(
  row: InvestigationRow,
): { id: string; label: string; when: string; status: string } | null {
  const r = row as WithLatestRun;
  if (!r.latestRunId || r.latestRunId === row.id) return null;
  const label = LATEST_RUN_FAILURE[r.latestRunStatus ?? ""];
  if (!label) return null;
  return {
    id: r.latestRunId,
    label,
    when: r.latestRunWhen ?? "",
    status: r.latestRunStatus ?? "",
  };
}

// select | detection | verdict | conf | source→dest | status | when | delete.
// Source→Dest gets a real minimum (two full IPv4s + arrow ≈ 220px at 12px mono)
// and grows with spare width — the old fixed 120px clipped the destination to a
// fragment while the verdict/conf/when gutters sat unused (register FR).
// The chips of a row sit in the tags column before the delete gutter. The
// detection cell holds the name and nothing else, so every name starts at the
// same x (owner, 2026-10-07). The flow wraps its two ends onto two lines,
// so its floor holds one address. The table fits a 1280px window and scrolls
// sideways under the sum of the floors.
const GRID = `28px minmax(160px,1.4fr) 132px 52px minmax(120px,1fr) 96px 96px ${TAGS_COLUMN} 44px`;
/** The sum of the column floors, the gaps and the row padding. */
const GRID_MIN_WIDTH = 996;

// One SQL page. The server clamps to its own cap and echoes what it used; this
// is only the size the screen ASKS for.
const PAGE_SIZE = 50;

// A typed query is a new result set, so a keystroke can't fire a request.
// Matches the Hosts screen's cadence.
const SEARCH_DEBOUNCE_MS = 250;

type SortKey = "name" | "verdict" | "conf" | "host" | "status" | "when";

const VERDICT_ORDER: Record<Verdict, number> = {
  true_positive: 0,
  false_positive: 1,
  needs_more_info: 2,
  inconclusive: 3,
  untriaged: 4,
};

const STATUS_ORDER: Record<InvestigationRow["status"], number> = {
  running: 0,
  error: 2,
  interrupted: 3,
  cancelled: 4,
  complete: 5,
};

function cmpRows(
  a: InvestigationRow,
  b: InvestigationRow,
  key: SortKey,
  dir: SortDir,
): number {
  let result = 0;
  switch (key) {
    case "name":
      result = a.name.localeCompare(b.name);
      break;
    case "verdict":
      result = VERDICT_ORDER[a.verdict] - VERDICT_ORDER[b.verdict];
      break;
    case "conf":
      result = (a.conf ?? -1) - (b.conf ?? -1);
      break;
    case "host":
      result = (a.host ?? "").localeCompare(b.host ?? "");
      break;
    case "status":
      result = STATUS_ORDER[a.status] - STATUS_ORDER[b.status];
      break;
    case "when":
      // Sort by raw ISO timestamp for correct chronological order; fall back to
      // empty string (treats missing ts as oldest) if the field is absent.
      result = (a.ts ?? "").localeCompare(b.ts ?? "");
      break;
  }
  return dir === "asc" ? result : -result;
}

// ---------------------------------------------------------------------------
// The landing window
// ---------------------------------------------------------------------------

/** The windows the screen may land on, narrowest first, with their spans. */
const LANDING_WINDOWS: ReadonlyArray<readonly [string, number]> = [
  ["24h", 24 * 3_600_000],
  ["7d", 7 * 24 * 3_600_000],
  ["30d", 30 * 24 * 3_600_000],
];

/**
 * The narrowest landing window that still holds the newest run.
 *
 * A real deployment's investigations are days old, so a screen that opens on
 * an empty 24h reads as an empty product on the first click (dogfood
 * 2026-09-17). Null when there is no run to hold: an empty store keeps the
 * default, and its own empty state explains that in different words.
 *
 * A run older than every preset window gets all time. The widest preset left
 * the list empty over a store that holds runs (dogfood 2026-10-06).
 */
export function landingWindow(
  newest: string | null | undefined,
  now = Date.now(),
): string | null {
  if (!newest) return null;
  const age = now - new Date(newest).getTime();
  if (!Number.isFinite(age)) return null;
  for (const [preset, span] of LANDING_WINDOWS) if (age <= span) return preset;
  return ALL_TIME;
}

/** The window with no lower edge. The query sends no `since`. */
export const ALL_TIME = "all";

/** The presets this list offers: the shared ones and all time. */
const PRESETS = ["15m", "1h", "4h", "24h", "3d", "7d", "30d", ALL_TIME];

/** The active window in words, for the count line. A count with no window
 *  beside it is read as a count of everything. */
export function windowPhrase(range: string): string {
  if (range === ALL_TIME) return "all time";
  if (range === "custom") return "the window you chose";
  const parsed = range.match(/^(\d+)([mhd])$/);
  if (!parsed) return "this window";
  const n = Number(parsed[1]);
  const unit =
    parsed[2] === "m" ? "minute" : parsed[2] === "h" ? "hour" : "day";
  return `the last ${n} ${unit}${n === 1 ? "" : "s"}`;
}

/** The figures over the list, with the backtest replays they leave out or
 *  hold. A backtest replay measures the model on an alert an analyst already
 *  closed. The server leaves replays out of the rows and the figures by
 *  default, and the line names how many it left out. With the replays shown,
 *  the line names how many of the counted runs are replays. On the range, 12
 *  of 14 "true positives" in a week were replays (dogfood 2026-10-06). Over all
 *  time the window reads "in total". */
export function countLine(p: {
  total: number;
  running: number;
  truePositives: number;
  range: string;
  replays: number;
  includesReplays: boolean;
}): string {
  const window =
    p.range === ALL_TIME ? "in total" : `in ${windowPhrase(p.range)}`;
  const base =
    `${plural(p.total, "investigation")} ${window} · ` +
    `${p.running.toLocaleString()} in progress · ${plural(p.truePositives, "true positive")}`;
  if (p.replays <= 0) return base;
  return p.includesReplays
    ? `${base} · includes ${plural(p.replays, "backtest replay")}`
    : `${base} · ${plural(p.replays, "backtest replay")} not counted`;
}

/** What the verdict cell says on a row with no verdict. A dash read as "no
 *  data" on a run that failed, and as nothing on a run still going.
 *
 *  A failed run that is not its alert's primary run has a sibling: a later
 *  run, or an earlier complete one. The row says which. */
export function noVerdictText(r: InvestigationRow): string {
  if (r.status === "running") return "Running";
  const latest = (r as WithLatestRun).latestRunId;
  if (r.isPrimary === false) {
    return latest && latest !== r.id
      ? "Failed. A later run replaced it."
      : "Failed. An earlier run holds the verdict.";
  }
  return "Failed. No run reached a verdict.";
}

/** A host-log alert: a Sigma alert, or any alert on a named machine, with no
 *  destination. Its flow cell read "<address> → " and a dash, which looked
 *  like a lost destination. The cell names the machine. */
export function hostLogMachine(r: InvestigationRow): string | null {
  if (r.dst) return null;
  if (r.kind === "hunt" || r.subjectType === "hunt") return null;
  if (r.hostName) return r.hostName;
  const address = r.host && r.host !== "—" ? r.host : null;
  return r.kind === "sigma" ? address : null;
}

/** The flow cell. A host-log alert names its machine. A flow keeps the pair. */
function FlowCell({ r, dim = false }: { r: InvestigationRow; dim?: boolean }) {
  const machine = hostLogMachine(r);
  if (machine) {
    return (
      <span
        data-testid={`host-log-${r.id}`}
        title={`A host-log alert on ${machine}. It has no network flow.`}
        className={`inline-flex min-w-0 max-w-full flex-wrap items-center gap-x-1 text-[12px] ${dim ? "opacity-70" : ""}`}
      >
        <span className="flex-none text-faint">on</span>{" "}
        <span className="break-all font-mono text-mono-amber">{machine}</span>{" "}
        <span className="flex-none text-faint">· host log</span>
      </span>
    );
  }
  return (
    <span className={dim ? "opacity-70" : ""}>
      <FlowBadge src={r.host === "—" ? null : r.host} dst={r.dst} />
    </span>
  );
}

/** The verdict cell. A row with no verdict says why in words. */
function VerdictCell({ r }: { r: InvestigationRow }) {
  if (r.fallback) return <PipelineErrorChip />;
  if (r.verdict !== "untriaged") return <VerdictPill verdict={r.verdict} />;
  return (
    <span
      data-testid={`no-verdict-${r.id}`}
      title={statusDetail(r.status)}
      className="block text-[11.5px] leading-[1.3] text-faint"
    >
      {noVerdictText(r)}
    </span>
  );
}

/** The status cell. Error, cancelled and interrupted read "Failed", and the
 *  title names the cause. */
function StatusCell({
  status,
  small = false,
}: {
  status: InvestigationRow["status"];
  small?: boolean;
}) {
  const st = statusMeta(status);
  const pulse = status === "running";
  return (
    <span
      data-testid="status-cell"
      className={`inline-flex items-center gap-1.5 ${small ? "text-[11px]" : "text-[11.5px]"}`}
      style={{ color: st.color }}
      title={statusDetail(status)}
    >
      <span
        className={
          "h-1.5 w-1.5 rounded-full " + (pulse ? "animate-pulseDot" : "")
        }
        style={{ background: st.color }}
      />
      {st.label}
    </span>
  );
}

/** The When cell: the shared relative time, and the absolute time with its
 *  zone in the title. The server's own label is the fallback for a row with
 *  no timestamp. */
function WhenCell({
  r,
  className,
}: {
  r: InvestigationRow;
  className: string;
}) {
  const t = r.ts ? timeLabel(r.ts) : { text: agoFromLabel(r.when), title: "" };
  return (
    <div
      className={className}
      title={t.title || undefined}
      data-testid={`when-${r.id}`}
    >
      {t.text}
    </div>
  );
}

export function Investigations() {
  const navigate = useNavigate();
  const location = useLocation();
  // Demo seeded runs span a couple of hours; widen the default window in demo so
  // none age out. useDemo() is false outside a DemoProvider — normal deploys keep
  // 24h. The /demo-status probe resolves async, so the widening happens in an
  // effect below once `demo` flips (the useState initializer runs before it does).
  const demo = useDemo();

  // Seed the Verdict filter from the URL (?verdict=pipeline_error — the
  // Dashboard's pipeline-error KPI deep-links here). Initializer-only: once
  // mounted the MultiSelect owns the state, so clearing the filter works
  // normally and doesn't fight the URL.
  const [filterVerdicts, setFilterVerdicts] = useState<string[]>(() =>
    verdictFilterFromSearch(location.search),
  );
  const [filterStatuses, setFilterStatuses] = useState<string[]>([]);
  // Which half of a pipeline-error set is on screen. The Dashboard tile counts
  // the runs that still need a retry and links here saying so, so the list can
  // reproduce its number instead of sitting at twenty beside a tile reading
  // seven, with a run dismissed seconds earlier rendered identically to a
  // counted one (dogfood 2026-09-07, D2). null means the whole set.
  const [errorState, setErrorState] = useState<string | null>(() =>
    errorStateFromSearch(location.search),
  );
  // Backtest replays are off by default: a replay measures the model on an
  // alert an analyst already closed, and this list is the live work. The
  // server leaves them out of the rows and the header figures unless asked.
  const [showReplays, setShowReplays] = useState(false);
  // Free text, matched SERVER-side against rule name, source and destination.
  // Alerts had a search box and this screen did not, which is half of why the
  // two never read as the same product (dogfood A3). Client-side filtering was
  // never an option here: it is the exact defect the server-side query
  // replaced.
  const [q, setQ] = useState(
    () => new URLSearchParams(location.search).get("q") ?? "",
  );
  const [debouncedQ, setDebouncedQ] = useState(
    () => new URLSearchParams(location.search).get("q") ?? "",
  );
  // A deep link widens the window to the widest preset: the Dashboard KPI counts
  // its 100 most recent runs with NO time filter, so landing on the default 24h
  // could show an empty list for the very rows the link promised.
  const [range, setRange] = useState(() => {
    // A link may name the window it counted over (`?range=30d`), so the page
    // opens on the rows the link promised instead of an empty 24h.
    const wanted = new URLSearchParams(location.search).get("range");
    if (wanted && (wanted === ALL_TIME || /^\d+[mhd]$/.test(wanted)))
      return wanted;
    return verdictFilterFromSearch(location.search).length ? "30d" : "24h";
  });
  // True while the landing window is still the screen's own guess. A link that
  // named a window, and every later pick, owns it instead.
  const [autoWindow] = useState(() => {
    const wanted = new URLSearchParams(location.search).get("range");
    if (wanted && (wanted === ALL_TIME || /^\d+[mhd]$/.test(wanted)))
      return false;
    return verdictFilterFromSearch(location.search).length === 0;
  });
  // The start time of the newest run when the screen widened its own window
  // to hold it. The header says why the window is not 24 hours. Cleared when
  // the analyst picks a window.
  const [widenedFor, setWidenedFor] = useState<string | null>(null);
  const windowChosen = useRef(false);
  useEffect(() => {
    if (demo) {
      windowChosen.current = true;
      setRange("30d");
    }
  }, [demo]);
  const [custom, setCustom] = useState<CustomRange | null>(null);
  // SQL paging offset. Every filter change resets it: page 3 of the old query
  // is a meaningless position in the new one.
  const [offset, setOffset] = useState(0);
  useEffect(() => {
    const t = setTimeout(() => setDebouncedQ(q.trim()), SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [q]);
  // A new query is a new result set — page 3 of the old one means nothing under
  // it. Reset with the DEBOUNCED value so offset and query change in one
  // refetch instead of two.
  useEffect(() => {
    setOffset(0);
  }, [debouncedQ]);
  // Re-apply on a LATER navigation to this screen with a ?verdict= param (the
  // mount initializers above won't re-run). Param absent → no-op, so the
  // operator's manual filter/range changes are never clobbered.
  useEffect(() => {
    const fromUrl = verdictFilterFromSearch(location.search);
    if (fromUrl.length) {
      setFilterVerdicts(fromUrl);
      setErrorState(errorStateFromSearch(location.search));
      windowChosen.current = true;
      setRange("30d");
      setOffset(0);
    }
  }, [location.search]);

  // useAsync captures pauseWhen at setup and can't see `data` there, so track
  // whether any run is still live in a ref and let pauseWhen consult it: stop
  // polling once every run has reached a terminal state. The ref is fed by the
  // server's `active` flag (any running run in the WHOLE store), not by the
  // page: a run outside the current filter can complete INTO it.
  const activeRef = useRef(false);
  // The filters travel to the server and come back as SQL WHERE clauses — the
  // whole point. Filtering the fetched page client-side is how 108 of 109
  // failed runs became unreachable under every filter the operator could set
  // (the newest-100 page was saturated by completed FPs). Array deps are joined
  // so a re-render with equal filters doesn't refetch.
  const { data, loading, error, lastUpdated, failCount, refetch } = useAsync(
    () =>
      listInvestigations({
        ...(range === ALL_TIME ? {} : rangeToSinceUntil(range, custom)),
        verdict: filterVerdicts,
        status: filterStatuses,
        q: debouncedQ || undefined,
        errorState: errorState ?? undefined,
        includeBacktest: showReplays || undefined,
        limit: PAGE_SIZE,
        offset,
      }),
    [
      range,
      custom,
      filterVerdicts.join(","),
      filterStatuses.join(","),
      debouncedQ,
      errorState ?? "",
      showReplays,
      offset,
    ],
    {
      refetchInterval: 10000, // live status (running → complete) without a reload
      pauseWhen: () => !activeRef.current,
    },
  );

  // The landing window, decided once and only when the default came back
  // empty over a store that is not. ONE extra read, for the newest run's
  // timestamp, which is all it takes to name the narrowest window holding it.
  // Nothing is probed when the list already has rows, when the store is
  // empty, or when a link or the operator named the window.
  const probed = useRef(false);
  useEffect(() => {
    if (!autoWindow || windowChosen.current || probed.current) return;
    if (loading || error || !data) return;
    probed.current = true;
    if (data.total > 0 || data.totalAll === 0) return;
    let alive = true;
    listInvestigations({ limit: 1, offset: 0 })
      .then((newest) => {
        if (!alive || windowChosen.current) return;
        const newestTs = newest.rows[0]?.ts ?? null;
        const wider = landingWindow(newestTs);
        if (wider && wider !== range) {
          setRange(wider);
          setWidenedFor(newestTs);
          setOffset(0);
        }
      })
      .catch(() => {
        // The list's own request reports a failed read. A second error line
        // about a window probe would describe machinery, not the outage.
      });
    return () => {
      alive = false;
    };
  }, [autoWindow, data, loading, error, range]);

  // A run started elsewhere (another tab, auto-triage) won't be reflected while
  // this list is idle — so force one refetch when the tab regains focus.
  useEffect(() => {
    const onFocus = () => refetch();
    const onVisible = () => {
      if (document.visibilityState === "visible") refetch();
    };
    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, []);
  // Shared sort mechanics; clicking a new column here starts it ascending.
  const { sort, toggleSort, caret, headerCls, ariaSort } = useSort<SortKey>(
    { key: "when", dir: "desc" },
    "asc",
  );
  const [groupBy, setGroupBy] = useState<"none" | "detection">("none");
  // Alert ids whose earlier (non-primary) runs are expanded inline.
  const [expandedAlerts, setExpandedAlerts] = useState<Record<string, boolean>>(
    {},
  );

  const [rehunting, setRehunting] = useState(false);
  const [rehuntMsg, setRehuntMsg] = useState<string | null>(null);
  // The re-investigate / delete status line is a transient toast, not a
  // permanent banner — auto-dismiss it after a few seconds so it doesn't linger
  // over the list. Errors get a little longer to be read.
  useEffect(() => {
    if (!rehuntMsg) return;
    const isError = /failed/i.test(rehuntMsg);
    const t = setTimeout(() => setRehuntMsg(null), isError ? 8000 : 4500);
    return () => clearTimeout(t);
  }, [rehuntMsg]);
  // Structured rehunt outcome (E2.2): the collapsed "Started N · M skipped"
  // header auto-dismisses like the toast, but once the operator expands the
  // per-id detail it PERSISTS until they collapse or dismiss it — so a mixed
  // batch's "which/why" isn't yanked away mid-read.
  const [rehuntResult, setRehuntResult] = useState<RehuntResult | null>(null);
  const [rehuntExpanded, setRehuntExpanded] = useState(false);
  useEffect(() => {
    if (!rehuntResult || rehuntExpanded) return;
    const t = setTimeout(() => setRehuntResult(null), 6000);
    return () => clearTimeout(t);
  }, [rehuntResult, rehuntExpanded]);
  const [deleting, setDeleting] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);

  const rows = data?.rows ?? [];
  // Server truth, whole store: keep polling while ANY run is live, even one the
  // current filter (or page) excludes — it can complete into the filter set.
  activeRef.current = data?.active ?? false;

  // invId → detection/rule name, for labelling the rehunt result panel (E2.2).
  // The rehunt targets the SOURCE investigation, whose row is still in the list.
  const nameById = new Map(rows.map((r) => [r.id, r.name]));
  const labelForInv = (invId: string): string => {
    const name = nameById.get(invId);
    return name && name.trim() ? name : invId;
  };

  // Filtering happens in SQL — `rows` IS the filter set's page. Only the sort
  // is applied here, and it orders the current page (the server pages by
  // recency; re-sorting a page by name orders that page, not the query).
  const visible = [...rows].sort((a, b) => cmpRows(a, b, sort.key, sort.dir));

  // Header figures come from the server's counts over the SAME filter set as
  // the rows. Tallying the page instead would describe up to PAGE_SIZE rows
  // while reading as the query's — the phantom-untriaged defect, again.
  const total = data?.total ?? 0;
  const totalAll = data?.totalAll ?? 0;
  const running = data?.running ?? 0;
  const tps = data?.truePositives ?? 0;
  const replays = data?.backtestReplays ?? 0;

  // Cluster retries of the SAME alert: surface the canonical (primary) run and
  // tuck earlier/errored/cancelled re-runs under it, so the one that WORKED is
  // never buried under a pile of failed attempts. Retries reveal inline on
  // demand. `isPrimary` is decided by the SERVER over the alert's WHOLE run
  // group (filters change which rows come back, never what primary means) — so
  // a filtered page can hold a retry whose primary is absent. Such a retry is
  // shown TOP-LEVEL: tucking it under a parent that is not here to expand
  // rendered a blank table for the very rows the filter promised (dogfood
  // 2026-07-15 pipeline_error; 2026-08-05 needs_more_info — this rule is those
  // two special cases generalized).
  const primaryAlertsOnPage = new Set(
    visible.filter((r) => r.isPrimary !== false).map((r) => r.alertId ?? ""),
  );
  const promoted = (r: InvestigationRow): boolean =>
    r.isPrimary === false && !primaryAlertsOnPage.has(r.alertId ?? "");
  const retriesByAlert = new Map<string, InvestigationRow[]>();
  for (const r of visible) {
    if (r.isPrimary === false && r.alertId && !promoted(r)) {
      const arr = retriesByAlert.get(r.alertId) ?? [];
      arr.push(r);
      retriesByAlert.set(r.alertId, arr);
    }
  }
  const primaries = visible.filter((r) => r.isPrimary !== false || promoted(r));

  // When grouping, cluster rows by detection name (keeping the user's sort within
  // each group) and precompute per-group counts for the headers.
  const displayRows =
    groupBy === "detection"
      ? [...primaries].sort(
          (a, b) =>
            (a.name || "").localeCompare(b.name || "") ||
            cmpRows(a, b, sort.key, sort.dir),
        )
      : primaries;
  const groupCounts = new Map<string, number>();
  if (groupBy === "detection") {
    for (const r of displayRows) {
      const k = r.name || "(unnamed detection)";
      groupCounts.set(k, (groupCounts.get(k) ?? 0) + 1);
    }
  }

  // Selection: the shared hook, which IS this screen's logic — the other lists
  // now borrow it from here rather than each keeping their own copy. A
  // promoted finding (kind='hunt') is excluded from the eligible id set, not
  // just from the bulk request: passing only eligible ids means select-all
  // skips those rows and the strip's count can never disagree with what the
  // bulk action actually submits (the server's `hunt_kind` rehunt-skip guard
  // stays a defense in depth, not the only guard).
  const bulkEligible = visible.filter((r) => r.kind !== "hunt");

  // The depth chip shows on every row or on none. A chip on some rows only
  // read as a property the other rows lack (dogfood 2026-10-06).
  const showDepth = visible.some(
    (r) => !!r.runClass && r.runClass in CHIP_RUN_CLASS,
  );
  const sel = useListSelection(bulkEligible.map((r) => r.id));
  const selCount = sel.count;

  // Saved views. The filter state travels as one object, so a chip restores the
  // whole set at once — half-applying a view is how a "saved" view stops being
  // the thing that was saved.
  const currentQuery: SavedViewQuery = {
    verdict: filterVerdicts,
    status: filterStatuses,
    range,
    custom,
    q,
    groupBy,
  };
  // A TOTAL apply: a facet the view does not name goes back to THIS screen's
  // default, never to whatever happened to be on screen a moment ago. That is
  // also what makes the chip a real toggle — clicking an active chip applies
  // the EMPTY query, which is this screen unfiltered.
  const views = useSavedViews("investigations", currentQuery, (saved) => {
    setFilterVerdicts(
      Array.isArray(saved.verdict) ? (saved.verdict as string[]) : [],
    );
    setFilterStatuses(
      Array.isArray(saved.status) ? (saved.status as string[]) : [],
    );
    // Same widening the demo gets at mount: the seeded runs span a couple of
    // hours, so resetting the demo to a flat 24h would empty the list.
    windowChosen.current = true;
    setWidenedFor(null);
    setRange(
      typeof saved.range === "string" ? saved.range : demo ? "30d" : "24h",
    );
    setCustom((saved.custom as CustomRange | null) ?? null);
    setQ(typeof saved.q === "string" ? saved.q : "");
    setGroupBy(saved.groupBy === "detection" ? "detection" : "none");
    // A view names no replay facet, so the screen default applies: off.
    setShowReplays(false);
    setOffset(0);
  });

  const handleRehunt = async () => {
    const ids = sel.ids;
    if (!ids.length) return;
    const blocked = demoBlocked(demo);
    if (blocked) {
      setRehuntMsg(blocked);
      return;
    } // demo: no doomed write
    setRehunting(true);
    setRehuntMsg(null);
    setRehuntResult(null);
    setRehuntExpanded(false);
    try {
      // Surface the per-id started/skipped detail the API already returns —
      // "Started N · M skipped" alone hides which ids skipped and why (E2.2).
      setRehuntResult(await rehuntInvestigations(ids));
      sel.clear();
      refetch();
    } catch (err) {
      setRehuntMsg(
        `Re-investigate failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    } finally {
      setRehunting(false);
    }
  };

  // Per-row delete (the discoverable path): a hover trash icon arms an inline
  // confirm in the row, then deletes just that investigation.
  const deleteOne = async (id: string) => {
    setRehuntMsg(null);
    const blocked = demoBlocked(demo);
    if (blocked) {
      setRehuntMsg(blocked);
      setPendingDelete(null);
      return;
    } // demo: no doomed write
    try {
      await deleteInvestigation(id);
      setRehuntMsg("Investigation deleted");
    } catch {
      setRehuntMsg(
        "Delete failed. Cancel a running investigation first. Only an admin can delete.",
      );
    }
    setPendingDelete(null);
    refetch();
  };

  const handleDelete = async () => {
    const ids = sel.ids;
    if (!ids.length) return;
    const blocked = demoBlocked(demo);
    if (blocked) {
      setRehuntMsg(blocked);
      setConfirmDelete(false);
      return;
    } // demo: no doomed write
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
      `Deleted ${ok} investigation${ok !== 1 ? "s" : ""}` +
        (failed
          ? ` · ${failed} failed. Cancel a running investigation first. Only an admin can delete.`
          : ""),
    );
    sel.clear();
    setConfirmDelete(false);
    setDeleting(false);
    refetch();
  };

  return (
    <div className="px-[22px] pb-[60px] pt-5">
      <div className="flex items-baseline gap-3">
        <div className="text-title">Investigations</div>
        <Freshness at={lastUpdated} />
      </div>
      {/* Server-side counts over the active filter set — never the page's.
          The window rides with the count, because the screen may have chosen
          it and a number read as the store's is how "5" becomes "5 ever". */}
      <div
        data-testid="investigations-count"
        className="mb-4 mt-0.5 text-[13px] text-dim"
      >
        <div>
          {countLine({
            total,
            running,
            truePositives: tps,
            range,
            replays,
            includesReplays: data?.includesBacktest ?? showReplays,
          })}
        </div>
        {widenedFor && (
          <div
            data-testid="window-widened"
            className="mt-0.5 text-[12px] text-faint"
          >
            No run started in the last 24 hours. The newest run started{" "}
            {ago(widenedFor)}, so the list shows {windowPhrase(range)}.
          </div>
        )}
      </div>
      {failCount >= 2 && (
        <StaleNotice since={lastUpdated} onRefresh={refetch} className="mb-3" />
      )}

      {/* The shared list toolbar: saved-view chips, the search box, this
          screen's own facets, and the selection strip that takes the facet
          row's slot so the table's top edge stays put. */}
      <ListToolbar
        views={views.views}
        activeViewId={views.activeViewId}
        onApplyView={views.onApplyView}
        onDeleteView={views.onDeleteView}
        onSaveView={views.onSaveView}
        viewError={views.error}
        saveViewUnavailable={views.unavailable}
        search={{
          value: q,
          onChange: (v) => {
            setQ(v);
            views.clearActive();
          },
          placeholder: "Search detection, host or IP",
          label: "Search investigations",
        }}
        note={rehuntMsg}
        selection={{
          count: selCount,
          offPageCount: sel.offPageCount,
          onClearOffPage: sel.clearOffPage,
          onClear: sel.clear,
          actions: (
            <>
              <button
                disabled={rehunting}
                onClick={() => {
                  void handleRehunt();
                }}
                className="flex items-center gap-1.5 rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold text-[#cfe0ff] disabled:opacity-50"
                style={{
                  background: "rgba(75,139,245,.14)",
                  borderColor: "rgba(75,139,245,.4)",
                }}
              >
                <RefreshCw
                  size={12}
                  className={rehunting ? "animate-spin" : ""}
                />
                {rehunting ? "Starting" : `Re-investigate (${selCount})`}
              </button>
              {confirmDelete ? (
                <>
                  <button
                    disabled={deleting}
                    onClick={() => {
                      void handleDelete();
                    }}
                    className="flex items-center gap-1.5 rounded-[7px] border border-danger px-[11px] py-1.5 text-[12.5px] font-semibold text-danger disabled:opacity-50"
                  >
                    <Trash2 size={12} />
                    {deleting ? "Deleting" : `Confirm delete (${selCount})`}
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
                  title="Delete the selected investigations. Only an admin can delete."
                  className="flex items-center gap-1.5 rounded-[7px] border border-border-strong bg-transparent px-[11px] py-1.5 text-[12.5px] font-semibold text-dim hover:border-danger hover:text-danger"
                >
                  <Trash2 size={12} /> Delete
                </button>
              )}
            </>
          ),
        }}
      >
        <TimeRangeFilter
          value={range}
          custom={custom}
          presets={PRESETS}
          onChange={(v, r) => {
            windowChosen.current = true;
            setWidenedFor(null);
            setRange(v);
            if (r) setCustom(r);
            setOffset(0);
            views.clearActive();
          }}
        />
        <MultiSelect
          label="Verdict"
          options={[
            { value: "true_positive", label: "True positive" },
            { value: "false_positive", label: "False positive" },
            { value: "needs_more_info", label: "Needs more info" },
            { value: "inconclusive", label: "Inconclusive" },
            // No 'Untriaged' option — see VERDICT_FILTER_VALUES: an
            // uninvestigated group has no row on this list at all.
            { value: "pipeline_error", label: "Pipeline error" },
          ]}
          value={filterVerdicts}
          onChange={(v) => {
            setFilterVerdicts(v);
            setOffset(0);
            views.clearActive();
          }}
        />
        <MultiSelect
          label="Status"
          options={[
            // The rows read "Failed" for all three stops. The filter keeps
            // them apart, and each option starts with the word the row shows.
            { value: "complete", label: statusMeta("complete").label },
            { value: "running", label: statusMeta("running").label },
            { value: "error", label: "Failed: error" },
            { value: "interrupted", label: "Failed: interrupted" },
            { value: "cancelled", label: "Failed: cancelled" },
          ]}
          value={filterStatuses}
          onChange={(v) => {
            setFilterStatuses(v);
            setOffset(0);
            views.clearActive();
          }}
        />
        {/* Which half of a pipeline-error set is on screen. Only shown when the
            list IS about pipeline errors, because that is the only query where
            "handled" means anything. The Dashboard tile links straight to
            "Needs retry", so its number and this list's header now come off the
            same server query (dogfood 2026-09-07, D2). */}
        {filterVerdicts.includes("pipeline_error") && (
          <div className="flex items-center gap-1 rounded-[7px] border border-border-strong p-[2px]">
            {(
              [
                [
                  "live",
                  "Needs retry",
                  "These runs produced no usable verdict. No operator has handled them. The Dashboard tile counts these runs.",
                ],
                [
                  "handled",
                  "Handled",
                  "An operator dismissed the run, or a later run reached a verdict.",
                ],
                [
                  null,
                  "All errors",
                  "Every run that produced no usable verdict. The list includes the handled runs.",
                ],
              ] as const
            ).map(([value, label, hint]) => (
              <button
                key={label}
                aria-pressed={errorState === value}
                title={hint}
                onClick={() => {
                  setErrorState(value);
                  setOffset(0);
                  views.clearActive();
                }}
                className={
                  "rounded-[5px] px-[9px] py-[3px] text-[12px] font-semibold " +
                  (errorState === value
                    ? "bg-surface-3 text-text"
                    : "text-dim hover:text-text")
                }
              >
                {label}
              </button>
            ))}
          </div>
        )}
        <button
          onClick={() => {
            setGroupBy((g) => (g === "detection" ? "none" : "detection"));
            views.clearActive();
          }}
          title="Group investigations by detection rule"
          className={
            "rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold " +
            (groupBy === "detection"
              ? "border-accent text-accent"
              : "border-border-strong text-dim hover:text-text")
          }
        >
          Group by detection{groupBy === "detection" ? " ✓" : ""}
        </button>
        <button
          data-testid="show-backtest-replays"
          aria-pressed={showReplays}
          onClick={() => {
            setShowReplays((v) => !v);
            setOffset(0);
            views.clearActive();
          }}
          title="Show the investigations that a backtest ran. A replay measures the model on an alert that an analyst closed before. The figures then count the replays."
          className={
            "rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold " +
            (showReplays
              ? "border-accent text-accent"
              : "border-border-strong text-dim hover:text-text")
          }
        >
          Show backtest replays{showReplays ? " ✓" : ""}
        </button>
      </ListToolbar>

      {/* Bulk re-investigate result (E2.2): a collapsed "Started N · M skipped"
          header expands to the per-id detail the API already returns — WHICH
          detections re-ran and WHY each skip happened — so a mixed batch is
          never an opaque count. */}
      {rehuntResult &&
        (() => {
          const started = rehuntResult.started;
          const skipped = rehuntResult.skipped;
          const total = started.length + skipped.length;
          return (
            <div
              className="mb-3.5 overflow-hidden rounded-card border"
              style={{
                borderColor: "rgba(75,139,245,.30)",
                background: "rgba(75,139,245,.06)",
              }}
            >
              <div className="flex items-center gap-2.5 px-3.5 py-2.5 text-[13px]">
                <RefreshCw size={13} className="flex-none text-accent" />
                <button
                  onClick={() => total > 0 && setRehuntExpanded((v) => !v)}
                  disabled={total === 0}
                  className="flex min-w-0 flex-1 items-center gap-2.5 text-left"
                >
                  <span className="min-w-0 break-words font-semibold text-text-2">
                    Started {started.length} re-investigation
                    {started.length !== 1 ? "s" : ""}
                    {skipped.length > 0 ? ` · ${skipped.length} skipped` : ""}
                  </span>
                  {total > 0 && (
                    <span className="flex flex-none items-center gap-1 text-[11.5px] text-dim">
                      {rehuntExpanded ? (
                        <ChevronDown size={13} />
                      ) : (
                        <ChevronRight size={13} />
                      )}
                      {rehuntExpanded ? "Hide detail" : "Show detail"}
                    </span>
                  )}
                </button>
                <button
                  onClick={() => {
                    setRehuntResult(null);
                    setRehuntExpanded(false);
                  }}
                  className="flex flex-none text-dim hover:text-text"
                  aria-label="Dismiss"
                >
                  <X size={14} />
                </button>
              </div>
              {rehuntExpanded && total > 0 && (
                <div className="border-t border-border-faint px-3.5 py-2 text-[12.5px]">
                  {started.map((s) => (
                    <div
                      key={s.invId}
                      className="flex items-center gap-2 py-[3px]"
                    >
                      <Check size={12} className="flex-none text-success" />
                      <span className="min-w-0 break-words text-text-2">
                        {labelForInv(s.invId)}
                      </span>
                      <span className="flex-none text-faint">→ new run</span>
                    </div>
                  ))}
                  {skipped.map((s) => (
                    <div
                      key={s.invId}
                      className="flex items-center gap-2 py-[3px]"
                    >
                      <X size={12} className="flex-none text-faint" />
                      <span className="min-w-0 break-words text-dim">
                        {labelForInv(s.invId)}
                      </span>
                      <span className="flex-none text-faint">
                        {rehuntSkipReason(s.reason)}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })()}

      <div className="overflow-x-auto overflow-y-hidden rounded-card border border-border bg-surface-1">
        <div
          role="row"
          className="grid gap-2.5 border-b border-border bg-surface-2 px-3.5 py-[9px] text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint"
          style={{ gridTemplateColumns: GRID, minWidth: GRID_MIN_WIDTH }}
        >
          <div
            className="flex items-center"
            onClick={(e) => e.stopPropagation()}
          >
            <Checkbox
              checked={sel.allVisibleSelected}
              indeterminate={!sel.allVisibleSelected && sel.someVisibleSelected}
              onChange={sel.toggleAll}
              disabled={bulkEligible.length === 0}
              title={
                bulkEligible.length === 0
                  ? "A bulk re-investigation skips a promoted finding. Re-promote it from the hunt page."
                  : "Select all visible"
              }
            />
          </div>
          <div role="columnheader" aria-sort={ariaSort("name")}>
            <button
              type="button"
              aria-label="Sort by Detection"
              className={`text-left uppercase ${headerCls("name")}`}
              onClick={() => toggleSort("name")}
            >
              Detection{caret("name")}
            </button>
          </div>
          <div role="columnheader" aria-sort={ariaSort("verdict")}>
            <button
              type="button"
              aria-label="Sort by Verdict"
              className={`text-left uppercase ${headerCls("verdict")}`}
              onClick={() => toggleSort("verdict")}
            >
              Verdict{caret("verdict")}
            </button>
          </div>
          <div role="columnheader" aria-sort={ariaSort("conf")}>
            <button
              type="button"
              aria-label="Sort by Conf"
              className={`text-left uppercase ${headerCls("conf")}`}
              onClick={() => toggleSort("conf")}
            >
              Conf{caret("conf")}
            </button>
          </div>
          <div role="columnheader" aria-sort={ariaSort("host")}>
            <button
              type="button"
              aria-label="Sort by Source → Dest"
              className={`text-left uppercase ${headerCls("host")}`}
              onClick={() => toggleSort("host")}
            >
              Source → Dest{caret("host")}
            </button>
          </div>
          <div role="columnheader" aria-sort={ariaSort("status")}>
            <button
              type="button"
              aria-label="Sort by Status"
              className={`text-left uppercase ${headerCls("status")}`}
              onClick={() => toggleSort("status")}
            >
              Status{caret("status")}
            </button>
          </div>
          <div role="columnheader" aria-sort={ariaSort("when")}>
            <button
              type="button"
              aria-label="Sort by When"
              className={`text-left uppercase ${headerCls("when")}`}
              onClick={() => toggleSort("when")}
            >
              When{caret("when")}
            </button>
          </div>
          <TagsHeader className="uppercase" />
          <div />
        </div>

        {loading && <LoadingState />}
        {error && (
          <div className="p-3">
            <ErrorState
              error={error}
              onRetry={refetch}
              label="investigations"
            />
          </div>
        )}
        {/* `totalAll` (whole store) tells an empty STORE apart from a filter
            that matched nothing — the filtered page alone cannot. */}
        {!loading && !error && displayRows.length === 0 && totalAll === 0 && (
          <EmptyState
            title="No investigations yet"
            action={
              <Link
                to="/alerts"
                className="flex items-center gap-1.5 rounded-control border border-accent bg-accent/10 px-3.5 py-1.5 text-[12.5px] font-semibold text-accent hover:bg-accent/20"
              >
                Start from Alerts
              </Link>
            }
          >
            soc-ai runs an investigation on a detection. The investigation pulls
            the evidence, reasons over the evidence and reaches a verdict. Pick
            a detection on the Alerts screen. Auto-Investigate can also work the
            backlog.
          </EmptyState>
        )}
        {!loading && !error && displayRows.length === 0 && totalAll > 0 && (
          <EmptyState
            action={
              range !== ALL_TIME ? (
                <button
                  type="button"
                  onClick={() => {
                    windowChosen.current = true;
                    setWidenedFor(null);
                    setRange(ALL_TIME);
                    setOffset(0);
                    views.clearActive();
                  }}
                  className="rounded-control border border-accent bg-accent/10 px-3.5 py-1.5 text-[12.5px] font-semibold text-accent hover:bg-accent/20"
                >
                  {debouncedQ ? "Search all time" : "Show all time"}
                </button>
              ) : undefined
            }
          >
            {/* Named after the filter in force. "Widen the time range" read as
                the cure also when the cause was the search text (RL13). The
                search names its window too: a search for a run older than the
                window read as a run that does not exist (dogfood 2026-10-06). */}
            {!showReplays && replays > 0
              ? `Only ${plural(replays, "backtest replay")} ${replays === 1 ? "matches" : "match"}. Turn on "Show backtest replays" to see ${replays === 1 ? "it" : "them"}.`
              : debouncedQ
                ? range === ALL_TIME
                  ? "No investigation matches the search."
                  : `No investigation matches the search in ${windowPhrase(range)}.`
                : filterVerdicts.length
                  ? "No investigation matches the verdict filter in this time range."
                  : filterStatuses.length
                    ? "No investigation matches the status filter in this time range."
                    : errorState
                      ? "No investigation matches the pipeline error filter in this time range."
                      : range === "30d" && !custom
                        ? "No investigations in the last 30 days."
                        : "No investigations in this time range. Widen the time range above."}
          </EmptyState>
        )}
        {displayRows.map((r, i) => {
          const failedNewer = latestRunFailure(r);
          const retries = retriesByAlert.get(r.alertId ?? "") ?? [];
          const expanded = !!expandedAlerts[r.alertId ?? ""];
          const groupName = r.name || "(unnamed detection)";
          const showHeader =
            groupBy === "detection" &&
            (i === 0 ||
              (displayRows[i - 1].name || "(unnamed detection)") !== groupName);
          return (
            <Fragment key={r.id}>
              {showHeader && (
                <div className="flex items-center gap-2 border-b border-border bg-surface-2 px-3.5 py-2 text-[12px] font-semibold text-text-2">
                  <span title={groupName} className="min-w-0 break-words">
                    {groupName}
                  </span>
                  <span className="font-mono text-[11px] text-faint">
                    {groupCounts.get(groupName)}
                  </span>
                </div>
              )}
              <div
                onClick={() =>
                  navigate(`/investigation/${r.id}`, {
                    state: { from: "/investigations" },
                  })
                }
                className="group grid cursor-pointer items-center gap-2.5 border-b border-border-faint px-3.5 py-[11px] hover:bg-surface-hover"
                style={{ gridTemplateColumns: GRID, minWidth: GRID_MIN_WIDTH }}
              >
                <div
                  className="flex items-center"
                  onClick={(e) => {
                    e.stopPropagation();
                    if (r.kind === "hunt") return;
                    sel.toggle(r.id);
                  }}
                >
                  <Checkbox
                    checked={sel.isSelected(r.id)}
                    disabled={r.kind === "hunt"}
                    title={
                      r.kind === "hunt"
                        ? "A bulk re-investigation skips a promoted finding. Re-promote it from the hunt page."
                        : "Select"
                    }
                  />
                </div>
                {/* The name and nothing else. The chips of the row sit in the
                  tags column, so every name starts at the same x.
                  A real link, not a span: the row's onClick serves the
                  mouse, and this is what serves the keyboard, a screen
                  reader, a middle-click and a copied address.
                  The whole name shows and wraps in its cell. A character
                  count cut a rule name in the middle, and the browser cut a
                  finding title at the cell width. Both hid the words that
                  tell two rows apart (owner, 2026-10-07). */}
                <div className="min-w-0" data-testid={`inv-title-cell-${r.id}`}>
                  <Link
                    to={`/investigation/${r.id}`}
                    state={{ from: "/investigations" }}
                    onClick={(e) => e.stopPropagation()}
                    title={r.name}
                    data-testid={`inv-name-${r.id}`}
                    className="block min-w-0 whitespace-normal break-words text-[13px] font-medium leading-[1.4] hover:text-accent"
                  >
                    {r.name}
                  </Link>
                </div>
                {/* Only a finished run has a verdict. For running/awaiting/error/
                  cancelled/interrupted rows the Status column carries the state —
                  an "untriaged" pill there reads as a contradiction. A pipeline
                  fallback (E1.2) replaces the amber NMI pill with a distinct
                  pipeline-error chip so infra failures aren't mistaken for
                  genuine "needs more info". */}
                <div>
                  <VerdictCell r={r} />
                </div>
                <div className="font-mono text-[12.5px] text-text-2">
                  {confidenceText(r.conf, "")}
                </div>
                <div className="min-w-0 overflow-hidden">
                  <FlowCell r={r} />
                </div>
                <div>
                  <StatusCell status={r.status} />
                </div>
                <WhenCell r={r} className="font-mono text-[12px] text-dim" />
                {/* The tags, in the one order of every list. The type and
                  the hunt subject say what raised the run and what it read.
                  The synthetic mark keeps a planted attack from reading as
                  real activity. A backtest replay is a measurement. The
                  depth is on every row or on none. Dismissed and Superseded
                  say why the Dashboard tile does not count the row
                  (dogfood 2026-09-07, D2). The newer-run chip says the row is
                  representative but not current, and opens the run that
                  failed. The "N earlier" chip unfolds the earlier runs. */}
                <RowTags
                  testId={`inv-tags-${r.id}`}
                  kind={r.kind}
                  subjectHunt={r.subjectType === "hunt"}
                  subjectTestId={`subject-type-${r.id}`}
                  depth={{
                    runClass: r.runClass,
                    testId: `run-class-${r.id}`,
                    placeholder: showDepth,
                    running: r.status === "running",
                  }}
                  synthetic={r.isSynthEval}
                  replay={isBacktestReplay(r.ranBy)}
                  replayTestId={`backtest-replay-${r.id}`}
                  dismissed={r.errorDismissed}
                  superseded={
                    r.isPrimary === false
                      ? r.status === "complete"
                        ? "A newer run of this alert replaced this run. The newer verdict is the current verdict."
                        : "A later run of this alert reached a verdict. A re-run already fixed this run."
                      : null
                  }
                  links={
                    <>
                      {failedNewer && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/investigation/${failedNewer.id}`, {
                              state: { from: "/investigations" },
                            });
                          }}
                          title={`A newer run of this alert reached no verdict. ${statusDetail(failedNewer.status)} Open the newer run.`}
                          className="flex flex-none items-center gap-[4px] rounded-badge border px-[6px] py-[2px] text-[10.5px] font-semibold"
                          style={{
                            borderColor: "rgba(240,68,56,.45)",
                            background: "rgba(240,68,56,.1)",
                            color: "#fca5a5",
                          }}
                        >
                          <AlertTriangle size={10} />
                          {failedNewer.label}
                          {failedNewer.when && (
                            <span className="font-mono text-faint">
                              {agoFromLabel(failedNewer.when)}
                            </span>
                          )}
                        </button>
                      )}
                      {retries.length > 0 && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setExpandedAlerts((prev) => ({
                              ...prev,
                              [r.alertId ?? ""]: !prev[r.alertId ?? ""],
                            }));
                          }}
                          title={`${retries.length} earlier run${retries.length === 1 ? "" : "s"} of this alert`}
                          className="flex flex-none items-center gap-[3px] rounded-badge border border-border-2 bg-surface-2 px-[6px] py-[2px] font-mono text-[10.5px] text-faint hover:text-text-2"
                        >
                          {expanded ? (
                            <ChevronDown size={11} />
                          ) : (
                            <ChevronRight size={11} />
                          )}
                          {retries.length} earlier
                        </button>
                      )}
                    </>
                  }
                  chatCount={r.chatCount}
                />
                <div
                  className="flex justify-end"
                  onClick={(e) => e.stopPropagation()}
                >
                  {pendingDelete === r.id ? (
                    <div className="flex items-center gap-1.5">
                      <button
                        onClick={() => {
                          void deleteOne(r.id);
                        }}
                        title="Confirm delete"
                        className="flex text-danger hover:opacity-80"
                      >
                        <Check size={14} />
                      </button>
                      <button
                        onClick={() => setPendingDelete(null)}
                        title="Cancel"
                        className="flex text-faint hover:text-text"
                      >
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
                  return (
                    <div
                      key={rt.id}
                      onClick={() =>
                        navigate(`/investigation/${rt.id}`, {
                          state: { from: "/investigations" },
                        })
                      }
                      className="group grid cursor-pointer items-center gap-2.5 border-b border-border-faint bg-surface-2/30 px-3.5 py-[8px] hover:bg-surface-hover"
                      style={{ gridTemplateColumns: GRID, minWidth: GRID_MIN_WIDTH }}
                    >
                      <div />
                      <div className="flex min-w-0 items-center gap-[7px] pl-3 text-faint">
                        <CornerDownRight size={12} className="flex-none" />
                        <Link
                          to={`/investigation/${rt.id}`}
                          state={{ from: "/investigations" }}
                          onClick={(e) => e.stopPropagation()}
                          title="A newer run of this alert replaced this run."
                          className="min-w-0 break-words text-[12px] hover:text-accent"
                        >
                          superseded run
                        </Link>
                      </div>
                      <div>
                        <VerdictCell r={rt} />
                      </div>
                      <div className="font-mono text-[12px] text-faint">
                        {confidenceText(rt.conf, "")}
                      </div>
                      <div className="min-w-0 overflow-hidden">
                        <FlowCell r={rt} dim />
                      </div>
                      <div>
                        <StatusCell status={rt.status} small />
                      </div>
                      <WhenCell
                        r={rt}
                        className="font-mono text-[12px] text-faint"
                      />
                      <RowTags
                        testId={`inv-tags-${rt.id}`}
                        depth={{
                          runClass: rt.runClass,
                          testId: `run-class-${rt.id}`,
                          placeholder: showDepth,
                          running: rt.status === "running",
                        }}
                        synthetic={rt.isSynthEval}
                      />
                      <div
                        className="flex justify-end"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {pendingDelete === rt.id ? (
                          <div className="flex items-center gap-1.5">
                            <button
                              onClick={() => {
                                void deleteOne(rt.id);
                              }}
                              title="Confirm delete"
                              className="flex text-danger hover:opacity-80"
                            >
                              <Check size={14} />
                            </button>
                            <button
                              onClick={() => setPendingDelete(null)}
                              title="Cancel"
                              className="flex text-faint hover:text-text"
                            >
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

        {/* Real pagination over the SQL page (the /hosts pattern): `total` is
            the whole match set, so the range shown is exact, not inferred. */}
        {!loading && !error && total > PAGE_SIZE && (
          <div className="flex items-center justify-between border-t border-border px-3.5 py-2.5">
            <span className="font-mono text-[11.5px] text-faint">
              {`${total === 0 ? 0 : offset + 1} to ${Math.min(offset + PAGE_SIZE, total)} of ${total.toLocaleString()}`}
            </span>
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
                disabled={offset === 0}
                className="rounded-control border border-border-strong px-2.5 py-1 text-[11.5px] font-semibold text-dim hover:text-text disabled:opacity-40"
              >
                Previous
              </button>
              <button
                onClick={() => setOffset(offset + PAGE_SIZE)}
                disabled={Math.min(offset + PAGE_SIZE, total) >= total}
                className="rounded-control border border-border-strong px-2.5 py-1 text-[11.5px] font-semibold text-dim hover:text-text disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
