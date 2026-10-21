import { AlertTriangle, ArrowUpRight, Check, ChevronRight, Filter, Sparkles, X, Zap } from 'lucide-react';
import { KeyHelpOverlay } from '../components/KeyHelpOverlay';
import { chipProps, confidenceText, verdictLabel, verdictMeta } from '../lib/labels';
import { type Dispatch, type RefObject, type SetStateAction, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { KindBadge, PipelineErrorChip, SeverityTag, VerdictPill } from '../components/Badges';
import { FlowBadge } from '../components/FlowBadge';
import { GridGapStrip } from '../components/GridGapStrip';
import { RowTags, TAGS_COLUMN, TagsHeader } from '../components/RowTags';
import { SameFlowChip } from '../components/SameFlowChip';
import { Checkbox } from '../components/Controls';
import { ListToolbar } from '../components/ListToolbar';
import { useListSelection } from '../lib/useListSelection';
import { useSavedViews } from '../lib/useSavedViews';
import { Drawer } from '../components/Drawer';
import { MultiSelect } from '../components/MultiSelect';
import { TimeRangeFilter, type CustomRange } from '../components/TimeRangeFilter';
import { ErrorState, Freshness, LoadingInline, LoadingState, Spinner } from '../components/States';
import { groupOutcome, hideOptimisticallyAcked, outcomeOf } from '../lib/alertFilters';
import { ago } from '../lib/timeRange';
import { MIN_BUCKET, bucketEvents } from '../lib/alertEventBuckets';
import {
  type AckGroupResult,
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
  getAlertsEmptyReason,
  getAutoTriageStatus,
  getInvestigation,
  getMe,
  getRepresentative,
  isRequestTimeout,
  startAutoTriage,
  startHunt,
  stopAutoTriage,
} from '../lib/api';
import { DEMO_ACTION_NOTE, demoBlocked, useDemo } from '../lib/demo';
import {
  ackMessage,
  ackTail,
  ackWroteNothing,
  escalateLinks,
  escalateMessage,
  escalateNamesCase,
  escalateWroteNothing,
} from '../lib/groupWriteMessages';
import { plural } from '../lib/plural';
import { COUNTING } from '../lib/text';
import { type ToastTone, useToast } from '../lib/toast';
import { useAsync } from '../lib/useAsync';
import { isEditableTarget, nextFocusIndex, resolveTriageKey } from '../lib/triageKeys';
import { type SortDir, useSort } from '../lib/useSort';
import type {
  AlertEvent,
  AlertGroup,
  AlertSibling,
  AlertsEmptyReason,
  CaseLink,
  Investigation as Inv,
  SavedViewQuery,
  Severity,
  TriageState,
  Verdict,
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
// The chips of a group sit in the tags column before the actions: the type,
// the handled counts and the "uncounted" mark. The detection cell holds the
// name and the flow line, so every name starts at the same x (owner,
// 2026-10-07). The name wraps whole, so its floor is lower than when it held
// the chips. The table fits a 1280px window and scrolls sideways under the sum
// of the floors.
const GRID = `28px minmax(160px,1fr) 96px 128px 44px 40px 84px ${TAGS_COLUMN} 166px`;
/** The sum of the column floors, the gaps and the row padding. */
const GRID_MIN_WIDTH = 998;

// Per-alert (expanded) event row: checkbox | alert time (abs+rel) | sev |
// src→dst:port | host (+ its address) | verdict provenance (+ when) |
// investigate. Each row now carries the alert's OWN timestamp AND the
// investigation's timestamp. The sev column fits the widest label ("Critical") —
// narrower and the tag bleeds into the src endpoint with zero gap. The host
// column stacks its second line (the endpoint agent's IP, host detections only)
// rather than taking a column of its own: it is absent on every flow alert, so a
// column would be empty on the common case.
// The time column fits "Oct 19, 14:23:05 EDT" (R2-D17). The last column fits
// the row's own Acknowledge beside Investigate (R2-I1).
const EVENT_GRID = '16px 150px 76px minmax(150px,1fr) 116px 196px 206px';

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
  running: 'in progress',
  inherited: 'covered by a prior verdict',
};

// " (8 already triaged, 3 in-flight)" — the per-reason breakdown of a batch's
// skip count, or "" when the backend didn't carry one.
//
// An unmapped code is humanized rather than printed raw: a new backend reason is
// surfaced instead of silently dropped, and a RETIRED one (a historical status
// row can still hold "no_ip") reads as words, not as wire format.
/** The window the header Bulk Investigate sweeps, whatever window the list
 *  shows. The button, the progress line and the summary state it in words,
 *  because the page time filter does not apply to the sweep. */
const SWEEP_RANGE = '24h';
const SWEEP_WORDS = 'last 24 hours';
const SWEEP_HEAD = 'Last 24 hours';

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
// 'unknown' is not in SEV_RANK and must not be: it is the absence of a
// severity, so it has no place among the four. The severity sort groups those
// rows at the END in either direction, the same convention the confidence sort
// already uses for a null. Ranking them 0 would have sunk them below Low on a
// descending sort, which is where they were hiding in the first place.
const isRanked = (sev: string): boolean => sev in SEV_RANK;
// inconclusive sorts with needs_more_info: both are terminal non-committed
// verdicts that still need an analyst decision.
const VERDICT_RANK: Record<string, number> = { true_positive: 6, false_positive: 5, needs_more_info: 4, inconclusive: 3, untriaged: 1 };
// A row that is actively being investigated has no verdict yet (still "untriaged"
// in the DB) but should not interleave with genuinely-untriaged rows when sorting
// by verdict — rank it just above untriaged so triaging rows cluster together.
const TRIAGING_RANK = 2;
// The verdict sort reads the verdict the group counts under, so a true
// positive that later false positives followed sorts with the true positives.
// Runs inside the page window decide that verdict (owner rule, 2026-10-14).
const verdictRank = (g: AlertGroup): number =>
  g.triaging ? TRIAGING_RANK : VERDICT_RANK[groupOutcome(g) ?? g.verdict] ?? 0;

// ---- deep-link seeding ------------------------------------------------------
// Allow-lists for the URL-seeded filters. A value outside its set is DROPPED,
// not applied: a filter the on-screen control can't display is one the operator
// can't clear, so a mangled or stale bookmark would silently hide rows with no
// visible way back.
const SEV_LINK_VALUES = new Set(['critical', 'high', 'medium', 'low', 'unknown']);
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
/** Exactly the preset chips, and so the only views a ?view= (or a saved view)
 * can name. Anything else resolves to the default rather than falling through
 * matchView to "every row": that branch showed the whole list under no
 * highlighted chip, so an analyst who asked for their own queue got the
 * network's detections with no sign the ask had been dropped. */
const VIEW_LINK_VALUES: ReadonlySet<string> = new Set<ViewId>([
  'mine',
  'inreview',
  'critical',
  'decision',
  'all',
]);
const asViewId = (raw: unknown): ViewId =>
  typeof raw === 'string' && VIEW_LINK_VALUES.has(raw) ? (raw as ViewId) : DEFAULT_VIEW;
const DEFAULT_RANGE = '24h';
const DEFAULT_HIDE_ACKED = true;

/** A custom bound as ISO UTC for the API, when it parses. The picker writes a
 *  wall time in the browser zone ("2026-08-25T00:00"), and the chip states it
 *  in that zone. The server reads a bound without an offset in the zone of
 *  Security Onion, so the chip and the query disagreed where the two zones
 *  differ. The URL keeps the value the picker wrote. */
export function utcBound(value: string): string {
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toISOString();
}

function seedFromLink(params: URLSearchParams): {
  sevs: string[];
  verdicts: string[];
  range: string | null;
  custom: CustomRange | null;
  hideAcked: boolean;
  q: string | null;
  sort: { key: SortKey; dir: SortDir } | null;
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
    sort: sortFromLink(params.get('sort')),
  };
}

const SORT_KEYS = new Set<SortKey>(['count', 'detection', 'sev', 'verdict', 'conf', 'latest']);
const DEFAULT_SORT: { key: SortKey; dir: SortDir } = { key: 'sev', dir: 'desc' };

/** `?sort=latest:asc`. Anything else is ignored and the default applies. */
function sortFromLink(raw: string | null): { key: SortKey; dir: SortDir } | null {
  if (!raw) return null;
  const [key, dir] = raw.split(':');
  if (!SORT_KEYS.has(key as SortKey) || (dir !== 'asc' && dir !== 'desc')) return null;
  return { key: key as SortKey, dir };
}

/**
 * Write the filters back into the URL, so a reload or a shared link keeps
 * them. The screen read ?range, ?sev, ?verdict and ?hide_acked and never wrote
 * them, so a reload reset every filter the analyst had set (P8, RL15). A value
 * at its default leaves the URL; every other parameter (view, drawer, q) stays.
 */
function writeFiltersToParams(
  params: URLSearchParams,
  f: {
    range: string;
    custom: CustomRange | null;
    sevs: string[];
    verdicts: string[];
    hideAcked: boolean;
    sort: { key: SortKey; dir: SortDir };
  },
): URLSearchParams {
  const next = new URLSearchParams(params);
  const put = (k: string, v: string | null) => (v ? next.set(k, v) : next.delete(k));
  const custom = f.range === 'custom' && f.custom ? f.custom : null;
  put('range', custom ? 'custom' : f.range === DEFAULT_RANGE ? null : f.range);
  put('from', custom ? custom.from : null);
  put('to', custom ? custom.to : null);
  put('sev', f.sevs.length ? f.sevs.join(',') : null);
  put('verdict', f.verdicts.length ? f.verdicts.join(',') : null);
  put('hide_acked', f.hideAcked === DEFAULT_HIDE_ACKED ? null : String(f.hideAcked));
  const sortIsDefault = f.sort.key === DEFAULT_SORT.key && f.sort.dir === DEFAULT_SORT.dir;
  put('sort', sortIsDefault ? null : `${f.sort.key}:${f.sort.dir}`);
  return next;
}

/** Stable per-detection identity for client-side row state (expansion,
 * selection, keyboard focus, refs). The backend sets `g.id` to the NEWEST
 * event's ES `_id`, which changes on every 10s poll as new events land —
 * keying row state on it orphans that state each refresh (an expanded group
 * collapses, a ticked checkbox drops). kind+name is the identity every write
 * path already addresses a group by (ackGroup / assignAlert take `g.name`).
 * `g.id` is kept only as the representative-event payload for a new hunt. */
const groupKey = (g: Pick<AlertGroup, 'kind' | 'name'>): string => `${g.kind}:${g.name}`;

/** What a group write needs to know about its target. The drawer has only the
 *  investigation's name and type, so the counts and owner are optional. */
type GroupRef = Pick<AlertGroup, 'name' | 'kind'> &
  Partial<Pick<AlertGroup, 'owner' | 'ackedCount' | 'escalatedCount' | 'cases' | 'casesComplete'>>;

/** The count chip for a group's already-handled events — or the absence of one.
 *
 * Three states, because there are three: a number the grid stands behind, a
 * zero that needs no chip at all, and `null`, which is the grid saying it
 * cannot count. Elastic Defend's endpoint alert index does not map
 * `event.acknowledged` or `event.escalated` as searchable fields, so the
 * aggregation these come from answers 0 for a group an analyst cleared this
 * morning exactly as it does for one nobody has opened. Drawing a green check
 * from that 0 — or, worse, drawing nothing and letting the row read as
 * untouched — is the console asserting something it does not know.
 *
 * So `null` gets its own faint chip with the question in the tooltip, and it
 * points at the one place the answer does exist: each event carries the flag in
 * its own document, which the expanded group shows. */
function HandledChip({
  count,
  icon,
  colour,
  known,
  cases,
}: {
  count: number | null | undefined;
  icon: React.ReactNode;
  colour: { borderColor: string; background: string; color: string };
  known: (n: number) => string;
  /** The cases the counted alerts are on. The chip links to the first case
   *  with a page in the Security Onion console (R2-I2). */
  cases?: CaseLink[];
}) {
  const cls =
    'inline-flex flex-shrink-0 items-center gap-[3px] rounded-chip border px-[5px] py-[2px] font-mono text-[10px] font-semibold';
  // An unknown count draws no chip of its own. Two "?" chips on every
  // endpoint row explained nothing (dogfood 2026-10-06, first hour C7). The
  // row shows one "uncounted" chip in their place, with the reason.
  if (count === null) return null;
  if (!count || count <= 0) return null;
  const linked = (cases ?? []).find((c) => !!c.url);
  if (linked?.url) {
    const others = (cases ?? []).filter((c) => c.id !== linked.id).map((c) => c.id);
    const label =
      `${known(count)}. Open case ${linked.id} in Security Onion.` +
      (others.length ? ` soc-ai found ${others.length === 1 ? 'case' : 'cases'} ${others.join(', ')} too.` : '');
    return (
      <a
        href={linked.url}
        target="_blank"
        rel="noopener noreferrer"
        aria-label={label}
        title={label}
        onClick={(e) => e.stopPropagation()}
        className={`${cls} hover:brightness-125 hover:underline`}
        style={colour}
      >
        {icon}
        {count}
      </a>
    );
  }
  return (
    <span title={known(count)} className={cls} style={colour}>
      {icon}
      {count}
    </span>
  );
}

/** Why a row shows no handled counts: the index of the detection cannot
 *  search the flags. */
export const COUNTS_UNKNOWN =
  'Security Onion cannot count the acknowledged and escalated alerts of this detection. The index of this detection cannot search the flags. Expand the group to see what each event says.';

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

/** The time of an event row: the date, the 24 h clock time and, unless
 *  `zone` is false, the zone of the browser ("Oct 19, 14:23:05 EDT"). A clock
 *  time alone was ambiguous in a 30 day window, and a run of events read
 *  "08:27:23 PM to 06:20:57 AM" across two days (dogfood 2026-10-19, R2-D17).
 *  The year is in the title. */
function eventStamp(iso?: string, zone = true): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
    ...(zone ? { timeZoneName: 'short' as const } : {}),
  });
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
  // The verdict leads the chip, in its own colour: "True positive 0.62, 4d
  // ago". The chip said "inherited 4d ago" with no verdict, so a true
  // positive inside a group read like every other event (dogfood 2026-10-06).
  const verdict = ev.verdict ? verdictMeta(ev.verdict) : null;
  const label = verdict
    ? `${verdict.label}${ev.conf != null ? ` ${confidenceText(ev.conf)}` : ''}${when ? `, ${when}` : ''}`
    : when
      ? `${kind} ${when}`
      : kind;
  const tone = verdict
    ? { borderColor: verdict.border, background: verdict.bg, color: verdict.color }
    : green
      ? { borderColor: 'rgba(34,197,94,.35)', background: 'rgba(34,197,94,.08)', color: '#4ade80' }
      : { borderColor: 'rgba(148,163,184,.25)', background: 'rgba(148,163,184,.07)', color: '#94a3b8' };
  const how = green ? 'The investigation covers this exact event. Open the report.' : null;
  const title = verdict
    ? `${ev.inheritedReason ?? how ?? ''} ${green ? 'Investigated directly.' : 'Inherited.'}`.trim()
    : ev.inheritedReason ?? how ?? '';
  const cls =
    'inline-flex min-w-0 max-w-full items-center gap-0.5 flex-wrap rounded-chip border px-[6px] py-[2px] font-mono text-[9.5px] font-semibold';
  if (ev.invId) {
    return (
      <button
        type="button"
        onClick={(e) => { e.stopPropagation(); onOpen(ev.invId!); }}
        title={title}
        className={`${cls} hover:brightness-125`}
        style={tone}
      >
        <span className="break-words">{label}</span>
        <ArrowUpRight size={9} strokeWidth={2.5} className="flex-shrink-0" />
      </button>
    );
  }
  return (
    <span title={title} className={`${cls} cursor-help`} style={tone}>
      <span className="break-words">{label}</span>
    </span>
  );
}

/** "1 true positive, 8 false positives": the verdict counts of a group, worst
 *  first, in the words lib/labels.ts gives each verdict. */
export function verdictCountsLine(counts: Record<string, number> | undefined): string {
  const order = ['true_positive', 'needs_more_info', 'inconclusive', 'false_positive'];
  const keys = Object.keys(counts ?? {}).sort(
    (a, b) => (order.indexOf(a) + 1 || 99) - (order.indexOf(b) + 1 || 99),
  );
  return keys
    .filter((k) => (counts?.[k] ?? 0) > 0)
    .map((k) => {
      const n = counts![k];
      const word = verdictLabel(k).toLowerCase();
      // "needs more info" reads "need more info" for more than one.
      const noun = n === 1 ? word : word === 'needs more info' ? 'need more info' : `${word}s`;
      return `${n} ${noun}`;
    })
    .join(', ');
}

/** What the row pill of a group shows. A group counts under the worst verdict
 *  among its runs in the page window (owner rule, 2026-10-14), and the pill
 *  shows that verdict. A group with no run in the window shows its standing
 *  verdict, inherited, with the age of the run behind it.
 *
 *  An older server sends no window verdict. The pill then keeps the standing
 *  verdict, and "inherited" means that the run investigated another alert of
 *  the group. */
interface RowPill {
  verdict: Verdict;
  conf: number | null;
  /** The run the pill opens. */
  invId: string | null;
  inherited: boolean;
  /** "3d ago", the age of an inherited verdict. */
  when: string | null;
  title: string | undefined;
}

function rowPill(g: AlertGroup): RowPill {
  const o = outcomeOf(g);
  if (g.windowVerdict === undefined || o.verdict === null) {
    return {
      verdict: g.verdict,
      conf: g.conf,
      invId: g.invId ?? null,
      inherited: g.inherited,
      when: inheritedWhen(g.inheritedReason),
      title: g.inherited
        ? g.inheritedReason ?? 'This verdict comes from an earlier investigation of this detection.'
        : undefined,
    };
  }
  if (o.inherited) {
    const when = o.at ? ago(o.at) : null;
    return {
      verdict: o.verdict,
      conf: o.conf,
      invId: o.invId,
      inherited: true,
      when,
      title:
        'No investigation of this detection ran in this window. The verdict comes from the newest ' +
        `earlier run${when ? `, ${when}` : ''}. Open the investigation.`,
    };
  }
  return {
    verdict: o.verdict,
    conf: o.conf,
    invId: o.invId,
    inherited: false,
    when: null,
    title: 'The worst verdict among the runs in this window. Open the investigation.',
  };
}

/** The confidence column of a row: the confidence of the verdict on the pill. */
function rowConf(g: AlertGroup): number | null {
  return g.fallback ? g.conf : rowPill(g).conf;
}

/** The window verdict of a group as a chip that opens its run, when the pill
 *  shows something else, and the count of each verdict. Both describe the
 *  runs inside the page window only. Nothing when the group holds one verdict
 *  and the pill already shows it. */
function VerdictMix({
  g,
  shown,
  onOpen,
}: {
  g: AlertGroup;
  /** The verdict on the pill, or null for the pipeline-error chip. */
  shown: Verdict | null;
  onOpen: (id: string) => void;
}) {
  const counts = g.verdictCounts ?? {};
  const kinds = Object.values(counts).filter((n) => n > 0).length;
  const o = outcomeOf(g);
  const chipVerdict = o.verdict && o.verdict !== 'untriaged' && !o.inherited && o.verdict !== shown ? o.verdict : null;
  if (!chipVerdict && kinds < 2) return null;
  const line = verdictCountsLine(counts);
  const chip = chipVerdict ? verdictMeta(chipVerdict) : null;
  return (
    <span className="flex min-w-0 flex-wrap items-center gap-1" data-testid="verdict-mix">
      {chip && chipVerdict && (
        <button
          type="button"
          disabled={!o.invId}
          onClick={(e) => {
            e.stopPropagation();
            if (o.invId) onOpen(o.invId);
          }}
          title={`${counts[chipVerdict] ?? 1} ${chip.label.toLowerCase()} in this window. Open the investigation.`}
          {...chipProps(chip, { className: 'enabled:hover:brightness-125 disabled:cursor-default' })}
        >
          {chip.label}
          {o.conf != null ? ` ${confidenceText(o.conf)}` : ''}
        </button>
      )}
      {line && (
        <span
          className="break-all font-mono text-[10.5px] text-faint"
          title="The verdict of each alert of this group with a run in this window."
        >
          {line}
        </span>
      )}
    </span>
  );
}

/** Secondary, subtle red hint next to a group's standing verdict chip (E2.1):
 * the last RE-RUN of this rule crashed (error/cancelled/interrupted) or fell
 * back, while the real verdict still stands. Answers the "stayed at Needs Info"
 * mystery — the verdict chip stays primary; this is a quiet warning. */
/** The analyst verdict on the alert behind the row, when the pill shows
 *  another run. A newer model run hid it: the row read "False positive"
 *  while the analyst true positive stood (V1-A3). */
export function analystHint(
  g: Pick<AlertGroup, 'analystVerdict' | 'analystBy' | 'analystInvId'>,
  shownInvId: string | null,
): { text: string; title: string; invId: string } | null {
  if (!g.analystVerdict || !g.analystInvId || g.analystInvId === shownInvId) return null;
  const word = verdictLabel(g.analystVerdict).toLowerCase();
  return {
    text: `· analyst: ${word}`,
    title: `${g.analystBy || 'An analyst'} set the verdict of this alert to ${word} on another run. Open that run.`,
    invId: g.analystInvId,
  };
}

function LastRetryHint({ attempt }: { attempt: NonNullable<AlertGroup['lastAttempt']> }) {
  // "fallback" reads as "failed" for the operator; the other statuses name the
  // terminal state directly ("error"/"cancelled"/"interrupted").
  const label = attempt.status === 'fallback' ? 'failed' : attempt.status;
  const outcome = attempt.status === 'fallback' ? 'failed with a pipeline fallback' : `ended in ${attempt.status}`;
  return (
    <span
      title={`The last re-run of this detection ${outcome} ${attempt.ago} ago. The standing verdict comes from an earlier run.`}
      className="flex min-w-0 items-center flex-wrap font-mono text-[10.5px] font-semibold text-danger"
    >
      <span className="break-words">· last retry {label} {attempt.ago} ago</span>
    </span>
  );
}

/** Format an ISO timestamp as a human-readable absolute time for a tooltip,
 * with the zone of the browser (R2-D17). Falls back to the raw string if it
 * isn't parseable. */
function absTime(iso?: string): string | undefined {
  if (!iso) return undefined;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    timeZoneName: 'short',
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
      // Unranked (no severity on the document) sorts last in either direction.
      if (!isRanked(a.sev) || !isRanked(b.sev)) {
        if (isRanked(a.sev) === isRanked(b.sev)) return 0;
        return isRanked(a.sev) ? -1 : 1;
      }
      result = SEV_RANK[a.sev] - SEV_RANK[b.sev];
      break;
    case 'verdict':
      result = verdictRank(a) - verdictRank(b);
      break;
    case 'conf': {
      // The confidence on screen, the one of the verdict on the pill. null
      // sorts last in either direction.
      const ac = rowConf(a);
      const bc = rowConf(b);
      if (ac == null && bc == null) result = 0;
      else if (ac == null) result = 1;
      else if (bc == null) result = -1;
      else result = ac - bc;
      break;
    }
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
    case 'decision': {
      // Non-committed verdicts: NMI + inconclusive (terminal hedges) + untriaged,
      // by the verdict the group counts under in this window. A pipeline error
      // counts under no verdict, and it still waits on the analyst.
      const v = groupOutcome(g);
      return v === null || v === 'needs_more_info' || v === 'inconclusive' || v === 'untriaged';
    }
    default:
      return true;
  }
}

function EventRow({ ev, g, selEvents, setSelEvents, navigate, openDrawer, huntEvent, ackState, onAck }: {
  ev: AlertEvent;
  g: AlertGroup;
  selEvents: Record<string, boolean>;
  setSelEvents: Dispatch<SetStateAction<Record<string, boolean>>>;
  navigate: ReturnType<typeof useNavigate>;
  openDrawer: (id: string) => void;
  huntEvent: (g: AlertGroup, ev: AlertEvent) => void;
  /** This session's acknowledge of the event: in flight, or written. */
  ackState?: 'pending' | 'done';
  onAck: (ev: AlertEvent) => void;
}) {
  // Resolved once per row: which of these are real values and
  // which are the backend's "—" placeholder (see pivotTarget).
  const srcPivot = pivotTarget(ev.src);
  const dstPivot = pivotTarget(ev.dst);
  const hostPivot = pivotTarget(ev.host);
  const hostIpPivot = pivotTarget(ev.hostIp);
  // The name of the row in its controls: the time of the alert, else its id.
  // The visible label of the Acknowledge button is the same for every row.
  const stamp = eventStamp(ev.ts);
  const which = stamp ? `at ${stamp}` : (ev.id ?? '');
  return (
    <div
      className="grid items-center gap-2.5 py-[7px] pl-[36px] pr-3.5 font-mono text-[11.5px] hover:bg-surface-2"
      style={{ gridTemplateColumns: EVENT_GRID }}
    >
      {/* per-event checkbox. It had no accessible name (R2-D18). */}
      <div onClick={(e) => e.stopPropagation()}>
        <Checkbox
          checked={!!(ev.id && selEvents[ev.id])}
          onChange={(checked) => {
            if (!ev.id) return;
            setSelEvents((prev) => ({ ...prev, [ev.id!]: checked }));
          }}
          onClick={(e) => e.stopPropagation()}
          aria-label={`Select the event ${which}`.trim()}
        />
      </div>
      {/* this alert's OWN timestamp: date, clock time, zone + relative age */}
      <div className="flex min-w-0 flex-col leading-tight" title={absTime(ev.ts) ?? ev.ts ?? ''}>
        <span data-testid="event-time" className="break-words text-text-2">{eventStamp(ev.ts) || '—'}</span>
        {ev.ago && <span className="text-[10px] text-faint">{ev.ago} ago</span>}
      </div>
      {/* severity */}
      <div><SeverityTag sev={(ev.sev ?? 'unknown') as Severity} /></div>
      {/* src → dst:port — each endpoint pivots to its entity page.
          The backend sends BARE endpoints (the pivot value); the
          destination port renders exactly once here, hugging the
          dst (inside the same span group, outside the flex gap). */}
      <div className="flex min-w-0 items-center gap-1.5 flex-wrap">
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
        <span className="flex min-w-0 items-center flex-wrap">
          {dstPivot ? (
            <span
              className="cursor-pointer break-words text-mono-amber hover:underline"
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
            className="cursor-pointer break-words text-dim hover:text-text hover:underline"
            title={`Pivot to ${hostPivot}`}
            onClick={() => navigate(`/entity/${encodeURIComponent(hostPivot)}`)}
          >
            {ev.host}
          </span>
        ) : (
          <span className="break-words text-dim">{ev.host}</span>
        )}
        {hostIpPivot && (
          <span
            className="cursor-pointer break-words text-[10px] text-faint hover:text-dim hover:underline"
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
      {/* acknowledge or investigate this exact event. The Ack took four
          steps through the selection and the bulk bar (R2-I1). */}
      <div className="flex items-center justify-end gap-1.5">
        {ev.id && (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              onAck(ev);
            }}
            disabled={!!ackState}
            aria-label={`${ackState === 'done' ? 'Acknowledged' : 'Acknowledge'} the event ${which}`.trim()}
            title={
              ackState === 'done'
                ? 'Security Onion acknowledged this event.'
                : 'Acknowledge this event in Security Onion.'
            }
            aria-busy={ackState === 'pending' || undefined}
            className={`inline-flex items-center whitespace-nowrap rounded-badge border px-[7px] py-[3px] font-sans text-[11px] font-semibold ${
              ackState === 'done'
                ? 'border-success-btn-border text-success'
                : 'border-border-strong text-dim enabled:hover:border-success-btn-border enabled:hover:text-success disabled:opacity-60'
            }`}
          >
            {ackState === 'done' ? 'Acknowledged' : 'Acknowledge'}
          </button>
        )}
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
}

const WIDEST_RANGE = '30d';

/** The windows the screen may widen to on landing, narrowest first. */
const LANDING_WINDOWS = ['7d', '30d'] as const;

/** True when the landing window `wider` is wider than `range`. Every preset
 *  under 7 days is narrower than both. An empty custom range is offered both
 *  too, and the probe picks the narrowest that holds a detection. */
function widerThan(wider: (typeof LANDING_WINDOWS)[number], range: string): boolean {
  if (range === WIDEST_RANGE) return false;
  if (range === '7d') return wider === '30d';
  return true;
}

/** "7d" as "7 days", "24h" as "24 hours", for a sentence. */
function windowWords(range: string): string {
  const m = range.match(/^(\d+)([mhd])$/);
  if (!m) return 'the window you chose';
  const n = Number(m[1]);
  const unit = m[2] === 'm' ? 'minute' : m[2] === 'h' ? 'hour' : 'day';
  return `${n} ${unit}${n === 1 ? '' : 's'}`;
}

/** "Oct 19, 14:05 EDT", the local date and time of a read, with the zone
 *  (R2-D17). */
function readTime(ms: number): string {
  return new Date(ms).toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
    timeZoneName: 'short',
  });
}

/**
 * Why the list is empty, named after the narrowest filter in force. "Widen the
 * time range" was the only answer, also where the cause was the Mine view, the
 * verdict filter or the query, and also at the widest window (D16, P9, RL13).
 */
function emptySentence(f: {
  view: ViewId;
  sevs: string[];
  verdicts: string[];
  q: string | null;
  hideAcked: boolean;
  widest: boolean;
}): string {
  switch (f.view) {
    case 'mine':
      return 'No detection is assigned to you in this window.';
    case 'inreview':
      return 'No detection is in review in this window.';
    case 'critical':
      return 'No critical detection fired in this window.';
    case 'decision':
      return 'No detection needs a decision in this window.';
    default:
      break;
  }
  if (f.q) return 'No detection matches the query filter in this window.';
  if (f.verdicts.length) return 'No detection matches the verdict filter in this window.';
  if (f.sevs.length) return 'No detection matches the severity filter in this window.';
  const tail = f.widest ? '' : ' Widen the time range.';
  if (f.hideAcked) {
    return `No open detection in this window. The list hides acknowledged and escalated groups.${tail}`;
  }
  return `No detection fired in this window.${tail}`;
}

/** A group write the console stopped waiting for, with the group's state at
 *  the press. The poll compares the rows against it to see the write land. */
interface PendingWrite {
  kind: 'ack' | 'escalate' | 'assign' | 'release';
  name: string;
  toastId: number;
  /** The filter the press ran under. A row that leaves the list under a
   *  different filter says nothing about the write. */
  queryKey: string;
  owner: string;
  acked: number | null;
  escalated: number | null;
}

const WRITE_NOUN: Record<PendingWrite['kind'], string> = {
  ack: 'acknowledgement',
  escalate: 'escalation',
  assign: 'assignment',
  release: 'release',
};

/** True when the polled row shows the timed-out write took effect. A row that
 *  left the list counts only for ack and escalate, and only under the filter
 *  of the press: hide-acknowledged drops a handled group from the list. */
function writeLanded(
  p: PendingWrite,
  g: AlertGroup | undefined,
  queryKey: string,
  me: string,
): boolean {
  if (p.queryKey !== queryKey) return false;
  switch (p.kind) {
    case 'ack':
      return !g || (g.ackedCount != null && g.ackedCount > (p.acked ?? 0));
    case 'escalate':
      return !g || (g.escalatedCount != null && g.escalatedCount > (p.escalated ?? 0));
    case 'assign':
      return !!g && !!g.owner && g.owner !== p.owner && (!me || g.owner === me);
    case 'release':
      return !!g && !g.owner;
  }
}

/** The tone of an ack answer. A press that wrote nothing is not a success,
 *  and the green check said it was (R2-D15). */
function ackTone(r: AckGroupResult): ToastTone {
  if (r.failed > 0) return 'danger';
  return ackWroteNothing(r) ? 'info' : 'success';
}

/** The message and the tone after a bulk ack of more than one group.
 *
 *  Groups that wrote nothing are said apart from the groups that wrote. The
 *  already-acknowledged tail counts only the groups that wrote: a group that
 *  wrote nothing read its handled alerts again without the hide filter, so
 *  the "cannot hide them" sentence of the tail is not true of it. */
export function bulkAckMessage(
  answered: Array<{ g: AlertGroup; r: AckGroupResult }>,
  failedGroups: number,
  timedOut: number,
): [string, ToastTone] {
  const wrote = answered.filter(({ r }) => !ackWroteNothing(r));
  const idle = answered.filter(({ r }) => ackWroteNothing(r));
  const acked = wrote.reduce((n, { r }) => n + r.acked, 0);
  const failed = wrote.reduce((n, { r }) => n + r.failed, 0);
  const idleAlready = idle.reduce((n, { r }) => n + (r.already_acked ?? 0), 0);
  const tail = ackTail({
    capped: answered.some(({ r }) => r.capped),
    remaining: answered.reduce((n, { r }) => n + (r.remaining ?? 0), 0),
    already_acked: wrote.reduce((n, { r }) => n + (r.already_acked ?? 0), 0),
  });
  if (!wrote.length && !failedGroups && !timedOut) {
    const remaining = idle.reduce((n, { r }) => n + (r.remaining ?? 0), 0);
    const sentences = [
      idleAlready > 0
        ? `${plural(idleAlready, 'alert')} of the ${plural(idle.length, 'group')} ${idleAlready === 1 ? 'is' : 'are'} already acknowledged.`
        : `No alert of the ${plural(idle.length, 'group')} waits for an acknowledgement.`,
      'soc-ai wrote nothing.',
    ];
    if (remaining > 0) sentences.push(`${plural(remaining, 'alert')} left. Press again to continue.`);
    return [sentences.join(' '), 'info'];
  }
  const parts: string[] = [];
  if (wrote.length) parts.push(`Acknowledged ${plural(acked, 'alert')} across ${plural(wrote.length, 'group')}`);
  if (failed) parts.push(`${plural(failed, 'event')} failed`);
  if (idle.length) parts.push(`${plural(idle.length, 'group')} already acknowledged`);
  if (failedGroups) parts.push(`${plural(failedGroups, 'group')} failed. The failed groups stay selected. Select Acknowledge to try again.`);
  if (timedOut) parts.push(`${plural(timedOut, 'group')} did not answer yet`);
  const tone: ToastTone = failed || failedGroups ? 'danger' : wrote.length ? 'success' : 'info';
  return [parts.join(' · ') + tail, tone];
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
  // True once a link, a saved view, the demo or the analyst picked the window.
  // The landing widening below leaves a chosen window alone.
  const windowChosen = useRef(seed.range != null);
  useEffect(() => {
    if (demo && !rangeFromLink.current) {
      windowChosen.current = true;
      setFilterTime('30d');
    }
  }, [demo]);
  // The window the screen widened from on landing, for the note that says so.
  const [widenedFrom, setWidenedFrom] = useState<string | null>(null);
  /** The analyst picked a window. The landing note no longer applies. */
  const chooseWindow = (range: string) => {
    windowChosen.current = true;
    setWidenedFrom(null);
    setFilterTime(range);
  };
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
      ? { range: 'custom', from: utcBound(customRange.from), to: utcBound(customRange.to) }
      : { range: filterTime }),
    hideAcked: hideAcked || undefined,
    // In alertQuery (not a one-off param) so the lazy event pages and the
    // representative pick fetched under this filter stay scoped to the same
    // set the rows on screen came from.
    q: filterQ || undefined,
  };
  const view = asViewId(searchParams.get('view'));
  const drawerId = searchParams.get('drawer');
  // useAsync captures pauseWhen at setup and can't see `drawerId` there (it's
  // not in the deps below), so track it in a ref and let pauseWhen consult
  // that instead — same gotcha/pattern as Investigations.tsx, Hunts.tsx, etc.
  const drawerOpenRef = useRef(false);
  drawerOpenRef.current = !!drawerId;
  // A filter the server refused. Polling it re-sent the same 400 every few
  // seconds (P7), so the poll stops until the filter changes.
  const badFilterRef = useRef(false);
  const { data: queue, loading, error, lastUpdated, failCount, refetch } = useAsync(
    // links: the same-flow siblings and the case ids of each row (R2-I9,
    // R2-I2). Only this screen asks for them.
    () => getAlerts({ ...alertQuery, links: true }),
    [filterTime, customRange?.from, customRange?.to, hideAcked, filterQ, reloadKey],
    {
      refetchInterval: 10000, // keep the grid + verdict/status badges live without a reload
      // Pause the 10s ES aggregation while an investigation drawer is open, so
      // the grid doesn't churn under the analyst; resumes on close.
      pauseWhen: () => drawerOpenRef.current || badFilterRef.current,
    }
  );
  const badFilter = error instanceof ApiError && error.status === 400 && error.reason === 'bad_oql';
  badFilterRef.current = badFilter;

  // Which window the rows on screen came from. A range change keeps the old
  // rows while the new window loads, and the header went on showing the 24h
  // figures under a pressed 30d chip for about 6 s (P5). A response that lands
  // after a filter change always belongs to the new filter: useAsync drops the
  // older ones.
  const windowKey = [filterTime, customRange?.from, customRange?.to, hideAcked, filterQ].join('|');
  const [dataWindow, setDataWindow] = useState(windowKey);
  useEffect(() => {
    if (lastUpdated != null) setDataWindow(windowKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lastUpdated]);
  const switchingWindow = loading && !!queue && dataWindow !== windowKey;

  // The landing window. A real grid's open alerts are often days old, and the
  // screen opened on an empty 24 h list with a 30 d window of 4 groups behind
  // it (dogfood 2026-10-06). When the default window comes back empty on a
  // plain landing, the screen reads 7 d and then 30 d, once, and lands on the
  // narrowest window that holds a group, the way Investigations does. A link,
  // a saved view or a pick by the analyst names the window, and nothing is
  // probed then.
  const plainLanding = useRef(
    !seed.verdicts.length && !seed.sevs.length && !seed.q && !searchParams.get('view'),
  );
  const probed = useRef(false);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  // The first read of the default window decides the landing once. A list
  // that has rows on landing is not widened later, when it empties.
  useEffect(() => {
    if (!plainLanding.current || windowChosen.current || probed.current) return;
    if (loading || error || !queue || filterTime !== DEFAULT_RANGE) return;
    if (queue.groups.length > 0) probed.current = true;
  }, [queue, loading, error, filterTime]);

  // The rows, and separately whether they are all the rows. The grid caps every
  // terms aggregation, so past the cap these are a floor — see `truncated`.
  const groups = queue?.groups;

  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  // Events live behind a lazy fetch — pulled the first time a group is expanded.
  const [groupEvents, setGroupEvents] = useState<Record<string, AlertEvent[]>>({});
  const [eventsLoading, setEventsLoading] = useState<Record<string, boolean>>({});
  // Per-group "Load more" state: whether another page likely exists, and whether
  // a follow-up page is currently fetching.
  const [eventsMore, setEventsMore] = useState<Record<string, boolean>>({});
  const [eventsLoadingMore, setEventsLoadingMore] = useState<Record<string, boolean>>({});
  // Why a group's first page could not be fetched, keyed like the maps above.
  // A failed page is NOT cached as an empty one: "No events in window." is a
  // claim about the grid, and a 503 supports no such claim — it read as a
  // group with nothing in it, with no way to ask again short of a filter change.
  const [eventsError, setEventsError] = useState<Record<string, string>>({});
  // Bumped by the filter-reset effect. A page already in flight when the
  // filter changes cannot be cancelled, but it can be ignored when it lands:
  // written into the freshly cleared map it sat under the NEW filter, and the
  // cached-key guard in fetchFirstPage then kept it there.
  const eventsEpoch = useRef(0);
  // Which event buckets (keyed "<groupKey>:<bucketIndex>") an analyst has
  // unfolded into individual rows via "Show each".
  const [openBuckets, setOpenBuckets] = useState<Record<string, boolean>>({});
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
  // The row whose drawer is open, read on close. A getter so it resolves the
  // row element at close time: a reload can replace the element.
  const drawerRowKeyRef = useRef<string | null>(null);
  const drawerReturnRef = useMemo<RefObject<HTMLElement | null>>(
    () => ({
      get current() {
        const key = drawerRowKeyRef.current;
        return key ? (rowRefs.current[key] ?? null) : null;
      },
    }),
    [],
  );
  // Shared sort mechanics; clicking a new column here starts it descending.
  const { sort, toggleSort, caret, headerCls: hdrCls } = useSort<SortKey>(
    seed.sort ?? DEFAULT_SORT,
    'desc',
  );
  // The filters go back into the URL on every change (see writeFiltersToParams).
  // `replace`, so a filter change is not a Back step.
  useEffect(() => {
    setSearchParams(
      (prev) => {
        const next = writeFiltersToParams(prev, {
          range: filterTime,
          custom: customRange,
          sevs: filterSevs,
          verdicts: filterVerdicts,
          hideAcked,
          sort,
        });
        return next.toString() === prev.toString() ? prev : next;
      },
      { replace: true },
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filterTime, customRange?.from, customRange?.to, filterSevs, filterVerdicts, hideAcked, sort]);

  // Results (ack / triage batch summaries) go to the app-wide toaster instead of
  // stacking dismissible strips in this header.
  const { toast, dismiss: dismissToast } = useToast();

  // ---- group-ack strip ---------------------------------------------------
  const [acking, setAcking] = useState(false);
  const [ackingCount, setAckingCount] = useState(0);
  const [ackingAlertTotal, setAckingAlertTotal] = useState(0);
  // A rejected write goes out as 'danger': the toaster keeps that tone until
  // it is dismissed, where a 'success' wears the green check and is gone at 6s,
  // which read as the write having landed to anyone who glanced and looked away.
  const showAckMsg = (m: string, tone: ToastTone = 'success') =>
    toast({ message: m, tone: m === DEMO_ACTION_NOTE ? 'info' : tone });

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
  // True while the batch on screen is the header sweep over SWEEP_RANGE. A
  // selection names no window, so its lines say none.
  const [triageSweep, setTriageSweep] = useState(false);
  const triageTimer = useRef<ReturnType<typeof setInterval> | null>(null);
  // Whether this screen is still on the page. The start POST can outlive it
  // (api.ts gives the request 20s; the analyst may navigate away sooner), and
  // the unmount cleanup can only clear an interval that already exists — one
  // installed by a `.then` landing after it would poll the status route every
  // 2s for the rest of the sweep from a screen nobody is looking at.
  const mountedRef = useRef(true);
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
      return `The API refused Bulk Investigate. ${endSentence(
        detail || `The API answered ${err.status}`,
      )}`;
    }
    // The next step leads here, because it is the part that stops a duplicate
    // sweep; the transport's own words follow it.
    return (
      'Bulk Investigate gave no answer. The sweep may have started. Check the ' +
      `Auto-Investigate tile on the Dashboard before you start another sweep. ${endSentence(
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
    const sweep = !alertIds?.length;
    // The summary of a sweep names its window, because the list on screen can
    // show another one.
    const scoped = (msg: string): string => (sweep ? `${SWEEP_HEAD}: ${msg}` : msg);
    setTriaging(true);
    setTriageSweep(sweep);
    setTriageError(null);
    setPct(0);
    if (triageTimer.current) clearInterval(triageTimer.current);
    const finish = (msg: string | null) => {
      if (triageTimer.current) clearInterval(triageTimer.current);
      if (!mountedRef.current) return;
      setPct(100);
      setTimeout(() => {
        if (mountedRef.current) setTriaging(false);
      }, 900);
      setReloadKey((k) => k + 1); // pull in the verdicts the batch produced
      if (msg) showTriageMsg(msg);
    };
    const poll = () => {
      getAutoTriageStatus()
        .then((s) => {
          if (!mountedRef.current) return;
          // skipped never enters the worker, so progress is processed/total.
          const done = s.hunted + s.failed;
          setPct(s.total ? Math.round((100 * done) / s.total) : 0);
          setTriageStatus(s);
          if (!s.active) finish(scoped(triageSummary(s)));
        })
        .catch(() => finish('The status check for Bulk Investigate failed'));
    };
    // The sweep names its window to the server. The server default is the
    // same 24 hours, and the words on the button come from the same constant.
    startAutoTriage(sweep ? { minSeverity, range: SWEEP_RANGE } : { alertIds })
      .then((s) => {
        // Landed after the analyst left: nothing to show, and no poll to start.
        if (!mountedRef.current) return;
        if (!s.active) {
          // nothing to hunt, or the batch already wrapped up — show why
          finish(scoped(s.note || (s.total ? triageSummary(s) : 'Nothing to investigate')));
          return;
        }
        // Surface the backend's start note up-front (e.g. "triaging 6 selected
        // (2 already triaged)") so a partial selection isn't a mystery.
        if (s.note) showTriageMsg(s.note);
        // Refresh the list ~1.5 s after start so rows flip to "Triaging…"
        // before investigations have completed (the finish() bump handles verdicts).
        setTimeout(() => {
          if (mountedRef.current) setReloadKey((k) => k + 1);
        }, 1500);
        triageTimer.current = setInterval(poll, 2000);
      })
      .catch((err: unknown) => {
        if (!mountedRef.current) return;
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

  useEffect(() => {
    // Set on mount as well as at declaration: a dev-mode double-invoke runs
    // this cleanup once before the mount that counts, and the flag must come
    // back up with it.
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (triageTimer.current) clearInterval(triageTimer.current);
      if (huntReasonTimer.current) clearTimeout(huntReasonTimer.current);
    };
  }, []);

  // Reset row expansion + cached events when the query that produced them
  // changes. hideAcked is part of alertQuery, so a per-group event page fetched
  // with the old value is stale under the new filter — clear it too, else an
  // expanded group shows acknowledged events after "Hide acknowledged" is on.
  useEffect(() => {
    eventsEpoch.current += 1;
    setExpanded({});
    setGroupEvents({});
    setEventsLoading({});
    setEventsMore({});
    setEventsLoadingMore({});
    setEventsError({});
    // Bucket-unfold state is keyed on "<groupKey>:<bucketIndex>", and the
    // index is only stable within one fetched event page — the group key
    // alone collides across a filter change, so a stale unfold would show
    // the new flood pre-expanded instead of summarized.
    setOpenBuckets({});
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
      showAckMsg('The filter changed. The screen cleared the selection.');
    }
    sel.clear();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filterTime, customRange?.from, customRange?.to, hideAcked, filterQ]);

  const setView = (v: ViewId) => {
    searchParams.set('view', v);
    setSearchParams(searchParams, { replace: true });
  };
  const openDrawer = (id: string) => {
    // Remember the row the drawer belongs to, so Escape hands focus back to
    // it. A row opened by a key or a click on the row body has no focused
    // control, and focus used to land on BODY (fleet P13).
    const active = document.activeElement as HTMLElement | null;
    const fromRow = active?.closest?.('[data-group-key]')?.getAttribute('data-group-key');
    // A re-run from inside the open drawer swaps the run and keeps the row.
    if (!drawerId || fromRow) {
      const byInv = groups?.find((g) => g.invId === id);
      drawerRowKeyRef.current = fromRow ?? focusedKey ?? (byInv ? groupKey(byInv) : null);
    }
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
        showHuntReason(`The investigation uses the representative event: ${rep.reason}`);
        setStarting(g);
        return startHunt(rep.alert_id);
      })
      .then((invId) => openDrawer(invId))
      .catch((err: unknown) => {
        setStarting(null);
        // The strip above named the event this hunt would use; with no hunt
        // it describes nothing, and beside the refusal it would contradict it.
        setHuntReason(null);
        // e.g. 409 hunt_in_progress — same report as hunt()/huntEvent(), so the
        // drawer does not just flash and close with nothing to say why.
        showTriageMsg(err instanceof Error ? err.message : 'Could not start the investigation');
      })
      .finally(() => setHuntGroupPending((s) => ({ ...s, [gk]: false })));
  };

  // ---- writes the console stopped waiting for -------------------------------
  // A client abort is not a failed write. On a slow grid the ack or the case
  // landed 60 to 75 s after the abort, under a red "Could not escalate" toast
  // that stayed after the row was gone (dogfood 2026-10-01, RL2). So a timed-out
  // write is recorded here with the group's state at the press, and the poll
  // below dismisses its notice once the rows show the change landed.
  const pendingWrites = useRef<Record<string, PendingWrite>>({});
  const queryKey = JSON.stringify(alertQuery);
  const noteTimedOut = (g: GroupRef, kind: PendingWrite['kind'], err: Error) => {
    const toastId = toast({
      message: `No answer yet for the ${WRITE_NOUN[kind]} of ${g.name}. ${err.message}`,
      tone: 'info',
      duration: 0,
    });
    const gk = groupKey(g);
    const prior = pendingWrites.current[gk];
    if (prior) dismissToast(prior.toastId);
    pendingWrites.current[gk] = {
      kind,
      name: g.name,
      toastId,
      queryKey,
      owner: g.owner ?? '',
      acked: g.ackedCount ?? null,
      escalated: g.escalatedCount ?? null,
    };
  };
  useEffect(() => {
    if (!groups) return;
    const byKey = new Map(groups.map((g) => [groupKey(g), g]));
    for (const [gk, p] of Object.entries(pendingWrites.current)) {
      if (!writeLanded(p, byKey.get(gk), queryKey, me)) continue;
      dismissToast(p.toastId);
      delete pendingWrites.current[gk];
      toast({ message: `The ${WRITE_NOUN[p.kind]} of ${p.name} is complete.`, tone: 'success' });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groups]);

  // This session's acknowledges of single events, keyed by event id. An
  // expanded group does not read its events again after a write, so the row
  // reads its Ack state from here.
  const [eventAck, setEventAck] = useState<Record<string, 'pending' | 'done'>>({});

  /** Acknowledge events by id: the Ack of one row, or the loose events of the
   *  bulk bar. The answer is always said. The client dropped it, so a 200
   *  with failures said nothing (R2-D7). The server takes at most ACK_CAP ids,
   *  so a larger selection goes in more than one press. */
  const ackSomeEvents = async (ids: string[]): Promise<void> => {
    const blocked = demoBlocked(demo);
    if (blocked) { showAckMsg(blocked); return; } // demo: no doomed write
    const batch = ids.slice(0, ACK_CAP);
    const left = ids.length - batch.length;
    const selected = batch.some((id) => selEvents[id]);
    const mark = (state: 'pending' | 'done' | null) =>
      setEventAck((m) => {
        const next = { ...m };
        batch.forEach((id) => {
          if (state) next[id] = state;
          else delete next[id];
        });
        return next;
      });
    const unselect = () =>
      setSelEvents((prev) => {
        const next = { ...prev };
        batch.forEach((id) => delete next[id]);
        return next;
      });
    mark('pending');
    try {
      const r = await ackEvents(batch);
      if (r.failed > 0) {
        // The answer does not say which events failed, so the selection stays
        // whole and the same press tries again.
        mark(null);
        showAckMsg(
          `Acknowledged ${r.acked.toLocaleString()} of ${plural(r.acked + r.failed, 'event')}. ${plural(r.failed, 'event')} failed.` +
            (selected ? ' The events stay selected. Select Acknowledge to try again.' : ''),
          'danger',
        );
      } else {
        mark('done');
        unselect();
        const parts = [r.acked > 0 ? `Acknowledged ${plural(r.acked, 'event')}.` : 'soc-ai wrote nothing.'];
        if (left > 0) parts.push(`${plural(left, 'event')} left. Press again to continue.`);
        showAckMsg(parts.join(' '), r.acked > 0 ? 'success' : 'info');
      }
      setReloadKey((k) => k + 1);
    } catch (err: unknown) {
      mark(null);
      if (isRequestTimeout(err)) {
        // Not a failure: the write can still land. The notice says so, the
        // list reads again, and the selection goes. A red toast over a
        // standing selection invited a second write of the same events.
        toast({
          message: `No answer yet for the acknowledgement of ${plural(batch.length, 'event')}. ${err.message}`,
          tone: 'info',
          duration: 0,
        });
        unselect();
        setReloadKey((k) => k + 1);
        return;
      }
      // The selection is deliberately left standing so the same click
      // retries it, as the group path does.
      showAckMsg(
        err instanceof Error ? err.message : 'Could not acknowledge the selected events',
        'danger',
      );
    }
  };

  // Groups with an escalate in flight. The ack has its strip in the activity
  // slot; an escalate had nothing, so a slow one read as a dead key press.
  const [escalating, setEscalating] = useState<Record<string, string>>({});
  // Rows whose owner change is in flight: the avatar shows a spinner and
  // takes no second click.
  const [ownerPending, setOwnerPending] = useState<Record<string, boolean>>({});

  // Acknowledge a single group (keyboard `a`) — reuses the same ackGroup write
  // path + ack strip as the bulk bar, scoped to one detection.
  const ackOneGroup = (g: AlertGroup) => {
    const blocked = demoBlocked(demo);
    if (blocked) { showAckMsg(blocked); return; } // demo: no doomed write
    setAckingCount(1);
    setAckingAlertTotal(pressPlan([g], [g], ACK_CAP)?.press ?? g.count ?? 0);
    setAcking(true);
    ackGroup(g, alertQuery)
      .then((r) => {
        showAckMsg(ackMessage(r, g.name, { unhidable: g.ackedCount === null }), ackTone(r));
        setReloadKey((k) => k + 1);
      })
      .catch((err: unknown) => {
        if (isRequestTimeout(err)) noteTimedOut(g, 'ack', err);
        else showAckMsg(`Could not acknowledge ${g.name}`, 'danger');
      })
      .finally(() => setAcking(false));
  };

  // Escalate groups to Security Onion cases: keyboard `e`, the bulk bar and
  // the drawer. The toast names each case and links it when the server can
  // build the console URL.
  const escalateGroups = (targets: GroupRef[], query: AlertQuery = alertQuery) => {
    const blocked = demoBlocked(demo);
    if (blocked) { showAckMsg(blocked); return; } // demo: no doomed write
    const fresh = targets.filter((g) => !escalating[groupKey(g)]);
    if (!fresh.length) return;
    setEscalating((m) => {
      const next = { ...m };
      fresh.forEach((g) => { next[groupKey(g)] = g.name; });
      return next;
    });
    fresh.forEach((g) => {
      escalateGroup(g, query)
        .then((r) => {
          toast({
            message: escalateMessage(r, g.name),
            // A press that opened no case wears no success check (R2-D15).
            tone: r.failed > 0 ? 'danger' : escalateWroteNothing(r) ? 'info' : 'success',
            links: escalateLinks(r),
            // A case id is something to copy; do not take it away at 6 s.
            duration: escalateNamesCase(r) ? 0 : undefined,
          });
          setReloadKey((k) => k + 1);
        })
        .catch((err: unknown) => {
          if (isRequestTimeout(err)) noteTimedOut(g, 'escalate', err);
          else
            showAckMsg(
              `Could not escalate ${g.name}. ${err instanceof Error ? err.message : ''}`.trim(),
              'danger',
            );
        })
        .finally(() =>
          setEscalating((m) => {
            const next = { ...m };
            delete next[groupKey(g)];
            return next;
          }),
        );
    });
  };
  // Every escalate asks first, with the count of cases it opens (dogfood
  // 2026-10-06, investigation S2). The server opens one case for each alert,
  // so a 16-alert group is 16 cases. The key `e`, the bulk bar and the drawer
  // all come through here.
  const [escalateAsk, setEscalateAsk] = useState<{
    targets: GroupRef[];
    query: AlertQuery;
    onConfirm?: () => void;
  } | null>(null);
  const askEscalate = (targets: GroupRef[], query: AlertQuery = alertQuery, onConfirm?: () => void) => {
    const fresh = targets.filter((g) => !escalating[groupKey(g)]);
    if (!fresh.length) return;
    setEscalateAsk({ targets: fresh, query, onConfirm });
  };
  // The plan of the press on confirm. A write under another window than the
  // list (the drawer's) cannot be planned from these rows, so it has none.
  const escalateAskPlan =
    escalateAsk && JSON.stringify(escalateAsk.query) === queryKey
      ? pressPlan(escalateAsk.targets, groups ?? [], ESCALATE_CAP)
      : null;
  const escalateOneGroup = (g: AlertGroup) => askEscalate([g]);
  const escalatingNames = Object.values(escalating);

  // Toggle a single group's selection (keyboard `x`) into the same `selected`
  // map the checkboxes + bulk bar use.
  const toggleSelectGroup = (g: AlertGroup) => sel.toggle(groupKey(g));

  // A group's first page of events: fetched on its first expand, and again
  // from the inline Retry after a failure. Results from before the last filter
  // change are dropped rather than merged (see eventsEpoch).
  const fetchFirstPage = (g: AlertGroup) => {
    const gk = groupKey(g);
    const epoch = eventsEpoch.current;
    setEventsLoading((s) => ({ ...s, [gk]: true }));
    setEventsError((s) => {
      if (!(gk in s)) return s;
      const next = { ...s };
      delete next[gk];
      return next;
    });
    getAlertGroupEvents(g, alertQuery, { size: EVENTS_PAGE_SIZE, offset: 0 })
      .then((evs) => {
        if (epoch !== eventsEpoch.current) return;
        setGroupEvents((s) => ({ ...s, [gk]: evs }));
        // A full page implies there may be more — show "Load more".
        setEventsMore((s) => ({ ...s, [gk]: evs.length >= EVENTS_PAGE_SIZE }));
      })
      .catch((err: unknown) => {
        if (epoch !== eventsEpoch.current) return;
        setEventsError((s) => ({
          ...s,
          [gk]: err instanceof Error ? err.message : 'The request did not complete',
        }));
      })
      .finally(() => {
        // A stale finally must not flip loading off under a newer fetch; the
        // reset effect already cleared the map for this epoch.
        if (epoch !== eventsEpoch.current) return;
        setEventsLoading((s) => ({ ...s, [gk]: false }));
      });
  };

  const toggleExpand = (g: AlertGroup) => {
    const gk = groupKey(g);
    const opening = !expanded[gk];
    setExpanded((s) => ({ ...s, [gk]: !s[gk] }));
    // Fetch this group's first page of events the first time it's opened.
    if (opening && groupEvents[gk] === undefined && !eventsLoading[gk]) {
      fetchFirstPage(g);
    } else if (!opening) {
      // Collapsing: forget which buckets were unfolded, so re-expanding
      // starts summarized again rather than reopening a stale flood.
      setOpenBuckets((s) => {
        const prefix = `${gk}:`;
        const next: Record<string, boolean> = {};
        let changed = false;
        for (const [k, v] of Object.entries(s)) {
          if (k.startsWith(prefix)) { changed = true; continue; }
          next[k] = v;
        }
        return changed ? next : s;
      });
    }
  };

  // Fetch the next page of a group's events and append it. Hides "Load more"
  // once a returned page is short (no further pages).
  const loadMoreEvents = (g: AlertGroup) => {
    const gk = groupKey(g);
    if (eventsLoadingMore[gk]) return;
    const offset = groupEvents[gk]?.length ?? 0;
    const epoch = eventsEpoch.current;
    setEventsLoadingMore((s) => ({ ...s, [gk]: true }));
    getAlertGroupEvents(g, alertQuery, { size: EVENTS_PAGE_SIZE, offset })
      .then((evs) => {
        if (epoch !== eventsEpoch.current) return;
        setGroupEvents((s) => ({ ...s, [gk]: [...(s[gk] ?? []), ...evs] }));
        setEventsMore((s) => ({ ...s, [gk]: evs.length >= EVENTS_PAGE_SIZE }));
      })
      .catch(() => {
        if (epoch !== eventsEpoch.current) return;
        setEventsMore((s) => ({ ...s, [gk]: false }));
      })
      .finally(() => {
        if (epoch !== eventsEpoch.current) return;
        setEventsLoadingMore((s) => ({ ...s, [gk]: false }));
      });
  };

  const ownerOf = (g: AlertGroup) => g.owner ?? '';

  // ── E2.3 triage-state actions ──────────────────────────────────────────
  // Each reuses the one /alerts/assign endpoint (assignAlert), then refreshes
  // the list so the chip/owner update. Assign-to-me and release both change
  // ownership; mark-in-review / mark-done only move the state on an owned rule.
  // Demo blocks every /alerts/assign write; the note lands on the shared ack strip.
  // The owner avatar: one click assigns or releases. Each press reports its
  // outcome in a toast and holds the avatar until the write answers, so a
  // slow grid does not read as a click that did nothing (RL9).
  const changeOwner = (g: AlertGroup, kind: 'assign' | 'release') => {
    const blocked = demoBlocked(demo);
    if (blocked) { showAckMsg(blocked); return; }
    const gk = groupKey(g);
    if (ownerPending[gk]) return;
    setOwnerPending((m) => ({ ...m, [gk]: true }));
    assignAlert(g.name, kind === 'release')
      .then(() => {
        showAckMsg(kind === 'release' ? `Released ${g.name}.` : `Assigned ${g.name} to you.`);
        setReloadKey((k) => k + 1);
      })
      .catch((err: unknown) => {
        if (isRequestTimeout(err)) noteTimedOut(g, kind, err);
        else showAckMsg(`Could not ${kind} ${g.name}`, 'danger');
      })
      .finally(() =>
        setOwnerPending((m) => {
          const next = { ...m };
          delete next[gk];
          return next;
        }),
      );
  };
  const assignToMe = (g: AlertGroup) => changeOwner(g, 'assign');
  const release = (g: AlertGroup) => changeOwner(g, 'release');
  const setTriage = (g: AlertGroup, state: TriageState) => {
    const blocked = demoBlocked(demo);
    if (blocked) { showAckMsg(blocked); return; }
    assignAlert(g.name, false, state)
      .then(() => setReloadKey((k) => k + 1))
      .catch(() => showAckMsg(`Could not update ${g.name}`, 'danger'));
  };

  // The Verdict filter carries a synthetic 'pipeline_error' value (E1.2): a
  // fallback group matches it regardless of its (needs_more_info) verdict, and —
  // since the chip REPLACES the NMI pill — a fallback group is NOT matched by
  // selecting 'needs_more_info' alone.
  // A group matches the verdict it counts under on the Dashboard breakdown,
  // so the tile that opens this list and the list hold the same groups.
  const matchesVerdict = (g: AlertGroup): boolean => {
    if (!filterVerdicts.length) return true;
    if (filterVerdicts.includes('pipeline_error') && g.fallback) return true;
    const outcome = groupOutcome(g);
    return outcome !== null && filterVerdicts.includes(outcome);
  };
  // Every facet the analyst set EXCEPT the preset itself. Split out so the
  // preset chips can be counted against it: a chip badge answers "how many rows
  // would I get if I clicked this", which is only true when it is measured under
  // the same facets the list is already under. Counted off the raw fetch, the
  // chips described a list nobody was looking at, and the All chip disagreed
  // with the footer directly below it.
  const facet = (rows: AlertGroup[]): AlertGroup[] =>
    hideOptimisticallyAcked(rows, optimisticAcked, hideAcked)
      .filter((g) => !filterSevs.length || filterSevs.includes(g.sev))
      .filter(matchesVerdict);
  const faceted = useMemo(
    () => facet(groups ?? []),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [groups, filterSevs, filterVerdicts, optimisticAcked, hideAcked],
  );
  const visible = useMemo(
    () =>
      faceted
        .filter((g) => matchView(g, view, me))
        .sort((a, b) => cmpGroups(a, b, sort.key, sort.dir)),
    [faceted, view, me, sort],
  );

  // A sibling the analyst asked to see from the same-flow list (R2-I9). The
  // row expands and takes the keyboard focus. The server read the whole
  // window, so a sibling the list hides is in the window: Hide acknowledged
  // and the facets are the usual cause, and the press clears them. `after`
  // is the read the filter change waits past. null when no filter changed.
  const [pendingShow, setPendingShow] = useState<{ key: string; name: string; after: number | null } | null>(null);
  const showSibling = (s: AlertSibling) => {
    const key = groupKey({ kind: s.kind, name: s.name });
    let changed = false;
    if (!visible.some((g) => groupKey(g) === key)) {
      if (hideAcked && !(groups ?? []).some((g) => groupKey(g) === key)) {
        setHideAcked(false);
        changed = true;
      }
      if (filterSevs.length) {
        setFilterSevs([]);
        changed = true;
      }
      if (filterVerdicts.length) {
        setFilterVerdicts([]);
        changed = true;
      }
      if (view !== 'all') {
        setView('all');
        changed = true;
      }
    }
    setPendingShow({ key, name: s.name, after: changed ? lastUpdated ?? 0 : null });
  };
  // A Show link from a report names the row with ?show=<type>:<name> (V3).
  // The link also names the window, and the screen seeds the window and the
  // filters from the URL at mount. The row opens after the first read. The
  // parameter then leaves the URL, so a reload does not open the row again.
  const showParam = searchParams.get('show');
  useEffect(() => {
    if (!showParam) return;
    const at = showParam.indexOf(':');
    setPendingShow({ key: showParam, name: at >= 0 ? showParam.slice(at + 1) : showParam, after: lastUpdated ?? 0 });
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.delete('show');
        return next;
      },
      { replace: true },
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showParam]);
  useEffect(() => {
    if (!pendingShow) return;
    const g = visible.find((x) => groupKey(x) === pendingShow.key);
    if (g) {
      setPendingShow(null);
      setFocusedKey(pendingShow.key);
      if (!expanded[pendingShow.key]) toggleExpand(g);
      return;
    }
    // Wait for the read after a filter change. Then say why the row is not
    // there: the filter of the list or the row limit hides it.
    if (pendingShow.after !== null && (lastUpdated ?? 0) <= pendingShow.after) return;
    setPendingShow(null);
    showAckMsg(
      `The list does not show ${pendingShow.name}. The alert filter or the row limit hides it.`,
      'info',
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pendingShow, visible, lastUpdated]);

  // The next alert with a report, after the one the drawer shows (dogfood
  // 2026-10-06, first hour W1). Each alert took two clicks: close the
  // drawer, then Open report on the next row. The list stays as it is.
  const nextReport = drawerId ? nextReportAfter(visible, drawerId, drawerRowKeyRef.current) : null;
  const openNextReport = () => {
    if (!nextReport?.invId) return;
    const key = groupKey(nextReport);
    drawerRowKeyRef.current = key;
    setFocusedKey(key);
    openDrawer(nextReport.invId);
  };
  // j and ArrowDown open the next report while the drawer is open. The row
  // keys stay off behind the drawer; these two are the drawer's own.
  useEffect(() => {
    if (!drawerId) return;
    const onKey = (e: KeyboardEvent) => {
      if (escalateAsk || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key !== 'j' && e.key !== 'ArrowDown') return;
      if (isEditableTarget(e.target as HTMLElement | null)) return;
      if (!nextReport) return;
      e.preventDefault();
      openNextReport();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [drawerId, nextReport, escalateAsk]);

  // Which empty this is. An alerts filter that matches nothing looks exactly
  // like a quiet network, and on a measured grid it hid 22 unreviewed endpoint
  // alerts behind a screen that read as a calm night. Fetched only when the
  // list came back empty. It costs four counts against the grid, and the
  // answer means nothing for a screen that has rows on it. Failures are
  // swallowed: this is an explanation of silence, and it must never replace
  // the silence with an error.
  const isEmpty = !loading && !error && visible.length === 0;
  const [emptyReason, setEmptyReason] = useState<AlertsEmptyReason | null>(null);
  useEffect(() => {
    if (!isEmpty) {
      setEmptyReason(null);
      return;
    }
    let cancelled = false;
    getAlertsEmptyReason(alertQuery)
      .then((r) => !cancelled && setEmptyReason(r))
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
    // alertQuery is rebuilt every render; depend on the window it is built from.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isEmpty, filterTime, customRange?.from, customRange?.to, reloadKey]);

  // The wider window an empty list offers, found by a read (R2-D20, R2-I8).
  // The list offered "Show the last 7 days" where the last 7 days were empty
  // too. The probe reads the wider windows narrowest first, under the same
  // filters, and the button names the window and its count of detections.
  // On a plain landing the same probe widens the list instead.
  const [widerOffer, setWiderOffer] = useState<{
    key: string;
    range: (typeof LANDING_WINDOWS)[number] | null;
    count: number | null;
  } | null>(null);
  const offerKey = JSON.stringify([
    queryKey,
    view,
    view === 'mine' ? me : '',
    filterSevs,
    filterVerdicts,
    reloadKey,
  ]);
  useEffect(() => {
    if (!isEmpty) return;
    const landing =
      plainLanding.current && !windowChosen.current && !probed.current && filterTime === DEFAULT_RANGE;
    if (landing) probed.current = true;
    const candidates = LANDING_WINDOWS.filter((w) => widerThan(w, filterTime));
    if (!candidates.length) return;
    const key = offerKey;
    let cancelled = false;
    void (async () => {
      for (const wider of candidates) {
        const found = await getAlerts({ ...alertQuery, range: wider }).catch(() => null);
        if (cancelled || !mounted.current) return;
        if (!found) {
          // A failed read says nothing about the wider window. The list
          // reports its own read, so the button offers the next window and
          // claims no count.
          if (!landing) setWiderOffer({ key, range: candidates[0], count: null });
          return;
        }
        const count = facet(found.groups).filter((g) => matchView(g, view, me)).length;
        if (count > 0) {
          if (landing && !windowChosen.current) {
            setWidenedFrom(DEFAULT_RANGE);
            setFilterTime(wider);
          } else {
            setWiderOffer({ key, range: wider, count });
          }
          return;
        }
      }
      setWiderOffer({ key, range: null, count: 0 });
    })();
    return () => {
      cancelled = true;
    };
    // alertQuery and facet are rebuilt every render; offerKey names what they read.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isEmpty, offerKey]);
  const offer = widerOffer && widerOffer.key === offerKey ? widerOffer : null;

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
      // The escalate confirm is a modal surface too. Its own handler owns Esc.
      if (escalateAsk) return;
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
  }, [paletteOpen, modalOpen, keyHelpOpen, visible, focusedIndex, drawerId, escalateAsk]);
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
  // A group leaves the selection after a write, and the expanded event boxes
  // the group ticked must leave with it. They stayed ticked, and the bar then
  // offered group actions on "2 events" that did nothing (RL1). `keep` names
  // the groups still selected (the failed ones), whose events stay.
  const dropEventsOutside = (left: AlertGroup[], keep: string[]) => {
    const keepSet = new Set(keep);
    const ids = left
      .filter((g) => !keepSet.has(groupKey(g)))
      .flatMap((g) => (groupEvents[groupKey(g)] ?? []).map((ev) => ev.id).filter(Boolean) as string[]);
    if (!ids.length) return;
    setSelEvents((prev) => {
      const next = { ...prev };
      ids.forEach((id) => delete next[id]);
      return next;
    });
  };
  selectedRef.current = selCount + selectedEventIds.length;
  const alertsInWindow = selectedGroups.reduce((n, g) => n + (g.count || 0), 0);
  // What one press of the bulk Acknowledge writes (R2-D8).
  const ackPlan = pressPlan(selectedGroups, selectedGroups, ACK_CAP);
  const ackOff = ackButtonOffReason(ackPlan);

  const toggleSelectAll = () => sel.toggleAll();

  // A chip badge is a promise about the list clicking it produces, so each one
  // is the preset's own predicate run over the FACETED rows — the same
  // `matchView` the list itself uses, not a second copy of it that can drift.
  const counts = useMemo(
    () => ({
      mine: faceted.filter((g) => matchView(g, 'mine', me)).length,
      inreview: faceted.filter((g) => matchView(g, 'inreview', me)).length,
      critical: faceted.filter((g) => matchView(g, 'critical', me)).length,
      decision: faceted.filter((g) => matchView(g, 'decision', me)).length,
      all: faceted.length,
    }),
    [faceted, me],
  );
  // The header and footer caption the rows on screen, which means the preset
  // counts too. Measured off the raw fetch, a list showing one row was captioned
  // "59 detections": a claim about a list the analyst had already narrowed away.
  const { shown, untriaged, totalEvents } = useMemo(
    () => ({
      shown: visible.length,
      // The verdict each group counts under, as on the Dashboard breakdown.
      untriaged: visible.filter((g) => groupOutcome(g) === 'untriaged').length,
      totalEvents: visible.reduce((a, g) => a + g.count, 0),
    }),
    [visible],
  );

  // Unknown is not zero. Every number on this screen is derived from `groups`,
  // which is an empty array both before the first load lands and after a failed
  // one — so the header, the view chips and the footer each printed a literal 0
  // for a count the screen never obtained. On a down grid that put
  // "0 untriaged · 0 detections · 0 events in window" directly above this
  // screen's own "Could not load this view" card: a false all-clear, which is the
  // one thing worse than a loud error, sitting on the top line a tired analyst
  // scans first. Same convention (and the same shape) as the Dashboard's stat
  // cards: the real number once we have data — INCLUDING a genuine 0, because a
  // quiet shift is a real and common answer — an em-dash for a number we asked
  // for and did not get, an ellipsis while we are still asking. Keyed off
  // `groups`, not off `error`, so stale rows left on screen by a failed
  // background poll keep counts that describe the rows actually rendered.
  // While a new window loads, the rows on screen are the OLD window's, so a
  // count of them is a count of the wrong window: it reads as still asking.
  const counted = !!groups && !switchingWindow;
  const num = (n: number): string => (counted ? n.toLocaleString() : error ? '—' : COUNTING);
  const countOf = (n: number, one: string, many = `${one}s`): string =>
    counted ? plural(n, one, many) : `${num(n)} ${many}`;
  // A chip badge is one glyph wide with no room for that distinction, so an
  // uncounted view carries NO badge rather than a confident "0" one.
  const chipCount = (n: number): number | undefined => (counted ? n : undefined);

  // The OTHER way every number on this line can be wrong, and the harder one to
  // notice. The grid caps each terms aggregation at a fixed number of distinct
  // groups; past that it returns the biggest ones and a lump sum for the rest.
  // So "212 detections · 41,908 events in window" was a true count of what came
  // back and a false count of what is there, and it reads as a total because
  // nothing about it looks uncertain. The em-dash convention above covers "I
  // could not tell"; this covers "I could tell, partly", which needs its own
  // mark rather than borrowing that one.
  //
  // The flag is the server's, from whichever cut fired. Inferring it here by
  // comparing `groups.length` against a copied cap would read an exactly-full
  // page as a cut one, and would go quietly false the day the cap moves or a
  // muted rule is dropped after the cap is applied — both of which are true of
  // this route.
  const truncated = queue?.truncated ?? false;
  const floorOf = (n: number, one: string, many = `${one}s`): string =>
    counted && truncated ? `${n.toLocaleString()}+ ${many}` : countOf(n, one, many);
  const FLOOR_TITLE =
    'The grid returned the largest detections and stopped at its group limit. These numbers ' +
    'are minimums. This window holds more detections than the queue can show. Narrow the ' +
    'window, the severity or the query until the queue shows every detection.';

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
    setView(asViewId(saved.view));
    setFilterSevs(Array.isArray(saved.sevs) ? (saved.sevs as string[]) : []);
    setFilterVerdicts(Array.isArray(saved.verdicts) ? (saved.verdicts as string[]) : []);
    setHideAcked(typeof saved.hideAcked === 'boolean' ? saved.hideAcked : DEFAULT_HIDE_ACKED);
    windowChosen.current = true;
    setWidenedFrom(null);
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
          <div className="mt-0.5 text-[13px] text-dim" title={truncated ? FLOOR_TITLE : undefined}>
            {num(untriaged)} untriaged · {floorOf(shown, 'detection')} ·{' '}
            {floorOf(totalEvents, 'event')} in window
            {/* The "+" alone is a mark somebody has to already know how to
                read. This says what it means, once, on the line it modifies —
                the numbers stay scannable and the sentence is there for the
                analyst who wonders why the queue will not add up. */}
            {truncated && counted && (
              <span className="ml-1.5" style={{ color: '#f5a623' }}>
                · more than the queue can show
              </span>
            )}
            {switchingWindow && (
              <span className="ml-1.5 inline-flex items-center gap-1.5 text-accent" role="status">
                <Spinner size={11} /> Loading the {filterTime === 'custom' ? 'custom' : filterTime} window
              </span>
            )}
          </div>
        </div>
        <div className="flex-1" />
        <div className="flex items-center gap-0">
          <select
            value={triageFloor}
            onChange={(e) => setTriageFloor(e.target.value)}
            disabled={triaging}
            className="rounded-l-control border border-r-0 border-border-strong bg-surface-3 px-2.5 py-2 text-[12.5px] text-dim focus:outline-none focus:ring-1 focus:ring-accent disabled:opacity-50"
            title="The severity floor for Bulk Investigate. Select the lowest severity to investigate."
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
            {/* The sweep reads its own window. The list filter above does
                not apply to it, so the button says which window it reads. */}
            <span className="font-normal text-dim">· {SWEEP_WORDS}</span>
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
      {(triaging || acking || escalatingNames.length > 0) && (
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
              <div data-testid="bulk-investigate-progress" className="text-[13px] font-semibold">
                Bulk Investigate runs
                {triageStatus?.severities?.length ? ` on ${triageStatus.severities.join(', ')}` : ''}
                {triageSweep && <span className="font-normal text-dim"> · {SWEEP_WORDS}</span>}
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
              <span className="font-semibold text-text-2">
                Security Onion acknowledges up to {plural(ackingAlertTotal, 'alert')} in {plural(ackingCount, 'group')}.
              </span>
            </div>
          )}
          {escalatingNames.length > 0 && (
            <div className="flex items-center gap-2.5 text-[13px]" role="status">
              <Spinner size={14} />
              <span className="min-w-0 break-words font-semibold text-text-2">
                Security Onion opens cases for {escalatingNames.length === 1 ? escalatingNames[0] : plural(escalatingNames.length, 'group')}.
              </span>
            </div>
          )}
        </div>
      )}

      {/* The shared list toolbar. The preset tabs became chips in its view row
          so they read as the same mechanism as a saved view — one is a view
          this screen ships with, the other one the analyst named. The selection
          strip takes the facet row's slot, which is where that behaviour came
          from in the first place.
          The selection strip sticks to the top of the page, so the bulk
          actions stay in view for a selection low on the page (R2-D16). The
          holder and the toolbar box take no box of their own, so the strip
          sticks for the height of the page and the toolbar keeps its layout. */}
      <div data-testid="alerts-toolbar" className={STICKY_SELECTION}>
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
        saveViewUnavailable={views.unavailable}
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
                          title="The selected detections fired this many times in the current window. Acknowledge a group to cover every alert in it."
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
                  {/* The group actions render only with a group selected. With
                      events alone they returned early and did nothing, under a
                      bar that still offered them (RL1). */}
                  {selectedGroups.length > 0 && (
                  <button
                    onClick={() => {
                      if (!selectedGroups.length) return;
                      const blocked = demoBlocked(demo);
                      if (blocked) { showAckMsg(blocked); return; } // demo: no doomed write
                      const targets = selectedGroups;
                      const n = targets.length;
                      // allSettled: a single assign failing must not silently drop the rest.
                      // Keep failed groups selected so the analyst can retry them.
                      Promise.allSettled(targets.map((g) => assignAlert(g.name)))
                        .then((outcomes) => {
                          const failedIds: string[] = [];
                          let timedOut = 0;
                          outcomes.forEach((o, i) => {
                            if (o.status === 'fulfilled') return;
                            if (isRequestTimeout(o.reason)) {
                              timedOut += 1;
                              noteTimedOut(targets[i], 'assign', o.reason);
                            } else {
                              failedIds.push(groupKey(targets[i]));
                            }
                          });
                          const ok = n - failedIds.length - timedOut;
                          sel.select(failedIds);
                          dropEventsOutside(targets, failedIds);
                          if (failedIds.length) {
                            showAckMsg(`Assigned ${ok} of ${n} group${n !== 1 ? 's' : ''} · ${failedIds.length} failed. The failed groups stay selected. Select Assign to me to try again.`, 'danger');
                          } else if (ok > 0) {
                            showAckMsg(`Assigned ${ok} group${ok !== 1 ? 's' : ''} to you`);
                          }
                          setReloadKey((k) => k + 1);
                        });
                    }}
                    className="rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-1.5 text-[12.5px] font-semibold text-text hover:border-accent"
                  >
                    Assign to me
                  </button>
                  )}
                  {selectedGroups.length > 0 && (
                  <button
                    onClick={() => {
                      if (!selectedGroups.length) return;
                      const blocked = demoBlocked(demo);
                      if (blocked) { showAckMsg(blocked); return; } // demo: no doomed write (before setAcking so the strip shows)
                      const targets = selectedGroups;
                      const n = targets.length;
                      setAckingCount(n);
                      setAckingAlertTotal(ackPlan?.press ?? alertsInWindow);
                      setAcking(true);
                      // allSettled: one group failing must not wipe the whole batch. Keep
                      // failed groups selected so the analyst can retry them.
                      Promise.allSettled(targets.map((g) => ackGroup(g, alertQuery)))
                        .then((outcomes) => {
                          const failedIds: string[] = [];
                          const answered: Array<{ g: AlertGroup; r: AckGroupResult }> = [];
                          let timedOut = 0;
                          outcomes.forEach((o, i) => {
                            if (o.status === 'fulfilled') {
                              answered.push({ g: targets[i], r: o.value });
                            } else if (isRequestTimeout(o.reason)) {
                              // Not a failure: the write may still land. Its own
                              // notice says so, and the poll clears it.
                              timedOut += 1;
                              noteTimedOut(targets[i], 'ack', o.reason);
                            } else {
                              failedIds.push(groupKey(targets[i]));
                            }
                          });
                          const failedGroups = failedIds.length;
                          // Clear only the groups that succeeded; retain failed ones for retry.
                          sel.select(failedIds);
                          dropEventsOutside(targets, failedIds);
                          if (answered.length === 1 && !failedGroups && !timedOut) {
                            // One group: the sentence of the `a` key, so a
                            // second press names what is already done (R2-D15).
                            const { g, r } = answered[0];
                            showAckMsg(ackMessage(r, g.name, { unhidable: g.ackedCount === null }), ackTone(r));
                          } else if (answered.length > 0 || failedGroups > 0) {
                            showAckMsg(...bulkAckMessage(answered, failedGroups, timedOut));
                          }
                          setReloadKey((k) => k + 1);
                        })
                        .finally(() => setAcking(false));
                    }}
                    disabled={ackOff != null}
                    title={ackOff ?? ackButtonTitle(ackPlan)}
                    className="rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-1.5 text-[12.5px] font-semibold text-text enabled:hover:border-success-btn-border enabled:hover:text-success disabled:opacity-50"
                  >
                    {ackButtonLabel(selectedGroups.length, ackPlan)}
                  </button>
                  )}
                  {selectedGroups.length > 0 && (
                    <button
                      onClick={() => {
                        const targets = selectedGroups;
                        askEscalate(targets, alertQuery, () => {
                          sel.clear();
                          dropEventsOutside(targets, []);
                        });
                      }}
                      disabled={selectedGroups.every((g) => !!escalating[groupKey(g)])}
                      title="Open a Security Onion case for each alert in the selected groups"
                      className="rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold disabled:opacity-50"
                      style={{ borderColor: 'rgba(240,68,56,.4)', background: 'rgba(240,68,56,.10)', color: '#fca5a5' }}
                    >
                      Escalate to cases
                    </button>
                  )}
                  {looseEventIds.length > 0 && (
                    <button
                      disabled={ackingEvents}
                      onClick={async () => {
                        setAckingEvents(true);
                        try {
                          await ackSomeEvents(looseEventIds);
                        } finally {
                          setAckingEvents(false);
                        }
                      }}
                      title={
                        looseEventIds.length > ACK_CAP
                          ? `One press acknowledges at most ${ACK_CAP} events. Press again for the other ${plural(looseEventIds.length - ACK_CAP, 'event')}.`
                          : undefined
                      }
                      className="rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-1.5 text-[12.5px] font-semibold text-text hover:border-success-btn-border hover:text-success disabled:opacity-50"
                    >
                      {ackingEvents
                        ? 'Acknowledging'
                        : looseEventIds.length > ACK_CAP
                          ? `Acknowledge ${ACK_CAP} of ${plural(looseEventIds.length, 'event')}`
                          : `Acknowledge ${plural(looseEventIds.length, 'event')}`}
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
            chooseWindow(v);
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
            // Alerts whose document carries no severity label. Offered as its
            // own option because the badge names it: a filter the screen can
            // display a value for but not select by is the same disagreement.
            { value: 'unknown', label: 'Unknown' },
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
            title="The list shows only the detections that match this filter. Clear the filter to see every detection."
            className="flex max-w-[420px] items-center gap-1.5 rounded-control border border-accent/40 bg-accent/10 px-[10px] py-[7px] text-[12px] text-accent"
          >
            <Filter size={12} className="flex-none" />
            <span className="min-w-0 break-all font-mono text-[11.5px]">{filterQ}</span>
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
      </div>

      {/* Group-hunt (pivot) representative reason — a subtle 12px annotation
          attached beneath the context row, not a standalone strip (DESIGN Q4). */}
      {huntReason && (
        <div className="-mt-2 mb-3.5 flex items-center gap-1.5 text-[12px] text-dim">
          <span className="flex flex-shrink-0" style={{ color: '#a78bfa' }}><Sparkles size={12} /></span>
          <span className="min-w-0 break-words">{huntReason}</span>
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
          className="grid items-center gap-2 border-b border-border bg-surface-2 px-3.5 py-[9px] text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint"
          style={{ gridTemplateColumns: GRID, minWidth: GRID_MIN_WIDTH }}
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
            soc-ai verdict{caret('verdict')}
          </div>
          <div className={`text-right ${hdrCls('conf')}`} onClick={() => toggleSort('conf')}>
            Conf{caret('conf')}
          </div>
          <div>Owner</div>
          <div className={`text-right ${hdrCls('latest')}`} onClick={() => toggleSort('latest')}>
            Last seen{caret('latest')}
          </div>
          <TagsHeader />
          <div />
        </div>

        {loading && !groups && <LoadingState label="Loading detections" />}
        {/* A filter the server refused is the analyst's to fix, not an outage.
            The generic card hid the reason under Details and offered a Retry
            that sent the same 400 again (P7, RL8). */}
        {badFilter && error && (
          <div
            role="alert"
            className="m-3 flex flex-col items-center gap-2 rounded-card border border-[rgba(245,166,35,.35)] bg-[rgba(245,166,35,.06)] px-4 py-6 text-center"
          >
            <div className="text-[13.5px] font-semibold text-text">The filter is not valid</div>
            <div className="max-w-[560px] break-words text-[12.5px] leading-[1.6] text-text-2">{error.message}</div>
            <div className="text-[12px] text-faint">Correct the filter or clear its chip. The list does not refresh until then.</div>
          </div>
        )}
        {/* The card's own remedy is "retry shortly" — so give it something to
            click. Without onRetry, acting on that advice meant reloading the
            whole page, while the Dashboard's card for the same outage has had a
            Retry button all along. */}
        {error && !badFilter && <div className="p-3"><ErrorState error={error} onRetry={refetch} /></div>}
        {/* Rows from the last good read stay on screen while the grid does not
            answer. "updated 1m ago" alone did not say that the rows are old
            (RL12), so name the time of the read. */}
        {groups && lastUpdated != null && !badFilter && (failCount > 0 || (error && !loading)) && (
          <div
            role="status"
            className="mx-3 mt-2 rounded-card border border-[rgba(245,166,35,.35)] bg-[rgba(245,166,35,.06)] px-3 py-1.5 text-[12px] text-text-2"
          >
            Showing the last good read from {readTime(lastUpdated)}. The grid did not answer.
          </div>
        )}
        {widenedFrom && groups && groups.length > 0 && (
          <div
            role="status"
            data-testid="alerts-widened"
            className="mx-3 mt-2 rounded-card border border-border-faint bg-surface-2 px-3 py-1.5 text-[12px] text-text-2"
          >
            The last {windowWords(widenedFrom)} held no open detection. The list shows the last{' '}
            {windowWords(filterTime)}.
          </div>
        )}
        <GridGapStrip range={filterTime} custom={customRange} className="mx-3 mt-2" />
        {isEmpty && (
          <div
            className="px-4 py-10 text-center text-[13px] text-faint"
            data-empty-reason={emptyReason?.reason ?? 'unchecked'}
          >
            <div>
              {emptySentence({
                view,
                sevs: filterSevs,
                verdicts: filterVerdicts,
                q: filterQ,
                hideAcked,
                widest: filterTime === WIDEST_RANGE,
              })}
            </div>
            {/* Only when the backend has something to add. `not_empty` means the
                feed did match events in this window, so the screen is empty
                because of the filters above it, which the sentence already says. */}
            {emptyReason && emptyReason.reason !== 'not_empty' && emptyReason.hint ? (
              <div className="mx-auto mt-2 max-w-xl">{emptyReason.hint}</div>
            ) : null}
            {/* The way out, as a control. "Widen the time range" pointed at a
                filter bar and offered nothing to press (dogfood 2026-10-06). */}
            {offer?.range && (
              <button
                type="button"
                data-testid="alerts-widen"
                onClick={() => chooseWindow(offer.range!)}
                className="mt-3 rounded-control border border-border-strong bg-surface-3 px-3 py-1.5 text-[12px] font-semibold text-text-2 hover:border-accent hover:text-text"
              >
                Show the last {windowWords(offer.range)}
                {offer.count != null ? ` · ${plural(offer.count, 'detection')}` : ''}
              </button>
            )}
          </div>
        )}

        {visible.map((g, rowIdx) => {
          const gk = groupKey(g);
          const pill = rowPill(g);
          const isExp = !!expanded[gk];
          const owner = ownerOf(g);
          const seld = sel.isSelected(gk);
          const kbFocused = rowIdx === focusedIndex;
          return (
            <div
              key={gk}
              ref={(el) => { rowRefs.current[gk] = el; }}
              data-group-key={gk}
              tabIndex={-1}
              className="outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-accent"
            >
              <div
                onClick={() => toggleExpand(g)}
                className={`relative grid cursor-pointer items-center gap-2 border-b border-border-faint hover:bg-surface-hover${
                  kbFocused ? ' bg-surface-hover ring-1 ring-inset ring-accent' : ''
                }`}
                style={{ gridTemplateColumns: GRID, minWidth: GRID_MIN_WIDTH, padding: rowPad }}
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
                {/* The name and the flow line, and no chip: the chips sit in
                    the tags column, so every name starts at the same x. The
                    whole name shows and wraps. A middle cut hid the words
                    that tell two rules apart (owner, 2026-10-07). */}
                <div data-testid="alert-title-cell" className="flex min-w-0 items-start gap-[9px]">
                  <span className="mt-[3px] flex flex-none text-faint transition-transform" style={{ transform: isExp ? 'rotate(90deg)' : 'rotate(0deg)' }}>
                    <ChevronRight size={13} />
                  </span>
                  <div className="flex min-w-0 flex-1 flex-col gap-px">
                    <div className="min-w-0 whitespace-normal break-words text-[13.5px] font-medium leading-[1.4]">
                      <span data-testid="alert-name">{g.name}</span>
                      {g.count > 1 && (
                        <span
                          className="ml-1.5 whitespace-nowrap font-mono text-[10.5px] font-normal text-faint"
                          title={`This detection fired ${g.count.toLocaleString()} times in the window. Expand the row to see each event.`}
                        >
                          ×{g.count.toLocaleString()}
                        </span>
                      )}
                    </div>
                    {/* Who is involved: the flow of the latest alert, how many
                        other sources the group holds, and the machine. The row
                        showed none of it until it was expanded (dogfood
                        2026-10-06, W3). A host log has no flow, and says so. */}
                    {(g.src || g.dst || g.host || (g.siblingCount ?? 0) > 0) && (
                      <div data-testid="group-who" className="flex min-w-0 flex-wrap items-center gap-x-1.5 gap-y-0.5 font-mono text-[10.5px] text-faint">
                        {g.src || g.dst ? (
                          <FlowBadge src={g.src} dst={g.dst} className="text-[10.5px]" />
                        ) : null}
                        {(g.srcCount ?? 0) > 1 && (
                          <span
                            className="flex-none"
                            title={`The group holds ${g.srcCount} source addresses. Expand the row to see each event.`}
                          >
                            +{(g.srcCount ?? 1) - 1}
                          </span>
                        )}
                        {g.host && (
                          <span className="min-w-0 break-all">
                            {g.src || g.dst ? `· on ${g.host}` : `on ${g.host} · host log`}
                          </span>
                        )}
                        {/* The other detections on this flow (R2-I9, R2-D9). */}
                        {g.siblings && (g.siblingCount ?? 0) > 0 && (
                          <SameFlowChip
                            verdict={g.fallback ? null : pill.verdict}
                            siblings={g.siblings}
                            count={g.siblingCount ?? g.siblings.length}
                            partial={!!g.siblingsPartial}
                            onShow={showSibling}
                            onOpen={openDrawer}
                          />
                        )}
                      </div>
                    )}
                  </div>
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
                      Investigating
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
                      title="The standing verdict is a pipeline error. Open the investigation and run it again."
                      className="flex min-w-0 items-center rounded-pill text-left enabled:hover:opacity-90 disabled:cursor-default"
                    >
                      <PipelineErrorChip />
                    </button>
                  ) : pill.inherited ? (
                    // Inherited verdict: make the whole thing a link to the source
                    // investigation, so the analyst can see WHERE this verdict came
                    // from and jump to it. With a window verdict from the server,
                    // inherited means that no run of the group is in the window.
                    <button
                      type="button"
                      disabled={!pill.invId}
                      onClick={(e) => {
                        e.stopPropagation();
                        if (pill.invId) openDrawer(pill.invId);
                      }}
                      title={pill.title}
                      className="group/inh flex min-w-0 items-center gap-1.5 rounded-pill text-left enabled:hover:opacity-90 disabled:cursor-default"
                    >
                      <VerdictPill verdict={pill.verdict} conf={pill.conf} inherited showConf={false} showInherited={false} />
                      <span className="flex min-w-0 items-center gap-0.5 flex-wrap font-mono text-[10.5px] text-faint group-enabled/inh:group-hover/inh:text-accent">
                        <span className="break-words">
                          · inherited{pill.when ? ` ${pill.when}` : ''}
                        </span>
                        {pill.invId && <ArrowUpRight size={10} className="flex-shrink-0" />}
                      </span>
                    </button>
                  ) : pill.invId && pill.invId !== g.invId ? (
                    // The window verdict comes from another run than the standing
                    // verdict. The pill opens that run.
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        if (pill.invId) openDrawer(pill.invId);
                      }}
                      title={pill.title}
                      className="flex min-w-0 items-center rounded-pill text-left hover:opacity-90"
                    >
                      <VerdictPill verdict={pill.verdict} conf={pill.conf} inherited={false} showConf={false} showInherited={false} />
                    </button>
                  ) : (
                    <VerdictPill verdict={pill.verdict} conf={pill.conf} inherited={false} showConf={false} showInherited={false} />
                  )}
                  {/* The counts of each verdict among the runs in the window, and
                      the window verdict as a chip when the pill shows something
                      else. The row said "False positive" over a group that held
                      a true positive (dogfood 2026-10-06, S5). */}
                  {!g.triaging && <VerdictMix g={g} shown={g.fallback ? null : pill.verdict} onOpen={openDrawer} />}
                  {!g.triaging &&
                    (() => {
                      const hint = analystHint(g, g.fallback ? g.invId ?? null : pill.invId);
                      return hint ? (
                        <button
                          type="button"
                          data-testid={`analyst-verdict-${g.id}`}
                          onClick={(e) => {
                            e.stopPropagation();
                            openDrawer(hint.invId);
                          }}
                          title={hint.title}
                          className="font-mono text-[10.5px] font-semibold text-warn hover:underline"
                        >
                          {hint.text}
                        </button>
                      ) : null;
                    })()}
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
                  {(() => {
                    const conf = rowConf(g);
                    return conf != null ? conf.toFixed(2) : '—';
                  })()}
                </div>
                <div className="flex items-center">
                  {ownerPending[gk] ? (
                    <span
                      role="status"
                      aria-label={owner ? `Releasing ${g.name}` : `Assigning ${g.name}`}
                      className="flex h-[25px] w-[25px] items-center justify-center"
                    >
                      <Spinner size={13} />
                    </span>
                  ) : owner ? (
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        release(g);
                      }}
                      title={`Assigned to ${owner}. Select to release it.`}
                      aria-label={`Release ${g.name}`}
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
                      aria-label={`Assign ${g.name} to me`}
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
                {/* The tags, in the one order of every list: the type, then
                    the handled counts. An unknown count draws one
                    "uncounted" chip with the reason in its tooltip. */}
                <RowTags
                  testId={`alert-tags-${g.id}`}
                  kind={g.kind}
                  counts={
                    <>
                      <HandledChip
                        count={g.ackedCount}
                        icon={<Check size={9} strokeWidth={2.5} />}
                        colour={{ borderColor: 'rgba(34,197,94,.35)', background: 'rgba(34,197,94,.08)', color: '#4ade80' }}
                        known={(n) => `${n} acknowledged`}
                      />
                      <HandledChip
                        count={g.escalatedCount}
                        icon={<ArrowUpRight size={9} strokeWidth={2.5} />}
                        colour={{ borderColor: 'rgba(251,146,60,.35)', background: 'rgba(251,146,60,.08)', color: '#fb923c' }}
                        // "1 escalated." read as a sentence with no noun (V3).
                        known={(n) => `${alertsAre(n)} on a case`}
                        cases={g.cases}
                      />
                      {(g.ackedCount === null || g.escalatedCount === null) && (
                        <span
                          data-testid="counts-unknown"
                          title={COUNTS_UNKNOWN}
                          className="inline-flex flex-shrink-0 cursor-help items-center rounded-chip border px-[5px] py-[2px] text-[10px] font-semibold"
                          style={{ borderColor: 'rgba(148,163,184,.32)', background: 'rgba(148,163,184,.08)', color: '#94a3b8' }}
                        >
                          uncounted
                        </span>
                      )}
                    </>
                  }
                />
                {/* flex-wrap keeps the action pills INSIDE this cell: when an
                    owned row shows all three (Review/Done/Open report) the
                    overflow wraps to a second line below, never left into the
                    "Last seen" column; each button is nowrap so its own label
                    can't break mid-word. */}
                <div className="flex flex-wrap items-center justify-end gap-1.5">
                  {/* Wave 2 Task 7: Detection tuning now lives in the Operate
                      hub, but noise NOMINATIONS still start here — an analyst
                      staring at a noisy group needs a way there without
                      hunting through the nav. Quiet (text only, no border/
                      background) so it doesn't compete with the row's real
                      triage actions below; once per GROUP row, not per event
                      (lives here, not inside the expanded event map). */}
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      navigate('/config#detection-tuning');
                    }}
                    title="Open Detection tuning"
                    className="inline-flex items-center whitespace-nowrap text-[11px] font-semibold text-dim hover:text-accent"
                  >
                    Tune rule
                  </button>
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
                      title="The last re-run failed. Investigate the representative event again."
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
                    <div className="py-2.5 pl-[50px] font-mono text-[11.5px] text-faint"><LoadingInline size={11}>Loading events</LoadingInline></div>
                  )}
                  {!eventsLoading[gk] && eventsError[gk] && (
                    <div
                      role="alert"
                      className="flex items-center gap-2.5 py-2.5 pl-[50px] pr-3.5 font-mono text-[11.5px] text-danger"
                    >
                      <span className="min-w-0 break-words">Could not load the events for this group. {eventsError[gk]}</span>
                      <button
                        onClick={() => fetchFirstPage(g)}
                        className="flex-shrink-0 rounded-control border border-border-strong bg-surface-3 px-2 py-0.5 font-sans text-[11px] font-semibold text-text hover:border-accent"
                      >
                        Retry
                      </button>
                    </div>
                  )}
                  {!eventsLoading[gk] && !eventsError[gk] && (groupEvents[gk]?.length ?? 0) === 0 && (
                    <div className="py-2.5 pl-[50px] font-mono text-[11.5px] text-faint">No events in window.</div>
                  )}
                  {bucketEvents(groupEvents[gk] ?? []).map((b, bi) => {
                    const bk = `${gk}:${bi}`;
                    // Runs under the threshold — and buckets an analyst has
                    // explicitly unfolded — render as plain per-event rows,
                    // byte-identical to the pre-bucketing behavior.
                    if (b.events.length < MIN_BUCKET || openBuckets[bk]) {
                      return b.events.map((ev, i) => (
                        <EventRow
                          key={ev.id ?? `${bk}-${i}`}
                          ev={ev}
                          g={g}
                          selEvents={selEvents}
                          setSelEvents={setSelEvents}
                          navigate={navigate}
                          openDrawer={openDrawer}
                          huntEvent={huntEvent}
                          ackState={ev.id ? eventAck[ev.id] : undefined}
                          onAck={(e) => {
                            if (e.id) void ackSomeEvents([e.id]);
                          }}
                        />
                      ));
                    }
                    const ids = b.events.map((e) => e.id).filter(Boolean) as string[];
                    const allSel = ids.length > 0 && ids.every((id) => selEvents[id]);
                    return (
                      <div
                        key={bk}
                        data-testid="event-bucket-row"
                        className="grid items-center gap-2.5 py-[7px] pl-[36px] pr-3.5 font-mono text-[11.5px] hover:bg-surface-2"
                        style={{ gridTemplateColumns: EVENT_GRID }}
                      >
                        {/* selects every event this bucket covers */}
                        <div onClick={(e) => e.stopPropagation()}>
                          <Checkbox
                            checked={allSel}
                            onChange={(checked) => setSelEvents((prev) => {
                              const next = { ...prev };
                              for (const id of ids) next[id] = checked;
                              return next;
                            })}
                            onClick={(e) => e.stopPropagation()}
                            aria-label={`Select ${b.events.length} identical events`}
                          />
                        </div>
                        {/* span of the collapsed run: both ends dated, one zone.
                            A clock time alone hid a run that crossed midnight
                            (R2-D17). */}
                        <div className="flex min-w-0 flex-col leading-tight" title={`${absTime(b.first) ?? ''} to ${absTime(b.last) ?? ''}`}>
                          <span data-testid="event-time" className="break-words text-text-2">{eventStamp(b.first, false) || '—'} to {eventStamp(b.last) || '—'}</span>
                          {b.head.ago && <span className="text-[10px] text-faint">newest {b.head.ago} ago</span>}
                        </div>
                        {/* severity */}
                        <div><SeverityTag sev={(b.head.sev ?? 'unknown') as Severity} /></div>
                        {/* src → dst:port, plus the collapsed count */}
                        <div className="flex min-w-0 items-center gap-1.5 flex-wrap">
                          <span className="text-mono-green">{b.head.src}</span>
                          <span className="text-ghost">→</span>
                          <span className="break-words text-mono-amber">{b.head.dst}</span>
                          {b.head.port != null && <span className="text-faint">:{b.head.port}</span>}
                          <span className="flex-shrink-0 text-faint" title={`This row holds ${b.events.length} identical events.`}>
                            ×{b.events.length}
                          </span>
                        </div>
                        {/* host the detection fired on */}
                        <div className="flex min-w-0 flex-col leading-tight">
                          <span className="break-words text-dim">{b.head.host}</span>
                        </div>
                        {/* verdict provenance, shared by every event in the run */}
                        <div className="flex min-w-0 items-center">
                          <ProvenanceBadge ev={b.head} onOpen={openDrawer} />
                        </div>
                        {/* unfold into individual rows */}
                        <div className="flex justify-end">
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              setOpenBuckets((s) => ({ ...s, [bk]: true }));
                            }}
                            className="inline-flex items-center whitespace-nowrap font-sans text-[11px] font-semibold text-dim hover:text-accent"
                          >
                            Show each ({b.events.length})
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
                        {eventsLoadingMore[gk] ? 'Loading' : 'Load more'}
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
        {countOf(shown, 'detection')} · grouped · select a row to expand its events
      </div>

      {/* keyboard cheatsheet (E2.5) — `?` opens; Esc / backdrop closes */}
      {keyHelpOpen && <KeyHelpOverlay onClose={() => setKeyHelpOpen(false)} rowKeys />}

      {/* investigation drawer */}
      <AlertDrawer
        drawerId={drawerId}
        starting={starting}
        onClose={closeDrawer}
        returnFocusRef={drawerReturnRef}
        navigateToPermalink={(id) => navigate(`/investigation/${id}`, { state: { from: '/alerts' } })}
        onReHunt={openDrawer}
        onComplete={onDrawerComplete}
        onAcked={onDrawerAcked}
        onEscalate={(inv) =>
          // The drawer's investigation may sit outside the screen's filter, so
          // its escalate takes the server's default window, as the settled bar
          // in the report does.
          askEscalate([drawerGroup(inv)], {})
        }
        escalatingNames={escalatingNames}
        nextName={nextReport?.name ?? null}
        onNext={openNextReport}
        onShowSibling={(s) => {
          // The drawer closes and hands the focus to the row of the sibling.
          drawerRowKeyRef.current = groupKey({ kind: s.kind, name: s.name });
          closeDrawer();
          showSibling(s);
        }}
      />

      {escalateAsk && (
        <EscalateConfirm
          targets={escalateAsk.targets}
          plan={escalateAskPlan}
          onCancel={() => setEscalateAsk(null)}
          onConfirm={() => {
            const ask = escalateAsk;
            setEscalateAsk(null);
            escalateGroups(ask.targets, ask.query);
            ask.onConfirm?.();
          }}
        />
      )}
    </div>
  );
}

/** The next row after the drawer's row that has a report to open. */
export function nextReportAfter(
  list: AlertGroup[],
  drawerId: string,
  rowKey: string | null,
): AlertGroup | null {
  let i = list.findIndex((g) => g.invId === drawerId);
  if (i < 0 && rowKey) i = list.findIndex((g) => groupKey(g) === rowKey);
  if (i < 0) return null;
  return list.slice(i + 1).find((g) => !!g.invId) ?? null;
}

/** The per-press caps of the group writes, as the server enforces them
 *  (routes_alert_actions.py: _ACK_CAP, _ESCALATE_CAP). ack-events takes at
 *  most ACK_CAP ids too. */
export const ACK_CAP = 199;
export const ESCALATE_CAP = 25;

/** The classes that hold the selection strip of the list toolbar sticky to
 *  the top of the scroll area (R2-D16). A sticky box stays inside its parent,
 *  and the parent of the strip is the toolbar box, which ends under the strip.
 *  So the holder and the toolbar box take `display: contents`, and the strip
 *  sticks inside the page. */
const STICKY_SELECTION =
  'contents [&>div]:contents [&_[data-testid=list-toolbar-selection]]:sticky [&_[data-testid=list-toolbar-selection]]:top-2 [&_[data-testid=list-toolbar-selection]]:z-30 [&_[data-testid=list-toolbar-selection]]:shadow-dropdown';

/** What one press of a group write does, from the rows on screen. */
export interface PressPlan {
  /** The alerts of the targets in the window. */
  total: number;
  /** The alerts this press writes: the open alerts, at most the cap for each
   *  group. */
  press: number;
  /** The open alerts past the cap. A further press writes them. */
  rest: number;
  /** True when the grid cannot count the handled alerts of a target. The
   *  press then writes at most `press` alerts. */
  upTo: boolean;
  /** The alerts already on a case, and the alerts only acknowledged. */
  escalated: number;
  acked: number;
  /** The cases the targets are on, one entry per case, from the rows
   *  (R2-I2). Empty when the rows name no case. */
  cases: CaseLink[];
  /** True when `cases` covers every alert already on a case. */
  casesComplete: boolean;
}

/** The plan of one press over the targets, each capped at `cap`, or null when
 *  a target is not on the page and its count is unknown.
 *
 *  The confirm said "Open 1 Security Onion case" for a group already on a
 *  case, "Open 51 cases" where one press opens 25, and "1,531 alerts" on an
 *  ack that writes 199 (dogfood 2026-10-19, R2-D8). Both writes skip an alert
 *  Security Onion already acknowledged or escalated, and an escalate also
 *  acknowledges, so the handled alerts are the larger of the two counts. A
 *  null count is a grid that cannot answer: the press writes at most the
 *  count, and the plan says "at most". */
export function pressPlan(targets: GroupRef[], groups: AlertGroup[], cap: number): PressPlan | null {
  const plan: PressPlan = {
    total: 0,
    press: 0,
    rest: 0,
    upTo: false,
    escalated: 0,
    acked: 0,
    cases: [],
    casesComplete: true,
  };
  for (const t of targets) {
    const g = groups.find((x) => groupKey(x) === groupKey(t));
    if (!g || g.count == null) return null;
    const known = g.ackedCount !== null && g.escalatedCount !== null;
    const onCase = known ? Math.min(g.count, g.escalatedCount ?? 0) : 0;
    const handled = known ? Math.min(g.count, Math.max(onCase, g.ackedCount ?? 0)) : 0;
    const open = g.count - handled;
    plan.total += g.count;
    plan.press += Math.min(open, cap);
    plan.rest += Math.max(0, open - cap);
    plan.upTo = plan.upTo || !known;
    plan.escalated += onCase;
    plan.acked += handled - onCase;
    for (const c of g.cases ?? []) {
      if (!plan.cases.some((x) => x.id === c.id)) plan.cases.push(c);
    }
    if (onCase > 0 && !g.casesComplete) plan.casesComplete = false;
  }
  return plan;
}

/** "on a case", "on case X", "on cases X, Y": where the handled alerts are.
 *  A case list that does not cover every alert names no case here. */
function onCaseWords(plan: PressPlan): string {
  const ids = plan.cases.map((c) => c.id);
  if (!ids.length || !plan.casesComplete) return 'on a case';
  return `on ${ids.length === 1 ? 'case' : 'cases'} ${ids.join(', ')}`;
}

/** The cases a partial list names, as a finding: "soc-ai found case X." */
function foundCases(plan: PressPlan): string | null {
  const ids = plan.cases.map((c) => c.id);
  if (!ids.length || plan.casesComplete) return null;
  return `soc-ai found ${ids.length === 1 ? 'case' : 'cases'} ${ids.join(', ')}.`;
}

/** "1 alert is", "3 alerts are". */
function alertsAre(n: number): string {
  return `${plural(n, 'alert')} ${n === 1 ? 'is' : 'are'}`;
}

/** The label of the bulk Acknowledge button: what one press writes. */
export function ackButtonLabel(groupCount: number, plan: PressPlan | null): string {
  const head = `Acknowledge ${plural(groupCount, 'group')}`;
  if (!plan) return head;
  const upTo = plan.upTo ? 'up to ' : '';
  if (plan.rest > 0) {
    return `${head} · ${upTo}${plan.press.toLocaleString()} of ${plural(plan.press + plan.rest, 'alert')}`;
  }
  return `${head} · ${upTo}${plural(plan.press, 'alert')}`;
}

/** Why the bulk Acknowledge button is off: Security Onion already handled
 *  every alert of the selection, so a press writes nothing (V1-A6). Null
 *  when a press writes, and when the grid cannot count the handled alerts. */
export function ackButtonOffReason(plan: PressPlan | null): string | null {
  if (!plan || plan.upTo || plan.press > 0) return null;
  return 'Every alert of the selected groups is already acknowledged or on a case. A press writes nothing.';
}

/** The title of the bulk Acknowledge button, when one press is not enough. */
export function ackButtonTitle(plan: PressPlan | null): string | undefined {
  if (!plan || plan.rest === 0) return undefined;
  const others = plan.upTo ? 'the other alerts' : `the other ${plural(plan.rest, 'alert')}`;
  return `One press acknowledges at most ${ACK_CAP} alerts of each group. Press Acknowledge again for ${others}.`;
}

/** The sentences an escalate confirm shows: what one press opens. */
export function escalateConfirmText(targets: GroupRef[], plan: PressPlan | null): string {
  const many = targets.length > 1;
  const what = many ? `${targets.length} detections` : targets[0].name;
  const capSentence = `One press opens at most ${ESCALATE_CAP} cases${many ? ' for each detection' : ''}.`;
  if (plan == null) {
    return `Open one Security Onion case for each alert of ${what}. ${capSentence}`;
  }
  const s: string[] = [];
  const handled = plan.escalated + plan.acked;
  if (plan.press === 0) {
    // Every alert is already handled (R2-I2). The press opens nothing, and
    // the confirm must not promise a case.
    if (plan.escalated === plan.total) {
      s.push(
        plan.total === 1
          ? `The alert of ${what} is already ${onCaseWords(plan)}.`
          : `The ${plan.total.toLocaleString()} alerts of ${what} are already ${onCaseWords(plan)}.`,
      );
      const found = foundCases(plan);
      if (found) s.push(found);
    } else if (plan.acked === plan.total) {
      s.push(
        plan.total === 1
          ? `The alert of ${what} is already acknowledged.`
          : `The ${plan.total.toLocaleString()} alerts of ${what} are already acknowledged.`,
      );
    } else {
      if (plan.escalated > 0) s.push(`${alertsAre(plan.escalated)} already ${onCaseWords(plan)}.`);
      const found = foundCases(plan);
      if (found) s.push(found);
      if (plan.acked > 0) s.push(`${alertsAre(plan.acked)} already acknowledged.`);
    }
    s.push('soc-ai opens no case.');
    return s.join(' ');
  }
  const cases = plan.press === 1 ? 'case' : 'cases';
  if (plan.upTo) {
    s.push(
      `Open at most ${plan.press.toLocaleString()} Security Onion ${cases} for the ${plural(plan.total, 'alert')} of ${what}.`,
      'soc-ai skips an alert that is already acknowledged or on a case.',
    );
  } else if (handled === 0 && plan.rest === 0) {
    s.push(
      plan.press === 1
        ? `Open 1 Security Onion case for the alert of ${what}.`
        : `Open ${plan.press.toLocaleString()} Security Onion cases, one for each alert of ${what}.`,
    );
  } else {
    s.push(
      `Open ${plan.press.toLocaleString()} Security Onion ${cases} for ${plan.press.toLocaleString()} of the ${plural(plan.total, 'alert')} of ${what}.`,
    );
    if (plan.escalated > 0) s.push(`${alertsAre(plan.escalated)} already ${onCaseWords(plan)}.`);
    const found = foundCases(plan);
    if (found) s.push(found);
    if (plan.acked > 0) s.push(`${alertsAre(plan.acked)} already acknowledged.`);
  }
  if (plan.rest > 0) {
    const others = plan.upTo ? 'the other alerts' : `the other ${plural(plan.rest, 'alert')}`;
    s.push(capSentence, `Press Escalate again for ${others}.`);
  }
  return s.join(' ');
}

function EscalateConfirm({
  targets,
  plan,
  onCancel,
  onConfirm,
}: {
  targets: GroupRef[];
  plan: PressPlan | null;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  // Esc cancels. Capture phase, so the drawer behind does not also close.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      e.stopPropagation();
      onCancel();
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [onCancel]);
  // A plan that opens no case offers no write. Its one button closes.
  const writes = plan == null || plan.press > 0;
  const cases = plan?.press === 1 ? 'case' : 'cases';
  return (
    <div
      className="fixed inset-0 z-[70] flex items-center justify-center"
      style={{ background: 'rgba(0,0,0,.65)' }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onCancel();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Confirm escalate"
        data-testid="escalate-confirm"
        className="relative w-[460px] max-w-[calc(100vw-32px)] rounded-panel-lg border p-6"
        style={{ background: '#0e1117', borderColor: '#1c232e' }}
      >
        <div className="mb-4 text-[14px] font-semibold">Escalate to Security Onion</div>
        <div
          className="mb-5 flex items-start gap-2 rounded-[7px] border px-3 py-2.5 text-[12.5px] leading-[1.5]"
          style={
            writes
              ? { borderColor: 'rgba(240,68,56,.35)', background: 'rgba(240,68,56,.07)', color: '#fca5a5' }
              : { borderColor: 'rgba(148,163,184,.32)', background: 'rgba(148,163,184,.08)', color: '#cbd5e1' }
          }
        >
          <AlertTriangle size={13} className="mt-px flex-none" />
          <span>
            {writes ? 'This writes to Security Onion. ' : ''}
            {escalateConfirmText(targets, plan)}
          </span>
        </div>
        {/* The cases the alerts are already on, each a link to its page in
            the Security Onion console (R2-I2). */}
        {(plan?.cases ?? []).some((c) => !!c.url) && (
          <div data-testid="escalate-confirm-cases" className="-mt-2 mb-5 flex flex-wrap gap-x-3 gap-y-1 text-[12.5px]">
            {(plan?.cases ?? [])
              .filter((c): c is { id: string; url: string } => !!c.url)
              .map((c) => (
                <a
                  key={c.id}
                  href={c.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  aria-label={`Open case ${c.id} in Security Onion`}
                  className="inline-flex items-center gap-1 font-semibold text-accent hover:underline"
                >
                  Open case {c.id}
                  <ArrowUpRight size={12} />
                </a>
              ))}
          </div>
        )}
        <div className="flex justify-end gap-2.5">
          <button
            onClick={onCancel}
            className="rounded-control border border-border-strong bg-surface-3 px-4 py-2 text-[13px] font-semibold text-text-2 hover:text-text"
          >
            {writes ? 'Cancel' : 'Close'}
          </button>
          {writes && (
            <button
              onClick={onConfirm}
              className="rounded-control border border-danger bg-[rgba(240,68,56,.1)] px-4 py-2 text-[13px] font-semibold text-[#fca5a5] hover:bg-[rgba(240,68,56,.18)]"
            >
              {plan == null
                ? 'Open the cases'
                : `Open ${plan.upTo ? 'at most ' : ''}${plan.press.toLocaleString()} ${cases}`}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

/** The group the drawer's investigation belongs to, shaped for the group write. */
function drawerGroup(inv: Inv): GroupRef {
  return { name: inv.name, kind: inv.kind };
}

/** Whether the drawer header offers Escalate. A hunt has no alert in Security
 *  Onion. A settled run with no actions shows its own Escalate in the report,
 *  and a second button for the same write would only confuse. */
function drawerCanEscalate(inv: Inv): boolean {
  if (inv.kind === 'hunt') return false;
  const settledBar = inv.status === 'complete' && inv.actions.length === 0 && !inv.fallback;
  return !settledBar;
}

function AlertDrawer({
  drawerId,
  starting,
  onClose,
  returnFocusRef,
  navigateToPermalink,
  onReHunt,
  onComplete,
  onAcked,
  onEscalate,
  escalatingNames = [],
  nextName = null,
  onNext,
  onShowSibling,
}: {
  drawerId: string | null;
  starting: AlertGroup | null;
  onClose: () => void;
  returnFocusRef?: RefObject<HTMLElement | null>;
  navigateToPermalink: (id: string) => void;
  onReHunt: (id: string) => void;
  onComplete: () => void;
  onAcked?: (ruleName: string) => void;
  onEscalate?: (inv: Inv) => void;
  escalatingNames?: string[];
  /** The rule of the next alert with a report, or null at the end of the list. */
  nextName?: string | null;
  onNext?: () => void;
  /** Show a same-flow sibling of the report on the list. */
  onShowSibling?: (sibling: AlertSibling) => void;
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
      returnFocusRef={returnFocusRef}
      ariaLabel={inv?.name ?? starting?.name ?? 'Investigation'}
      header={
        <>
          {/* KindBadge, not a hand-rolled chip: this one hardcoded Suricata's
              blue whatever kind it printed, so a hunt-promoted or generic-alert
              investigation still opened wearing a Suricata colour. */}
          <KindBadge kind={inv?.kind ?? starting?.kind ?? 'alert'} />
          <div className="min-w-0 flex-1 break-words text-[14px] font-semibold" title={inv?.name ?? starting?.name ?? 'Investigation'}>
            {inv?.name ?? starting?.name ?? 'Investigation'}
          </div>
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
              <X size={13} /> {cancelling ? 'Cancelling' : 'Cancel'}
            </button>
          )}
          {inv && onEscalate && drawerCanEscalate(inv) && (
            <button
              onClick={() => onEscalate(inv)}
              disabled={escalatingNames.includes(inv.name)}
              title="Open a Security Onion case for each alert in this detection"
              className="flex items-center gap-1.5 text-[12px] font-semibold text-[#fca5a5] hover:text-danger disabled:opacity-50"
            >
              {escalatingNames.includes(inv.name) ? <Spinner size={12} /> : null}
              {escalatingNames.includes(inv.name) ? 'Escalating' : 'Escalate'}
            </button>
          )}
          {onNext && (
            <button
              data-testid="drawer-next"
              onClick={onNext}
              disabled={!nextName}
              title={
                nextName
                  ? `Open the next alert: ${nextName}. Keys: j or the down arrow.`
                  : 'No later alert in this list has a report.'
              }
              className="flex items-center gap-1 text-[12px] font-semibold text-dim hover:text-accent disabled:opacity-40"
            >
              Next <ChevronRight size={13} />
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
      {isStarting && <LoadingState label={`Starting the investigation of ${starting?.name}`} />}
      {drawerId && loading && !inv && <LoadingState label="Loading investigation" />}
      {error && <div className="p-4"><ErrorState error={error} onRetry={refetch} /></div>}
      {inv && (
        <Investigation
          inv={inv}
          layout="drawer"
          onReHunt={onReHunt}
          onVerdictApplied={() => setTick((x) => x + 1)}
          onAcked={onAcked}
          onShowSibling={onShowSibling}
        />
      )}
    </Drawer>
  );
}
