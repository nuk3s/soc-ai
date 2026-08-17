import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  CircleDashed,
  RadioTower,
  RefreshCw,
  Server,
  UserCheck,
} from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { StatusTag } from '../components/Badges';
import { Checkbox, Select } from '../components/Controls';
import { DOSSIER_CONFIG_HREF, HostsSummary } from '../components/HostsSummary';
import { ListToolbar } from '../components/ListToolbar';
import { Panel, PanelHeader } from '../components/Panel';
import { EmptyState, ErrorState, Freshness, LoadingState, StaleNotice } from '../components/States';
import {
  bulkSetDossierOverride,
  getDossierConflicts,
  getDossierRefreshStatus,
  getDossierSummary,
  getMe,
  listDossiers,
  startDossierRefresh,
} from '../lib/api';
import { cn } from '../lib/cn';
import { demoBlocked, useDemo } from '../lib/demo';
import { criticalityAccent, provenanceTone, roleAccent } from '../lib/hostColors';
import { fieldLabel, isResolved, roleLabel, roleVocabulary } from '../lib/hostDossier';
import { plural } from '../lib/plural';
import { SHOWN_ERRORS, sweepErrorList } from '../lib/sweepErrors';
import { ago } from '../lib/timeRange';
import { useListSelection } from '../lib/useListSelection';
import { useSavedViews } from '../lib/useSavedViews';
import type {
  DossierConflictKind,
  DossierConflictRow,
  DossierFieldBrief,
  DossierFieldName,
  DossierRefreshStatus,
  DossierRow,
  DossierSortKey,
  Me,
  SavedViewQuery,
} from '../lib/types';
import { useAsync } from '../lib/useAsync';

// ---------------------------------------------------------------------------
// Sweep health for a NON-admin: GET /api/v1/dossiers/sweep-health.
//
// `GET /dossiers/refresh` is admin-gated because its `last_summary` carries the
// sweep's raw failure strings; the projection is the CLOSED four-field record
// (running / degraded / last_run / error count) the backend serves to any
// authenticated caller, so the honest empty states below work for every role —
// before it existed, an analyst on a fresh install read "the sweep hasn't run
// yet" over a sweep that ran and died. Fetched here rather than through
// lib/api.ts deliberately: lib/ belongs to an in-flight branch, and this moves
// there when it frees up (the sweepErrors.ts precedent — HostDetail carries the
// same copy for the same reason). No login redirect on a failure either: a
// failed read leaves the sweep unreadable — the empty lead says "could not
// check" rather than claiming no sweep has run — and every other request on
// this screen still goes through lib/api's own expiry handoff.
// ---------------------------------------------------------------------------

interface SweepHealth {
  running: boolean;
  degraded: boolean;
  last_run: string | null;
  error_count: number;
}

async function getSweepHealth(): Promise<SweepHealth> {
  const token = import.meta.env.VITE_API_TOKEN as string | undefined;
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch('/api/v1/dossiers/sweep-health', {
    credentials: 'include',
    signal: AbortSignal.timeout(20_000),
    headers,
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as SweepHealth;
}

/** One shape for BOTH status reads, so everything below keys off what is known
 *  rather than which route the caller was allowed to ask. `errors` and
 *  `summary` are the admin read's extras; the projection leaves them empty —
 *  `errorCount` is the piece of the verdict that crosses the role boundary. */
interface SweepStatusRead {
  running: boolean;
  last_run: string | null;
  degraded: boolean;
  errors: string[];
  errorCount: number;
  summary: Record<string, unknown> | null;
}

const fromFullStatus = (s: DossierRefreshStatus): SweepStatusRead => {
  const errors = sweepErrorList(s.last_summary);
  return {
    running: s.running,
    last_run: s.last_run,
    degraded: errors.length > 0,
    errors,
    errorCount: errors.length,
    summary: s.last_summary,
  };
};

const fromProjection = (h: SweepHealth): SweepStatusRead => ({
  running: h.running,
  last_run: h.last_run,
  degraded: h.degraded,
  errors: [],
  errorCount: h.error_count,
  summary: null,
});

// One SQL page. The store's own default (DEFAULT_LIST_LIMIT in
// soc_ai/store/host_dossier.py); the endpoint 422s above MAX_LIST_LIMIT=200.
// The network is capped at 5,000 hosts, which is why this screen pages against
// the server instead of fetching the table and slicing it.
const PAGE_SIZE = 50;

// A typed query is a new result set, so a keystroke can't fire a request.
const SEARCH_DEBOUNCE_MS = 250;

// address | host | role | flags | events | last seen. Identity first, then the
// flags column that says which rows want a human — the criticality word, the
// disagreement badge, the declared count and the broken-build marker share it,
// because they answer one question ("does this row need me?") and the two
// columns they used to occupy were dashes on 37+ of 41 rows.
const GRID = 'minmax(126px,1fr) minmax(110px,1.1fr) minmax(110px,1fr) minmax(120px,1fr) 76px 82px';
// With the select column, when the operator can actually declare something.
// Same 28px gutter the Investigations table uses.
const GRID_SELECTABLE = `28px ${GRID}`;

// The two fields a bulk declare is FOR. Both are operator-lane-only in practice
// — criticality is never inferred at all, and a role the sweep guessed is the
// thing an operator most often corrects across a whole subnet at once.
const BULK_FIELDS: Array<{ value: 'role' | 'criticality'; label: string }> = [
  { value: 'criticality', label: 'Criticality' },
  { value: 'role', label: 'Role' },
];

// The criticality vocabulary, worst first — the same four words the importance
// sort ranks on (soc_ai/store/host_dossier.py::_CRITICALITY_RANK).
const CRITICALITIES = ['critical', 'high', 'medium', 'low'];

const SORTS: Array<{ value: DossierSortKey; label: string }> = [
  // Importance is what the screen LANDS on, and the label is the rule: hosts
  // graded critical or high, then NAMED hosts, then the rest of the grading
  // (medium, low), then any host a human has touched. Only the two grades that
  // say the host matters lead the named ones — putting every grade in front
  // would mean one bulk "declare criticality" pass over a subnet of printers
  // tagged low buries the named servers, which is this very defect again.
  // Attention — broken builds, then
  // open disagreements, then declared, then named — was the landing order and
  // is now one click away. It ranks "no clean build" first, and on a real
  // estate that is not a tier, it is nearly the whole table: the first screen
  // was 15 rows of `HOST — ROLE —` while the domain controller sat below the
  // fold (dogfood B2a, 2026-08-11). Broken hosts stay findable — this control,
  // the summary bar's own count, and the ?health=broken filter behind it.
  { value: 'importance', label: 'named & critical first' },
  { value: 'attention', label: 'needs attention' },
  { value: 'last_seen', label: 'last seen' },
  { value: 'first_seen', label: 'first seen' },
  { value: 'stale', label: 'stalest' },
  { value: 'event_count', label: 'busiest' },
  { value: 'ip', label: 'address' },
];

// The landing order is the SCREEN's choice, not the endpoint's: the API keeps
// defaulting to `attention` for callers asking "what is the sweep failing to
// reach", and this screen always names the order it wants (see SORTS). Named,
// because a saved view that does not carry a sort must restore THIS, not
// whatever the operator happened to be sorting by.
const DEFAULT_SORT: DossierSortKey = 'importance';

// How a disagreement undermines the declaration, weakest first. The word alone
// is jargon; the gloss is what tells an operator whether their answer was wrong
// or merely about a machine that is no longer there.
const CONFLICT_KIND_HELP: Record<DossierConflictKind, string> = {
  mismatch: 'The evidence points somewhere else',
  retracted: 'The evidence this field rested on is gone',
  rebound: 'A different machine appears to answer on this address now',
};

/** Pull one field out of a row's twelve. The wire order is the backend's render
 *  order, so a positional read would silently shift if a field were ever added
 *  in the middle of DOSSIER_FIELDS. */
function fieldOf(row: DossierRow, name: DossierFieldName): DossierFieldBrief | undefined {
  return row.fields.find((f) => f.field === name);
}

/** Why a cell shows nothing — three different answers that a bare blank cell
 *  collapses into one. */
function unresolvedTitle(f: DossierFieldBrief | undefined): string {
  switch (f?.reason) {
    case 'stale':
      return 'Last observed too long ago to trust — the sweep has not re-confirmed it';
    case 'low_confidence':
      return 'Observed, but the evidence is too thin to say';
    case 'no_signal':
      return 'Nothing found for this yet';
    default:
      return 'Not known';
  }
}

function absolute(iso: string | null): string {
  if (!iso) return 'never seen';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

/** One lane's answer as text, for the conflict queue. The structured fields
 *  leave `value` null and carry the answer in `value_json` — a cell reading
 *  only the scalar renders blank on exactly the rows hardest to read. */
function laneText(value: string | null, json: unknown): string | null {
  const scalar = value?.trim();
  if (scalar) return scalar;
  if (json == null) return null;
  return typeof json === 'string' ? json : JSON.stringify(json);
}

/** The em-dash a cell shows when a field never resolved. TEXT, never a link:
 *  the placeholder is a truthy string, and `value ? <link> : <text>` is what
 *  shipped `/entity/%E2%80%94` on the Alerts screen (2026-08-07). */
function Unknown({ f }: { f: DossierFieldBrief | undefined }) {
  return (
    <span className="text-faint" title={unresolvedTitle(f)}>
      —
    </span>
  );
}

/**
 * Everything on a row that says "this one wants a human", in one cell:
 * a broken or never-run build, an open disagreement, the operator's own
 * declarations, and the criticality word. No per-row confidence decimals —
 * "0.63" vs "0.70" is not a distinction anyone acts on in a table.
 */
function FlagsCell({ row }: { row: DossierRow }) {
  const crit = fieldOf(row, 'criticality');
  const critValue = crit && isResolved(crit) ? crit.value : null;
  const empty =
    !row.build_error &&
    row.last_built_at != null &&
    row.conflict_count === 0 &&
    row.override_count === 0 &&
    !row.reporting &&
    !critValue;
  if (empty) return null;
  return (
    <span className="flex flex-wrap items-center gap-1.5">
      {row.build_error && (
        <span
          title={`Last build failed: ${row.build_error}`}
          aria-label="build failed"
          className="flex items-center text-danger"
        >
          <AlertTriangle size={12} />
        </span>
      )}
      {!row.build_error && row.last_built_at == null && (
        <span
          title="Never built — no sweep has written this host yet"
          aria-label="never built"
          className="flex items-center text-faint"
        >
          <CircleDashed size={12} />
        </span>
      )}
      {row.conflict_count > 0 && (
        <span
          title={`The sweep disagrees with ${row.conflict_count} declared field${row.conflict_count === 1 ? '' : 's'} — open the host to decide`}
          className="flex items-center gap-1 rounded-badge border border-warn/40 bg-warn/10 px-[6px] py-[2px] font-mono text-[10.5px] font-semibold text-warn"
        >
          <AlertTriangle size={10} />
          {row.conflict_count}
        </span>
      )}
      {row.override_count > 0 && (
        <span
          title={`${row.override_count} field${row.override_count === 1 ? '' : 's'} declared by an operator`}
          className="flex items-center gap-1 rounded-badge border border-border-2 bg-surface-2 px-[6px] py-[2px] font-mono text-[10.5px] text-text-2"
        >
          <UserCheck size={10} />
          {row.override_count}
        </span>
      )}
      {/* Agent coverage, row by row: the aggregate ("no agent data on 32")
          never said WHICH rows were the blind spots. Marking the covered
          minority keeps the flag rare — absence reads as network-only. */}
      {row.reporting && (
        <span
          title="An agent on this machine reports its own logs — its host page can say more than traffic alone shows"
          aria-label="agent reporting"
          className={cn('flex items-center', provenanceTone('hostlog'))}
        >
          <RadioTower size={11} />
        </span>
      )}
      {critValue && (
        <span
          title="Criticality — how much this machine matters"
          className={cn(
            'rounded-chip border px-1.5 py-px font-mono text-[10.5px] font-semibold',
            criticalityAccent(critValue),
          )}
        >
          {critValue}
        </span>
      )}
    </span>
  );
}

/** One open disagreement, read-only. Both claims side by side is the whole
 *  argument; the two RESOLUTIONS live on the host page, so this queue is pure
 *  triage. */
function ConflictRow({ c }: { c: DossierConflictRow }) {
  const yours = laneText(c.operator_value, c.operator_value_json);
  const theirs = laneText(c.inferred_value, c.inferred_value_json);
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-border-faint px-3.5 py-2 text-[12.5px] last:border-0">
      <Link
        // ?field= is the host page's highlight+scroll target — without it the
        // reader lands with no sign of which fact prodded.
        to={`/hosts/${encodeURIComponent(c.ip)}?field=${encodeURIComponent(c.field)}`}
        className="flex-none font-mono text-[12px] font-semibold text-accent hover:underline"
      >
        {`${c.ip} · ${fieldLabel(c.field).toLowerCase()}`}
      </Link>
      {c.kind && (
        <span className="flex-none text-[11px] text-faint" title={CONFLICT_KIND_HELP[c.kind]}>
          {c.kind}
        </span>
      )}
      <span className="flex min-w-0 items-center gap-1.5">
        <span className="flex-none text-[11px] text-faint">yours</span>
        <span className="min-w-0 truncate font-mono text-[11.5px] text-text-2">{yours ?? '—'}</span>
      </span>
      <span className="flex min-w-0 items-center gap-1.5">
        <span className="flex-none text-[11px] text-faint">sweep</span>
        <span className="min-w-0 truncate font-mono text-[11.5px] text-text-2">{theirs ?? '—'}</span>
      </span>
      <span
        className="flex-none text-[11px] text-faint"
        title="Sweeps that concluded this since the disagreement opened"
      >
        seen {c.observations}x
      </span>
      {c.identity_rebound_at && (
        <span
          className="flex-none text-[11px] font-semibold text-warn"
          title={`A different machine appears to hold this address since ${absolute(c.identity_rebound_at)} — the declaration may describe a host that has moved on`}
        >
          rebound
        </span>
      )}
    </div>
  );
}

/**
 * The host list: every machine the sweep holds a row for, ordered by which
 * rows want a human first.
 *
 * The screen shows the RESOLVED answer — the operator's declaration where one
 * exists, otherwise what the sweep concluded — because that is the only value
 * anything downstream (the agent's prompt block, the host tool) ever sees.
 */
export function Hosts() {
  const navigate = useNavigate();
  const demo = useDemo();
  const [searchParams, setSearchParams] = useSearchParams();

  // Filters are SERVER parameters, not a view over the fetched page: the table
  // is one page of up to 5,000 hosts, and a client-side filter would quietly
  // claim the other 4,950 don't match.
  const [q, setQ] = useState('');
  const [debouncedQ, setDebouncedQ] = useState('');
  const [role, setRole] = useState('');
  const [source, setSource] = useState('');
  const [sort, setSort] = useState<DossierSortKey>(DEFAULT_SORT);
  const [offset, setOffset] = useState(0);
  // The broken-builds view lives in the URL so the summary bar's count can be
  // a door and the view can be shared. The spelling (?health=broken) is the
  // hosts-kpi backend contract — the same predicate the count describes.
  const health = searchParams.get('health') === 'broken' ? ('broken' as const) : undefined;

  useEffect(() => {
    const t = setTimeout(() => setDebouncedQ(q.trim()), SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [q]);
  // A new query is a new result set — page 3 of the old one means nothing
  // under it. Reset with the DEBOUNCED value so offset and query change in one
  // refetch instead of two.
  useEffect(() => {
    setOffset(0);
  }, [debouncedQ, health]);

  const list = useAsync(
    () =>
      listDossiers({
        q: debouncedQ || undefined,
        role: role || undefined,
        source: source === 'operator' || source === 'inferred' ? source : undefined,
        health,
        sort,
        limit: PAGE_SIZE,
        offset,
      }),
    [debouncedQ, role, source, health, sort, offset],
  );

  // The summary bar's numbers: an AGGREGATE request over the whole table,
  // never computed from `list.data.rows` (one page of up to 5,000 hosts).
  const kpis = useAsync(() => getDossierSummary(), []);

  // The disagreement queue. Its own request because `pending` counts the whole
  // queue, not this page.
  const conflicts = useAsync(() => getDossierConflicts(), []);
  const pending = conflicts.data?.pending ?? 0;
  // The Dashboard nudge deep-links with ?conflicts=1. Initializer-only: once
  // mounted the operator owns the toggle and the URL never fights them.
  const [showConflicts, setShowConflicts] = useState(() => searchParams.get('conflicts') === '1');
  const conflictsParam = searchParams.get('conflicts');
  useEffect(() => {
    if (conflictsParam === '1') setShowConflicts(true);
  }, [conflictsParam]);

  // The SPA's only role source (Sidebar reads it the same way). The mutating
  // dossier routes are admin-gated server-side with no `hint` on the 403.
  const [me, setMe] = useState<Me | null>(null);
  useEffect(() => {
    getMe()
      .then(setMe)
      .catch(() => {
        /* unknown role — the rebuild control stays hidden, reads still work */
      });
  }, []);
  const isAdmin = me?.role === 'admin';

  // Sweep status. The FULL record (counters + failure strings) is an
  // admin-gated GET; every other role reads the closed sweep-health projection
  // instead, so a dead or running sweep is disclosed to whoever is looking at
  // the list it explains. Neither is asked until /me has answered — the
  // projection needs an authenticated caller, and getMe failing leaves the
  // whole page degraded anyway. Polling is armed but SKIPPED unless a sweep is
  // in flight — a rebuild is a rare, operator-initiated act, not a live
  // console.
  const roleKnown = me !== null;
  const runningRef = useRef(false);
  const refresh = useAsync<SweepStatusRead | null>(
    () =>
      isAdmin
        ? getDossierRefreshStatus().then(fromFullStatus)
        : roleKnown
          ? getSweepHealth().then(fromProjection)
          : Promise.resolve(null),
    [isAdmin, roleKnown],
    { refetchInterval: 4000, pauseWhen: () => !runningRef.current },
  );
  const running = !!refresh.data?.running;
  runningRef.current = running;
  const [starting, setStarting] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  // A finished sweep rewrote every row it touched — reload the page the
  // operator is looking at rather than leaving them on pre-sweep answers.
  const wasRunning = useRef(false);
  useEffect(() => {
    if (wasRunning.current && !running) {
      list.refetch();
      conflicts.refetch();
      // The bar counts what the sweep just rewrote; leaving it on pre-sweep
      // numbers would make it the one thing on screen describing yesterday.
      kpis.refetch();
    }
    wasRunning.current = running;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running]);

  const rebuild = async () => {
    const blocked = demoBlocked(demo);
    if (blocked) {
      setNote(blocked);
      return;
    }
    setStarting(true);
    setNote(null);
    try {
      const status = await startDossierRefresh();
      // 'started' is the happy path and needs no words; 'already running' and
      // 'dossier disabled' both mean THIS click did nothing, and saying so is
      // the difference between an honest no-op and a button that lies.
      if (status.note && status.note !== 'started') setNote(status.note);
      refresh.refetch();
    } catch (err) {
      setNote(err instanceof Error ? err.message : String(err));
    } finally {
      setStarting(false);
    }
  };

  const rows = list.data?.rows ?? [];
  const total = list.data?.total ?? 0;
  const limit = list.data?.limit ?? PAGE_SIZE;
  const shownFrom = total === 0 ? 0 : offset + 1;
  const shownTo = Math.min(offset + limit, total);

  // Checkboxes — the one list screen that never had them (dogfood A4). Admin
  // only, because the declare they exist for is admin-gated server-side:
  // offering a selection to an analyst who can only be 403'd for using it is a
  // worse screen than not offering it.
  const sel = useListSelection(rows.map((r) => r.ip));
  const selecting = isAdmin && sel.count > 0;
  const [bulkField, setBulkField] = useState<'role' | 'criticality'>('criticality');
  const [bulkValue, setBulkValue] = useState('');
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkNote, setBulkNote] = useState<string | null>(null);
  useEffect(() => {
    if (!bulkNote) return;
    const t = setTimeout(() => setBulkNote(null), 6000);
    return () => clearTimeout(t);
  }, [bulkNote]);

  const declare = async () => {
    const ips = sel.ids;
    const value = bulkValue.trim();
    if (!ips.length || !value) return;
    const blocked = demoBlocked(demo);
    if (blocked) {
      setBulkNote(blocked);
      return;
    }
    setBulkBusy(true);
    setBulkNote(null);
    try {
      const out = await bulkSetDossierOverride(ips, { field: bulkField, value });
      // Name what did NOT take, per arm. A bare count — or worse, a raw error
      // after a batch that half-landed — leaves the operator re-checking every
      // row by hand.
      const names = (list: string[]) =>
        `${list.slice(0, 3).join(', ')}${list.length > 3 ? `, +${list.length - 3} more` : ''}`;
      const failedIps = (out.failed ?? []).map((f) => f.ip);
      const parts = [
        `Declared ${bulkField} "${value}" on ${out.updated.length} of ${ips.length} host${ips.length === 1 ? '' : 's'}`,
      ];
      if (out.not_found.length) {
        parts.push(`${out.not_found.length} not swept yet (${names(out.not_found)})`);
      }
      if (failedIps.length) {
        parts.push(`${failedIps.length} failed (${names(failedIps)}) — try those again`);
      }
      setBulkNote(parts.join(' · '));
      // Keep the ones that did not land selected, so "try those again" is one
      // click and not a re-selection exercise (the Alerts retry contract).
      const retry = [...out.not_found, ...failedIps];
      if (retry.length) sel.select(retry);
      else sel.clear();
      setBulkValue('');
      list.refetch();
      kpis.refetch();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setBulkNote(/^403\b/.test(msg) ? 'Only an admin can declare host facts.' : msg);
    } finally {
      setBulkBusy(false);
    }
  };

  // First run: nothing swept, nothing filtered. One sentence and one action —
  // not four zero tiles, two competing calls to action and a live search box
  // over zero rows.
  const unfiltered = !debouncedQ && !role && !source && !health;
  const firstRun = !!list.data && total === 0 && unfiltered;

  // The role options the screen can honestly offer: the classifier's closed
  // vocabulary read from the summary wire (frontend list as fallback), plus any
  // declared role visible on this page, plus whatever is currently selected (so
  // an active filter never vanishes from its own list).
  const wireRoles = kpis.data?.role_vocabulary;
  const roleOptions = useMemo(() => {
    const seen = new Set(roleVocabulary(wireRoles));
    for (const r of rows) {
      const v = fieldOf(r, 'role')?.value?.trim();
      if (v) seen.add(v);
    }
    if (role) seen.add(role);
    return [
      { value: '', label: 'any role' },
      ...[...seen].sort().map((r) => ({ value: r, label: roleLabel(r) })),
    ];
  }, [rows, role, wireRoles]);

  // What a BULK declare may set a role to: the classifier's closed vocabulary,
  // and nothing else. Deliberately NOT `roleOptions` — the filter widens to
  // whatever is on the page (a filter that cannot name a value on screen is
  // broken), but a bulk WRITE that widens the same way would launder one
  // free-text declare into the list everyone picks from.
  //
  // The single-host declare on /hosts/:ip stays free text on purpose. An
  // operator who knows a machine is a `jump_host` knows more than the
  // classifier, and that claim costs one row. This control writes the same
  // keystroke to every selected host, and a role is a bucket in the ROLES bar
  // and an entry in this screen's own facet — so one typo here is a new
  // first-class role for every user of the deployment. The server enforces the
  // same list (routes_dossier.py::bulk_set_dossier_override, `unknown_role`);
  // this is the affordance, not the guard.
  const bulkRoleOptions = useMemo(
    () => [
      { value: '', label: 'choose…' },
      ...[...roleVocabulary(wireRoles)].sort().map((r) => ({ value: r, label: roleLabel(r) })),
    ],
    [wireRoles],
  );

  // Saved views. The whole filter set travels as one object, so a chip restores
  // it whole — half-applying a view is how a "saved" view stops being the thing
  // that was saved.
  const currentQuery: SavedViewQuery = { q, role, source, sort };
  // A TOTAL apply: a facet the view does not name goes back to THIS screen's
  // default, never to whatever was on screen a moment ago. That is also what
  // makes the chip a real toggle — clicking an active chip applies the empty
  // query, which is this screen unfiltered.
  const views = useSavedViews('hosts', currentQuery, (saved) => {
    setQ(typeof saved.q === 'string' ? saved.q : '');
    setRole(typeof saved.role === 'string' ? saved.role : '');
    setSource(typeof saved.source === 'string' ? saved.source : '');
    setSort(typeof saved.sort === 'string' ? (saved.sort as DossierSortKey) : DEFAULT_SORT);
    setOffset(0);
  });

  const onRole = (v: string) => {
    setRole(v);
    setOffset(0);
    views.clearActive();
  };
  const onSource = (v: string) => {
    setSource(v);
    setOffset(0);
    views.clearActive();
  };
  const onSort = (v: string) => {
    setSort(v as DossierSortKey);
    setOffset(0);
    views.clearActive();
  };
  const clearHealth = () => {
    const next = new URLSearchParams(searchParams);
    next.delete('health');
    setSearchParams(next, { replace: true });
  };

  const summary = refresh.data?.summary ?? null;
  const summaryCount = (key: string): number | null => {
    const v = summary?.[key];
    return typeof v === 'number' ? v : null;
  };

  // What the last sweep DID, with no clock on it: the age of the data itself
  // is the summary bar's one freshness line, and a second clock here (the
  // sweep PROCESS's own stamp) legitimately disagrees with it.
  const sweptCounts: string[] = [];
  const hostsBuilt = summaryCount('hosts_built');
  const fieldsWritten = summaryCount('fields_written');
  if (hostsBuilt != null) sweptCounts.push(`${hostsBuilt.toLocaleString()} hosts built`);
  if (fieldsWritten != null) sweptCounts.push(`${fieldsWritten.toLocaleString()} fields written`);

  // What the sweep could NOT do. The counts above are the sweep's own report of
  // its work, and on a blind run they are a quiet, plausible-looking zero — the
  // refresh route writes a bare {"errors": [...]} when the task died, so on the
  // worst run of all there are no counts to print at all and this line was the
  // only thing that could have said so.
  //
  // `errors` and nothing else. DossierSummary keeps advisory `notes` (a
  // truncated cap, a cadence ceiling) in a separate field precisely so a
  // healthy nightly sweep does not report trouble every night, and a zero
  // count is not trouble either: an estate where nothing changed builds zero
  // hosts and that is the right answer. (The projection's `degraded` is keyed
  // to the same rule server-side, so the two reads cannot disagree about
  // whether a run was trouble.)
  //
  // The STRINGS are the admin read's; a non-admin gets the verdict and the
  // count. Both are the same `degraded` answer.
  const sweepErrors = refresh.data?.errors ?? [];
  const sweepErrorCount = refresh.data?.errorCount ?? 0;
  const sweepDegraded = !!refresh.data?.degraded;
  // The screen asked after the sweep and got nothing back — distinct from a
  // read that has not answered yet, and from a record read clean. "We could
  // not check" and "no sweep has run" are different sentences, and the empty
  // lead below used to print the second over this state. A FOREGROUND failure
  // only, the HostDetail rule: useAsync keeps last-good data through a failed
  // background poll, and a record read once outranks the blip that followed it.
  const sweepUnreadable = !!refresh.error && !refresh.data;

  // The verdict on the last SWEEP, which is not feedback on the last click, so
  // a POST note ('already running', a demo block, a failed POST) does not stand
  // in for it. The note is never cleared, so letting it suppress the verdict
  // meant one click that collided with a sweep already in flight buried that
  // sweep's outcome for the rest of the session — and the sweep the operator
  // collided with is exactly the one whose result they were waiting for.
  //
  // Not gated on `firstRun` either. An empty table is precisely what a first
  // sweep that died against a down grid leaves behind, and a fresh install
  // against a down grid is where the catch-all payload comes from — the state
  // that most needs saying was the one state that could not say it.
  //
  // Not gated on the ROLE either, any more: an incomplete list is incomplete
  // for whoever is reading it, and the projection carries the verdict and the
  // count for a non-admin — only the failure strings stay behind the admin
  // gate.
  const showSweepErrors = !running && sweepDegraded;
  const showSweptCounts = isAdmin && !note && !running && !firstRun && sweptCounts.length > 0;

  // A sweep this screen is waiting on: one the server reports running, and the
  // gap before the POST that starts one has answered — which on a slow grid is
  // seconds long, and is time the empty state below spends asserting that no
  // sweep has ever run.
  const sweepInFlight = running || starting;

  return (
    <div className="px-[22px] pb-[60px] pt-5">
      {/* page header */}
      <div className="mb-4">
        <div className="flex items-baseline gap-3">
          <div className="text-title">Hosts</div>
          <Freshness at={list.lastUpdated} />
        </div>
        <div className="mt-0.5 max-w-[760px] text-[13px] text-dim">
          What the network sweep has learned about each machine, and what you've told it. Your
          answers win.
        </div>
      </div>

      {list.failCount >= 2 && (
        <StaleNotice since={list.lastUpdated} onRefresh={list.refetch} className="mb-3" />
      )}

      {/* The shared list toolbar — server parameters, all of them. Hidden on
          first run: search, three filters and a sort over zero rows was half of
          F9. */}
      {!firstRun && (
        <ListToolbar
          views={views.views}
          activeViewId={views.activeViewId}
          onApplyView={views.onApplyView}
          onDeleteView={views.onDeleteView}
          onSaveView={views.onSaveView}
          viewError={views.error}
          search={{
            value: q,
            onChange: (v) => {
              setQ(v);
              views.clearActive();
            },
            placeholder: 'Search address or hostname…',
            label: 'Search hosts',
          }}
          note={bulkNote}
          selection={
            selecting
              ? {
                  count: sel.count,
                  noun: sel.count === 1 ? 'host selected' : 'hosts selected',
                  offPageCount: sel.offPageCount,
                  onClearOffPage: sel.clearOffPage,
                  onClear: sel.clear,
                  actions: (
                    <>
                      <Select
                        value={bulkField}
                        options={BULK_FIELDS}
                        label="Field to declare"
                        onChange={(v) => {
                          setBulkField(v as 'role' | 'criticality');
                          setBulkValue('');
                        }}
                      />
                      {bulkField === 'criticality' ? (
                        <Select
                          value={bulkValue}
                          options={[
                            { value: '', label: 'choose…' },
                            ...CRITICALITIES.map((c) => ({ value: c, label: c })),
                          ]}
                          onChange={setBulkValue}
                          label="Criticality to declare"
                        />
                      ) : (
                        <Select
                          value={bulkValue}
                          options={bulkRoleOptions}
                          onChange={setBulkValue}
                          label="Role to declare"
                        />
                      )}
                      <button
                        disabled={bulkBusy || !bulkValue.trim()}
                        onClick={() => {
                          void declare();
                        }}
                        title="Declare this on every selected host. Your answer wins over the sweep's, and survives the next rebuild."
                        className="flex items-center gap-1.5 rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold text-[#cfe0ff] disabled:opacity-50"
                        style={{ background: 'rgba(75,139,245,.14)', borderColor: 'rgba(75,139,245,.4)' }}
                      >
                        <UserCheck size={12} />
                        {bulkBusy ? 'Declaring…' : `Declare (${sel.count})`}
                      </button>
                    </>
                  ),
                }
              : undefined
          }
          trailing={
            isAdmin ? (
              <button
                onClick={() => {
                  void rebuild();
                }}
                disabled={starting || running}
                title="Sweep the network now — hundreds of hosts across several grid queries, so it runs in the background"
                className="flex items-center gap-1.5 rounded-[7px] border border-border-strong px-[11px] py-1.5 text-[12.5px] font-semibold text-dim hover:text-text disabled:opacity-60"
              >
                <RefreshCw size={12} className={running || starting ? 'animate-spin' : ''} />
                {running ? 'Rebuilding…' : 'Rebuild now'}
              </button>
            ) : undefined
          }
        >
          <label className="flex items-center gap-1.5">
            <span className="text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
              Role
            </span>
            <Select value={role} options={roleOptions} onChange={onRole} />
          </label>
          <label className="flex items-center gap-1.5">
            <span className="text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
              Show
            </span>
            <Select
              value={source}
              options={[
                { value: '', label: 'all hosts' },
                { value: 'operator', label: 'with declarations' },
                { value: 'inferred', label: 'sweep answers only' },
              ]}
              onChange={onSource}
            />
          </label>
          <label className="flex items-center gap-1.5">
            <span className="text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
              Sort
            </span>
            <Select value={sort} options={SORTS} onChange={onSort} />
          </label>
        </ListToolbar>
      )}

      {/* Sweep feedback: the note from the POST (never a silent no-op) and a
          compact read of the last run's counters. */}
      {note && (
        <div className="mb-3.5 rounded-card border border-warn/30 bg-warn/[0.06] px-3.5 py-2.5 text-[12.5px] text-text-2">
          {note === 'dossier disabled' ? (
            <>
              The host dossier is switched off, so nothing was swept. Turn it on in{' '}
              <Link to={DOSSIER_CONFIG_HREF} className="font-semibold text-accent hover:underline">
                Config → Host dossier
              </Link>
              .
            </>
          ) : (
            note
          )}
        </div>
      )}
      {(showSweepErrors || showSweptCounts) && (
        <div className="mb-3.5">
          {/* Above the counts, not instead of them: a sweep that failed four
              queries and still built 300 hosts really did build them, and
              erasing that record under-reports the run in the other direction.
              A total failure carries no counts, so the note stands alone. */}
          {showSweepErrors && (
            <div
              data-testid="sweep-degraded"
              className={cn(
                'rounded-card border border-warn/30 bg-warn/[0.06] px-3.5 py-2.5',
                showSweptCounts && 'mb-2',
              )}
            >
              <StatusTag color="#d29922" label="Sweep degraded" />
              <div className="mt-1 max-w-[760px] text-[12px] leading-[1.5] text-text-2">
                The last sweep hit {plural(sweepErrorCount, 'error')} and did not read the whole
                network, so this list is incomplete. A host that is missing below, or still showing
                old answers, may be one the sweep could not reach.{' '}
                {sweepErrors.length > 0
                  ? 'A rebuild runs the same queries, so start with what failed:'
                  : 'An admin can read what failed on this screen and start another sweep.'}
              </div>
              {/* The strings themselves, not just how many. This channel carries
                  local faults as well as grid ones ("no internal CIDRs
                  configured; cannot scope the network"), and a bare count sends
                  the operator off to wait on Security Onion for something
                  Security Onion will never fix. Admin only: the strings are the
                  reason the full status is gated, so the projection a non-admin
                  reads never carries them — for that reader the verdict and
                  the count stand alone. */}
              {sweepErrors.length > 0 && (
                <ul className="mt-1.5 max-w-[760px] space-y-0.5 text-[11.5px] text-dim">
                  {sweepErrors.slice(0, SHOWN_ERRORS).map((e, i) => (
                    <li key={i} className="truncate font-mono" title={e}>
                      {e}
                    </li>
                  ))}
                  {sweepErrors.length > SHOWN_ERRORS && (
                    <li className="text-faint">
                      and {(sweepErrors.length - SHOWN_ERRORS).toLocaleString()} more
                    </li>
                  )}
                </ul>
              )}
            </div>
          )}
          {showSweptCounts && (
            <div
              data-testid="sweep-run-summary"
              title="What the most recent sweep wrote. When it ran is in the summary line above, which dates the data itself."
              className="text-[11.5px] text-faint"
            >
              Last sweep: {sweptCounts.join(' · ')}
            </div>
          )}
        </div>
      )}

      {/* Network-wide, above everything the table says about a page of it. */}
      {!firstRun && (
        <HostsSummary summary={kpis.data} failed={kpis.error != null} queueVisible={pending > 0} />
      )}

      {/* The disagreement queue — the single conflict surface on this screen,
          in the one-line both-claims shape the critique called the good one. */}
      {!firstRun && pending > 0 && (
        <div className="mb-3.5 overflow-hidden rounded-card border border-warn/30 bg-warn/[0.06]">
          <div className="flex items-center gap-2.5 px-3.5 py-2.5 text-[13px]">
            <AlertTriangle size={13} className="flex-none text-warn" />
            <button
              onClick={() => setShowConflicts((v) => !v)}
              className="flex min-w-0 flex-1 items-center gap-2.5 text-left"
            >
              <span className="min-w-0 truncate font-semibold text-text-2">
                {pending} disagreement{pending === 1 ? '' : 's'} need{pending === 1 ? 's' : ''}{' '}
                review
              </span>
              <span className="flex flex-none items-center gap-1 text-[11.5px] text-dim">
                {showConflicts ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                {showConflicts ? 'Hide' : 'Show'}
              </span>
            </button>
          </div>
          {showConflicts && (
            <div className="border-t border-border-faint">
              {(conflicts.data?.rows ?? []).map((c) => (
                <ConflictRow key={`${c.ip}:${c.field}`} c={c} />
              ))}
              {pending > (conflicts.data?.rows.length ?? 0) && (
                <div className="px-3.5 py-2 text-[11.5px] text-faint">
                  Showing the {conflicts.data?.rows.length} oldest — resolve these first.
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* The broken-builds view names itself, with the way back — a filtered
          table that looks like the whole network is its own defect. */}
      {health && (
        <div className="mb-3.5 flex flex-wrap items-center gap-3 rounded-card border border-danger/30 bg-danger/[0.05] px-3.5 py-2.5 text-[12.5px] text-text-2">
          <AlertTriangle size={13} className="flex-none text-danger" />
          <span className="min-w-0 flex-1">
            Showing the hosts the sweep is not getting through to — never built, or the last build
            failed.
          </span>
          <button
            onClick={clearHealth}
            className="flex-none rounded-control border border-border-strong bg-surface-3 px-2.5 py-1 text-[11.5px] font-semibold text-text-2 hover:text-text"
          >
            Show all hosts
          </button>
        </div>
      )}

      {firstRun ? (
        <Panel>
          <PanelHeader icon={<Server size={15} />} title="Hosts" />
          <EmptyState>
            <div className="mx-auto max-w-[520px]">
              {/* An empty table has THREE very different causes and the sweep
                  record tells them apart. "Hasn't run yet" over a sweep that
                  ran and died is this screen's own version of the bug the note
                  above exists to fix, and it is the sentence a fresh install
                  against a down grid lands on every time. It is just as false
                  over a sweep that is running right now, which is the state an
                  operator who has just pressed the button is staring at — for
                  minutes, on a grid that answers slowly, with a dimmed button
                  as the only sign anything is happening. The in-flight branch
                  goes FIRST: a running sweep supersedes the last one's verdict,
                  the same way the degraded note above hides itself while one is
                  in flight.

                  All three branches key off the normalized status read, so they
                  hold for a NON-admin too (the projection carries running and
                  degraded) — an analyst on a fresh install used to read
                  "hasn't run yet" over a sweep that ran and died, because the
                  full status is admin-gated and this screen never asked
                  anything else.

                  A FOURTH branch for the read that FAILED: 'unknown' below is
                  a status still in flight, and the healthy copy stands in for
                  the moment it takes to answer — but once the answer is a
                  failure, "hasn't run yet" is a claim this screen has just
                  proven it cannot make, and the paused poll means it would
                  stand for the session. HostDetail's sweepUnreadable precedent:
                  say "could not check" instead.

                  `data-sweep` says what this lead KNOWS: the healthy copy also
                  renders while the status read is in flight, so a test (or
                  anything else) asserting the first-run copy off the first
                  paint would be asserting nothing. */}
              <div
                data-testid="hosts-empty-lead"
                data-sweep={
                  sweepInFlight
                    ? 'running'
                    : sweepDegraded
                      ? 'blind'
                      : sweepUnreadable
                        ? 'unreadable'
                        : refresh.data
                          ? 'read'
                          : 'unknown'
                }
                className="text-[13px] leading-[1.6] text-dim"
              >
                {sweepInFlight ? (
                  'The network sweep is running now. This list fills in when it finishes — it builds from telemetry Security Onion already holds, so nothing new touches your network.'
                ) : sweepDegraded ? (
                  'The last sweep could not read the network, so it built nothing. This list is empty because the sweep came back blind, not because there is nothing out there to find.'
                ) : sweepUnreadable ? (
                  <>
                    This screen could not check how the last sweep went, so it cannot tell you why
                    this list is empty — a sweep that has never run and one that ran and came back
                    blind both leave it looking exactly like this.
                    <span className="mt-1 block font-mono text-[11.5px] text-faint">
                      {refresh.error?.message}
                    </span>
                  </>
                ) : (
                  "The network sweep hasn't run yet. It builds this list from telemetry Security Onion already holds — nothing new touches your network."
                )}
              </div>
              {isAdmin ? (
                <button
                  onClick={() => {
                    void rebuild();
                  }}
                  disabled={sweepInFlight}
                  className="mx-auto mt-3 flex items-center gap-1.5 rounded-control border border-accent bg-accent/10 px-3.5 py-1.5 text-[12.5px] font-semibold text-accent hover:bg-accent/20 disabled:opacity-60"
                >
                  <RefreshCw size={12} className={sweepInFlight ? 'animate-spin' : ''} />
                  {/* "Run the first sweep" claims none has run — over an
                      unreadable record that is the lead's false sentence again,
                      half an inch lower. A neutral label makes no claim. */}
                  {sweepInFlight
                    ? 'Sweeping…'
                    : sweepDegraded
                      ? 'Try the sweep again'
                      : sweepUnreadable
                        ? 'Run a sweep'
                        : 'Run the first sweep'}
                </button>
              ) : (
                <div className="mt-2 text-[12.5px] text-faint">
                  An admin starts it from this screen, or turns on the schedule.
                </div>
              )}
              <div className="mt-2">
                <Link
                  to={DOSSIER_CONFIG_HREF}
                  className="text-[12.5px] font-semibold text-accent hover:underline"
                >
                  turn on scheduled sweeps
                </Link>
              </div>
            </div>
          </EmptyState>
        </Panel>
      ) : (
        <Panel>
          <PanelHeader
            icon={<Server size={15} />}
            title={list.data ? `Hosts · ${total.toLocaleString()}` : 'Hosts'}
          />

          <div
            className="grid gap-2.5 border-b border-border bg-surface-2 px-[15px] py-[9px] text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint"
            style={{ gridTemplateColumns: isAdmin ? GRID_SELECTABLE : GRID }}
          >
            {isAdmin && (
              <div className="flex items-center">
                <Checkbox
                  checked={sel.allVisibleSelected}
                  indeterminate={!sel.allVisibleSelected && sel.someVisibleSelected}
                  onChange={sel.toggleAll}
                  title="Select all visible"
                  aria-label="Select all hosts on this page"
                />
              </div>
            )}
            <div>Address</div>
            <div>Host</div>
            <div>Role</div>
            <div>Flags</div>
            <div className="text-right">Events</div>
            <div className="text-right">Last seen</div>
          </div>

          {list.loading && !list.data ? (
            <LoadingState label="Loading hosts…" />
          ) : list.error ? (
            <div className="p-3.5">
              <ErrorState error={list.error} onRetry={list.refetch} label="the host list" />
            </div>
          ) : rows.length === 0 ? (
            <EmptyState>No hosts match the current filters.</EmptyState>
          ) : (
            <>
              {rows.map((row) => {
                const hostnameField = fieldOf(row, 'hostname');
                const hostname =
                  hostnameField && isResolved(hostnameField) ? hostnameField.value : null;
                const roleField = fieldOf(row, 'role');
                const roleValue = roleField && isResolved(roleField) ? roleField.value : null;
                return (
                  <div
                    key={row.ip}
                    onClick={() => navigate(`/hosts/${encodeURIComponent(row.ip)}`)}
                    className="grid cursor-pointer items-center gap-2.5 border-b border-border-faint px-[15px] py-[10px] last:border-0 hover:bg-surface-hover"
                    style={{ gridTemplateColumns: isAdmin ? GRID_SELECTABLE : GRID }}
                  >
                    {isAdmin && (
                      <div
                        className="flex items-center"
                        onClick={(e) => {
                          e.stopPropagation();
                          sel.toggle(row.ip);
                        }}
                      >
                        <Checkbox
                          checked={sel.isSelected(row.ip)}
                          title="Select"
                          aria-label={`Select ${row.ip}`}
                        />
                      </div>
                    )}
                    <div className="min-w-0">
                      <Link
                        to={`/hosts/${encodeURIComponent(row.ip)}`}
                        onClick={(e) => e.stopPropagation()}
                        className="min-w-0 truncate font-mono text-[12.5px] text-text hover:text-accent"
                      >
                        {row.ip}
                      </Link>
                    </div>
                    <div className="min-w-0">
                      {hostname ? (
                        <span className="min-w-0 truncate font-mono text-[12.5px] text-text-2">
                          {hostname}
                        </span>
                      ) : (
                        <Unknown f={hostnameField} />
                      )}
                    </div>
                    <div className="min-w-0">
                      {/* The FRIENDLY label, the same one the ROLES legend up
                          the screen uses. The pill used to print the raw slug,
                          so one screen showed `network_device` in the table and
                          "network device" in the legend counting it — two
                          spellings of one value, twelve rows apart, reading as
                          two things. roleLabel passes operator free text
                          through, so a declared role is still their own word;
                          the title keeps the stored value one hover away. */}
                      {roleValue ? (
                        <span
                          title={roleValue}
                          className={cn(
                            'inline-flex max-w-full truncate rounded-chip border px-1.5 py-px text-[12px] font-medium',
                            roleAccent(roleValue),
                          )}
                        >
                          {roleLabel(roleValue)}
                        </span>
                      ) : (
                        <Unknown f={roleField} />
                      )}
                    </div>
                    <div className="min-w-0">
                      <FlagsCell row={row} />
                    </div>
                    <div className="text-right font-mono text-[12px] text-dim">
                      {row.event_count.toLocaleString()}
                    </div>
                    <div
                      className="text-right font-mono text-[11.5px] text-faint"
                      title={absolute(row.last_seen)}
                    >
                      {ago(row.last_seen)}
                    </div>
                  </div>
                );
              })}

              {/* Real pagination over the SQL page: `total` is the whole match
                  set, so the range is exact rather than inferred. */}
              <div className="flex items-center justify-between border-t border-border px-[15px] py-2.5">
                <span className="font-mono text-[11.5px] text-faint">
                  {`${shownFrom}–${shownTo} of ${total.toLocaleString()}`}
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
                    disabled={shownTo >= total}
                    className="rounded-control border border-border-strong px-2.5 py-1 text-[11.5px] font-semibold text-dim hover:text-text disabled:opacity-40"
                  >
                    Next
                  </button>
                </div>
              </div>
            </>
          )}
        </Panel>
      )}
    </div>
  );
}
