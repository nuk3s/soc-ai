import {
  AlertTriangle,
  ArrowUpDown,
  Check,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Filter,
  RefreshCw,
  Scale,
  Server,
  UserCheck,
  X,
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { StatusTag } from '../components/Badges';
import { Checkbox, Select } from '../components/Controls';
import { DOSSIER_CONFIG_HREF, HostsSummary, ROLE_BUCKETS } from '../components/HostsSummary';
import { ListToolbar } from '../components/ListToolbar';
import { Panel, PanelHeader } from '../components/Panel';
import { EmptyState, ErrorState, Freshness, LoadingState, StaleNotice } from '../components/States';
import {
  bulkSetDossierOverride,
  clearDossierOverride,
  getDossier,
  getDossierConflicts,
  getDossierRefreshStatus,
  getDossierSummary,
  getMachineSummary,
  getMe,
  listDossiers,
  listMachines,
  setDossierOverride,
  startDossierRefresh,
} from '../lib/api';
import { cn } from '../lib/cn';
import { demoBlocked, useDemo } from '../lib/demo';
import { roleAccent } from '../lib/hostColors';
import {
  fieldLabel,
  machineRoleView,
  nameSourceLabel,
  nameSourceTitle,
  roleLabel,
  roleVocabulary,
} from '../lib/hostDossier';
import {
  FIRST_DIR,
  HOSTS_PAGE_SIZE,
  MACHINE_SORT_KEYS,
  agentStaleTitle,
  listHref,
  machineHref,
  machineQuery,
  patchListParams,
  readListState,
  rememberListScroll,
  rememberListUrl,
  savedListScroll,
  scrollParent,
  type HostsListState,
  type HostsLocationState,
  type ListSweep,
} from '../lib/hostsList';
import { plural } from '../lib/plural';
import { SHOWN_ERRORS, sweepErrorList } from '../lib/sweepErrors';
import { absTime, ago } from '../lib/timeRange';
import { useListSelection } from '../lib/useListSelection';
import { useSavedViews } from '../lib/useSavedViews';
import type {
  DossierConflictKind,
  DossierConflictRow,
  DossierRefreshStatus,
  MachineRow,
  MachineSortKey,
  MachineSummary,
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
// authenticated caller, so the empty states below work for every role. Before
// it existed, an analyst on a fresh install read "the sweep hasn't run yet"
// over a sweep that ran and died. HostDetail carries the same copy for the
// same reason. No login redirect on a failure either: a failed read leaves the
// sweep unreadable, and the empty lead says "could not check".
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
 *  `summary` are the admin read's extras; the projection leaves them empty.
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

// A typed query is a new result set, so a keystroke can't fire a request.
const SEARCH_DEBOUNCE_MS = 250;

// The two fields a bulk declare is FOR. Criticality is never inferred at all,
// and a role the sweep guessed is the thing an operator most often corrects
// across a whole subnet at once.
const BULK_FIELDS: Array<{ value: 'role' | 'criticality'; label: string }> = [
  { value: 'criticality', label: 'Criticality' },
  { value: 'role', label: 'Role' },
];

// The criticality vocabulary, worst first.
const CRITICALITIES = ['critical', 'high', 'medium', 'low'];

// How a disagreement undermines the declaration, weakest first.
const CONFLICT_KIND_HELP: Record<DossierConflictKind, string> = {
  mismatch: 'The evidence points to a different value.',
  retracted: 'The evidence for this field is gone.',
  rebound: 'A different host answers on this address now.',
};

/** The broken-builds view: the addresses with no clean build. Build health
 *  is a fact about an address dossier, so this view lists addresses. */
const BROKEN_HREF = '/hosts?health=broken';
const CONFLICTS_HREF = '/hosts?conflicts=1';

function absolute(iso: string | null): string {
  if (!iso) return 'never seen';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

/** One lane's answer as text, for the conflict queue. The structured fields
 *  leave `value` null and carry the answer in `value_json`. */
function laneText(value: string | null, json: unknown): string | null {
  const scalar = value?.trim();
  if (scalar) return scalar;
  if (json == null) return null;
  return typeof json === 'string' ? json : JSON.stringify(json);
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
        // ?field= is the host page's highlight target. The host page resolves
        // the address to its machine and keeps the address in focus.
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
        <span className="min-w-0 truncate font-mono text-[11.5px] text-text-2">{yours ?? 'none'}</span>
      </span>
      <span className="flex min-w-0 items-center gap-1.5">
        <span className="flex-none text-[11px] text-faint">sweep</span>
        <span className="min-w-0 truncate font-mono text-[11.5px] text-text-2">{theirs ?? 'none'}</span>
      </span>
      <span
        className="flex-none text-[11px] text-faint"
        title="The number of sweeps that reached this conclusion. The count starts at the time the disagreement opened."
      >
        seen {c.observations}x
      </span>
      {c.identity_rebound_at && (
        <span
          className="flex-none text-[11px] font-semibold text-warn"
          title={`A different host appears to hold this address since ${absolute(c.identity_rebound_at)}. The declaration may describe a host that has moved.`}
        >
          rebound
        </span>
      )}
    </div>
  );
}

// ---- header controls --------------------------------------------------------

interface FilterOption {
  value: string;
  label: string;
  count?: number;
}

interface FilterGroup {
  /** The group heading, when a menu holds more than one group. */
  label?: string;
  value: string;
  /** The first option is the default: the filter is off. */
  options: FilterOption[];
  onChange: (value: string) => void;
}

/**
 * A small filter menu in a column header. The button shows the filter is on;
 * the menu lists each choice with its count where the summary has one.
 */
function HeaderFilter({
  name,
  groups,
  align = 'left',
}: {
  name: string;
  groups: FilterGroup[];
  /** Which edge of the button the menu lines up with. A right-aligned
   *  column opens its menu leftward, so the menu stays on screen. */
  align?: 'left' | 'right';
}) {
  const [open, setOpen] = useState(false);
  // The menu is position: fixed at the button. The table panel clips its
  // overflow, and a short list (no rows, one row) would cut an absolute menu
  // off exactly when the operator needs to change the filter.
  const [at, setAt] = useState<{ top: number; left?: number; right?: number } | null>(null);
  const ref = useRef<HTMLSpanElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    // A fixed menu does not move with the page, so a scroll closes it.
    const onScroll = (e: Event) => {
      if (ref.current && e.target instanceof Node && ref.current.contains(e.target)) return;
      setOpen(false);
    };
    const onResize = () => setOpen(false);
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    window.addEventListener('scroll', onScroll, true);
    window.addEventListener('resize', onResize);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
      window.removeEventListener('scroll', onScroll, true);
      window.removeEventListener('resize', onResize);
    };
  }, [open]);
  const toggle = () => {
    if (!open) {
      const rect = buttonRef.current?.getBoundingClientRect();
      if (rect) {
        setAt(
          align === 'right'
            ? { top: rect.bottom + 4, right: Math.max(8, window.innerWidth - rect.right) }
            : { top: rect.bottom + 4, left: rect.left },
        );
      }
    }
    setOpen((v) => !v);
  };
  const active = groups.some((g) => g.value !== (g.options[0]?.value ?? ''));
  return (
    <span ref={ref} className="relative inline-flex">
      <button
        ref={buttonRef}
        type="button"
        aria-label={`Filter by ${name.toLowerCase()}`}
        aria-haspopup="menu"
        aria-expanded={open}
        data-active={active ? 'true' : 'false'}
        title={active ? `The ${name.toLowerCase()} filter is on.` : `Filter by ${name.toLowerCase()}.`}
        onClick={toggle}
        className={cn(
          'flex items-center rounded-[4px] p-[3px]',
          active ? 'bg-accent/15 text-accent' : 'text-faint hover:text-text-2',
        )}
      >
        <Filter size={10} />
      </button>
      {open && (
        <div
          role="menu"
          aria-label={`${name} filter`}
          style={at ? { position: 'fixed', top: at.top, left: at.left, right: at.right } : undefined}
          className={cn(
            'z-50 min-w-[200px] rounded-card border border-border-strong bg-surface-card p-1 text-left normal-case tracking-normal shadow-palette',
            !at && 'absolute left-0 top-full mt-1',
          )}
        >
          {groups.map((g, gi) => (
            <div key={g.label ?? gi} role="group" aria-label={g.label ?? name}>
              {g.label && (
                <div className="px-2 pb-0.5 pt-1.5 text-[10px] font-semibold uppercase tracking-[.06em] text-faint">
                  {g.label}
                </div>
              )}
              {g.options.map((o) => (
                <button
                  key={o.value || 'any'}
                  type="button"
                  role="menuitemradio"
                  aria-checked={g.value === o.value}
                  onClick={() => {
                    g.onChange(o.value);
                    setOpen(false);
                  }}
                  className="flex w-full items-center gap-2 rounded-control px-2 py-1.5 text-[12px] font-normal text-text-2 hover:bg-surface-hover hover:text-text"
                >
                  <span className="flex w-3 flex-none justify-center text-accent">
                    {g.value === o.value && <Check size={11} />}
                  </span>
                  <span className="flex-1">{o.label}</span>
                  {o.count != null && (
                    <span className="font-mono text-[10.5px] text-faint">{o.count.toLocaleString()}</span>
                  )}
                </button>
              ))}
            </div>
          ))}
        </div>
      )}
    </span>
  );
}

interface Column {
  key: MachineSortKey;
  label: string;
  right?: boolean;
  width: string;
}

const COLUMNS: Column[] = [
  { key: 'name', label: 'Host', width: 'w-[22%]' },
  { key: 'address', label: 'Address', width: 'w-[15%]' },
  { key: 'agent', label: 'Agent', width: 'w-[15%]' },
  { key: 'role', label: 'Role', width: 'w-[17%]' },
  { key: 'events', label: 'Events', right: true, width: 'w-[9%]' },
  { key: 'first_seen', label: 'First seen', right: true, width: 'w-[10%]' },
  { key: 'last_seen', label: 'Last seen', right: true, width: 'w-[10%]' },
];

/** A column header that sorts on click, toggles the direction and shows it. */
function SortHeader({
  col,
  state,
  onSort,
  filter,
}: {
  col: Column;
  state: HostsListState;
  onSort: (key: MachineSortKey) => void;
  filter?: ReactNode;
}) {
  const active = state.sort === col.key;
  const ariaSort = active ? (state.dir === 'asc' ? 'ascending' : 'descending') : 'none';
  const nextDir = active ? (state.dir === 'asc' ? 'desc' : 'asc') : FIRST_DIR[col.key];
  return (
    <th
      scope="col"
      aria-sort={ariaSort}
      className={cn('px-2.5 py-[9px] font-semibold', col.width, col.right ? 'text-right' : 'text-left')}
    >
      <span className={cn('inline-flex items-center gap-1', col.right && 'justify-end')}>
        <button
          type="button"
          onClick={() => onSort(col.key)}
          title={`Sort by ${col.label.toLowerCase()}, ${nextDir === 'asc' ? 'ascending' : 'descending'}.`}
          className={cn(
            'inline-flex items-center gap-1 uppercase tracking-[.06em] hover:text-text-2',
            active && 'text-text-2',
          )}
        >
          {col.label}
          {active ? (
            state.dir === 'asc' ? (
              <ChevronUp size={11} aria-hidden="true" />
            ) : (
              <ChevronDown size={11} aria-hidden="true" />
            )
          ) : (
            <ArrowUpDown size={10} aria-hidden="true" className="opacity-50" />
          )}
        </button>
        {filter}
      </span>
    </th>
  );
}

// ---- one machine row --------------------------------------------------------

function RowFlags({ row }: { row: MachineRow }) {
  const f = row.flags;
  if (!f.broken && !f.conflict && !f.rebound && !f.new && !f.declared) return null;
  return (
    <span className="flex flex-none items-center gap-1">
      {f.broken && (
        <span
          title="The sweep cannot build this machine. The last build failed or never ran."
          aria-label="build failed"
          className="flex items-center text-danger"
        >
          <AlertTriangle size={11} />
        </span>
      )}
      {f.conflict && (
        <span
          title="An operator declaration and the sweep disagree. Open the machine to decide."
          aria-label="disagreement"
          className="flex items-center text-warn"
        >
          <Scale size={11} />
        </span>
      )}
      {f.rebound && (
        <span
          title="A different machine may hold this address now."
          className="rounded-chip border border-warn/40 px-1 font-mono text-[9.5px] font-semibold text-warn"
        >
          rebound
        </span>
      )}
      {f.declared && (
        <span
          title="An operator declared a value on this machine."
          aria-label="declared"
          className="flex items-center text-text-2"
        >
          <UserCheck size={11} />
        </span>
      )}
      {f.new && (
        <span
          title="First seen in the last 7 days."
          className="rounded-chip border border-accent/40 px-1 font-mono text-[9.5px] font-semibold text-accent"
        >
          new
        </span>
      )}
    </span>
  );
}

function RoleCell({ row }: { row: MachineRow }) {
  const view = machineRoleView(row.role);
  if (view.state === 'unknown') {
    return (
      <span data-testid="role-unknown" className="text-[12px] text-faint" title={view.title}>
        unknown
      </span>
    );
  }
  if (view.state === 'low_confidence' || view.state === 'stale') {
    // The guess sits whole in the chip and the state words follow it, as the
    // "inferred" note follows an answer. One chip cut "low confidence:
    // security appliance" to "security applianc" in the Role column. The
    // pair wraps to a second line when the cell is narrow.
    return (
      <span
        data-testid={`role-${view.state === 'stale' ? 'stale' : 'low-confidence'}`}
        title={view.title}
        className="inline-flex max-w-full flex-wrap items-baseline gap-x-1.5"
      >
        <span
          data-testid="role-guess"
          className="inline-flex max-w-full items-center gap-1.5 whitespace-normal break-words rounded-chip border border-warn/40 bg-warn/[0.08] px-1.5 py-px text-[12px] font-medium text-warn"
        >
          <span className="h-1.5 w-1.5 flex-none rounded-full bg-warn" />
          {view.guess ?? view.qualifier ?? view.text}
        </span>
        {view.guess && (
          <span data-testid="role-qualifier" className="text-[10.5px] text-warn">
            {view.qualifier}
          </span>
        )}
      </span>
    );
  }
  return (
    <span className="inline-flex max-w-full items-baseline gap-1.5" title={view.title}>
      <span
        className={cn(
          'inline-flex max-w-full truncate rounded-chip border px-1.5 py-px text-[12px] font-medium',
          roleAccent(view.accent),
        )}
      >
        {view.text}
      </span>
      {view.note && <span className="text-[10.5px] text-faint">{view.note}</span>}
    </span>
  );
}

function AddressCell({ row }: { row: MachineRow }) {
  const more = Math.max(0, row.address_count - 1);
  const others = row.addresses.filter((a) => a !== row.primary_ip);
  const unlisted = Math.max(0, more - others.length);
  const tip = `${others.join(', ')}${unlisted > 0 ? `${others.length ? ', ' : ''}and ${plural(unlisted, 'more address', 'more addresses')}` : ''}`;
  return (
    <span className="inline-flex min-w-0 items-baseline gap-1.5">
      <span className="truncate font-mono text-[12.5px] text-text">{row.primary_ip}</span>
      {more > 0 && (
        <span
          data-testid="address-more"
          title={tip}
          aria-label={`${plural(more, 'more address', 'more addresses')}: ${tip}`}
          className="flex-none rounded-chip border border-border-2 px-1 font-mono text-[10.5px] text-dim"
        >
          +{more}
        </span>
      )}
    </span>
  );
}

function MachineTableRow({
  row,
  selectable,
  selected,
  onToggle,
  onOpen,
  linkState,
  sweep,
}: {
  row: MachineRow;
  selectable: boolean;
  selected: boolean;
  onToggle: () => void;
  onOpen: () => void;
  linkState: HostsLocationState;
  /** The sweep the row comes from, for the stale marker. */
  sweep: ListSweep;
}) {
  const navigate = useNavigate();
  const href = machineHref(row.key);
  const source = nameSourceLabel(row.name_source);
  const staleTitle = row.agent ? agentStaleTitle(row.agent.last_report, sweep) : null;
  return (
    <tr
      data-testid={`machine-row-${row.key}`}
      onClick={() => {
        onOpen();
        navigate(href, { state: linkState });
      }}
      className="cursor-pointer border-b border-border-faint last:border-0 hover:bg-surface-hover"
    >
      {selectable && (
        <td
          className="w-[28px] px-2.5 py-[9px] align-middle"
          onClick={(e) => {
            e.stopPropagation();
            onToggle();
          }}
        >
          <Checkbox
            checked={selected}
            title="Select this machine."
            aria-label={`Select ${row.name ?? row.primary_ip}`}
          />
        </td>
      )}
      <td className="min-w-0 px-2.5 py-[9px] align-middle">
        <div className="flex min-w-0 items-center gap-1.5">
          {/* The one tab stop per row. The whole row is a link for a mouse;
              this is the link for a keyboard. */}
          <Link
            to={href}
            state={linkState}
            onClick={(e) => {
              e.stopPropagation();
              onOpen();
            }}
            aria-label={`${row.name ?? 'No name'}, ${row.primary_ip}`}
            className={cn(
              'min-w-0 truncate text-[12.5px] hover:text-accent focus-visible:text-accent',
              row.name ? 'font-mono text-text' : 'italic text-faint',
            )}
          >
            {row.name ?? 'no name'}
          </Link>
          <RowFlags row={row} />
        </div>
        {row.name && source && (
          <div className="text-[10.5px] text-faint" title={nameSourceTitle(row.name_source)}>
            {source}
          </div>
        )}
      </td>
      <td className="min-w-0 px-2.5 py-[9px] align-middle">
        <AddressCell row={row} />
      </td>
      <td className="min-w-0 px-2.5 py-[9px] align-middle">
        {row.agent ? (
          <div
            className="min-w-0"
            title={
              row.agent.last_report
                ? `The agent last reported ${absTime(row.agent.last_report)}.`
                : 'The agent has no report time on record.'
            }
          >
            <div className="flex min-w-0 items-center gap-1">
              <span className="truncate font-mono text-[12px] text-text-2">{row.agent.name}</span>
              {staleTitle && (
                <span
                  data-testid={`agent-stale-${row.key}`}
                  className="flex-none rounded-chip border px-1 py-px text-[9.5px] font-semibold text-warn"
                  style={{ borderColor: 'rgba(210,153,34,.45)' }}
                  title={staleTitle}
                  onClick={(e) => e.stopPropagation()}
                >
                  stale
                </span>
              )}
            </div>
            {row.agent.os && <div className="truncate text-[10.5px] text-faint">{row.agent.os}</div>}
          </div>
        ) : (
          <span className="text-[12px] text-faint" title="No agent reports from this machine.">
            none
          </span>
        )}
      </td>
      <td className="min-w-0 px-2.5 py-[9px] align-middle">
        <RoleCell row={row} />
      </td>
      <td className="px-2.5 py-[9px] text-right align-middle font-mono text-[12px] text-dim">
        {row.events.toLocaleString()}
      </td>
      <td
        className="px-2.5 py-[9px] text-right align-middle font-mono text-[11.5px] text-faint"
        title={absolute(row.first_seen)}
      >
        {ago(row.first_seen)}
      </td>
      <td
        className="px-2.5 py-[9px] text-right align-middle font-mono text-[11.5px] text-faint"
        title={absolute(row.last_seen)}
      >
        {ago(row.last_seen)}
      </td>
    </tr>
  );
}

// ---- the broken-builds view -------------------------------------------------

/**
 * The addresses the sweep is not getting through to: a build never ran, or
 * the last build failed. Build health is a fact about one address dossier, so
 * this view lists addresses. Each address links to its machine page.
 */
function BrokenBuilds({ page, onPage }: { page: number; onPage: (page: number) => void }) {
  const list = useAsync(
    () =>
      listDossiers({
        health: 'broken',
        limit: HOSTS_PAGE_SIZE,
        offset: (page - 1) * HOSTS_PAGE_SIZE,
      }),
    [page],
  );
  const rows = list.data?.rows ?? [];
  const total = list.data?.total ?? 0;
  const from = total === 0 ? 0 : (page - 1) * HOSTS_PAGE_SIZE + 1;
  const to = Math.min(page * HOSTS_PAGE_SIZE, total);
  return (
    <Panel>
      <PanelHeader
        icon={<AlertTriangle size={15} />}
        title={list.data ? `Addresses with no clean build · ${total.toLocaleString()}` : 'Addresses with no clean build'}
      />
      {list.loading && !list.data ? (
        <LoadingState label="Loading addresses…" />
      ) : list.error ? (
        <div className="p-3.5">
          <ErrorState error={list.error} onRetry={list.refetch} label="the broken builds" />
        </div>
      ) : rows.length === 0 ? (
        <EmptyState>Every address has a clean build.</EmptyState>
      ) : (
        <>
          <table className="w-full table-fixed text-[12.5px]">
            <thead className="border-b border-border bg-surface-2 text-[10.5px] uppercase tracking-[.06em] text-faint">
              <tr>
                <th scope="col" className="w-[22%] px-[15px] py-[9px] text-left font-semibold">
                  Address
                </th>
                <th scope="col" className="px-2.5 py-[9px] text-left font-semibold">
                  Build
                </th>
                <th scope="col" className="w-[14%] px-[15px] py-[9px] text-right font-semibold">
                  Last built
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.ip} className="border-b border-border-faint last:border-0">
                  <td className="px-[15px] py-[9px]">
                    <Link
                      to={`/hosts/${encodeURIComponent(r.ip)}`}
                      className="font-mono text-text hover:text-accent"
                    >
                      {r.ip}
                    </Link>
                  </td>
                  <td className="min-w-0 truncate px-2.5 py-[9px] font-mono text-[11.5px] text-text-2" title={r.build_error ?? undefined}>
                    {r.build_error ?? (r.last_built_at == null ? 'never built' : 'failed')}
                  </td>
                  <td
                    className="px-[15px] py-[9px] text-right font-mono text-[11.5px] text-faint"
                    title={absolute(r.last_built_at)}
                  >
                    {r.last_built_at ? ago(r.last_built_at) : 'never'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pager from={from} to={to} total={total} page={page} onPage={onPage} />
        </>
      )}
    </Panel>
  );
}

function Pager({
  from,
  to,
  total,
  page,
  onPage,
}: {
  from: number;
  to: number;
  total: number;
  page: number;
  onPage: (page: number) => void;
}) {
  return (
    <div className="flex items-center justify-between border-t border-border px-[15px] py-2.5">
      <span data-testid="hosts-pager" className="font-mono text-[11.5px] text-faint">
        {`${from} to ${to} of ${total.toLocaleString()}`}
      </span>
      <div className="flex items-center gap-1.5">
        <button
          type="button"
          onClick={() => onPage(Math.max(1, page - 1))}
          disabled={page <= 1}
          className="rounded-control border border-border-strong px-2.5 py-1 text-[11.5px] font-semibold text-dim hover:text-text disabled:opacity-40"
        >
          Previous
        </button>
        <button
          type="button"
          onClick={() => onPage(page + 1)}
          disabled={to >= total}
          className="rounded-control border border-border-strong px-2.5 py-1 text-[11.5px] font-semibold text-dim hover:text-text disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  );
}

// ---- filter vocabulary ------------------------------------------------------

const BUCKET_LABELS: Record<string, string> = {
  low_confidence: 'low confidence',
  stale: 'stale',
  unknown: 'unknown',
};

function roleFilterLabel(role: string): string {
  return BUCKET_LABELS[role] ?? roleLabel(role);
}

/** The role menu: every role a machine holds, with its count, then the three
 *  buckets. A role with no machine is not offered. A filter that lists
 *  nothing reads as a broken filter. The three buckets are always offered
 *  with their count, 0 included: the count says the bucket is empty. */
function roleOptions(summary: MachineSummary | null, current: string): FilterOption[] {
  const roles = summary?.roles ?? {};
  const buckets = new Set<string>(ROLE_BUCKETS);
  const known = Object.entries(roles)
    .filter(([role, count]) => !buckets.has(role) && count > 0)
    .sort(([a], [b]) => roleLabel(a).localeCompare(roleLabel(b)))
    .map(([role, count]) => ({ value: role, label: roleLabel(role), count }));
  const options: FilterOption[] = [{ value: '', label: 'any role' }, ...known];
  for (const bucket of ROLE_BUCKETS) {
    options.push({ value: bucket, label: BUCKET_LABELS[bucket], count: summary ? roles[bucket] ?? 0 : undefined });
  }
  if (current && !options.some((o) => o.value === current)) {
    options.push({ value: current, label: roleFilterLabel(current) });
  }
  return options;
}

/** A saved view, read into the URL shape. Views saved before the machine list
 *  carry `source` and the old sort keys; each maps to its nearest filter. */
function fromSavedView(saved: SavedViewQuery): Partial<Record<keyof HostsListState, string | null>> {
  const str = (v: unknown) => (typeof v === 'string' ? v : '');
  let role = str(saved.role);
  if (role === '__low_confidence__') role = 'low_confidence';
  if (role === '__stale__') role = 'stale';
  let activity = str(saved.activity);
  let declared = str(saved.declared);
  if (typeof saved.source === 'string') {
    if (saved.source === '') activity = 'all';
    if (saved.source === 'operator') declared = 'yes';
    if (saved.source === 'inferred') declared = 'no';
  }
  const sort = str(saved.sort) as MachineSortKey;
  const known = MACHINE_SORT_KEYS.includes(sort);
  return {
    q: str(saved.q) || null,
    role: role || null,
    agent: str(saved.agent) || null,
    activity: activity || null,
    seen: str(saved.seen) || null,
    declared: declared || null,
    sort: known ? sort : null,
    dir: known ? str(saved.dir) || null : null,
  };
}

// ---- the screen -------------------------------------------------------------

/**
 * The host list: one row per machine.
 *
 * A machine is a set of addresses soc-ai holds to be one device. The server
 * resolves the machine, its name, its role and the state of that role; this
 * screen shows the answer and keeps every control in the URL, so Back, reload
 * and the host page breadcrumb return to the same list.
 */
export function Hosts() {
  const demo = useDemo();
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();
  const state = readListState(searchParams);
  // The broken-builds view lives in the URL so the Needs attention card can be
  // a door and the view can be shared.
  const health = searchParams.get('health') === 'broken' ? ('broken' as const) : undefined;

  // One URL write per change. A change to anything but the page resets the
  // page to 1 in the same write, so a search from page 3 is one request.
  const update = useCallback(
    (patch: Partial<Record<keyof HostsListState, string | number | null>>) => {
      setSearchParams((prev) => patchListParams(prev, patch), { replace: true });
    },
    [setSearchParams],
  );

  // The search box. The input is local so typing stays fast; the URL takes the
  // value after the debounce, and the request follows the URL.
  const [qInput, setQInput] = useState(state.q);
  const urlQ = state.q;
  const lastWritten = useRef(urlQ);
  useEffect(() => {
    // Back, a saved view or a card link changed the URL: show its query.
    if (urlQ !== lastWritten.current) {
      lastWritten.current = urlQ;
      setQInput(urlQ);
    }
  }, [urlQ]);
  useEffect(() => {
    const next = qInput.trim();
    if (next === urlQ) return;
    const t = setTimeout(() => {
      lastWritten.current = next;
      update({ q: next || null });
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qInput]);

  const queryKey = JSON.stringify(machineQuery(state));
  const list = useAsync(
    () => (health ? Promise.resolve(null) : listMachines(machineQuery(state))),
    [queryKey, health],
  );

  // The cards: counts over the whole census, never the page.
  const kpis = useAsync(() => getMachineSummary(), []);
  // The header menus: counts under the activity the list shows, so a menu
  // count is the number of rows its choice lists. A search ignores the
  // activity, and so do its menus.
  const menuActivity = state.activity === 'active' && !state.q ? 'active' : 'all';
  const activeCounts = useAsync(
    () => (menuActivity === 'active' ? getMachineSummary('active') : Promise.resolve(null)),
    [menuActivity],
  );
  const menuCounts = menuActivity === 'active' ? activeCounts.data : kpis.data;
  // The address census. It says whether any sweep has built anything (the
  // first-run screen), whether sweeps run on a schedule, and the role
  // vocabulary a bulk declare may write.
  const census = useAsync(() => getDossierSummary(), []);
  // What a row's stale marker says about the sweep the row comes from.
  const listSweep: ListSweep = {
    scheduleEnabled: census.data ? census.data.schedule_enabled : null,
    staleHours: kpis.data?.stale_hours ?? null,
  };

  // The disagreement queue. Its own request because `pending` counts the whole
  // queue, not this page.
  const conflicts = useAsync(() => getDossierConflicts(), []);
  const pending = conflicts.data?.pending ?? 0;
  // The Dashboard nudge and the Conflicts card deep-link with ?conflicts=1.
  const [showConflicts, setShowConflicts] = useState(() => searchParams.get('conflicts') === '1');
  const conflictsParam = searchParams.get('conflicts');
  useEffect(() => {
    if (conflictsParam === '1') setShowConflicts(true);
  }, [conflictsParam]);

  // The SPA's only role source. The mutating dossier routes are admin-gated.
  const [me, setMe] = useState<Me | null>(null);
  useEffect(() => {
    getMe()
      .then(setMe)
      .catch(() => {
        /* unknown role: the rebuild control stays hidden, reads still work */
      });
  }, []);
  const isAdmin = me?.role === 'admin';

  // Sweep status. The FULL record is an admin-gated GET; every other role
  // reads the closed sweep-health projection. Polling is armed but SKIPPED
  // unless a sweep is in flight.
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

  // A finished sweep rewrote every machine it touched. Reload the page the
  // operator is looking at, the cards and the queue.
  const wasRunning = useRef(false);
  useEffect(() => {
    if (wasRunning.current && !running) {
      list.refetch();
      conflicts.refetch();
      kpis.refetch();
      activeCounts.refetch();
      census.refetch();
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
      // 'already running' and 'dossier disabled' both mean THIS click did
      // nothing, and the screen says so.
      if (status.note && status.note !== 'started') setNote(status.note);
      refresh.refetch();
    } catch (err) {
      setNote(err instanceof Error ? err.message : String(err));
    } finally {
      setStarting(false);
    }
  };

  const listData = list.data;
  const rows = useMemo(() => listData?.rows ?? [], [listData]);
  const total = listData?.total ?? 0;
  const offset = (state.page - 1) * HOSTS_PAGE_SIZE;
  const shownFrom = total === 0 ? 0 : offset + 1;
  const shownTo = Math.min(offset + HOSTS_PAGE_SIZE, total);

  // ---- the way back: the list URL and the scroll position ------------------
  const rootRef = useRef<HTMLDivElement>(null);
  const scrollTop = useRef(0);
  // A row click saves the position at the click. The machine page then takes
  // the place of the long list, the pane is short, and its scroll goes to 0
  // before the unmount cleanup runs. The cleanup must not write that 0 over
  // the click (dogfood 2026-10-02: 1729, then 0 52 ms later).
  const savedAtOpen = useRef(false);
  const search = location.search;
  const searchRef = useRef(search);
  searchRef.current = search;
  useEffect(() => {
    rememberListUrl(search);
    // A click that opened a new tab left the list here, on a new URL now.
    savedAtOpen.current = false;
  }, [search]);
  useEffect(() => {
    const scroller = scrollParent(rootRef.current);
    if (!scroller) return;
    const onScroll = () => {
      scrollTop.current = scroller.scrollTop;
    };
    scroller.addEventListener('scroll', onScroll, { passive: true });
    return () => {
      scroller.removeEventListener('scroll', onScroll);
      if (!savedAtOpen.current) rememberListScroll(searchRef.current, scrollTop.current);
    };
  }, []);
  const saveScroll = () => {
    const scroller = scrollParent(rootRef.current);
    rememberListScroll(search, scroller?.scrollTop ?? scrollTop.current);
    savedAtOpen.current = true;
  };
  // Restore once, after the rows for this URL have rendered. Before the rows
  // load the page is too short to hold the old position.
  const restored = useRef(false);
  useEffect(() => {
    if (restored.current || !listData) return;
    restored.current = true;
    const top = savedListScroll(search);
    if (top == null || top <= 0) return;
    const scroller = scrollParent(rootRef.current);
    if (scroller) {
      scroller.scrollTop = top;
      scrollTop.current = top;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [listData]);
  const linkState: HostsLocationState = { fromList: `/hosts${search}` };

  // ---- bulk declare --------------------------------------------------------
  // Admin only, because the declare is admin-gated server-side. A machine is
  // declared through its primary address: the address the machine page shows
  // and edits.
  const sel = useListSelection(rows.map((r) => r.primary_ip));
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

  // The last bulk declaration, for Undo. Each address carries the operator
  // value it held BEFORE the declaration: Undo restores that value, or removes
  // the declaration when there was none. An address whose earlier value could
  // not be read is left alone, and the note says so.
  const [lastBulk, setLastBulk] = useState<{
    field: 'role' | 'criticality';
    value: string;
    prior: Array<{ ip: string; value: string | null }>;
    unknown: string[];
  } | null>(null);
  const [undoBusy, setUndoBusy] = useState(false);

  const undoBulk = async () => {
    if (!lastBulk) return;
    const blocked = demoBlocked(demo);
    if (blocked) {
      setBulkNote(blocked);
      return;
    }
    setUndoBusy(true);
    const failed: string[] = [];
    for (const { ip, value } of lastBulk.prior) {
      try {
        if (value == null) await clearDossierOverride(ip, lastBulk.field);
        else await setDossierOverride(ip, { field: lastBulk.field, value });
      } catch {
        failed.push(ip);
      }
    }
    const undone = lastBulk.prior.length - failed.length;
    const parts = [`Undid ${lastBulk.field} "${lastBulk.value}" on ${plural(undone, 'machine')}.`];
    if (lastBulk.unknown.length) {
      parts.push(
        `${plural(lastBulk.unknown.length, 'machine')} kept the declaration. This page could not read their earlier value.`,
      );
    }
    if (failed.length) parts.push(`${failed.length} failed: ${failed.slice(0, 3).join(', ')}.`);
    setBulkNote(parts.join(' '));
    setLastBulk(null);
    setUndoBusy(false);
    list.refetch();
    kpis.refetch();
    activeCounts.refetch();
  };

  /** The operator value each address holds now, read off its dossier. An
   *  address whose dossier cannot be read maps to undefined. */
  const readPrior = async (ips: string[], field: 'role' | 'criticality') => {
    const out = new Map<string, string | null | undefined>();
    await Promise.all(
      ips.map((ip) =>
        getDossier(ip)
          .then((d) => {
            const f = d.fields.find((x) => x.field === field);
            out.set(ip, f && f.overridden ? (f.value ?? null) : null);
          })
          .catch(() => {
            out.set(ip, undefined);
          }),
      ),
    );
    return out;
  };

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
      const before = await readPrior(ips, bulkField);
      const out = await bulkSetDossierOverride(ips, { field: bulkField, value });
      // Name what did NOT take, per arm.
      const names = (items: string[]) =>
        `${items.slice(0, 3).join(', ')}${items.length > 3 ? `, +${items.length - 3} more` : ''}`;
      const failedIps = (out.failed ?? []).map((f) => f.ip);
      const parts = [
        `Declared ${bulkField} "${value}" on ${out.updated.length} of ${plural(ips.length, 'machine')}.`,
      ];
      if (out.not_found.length) {
        parts.push(`${out.not_found.length} not swept yet: ${names(out.not_found)}.`);
      }
      if (failedIps.length) {
        parts.push(`${failedIps.length} failed: ${names(failedIps)}. Try those again.`);
      }
      setBulkNote(parts.join(' '));
      const known = (ip: string) => before.get(ip) !== undefined;
      setLastBulk(
        out.updated.length
          ? {
              field: bulkField,
              value,
              prior: out.updated
                .filter(known)
                .map((ip) => ({ ip, value: before.get(ip) ?? null })),
              unknown: out.updated.filter((ip) => !known(ip)),
            }
          : null,
      );
      // Keep the ones that did not land selected, so "try those again" is one
      // click.
      const retry = [...out.not_found, ...failedIps];
      if (retry.length) sel.select(retry);
      else sel.clear();
      setBulkValue('');
      list.refetch();
      kpis.refetch();
      activeCounts.refetch();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setBulkNote(/^403\b/.test(msg) ? 'Only an admin can declare host facts.' : msg);
    } finally {
      setBulkBusy(false);
    }
  };

  // What a BULK declare may set a role to: the classifier's closed vocabulary,
  // and nothing else. One typo here would become a role for every machine
  // selected. The server enforces the same list.
  const wireRoles = census.data?.role_vocabulary;
  const bulkRoleOptions = useMemo(
    () => [
      { value: '', label: 'choose…' },
      ...[...roleVocabulary(wireRoles)].sort().map((r) => ({ value: r, label: roleLabel(r) })),
    ],
    [wireRoles],
  );

  // ---- filters, sort, saved views ------------------------------------------
  const currentQuery: SavedViewQuery = {
    q: state.q,
    role: state.role,
    agent: state.agent,
    activity: state.activity,
    seen: state.seen,
    declared: state.declared,
    sort: state.sort,
    dir: state.dir,
  };
  // A TOTAL apply: a filter the view does not name goes back to the default.
  const views = useSavedViews('hosts', currentQuery, (saved) => {
    const patch = fromSavedView(saved);
    setSearchParams(
      (prev) => {
        const base = new URLSearchParams(prev);
        for (const key of ['q', 'role', 'agent', 'activity', 'seen', 'declared', 'sort', 'dir', 'page']) {
          base.delete(key);
        }
        return patchListParams(base, patch);
      },
      { replace: true },
    );
  });

  const setFilter = (patch: Partial<Record<keyof HostsListState, string | null>>) => {
    update(patch);
    views.clearActive();
  };
  const onSort = (key: MachineSortKey) => {
    const dir = state.sort === key ? (state.dir === 'asc' ? 'desc' : 'asc') : FIRST_DIR[key];
    update({ sort: key, dir });
    views.clearActive();
  };
  const clearHealth = () => {
    const next = new URLSearchParams(searchParams);
    next.delete('health');
    next.delete('page');
    setSearchParams(next, { replace: true });
  };
  const clearFilters = () => {
    setQInput('');
    lastWritten.current = '';
    setFilter({ q: null, role: null, agent: null, seen: null, declared: null });
  };

  const summary = refresh.data?.summary ?? null;
  const summaryCount = (key: string): number | null => {
    const v = summary?.[key];
    return typeof v === 'number' ? v : null;
  };
  const sweptCounts: string[] = [];
  const hostsBuilt = summaryCount('hosts_built');
  const fieldsWritten = summaryCount('fields_written');
  if (hostsBuilt != null) sweptCounts.push(`${hostsBuilt.toLocaleString()} hosts built`);
  if (fieldsWritten != null) sweptCounts.push(`${fieldsWritten.toLocaleString()} fields written`);

  // What the sweep could NOT do. `errors` and nothing else: advisory notes are
  // not trouble, and a zero count is not trouble either.
  const sweepErrors = refresh.data?.errors ?? [];
  const sweepErrorCount = refresh.data?.errorCount ?? 0;
  const sweepDegraded = !!refresh.data?.degraded;
  // The screen asked after the sweep and got nothing back. "We could not
  // check" and "no sweep has run" are different sentences. A FOREGROUND
  // failure only: useAsync keeps last-good data through a failed poll.
  const sweepUnreadable = !!refresh.error && !refresh.data;

  // The first run: nothing swept, nothing filtered. Gated on the address
  // CENSUS, never on the page's own total. A census that is swept but quiet is
  // "no machines match", not "the sweep hasn't run". A failed list read is an
  // error with Retry, never the first-run panel.
  const narrowed = !!(state.q || state.role || state.agent || state.seen || state.declared || health);
  const firstRun = !!census.data && census.data.hosts === 0 && !narrowed && !list.error;

  const showSweepErrors = !running && sweepDegraded;
  const showSweptCounts = isAdmin && !note && !running && !firstRun && sweptCounts.length > 0;
  const sweepInFlight = running || starting;

  const activeChips: Array<{ key: keyof HostsListState; label: string }> = [];
  if (state.role) activeChips.push({ key: 'role', label: `Role: ${roleFilterLabel(state.role)}` });
  if (state.agent) activeChips.push({ key: 'agent', label: state.agent === 'yes' ? 'With an agent' : 'Without an agent' });
  if (state.seen) activeChips.push({ key: 'seen', label: 'New in 7 days' });
  if (state.declared) {
    activeChips.push({ key: 'declared', label: state.declared === 'yes' ? 'Declared by an operator' : 'Not declared' });
  }

  const machines = kpis.data?.machines;
  const addresses = kpis.data?.addresses;

  return (
    <div ref={rootRef} className="px-[22px] pb-[60px] pt-5">
      {/* page header */}
      <div className="mb-4">
        <div className="flex items-baseline gap-3">
          <div className="text-title">Hosts</div>
          <Freshness at={list.lastUpdated} />
        </div>
        <div data-testid="hosts-count" className="mt-0.5 font-mono text-[12.5px] text-text-2">
          {machines != null && addresses != null
            ? `${plural(machines, 'machine')} · ${plural(addresses, 'address', 'addresses')}`
            : kpis.error
              ? 'The machine count could not be read.'
              : 'Counting machines…'}
        </div>
        <div className="mt-0.5 max-w-[760px] text-[13px] text-dim">
          One row is one machine. A machine holds every address that soc-ai ties to one device.
          You can declare your own answers. Your declaration replaces the sweep answer.
        </div>
      </div>

      {list.failCount >= 2 && (
        <StaleNotice since={list.lastUpdated} onRefresh={list.refetch} className="mb-3" />
      )}

      {/* The shared list toolbar. Hidden on first run. The toolbar holds the
          bulk bar and stays on screen while the operator selects rows. */}
      {!firstRun && !health && (
        <div
          data-testid="hosts-toolbar"
          className={cn(selecting && 'sticky top-0 z-20 bg-bg pb-1 shadow-[0_1px_0_rgba(0,0,0,.4)]')}
        >
          <ListToolbar
            views={views.views}
            activeViewId={views.activeViewId}
            onApplyView={views.onApplyView}
            onDeleteView={views.onDeleteView}
            onSaveView={views.onSaveView}
            viewError={views.error}
            saveViewUnavailable={views.unavailable}
            search={{
              value: qInput,
              onChange: (v) => {
                setQInput(v);
                views.clearActive();
              },
              placeholder: 'Search name, address, MAC, OS, role, agent…',
              label: 'Search hosts',
              fitPlaceholder: true,
            }}
            note={bulkNote}
            selection={
              selecting
                ? {
                    count: sel.count,
                    noun: sel.count === 1 ? 'machine selected' : 'machines selected',
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
                          title="Declare this value on the primary address of every selected machine. Your answer wins over the sweep answer and survives the next rebuild."
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
                <>
                  {lastBulk && (
                    <button
                      data-testid="bulk-undo"
                      onClick={() => {
                        void undoBulk();
                      }}
                      disabled={undoBusy}
                      title="Undo the last bulk declaration. Each address gets back the value it held before. Nothing else changes."
                      className="flex items-center gap-1.5 rounded-[7px] border border-warn/40 px-[11px] py-1.5 text-[12.5px] font-semibold text-warn hover:bg-warn/10 disabled:opacity-60"
                    >
                      {undoBusy
                        ? 'Undoing…'
                        : `Undo ${lastBulk.field} "${lastBulk.value}" (${lastBulk.prior.length})`}
                    </button>
                  )}
                  <button
                    onClick={() => {
                      void rebuild();
                    }}
                    disabled={starting || running}
                    title="Start a network sweep now. The sweep runs in the background because it queries hundreds of hosts."
                    className="flex items-center gap-1.5 rounded-[7px] border border-border-strong px-[11px] py-1.5 text-[12.5px] font-semibold text-dim hover:text-text disabled:opacity-60"
                  >
                    <RefreshCw size={12} className={running || starting ? 'animate-spin' : ''} />
                    {running ? 'Rebuilding…' : 'Rebuild now'}
                  </button>
                </>
              ) : undefined
            }
          />
          {/* The search reads the whole census. The activity filter does not
              apply to it, and the screen says so while a query is set. */}
          {state.q && (
            <div data-testid="hosts-search-scope" className="-mt-1.5 mb-2 text-[11.5px] text-faint">
              Searching all hosts. The activity filter does not apply to a search.
            </div>
          )}
          {activeChips.length > 0 && (
            <div data-testid="hosts-active-filters" className="mb-2.5 flex flex-wrap items-center gap-1.5">
              {activeChips.map((c) => (
                <button
                  key={c.key}
                  type="button"
                  onClick={() => setFilter({ [c.key]: null })}
                  aria-label={`Remove the filter ${c.label}`}
                  className="flex items-center gap-1 rounded-chip border border-accent/40 bg-accent/10 px-2 py-0.5 text-[11.5px] font-semibold text-accent hover:bg-accent/20"
                >
                  {c.label}
                  <X size={11} />
                </button>
              ))}
              <button
                type="button"
                onClick={clearFilters}
                className="text-[11.5px] text-dim underline hover:text-text"
              >
                Clear filters
              </button>
            </div>
          )}
        </div>
      )}

      {/* Sweep feedback: the note from the POST and the last run's counters. */}
      {note && (
        <div className="mb-3.5 rounded-card border border-warn/30 bg-warn/[0.06] px-3.5 py-2.5 text-[12.5px] text-text-2">
          {note === 'dossier disabled' ? (
            <>
              The host dossier is off. The sweep did not run. Turn the host dossier on in{' '}
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
                The last sweep recorded {plural(sweepErrorCount, 'error')}. The sweep did not read
                the whole network. This list is incomplete. A host that is missing below, or that
                shows old answers, may be a host the sweep could not reach.{' '}
                {sweepErrors.length > 0
                  ? 'A rebuild runs the same queries. Start with what failed:'
                  : 'An admin can read what failed on this screen. An admin can start another sweep.'}
              </div>
              {sweepErrors.length > 0 && (
                <ul className="mt-1.5 max-w-[760px] space-y-0.5 text-[11.5px] text-dim">
                  {sweepErrors.slice(0, SHOWN_ERRORS).map((e, i) => (
                    <li key={i} className="truncate font-mono" title={e}>
                      {e}
                    </li>
                  ))}
                  {sweepErrors.length > SHOWN_ERRORS && (
                    <li className="text-faint">
                      {(sweepErrors.length - SHOWN_ERRORS).toLocaleString()} more errors
                    </li>
                  )}
                </ul>
              )}
            </div>
          )}
          {showSweptCounts && (
            <div
              data-testid="sweep-run-summary"
              title="The most recent sweep wrote these counts. The summary line above gives the age of the data."
              className="text-[11.5px] text-faint"
            >
              Last sweep: {sweptCounts.join(' · ')}
            </div>
          )}
        </div>
      )}

      {/* Network-wide, above everything the table says about a page of it. */}
      {!firstRun && (
        <HostsSummary
          summary={kpis.data}
          failed={kpis.error != null}
          linkFor={(patch) => listHref({ sort: state.sort, dir: state.dir, ...patch })}
          brokenHref={BROKEN_HREF}
          conflictsHref={CONFLICTS_HREF}
          scheduleEnabled={census.data ? census.data.schedule_enabled : null}
        />
      )}

      {/* The disagreement queue: the single conflict surface on this screen. */}
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
                  This queue shows the {conflicts.data?.rows.length} oldest disagreements. Resolve
                  these first.
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* The broken-builds view names itself, with the way back. */}
      {health && (
        <div className="mb-3.5 flex flex-wrap items-center gap-3 rounded-card border border-danger/30 bg-danger/[0.05] px-3.5 py-2.5 text-[12.5px] text-text-2">
          <AlertTriangle size={13} className="flex-none text-danger" />
          <span className="min-w-0 flex-1">
            This view shows the addresses the sweep is not getting through to. A build never ran,
            or the last build failed.
          </span>
          <button
            onClick={clearHealth}
            className="flex-none rounded-control border border-border-strong bg-surface-3 px-2.5 py-1 text-[11.5px] font-semibold text-text-2 hover:text-text"
          >
            Show all machines
          </button>
        </div>
      )}

      {firstRun ? (
        <Panel>
          <PanelHeader icon={<Server size={15} />} title="Hosts" />
          <EmptyState>
            <div className="mx-auto max-w-[520px]">
              {/* An empty census has several causes, and the sweep record
                  tells them apart: a sweep in flight, a sweep that died, a
                  status read that failed, and a sweep that never ran.
                  `data-sweep` says what this lead KNOWS. */}
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
                  'The network sweep is running now. This list fills in after the sweep finishes. The sweep reads telemetry Security Onion already holds. Nothing new touches your network.'
                ) : sweepDegraded ? (
                  'The last sweep could not read the network. The sweep built nothing. This list is empty because the sweep failed. The network may still hold hosts.'
                ) : sweepUnreadable ? (
                  <>
                    This screen could not check the result of the last sweep. This screen cannot
                    tell you why this list is empty. A sweep that never ran leaves an empty list. A
                    sweep that failed leaves the same empty list.
                    <span className="mt-1 block font-mono text-[11.5px] text-faint">
                      {refresh.error?.message}
                    </span>
                  </>
                ) : (
                  "The network sweep hasn't run yet. The sweep builds this list from telemetry Security Onion already holds. Nothing new touches your network."
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
                  An admin starts it from this screen. An admin can also turn on the schedule.
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
      ) : health ? (
        <BrokenBuilds page={state.page} onPage={(page) => update({ page })} />
      ) : (
        <Panel>
          <PanelHeader
            icon={<Server size={15} />}
            title={listData ? `Machines · ${total.toLocaleString()}` : 'Machines'}
          />
          <div className="overflow-x-auto">
            <table data-testid="hosts-table" className="w-full table-fixed border-collapse text-[12.5px]">
              <thead className="border-b border-border bg-surface-2 text-[10.5px] text-faint">
                <tr>
                  {isAdmin && (
                    <th scope="col" className="w-[38px] px-2.5 py-[9px] text-left">
                      <Checkbox
                        checked={sel.allVisibleSelected}
                        indeterminate={!sel.allVisibleSelected && sel.someVisibleSelected}
                        onChange={sel.toggleAll}
                        title="Select every machine on this page."
                        aria-label="Select all hosts on this page"
                      />
                    </th>
                  )}
                  {COLUMNS.map((col) => (
                    <SortHeader
                      key={col.key}
                      col={col}
                      state={state}
                      onSort={onSort}
                      filter={
                        col.key === 'role' ? (
                          <HeaderFilter
                            name="Role"
                            groups={[
                              {
                                label: 'Role',
                                value: state.role,
                                options: roleOptions(menuCounts, state.role),
                                onChange: (v) => setFilter({ role: v || null }),
                              },
                              {
                                label: 'Declaration',
                                value: state.declared,
                                options: [
                                  { value: '', label: 'any' },
                                  { value: 'yes', label: 'declared by an operator' },
                                  { value: 'no', label: 'not declared' },
                                ],
                                onChange: (v) => setFilter({ declared: v || null }),
                              },
                            ]}
                          />
                        ) : col.key === 'agent' ? (
                          <HeaderFilter
                            name="Agent"
                            groups={[
                              {
                                value: state.agent,
                                options: [
                                  { value: '', label: 'any' },
                                  { value: 'yes', label: 'with an agent', count: menuCounts?.with_agent },
                                  { value: 'no', label: 'without an agent', count: menuCounts?.without_agent },
                                ],
                                onChange: (v) => setFilter({ agent: v || null }),
                              },
                            ]}
                          />
                        ) : col.key === 'events' ? (
                          <HeaderFilter
                            name="Activity"
                            align="right"
                            groups={[
                              {
                                value: state.activity,
                                options: [
                                  { value: 'active', label: 'machines with events' },
                                  { value: 'all', label: 'all machines', count: kpis.data?.machines },
                                ],
                                onChange: (v) => setFilter({ activity: v === 'all' ? 'all' : null }),
                              },
                            ]}
                          />
                        ) : col.key === 'first_seen' ? (
                          <HeaderFilter
                            name="First seen"
                            align="right"
                            groups={[
                              {
                                value: state.seen,
                                options: [
                                  { value: '', label: 'any time' },
                                  { value: 'new', label: 'in the last 7 days', count: menuCounts?.new_7d },
                                ],
                                onChange: (v) => setFilter({ seen: v || null }),
                              },
                            ]}
                          />
                        ) : undefined
                      }
                    />
                  ))}
                </tr>
              </thead>
              <tbody>
                {list.loading && !listData ? (
                  <tr>
                    <td colSpan={COLUMNS.length + (isAdmin ? 1 : 0)}>
                      <LoadingState label="Loading machines…" />
                    </td>
                  </tr>
                ) : list.error ? (
                  <tr>
                    <td colSpan={COLUMNS.length + (isAdmin ? 1 : 0)} className="p-3.5">
                      <ErrorState error={list.error} onRetry={list.refetch} label="the host list" />
                    </td>
                  </tr>
                ) : rows.length === 0 ? (
                  <tr>
                    <td colSpan={COLUMNS.length + (isAdmin ? 1 : 0)}>
                      <EmptyState>
                        {state.q
                          ? `No machine matches "${state.q}". The search reads every name, address, MAC, OS, role and agent name.`
                          : 'No machines match the current filters. Change a filter to see more machines.'}
                      </EmptyState>
                    </td>
                  </tr>
                ) : (
                  rows.map((row) => (
                    <MachineTableRow
                      key={row.key}
                      row={row}
                      selectable={isAdmin}
                      selected={sel.isSelected(row.primary_ip)}
                      onToggle={() => sel.toggle(row.primary_ip)}
                      onOpen={saveScroll}
                      linkState={linkState}
                      sweep={listSweep}
                    />
                  ))
                )}
              </tbody>
            </table>
          </div>

          {listData && !list.error && rows.length > 0 && (
            <Pager
              from={shownFrom}
              to={shownTo}
              total={total}
              page={state.page}
              onPage={(page) => update({ page })}
            />
          )}

          {/* The note for the screen's default: quiet machines are hidden, not
              gone, and the way back is one click. Not while a search is set:
              the search reads every machine. */}
          {!(list.loading && !listData) && !list.error && state.activity === 'active' && !state.q && (
            <div className="px-[15px] pb-2.5 pt-1 text-[11.5px] text-faint">
              This list hides quiet machines. A quiet machine has no events.{' '}
              <button
                type="button"
                className="text-dim underline hover:text-text"
                onClick={() => setFilter({ activity: 'all' })}
              >
                show all machines
              </button>
            </div>
          )}
        </Panel>
      )}
    </div>
  );
}
