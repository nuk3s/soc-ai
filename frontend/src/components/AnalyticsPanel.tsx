import { Plus, Radar } from 'lucide-react';
import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';

import {
  createAnalytic,
  getAnalytics,
  getHuntCatalog,
  type AnalyticRow,
  type AnalyticsList,
  type HuntCatalog,
  type PriorCoverage,
} from '../lib/api';
import { ago } from '../lib/timeRange';
import { useAsync, type UseAsyncResult } from '../lib/useAsync';
import { AnalyticActions, COVERAGE_TITLE, StatusDot } from './AnalyticDrawer';
import { AnalyticDrawer } from './AnalyticDrawer';
import { Select } from './Controls';
import { Definition } from './Definition';
import { LeadQualityPanel } from './LeadQualityPanel';
import { ListToolbar } from './ListToolbar';
import { Panel, PanelHeader } from './Panel';
import { Freshness, LoadingState } from './States';

// ---------------------------------------------------------------------------
// The Analytics tab — one analytic is one detection logic.
//
// Operate answers "does this analytic run and what can it see". This panel
// answers "what did it find and does it earn its place". The two questions
// sit one tab apart on purpose: the first is an operator's, the second is an
// analyst's, and one list that tried to answer both answered neither.
//
// The status word is the column that was missing. A retired analytic and a
// quiet live one render the same row of zeros without it.
// ---------------------------------------------------------------------------

const STATUS_ORDER: Record<string, number> = { shadow: 0, candidate: 1, live: 2, retired: 3 };

// ---------------------------------------------------------------------------
// Filters. Twenty analytics fit on one screen. Two hundred do not, and the
// owner asked for the list to filter on criteria. Each filter lives in the
// address bar beside the tab, so a reload keeps it and a link carries it.
// The Hunts screen drops them when it leaves the tab, so the address always
// describes the table on screen.
// ---------------------------------------------------------------------------

/** The address-bar parameters this panel reads. Hunts clears them on a tab change. */
export const ANALYTIC_FILTER_PARAMS = [
  'status',
  'tier',
  'level',
  'evaluator',
  'scope',
  'active',
  'q',
] as const;

const STATUS_CHIPS: { id: string; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'live', label: 'Live' },
  { id: 'shadow', label: 'Shadow' },
  { id: 'candidate', label: 'Candidate' },
  { id: 'retired', label: 'Retired' },
];

const LEVELS = ['critical', 'high', 'medium', 'low'];

interface AnalyticFilters {
  status: string;
  tier: string;
  level: string;
  evaluator: string;
  scope: string;
  /** Only analytics that wrote an observation in the last 7 days. */
  active: boolean;
  q: string;
}

function readFilters(params: URLSearchParams): AnalyticFilters {
  const status = params.get('status') ?? 'all';
  return {
    status: STATUS_CHIPS.some((c) => c.id === status) ? status : 'all',
    tier: params.get('tier') ?? '',
    level: params.get('level') ?? '',
    evaluator: params.get('evaluator') ?? '',
    scope: params.get('scope') ?? '',
    active: params.get('active') === '1',
    q: params.get('q') ?? '',
  };
}

function anyFilter(f: AnalyticFilters): boolean {
  return (
    f.status !== 'all' || !!f.tier || !!f.level || !!f.evaluator || !!f.scope || f.active || !!f.q
  );
}

/** The rows that pass every filter. The search reads the title and the id. */
export function filterAnalytics(rows: AnalyticRow[], f: AnalyticFilters): AnalyticRow[] {
  const q = f.q.trim().toLowerCase();
  return rows.filter(
    (a) =>
      (f.status === 'all' || a.status === f.status) &&
      (!f.tier || a.tier === f.tier) &&
      (!f.level || a.level === f.level) &&
      (!f.evaluator || a.evaluator === f.evaluator) &&
      (!f.scope || a.scope_kind === f.scope) &&
      (!f.active || a.observations_7d > 0) &&
      (!q || a.title.toLowerCase().includes(q) || a.id.toLowerCase().includes(q)),
  );
}

/** The values the loaded list carries, so a select never offers a value that
 *  matches nothing. */
function valuesOf(rows: AnalyticRow[], key: 'tier' | 'evaluator' | 'scope_kind'): string[] {
  return [...new Set(rows.map((r) => r[key]).filter(Boolean))].sort();
}

// Each status names the actor and what happens to what it finds. "runs,
// recorded, not raised" named neither, so an analyst could not tell whether
// the sweep or an analyst does the recording.
const LEGEND =
  'live: the sweep runs it and raises what it finds. ' +
  'shadow: the sweep runs it and records what it finds. ' +
  'candidate: the sweep has never run it. ' +
  'retired: the analytic keeps its ledger and its reason. ' +
  'Rejected = retired with a reason.';

const TIER_TITLE =
  'Where the analytic is stored. A shipped analytic is a file in the repository. A local analytic is a row in this deployment.';

const WEEK_TITLE =
  'What this analytic did over the last 7 days. obs is observations written. leads is the leads it fed.';

/** How fresh the baseline the sweep scored against was, or why a dimension
 *  could not be measured. Empty for a backend that does not say. */
export function baselineNote(coverage: PriorCoverage): string {
  if (coverage.profiles_reason) return ` · baseline unmeasurable: ${coverage.profiles_reason}`;
  if (!coverage.profiles_built_at) return '';
  const hours = Math.max(
    0,
    Math.floor((Date.now() - Date.parse(coverage.profiles_built_at)) / 3_600_000),
  );
  return ` · baseline ${hours} h old${coverage.profiles_stale ? ', stale' : ''}`;
}

function coverageCell(coverage: PriorCoverage | null | undefined): string {
  if (!coverage) return '—';
  return `${coverage.measured} measured · ${coverage.blind} blind${baselineNote(coverage)}`;
}

/** The sweep the coverage figures came from. A coverage column with no date
 *  on it reads as the state of the grid now, and it is the state of the grid
 *  at the newest sweep. */
function sweepLine(catalog: HuntCatalog | null | undefined): string {
  if (!catalog) return '';
  const when = catalog.last_sweep_at ? ago(catalog.last_sweep_at) : 'never';
  return `last sweep ${when} · window ${catalog.sweep_window_minutes} min`;
}

function NewAnalyticBox({ onCreated }: { onCreated: () => void }) {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [hint, setHint] = useState<string | null>(null);

  const submit = async () => {
    setBusy(true);
    setHint(null);
    try {
      await createAnalytic(text);
      setText('');
      setOpen(false);
      onCreated();
    } catch (e) {
      setHint(e instanceof Error ? e.message : 'The analytic was not stored.');
    } finally {
      setBusy(false);
    }
  };

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="flex items-center gap-1 rounded-control border border-border-strong px-2.5 py-1 text-[11.5px] font-semibold hover:bg-surface-2"
      >
        <Plus size={12} /> New analytic
      </button>
    );
  }
  return (
    <div className="flex w-full flex-col gap-1.5">
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={8}
        placeholder="Paste the analytic as YAML. It is stored as a candidate. Put it in shadow to run it."
        className="w-full rounded-control border border-border bg-surface-2 p-2 font-mono text-[11.5px]"
      />
      {hint && <div className="text-[11.5px] text-warn">{hint}</div>}
      <div className="flex items-center gap-2">
        <button
          type="button"
          disabled={!text.trim() || busy}
          onClick={submit}
          className="rounded-control bg-accent px-3 py-1 text-[11.5px] font-semibold text-white disabled:opacity-50"
        >
          Store as candidate
        </button>
        <button type="button" onClick={() => setOpen(false)} className="text-[11.5px] text-dim">
          Cancel
        </button>
      </div>
    </div>
  );
}

function Row({
  analytic,
  coverage,
  blind,
  onOpen,
  onChanged,
}: {
  analytic: AnalyticRow;
  coverage: PriorCoverage | null | undefined;
  /** The newest sweep found nothing the analytic reads. Its zero row is the
   *  absence of telemetry, and it read as an analytic that found nothing. */
  blind: boolean;
  onOpen: () => void;
  onChanged: () => void;
}) {
  return (
    <tr data-testid={`analytic-${analytic.id}`} className="border-t border-border align-top">
      <td className="px-[15px] py-2.5">
        <button
          type="button"
          onClick={onOpen}
          className="text-left text-[12.5px] font-semibold text-accent hover:underline"
        >
          {analytic.title}
        </button>
        {/* The id under the title: two analytics on one subject read the same
            from the title alone, and the id is what an objective and a CLI
            call take. */}
        <div className="mt-0.5 truncate font-mono text-[11px] text-faint">{analytic.id}</div>
        <div className="mt-1 flex flex-wrap items-center gap-1.5">
          <span className="rounded-chip border border-border-strong px-1.5 py-px text-[10px] uppercase tracking-[.04em] text-dim">
            {analytic.level}
          </span>
          {analytic.no_benign_baseline && (
            <span
              className="rounded-chip border border-border-strong px-1.5 py-px text-[10px] text-dim"
              title="No benign population produces this. One observation from this analytic is a finding on its own."
            >
              no benign baseline
            </span>
          )}
        </div>
      </td>
      <td className="whitespace-nowrap px-2 py-2.5 text-[11.5px] text-dim" title={TIER_TITLE}>
        {analytic.tier}
      </td>
      <td className="whitespace-nowrap px-2 py-2.5 text-[12px]">
        <StatusDot status={analytic.status} />
      </td>
      <td className="px-2 py-2.5 font-mono text-[11px] text-dim" title={WEEK_TITLE}>
        {analytic.observations_7d} obs · {analytic.leads_7d} leads · {analytic.hunted_7d} hunted ·{' '}
        {analytic.dismissed_7d} dismissed
        {analytic.status === 'shadow' && (
          <div>
            {analytic.shadow_hits_7d} shadow hits · {analytic.unread_shadow_hits} unread
          </div>
        )}
      </td>
      <td className="px-2 py-2.5 font-mono text-[11px] text-dim" title={COVERAGE_TITLE}>
        {coverageCell(coverage)}
        {blind && (
          <div
            data-testid={`analytic-blind-${analytic.id}`}
            title="The newest sweep matched nothing this analytic reads. Its zero is the absence of telemetry."
          >
            blind on the last sweep
          </div>
        )}
      </td>
      <td className="px-[15px] py-2.5">
        <AnalyticActions analytic={analytic} onChanged={onChanged} />
      </td>
    </tr>
  );
}

/**
 * The Analytics tab.
 *
 * `shared` is the list the Hunts screen already holds for its tab count. The
 * screen and the panel each read GET /analytics before, so the same list
 * arrived twice and the two could disagree for one poll. The panel still
 * fetches for itself wherever no parent holds the list.
 */
export function AnalyticsPanel({
  shared,
  onChanged,
}: {
  shared?: UseAsyncResult<AnalyticsList>;
  onChanged?: () => void;
} = {}) {
  const [reload, setReload] = useState(0);
  const [searchParams, setSearchParams] = useSearchParams();
  // The open drawer lives in the address, the way the same drawer does when a
  // lead page links to it. A title click held it in component state alone, so
  // a reload closed it and the address described a screen that was not on
  // display.
  const openId = searchParams.get('open');
  const setOpenId = (id: string | null) => {
    const params = new URLSearchParams(searchParams);
    if (id) params.set('open', id);
    else params.delete('open');
    setSearchParams(params, { replace: true });
  };
  const filters = readFilters(searchParams);
  const setFilter = (key: (typeof ANALYTIC_FILTER_PARAMS)[number], value: string) => {
    const params = new URLSearchParams(searchParams);
    if (!value || (key === 'status' && value === 'all')) params.delete(key);
    else params.set(key, value);
    setSearchParams(params, { replace: true });
  };
  const clearFilters = () => {
    const params = new URLSearchParams(searchParams);
    for (const key of ANALYTIC_FILTER_PARAMS) params.delete(key);
    setSearchParams(params, { replace: true });
  };
  const own = useAsync<AnalyticsList | null>(
    () => (shared ? Promise.resolve(null) : getAnalytics()),
    [reload],
    { refetchInterval: shared ? 0 : 300_000 },
  );
  const list: UseAsyncResult<AnalyticsList | null> = shared ?? own;
  const catalog = useAsync(getHuntCatalog, [reload], { refetchInterval: 300_000 });
  const data = list.data;
  const coverageOf = new Map(
    (catalog.data?.specs ?? []).map((s) => [s.id, s.coverage] as const),
  );
  const blindOf = new Map((catalog.data?.specs ?? []).map((s) => [s.id, s.blind] as const));
  const sweep = sweepLine(catalog.data);
  const all = data?.analytics ?? [];
  const rows = filterAnalytics(all, filters).sort(
    (a, b) => (STATUS_ORDER[a.status] ?? 9) - (STATUS_ORDER[b.status] ?? 9),
  );
  const counts = data?.counts ?? {};
  const filtered = anyFilter(filters);
  const changed = () => {
    setReload((n) => n + 1);
    onChanged?.();
  };

  return (
    <>
      <Panel>
        <PanelHeader
          icon={<Radar size={16} />}
          title="Analytics"
          right={
            <span className="flex items-center gap-2.5">
              <NewAnalyticBox onCreated={changed} />
              <Freshness at={list.lastUpdated} />
            </span>
          }
        />
        {/* What an analytic is, before the analytics. */}
        <Definition of="analytic" className="border-b border-border px-[15px] py-2.5" />
        {!data ? (
          list.error ? (
            <div className="px-[15px] py-3 text-[13px] text-dim">Could not read the analytics.</div>
          ) : (
            <LoadingState label="Reading the analytics…" />
          )
        ) : (
          <>
            <div
              data-testid="analytics-counts"
              className="border-b border-border px-[15px] py-2.5 text-[12.5px] text-text-2"
            >
              {filtered
                ? `${rows.length} of ${all.length} analytics match`
                : `${all.length} analytics`}
              {' · '}
              {counts.live ?? 0} live · {counts.shadow ?? 0} shadow · {counts.candidate ?? 0}{' '}
              candidate · {counts.retired ?? 0} retired
            </div>
            <div className="border-b border-border-faint px-[15px] py-2">
              <ListToolbar
                presets={STATUS_CHIPS.map((c) => ({
                  id: c.id,
                  label: c.label,
                  count: c.id === 'all' ? all.length : (counts[c.id] ?? 0),
                  active: filters.status === c.id,
                }))}
                onPreset={(id) => setFilter('status', id)}
                search={{
                  value: filters.q,
                  onChange: (v) => setFilter('q', v),
                  placeholder: 'Search title or id…',
                  label: 'Search analytics',
                }}
                trailing={
                  filtered ? (
                    <button
                      type="button"
                      onClick={clearFilters}
                      className="text-[11.5px] font-semibold text-accent hover:underline"
                    >
                      Clear filters
                    </button>
                  ) : undefined
                }
              >
                <Select
                  label="Tier"
                  value={filters.tier}
                  onChange={(v) => setFilter('tier', v)}
                  options={[{ value: '', label: 'tier: any' }, ...valuesOf(all, 'tier')]}
                />
                <Select
                  label="Level"
                  value={filters.level}
                  onChange={(v) => setFilter('level', v)}
                  options={[{ value: '', label: 'level: any' }, ...LEVELS]}
                />
                <Select
                  label="Evaluator"
                  value={filters.evaluator}
                  onChange={(v) => setFilter('evaluator', v)}
                  options={[{ value: '', label: 'evaluator: any' }, ...valuesOf(all, 'evaluator')]}
                />
                <Select
                  label="Scope"
                  value={filters.scope}
                  onChange={(v) => setFilter('scope', v)}
                  options={[{ value: '', label: 'scope: any' }, ...valuesOf(all, 'scope_kind')]}
                />
                <label
                  className="flex cursor-pointer items-center gap-1.5 text-[12px] text-dim"
                  title="Only analytics that wrote an observation in the last 7 days."
                >
                  <input
                    type="checkbox"
                    checked={filters.active}
                    onChange={(e) => setFilter('active', e.target.checked ? '1' : '')}
                  />
                  active in 7 days
                </label>
              </ListToolbar>
            </div>
            {/* The date the coverage column speaks for. Without it the
                column reads as the state of the grid now. */}
            {sweep && (
              <div
                data-testid="analytics-sweep"
                className="border-b border-border-faint px-[15px] py-1.5 font-mono text-[11px] text-dim"
              >
                {sweep}
              </div>
            )}
            <div
              data-testid="analytics-legend"
              className="border-b border-border-faint px-[15px] py-1.5 text-[11px] text-dim"
            >
              {LEGEND}
            </div>
            {rows.length === 0 ? (
              <div className="px-[15px] py-3 text-[12.5px] text-dim">
                {filtered ? (
                  <>
                    No analytic matches these filters.{' '}
                    <button
                      type="button"
                      onClick={clearFilters}
                      className="font-semibold text-accent hover:underline"
                    >
                      Clear filters
                    </button>
                  </>
                ) : (
                  'No analytics are installed. The catalog is empty.'
                )}
              </div>
            ) : (
              <table className="w-full table-auto text-left">
                <thead>
                  <tr className="text-[10.5px] font-semibold uppercase tracking-[.05em] text-faint">
                    <th className="px-[15px] py-1.5">Analytic</th>
                    <th className="px-2 py-1.5">Tier</th>
                    <th className="px-2 py-1.5">Status</th>
                    <th className="px-2 py-1.5">Last 7 days</th>
                    <th className="px-2 py-1.5">Coverage</th>
                    {/* The action buttons wrapped to two lines below 1024
                        and doubled the height of every row. */}
                    <th className="px-[15px] py-1.5 lg:w-[210px]">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((analytic) => (
                    <Row
                      key={analytic.id}
                      analytic={analytic}
                      coverage={coverageOf.get(analytic.id)}
                      blind={blindOf.get(analytic.id) === true}
                      onOpen={() => setOpenId(analytic.id)}
                      onChanged={changed}
                    />
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}
      </Panel>
      {/* What the lead rule produced, under the analytics that feed it. The
          table above answers "does this analytic earn its place". This block
          answers the same question of the rule that joins their observations
          into a lead. */}
      <LeadQualityPanel />
      {/* Mounted only while it is open. `Drawer` registers with the modal
          stack before it renders, so a closed drawer left mounted would put
          every screen that embeds this panel inside the shell context. */}
      {openId !== null && (
        <AnalyticDrawer analyticId={openId} onClose={() => setOpenId(null)} onChanged={changed} />
      )}
    </>
  );
}
