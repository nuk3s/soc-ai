import { Plus, Radar } from 'lucide-react';
import { useState, type KeyboardEvent } from 'react';
import { Link, useSearchParams } from 'react-router-dom';

import {
  createAnalytic,
  getAnalytics,
  getHuntCatalog,
  type AnalyticRow,
  type AnalyticsList,
  type HuntCatalog,
  type PriorCoverage,
} from '../lib/api';
import {
  type RunState,
  appliesWord,
  failureLine,
  intervalWords,
  loopResultLine,
  methodWord,
  runsInProfileSweep,
  sourceWord,
  specRunState,
  sweepsNotice,
  windowWords,
} from '../lib/analyticRuns';
import { useDemo } from '../lib/demo';
import { plural } from '../lib/plural';
import { ago } from '../lib/timeRange';
import { CHIP_HELD_BY_SYSTEM } from '../lib/tooltips';
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

// "Paused by soc-ai" is a view of the shadow analytics that a system demotion
// holds. The word was nowhere on the screen (dogfood 2026-10-06 C6). A
// candidate reads "Draft": it is written and has never run.
const STATUS_CHIPS: { id: string; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'live', label: 'Live' },
  { id: 'shadow', label: 'Shadow' },
  { id: 'held', label: 'Paused by soc-ai' },
  { id: 'candidate', label: 'Draft' },
  { id: 'retired', label: 'Retired' },
];

/** True for the rows the status view shows. "held" is the paused view. */
function inStatusView(a: AnalyticRow, status: string): boolean {
  if (status === 'all') return true;
  if (status === 'held') return Boolean(a.held_by_system);
  return a.status === status;
}

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
      inStatusView(a, f.status) &&
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
  'live: the sweep runs the analytic and raises what it finds. ' +
  'shadow: the sweep runs the analytic and records what it finds. ' +
  'Paused by soc-ai: soc-ai moved a live analytic to shadow. The analytic fired too often or ' +
  'was often wrong. Approve it or reject it. ' +
  'draft: the sweep has never run the analytic. ' +
  'retired: the analytic keeps its ledger and its reason. ' +
  'Rejected: the analytic is retired, and the reason is on record.';

const TIER_TITLE =
  'Where the analytic is stored. A shipped analytic is a file in the repository. A local analytic is a row in this deployment.';

const WEEK_TITLE =
  'What this analytic did over the last 7 days: the observations it wrote and the leads it fed.';

/** How fresh the baseline the sweep scored against was, or why a dimension
 *  could not be measured. Empty for a backend that does not say. */
export function baselineNote(coverage: PriorCoverage): string {
  if (coverage.profiles_reason) return ` · baseline unmeasurable: ${coverage.profiles_reason}`;
  if (!coverage.profiles_built_at) return '';
  const hours = Math.max(
    0,
    Math.floor((Date.now() - Date.parse(coverage.profiles_built_at)) / 3_600_000),
  );
  return ` · profiles built ${hours} h ago${coverage.profiles_stale ? ', stale' : ''}`;
}

/** " · capped at 500" when the run's evaluations reached the recent read's
 *  cap. The totals then count the cap, not the estate: "blind 489" on a
 *  336-host estate read as operator hosts. */
export function capNote(coverage: PriorCoverage): string {
  return coverage.capped ? ` · capped at ${coverage.recent_cap ?? 500}` : '';
}

/** The coverage column. A learned detector reads no stored host profile, so
 *  the build time of those profiles says nothing about it. The cell read
 *  "baseline 13 h old" on a detector that builds its own baseline. */
function coverageCell(coverage: PriorCoverage | null | undefined, evaluator?: string): string {
  // A query analytic reads no baseline. The cell said a dash (K2).
  if (!coverage) return 'not measured';
  const baseline = evaluator === 'model' ? '' : baselineNote(coverage);
  return `${coverage.measured} measured · ${coverage.blind} blind${capNote(coverage)}${baseline}`;
}

/** The count a blind reason opens with. The sweep states it on every reason. */
const COUNTED_REASON = /^\d+ of \d+ blind /;

/** The reason the blind entities are blind, when the sweep named one. The
 *  two connection rate analytics read as "0 measured · 103 blind" for most
 *  of a day after an upgrade with nothing on any surface saying why. */
function blindReason(coverage: PriorCoverage | null | undefined): string | null {
  const reason = coverage?.blind_reason;
  if (!reason || !coverage || coverage.blind <= 0) return null;
  // The sweep opens each reason with its count: "35 of 56 blind hosts: ...".
  // A row an older sweep stored has no count, and it keeps the label.
  return COUNTED_REASON.test(reason) ? reason : `blind: ${reason}`;
}

/** The visible state when a loop does not run, with the setting that turns
 *  the catalog sweep on. The only sign used to be "last sweep never". */
function SweepsNotice({ catalog }: { catalog: HuntCatalog | null | undefined }) {
  const demo = useDemo();
  const lines = sweepsNotice(catalog);
  if (!lines.length) return null;
  return (
    <div
      data-testid="analytics-sweeps-notice"
      role="status"
      className="border-b border-border-faint bg-surface-2/40 px-[15px] py-2 text-[12.5px] text-warn"
    >
      {lines.join(' ')}{' '}
      {catalog && !catalog.sweeps_enabled && (
        <span data-testid="analytics-sweeps-explainer">
          An analytic sweep runs every live analytic as a grid query on a schedule. A document
          that matches becomes an observation on the host it names, and observations can form a
          lead.{' '}
        </span>
      )}
      {catalog && !catalog.sweeps_enabled && !demo && (
        <Link to="/config#triage-automation" className="font-semibold text-accent hover:underline">
          Turn on Analytic sweeps in Settings, under Triage automation.
        </Link>
      )}
    </div>
  );
}

/** The sweep the coverage figures came from. A coverage column with no date
 *  on it reads as the state of the grid now, and it is the state of the grid
 *  at the newest sweep. */
function sweepLine(catalog: HuntCatalog | null | undefined): string {
  if (!catalog) return '';
  const when = catalog.last_sweep_at ? ago(catalog.last_sweep_at) : 'never';
  const failed = catalog.sweep_health?.last_outcome === 'failed' ? 'failed ' : '';
  return `last sweep ${failed}${when} · looks back ${windowWords(catalog.sweep_window_minutes)}`;
}

/** The result line of each loop that ran: the newest run and the failed runs
 *  of the day. The tab read "last sweep 13m ago" over 25 failed sweeps. */
function SweepResults({ catalog }: { catalog: HuntCatalog | null | undefined }) {
  if (!catalog) return null;
  const lines = [
    { id: 'match', noun: 'Analytic sweep', health: catalog.sweep_health },
    { id: 'profile', noun: 'Profile sweep', health: catalog.prior_sweep_health },
  ]
    .map((l) => ({ ...l, text: loopResultLine(l.health) }))
    .filter((l) => l.text && l.health && (l.health.last_outcome !== 'ok' || l.health.failed_24h > 0));
  if (!lines.length) return null;
  return (
    <div
      data-testid="analytics-sweep-results"
      role="status"
      className="border-b border-border-faint px-[15px] py-1.5 text-[12px] text-warn"
    >
      {lines.map((l) => (
        <div key={l.id} data-testid={`analytics-sweep-result-${l.id}`}>
          {l.noun}: {l.text}
        </div>
      ))}
    </div>
  );
}

/** The control that opens the New analytic box. It sits in the panel header,
 *  and the box opens as a full-width row under the header. The box opened in
 *  the right slot of the header as a 200 px textarea, which is too narrow
 *  for a YAML analytic (dogfood 2026-10-19, V1-H9). */
function NewAnalyticButton({ open, onToggle }: { open: boolean; onToggle: () => void }) {
  return (
    <button
      type="button"
      onClick={onToggle}
      aria-expanded={open}
      aria-controls="new-analytic-box"
      className="flex items-center gap-1 rounded-control border border-border-strong px-2.5 py-1 text-[11.5px] font-semibold hover:bg-surface-2"
    >
      <Plus size={12} /> New analytic
    </button>
  );
}

function NewAnalyticBox({
  open,
  setOpen,
  onCreated,
}: {
  open: boolean;
  setOpen: (open: boolean) => void;
  onCreated: () => void;
}) {
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

  // Escape closes the box, as it closes every other form on the page. The
  // text stays, so a second open shows the draft again.
  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key !== 'Escape') return;
    e.stopPropagation();
    setOpen(false);
  };

  if (!open) return null;
  return (
    <div
      id="new-analytic-box"
      className="flex w-full flex-col gap-1.5 border-b border-border px-[15px] py-2.5"
      onKeyDown={onKeyDown}
      data-testid="new-analytic-box"
    >
      <textarea
        autoFocus
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={14}
        aria-label="The analytic as YAML"
        placeholder="Paste the analytic as YAML. It is stored as a draft. Put it in shadow to run it."
        className="w-full resize-y rounded-control border border-border bg-surface-2 p-2 font-mono text-[11.5px] leading-[1.5]"
      />
      {hint && <div className="text-[11.5px] text-warn">{hint}</div>}
      <div className="flex items-center gap-2">
        <button
          type="button"
          disabled={!text.trim() || busy}
          onClick={submit}
          className="rounded-control bg-accent px-3 py-1 text-[11.5px] font-semibold text-white disabled:opacity-50"
        >
          Store as draft
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
  running,
  every,
  failure,
  onOpen,
  onChanged,
}: {
  analytic: AnalyticRow;
  /** The failed newest run in one sentence, or null. */
  failure?: string | null;
  coverage: PriorCoverage | null | undefined;
  /** False when the loop that runs this analytic is off, 'waiting' when it is
   *  on and has not run yet. */
  running: RunState;
  /** How often the loop runs, as words. */
  every: string;
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
        <div className="mt-0.5 break-all font-mono text-[11px] text-faint">{analytic.id}</div>
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
          {(analytic.pinned?.length ?? 0) > 0 && (
            <span
              data-testid={`analytic-specific-${analytic.id}`}
              className="rounded-chip border px-1.5 py-px text-[10px] text-warn"
              style={{ borderColor: 'rgba(245,166,35,.35)' }}
              title={`This analytic is specific to one case. ${(analytic.pinned ?? []).join(' ')}`}
            >
              specific
            </span>
          )}
        </div>
      </td>
      <td className="whitespace-nowrap px-2 py-2.5 text-[11.5px] text-dim" title={TIER_TITLE}>
        {sourceWord(analytic.tier)}
        <div className="text-faint">method: {methodWord(analytic.evaluator)}</div>
      </td>
      <td className="whitespace-nowrap px-2 py-2.5 text-[12px]">
        <StatusDot status={analytic.status} running={running} every={every} />
        {/* A hold by soc-ai reads apart from an analyst's shadow. The reason
            is on the chip, and the drawer holds the evidence. */}
        {analytic.held_by_system && (
          <div
            data-testid={`analytic-held-${analytic.id}`}
            className="mt-1 w-fit rounded-chip border px-1.5 py-px text-[10px] text-warn"
            style={{ borderColor: 'rgba(210,153,34,.45)' }}
            title={`${CHIP_HELD_BY_SYSTEM} ${analytic.held_by_system}`}
          >
            Paused by soc-ai
          </div>
        )}
        {failure && (
          <div
            data-testid={`analytic-failed-${analytic.id}`}
            className="mt-1 max-w-[260px] whitespace-normal text-[11px] text-danger"
          >
            {failure}
          </div>
        )}
      </td>
      <td className="px-2 py-2.5 font-mono text-[11px] text-dim" title={WEEK_TITLE}>
        {plural(analytic.observations_7d, 'observation')} · {plural(analytic.leads_7d, 'lead')} ·{' '}
        {analytic.hunted_7d} hunted ·{' '}
        {analytic.dismissed_7d} dismissed
        {analytic.status === 'shadow' && (
          <div>
            {plural(analytic.shadow_hits_7d, 'shadow hit')} · {analytic.unread_shadow_hits} unread
          </div>
        )}
      </td>
      <td className="px-2 py-2.5 font-mono text-[11px] text-dim" title={COVERAGE_TITLE}>
        {coverageCell(coverage, analytic.evaluator)}
        {blindReason(coverage) && (
          <div
            data-testid={`analytic-blind-reason-${analytic.id}`}
            className="text-dim"
            title="Why the blind entities could not be measured on the newest sweep."
          >
            {blindReason(coverage)}
          </div>
        )}
        {blind && (
          <div
            data-testid={`analytic-blind-${analytic.id}`}
            title="The newest sweep matched nothing that this analytic reads. The zero means that the telemetry is absent."
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
  // The New analytic box: its button sits in the header, the box under it.
  const [newOpen, setNewOpen] = useState(false);
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
  const specOf = new Map((catalog.data?.specs ?? []).map((s) => [s.id, s] as const));
  // When the loop last tried to run an analytic. A failed profile sweep wrote
  // no trail row, so the loop's own record dates it.
  const triedAt = (id: string): string | null => {
    const spec = specOf.get(id);
    if (!spec) return null;
    return runsInProfileSweep(spec.evaluator)
      ? (catalog.data?.prior_sweep_health?.last_run_at ?? spec.last_swept_at)
      : spec.last_swept_at;
  };
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
              <NewAnalyticButton open={newOpen} onToggle={() => setNewOpen((v) => !v)} />
              <Freshness at={list.lastUpdated} />
            </span>
          }
        />
        <NewAnalyticBox open={newOpen} setOpen={setNewOpen} onCreated={changed} />
        {/* What an analytic is, before the analytics. */}
        <Definition of="analytic" className="border-b border-border px-[15px] py-2.5" />
        {!data ? (
          list.error ? (
            <div className="px-[15px] py-3 text-[13px] text-dim">Could not read the analytics.</div>
          ) : (
            <LoadingState label="Reading the analytics" />
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
              draft · {counts.retired ?? 0} retired
            </div>
            <div className="border-b border-border-faint px-[15px] py-2">
              <ListToolbar
                presets={STATUS_CHIPS.map((c) => ({
                  id: c.id,
                  label: c.label,
                  count:
                    c.id === 'all'
                      ? all.length
                      : c.id === 'held'
                        ? all.filter((a) => a.held_by_system).length
                        : (counts[c.id] ?? 0),
                  active: filters.status === c.id,
                }))}
                onPreset={(id) => setFilter('status', id)}
                search={{
                  value: filters.q,
                  onChange: (v) => setFilter('q', v),
                  placeholder: 'Search title or id',
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
                {/* The words a reader knows (C6). The address keeps the
                    stored names: tier, evaluator, scope. */}
                <Select
                  label="Source"
                  value={filters.tier}
                  onChange={(v) => setFilter('tier', v)}
                  options={[
                    { value: '', label: 'Source: any' },
                    ...valuesOf(all, 'tier').map((v) => ({ value: v, label: `Source: ${sourceWord(v)}` })),
                  ]}
                />
                <Select
                  label="Level"
                  value={filters.level}
                  onChange={(v) => setFilter('level', v)}
                  options={[{ value: '', label: 'level: any' }, ...LEVELS]}
                />
                <Select
                  label="Method"
                  value={filters.evaluator}
                  onChange={(v) => setFilter('evaluator', v)}
                  options={[
                    { value: '', label: 'Method: any' },
                    ...valuesOf(all, 'evaluator').map((v) => ({
                      value: v,
                      label: `Method: ${methodWord(v)}`,
                    })),
                  ]}
                />
                <Select
                  label="Applies to"
                  value={filters.scope}
                  onChange={(v) => setFilter('scope', v)}
                  options={[
                    { value: '', label: 'Applies to: any' },
                    ...valuesOf(all, 'scope_kind').map((v) => ({
                      value: v,
                      label: `Applies to: ${appliesWord(v)}`,
                    })),
                  ]}
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
            <SweepResults catalog={catalog.data} />
            <SweepsNotice catalog={catalog.data} />
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
                    <th className="px-2 py-1.5">Source</th>
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
                      running={specRunState(
                        catalog.data,
                        specOf.get(analytic.id),
                        analytic.evaluator,
                      )}
                      failure={failureLine(specOf.get(analytic.id), triedAt(analytic.id))}
                      every={intervalWords(
                        runsInProfileSweep(analytic.evaluator)
                          ? 60
                          : catalog.data?.sweep_interval_minutes,
                      )}
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
