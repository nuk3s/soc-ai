import {
  AlertTriangle,
  CalendarClock,
  Check,
  ChevronDown,
  ChevronRight,
  Crosshair,
  Loader2,
  Pencil,
  Plus,
  RefreshCw,
  RotateCw,
  Trash2,
  X,
} from 'lucide-react';
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Link, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { Checkbox } from '../components/Controls';
import { Definition } from '../components/Definition';
import { GridGapStrip } from '../components/GridGapStrip';
import { FLOW_PARAM, FlowLink, HowThisFlowsDrawer } from '../components/HowThisFlows';
import { ListToolbar } from '../components/ListToolbar';
import { scrollIntoViewSettled } from '../lib/scrollSettled';
import { useTabTitle } from '../lib/useTabTitle';
import { useListSelection } from '../lib/useListSelection';
import { useSavedViews } from '../lib/useSavedViews';
import { CollapseChevron, Panel } from '../components/Panel';
import { RowTags, TAGS_COLUMN, TagsHeader } from '../components/RowTags';
import { EmptyState, ErrorState, Freshness, LoadingState, StaleNotice } from '../components/States';
import { TimeRangeFilter, type CustomRange } from '../components/TimeRangeFilter';
import { demoBlocked, useDemo } from '../lib/demo';
import { rangeToSinceUntil } from '../lib/timeRange';
import {
  ApiError,
  bulkDeleteHunts,
  createHuntSchedule,
  deleteHunt,
  deleteHuntSchedule,
  getHunts,
  getHuntSchedules,
  getHuntStats,
  getHuntTotals,
  HUNTS_PAGE_CAP,
  rehuntHunts,
  startHuntConsole,
  updateHuntSchedule,
} from '../lib/api';
import type { HuntKindTotals, HuntSchedule, HuntScheduleList, Lead } from '../lib/api';
import { huntOutcome, outcomeLabel, outcomeMeta, statusDetail, statusMeta } from '../lib/labels';
import { HUNT_KIND } from '../lib/tokens';
import {
  STATUS_COMPLETE,
  STATUS_COULD_NOT_RUN,
  STATUS_RUNNING,
  TYPE_ALL,
  TYPE_CATALOG,
  TYPE_LEAD,
  TYPE_MANUAL,
  TYPE_SCHEDULE,
} from '../lib/tooltips';
import { useAsync } from '../lib/useAsync';
import { useSectionCollapse } from '../lib/useSectionCollapse';
import type { HuntKind, HuntRehuntResult, HuntRow, HuntStatus, SavedViewQuery } from '../lib/types';
import { LeadsStrip } from '../components/LeadsStrip';
import { ANALYTIC_FILTER_PARAMS, AnalyticsPanel } from '../components/AnalyticsPanel';
import { AnalyticHits } from '../components/AnalyticHits';
import { NeedsYouStrip } from '../components/NeedsYouStrip';
import { NewHuntDrawer } from '../components/NewHuntDrawer';
import { getAnalytics, type AnalyticsList } from '../lib/api';

// The two tabs of this screen. Hunts is what an analyst started. Analytics is
// the detection logic those hunts and the sweeps run.
type HuntsTab = 'hunts' | 'analytics';

function tabClass(active: boolean): string {
  return [
    'relative -mb-px border-b-2 px-3 py-1.5 text-[12.5px] font-semibold',
    active ? 'border-accent text-text' : 'border-transparent text-dim hover:text-text-2',
  ].join(' ');
}

// The four status words, in the order an analyst reads them: what runs, what
// records, what has never run, what stopped. The tab counted live and shadow
// and stopped, so "18 · 16 live · 1 shadow" left two analytics unaccounted
// for. A status with no analytics is left out: a standing zero says nothing.
const ANALYTIC_STATUS_WORDS = ['live', 'shadow', 'candidate', 'retired'] as const;

function analyticsCountLine(list: AnalyticsList | null): string | null {
  if (!list) return null;
  const parts = ANALYTIC_STATUS_WORDS.filter((w) => (list.counts[w] ?? 0) > 0).map(
    (w) => `${list.counts[w]} ${w}`,
  );
  return [String(list.analytics.length), ...parts].join(' · ');
}

/** The block the Scheduled hunts chevron folds. */
const SCHEDULES_BODY_ID = 'scheduled-hunts-body';

// The backend floors a schedule's interval at 60 minutes (MIN_INTERVAL_MINUTES);
// mirror that here so the picker can't offer an interval the API would clamp.
const MIN_INTERVAL_MINUTES = 60;

// ---------------------------------------------------------------------------
// Hunt Console — describe a hunt in plain language; the agent correlates across
// hosts/time and lands findings + a narrative (a HuntReport). Read-only. The
// list + stats are real (/api/v1/hunts*), starting a hunt spawns a background
// run and navigates to its live detail.
// ---------------------------------------------------------------------------

// 28px checkbox · objective · started by · findings · hosts · status ·
// started · actions (re-hunt + delete). The actions gutter grew from 44px to
// fit two icon buttons.
//
// Started by sits beside the objective, as the mockup draws it: the first
// question about a row is whose question it answers.
//
// The objective was the only `1fr` track, so below 1100px it took the whole
// shortfall and the row read "Hunt for hosts b…" while Findings and Hosts each
// held their full width for one digit. The objective now has a floor, and
// the two counters carry floors well under their preferred width, so the
// browser takes the shortfall from them first.
// K7: the status column fits the longest outcome, "No threat found, visibility
// gap", on one line. At 100 px an outcome wrapped onto two lines in every row
// that held it. In a narrow window the words wrap under the dot.
export const STATUS_COLUMN = '220px';
// The chips of a hunt sit in the tags column before the actions: the hunt
// kind, the synthetic mark and the chat count. The objective cell holds the
// objective and nothing else, so every objective starts at the same x
// (owner, 2026-10-07). The objective wraps whole, so its floor is lower than
// when it held the chips. The table fits a 1280px window and scrolls
// sideways under the sum of the floors.
const GRID = `28px minmax(170px, 1fr) 88px minmax(52px, 100px) minmax(48px, 90px) ${STATUS_COLUMN} 72px ${TAGS_COLUMN} 56px`;
const GRID_MIN_WIDTH = 1006;

// The window this screen lands on, and the one a saved view that names no
// window restores. Named so the two cannot drift apart.
//
// Seven days, not one. The hits block reads 7 days and the leads block reads
// all time, so a 24 h hunt list put three windows on one spine: the page read
// "0 hunts" directly under three leads that each offered Read hunt, over a
// database holding 17 hunts. `?range=` still overrides it.
const DEFAULT_RANGE = '7d';

/** The window in words, for a sentence. A custom window has no short name, so
 *  it stays "this window". */
function windowWords(range: string): string {
  if (!/^\d+[mhd]$/.test(range)) return 'this window';
  const n = Number(range.slice(0, -1));
  const unit = range.endsWith('m') ? 'minute' : range.endsWith('h') ? 'hour' : 'day';
  return `the last ${n} ${unit}${n === 1 ? '' : 's'}`;
}

// The type chips: how a hunt came to exist. The list holds agent runs only, so
// the chips read Manual, Schedule and Lead. 'chat' is the storage kind for a
// hunt an analyst typed and reads as "Manual". The storage keeps `kind`; the
// label says type.
//
// `empty` is the noun the empty state uses when the chip, not the window,
// left the table bare. It says "runs" for Schedule: the table lists the runs
// a schedule produced, and the panel titled "Scheduled hunts" further down
// lists the schedules themselves, so "No scheduled hunts" directly above three
// of them read as a contradiction.
//
// Catalog lists the runs the analytic sweep recorded. The list with no type
// holds them too, and the bell links a folded sweep line to this chip. The
// storage kind of a catalog run is `triggered`.
type HuntKindFilter = HuntKind | 'all';
const DEFAULT_KIND: HuntKindFilter = 'all';
type KindChip = { id: HuntKindFilter; label: string; empty: string; title: string };
/** The runs the analytic sweep recorded. */
const CATALOG_KIND: KindChip = {
  id: 'triggered',
  label: 'Catalog',
  empty: 'catalog runs',
  title: TYPE_CATALOG,
};
const KIND_CHIPS: KindChip[] = [
  { id: 'all', label: 'All', empty: 'hunts', title: TYPE_ALL },
  { id: 'chat', label: 'Manual', empty: 'manual hunts', title: TYPE_MANUAL },
  { id: 'scheduled', label: 'Schedule', empty: 'scheduled runs', title: TYPE_SCHEDULE },
  { id: 'lead', label: 'Lead', empty: 'lead hunts', title: TYPE_LEAD },
  CATALOG_KIND,
];
const isKindFilter = (v: unknown): v is HuntKindFilter => KIND_CHIPS.some((c) => c.id === v);

// Who started the hunt. The starter is the CLASS; startedBy is the actor
// name. A row the sweep wrote before the starter column existed reads
// "catalog run", because no person started it.
const starterText = (h: HuntRow): ReactNode => {
  switch (h.starter) {
    case 'lead':
      return h.leadId != null ? (
        <Link to={`/leads/${h.leadId}`} className="text-accent hover:underline">
          lead {h.leadId}
        </Link>
      ) : (
        'lead'
      );
    case 'schedule':
      return 'schedule';
    case 'catalog':
      return 'catalog run';
    default:
      return h.startedBy || 'analyst';
  }
};

/** The plain title of a hunt. The server writes it once for the list, the
 *  hunt page and the bell: a catalog run reads "<analytic>, last 24 h" and a
 *  lead hunt "Lead 6 hunt: domainadmin on SR-DC01". An older server sends no
 *  title, and the row then reads the objective. */
const rowTitle = (h: Pick<HuntRow, 'objective' | 'title'>): string => h.title || h.objective;

// Raw rehunt skip-reason codes (routes_hunts.py::bulk_rehunt) → friendly text.
// Unknown codes fall through to the raw code so a new backend reason is never
// silently swallowed (mirrors Investigations' rehuntSkipReason).
const REHUNT_SKIP_REASONS: Record<string, string> = {
  not_found: 'not found',
  running: 'still running',
  queued: 'queued. Re-hunt a smaller batch.',
  could_not_start: 'could not start',
};
const rehuntSkipReason = (code: string): string => REHUNT_SKIP_REASONS[code] ?? code;

// The header's count line reads "7 hunts · 10 findings · 1 in progress",
// lowercased and de-pluralised at 1 ("1 hunt", never "1 hunts"). The `ss`
// guard keeps "In progress" whole; an English noun ending in `ss` is not a
// plural, and that label is a phrase, not a count noun. `value` is compared
// as a string so it works whether the source is the server's HuntStat
// (string value) or the window-derived stats below (numeric value).
const statNoun = (s: { label: string; value: string | number }): string => {
  const plural = s.label.endsWith('s') && !s.label.endsWith('ss');
  const label = String(s.value) === '1' && plural ? s.label.slice(0, -1) : s.label;
  return label.toLowerCase();
};

/** The outcomes that did not test the objective. A count of their findings
 *  counts gaps and failed queries, so the cell states none. */
const NO_COUNT_OUTCOMES = new Set(['could_not_run', 'no_answer', 'no_threat_gap']);

/** F4: the cell and the header counted threat findings under the word
 *  Findings, so a hunt with one finding read 0 and one with six read 1. The
 *  cell states both counts. The outcome comes from lib/labels.ts. */
/** Whether the findings cell of a row states a count. The header counts the
 *  findings of these rows only, so the two agree. */
function findingsCellCounts(h: HuntRow): boolean {
  const outcome = huntOutcome(h);
  return !(outcome && NO_COUNT_OUTCOMES.has(outcome));
}

function findingsCellText(h: HuntRow): string {
  if (!findingsCellCounts(h)) return '—';
  const total = h.findingCount ?? 0;
  // A row recorded before the threat count existed states the total only.
  const threats = h.threatFindingCount;
  return threats != null && threats > 0 ? `${total} · ${threats} threat` : String(total);
}

/** The hunt a schedule last started. The server sends it beside the schedule
 *  row, and an older server sends nothing. */
function lastHuntOf(s: HuntSchedule): string | null {
  return (s as HuntSchedule & { lastHuntId?: string | null }).lastHuntId ?? null;
}

function findingsCellTitle(h: HuntRow): string | undefined {
  const outcome = huntOutcome(h);
  if (outcome && NO_COUNT_OUTCOMES.has(outcome)) {
    // The outcome in the words of lib/labels.ts, then the reason the server
    // wrote, then where the findings are.
    const reason = h.outcome_headline ? ` ${h.outcome_headline}` : '';
    const n = h.findingCount ?? 0;
    const where = n > 0 ? ` The hunt page lists its ${n} finding${n === 1 ? '' : 's'}.` : '';
    return `${outcomeLabel(outcome)}.${reason}${where}`;
  }
  const threats = h.threatFindingCount ?? h.findingCount;
  const other = h.findingCount - threats;
  return other > 0 ? `${threats} threat finding${threats === 1 ? '' : 's'} · ${other} other finding${other === 1 ? '' : 's'}: visibility gaps and observations` : undefined;
}

function StatusDot({
  status,
  outcome,
  outcomeLabel: serverLabel,
}: {
  status: HuntStatus;
  outcome?: HuntRow['outcome'];
  outcomeLabel?: string;
}) {
  // One outcome per hunt, in the words and the colour of lib/labels.ts. A hunt
  // that could not run is grey and a hunt that found a threat is red. The list
  // compared the legacy codes, so a could-not-run row wore the green dot of a
  // clean hunt. A complete row from an older server with no outcome reads its
  // status.
  const key = huntOutcome({ status, outcome });
  const m = key ? outcomeMeta(key) : statusMeta(status);
  // One sentence per status, the words of Frame 7. A stopped hunt names its
  // stop.
  const title =
    status === 'running'
      ? STATUS_RUNNING
      : key === 'could_not_run'
        ? status === 'complete'
          ? STATUS_COULD_NOT_RUN
          : statusDetail(status)
        : status === 'complete'
          ? STATUS_COMPLETE
          : undefined;
  // The backend names the outcome of a complete hunt. Its word wins, because
  // the client word disagreed with the hunt page beside it.
  // An investigating hunt also carries its count, "Investigating 2 of 3
  // findings", which the client word cannot state.
  const label =
    (status === 'complete' || status === 'investigating') && serverLabel ? serverLabel : m.label;
  return (
    <span
      className="flex items-start gap-1.5 text-[12px] leading-[1.35]"
      style={{ color: m.color }}
      title={title}
      data-testid="hunt-status"
      data-tone={m.tone}
    >
      <span
        className={`mt-[5px] h-1.5 w-1.5 flex-none rounded-full${status === 'running' ? ' animate-pulse' : ''}`}
        style={{ background: m.color }}
      />
      {label}
    </span>
  );
}

// Human-friendly interval label: 60 → "1h", 90 → "1h 30m", 1440 → "24h".
function intervalLabel(minutes: number): string {
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  if (h === 0) return `${m}m`;
  return m === 0 ? `${h}h` : `${h}h ${m}m`;
}

// ---------------------------------------------------------------------------
// Scheduled hunts — recurring hunts fired on an interval by the backend loop
// (gated behind the ``hunt_schedules_enabled`` master switch in Config). Each
// schedule is an objective + interval-minutes + enable toggle; add / edit /
// delete inline. Landing hunts are tagged ``scheduled`` and appear in the list
// above like any other hunt.
// ---------------------------------------------------------------------------
function ScheduledHunts() {
  const navigate = useNavigate();
  // The fold of this section. Nothing links to it, so it holds its own.
  const fold = useSectionCollapse('schedules');
  const demo = useDemo(); // read-only demo: schedule writes show a note, never POST/PATCH/DELETE
  const [reloadKey, setReloadKey] = useState(0);
  const { data, loading, error } = useAsync<HuntScheduleList>(getHuntSchedules, [reloadKey]);
  const schedules = data?.schedules;
  // Defaults to true (no false "paused" flash) until the first response lands —
  // loading/error states already gate the row list below.
  const masterSwitchOn = data?.masterSwitchEnabled ?? true;

  // The add/edit form state. ``editing`` holds the id being edited (null = the
  // add form). Kept flat (not a modal) — modest inline editor, like ManagedList.
  const [editing, setEditing] = useState<number | null>(null);
  const [objective, setObjective] = useState('');
  const [interval, setIntervalMin] = useState(MIN_INTERVAL_MINUTES);
  const [busy, setBusy] = useState(false);
  const [formErr, setFormErr] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<number | null>(null);

  const reload = () => setReloadKey((k) => k + 1);
  const resetForm = () => {
    setEditing(null);
    setObjective('');
    setIntervalMin(MIN_INTERVAL_MINUTES);
    setFormErr(null);
  };

  const startEdit = (s: HuntSchedule) => {
    setEditing(s.id);
    setObjective(s.objective);
    setIntervalMin(s.intervalMinutes);
    setFormErr(null);
  };

  const save = async () => {
    const obj = objective.trim();
    if (!obj || busy) return;
    const blocked = demoBlocked(demo);
    if (blocked) { setFormErr(blocked); return; } // demo: no doomed write
    const mins = Math.max(MIN_INTERVAL_MINUTES, Math.round(interval) || MIN_INTERVAL_MINUTES);
    setBusy(true);
    setFormErr(null);
    try {
      if (editing !== null) {
        await updateHuntSchedule(editing, { objective: obj, interval_minutes: mins });
      } else {
        await createHuntSchedule({ objective: obj, interval_minutes: mins, enabled: true });
      }
      resetForm();
      reload();
    } catch (e: unknown) {
      setFormErr(e instanceof Error ? e.message : 'Could not save the schedule.');
    } finally {
      setBusy(false);
    }
  };

  // A refused toggle or delete must say so. Both routes are admin-only and the
  // panel offers the controls to everyone, so an analyst's click is answered
  // with a 403 — and this list is not polled, so nothing would ever correct a
  // pill that silently stayed put while the schedule kept firing. The message
  // lands in the same slot the add/edit form uses.
  const writeFailure = (e: unknown, fallback: string): string => {
    if (e instanceof ApiError && e.status === 403) return 'Only an admin can change schedules.';
    return e instanceof Error ? e.message : fallback;
  };

  const toggleEnabled = async (s: HuntSchedule) => {
    const blocked = demoBlocked(demo);
    if (blocked) { setFormErr(blocked); return; } // demo: no doomed write
    setFormErr(null);
    try {
      await updateHuntSchedule(s.id, { enabled: !s.enabled });
    } catch (e: unknown) {
      setFormErr(writeFailure(e, 'Could not update the schedule.'));
    }
    reload();
  };

  const removeOne = async (id: number) => {
    const blocked = demoBlocked(demo);
    if (blocked) { setFormErr(blocked); setPendingDelete(null); return; } // demo: no doomed write
    setFormErr(null);
    try {
      await deleteHuntSchedule(id);
      if (editing === id) resetForm();
    } catch (e: unknown) {
      setFormErr(writeFailure(e, 'Could not delete the schedule.'));
    }
    setPendingDelete(null);
    reload();
  };

  return (
    <Panel className="mt-5">
      <div className="flex items-center gap-1.5 border-b border-border px-4 py-3 text-[13px] font-semibold">
        <CollapseChevron
          collapsed={fold.collapsed}
          onToggle={fold.toggle}
          section="Scheduled hunts"
          controls={SCHEDULES_BODY_ID}
        />
        <CalendarClock size={15} className="text-accent" /> Scheduled hunts
        {schedules && (
          <span className="font-mono text-[11.5px] font-normal text-faint">
            · {schedules.length}
          </span>
        )}
      </div>

      {/* What a schedule is, before the schedules. The definition stays while
          the section is folded: a folded block still says what it holds. */}
      <Definition of="schedule" className="px-4 pt-2.5" />

      {/* The banner's CTA deep-links to a Config toggle that is itself demo-
          guarded — a dead-end in the read-only demo — so suppress it in demo mode
          ONLY. The "on (paused)" pills below still render (that IS the 1.2.4
          feature); only this banner is hidden. Live behavior is unchanged. */}
      {data && !masterSwitchOn && !demo && (
        <div className="flex items-center gap-2 border-b border-warn/25 bg-warn/5 px-4 py-2.5 text-[12px] text-warn">
          <AlertTriangle size={14} className="flex-none" />
          <span>
            Scheduled hunts are paused globally.{' '}
            <button
              type="button"
              onClick={() => navigate('/config#triage-automation')}
              className="font-semibold underline decoration-warn/50 underline-offset-2 hover:decoration-warn"
            >
              Turn them on in Settings
            </button>
            . Each row below shows its own state. No schedule fires until the global
            switch is on.
          </span>
        </div>
      )}

      {fold.collapsed ? (
        <div id={SCHEDULES_BODY_ID} className="pb-2" />
      ) : (
        <div id={SCHEDULES_BODY_ID}>
      {loading && !data ? (
        <LoadingState label="Loading schedules" />
      ) : error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : (
        <>
          {!schedules || schedules.length === 0 ? (
            <EmptyState>No scheduled hunts. Add one below.</EmptyState>
          ) : (
            schedules.map((s) => (
              <div
                key={s.id}
                className="flex items-center gap-3 border-b border-border px-4 py-3 last:border-0"
              >
                <button
                  type="button"
                  onClick={() => { void toggleEnabled(s); }}
                  title={
                    !s.enabled
                      ? 'The schedule is paused. Select to turn it on.'
                      : masterSwitchOn
                        ? 'The schedule is on. Select to pause it.'
                        : 'The schedule is on. The global switch in Settings is off. This schedule does not fire.'
                  }
                  className={`flex-none rounded-badge border px-[8px] py-[2px] text-[10.5px] font-semibold uppercase tracking-[.04em] ${
                    s.enabled && masterSwitchOn
                      ? 'border-accent/40 bg-accent/10 text-accent'
                      : 'border-border-strong bg-surface-2 text-faint'
                  }`}
                >
                  {!s.enabled ? 'paused' : masterSwitchOn ? 'on' : 'on (paused)'}
                </button>
                <div className="min-w-0 flex-1">
                  <div
                    data-testid={`schedule-objective-${s.id}`}
                    className="break-words text-[13px] leading-[1.4] text-text"
                    title={s.objective}
                  >
                    {s.objective}
                  </div>
                  <div className="mt-0.5 text-[11.5px] text-faint">
                    every {intervalLabel(s.intervalMinutes)}
                    {/* F17: "last ran" was plain text. It links the hunt the
                        schedule started when the store still holds it. */}
                    {s.lastRunAt ? (
                      <>
                        {' · last ran '}
                        {lastHuntOf(s) ? (
                          <Link
                            data-testid={`schedule-last-hunt-${s.id}`}
                            to={`/hunts/${encodeURIComponent(lastHuntOf(s) ?? '')}`}
                            className="underline hover:text-accent"
                          >
                            {new Date(s.lastRunAt).toLocaleString()}
                          </Link>
                        ) : (
                          new Date(s.lastRunAt).toLocaleString()
                        )}
                      </>
                    ) : (
                      ' · never run'
                    )}
                  </div>
                </div>
                <div className="flex flex-none items-center gap-2">
                  <button
                    onClick={() => startEdit(s)}
                    title="Edit schedule"
                    className="flex text-faint hover:text-accent"
                  >
                    <Pencil size={14} />
                  </button>
                  {pendingDelete === s.id ? (
                    <div className="flex items-center gap-1.5">
                      <button
                        onClick={() => { void removeOne(s.id); }}
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
                      onClick={() => setPendingDelete(s.id)}
                      title="Delete schedule"
                      className="flex text-faint hover:text-danger"
                    >
                      <Trash2 size={13} />
                    </button>
                  )}
                </div>
              </div>
            ))
          )}

          {/* add / edit form */}
          <div className="flex flex-wrap items-center gap-2 px-4 py-3">
            <input
              value={objective}
              onChange={(e) => setObjective(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void save();
              }}
              placeholder={
                editing !== null ? 'Edit the hunt objective' : 'New recurring hunt objective'
              }
              className="min-w-[240px] flex-1 rounded-control border border-border-input bg-bg px-3 py-2 text-[13px] text-text outline-none focus:border-accent"
            />
            <label className="flex items-center gap-1.5 text-[12px] text-dim">
              every
              <input
                type="number"
                min={MIN_INTERVAL_MINUTES}
                step={30}
                value={interval}
                onChange={(e) => setIntervalMin(Number(e.target.value))}
                className="w-[80px] rounded-control border border-border-input bg-bg px-2 py-2 text-[13px] tabular-nums text-text outline-none focus:border-accent"
              />
              min
            </label>
            <button
              onClick={() => { void save(); }}
              disabled={!objective.trim() || busy}
              className="flex items-center gap-1.5 rounded-control bg-accent px-[13px] py-2 text-[13px] font-semibold text-white hover:bg-accent-deep disabled:cursor-not-allowed disabled:opacity-50"
            >
              {busy ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
              {editing !== null ? 'Save' : 'Add'}
            </button>
            {editing !== null && (
              <button
                onClick={resetForm}
                className="rounded-control border border-border-strong bg-surface-2 px-[13px] py-2 text-[13px] font-semibold text-dim hover:text-text"
              >
                Cancel
              </button>
            )}
          </div>
          {formErr && <div className="px-4 pb-3 text-[12px] text-danger">{formErr}</div>}
        </>
      )}
        </div>
      )}
    </Panel>
  );
}

export function Hunts() {
  const navigate = useNavigate();
  const location = useLocation();
  const [reloadKey, setReloadKey] = useState(0);
  // Per-row delete: a trash icon arms an inline confirm in the row, then deletes
  // just that hunt. A running hunt returns 409 (cancel it first).
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);
  const [deleteMsg, setDeleteMsg] = useState<string | null>(null);
  // Per-row re-hunt: an in-flight guard keyed by the source hunt id so a
  // double-click doesn't fire two fresh hunts for the same objective.
  const [rehuntingId, setRehuntingId] = useState<string | null>(null);

  const [rehunting, setRehunting] = useState(false);
  const [bulkDeleting, setBulkDeleting] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [bulkMsg, setBulkMsg] = useState<string | null>(null);
  // Structured bulk-rehunt outcome: the collapsed "Started N · M skipped" header
  // auto-dismisses, but once expanded it PERSISTS until collapsed/dismissed so a
  // mixed batch's which/why isn't yanked away mid-read (mirrors Investigations).
  const [rehuntResult, setRehuntResult] = useState<HuntRehuntResult | null>(null);
  const [rehuntExpanded, setRehuntExpanded] = useState(false);

  const [searchParams, setSearchParams] = useSearchParams();
  // The tab names the page. Every tab read "soc·ai: SOC alert triage".
  useTabTitle('Hunts');

  // Time filter, the same pattern as Alerts and Investigations: a preset
  // (default 7d) or a custom from/to, held in plain component state. Unlike
  // those screens the range feeds the FETCH (GET /hunts?since=&until=, filtered
  // server-side); bounds are recomputed inside the loader so every 8s poll
  // re-anchors "now".
  // A link may name the window it counted over (`/hunts?range=30d` from
  // Operate), so the page opens on the rows the link promised.
  const [range, setRange] = useState(() => {
    const wanted = searchParams.get('range');
    return wanted && /^\d+[mhd]$/.test(wanted) ? wanted : DEFAULT_RANGE;
  });
  const [custom, setCustom] = useState<CustomRange | null>(null);
  // The chip writes the window back, so a reload and a shared link keep it
  // (R3-D12). The default window and a custom range are the plain address.
  // The functional form reads the newest address, so a saved view that sets
  // the window and the type in one handler keeps both.
  useEffect(() => {
    const want = range === DEFAULT_RANGE || range === 'custom' ? null : range;
    if ((searchParams.get('range') ?? null) === want) return;
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (want) next.set('range', want);
        else next.delete('range');
        return next;
      },
      { replace: true },
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [range]);
  // Kind filter — the list's second facet, and like the window it is applied
  // SERVER-SIDE. It used to slice the page the window fetched, but the backend
  // caps that page at 100 rows, so any kind the newest hundred crowded out
  // vanished: 101 manual hunts newer than the one catalog hunt and the Catalog
  // chip read 0 over an empty state saying none existed. One hourly schedule
  // over the 30d preset is 720 rows, so that is the normal case, not an edge.
  //
  // The chip lives in the URL (`?kind=`), the way Hosts keeps `?health=broken`
  // there: a reload keeps it, a bookmark holds it, and the Operate panel can
  // link straight to the catalog rows. A value the chips do not know reads as
  // All; All itself is the absence of the param, so the plain address stays
  // the plain list. A saved view that names a kind writes it here too, so the
  // address bar always describes the table on screen.
  const kindParam = searchParams.get('kind');
  const kind: HuntKindFilter = isKindFilter(kindParam) ? kindParam : DEFAULT_KIND;
  const setKind = (next: HuntKindFilter) => {
    const params = new URLSearchParams(searchParams);
    if (next === DEFAULT_KIND) params.delete('kind');
    else params.set('kind', next);
    setSearchParams(params, { replace: true });
  };

  // The tab lives in the address bar for the reason the kind chip does: a
  // reload keeps it, a bookmark holds it, and the Operate panel links straight
  // to the Analytics tab. Hunts is the absence of the parameter, so the plain
  // address stays the plain console.
  const tabParam = searchParams.get('tab');
  const tab: HuntsTab = tabParam === 'analytics' ? 'analytics' : 'hunts';
  const setTab = (next: HuntsTab) => {
    const params = new URLSearchParams(searchParams);
    if (next === 'hunts') params.delete('tab');
    else params.set('tab', next);
    params.delete('open');
    // The analytics filters describe the Analytics table. They leave with it.
    for (const key of ANALYTIC_FILTER_PARAMS) params.delete(key);
    // So do the filters of the Hunts tab: the hit filter, the lead tab and the
    // composer. A parameter that describes a block the analyst cannot see is a
    // filter waiting to surprise them on the way back. The flow drawer goes
    // with them: a tab change is a move, and a drawer does not follow a move.
    for (const key of ['hits', 'leads', 'lead_entity', 'lead_entity_label', 'new', 'objective', FLOW_PARAM]) {
      params.delete(key);
    }
    setSearchParams(params, { replace: true });
  };

  // `?flow=1` opens the chart of the pipeline. Every definition line and the
  // header link write it, so a reload keeps the drawer open and closing it
  // takes the parameter out again. It is not tied to a tab: the Analytics tab
  // states what an analytic is and carries the same link.
  const flow = searchParams.get(FLOW_PARAM) === '1';
  const setFlow = (open: boolean) => {
    const params = new URLSearchParams(searchParams);
    if (open) params.set(FLOW_PARAM, '1');
    else params.delete(FLOW_PARAM);
    setSearchParams(params, { replace: true });
  };

  // `?new=1` opens the composer. The New hunt button writes it, so a reload
  // keeps the drawer open and closing it takes the parameter out again.
  const newHunt = searchParams.get('new') === '1' && tab === 'hunts';
  // `?objective=` fills the composer. The "Hunt with this query" link of an
  // observation writes it beside `new=1`. Closing the drawer takes both out.
  const newObjective = searchParams.get('objective') ?? '';
  const setNewHunt = (open: boolean) => {
    const params = new URLSearchParams(searchParams);
    if (open) params.set('new', '1');
    else {
      params.delete('new');
      params.delete('objective');
    }
    setSearchParams(params, { replace: true });
  };

  // `?open=<analytic id>` opens that analytic's drawer. The evidence of a
  // shadow hit names every analytic that observed the same documents, and each
  // one is a link to here. The Analytics panel owns that parameter now, so the
  // drawer a title opens and the drawer a link opens are the same drawer.
  // One read of the catalog feeds both the tab count and the panel. The screen
  // and the panel each held their own, so the same list arrived twice and the
  // two could disagree for a poll. The count is refreshed on the slow cadence:
  // the catalog moves when an analyst changes a status.
  const [analyticsReload, setAnalyticsReload] = useState(0);
  const analytics = useAsync(getAnalytics, [analyticsReload], { refetchInterval: 300_000 });
  const analyticsChanged = () => setAnalyticsReload((n) => n + 1);
  const analyticsCount = analyticsCountLine(analytics.data);

  // The fold of each section of this tab. The page holds the three folds that
  // a link can jump to, so a Needs-you link opens the block before it scrolls
  // there. A jump to a folded block lands on a header and reads as a dead link.
  const hitsFold = useSectionCollapse('hits');
  const leadsFold = useSectionCollapse('leads');
  const huntsFold = useSectionCollapse('hunts');

  // A fragment brings its block into view. The Needs-you links carry one, and
  // the bell and the Dashboard card still name #shadow-hits, which is now a
  // filter on the hits block rather than a band of its own.
  const hash = location.hash;
  const expandHits = hitsFold.expand;
  const expandLeads = leadsFold.expand;
  useEffect(() => {
    const target =
      hash === '#shadow-hits' || hash === '#analytic-hits'
        ? 'analytic-hits'
        : hash === '#leads'
          ? 'leads'
          : null;
    if (!target) return;
    // Open it, then scroll to it. The leads above the hits render later and
    // push the block down, so the scroll follows the block while the page
    // settles (R1-D12).
    if (target === 'analytic-hits') expandHits();
    else expandLeads();
    return scrollIntoViewSettled(target);
  }, [tab, hash, expandHits, expandLeads]);

  // `#shadow-hits` is the bell's anchor, and a shadow-hit notice is about one
  // unread hit. The anchor scrolled the block into view with the filter on All,
  // so the card the notice named sat somewhere in a list of every hit. The
  // Dashboard card link already sets the filter; this makes the two agree. A
  // filter the address already names wins: it is the more specific request.
  useEffect(() => {
    if (hash !== '#shadow-hits' || tab !== 'hunts') return;
    if (searchParams.get('hits')) return;
    const params = new URLSearchParams(searchParams);
    params.set('hits', 'unread');
    setSearchParams(params, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hash, tab]);

  // useAsync captures pauseWhen at setup and can't see `data` there, so track
  // whether any hunt is still running in a ref and let pauseWhen (on both polls)
  // consult it: stop polling once every hunt has reached a terminal state.
  const activeRef = useRef(false);
  // `kind` is sent only when a chip other than All is active, so the default
  // request keeps its shape (api.hunts.test.ts pins it).
  const { data, loading, error, lastUpdated, failCount } = useAsync<HuntRow[]>(
    () =>
      getHunts({
        ...rangeToSinceUntil(range, custom),
        ...(kind === 'all' ? {} : { kind }),
      }),
    [reloadKey, range, custom, kind],
    {
      refetchInterval: 8000, // live status (running → complete) without a reload
      pauseWhen: () => !activeRef.current,
    },
  );
  // The counts of the whole window. The list route caps a page at 100 rows,
  // and the header, the section badge and the type chip counted that page: a
  // window of 140 hunts read "100 hunts". The key tags each answer with its
  // window, so a count of the old window never sits over the new one.
  const huntWindowKey = [range, custom?.from ?? '', custom?.to ?? ''].join('|');
  const totalsRead = useAsync(
    async () => ({
      totals: await getHuntTotals(rangeToSinceUntil(range, custom)),
      key: huntWindowKey,
    }),
    [reloadKey, range, custom],
    {
      refetchInterval: 8000,
      pauseWhen: () => !activeRef.current,
    },
  );
  const stats = useAsync(getHuntStats, [reloadKey], {
    refetchInterval: 8000,
    pauseWhen: () => !activeRef.current,
  });
  activeRef.current = (data ?? []).some((h) => h.status === 'running');

  // The list is server-filtered, so an empty page can't tell "no hunts at all"
  // from "none in this window" on its own — the UNFILTERED stats total (already
  // polled for the cards) is the signal. Stats not loaded yet → onboarding text.
  const huntsExist = (stats.data?.find((s) => s.label === 'Hunts')?.value ?? '0') !== '0';

  // The leads the block above is showing. A lead that already holds a hunt is
  // the shortest route to a hunt older than this window, so the empty state
  // names it instead of sending the analyst to the range chips alone.
  const [leadRows, setLeadRows] = useState<Lead[]>([]);
  const leadsHoldHunts = leadRows.some((l) => Boolean(l.hunt_id));

  // `visible` is the server's answer to the window AND the kind chip together;
  // the header, the selection, the active chip's count and the table all read
  // it, so none of them can disagree.
  const visible = useMemo(() => data ?? [], [data]);

  // The header describes the window and the kind chip, as the server
  // answered them. The unwindowed `stats` poll stays: `huntsExist` needs "any
  // hunts EVER" (a quiet window must not flip the screen to onboarding).
  //
  // The counts come from GET /hunts/totals, which counts the whole window.
  // They counted the fetched page, and the backend caps the page at 100 rows,
  // so a window of 140 read "100 hunts". When the totals are not available
  // the counts fall back to the page, and a full page marks each count with
  // "+": the window can hold more rows than the page.
  //
  // Under All the hunt count is broken down by kind, manual included: "12
  // hunts (9 manual, 2 scheduled, 1 catalog)". A manual hunt wears no badge
  // (it is the default, and on most grids the majority; a chip on nine rows
  // in ten is noise), so this line is where the plain rows are accounted
  // for. Under a kind chip the chip names the kind and the breakdown would
  // only repeat it. Kinds come in chip order, spelled as the badges and the
  // detail page spell them, and a kind with no rows is not listed.
  const windowTotals = totalsRead.data?.key === huntWindowKey ? totalsRead.data.totals : null;
  // The totals of the type on screen. A type with no hunt in the window is
  // absent from `by_kind`, and it counts zero.
  const scopedTotals: HuntKindTotals | null = windowTotals
    ? kind === 'all'
      ? windowTotals
      : (windowTotals.by_kind[kind] ?? { hunts: 0, findings: 0, threat_findings: 0, running: 0 })
    : null;
  // With no totals, a full page means the counts are a floor.
  const pageFloor = !scopedTotals && visible.length >= HUNTS_PAGE_CAP;
  const huntCount = scopedTotals
    ? String(scopedTotals.hunts)
    : `${visible.length}${pageFloor ? '+' : ''}`;
  const windowStats = useMemo(() => {
    const rows = visible;
    const mark = (n: number): string => `${n}${pageFloor ? '+' : ''}`;
    const kindCount = (k: HuntKind): number =>
      windowTotals ? (windowTotals.by_kind[k]?.hunts ?? 0) : rows.filter((h) => h.kind === k).length;
    const byKind =
      kind === 'all' && (windowTotals ? windowTotals.hunts > 0 : rows.length > 0)
        ? KIND_CHIPS.filter((c) => c.id !== 'all')
            .map((c) => ({ n: kindCount(c.id as HuntKind), label: HUNT_KIND[c.id as HuntKind].label }))
            .filter((c) => c.n > 0)
            .map((c) => `${mark(c.n)} ${c.label}`)
            .join(', ')
        : '';
    // The header counts what the cells state. A row that could not run or
    // found no answer states no count, so its findings are not counted.
    const findings = scopedTotals
      ? scopedTotals.findings
      : rows.reduce((n, h) => n + (findingsCellCounts(h) ? (h.findingCount ?? 0) : 0), 0);
    const threats = scopedTotals
      ? scopedTotals.threat_findings
      : rows.reduce((n, h) => n + (h.threatFindingCount ?? h.findingCount ?? 0), 0);
    // A hunt that investigates its findings has not ended either.
    const running = scopedTotals
      ? scopedTotals.running
      : rows.filter((h) => h.status === 'running' || h.status === 'investigating').length;
    return [
      {
        label: 'Hunts',
        value: scopedTotals ? String(scopedTotals.hunts) : mark(rows.length),
        sub: 'in window',
        detail: byKind ? `(${byKind})` : '',
      },
      { label: 'Findings', value: mark(findings), sub: `${mark(threats)} threat`, detail: '' },
      { label: 'In progress', value: mark(running), sub: 'running or investigating', detail: '' },
    ];
  }, [visible, kind, windowTotals, scopedTotals, pageFloor]);

  // A hunt started elsewhere won't appear while this list is idle — force one
  // refetch when the tab regains focus.
  useEffect(() => {
    const onFocus = () => setReloadKey((k) => k + 1);
    const onVisible = () => {
      if (document.visibilityState === 'visible') setReloadKey((k) => k + 1);
    };
    window.addEventListener('focus', onFocus);
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      window.removeEventListener('focus', onFocus);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, []);

  // The bulk status line is a transient toast; auto-dismiss it (errors linger a
  // little longer to be read).
  useEffect(() => {
    if (!bulkMsg) return;
    const isError = /fail/i.test(bulkMsg);
    const t = setTimeout(() => setBulkMsg(null), isError ? 8000 : 4500);
    return () => clearTimeout(t);
  }, [bulkMsg]);
  // The collapsed rehunt-result header auto-dismisses; once expanded it stays.
  useEffect(() => {
    if (!rehuntResult || rehuntExpanded) return;
    const t = setTimeout(() => setRehuntResult(null), 6000);
    return () => clearTimeout(t);
  }, [rehuntResult, rehuntExpanded]);

  const deleteOne = async (id: string) => {
    setDeleteMsg(null);
    try {
      await deleteHunt(id);
    } catch (e: unknown) {
      // 409 = the hunt is still running; the API hint surfaces as the message.
      setDeleteMsg(
        e instanceof Error ? e.message : 'The delete failed. Cancel the running hunt first.',
      );
    }
    setPendingDelete(null);
    setReloadKey((k) => k + 1);
  };

  // Per-row re-hunt: a CLEAN re-run of the row's objective as a fresh hunt (no
  // prior-narrative seeding), then navigate to the new hunt's live view — same
  // optimistic navigation the "Start hunt" box does. objective_hash matches, so
  // the fresh run automatically gets the "vs last run" diff.
  const rehuntOne = (h: HuntRow) => {
    if (rehuntingId) return;
    setRehuntingId(h.id);
    setBulkMsg(null);
    startHuntConsole(h.objective)
      .then((r) => navigate(`/hunts/${r.hunt_id}`))
      .catch((e: unknown) => {
        setBulkMsg(`Re-hunt failed: ${e instanceof Error ? e.message : String(e)}`);
        setRehuntingId(null);
      });
  };

  // Selection: the shared hook over the rows on screen. A selection that
  // outlives a chip change is kept and surfaced as off-page, the same way the
  // other lists handle a filter change under a selection.
  const sel = useListSelection(visible.map((h) => h.id));
  const selCount = sel.count;

  // Saved views for the hunt list: the window and the kind chip — "the window
  // I keep coming back to", and for a catalog-heavy grid, "just the hunts a
  // person asked for".
  const savedQuery: SavedViewQuery = { range, custom, kind };
  // A TOTAL apply: a view that names no window (or no kind) restores THIS
  // screen's default one. That is also what makes the chip a real toggle —
  // clicking an active chip applies the empty query, which is this screen
  // unfiltered.
  const views = useSavedViews('hunts', savedQuery, (saved) => {
    setRange(typeof saved.range === 'string' ? saved.range : DEFAULT_RANGE);
    setCustom((saved.custom as CustomRange | null) ?? null);
    setKind(isKindFilter(saved.kind) ? saved.kind : DEFAULT_KIND);
  });

  const handleBulkRehunt = async () => {
    const ids = sel.ids;
    if (!ids.length) return;
    setRehunting(true);
    setBulkMsg(null);
    setRehuntResult(null);
    setRehuntExpanded(false);
    try {
      // Surface the per-id started/skipped detail (the batch is throttled — only
      // the first few start, the rest come back "queued").
      setRehuntResult(await rehuntHunts(ids));
      sel.clear();
      setReloadKey((k) => k + 1);
    } catch (err) {
      setBulkMsg(`Re-hunt failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setRehunting(false);
    }
  };

  const handleBulkDelete = async () => {
    const ids = sel.ids;
    if (!ids.length) return;
    setBulkDeleting(true);
    setBulkMsg(null);
    try {
      const res = await bulkDeleteHunts(ids);
      const nf = res.not_found.length;
      setBulkMsg(
        `Deleted ${res.deleted.length} hunt${res.deleted.length !== 1 ? 's' : ''}` +
          (nf
            ? ` · ${nf} skipped. Each skipped hunt is missing or still running. Cancel a running hunt first.`
            : ''),
      );
    } catch (err) {
      setBulkMsg(`Delete failed: ${err instanceof Error ? err.message : String(err)}`);
    }
    sel.clear();
    setConfirmDelete(false);
    setBulkDeleting(false);
    setReloadKey((k) => k + 1);
  };

  return (
    <div className="px-[22px] pb-[60px] pt-5">
      {/* Page header — the same two lines Alerts, Investigations and Hosts wear:
          title + freshness, then ONE line of counts. Those counts used to be a
          three-card KPI band; the figures (and their sub-labels, now hover
          context) are unchanged, the 112px of chrome around them is not. */}
      <div className="mb-4">
        <div className="flex items-baseline gap-3">
          <div className="text-title">Hunt Console</div>
          <Freshness at={lastUpdated} />
        </div>
        <div data-testid="hunt-stats-line" className="mt-0.5 text-[13px] text-dim">
          {windowStats.map((s, i) => (
            <span key={s.label} title={s.sub}>
              {i > 0 && ' · '}
              <span className="tabular-nums">{s.value}</span> {statNoun(s)}
              {s.detail && ` ${s.detail}`}
            </span>
          ))}
          {/* The chart of the pipeline, beside the line that counts it. */}
          <span className="ml-2 text-[12.5px]">
            <FlowLink />
          </span>
        </div>
        {/* Two tabs, and they live INSIDE the header band. Hunts.anatomy pins
            the count of page bands above the list toolbar at exactly two, the
            header and the composer, because the pixels this screen was fixed
            for were spent by a third band. A tab strip is part of the header,
            so it rides there. */}
        <div className="mt-3 flex gap-1 border-b border-border">
          <button
            type="button"
            onClick={() => setTab('hunts')}
            className={tabClass(tab === 'hunts')}
          >
            Hunts
          </button>
          <button
            type="button"
            onClick={() => setTab('analytics')}
            className={tabClass(tab === 'analytics')}
            title="An analytic is one written detection. Open this tab to read what each analytic found and to change it."
          >
            Analytics
            {analyticsCount && (
              <span className="ml-1.5 font-mono text-[11px] text-faint">{analyticsCount}</span>
            )}
          </button>
        </div>
      </div>

      {tab === 'analytics' ? (
        // The panel owns `?open=` and mounts the drawer itself, so one
        // parameter opens one drawer whichever surface asked for it.
        <AnalyticsPanel shared={analytics} onChanged={analyticsChanged} />
      ) : (
        <>
      {/* The page reads by the work, top to bottom: what needs the analyst,
          the leads that wait on a decision, what the analytics found, what
          was pursued. Each item appears once. W1: the leads started 1,977 px
          down a 900 px screen, under 12 hits that waited on nobody. */}
      <NeedsYouStrip />
      <LeadsStrip
        paramBound
        onRows={setLeadRows}
        collapsed={leadsFold.collapsed}
        onToggleCollapsed={leadsFold.toggle}
      />
      <AnalyticHits
        onAnalyticChanged={analyticsChanged}
        collapsed={hitsFold.collapsed}
        onToggleCollapsed={hitsFold.toggle}
      />

      {/* The hunt section: agent runs only. The catalog sweep writes an
          observation now, and its hit is a card in the block above. */}
      <div className="mb-1.5 flex flex-wrap items-center gap-2.5">
        <CollapseChevron
          collapsed={huntsFold.collapsed}
          onToggle={huntsFold.toggle}
          section="Hunts"
          controls="hunts-body"
        />
        <span className="text-[13px] font-semibold">Hunts</span>
        <span
          className="rounded-chip border border-border-strong bg-surface-2 px-1.5 py-px font-mono text-[11px] tabular-nums text-dim"
          title="The hunts in the window and the type on screen."
        >
          {huntCount}
        </span>
        <span className="ml-auto">
          <button
            type="button"
            onClick={() => setNewHunt(true)}
            title="Write a hunt of your own. The composer opens on the right."
            className="flex items-center gap-1.5 rounded-control bg-accent px-[13px] py-1.5 text-[13px] font-semibold text-white hover:bg-accent-deep"
          >
            <Plus size={14} /> New hunt
          </button>
        </span>
      </div>
      {/* What a hunt is, before the hunts. The definition stays while the
          section is folded: a folded block still says what it holds. */}
      <Definition of="hunt" className="mb-2.5" />
      {huntsFold.collapsed ? (
        <div id="hunts-body" />
      ) : (
        <div id="hunts-body">
      {deleteMsg && <div className="mb-2 text-[12px] text-danger">{deleteMsg}</div>}

      {/* The shared list toolbar — same placement as the other lists: directly
          above the table. The kind chips are its presets; the header line
          above follows whatever they leave in the table. Only the ACTIVE chip
          carries a count. The count is the window total of that type, the
          number the header states. */}
      <ListToolbar
        presetsLabel="Type"
        presets={KIND_CHIPS.map((c) => ({
          id: c.id,
          label: c.label,
          title: c.title,
          count: kind === c.id ? huntCount : undefined,
          active: kind === c.id,
        }))}
        onPreset={(id) => {
          if (!isKindFilter(id)) return;
          setKind(id);
          views.clearActive();
        }}
        views={views.views}
        activeViewId={views.activeViewId}
        onApplyView={views.onApplyView}
        onDeleteView={views.onDeleteView}
        onSaveView={views.onSaveView}
        viewError={views.error}
        saveViewUnavailable={views.unavailable}
        note={bulkMsg}
        selection={{
          count: selCount,
          offPageCount: sel.offPageCount,
          onClearOffPage: sel.clearOffPage,
          onClear: sel.clear,
          actions: (
            <>
              <button
                disabled={rehunting}
                onClick={() => { void handleBulkRehunt(); }}
                title="Re-run the selected objectives as fresh hunts. The batch is throttled. A few hunts start and the rest queue."
                className="flex items-center gap-1.5 rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold text-[#cfe0ff] disabled:opacity-50"
                style={{ background: 'rgba(75,139,245,.14)', borderColor: 'rgba(75,139,245,.4)' }}
              >
                <RefreshCw size={12} className={rehunting ? 'animate-spin' : ''} />
                {rehunting ? 'Starting' : `Re-hunt selected (${selCount})`}
              </button>
              {confirmDelete ? (
                <>
                  <button
                    disabled={bulkDeleting}
                    onClick={() => { void handleBulkDelete(); }}
                    className="flex items-center gap-1.5 rounded-[7px] border border-danger px-[11px] py-1.5 text-[12.5px] font-semibold text-danger disabled:opacity-50"
                  >
                    <Trash2 size={12} />
                    {bulkDeleting ? 'Deleting' : `Confirm delete (${selCount})`}
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
                  title="Delete the selected hunts. This action needs the admin role."
                  className="flex items-center gap-1.5 rounded-[7px] border border-border-strong bg-transparent px-[11px] py-1.5 text-[12.5px] font-semibold text-dim hover:border-danger hover:text-danger"
                >
                  <Trash2 size={12} /> Delete selected ({selCount})
                </button>
              )}
            </>
          ),
        }}
      >
        <TimeRangeFilter
          value={range}
          custom={custom}
          onChange={(v, r) => {
            setRange(v);
            if (r) setCustom(r);
            views.clearActive();
          }}
        />
      </ListToolbar>

      {/* Bulk re-hunt result: a collapsed "Started N · M skipped" header expands
          to the per-id detail the API returns — WHICH objectives re-ran and WHY
          each skip happened (throttle "queued", running, not found) — so a mixed
          batch is never an opaque count (mirrors Investigations E2.2). */}
      {rehuntResult && (() => {
        const started = rehuntResult.started;
        const skipped = rehuntResult.skipped;
        const total = started.length + skipped.length;
        return (
          <div
            className="mb-3.5 overflow-hidden rounded-card border"
            style={{ borderColor: 'rgba(75,139,245,.30)', background: 'rgba(75,139,245,.06)' }}
          >
            <div className="flex items-center gap-2.5 px-3.5 py-2.5 text-[13px]">
              <RefreshCw size={13} className="flex-none text-accent" />
              <button
                onClick={() => total > 0 && setRehuntExpanded((v) => !v)}
                disabled={total === 0}
                className="flex min-w-0 flex-1 items-center gap-2.5 text-left"
              >
                <span className="min-w-0 break-words font-semibold text-text-2">
                  Started {started.length} re-hunt{started.length !== 1 ? 's' : ''}
                  {skipped.length > 0 ? ` · ${skipped.length} skipped` : ''}
                </span>
                {total > 0 && (
                  <span className="flex flex-none items-center gap-1 text-[11.5px] text-dim">
                    {rehuntExpanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                    {rehuntExpanded ? 'Hide detail' : 'Show detail'}
                  </span>
                )}
              </button>
              <button
                onClick={() => { setRehuntResult(null); setRehuntExpanded(false); }}
                className="flex flex-none text-dim hover:text-text"
                aria-label="Dismiss"
              >
                <X size={14} />
              </button>
            </div>
            {rehuntExpanded && total > 0 && (
              <div className="border-t border-border-faint px-3.5 py-2 text-[12.5px]">
                {started.map((s) => (
                  <div key={s.old_id} className="flex items-center gap-2 py-[3px]">
                    <Check size={12} className="flex-none text-success" />
                    <span
                      data-testid={`rehunt-objective-${s.new_id}`}
                      className="min-w-0 break-words text-text-2"
                      title={s.objective}
                    >
                      {s.objective}
                    </span>
                    <span className="flex-none text-faint">→ new hunt</span>
                  </div>
                ))}
                {skipped.map((s) => (
                  <div key={s.id} className="flex items-center gap-2 py-[3px]">
                    <X size={12} className="flex-none text-faint" />
                    <span className="min-w-0 break-words text-dim">{s.id}</span>
                    <span className="flex-none text-faint">{rehuntSkipReason(s.reason)}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })()}

      {/* hunts list */}
      {failCount >= 2 && (
        <StaleNotice
          since={lastUpdated}
          onRefresh={() => setReloadKey((k) => k + 1)}
          className="mb-3"
        />
      )}
      <GridGapStrip range={range} custom={custom} className="mb-3" />
      <Panel>
        <div className="overflow-x-auto">
        <div
          className="grid items-center gap-2.5 border-b border-border px-4 py-2.5 text-[11px] font-semibold uppercase tracking-[.04em] text-dim"
          style={{ gridTemplateColumns: GRID, minWidth: GRID_MIN_WIDTH }}
        >
          <div className="flex items-center" onClick={(e) => e.stopPropagation()}>
            <Checkbox
              checked={sel.allVisibleSelected}
              indeterminate={!sel.allVisibleSelected && sel.someVisibleSelected}
              onChange={sel.toggleAll}
              title="Select all"
            />
          </div>
          <div>Objective</div>
          <div>Started by</div>
          <div>Findings</div>
          <div>Hosts</div>
          <div>Status</div>
          <div>Started</div>
          <TagsHeader />
          <div />
        </div>

        {loading && !data ? (
          <LoadingState label="Loading hunts" />
        ) : error ? (
          <ErrorState error={error} onRetry={() => setReloadKey((k) => k + 1)} />
        ) : !data || visible.length === 0 ? (
          kind !== 'all' ? (
            // The server answered the kind chip with nothing, so this is true
            // of the whole window, not of a capped page. Name the kind, then
            // point at the window: the chip is the question the analyst just
            // asked, and "pick another kind" tells them to drop it, while the
            // hunts they want may sit a week outside the 24h default (five
            // manual hunts four weeks back, in the dogfood that found this).
            // The unwindowed stats cannot say whether widening will find any,
            // so the copy names the control that could, not a promise.
            <EmptyState>
              No {KIND_CHIPS.find((c) => c.id === kind)?.empty} in this window. Widen the time
              range above.
            </EmptyState>
          ) : huntsExist ? (
            // A lead that holds a hunt is the route to a hunt this window does
            // not reach. The page read "0 hunts" under three leads that each
            // offered Read hunt, and the empty state named neither of them.
            leadsHoldHunts ? (
              <EmptyState>
                No hunts in {windowWords(range)}. The leads above link to older hunts.
              </EmptyState>
            ) : (
              <EmptyState>No hunts in this window. Widen the time range above.</EmptyState>
            )
          ) : (
            <EmptyState
              title="No hunts yet"
              action={
                <button
                  onClick={() => setNewHunt(true)}
                  className="flex items-center gap-1.5 rounded-control border border-accent bg-accent/10 px-3.5 py-1.5 text-[12.5px] font-semibold text-accent hover:bg-accent/20"
                >
                  <Plus size={12} /> Describe a hunt
                </button>
              }
            >
              A hunt answers a question about the whole network. Select New hunt and describe it.
              Example: &ldquo;look for hosts beaconing to rare external IPs&rdquo;.
            </EmptyState>
          )
        ) : (
          visible.map((h) => (
            <div
              key={h.id}
              className="group grid w-full items-center gap-2.5 border-b border-border px-4 py-3 text-left last:border-0 hover:bg-surface-2"
              style={{ gridTemplateColumns: GRID, minWidth: GRID_MIN_WIDTH }}
            >
              <div className="flex items-center" onClick={() => sel.toggle(h.id)}>
                <Checkbox checked={sel.isSelected(h.id)} title="Select" />
              </div>
              {/* The objective is the link, and it is the only link to the
                  hunt in the row. No row is clickable as a whole: the whole
                  row navigated, so the word that names the hunt was the one
                  word an analyst could not copy or open in a tab. The lead a
                  hunt came from is reached from the Started by cell.
                  The whole objective shows and wraps in its cell. One
                  truncated line read "Hunt for hosts b" and hid the hunt,
                  and a two-line clamp hid the rest (owner, 2026-10-07). The
                  chips sit in the tags column, so every objective starts at
                  the same x. */}
              <div data-testid="hunt-title-cell" className="flex min-w-0 items-start gap-2">
                <Crosshair size={14} className="mt-[2px] flex-none text-accent" />
                <Link
                  to={`/hunts/${h.id}`}
                  data-testid="hunt-row-objective"
                  className="min-w-0 whitespace-normal break-words text-[13px] leading-[1.4] text-accent hover:underline"
                  title={h.objective}
                >
                  {rowTitle(h)}
                </Link>
              </div>
              <div className="min-w-0 break-words text-[12px] text-dim" title="Who or what started this hunt.">
                {starterText(h)}
              </div>
              <div className="text-[13px] tabular-nums text-text-2" title={findingsCellTitle(h)}>
                {findingsCellText(h)}
              </div>
              <div className="text-[13px] tabular-nums text-text-2">{h.affectedHosts}</div>
              <div>
                <StatusDot status={h.status} outcome={h.outcome} outcomeLabel={h.outcome_label} />
              </div>
              <div className="text-[12px] text-dim" title={h.ts}>{h.when}</div>
              {/* The tags, in the one order of every list. Scheduled and
                  catalog-recorded hunts carry a kind chip. A manual hunt is
                  the default and carries none. The synthetic mark keeps a
                  planted attack from reading as real activity. */}
              <RowTags
                testId={`hunt-tags-${h.id}`}
                huntKind={h.kind}
                synthetic={h.isSynthEval}
                chatCount={h.chatCount}
              />
              <div className="flex items-center justify-end gap-2">
                {/* Re-hunt: a clean re-run of this objective as a fresh hunt.
                    Nothing to re-run while still running. Prominent (always
                    visible, accent) on error/interrupted rows — the ones that
                    need it; a quiet hover-reveal on a completed row. */}
                {h.status !== 'running' && (
                  <button
                    onClick={() => rehuntOne(h)}
                    disabled={rehuntingId === h.id}
                    title="Re-run this objective as a fresh hunt"
                    className={
                      h.status === 'error' || h.status === 'interrupted'
                        ? 'flex text-accent transition-opacity hover:opacity-80 disabled:opacity-50'
                        : 'flex text-faint opacity-0 transition-opacity hover:text-accent group-hover:opacity-100 disabled:opacity-50'
                    }
                  >
                    {rehuntingId === h.id ? (
                      <Loader2 size={13} className="animate-spin" />
                    ) : (
                      <RotateCw size={13} />
                    )}
                  </button>
                )}
                {pendingDelete === h.id ? (
                  <div className="flex items-center gap-1.5">
                    <button
                      onClick={() => { void deleteOne(h.id); }}
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
                    onClick={() => { setPendingDelete(h.id); setDeleteMsg(null); }}
                    title="Delete hunt"
                    className="flex text-faint opacity-0 transition-opacity hover:text-danger group-hover:opacity-100"
                  >
                    <Trash2 size={13} />
                  </button>
                )}
              </div>
            </div>
          ))
        )}
        </div>
      </Panel>
      {/* The counts above state the window. The table holds the newest page
          of it, so the line says how much of the window the table shows. */}
      {scopedTotals && data && scopedTotals.hunts > visible.length && (
        <div data-testid="hunts-page-note" className="mt-1.5 text-[12px] text-dim">
          The table shows the {visible.length} newest of {scopedTotals.hunts} hunts in this window.
        </div>
      )}
        </div>
      )}

      {/* recurring/scheduled hunts */}
      <ScheduledHunts />

      {/* Mounted only while it is open. `Drawer` registers with the modal
          stack before it renders. */}
      {newHunt && (
        <NewHuntDrawer onClose={() => setNewHunt(false)} initialObjective={newObjective} />
      )}
        </>
      )}

      {/* The chart sits outside the tabs: both tabs carry the link. */}
      {flow && <HowThisFlowsDrawer open onClose={() => setFlow(false)} />}
    </div>
  );
}
