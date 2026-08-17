import {
  AlertTriangle,
  CalendarClock,
  Check,
  ChevronDown,
  ChevronRight,
  Crosshair,
  Loader2,
  MessageSquare,
  Pencil,
  Plus,
  RefreshCw,
  RotateCw,
  Sparkles,
  Trash2,
  X,
} from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Checkbox } from '../components/Controls';
import { ListToolbar } from '../components/ListToolbar';
import { useListSelection } from '../lib/useListSelection';
import { useSavedViews } from '../lib/useSavedViews';
import { Panel } from '../components/Panel';
import { EmptyState, ErrorState, Freshness, LoadingState, StaleNotice } from '../components/States';
import { TimeRangeFilter, type CustomRange } from '../components/TimeRangeFilter';
import { demoBlocked, useDemo } from '../lib/demo';
import { rangeToSinceUntil } from '../lib/timeRange';
import {
  MAX_OBJECTIVE_CHARS,
  bulkDeleteHunts,
  createHuntSchedule,
  createHuntTemplate,
  deleteHunt,
  deleteHuntSchedule,
  deleteHuntTemplate,
  getHunts,
  getHuntSchedules,
  getHuntStats,
  getHuntTemplates,
  rehuntHunts,
  startHuntConsole,
  updateHuntSchedule,
} from '../lib/api';
import type { HuntSchedule, HuntScheduleList, HuntTemplate } from '../lib/api';
import { HUNT_STATUS } from '../lib/statusMeta';
import { useAsync } from '../lib/useAsync';
import type { HuntRehuntResult, HuntRow, HuntStat, HuntStatus, SavedViewQuery } from '../lib/types';

// The backend floors a schedule's interval at 60 minutes (MIN_INTERVAL_MINUTES);
// mirror that here so the picker can't offer an interval the API would clamp.
const MIN_INTERVAL_MINUTES = 60;

// ---------------------------------------------------------------------------
// Hunt Console — describe a hunt in plain language; the agent correlates across
// hosts/time and lands findings + a narrative (a HuntReport). Read-only. The
// list + stats are real (/api/v1/hunts*), starting a hunt spawns a background
// run and navigates to its live detail.
// ---------------------------------------------------------------------------

// 28px checkbox · objective · findings · hosts · status · started · actions
// (re-hunt + delete). The actions gutter grew from 44px to fit two icon buttons.
const GRID = '28px 1fr 120px 110px 110px 130px 72px';

// The window this screen lands on, and the one a saved view that names no
// window restores. Named so the two cannot drift apart.
const DEFAULT_RANGE = '24h';

// Raw rehunt skip-reason codes (routes_hunts.py::bulk_rehunt) → friendly text.
// Unknown codes fall through to the raw code so a new backend reason is never
// silently swallowed (mirrors Investigations' rehuntSkipReason).
const REHUNT_SKIP_REASONS: Record<string, string> = {
  not_found: 'not found',
  running: 'still running',
  queued: 'queued — re-hunt in a smaller batch',
  could_not_start: "couldn't start",
};
const rehuntSkipReason = (code: string): string => REHUNT_SKIP_REASONS[code] ?? code;

// The header's count line reads "7 hunts · 10 findings · 1 in progress" from
// whatever /hunts/stats returns — the labels are the server's, only lowercased
// and de-pluralised at 1 ("1 hunt", never "1 hunts"). Generic on purpose: a new
// stat the backend adds joins the line instead of needing a new card. The `ss`
// guard keeps "In progress" whole; an English noun ending in `ss` is not a
// plural, and that label is a phrase, not a count noun.
const statNoun = (s: HuntStat): string => {
  const plural = s.label.endsWith('s') && !s.label.endsWith('ss');
  const label = s.value === '1' && plural ? s.label.slice(0, -1) : s.label;
  return label.toLowerCase();
};

// Fallback pills — the six canned hunts, used ONLY when the template API is
// unreachable or empty (a fresh store before the builtin seed). Normally the
// picker is fed by GET /hunt-templates (curated + availability-annotated). Kept
// in sync with the backend builtins (soc_ai/store/hunt_templates.py::_BUILTINS).
const FALLBACK_PRESETS: { label: string; objective: string }[] = [
  {
    label: 'Beaconing to rare IPs',
    objective:
      'Hunt for internal hosts beaconing to rare external IPs in the last 24h — regular cadence, low data volume, novel destinations.',
  },
  {
    label: 'Credential abuse / lockouts',
    objective:
      'Hunt for credential-abuse signals: account lockouts, failed-auth spikes, and Kerberoasting on the domain controllers.',
  },
  {
    label: 'Lateral movement',
    objective:
      'Hunt for lateral movement: SMB/admin-share access, PsExec-style service creation, and RDP between internal hosts.',
  },
  {
    label: 'DNS / C2 exfiltration',
    objective:
      'Hunt for DNS tunneling and C2 exfiltration: high-entropy or high-volume DNS, long TXT records, and beaconing over DNS.',
  },
  {
    label: 'New external services',
    objective:
      'Hunt for internal hosts newly exposing or reaching new external services this week that they never used before.',
  },
  {
    label: 'Suspicious PowerShell / LOLBins',
    objective:
      'Hunt for suspicious PowerShell and living-off-the-land binary use across endpoints.',
  },
];

function StatusDot({ status }: { status: HuntStatus }) {
  const m = HUNT_STATUS[status] ?? HUNT_STATUS.error;
  return (
    <span className="flex items-center gap-1.5 text-[12px]" style={{ color: m.color }}>
      <span
        className={`h-1.5 w-1.5 rounded-full${m.pulse ? ' animate-pulse' : ''}`}
        style={{ background: m.color }}
      />
      {m.label}
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
// Template picker — curated hunt starters annotated on TWO independent axes
// (E3.2 + hunt-fit). Fed by GET /hunt-templates: each chip fills the objective
// box (like the old static pills). Three states, three operator actions:
//   · available + applicable → normal accent chip ("the telemetry is here").
//   · missing telemetry (available=false) → amber flag + "missing telemetry:
//     zeek.rdp" — a FIXABLE collection gap.
//   · availability UNKNOWN (availabilityKnown=false — the server could not read
//     the grid inventory, so `available` is a fail-open default and not a
//     measurement) → neutral gray chip, no glyph, one caption for the strip.
//     Deliberately unlike the amber state: "we looked and the telemetry is
//     missing" and "we could not look" are different facts and must not share a
//     colour. What they must NOT share is the accent chip, which asserts the
//     grid is seeing this telemetry — that assertion is how an analyst came to
//     launch a hunt against data a half-read grid could not read.
//   · not applicable (applicable=false — the network shows none of the
//     machinery the hunt targets, e.g. Kerberoasting with no domain) → DEMOTED
//     into a collapsed "Not applicable here" cluster at the end of the strip,
//     grayed, never hidden, still runnable. The server recomputes fit per
//     request from the dossier store, and this picker polls every 60s, so the
//     first observed domain join reopens the hunt on its own.
// Clicking any chip still fills the box (the operator may want to see the
// objective, or knows the data is coming). Falls back to the six static pills
// when the template API is unreachable/empty so the picker never disappears.
// An admin can save a modest custom template inline.
// ---------------------------------------------------------------------------
function TemplatePicker({ onPick }: { onPick: (objective: string) => void }) {
  const [reloadKey, setReloadKey] = useState(0);
  const { data, error } = useAsync<HuntTemplate[]>(getHuntTemplates, [reloadKey], {
    // Amber (missing telemetry) and demotion (environment fit) must clear on
    // their own once the grid or the dossier sweep catches up — the server side
    // is TTL-cached (300s inventory) so a 60s poll is cheap, and worst-case
    // staleness becomes TTL+interval instead of "until the operator reloads".
    refetchInterval: 60_000,
  });
  // The not-applicable cluster's expand state (collapsed by default — demoted,
  // not hidden).
  const [showDemoted, setShowDemoted] = useState(false);

  // Inline "add custom template" form (collapsed by default — modest, like the
  // schedule editor). builtin templates are code-owned; customs are operator-saved.
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState('');
  const [objective, setObjective] = useState('');
  const [datasets, setDatasets] = useState('');
  const [busy, setBusy] = useState(false);
  const [formErr, setFormErr] = useState<string | null>(null);

  const resetForm = () => {
    setName('');
    setObjective('');
    setDatasets('');
    setFormErr(null);
    setAdding(false);
  };

  const saveCustom = async () => {
    const nm = name.trim();
    const obj = objective.trim();
    if (!nm || !obj || busy) return;
    const required = datasets
      .split(',')
      .map((d) => d.trim())
      .filter(Boolean);
    setBusy(true);
    setFormErr(null);
    try {
      await createHuntTemplate({ name: nm, objective_template: obj, required_datasets: required });
      resetForm();
      setReloadKey((k) => k + 1);
    } catch (e: unknown) {
      setFormErr(e instanceof Error ? e.message : 'Could not save the template.');
    } finally {
      setBusy(false);
    }
  };

  const removeCustom = async (id: number) => {
    try {
      await deleteHuntTemplate(id);
    } catch {
      /* 409 on a builtin / admin-gated / transient — the next load reflects reality */
    }
    setReloadKey((k) => k + 1);
  };

  // Fallback to the static pills when the template API is unreachable or the
  // store is empty (fresh install, pre-seed) — the picker must never vanish.
  const templates = data ?? [];
  const useFallback = !!error || templates.length === 0;

  // `!== false` rather than a truthiness check is the fail-open half: the field
  // is optional on HuntTemplate, so a payload from a server predating it reads
  // as "known", which is what it was.
  const availabilityKnown = (t: HuntTemplate): boolean => t.availabilityKnown !== false;
  // One unreadable inventory annotates the whole strip — the server evaluates
  // the axis once for the list, so this is never mixed.
  const fitUnknown = !useFallback && templates.some((t) => !availabilityKnown(t));

  // The two-axis split: applicable chips render inline (normal or amber);
  // not-applicable ones cluster at the end, collapsed. `!== false` keeps a
  // payload without the field (older server) on the inline path — fail open.
  const applicableTemplates = templates.filter((t) => t.applicable !== false);
  const demoted = templates.filter((t) => t.applicable === false);

  const demotedTitle = (t: HuntTemplate): string => {
    const needs = t.missingEnvironment.length
      ? t.missingEnvironment.join(' and ')
      : 'machinery this network has not shown';
    return (
      `${t.objectiveTemplate}\n\nNeeds ${needs} — none observed on this network. ` +
      'Re-checked after every dossier sweep. Still runnable.'
    );
  };

  return (
    <div className="mb-2">
      <div className="flex flex-wrap items-center gap-1.5">
        {/* Names the row the way the toolbar's "Views" label names its own —
            the compact composer dropped the "New hunt" heading that used to
            introduce these chips. */}
        <span className="mr-0.5 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
          Starters
        </span>
        {useFallback
          ? FALLBACK_PRESETS.map((p) => (
              <button
                key={p.label}
                type="button"
                onClick={() => onPick(p.objective)}
                title={p.objective}
                className="rounded-badge border border-border-strong bg-surface-2 px-[9px] py-[3px] text-[11.5px] font-medium text-dim transition-colors hover:border-accent hover:text-accent"
              >
                {p.label}
              </button>
            ))
          : applicableTemplates.map((t) => {
              // Three states, and `unknown` is checked FIRST: when the server
              // could not read the inventory it reports every template
              // available, so asking `!t.available` alone can only ever produce
              // the confident answer.
              const unknown = !availabilityKnown(t);
              const flagged = !unknown && !t.available;
              const missing = t.missingDatasets.join(', ');
              const title = unknown
                ? `${t.objectiveTemplate}\n\nAvailability unknown — the grid inventory could not be read, so this template has not been checked against live telemetry.`
                : flagged
                  ? `${t.objectiveTemplate}\n\n⚠ missing telemetry: ${missing}`
                  : t.objectiveTemplate;
              return (
                <span key={t.id} className="inline-flex items-center">
                  <button
                    type="button"
                    onClick={() => onPick(t.objectiveTemplate)}
                    title={title}
                    // The state is in the DOM, not only in a class name: it is
                    // the contract the picker is tested against, and "no chip
                    // claims availability" is otherwise an assertion about
                    // Tailwind strings.
                    data-availability={unknown ? 'unknown' : flagged ? 'missing' : 'available'}
                    className={
                      unknown
                        ? 'flex items-center gap-1 rounded-badge border border-border-strong bg-surface-2 px-[9px] py-[3px] text-[11.5px] font-medium text-dim transition-colors hover:border-accent hover:text-accent'
                        : flagged
                          ? 'flex items-center gap-1 rounded-badge border border-warn/40 bg-warn/5 px-[9px] py-[3px] text-[11.5px] font-medium text-warn/80 opacity-70 transition-opacity hover:opacity-100'
                          : 'flex items-center gap-1 rounded-badge border border-accent/40 bg-accent/5 px-[9px] py-[3px] text-[11.5px] font-medium text-accent transition-colors hover:border-accent hover:bg-accent/10'
                    }
                  >
                    {flagged && <AlertTriangle size={11} className="flex-none" />}
                    {t.name}
                  </button>
                  {!t.builtin && (
                    <button
                      type="button"
                      onClick={() => { void removeCustom(t.id); }}
                      title="Delete custom template"
                      className="ml-0.5 flex text-faint hover:text-danger"
                    >
                      <X size={11} />
                    </button>
                  )}
                </span>
              );
            })}
        {/* Not-applicable cluster — demoted, never hidden. Grayed (muted
            border/text, no warn color: nothing here is broken or fixable, the
            network just hasn't shown the machinery), each chip still fills the
            objective box exactly like an inline one. */}
        {!useFallback && demoted.length > 0 && (
          <button
            type="button"
            onClick={() => setShowDemoted((v) => !v)}
            title="Hunts whose target machinery hasn't been observed on this network — demoted, not hidden. Re-checked after every dossier sweep; each is still runnable."
            className="flex items-center gap-1 rounded-badge border border-dashed border-border-strong bg-transparent px-[9px] py-[3px] text-[11px] font-medium text-faint transition-colors hover:text-dim"
          >
            {showDemoted ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
            Not applicable here · {demoted.length}
          </button>
        )}
        {!useFallback &&
          showDemoted &&
          demoted.map((t) => (
            <span key={t.id} className="inline-flex items-center">
              <button
                type="button"
                onClick={() => onPick(t.objectiveTemplate)}
                title={demotedTitle(t)}
                className="flex items-center gap-1 rounded-badge border border-border bg-surface-2 px-[9px] py-[3px] text-[11.5px] font-medium text-faint opacity-70 transition-opacity hover:opacity-100"
              >
                {t.name}
              </button>
            </span>
          ))}
        {/* add-custom toggle */}
        <button
          type="button"
          onClick={() => setAdding((v) => !v)}
          title="Save a custom hunt template"
          className="flex items-center gap-1 rounded-badge border border-dashed border-border-strong bg-transparent px-[9px] py-[3px] text-[11.5px] font-medium text-faint transition-colors hover:border-accent hover:text-accent"
        >
          <Plus size={11} /> Template
        </button>
      </div>

      {/* legend — only when at least one INLINE template is unavailable
          (nothing to contrast otherwise; the collapsed cluster explains
          itself). Positive framing: the highlighted ones are the runnable
          ones; the AlertTriangle stays on the unavailable chips only. It is
          gated on `!fitUnknown` because the claim it makes ("these match live
          telemetry") is exactly the one an unread inventory cannot support. */}
      {!useFallback && !fitUnknown && applicableTemplates.some((t) => !t.available) && (
        <div className="mt-1.5 text-[10.5px] text-accent/80">
          highlighted templates match telemetry this grid is seeing.
        </div>
      )}

      {/* The template list LOADED, but the server could not read the grid
          inventory to annotate it — the half-read-grid case, where every chip
          came back available because that is what fail-open means. Say the axis
          is unevaluated rather than let six confident chips imply it passed. */}
      {fitUnknown && (
        <div className="mt-1.5 text-[10.5px] text-faint">
          availability unknown — the grid inventory could not be read, so these templates are
          unchecked against live telemetry.
        </div>
      )}

      {/* Fallback pills carry NO annotation (neither axis is knowable without
          the template service) — say so once, muted, instead of per-pill. */}
      {useFallback && !!error && (
        <div className="mt-1.5 text-[10.5px] text-faint">
          availability unknown while the template service is unreachable.
        </div>
      )}

      {/* inline custom-template form */}
      {adding && (
        <div className="mt-2 flex flex-wrap items-center gap-2 rounded-control border border-border bg-surface-2 px-3 py-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Template name"
            className="min-w-[140px] flex-none rounded-control border border-border-input bg-bg px-2.5 py-1.5 text-[12px] text-text outline-none focus:border-accent"
          />
          <input
            value={objective}
            onChange={(e) => setObjective(e.target.value)}
            placeholder="Objective the chip loads…"
            className="min-w-[220px] flex-1 rounded-control border border-border-input bg-bg px-2.5 py-1.5 text-[12px] text-text outline-none focus:border-accent"
          />
          <input
            value={datasets}
            onChange={(e) => setDatasets(e.target.value)}
            placeholder="required datasets (comma-sep, e.g. zeek.dns)"
            className="min-w-[180px] flex-none rounded-control border border-border-input bg-bg px-2.5 py-1.5 text-[12px] text-text outline-none focus:border-accent"
          />
          <button
            type="button"
            onClick={() => { void saveCustom(); }}
            disabled={!name.trim() || !objective.trim() || busy}
            className="flex items-center gap-1 rounded-control bg-accent px-3 py-1.5 text-[12px] font-semibold text-white hover:bg-accent-deep disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? <Loader2 size={12} className="animate-spin" /> : <Check size={12} />} Save
          </button>
          <button
            type="button"
            onClick={resetForm}
            className="rounded-control border border-border-strong bg-bg px-3 py-1.5 text-[12px] font-semibold text-dim hover:text-text"
          >
            Cancel
          </button>
          {formErr && <div className="w-full text-[11.5px] text-danger">{formErr}</div>}
        </div>
      )}
    </div>
  );
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

  const toggleEnabled = async (s: HuntSchedule) => {
    const blocked = demoBlocked(demo);
    if (blocked) { setFormErr(blocked); return; } // demo: no doomed write
    try {
      await updateHuntSchedule(s.id, { enabled: !s.enabled });
      reload();
    } catch {
      /* transient — the next poll reflects reality */
    }
  };

  const removeOne = async (id: number) => {
    const blocked = demoBlocked(demo);
    if (blocked) { setFormErr(blocked); setPendingDelete(null); return; } // demo: no doomed write
    try {
      await deleteHuntSchedule(id);
    } catch {
      /* admin-gated / transient */
    }
    setPendingDelete(null);
    if (editing === id) resetForm();
    reload();
  };

  return (
    <Panel className="mt-5">
      <div className="flex items-center gap-1.5 border-b border-border px-4 py-3 text-[13px] font-semibold">
        <CalendarClock size={15} className="text-accent" /> Scheduled hunts
        <span className="ml-2 text-[11.5px] font-normal text-dim">
          Recurring hunts on an interval.
        </span>
      </div>

      {/* The banner's CTA deep-links to a Config toggle that is itself demo-
          guarded — a dead-end in the read-only demo — so suppress it in demo mode
          ONLY. The "on (paused)" pills below still render (that IS the 1.2.4
          feature); only this banner is hidden. Live behavior is unchanged. */}
      {data && !masterSwitchOn && !demo && (
        <div className="flex items-center gap-2 border-b border-warn/25 bg-warn/5 px-4 py-2.5 text-[12px] text-warn">
          <AlertTriangle size={14} className="flex-none" />
          <span>
            Scheduled hunts are paused globally —{' '}
            <button
              type="button"
              onClick={() => navigate('/config#triage-automation')}
              className="font-semibold underline decoration-warn/50 underline-offset-2 hover:decoration-warn"
            >
              enable them in Config
            </button>
            . Rows below still show their own on/off state, but nothing fires until the
            switch is on.
          </span>
        </div>
      )}

      {loading && !data ? (
        <LoadingState label="Loading schedules…" />
      ) : error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : (
        <>
          {!schedules || schedules.length === 0 ? (
            <EmptyState>No scheduled hunts yet — add one below.</EmptyState>
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
                      ? 'Paused — click to enable'
                      : masterSwitchOn
                        ? 'Enabled — click to pause'
                        : 'Enabled, but paused by the global master switch (Config) — it will not fire'
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
                  <div className="truncate text-[13px] text-text">{s.objective}</div>
                  <div className="mt-0.5 text-[11.5px] text-faint">
                    every {intervalLabel(s.intervalMinutes)}
                    {s.lastRunAt
                      ? ` · last ran ${new Date(s.lastRunAt).toLocaleString()}`
                      : ' · never run'}
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
                editing !== null ? 'Edit the hunt objective…' : 'New recurring hunt objective…'
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
    </Panel>
  );
}

export function Hunts() {
  const navigate = useNavigate();
  const [reloadKey, setReloadKey] = useState(0);
  const [objective, setObjective] = useState('');
  // The empty state's CTA puts the cursor where a hunt is actually written.
  const objectiveRef = useRef<HTMLTextAreaElement | null>(null);
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  // The composer is one row at rest and a four-row brief box while it is in use
  // — focused, or already holding an objective (a template chip fills it, so a
  // 1-click starter opens the box too). Never collapses text out of sight.
  const [composerFocused, setComposerFocused] = useState(false);
  const composerOpen = composerFocused || objective.length > 0;
  // Collapsing has to drop any height the analyst DRAGGED onto the box as well
  // as the row count. The grip writes an inline height, and an inline height
  // beats `rows` — so one drag would pin the composer tall for the life of the
  // page, putting the toolbar lower than it sat before this screen was fixed.
  useEffect(() => {
    if (!composerOpen && objectiveRef.current) objectiveRef.current.style.height = '';
  }, [composerOpen]);
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

  // Time filter — same pattern as Alerts/Investigations: a preset (default 24h)
  // or a custom from/to, held in plain component state. Unlike those screens the
  // range feeds the FETCH (GET /hunts?since=&until= — server-side filtering);
  // bounds are recomputed inside the loader so every 8s poll re-anchors "now".
  const [range, setRange] = useState(DEFAULT_RANGE);
  const [custom, setCustom] = useState<CustomRange | null>(null);

  // useAsync captures pauseWhen at setup and can't see `data` there, so track
  // whether any hunt is still running in a ref and let pauseWhen (on both polls)
  // consult it: stop polling once every hunt has reached a terminal state.
  const activeRef = useRef(false);
  const { data, loading, error, lastUpdated, failCount } = useAsync<HuntRow[]>(
    () => getHunts(rangeToSinceUntil(range, custom)),
    [reloadKey, range, custom],
    {
      refetchInterval: 8000, // live status (running → complete) without a reload
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
        e instanceof Error ? e.message : 'Delete failed — cancel the running hunt first.',
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

  // Selection: the shared hook, independent of the time filter (`range` /
  // `custom` feed the fetch, not the selection).
  const rows = data ?? [];
  const sel = useListSelection(rows.map((h) => h.id));
  const selCount = sel.count;

  // Saved views for the hunt list. Its only facet is the window, so a view here
  // is "the window I keep coming back to" — which is exactly the one an analyst
  // re-picks every morning.
  const savedQuery: SavedViewQuery = { range, custom };
  // A TOTAL apply: a view that names no window restores THIS screen's default
  // one. That is also what makes the chip a real toggle — clicking an active
  // chip applies the empty query, which is this screen unfiltered.
  const views = useSavedViews('hunts', savedQuery, (saved) => {
    setRange(typeof saved.range === 'string' ? saved.range : DEFAULT_RANGE);
    setCustom((saved.custom as CustomRange | null) ?? null);
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
          (nf ? ` · ${nf} skipped (missing or still running — cancel it first)` : ''),
      );
    } catch (err) {
      setBulkMsg(`Delete failed: ${err instanceof Error ? err.message : String(err)}`);
    }
    sel.clear();
    setConfirmDelete(false);
    setBulkDeleting(false);
    setReloadKey((k) => k + 1);
  };

  const launch = () => {
    const obj = objective.trim();
    if (!obj || starting) return;
    setStarting(true);
    setStartError(null);
    startHuntConsole(obj)
      .then((r) => {
        setObjective('');
        navigate(`/hunts/${r.hunt_id}`);
      })
      .catch((e: unknown) => {
        setStartError(e instanceof Error ? e.message : 'Could not start the hunt.');
      })
      .finally(() => setStarting(false));
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
          {(stats.data ?? []).map((s, i) => (
            <span key={s.label} title={s.sub}>
              {i > 0 && ' · '}
              <span className="tabular-nums">{s.value}</span> {statNoun(s)}
            </span>
          ))}
        </div>
      </div>

      {/* New hunt — this screen's primary action, so it stays at the top and
          keeps its 1-click template chips. It is COMPACT until used: one row of
          input, growing to a full brief the moment the box has focus or text.
          That is what lets the list section below start where the other three
          screens start it. */}
      <Panel className="mb-4 p-3">
        {/* Curated hunt templates — click a chip to load a high-payoff objective,
            then tweak the scope and launch. Templates the grid can run are
            highlighted; one needing telemetry this grid lacks stays muted +
            flagged (not hidden). */}
        <TemplatePicker
          onPick={(obj) => {
            setObjective(obj);
            setStartError(null);
          }}
        />
        <div className="flex items-start gap-2">
          <div className="relative flex-1">
            <Sparkles
              size={15}
              className="pointer-events-none absolute left-[11px] top-[10px] text-accent"
            />
            <textarea
              ref={objectiveRef}
              value={objective}
              onChange={(e) => setObjective(e.target.value)}
              onFocus={() => setComposerFocused(true)}
              onBlur={() => setComposerFocused(false)}
              onKeyDown={(e) => {
                // Enter submits, Shift+Enter newlines — a multi-line brief needs
                // a way to break lines without launching (dogfood 2026-08-06).
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  launch();
                }
              }}
              rows={composerOpen ? 4 : 1}
              maxLength={MAX_OBJECTIVE_CHARS}
              placeholder="Describe a hunt in plain language — e.g. hunt for beaconing to rare external IPs, or credential-abuse lockouts on the DCs"
              className={`w-full overflow-y-auto rounded-control border border-border-input bg-bg py-2 pl-9 pr-3 text-[13px] leading-[20px] text-text outline-none focus:border-accent ${
                // A grip on a one-row box is an invitation to break the compact
                // rest state; it belongs on the open brief box, where dragging a
                // long objective taller is the point.
                composerOpen ? 'resize-y' : 'resize-none'
              }`}
            />
          </div>
          <button
            onClick={launch}
            disabled={!objective.trim() || starting}
            className="flex flex-none items-center gap-1.5 rounded-control bg-accent px-[15px] py-2 text-[13px] font-semibold text-white hover:bg-accent-deep disabled:cursor-not-allowed disabled:opacity-50"
          >
            {starting ? <Loader2 size={15} className="animate-spin" /> : <Plus size={15} />}
            {starting ? 'Starting…' : 'Start hunt'}
          </button>
        </div>
        {/* The brief-writing hints the old 4-row placeholder carried. Shown only
            while the box is open, where they are actually actionable. */}
        {composerOpen && (
          <div className="mt-1.5 text-[11px] text-faint">
            The agent correlates across hosts &amp; time and reports findings + a narrative.
            Read-only. Shift+Enter for a new line — a detailed brief (scope, exclusions, specific
            behaviors) gets a better hunt.
          </div>
        )}
        {objective.length > MAX_OBJECTIVE_CHARS * 0.8 && (
          <div className="mt-1 text-right text-[11px] text-faint">
            {objective.length.toLocaleString()} / {MAX_OBJECTIVE_CHARS.toLocaleString()} characters
          </div>
        )}
        {startError && <div className="mt-2 text-[12px] text-danger">{startError}</div>}
        {deleteMsg && <div className="mt-2 text-[12px] text-danger">{deleteMsg}</div>}
      </Panel>

      {/* The shared list toolbar — same placement as the other lists: directly
          above the table. The stat cards above stay UNFILTERED, mirroring the
          Investigations header counts (which ignore its time filter). */}
      <ListToolbar
        views={views.views}
        activeViewId={views.activeViewId}
        onApplyView={views.onApplyView}
        onDeleteView={views.onDeleteView}
        onSaveView={views.onSaveView}
        viewError={views.error}
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
                title="Re-run the selected objectives as fresh hunts (throttled — starts a few, queues the rest)"
                className="flex items-center gap-1.5 rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold text-[#cfe0ff] disabled:opacity-50"
                style={{ background: 'rgba(75,139,245,.14)', borderColor: 'rgba(75,139,245,.4)' }}
              >
                <RefreshCw size={12} className={rehunting ? 'animate-spin' : ''} />
                {rehunting ? 'Starting…' : `Re-hunt selected (${selCount})`}
              </button>
              {confirmDelete ? (
                <>
                  <button
                    disabled={bulkDeleting}
                    onClick={() => { void handleBulkDelete(); }}
                    className="flex items-center gap-1.5 rounded-[7px] border border-danger px-[11px] py-1.5 text-[12.5px] font-semibold text-danger disabled:opacity-50"
                  >
                    <Trash2 size={12} />
                    {bulkDeleting ? 'Deleting…' : `Confirm delete (${selCount})`}
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
                  title="Delete the selected hunts (admin)"
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
                <span className="min-w-0 truncate font-semibold text-text-2">
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
                    <span className="min-w-0 truncate text-text-2">{s.objective}</span>
                    <span className="flex-none text-faint">→ new hunt</span>
                  </div>
                ))}
                {skipped.map((s) => (
                  <div key={s.id} className="flex items-center gap-2 py-[3px]">
                    <X size={12} className="flex-none text-faint" />
                    <span className="min-w-0 truncate text-dim">{s.id}</span>
                    <span className="flex-none text-faint">— {rehuntSkipReason(s.reason)}</span>
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
      <Panel>
        <div
          className="grid items-center gap-3 border-b border-border px-4 py-2.5 text-[11px] font-semibold uppercase tracking-[.04em] text-dim"
          style={{ gridTemplateColumns: GRID }}
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
          <div>Findings</div>
          <div>Hosts</div>
          <div>Status</div>
          <div>Started</div>
          <div />
        </div>

        {loading && !data ? (
          <LoadingState label="Loading hunts…" />
        ) : error ? (
          <ErrorState error={error} onRetry={() => setReloadKey((k) => k + 1)} />
        ) : !data || data.length === 0 ? (
          huntsExist ? (
            <EmptyState>No hunts in this window — widen the time range above.</EmptyState>
          ) : (
            <EmptyState
              title="No hunts yet"
              action={
                <button
                  onClick={() => objectiveRef.current?.focus()}
                  className="flex items-center gap-1.5 rounded-control border border-accent bg-accent/10 px-3.5 py-1.5 text-[12.5px] font-semibold text-accent hover:bg-accent/20"
                >
                  <Plus size={12} /> Describe a hunt
                </button>
              }
            >
              A hunt is a question you ask of the whole network rather than of one alert.
              Describe it in the box above — try &ldquo;look for hosts beaconing to rare external
              IPs&rdquo;.
            </EmptyState>
          )
        ) : (
          data.map((h) => (
            <div
              key={h.id}
              onClick={() => navigate(`/hunts/${h.id}`)}
              className="group grid w-full cursor-pointer items-center gap-3 border-b border-border px-4 py-3 text-left last:border-0 hover:bg-surface-2"
              style={{ gridTemplateColumns: GRID }}
            >
              <div
                className="flex items-center"
                onClick={(e) => {
                  e.stopPropagation();
                  sel.toggle(h.id);
                }}
              >
                <Checkbox checked={sel.isSelected(h.id)} title="Select" />
              </div>
              <div className="flex items-center gap-2 truncate">
                <Crosshair size={14} className="flex-none text-accent" />
                <span className="truncate text-[13px] text-text">{h.objective}</span>
                {(h.chatCount ?? 0) > 0 && (
                  <span
                    className="flex flex-none items-center gap-[4px] rounded-badge border border-border-2 bg-surface-2 px-[6px] py-[2px] font-mono text-[10.5px] text-accent"
                    title={`${h.chatCount} chat message${h.chatCount === 1 ? '' : 's'}`}
                  >
                    <MessageSquare size={10} />
                    {h.chatCount}
                  </span>
                )}
              </div>
              <div className="text-[13px] tabular-nums text-text-2">{h.findingCount}</div>
              <div className="text-[13px] tabular-nums text-text-2">{h.affectedHosts}</div>
              <div>
                <StatusDot status={h.status} />
              </div>
              <div className="text-[12px] text-dim" title={h.ts}>{h.when}</div>
              <div className="flex items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
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
      </Panel>

      {/* recurring/scheduled hunts */}
      <ScheduledHunts />
    </div>
  );
}
