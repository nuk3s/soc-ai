import {
  AlertTriangle,
  CalendarClock,
  Check,
  Crosshair,
  Loader2,
  MessageSquare,
  Pencil,
  Plus,
  Sparkles,
  Trash2,
  X,
} from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Panel } from '../components/Panel';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { TimeRangeFilter, type CustomRange } from '../components/TimeRangeFilter';
import { rangeToSinceUntil } from '../lib/timeRange';
import {
  createHuntSchedule,
  createHuntTemplate,
  deleteHunt,
  deleteHuntSchedule,
  deleteHuntTemplate,
  getHunts,
  getHuntSchedules,
  getHuntStats,
  getHuntTemplates,
  startHuntConsole,
  updateHuntSchedule,
} from '../lib/api';
import type { HuntSchedule, HuntTemplate } from '../lib/api';
import { HUNT_STATUS } from '../lib/statusMeta';
import { useAsync } from '../lib/useAsync';
import type { HuntRow, HuntStatus } from '../lib/types';

// The backend floors a schedule's interval at 60 minutes (MIN_INTERVAL_MINUTES);
// mirror that here so the picker can't offer an interval the API would clamp.
const MIN_INTERVAL_MINUTES = 60;

// ---------------------------------------------------------------------------
// Hunt Console — describe a hunt in plain language; the agent correlates across
// hosts/time and lands findings + a narrative (a HuntReport). Read-only. The
// list + stats are real (/api/v1/hunts*), starting a hunt spawns a background
// run and navigates to its live detail.
// ---------------------------------------------------------------------------

const GRID = '1fr 120px 110px 110px 130px 44px';

const TONE: Record<string, string> = {
  accent: '#4b8bf5',
  sigma: '#a371f7',
  warn: '#d29922',
  danger: '#f85149',
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
// Template picker — curated, availability-annotated hunt starters (E3.2).
// Fed by GET /hunt-templates: each chip fills the objective box (like the old
// static pills). Templates the grid CAN run are HIGHLIGHTED (accent styling —
// "the telemetry for these is here"); one needing telemetry this grid LACKS
// stays muted + flagged (a warning icon + "missing telemetry: zeek.rdp") rather
// than hidden — honesty over hiding. Clicking it still fills the box (the
// operator may want to see the objective, or knows the data is coming). Falls
// back to the six static pills when the template API is unreachable/empty so
// the picker never disappears. An admin can save a modest custom template inline.
// ---------------------------------------------------------------------------
function TemplatePicker({ onPick }: { onPick: (objective: string) => void }) {
  const [reloadKey, setReloadKey] = useState(0);
  const { data, error } = useAsync<HuntTemplate[]>(getHuntTemplates, [reloadKey]);

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

  return (
    <div className="mb-2.5">
      <div className="flex flex-wrap items-center gap-1.5">
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
          : templates.map((t) => {
              const flagged = !t.available;
              const missing = t.missingDatasets.join(', ');
              const title = flagged
                ? `${t.objectiveTemplate}\n\n⚠ missing telemetry: ${missing}`
                : t.objectiveTemplate;
              return (
                <span key={t.id} className="inline-flex items-center">
                  <button
                    type="button"
                    onClick={() => onPick(t.objectiveTemplate)}
                    title={title}
                    className={
                      flagged
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

      {/* legend — only when at least one template is unavailable (nothing to
          contrast otherwise). Positive framing: the highlighted ones are the
          runnable ones; the AlertTriangle stays on the unavailable chips only. */}
      {!useFallback && templates.some((t) => !t.available) && (
        <div className="mt-1.5 text-[10.5px] text-accent/80">
          highlighted templates match telemetry this grid is seeing.
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
  const [reloadKey, setReloadKey] = useState(0);
  const { data, loading, error } = useAsync<HuntSchedule[]>(getHuntSchedules, [reloadKey]);

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
    try {
      await updateHuntSchedule(s.id, { enabled: !s.enabled });
      reload();
    } catch {
      /* transient — the next poll reflects reality */
    }
  };

  const removeOne = async (id: number) => {
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
          Recurring hunts on an interval — enable the master switch in Config to run them.
        </span>
      </div>

      {loading && !data ? (
        <LoadingState label="Loading schedules…" />
      ) : error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : (
        <>
          {!data || data.length === 0 ? (
            <EmptyState>No scheduled hunts yet — add one below.</EmptyState>
          ) : (
            data.map((s) => (
              <div
                key={s.id}
                className="flex items-center gap-3 border-b border-border px-4 py-3 last:border-0"
              >
                <button
                  type="button"
                  onClick={() => { void toggleEnabled(s); }}
                  title={s.enabled ? 'Enabled — click to pause' : 'Paused — click to enable'}
                  className={`flex-none rounded-badge border px-[8px] py-[2px] text-[10.5px] font-semibold uppercase tracking-[.04em] ${
                    s.enabled
                      ? 'border-accent/40 bg-accent/10 text-accent'
                      : 'border-border-strong bg-surface-2 text-faint'
                  }`}
                >
                  {s.enabled ? 'on' : 'paused'}
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
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  // Per-row delete: a trash icon arms an inline confirm in the row, then deletes
  // just that hunt. A running hunt returns 409 (cancel it first).
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);
  const [deleteMsg, setDeleteMsg] = useState<string | null>(null);

  // Time filter — same pattern as Alerts/Investigations: a preset (default 24h)
  // or a custom from/to, held in plain component state. Unlike those screens the
  // range feeds the FETCH (GET /hunts?since=&until= — server-side filtering);
  // bounds are recomputed inside the loader so every 8s poll re-anchors "now".
  const [range, setRange] = useState('24h');
  const [custom, setCustom] = useState<CustomRange | null>(null);

  // useAsync captures pauseWhen at setup and can't see `data` there, so track
  // whether any hunt is still running in a ref and let pauseWhen (on both polls)
  // consult it: stop polling once every hunt has reached a terminal state.
  const activeRef = useRef(false);
  const { data, loading, error } = useAsync<HuntRow[]>(
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
      {/* page header */}
      <div className="mb-5 flex items-end gap-3">
        <div>
          <div className="flex items-center gap-2">
            <div className="text-[20px] font-semibold tracking-[-.015em]">Hunt Console</div>
          </div>
          <div className="mt-0.5 text-[13px] text-dim">
            Describe a hunt in plain language — the agent correlates across hosts &amp; time and
            reports findings + a narrative. Read-only.
          </div>
        </div>
      </div>

      {/* stat cards */}
      {stats.data && (
        <div className="mb-5 grid grid-cols-3 gap-3">
          {stats.data.map((s) => (
            <Panel key={s.label} className="px-4 py-3">
              <div className="text-[11px] uppercase tracking-[.05em] text-dim">{s.label}</div>
              <div
                className="mt-1 text-[24px] font-semibold tabular-nums"
                style={{ color: TONE[s.tone] ?? '#e6edf3' }}
              >
                {s.value}
              </div>
              <div className="mt-0.5 text-[11px] text-faint">{s.sub}</div>
            </Panel>
          ))}
        </div>
      )}

      {/* new-hunt objective box */}
      <Panel className="mb-5 p-4">
        <div className="mb-2 flex items-center gap-1.5 text-[13px] font-semibold">
          <Sparkles size={15} className="text-accent" /> New hunt
        </div>
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
        <div className="flex items-center gap-2">
          <input
            value={objective}
            onChange={(e) => setObjective(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') launch();
            }}
            placeholder="e.g. hunt for beaconing to rare external IPs, or credential-abuse lockouts on the DCs"
            className="flex-1 rounded-control border border-border-input bg-bg px-3 py-2.5 text-[13px] text-text outline-none focus:border-accent"
          />
          <button
            onClick={launch}
            disabled={!objective.trim() || starting}
            className="flex items-center gap-1.5 rounded-control bg-accent px-[15px] py-2.5 text-[13px] font-semibold text-white hover:bg-accent-deep disabled:cursor-not-allowed disabled:opacity-50"
          >
            {starting ? <Loader2 size={15} className="animate-spin" /> : <Plus size={15} />}
            {starting ? 'Starting…' : 'Start hunt'}
          </button>
        </div>
        {startError && <div className="mt-2 text-[12px] text-danger">{startError}</div>}
        {deleteMsg && <div className="mt-2 text-[12px] text-danger">{deleteMsg}</div>}
      </Panel>

      {/* filter bar — same placement as Alerts/Investigations: directly above
          the list. The stat cards above stay UNFILTERED, mirroring the
          Investigations header counts (which ignore its time filter). */}
      <div className="mb-3.5 flex flex-wrap items-center gap-2">
        <TimeRangeFilter
          value={range}
          custom={custom}
          onChange={(v, r) => {
            setRange(v);
            if (r) setCustom(r);
          }}
        />
      </div>

      {/* hunts list */}
      <Panel>
        <div
          className="grid items-center gap-3 border-b border-border px-4 py-2.5 text-[11px] font-semibold uppercase tracking-[.04em] text-dim"
          style={{ gridTemplateColumns: GRID }}
        >
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
          <EmptyState>
            {huntsExist ? (
              'No hunts in this window — widen the time range above.'
            ) : (
              <>
                No hunts yet. Describe one above — try &ldquo;look for hosts beaconing to rare
                external IPs&rdquo;.
              </>
            )}
          </EmptyState>
        ) : (
          data.map((h) => (
            <div
              key={h.id}
              onClick={() => navigate(`/hunts/${h.id}`)}
              className="group grid w-full cursor-pointer items-center gap-3 border-b border-border px-4 py-3 text-left last:border-0 hover:bg-surface-2"
              style={{ gridTemplateColumns: GRID }}
            >
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
              <div className="text-[12px] text-dim">{h.when}</div>
              <div className="flex justify-end" onClick={(e) => e.stopPropagation()}>
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
