import { Check, Crosshair, Loader2, MessageSquare, Plus, Sparkles, Trash2, X } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Panel } from '../components/Panel';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { deleteHunt, getHunts, getHuntStats, startHuntConsole } from '../lib/api';
import { HUNT_STATUS } from '../lib/statusMeta';
import { useAsync } from '../lib/useAsync';
import type { HuntRow, HuntStatus } from '../lib/types';

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

// Canned hunts — high-payoff, routine SOC hunts one click away. A chip fills the
// objective box (so the analyst can tweak the scope, then launch) rather than
// firing blind; label is the short name, `objective` is the full prompt.
const PRESETS: { label: string; objective: string }[] = [
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

  // useAsync captures pauseWhen at setup and can't see `data` there, so track
  // whether any hunt is still running in a ref and let pauseWhen (on both polls)
  // consult it: stop polling once every hunt has reached a terminal state.
  const activeRef = useRef(false);
  const { data, loading, error } = useAsync<HuntRow[]>(getHunts, [reloadKey], {
    refetchInterval: 8000, // live status (running → complete) without a reload
    pauseWhen: () => !activeRef.current,
  });
  const stats = useAsync(getHuntStats, [reloadKey], {
    refetchInterval: 8000,
    pauseWhen: () => !activeRef.current,
  });
  activeRef.current = (data ?? []).some((h) => h.status === 'running');

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
        {/* Canned hunts — click a chip to load a high-payoff objective, then
            tweak the scope and launch. */}
        <div className="mb-2.5 flex flex-wrap gap-1.5">
          {PRESETS.map((p) => (
            <button
              key={p.label}
              type="button"
              onClick={() => {
                setObjective(p.objective);
                setStartError(null);
              }}
              title={p.objective}
              className="rounded-badge border border-border-strong bg-surface-2 px-[9px] py-[3px] text-[11.5px] font-medium text-dim transition-colors hover:border-accent hover:text-accent"
            >
              {p.label}
            </button>
          ))}
        </div>
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
            No hunts yet. Describe one above — try &ldquo;look for hosts beaconing to rare external
            IPs&rdquo;.
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
    </div>
  );
}
