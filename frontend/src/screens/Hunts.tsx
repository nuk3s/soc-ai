import { ChevronRight, Crosshair, Loader2, Plus, Sparkles } from 'lucide-react';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Panel } from '../components/Panel';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { getHunts, getHuntStats, startHuntConsole } from '../lib/api';
import { useAsync } from '../lib/useAsync';
import type { HuntRow, HuntStatus } from '../lib/types';

// ---------------------------------------------------------------------------
// Hunt Console — describe a hunt in plain language; the agent correlates across
// hosts/time and lands findings + a narrative (a HuntReport). Read-only. The
// list + stats are real (/api/v1/hunts*), starting a hunt spawns a background
// run and navigates to its live detail.
// ---------------------------------------------------------------------------

const GRID = '1fr 120px 110px 110px 130px 44px';

const STATUS_META: Record<HuntStatus, { label: string; color: string; pulse?: boolean }> = {
  running: { label: 'Running', color: '#4b8bf5', pulse: true },
  complete: { label: 'Complete', color: '#3fb950' },
  error: { label: 'Error', color: '#f85149' },
  cancelled: { label: 'Cancelled', color: '#8b949e' },
  interrupted: { label: 'Interrupted', color: '#d29922' },
};

const TONE: Record<string, string> = {
  accent: '#4b8bf5',
  sigma: '#a371f7',
  warn: '#d29922',
  danger: '#f85149',
};

function StatusDot({ status }: { status: HuntStatus }) {
  const m = STATUS_META[status] ?? STATUS_META.error;
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

  const { data, loading, error } = useAsync<HuntRow[]>(getHunts, [reloadKey], {
    refetchInterval: 8000, // live status (running → complete) without a reload
  });
  const stats = useAsync(getHuntStats, [reloadKey], { refetchInterval: 8000 });

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
            <button
              key={h.id}
              onClick={() => navigate(`/hunts/${h.id}`)}
              className="grid w-full items-center gap-3 border-b border-border px-4 py-3 text-left last:border-0 hover:bg-surface-2"
              style={{ gridTemplateColumns: GRID }}
            >
              <div className="flex items-center gap-2 truncate">
                <Crosshair size={14} className="flex-none text-accent" />
                <span className="truncate text-[13px] text-text">{h.objective}</span>
              </div>
              <div className="text-[13px] tabular-nums text-text-2">{h.findingCount}</div>
              <div className="text-[13px] tabular-nums text-text-2">{h.affectedHosts}</div>
              <div>
                <StatusDot status={h.status} />
              </div>
              <div className="text-[12px] text-dim">{h.when}</div>
              <ChevronRight size={15} className="text-faint" />
            </button>
          ))
        )}
      </Panel>
    </div>
  );
}
