import {
  AlertTriangle,
  ChevronDown,
  ChevronLeft,
  Crosshair,
  GitBranch,
  Loader2,
  RotateCw,
  ShieldAlert,
  Trash2,
  Wrench,
  X,
} from 'lucide-react';
import { type ReactNode, useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { RecordedRunChip } from '../components/Badges';
import { ChatDockShell, ChatPanelShell } from '../components/ChatDock';
import { ConfidenceRing } from '../components/ConfidenceRing';
import { HuntVisuals } from '../components/HuntVisuals';
import { Markdown } from '../components/Markdown';
import { Panel, PanelHeader } from '../components/Panel';
import { ErrorState, LoadingState, Spinner } from '../components/States';
import {
  type HuntChatMessage,
  cancelHuntConsole,
  deleteHunt,
  getHunt,
  getHuntChat,
  postHuntChat,
  startHuntConsole,
} from '../lib/api';
import { useDemo } from '../lib/demo';
import { HUNT_STATUS } from '../lib/statusMeta';
import { TIMELINE_GROUP_COLOR, tint } from '../lib/tokens';
import { useAsync } from '../lib/useAsync';
import type { HuntDetailData, HuntDiff, HuntFinding, HuntStatus, TimelineStep } from '../lib/types';

const SEV_COLOR: Record<string, string> = {
  critical: '#f85149',
  high: '#f0883e',
  medium: '#d29922',
  low: '#3fb950',
  info: '#8b949e',
};

function StatusPill({ status }: { status: HuntStatus }) {
  const m = HUNT_STATUS[status] ?? HUNT_STATUS.error;
  return (
    <span
      className="flex items-center gap-1.5 rounded-chip border px-2 py-0.5 text-[11.5px] font-semibold"
      style={{ color: m.color, borderColor: `${m.color}55`, background: `${m.color}14` }}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full${m.pulse ? ' animate-pulse' : ''}`}
        style={{ background: m.color }}
      />
      {m.label}
    </span>
  );
}

// Strip the leading imperative from a free-text objective so the hero shows a
// short, scannable TITLE (like an investigation's rule name) instead of the raw
// prompt. The full objective is still shown beneath + in the tooltip.
const HUNT_TITLE_STRIP =
  /^(please\s+)?(look\s+for|look\s+into|hunt\s+for|hunt|search\s+for|search|find|check\s+for|check|investigate|show\s+me|scan\s+for|scan)\s+/i;
function huntTitle(objective: string): string {
  const raw = (objective || '').trim();
  if (!raw) return 'Hunt';
  let s = raw.replace(HUNT_TITLE_STRIP, '').replace(/^(for|into|at|the)\s+/i, '').trim() || raw;
  s = s.charAt(0).toUpperCase() + s.slice(1);
  return s.length > 80 ? `${s.slice(0, 79).trimEnd()}…` : s;
}

// A hunt has no true/false-positive verdict — it has findings. Derive a
// disposition BADGE (like the alerts verdict pill) from the worst finding
// severity + status, so the analyst sees the conclusion at a glance up top.
//
// ONLY 'threat' findings may claim malicious/suspicious activity: a critical
// VISIBILITY GAP is a coverage statement, and headlining it "Malicious
// activity found" tells the analyst something the hunt never observed.
const _SEV_ORDER = ['info', 'low', 'medium', 'high', 'critical'];
function huntDisposition(
  status: HuntStatus | undefined,
  findings: HuntFinding[],
): { label: string; color: string } {
  if (status === 'running') return { label: 'Hunting…', color: '#4b8bf5' };
  if (status !== 'complete') return { label: 'Inconclusive', color: '#8b949e' };
  const threats = findings.filter((f) => (f.category ?? 'threat') === 'threat');
  const gaps = findings.filter((f) => f.category === 'visibility_gap');
  const worst = threats.reduce(
    (w, f) => Math.max(w, _SEV_ORDER.indexOf((f.severity || 'info').toLowerCase())),
    -1,
  );
  if (worst >= 3) return { label: 'Malicious activity found', color: '#f85149' }; // high/critical
  if (worst === 2) return { label: 'Suspicious activity found', color: '#d29922' }; // medium
  if (worst === 1) return { label: 'Low-severity findings', color: '#d29922' }; // low
  // No threat evidence. Gaps mean the objective couldn't be fully tested —
  // an honest grey "couldn't see", never a green all-clear.
  if (gaps.length > 0) return { label: 'No threat observed — visibility gaps', color: '#8b949e' };
  return { label: 'No malicious activity found', color: '#3fb950' }; // observations-only or clean
}

function DispositionBadge({ label, color }: { label: string; color: string }) {
  return (
    <span
      className="inline-flex items-center gap-2 rounded-pill border px-3 py-1 text-[13px] font-bold uppercase tracking-[.02em]"
      style={{ color, borderColor: `${color}66`, background: `${color}1a` }}
    >
      <span
        className="h-2 w-2 rounded-full"
        style={{ background: color, boxShadow: `0 0 8px ${color}` }}
      />
      {label}
    </span>
  );
}

// Per-group timeline icon — matches the investigation timeline's icon-per-group
// treatment (was a single GitBranch for every hunt step).
const STEP_ICON: Record<string, ReactNode> = {
  Objective: <Crosshair size={14} />,
  'Tool calls': <Wrench size={14} />,
  Findings: <ShieldAlert size={14} />,
};

// "vs last run" diff strip — a compact summary above the findings that answers
// "what changed" since the previous COMPLETE run of the SAME objective:
// N new · M persisting · K resolved, with the baseline run's age. Expandable to
// list the new/resolved finding titles (persisting is the boring bucket — it's
// the count that matters, so it stays collapsed). Only rendered when a previous
// run exists (data.diff present).
function DiffCount({ n, label, color }: { n: number; label: string; color: string }) {
  return (
    <span className="inline-flex items-baseline gap-1">
      <span className="font-mono text-[13px] font-bold" style={{ color }}>
        {n}
      </span>
      <span className="text-[11.5px] text-dim">{label}</span>
    </span>
  );
}

function DiffList({ title, entries, color }: { title: string; entries: HuntDiff['new']; color: string }) {
  if (entries.length === 0) return null;
  return (
    <div>
      <div
        className="mb-1 text-[10px] font-semibold uppercase tracking-[.05em]"
        style={{ color }}
      >
        {title}
      </div>
      <ul className="flex flex-col gap-1">
        {entries.map((e, i) => (
          <li key={i} className="flex items-center gap-2 text-[12px] text-text-2">
            <span className="h-1.5 w-1.5 flex-none rounded-full" style={{ background: color }} />
            {/* Machine-generated finding titles run long — give them two lines
                before the ellipsis; the tooltip carries the full text. */}
            <span className="min-w-0 line-clamp-2" style={{ textWrap: 'pretty' }} title={e.title}>
              {e.title}
            </span>
            <span className="ml-auto flex-none font-mono text-[10px] uppercase text-faint">
              {e.severity}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function HuntDiffStrip({ diff }: { diff: HuntDiff }) {
  const [open, setOpen] = useState(false);
  const expandable = diff.new.length > 0 || diff.resolved.length > 0;
  return (
    <div className="rounded-card border border-border-2 bg-surface-2">
      <button
        onClick={() => expandable && setOpen((o) => !o)}
        className="flex w-full items-center gap-2.5 px-[15px] py-2.5 text-left"
        aria-expanded={open}
      >
        <GitBranch size={14} className="flex-none text-dim" />
        <span className="text-[11px] font-semibold uppercase tracking-[.05em] text-text-2">
          vs last run
        </span>
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <DiffCount n={diff.new.length} label="new" color="#f0883e" />
          <span className="text-ghost">·</span>
          <DiffCount n={diff.persisting.length} label="persisting" color="#8b949e" />
          <span className="text-ghost">·</span>
          <DiffCount n={diff.resolved.length} label="resolved" color="#3fb950" />
        </div>
        <div className="flex-1" />
        {diff.previousWhen && (
          <span className="flex-none font-mono text-[11px] text-faint">{diff.previousWhen}</span>
        )}
        {expandable && (
          <span
            className="flex flex-none text-ghost transition-transform"
            style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)' }}
          >
            <ChevronDown size={14} />
          </span>
        )}
      </button>
      {open && expandable && (
        <div className="grid grid-cols-1 gap-4 border-t border-border-faint px-[15px] py-3 sm:grid-cols-2">
          <DiffList title="New this run" entries={diff.new} color="#f0883e" />
          <DiffList title="Resolved since last run" entries={diff.resolved} color="#3fb950" />
        </div>
      )}
    </div>
  );
}

// Rich finding card — mirrors the investigation timeline rows: a severity dot,
// the title, prose detail, and mono host/citation chips.
function FindingCard({ f }: { f: HuntFinding }) {
  const color = SEV_COLOR[f.severity] ?? SEV_COLOR.info;
  return (
    <div
      className="relative overflow-hidden rounded-card border bg-surface-2 p-[14px_15px]"
      style={{ borderColor: tint(color, 0.28) }}
    >
      <div className="absolute left-0 top-0 h-full w-[3px]" style={{ background: color }} />
      <div className="mb-1.5 flex items-center gap-2">
        <span className="h-2 w-2 flex-none rounded-full" style={{ background: color }} />
        <span className="text-[13.5px] font-semibold text-text" style={{ textWrap: 'pretty' }}>
          {f.title}
        </span>
        {f.category === 'visibility_gap' && (
          <span
            className="flex-none rounded-chip border border-border-2 bg-surface-3 px-1.5 py-px text-[10px] font-semibold uppercase tracking-[.04em] text-dim"
            title="A coverage statement — telemetry this grid doesn't have. Not observed malicious activity."
          >
            visibility gap
          </span>
        )}
        {f.category === 'observation' && (
          <span
            className="flex-none rounded-chip border border-border-2 bg-surface-3 px-1.5 py-px text-[10px] font-semibold uppercase tracking-[.04em] text-dim"
            title="Benign/informational context — not a threat finding."
          >
            observation
          </span>
        )}
        <span
          className="ml-auto flex-none rounded-chip border px-1.5 py-px text-[10px] font-semibold uppercase tracking-[.04em]"
          style={{ color, borderColor: `${color}55`, background: `${color}14` }}
        >
          {f.severity}
        </span>
      </div>
      <div className="text-[12.5px] leading-[1.6] text-text-2" style={{ textWrap: 'pretty' }}>
        {f.detail}
      </div>
      {f.validatorNote && (
        <div
          className="mt-2 rounded-card border px-3 py-2 text-[11.5px] leading-[1.5] text-dim"
          style={{ borderColor: 'rgba(107,135,168,.3)', background: 'rgba(107,135,168,.05)' }}
        >
          <span className="font-semibold" style={{ color: '#8fa3bf' }}>
            Post-validator
          </span>
          {' — '}
          {f.validatorNote}
        </div>
      )}
      {(f.hosts.length > 0 || f.citations.length > 0) && (
        <div className="mt-2 flex flex-wrap gap-1.5 font-mono text-[10.5px]">
          {f.hosts.map((h) => (
            // Host chip → the entity pivot page ("what do we know about this box").
            <Link
              key={h}
              to={`/entity/${encodeURIComponent(h)}`}
              className="rounded-chip bg-surface-3 px-1.5 py-px text-mono-amber hover:brightness-125"
            >
              {h}
            </Link>
          ))}
          {f.citations.map((c) => (
            <span key={c} className="rounded-chip bg-surface-3 px-1.5 py-px text-accent">
              {c}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

// Execution-timeline row — styled to match the investigation timeline (icon
// puck in the group color, connector line, mono timestamp, expandable detail).
function TimelineRow({ step, last }: { step: TimelineStep; last: boolean }) {
  const [open, setOpen] = useState(false);
  const color = TIMELINE_GROUP_COLOR[step.group] ?? '#4b8bf5';
  return (
    <button
      onClick={() => step.detail && setOpen((o) => !o)}
      className="flex w-full gap-3 border-b border-border-faint px-[15px] py-3 text-left transition-colors last:border-0 hover:bg-surface-hover"
    >
      <div className="flex flex-none flex-col items-center">
        <span
          className="flex h-[26px] w-[26px] items-center justify-center rounded-[7px] border"
          style={{ color, background: tint(color), borderColor: tint(color, 0.3) }}
        >
          {STEP_ICON[step.group] ?? <GitBranch size={14} />}
        </span>
        {!last && <div className="mt-[5px] min-h-[8px] w-[1.5px] flex-1 bg-border-2" />}
      </div>
      <div className="min-w-0 flex-1 pt-[3px]">
        <div className="flex items-center gap-[9px]">
          <span
            className="text-[10px] font-semibold uppercase tracking-[.05em]"
            style={{ color }}
          >
            {step.group}
          </span>
          <div className="flex-1" />
          <span className="font-mono text-[11px] text-faint">{step.time}</span>
        </div>
        <div className="mt-[3px] text-[13.5px] font-medium" style={{ textWrap: 'pretty' }}>
          {step.title}
        </div>
        {open && step.detail && (
          <pre className="mt-[9px] animate-fadeUp-slow whitespace-pre-wrap break-words rounded-control border border-border bg-bg px-3 py-2.5 font-mono text-[11.5px] leading-[1.6] text-dim">
            {step.detail}
          </pre>
        )}
      </div>
      {step.detail && (
        <span
          className="flex self-center text-ghost transition-transform"
          style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)' }}
        >
          <ChevronDown size={14} />
        </span>
      )}
    </button>
  );
}

// Section block (uppercase title + mono meta) with a collapse toggle. Mirrors
// the investigation page's CollapsibleSection for visual parity.
function CollapsibleSection({
  title,
  meta,
  defaultOpen = true,
  children,
}: {
  title: string;
  meta?: ReactNode;
  defaultOpen?: boolean;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div>
      <button
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="mb-[11px] flex w-full items-center gap-2 text-left"
      >
        <div className="text-[13px] font-semibold uppercase tracking-[.05em] text-text-2">
          {title}
        </div>
        {meta != null && <div className="font-mono text-[11.5px] text-faint">{meta}</div>}
        <div className="flex-1" />
        <span
          className="flex text-ghost transition-transform"
          style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)' }}
        >
          <ChevronDown size={15} />
        </span>
      </button>
      {open && children}
    </div>
  );
}

export function HuntDetail() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const demo = useDemo(); // demo deployment → recorded-run label, no cancel
  const [reloadKey, setReloadKey] = useState(0);
  const [cancelling, setCancelling] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [rehunting, setRehunting] = useState(false);
  const [rehuntError, setRehuntError] = useState<string | null>(null);

  // useAsync captures pauseWhen at setup and can't see `data` there, so track
  // the current status in a ref and let pauseWhen consult it: stop polling once
  // the hunt reaches a terminal state.
  const statusRef = useRef<HuntStatus | undefined>(undefined);
  const { data, loading, error } = useAsync<HuntDetailData>(() => getHunt(id), [id, reloadKey], {
    refetchInterval: 3000,
    pauseWhen: () => {
      // Pause once the hunt reaches ANY terminal state. Only 'running' is live;
      // enumerating the terminal set missed 'interrupted', which then polled
      // every 3s forever. Gate on a known status that is not 'running' so a new
      // terminal status can never reintroduce the leak.
      const s = statusRef.current;
      return s !== undefined && s !== 'running';
    },
  });
  statusRef.current = data?.status;

  const doCancel = () => {
    if (cancelling) return;
    setCancelling(true);
    cancelHuntConsole(id)
      .then(() => setReloadKey((k) => k + 1))
      .catch(() => undefined)
      .finally(() => setCancelling(false));
  };

  const doDelete = () => {
    if (deleting) return;
    setDeleting(true);
    setDeleteError(null);
    deleteHunt(id)
      .then(() => navigate('/hunts'))
      .catch((e: unknown) => {
        setDeleteError(e instanceof Error ? e.message : 'Delete failed — please try again.');
        setDeleting(false);
      });
  };

  // Re-hunt = a CLEAN re-run of THIS objective as a fresh hunt (no prior-narrative
  // seeding — that would poison a re-run of a failed hunt). The objective_hash
  // matches, so the new run automatically gets the "vs last run" diff. Navigate
  // to the fresh hunt so its live view takes over.
  const doRehunt = () => {
    if (rehunting || !data) return;
    setRehunting(true);
    setRehuntError(null);
    startHuntConsole(data.objective)
      .then((r) => navigate(`/hunts/${r.hunt_id}`))
      .catch((e: unknown) => {
        setRehuntError(e instanceof Error ? e.message : 'Could not re-hunt — please try again.');
        setRehunting(false);
      });
  };

  const status = data?.status;
  const running = status === 'running';
  const failed = status === 'error' || status === 'cancelled' || status === 'interrupted';
  const complete = status === 'complete';
  // Terminal hunts (complete or errored/cancelled/interrupted) can be deleted
  // and support the read-only follow-up chat.
  const terminal = complete || failed;
  const statusColor = status ? (HUNT_STATUS[status]?.color ?? '#8b949e') : '#8b949e';
  const disp = data ? huntDisposition(data.status, data.findings) : null;
  const title = data ? huntTitle(data.objective) : '';

  return (
    <div className="px-[22px] pb-[60px] pt-[18px] font-sans text-text">
      {/* breadcrumb row */}
      <div className="mb-3.5 flex flex-wrap items-center gap-3">
        <Link
          to="/hunts"
          className="flex items-center gap-1.5 text-[12.5px] text-dim hover:text-text"
        >
          <ChevronLeft size={13} /> Hunt Console
        </Link>
        <span className="text-ghost">/</span>
        <div className="text-[15px] font-semibold">Hunt detail</div>
      </div>

      {loading && !data ? (
        <LoadingState label="Loading hunt…" />
      ) : error ? (
        <ErrorState error={error} onRetry={() => setReloadKey((k) => k + 1)} />
      ) : !data ? (
        <ErrorState error={new Error('Hunt not found')} />
      ) : (
        <div className="mx-auto max-w-workstation">
          {/* ── hero: objective headline, meta strip, confidence ring ────── */}
          <div
            className="relative overflow-hidden rounded-panel-lg border p-5"
            style={{
              borderColor: tint(statusColor, 0.32),
              background: `linear-gradient(180deg,${tint(statusColor, 0.08)},rgba(11,14,19,0) 70%),#0b0e13`,
            }}
          >
            <div className="absolute left-0 top-0 h-full w-[3px]" style={{ background: statusColor }} />
            {running && (
              <div className="absolute left-0 right-0 top-0 h-0.5 overflow-hidden">
                <div
                  className="h-full w-[35%] animate-scanline-slow"
                  style={{ background: 'linear-gradient(90deg,transparent,#4b8bf5,transparent)' }}
                />
              </div>
            )}
            <div className="flex items-start gap-4">
              <div className="min-w-0 flex-1">
                {/* verdict-style disposition badge + status — up top, like alerts */}
                <div className="mb-2.5 flex flex-wrap items-center gap-2.5">
                  {disp && <DispositionBadge label={disp.label} color={disp.color} />}
                  <StatusPill status={data.status} />
                  {demo && <RecordedRunChip />}
                </div>
                {/* generated title (from the objective) as the hero headline */}
                <div
                  className="text-[21px] font-semibold leading-[1.32] tracking-[-.015em]"
                  style={{ textWrap: 'pretty' }}
                  title={data.objective}
                >
                  {title}
                </div>
                {/* the analyst's original objective, de-emphasized */}
                <div className="mt-1.5 flex items-start gap-1.5 text-[12.5px] text-dim" style={{ textWrap: 'pretty' }}>
                  <Crosshair size={13} className="mt-0.5 flex-none text-faint" />
                  <span><span className="text-faint">objective:</span> {data.objective}</span>
                </div>
                {/* meta strip */}
                <div className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-[12px] text-dim">
                  <span className="text-faint">started by</span>
                  <span className="text-text-2">{data.startedBy}</span>
                  <span className="text-ghost">·</span>
                  <span className="text-faint">elapsed</span>
                  <span className="text-text-2">{data.elapsedLabel}</span>
                  <span className="text-ghost">·</span>
                  <span className="text-faint">kind</span>
                  <span className="text-text-2">{/* 'chat' is the storage kind for any operator-started hunt — 'manual' is what an analyst reads */}{data.kind === 'chat' ? 'manual' : data.kind}</span>
                </div>
              </div>
              {/* confidence ring — only meaningful once the hunt concludes */}
              {complete && (
                <div className="flex flex-none items-center gap-[9px]">
                  <ConfidenceRing conf={data.confidence} color={statusColor} />
                  <div>
                    <div className="font-mono text-[18px] font-bold leading-none">
                      {data.confidence.toFixed(2)}
                    </div>
                    <div className="text-[10.5px] uppercase tracking-[.05em] text-faint">
                      confidence
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* toolbar: re-hunt (terminal) / cancel (running) / delete (terminal) */}
            <div className="mt-4 flex items-center gap-2.5 border-t border-border-faint pt-3.5">
              <div className="flex-1" />
              {/* Re-hunt: a clean re-run of this objective as a fresh hunt. Prominent
                  on a failed/interrupted hunt (the ones that need re-running);
                  a quiet secondary action on a completed one. Never while running. */}
              {terminal && (
                <button
                  onClick={doRehunt}
                  disabled={rehunting}
                  title="Re-run this objective as a fresh hunt"
                  className={
                    failed
                      ? 'flex items-center gap-1.5 rounded-control border border-accent bg-[rgba(75,139,245,.14)] px-[11px] py-1.5 text-[12px] font-semibold text-[#cfe0ff] hover:bg-[rgba(75,139,245,.22)] disabled:opacity-60'
                      : 'flex items-center gap-1.5 rounded-control border border-border-strong bg-surface-3 px-[11px] py-1.5 text-[12px] font-semibold text-dim hover:border-accent hover:text-accent disabled:opacity-60'
                  }
                >
                  {rehunting ? <Spinner size={13} /> : <RotateCw size={13} />}
                  {rehunting ? 'Starting…' : 'Re-hunt'}
                </button>
              )}
              {rehuntError && (
                <span className="font-mono text-[11.5px] text-danger">{rehuntError}</span>
              )}
              {/* Demo: the cancel POST is demo-blocked (403) — don't offer a
                  button whose only outcome is a refusal. */}
              {running && !demo && (
                <button
                  onClick={doCancel}
                  disabled={cancelling}
                  className="flex items-center gap-1.5 rounded-control border border-border-strong bg-surface-3 px-[11px] py-1.5 text-[12px] font-semibold text-dim hover:border-danger hover:text-danger disabled:opacity-60"
                >
                  {cancelling ? <Spinner size={13} /> : <X size={13} />}
                  {cancelling ? 'Cancelling…' : 'Cancel hunt'}
                </button>
              )}
              {terminal &&
                (confirmDelete ? (
                  <div className="flex items-center gap-2.5">
                    {deleteError && (
                      <span className="font-mono text-[11.5px] text-danger">{deleteError}</span>
                    )}
                    <span className="text-[12px] text-dim">Delete this hunt?</span>
                    <button
                      onClick={doDelete}
                      disabled={deleting}
                      className="flex items-center gap-1.5 rounded-control border border-danger bg-[rgba(240,68,56,.1)] px-[11px] py-1.5 text-[12px] font-semibold text-[#fca5a5] hover:bg-[rgba(240,68,56,.18)] disabled:opacity-60"
                    >
                      {deleting ? <Spinner size={13} color="#fca5a5" /> : <Trash2 size={13} />}
                      {deleting ? 'Deleting…' : 'Confirm delete'}
                    </button>
                    <button
                      onClick={() => {
                        setConfirmDelete(false);
                        setDeleteError(null);
                      }}
                      disabled={deleting}
                      className="rounded-control border border-border-strong bg-surface-3 px-[11px] py-1.5 text-[12px] font-semibold text-text-2 hover:text-text disabled:opacity-60"
                    >
                      Cancel
                    </button>
                  </div>
                ) : (
                  <button
                    onClick={() => setConfirmDelete(true)}
                    className="flex items-center gap-1.5 rounded-control border border-border-strong bg-surface-3 px-[11px] py-1.5 text-[12px] font-semibold text-dim hover:border-danger hover:text-danger"
                  >
                    <Trash2 size={13} />
                    Delete
                  </button>
                ))}
            </div>
          </div>

          {/* running banner */}
          {running && (
            <Panel className="mt-[18px] flex items-center gap-2 px-4 py-3 text-[13px] text-dim">
              <Loader2 size={15} className="animate-spin text-accent" />
              Hunting… correlating events, enriching indicators, mapping to MITRE. This view updates
              live.
            </Panel>
          )}

          {/* failure banner */}
          {failed && (
            <div
              className="mt-[18px] flex items-start gap-2.5 rounded-panel-lg border px-[18px] py-3.5"
              style={{
                borderColor: 'rgba(240,68,56,.32)',
                background: 'linear-gradient(180deg,rgba(240,68,56,.07),rgba(240,68,56,.02))',
              }}
            >
              <span className="mt-px flex text-danger">
                <AlertTriangle size={16} />
              </span>
              <div className="text-[13px] leading-[1.55] text-dim" style={{ textWrap: 'pretty' }}>
                {status === 'cancelled'
                  ? 'This hunt was cancelled before it finished. Any partial findings and trace below are still shown.'
                  : status === 'interrupted'
                    ? 'This hunt was interrupted by a service restart. Any partial findings and trace below are still shown.'
                    : 'This hunt ended in an error. Any partial findings and trace below are still shown.'}
              </div>
            </div>
          )}

          {/* ── two-column workstation layout ────────────────────────────── */}
          <div className="mt-[18px] grid grid-cols-1 items-start gap-[18px] lg:grid-cols-[minmax(0,1fr)_360px]">
            {/* main column: narrative, findings, timeline */}
            <div className="flex min-w-0 flex-col gap-[18px]">
              {data.narrative && (
                <CollapsibleSection title="Narrative">
                  <Panel>
                    <div
                      className="p-4 text-[13.5px] leading-[1.6] text-text-2"
                      style={{ textWrap: 'pretty' }}
                    >
                      <Markdown>{data.narrative}</Markdown>
                    </div>
                  </Panel>
                </CollapsibleSection>
              )}

              {/* Deterministic charts from the findings — only once the hunt has
                  concluded WITH findings (a running or empty hunt has nothing
                  to plot, and a chart must never render from nothing). */}
              {complete && data.findings.length > 0 && (
                <CollapsibleSection title="Visual summary">
                  <HuntVisuals
                    findings={data.findings}
                    affectedHosts={data.affectedHosts}
                    charts={data.charts}
                  />
                </CollapsibleSection>
              )}

              {/* "vs last run" diff — only when a prior COMPLETE run of this
                  same objective exists (server omits diff otherwise). */}
              {complete && data.diff && <HuntDiffStrip diff={data.diff} />}

              <CollapsibleSection
                title="Findings"
                meta={`${data.findings.length} finding${data.findings.length === 1 ? '' : 's'}`}
              >
                {data.findings.length === 0 ? (
                  <Panel className="px-4 py-3.5 text-[13px] text-dim">
                    {complete
                      ? 'No findings — a clean hunt. Nothing notable surfaced for this objective.'
                      : 'No findings yet.'}
                  </Panel>
                ) : (
                  <div className="flex flex-col gap-2.5">
                    {data.findings.map((f, i) => (
                      <FindingCard key={i} f={f} />
                    ))}
                  </div>
                )}
              </CollapsibleSection>

              <CollapsibleSection
                title="Hunt timeline"
                meta={`${data.timeline.length} step${data.timeline.length === 1 ? '' : 's'} · ${data.elapsedLabel}`}
                defaultOpen
              >
                <Panel>
                  {data.timeline.length === 0 ? (
                    <div className="px-[15px] py-3.5 text-[12.5px] text-dim">No steps yet.</div>
                  ) : (
                    data.timeline.map((step, i) => (
                      <TimelineRow
                        key={step.id}
                        step={step}
                        last={i === data.timeline.length - 1}
                      />
                    ))
                  )}
                </Panel>
              </CollapsibleSection>

            </div>

            {/* right rail: hosts / MITRE / recommended actions */}
            <div className="flex flex-col gap-[18px]">
              {data.affectedHosts.length > 0 && (
                <Panel>
                  <PanelHeader
                    icon={<Crosshair size={15} />}
                    title="Affected hosts"
                    right={
                      <span className="font-mono text-[11px] text-accent">
                        {data.affectedHosts.length}
                      </span>
                    }
                  />
                  <div className="flex flex-wrap gap-1.5 p-4">
                    {data.affectedHosts.map((h) => (
                      <span
                        key={h}
                        className="rounded-chip bg-surface-3 px-2 py-0.5 font-mono text-[11.5px] text-mono-amber"
                      >
                        {h}
                      </span>
                    ))}
                  </div>
                </Panel>
              )}

              {data.mitreTechniques.length > 0 && (
                <Panel>
                  <PanelHeader
                    icon={<ShieldAlert size={15} />}
                    title="MITRE ATT&CK"
                    right={
                      <span className="font-mono text-[11px] text-accent">
                        {data.mitreTechniques.length}
                      </span>
                    }
                  />
                  <div className="flex flex-wrap gap-1.5 p-4">
                    {data.mitreTechniques.map((m) => (
                      <span
                        key={m}
                        className="rounded-chip border border-accent/40 bg-accent/10 px-2 py-0.5 font-mono text-[11.5px] text-accent"
                      >
                        {m}
                      </span>
                    ))}
                  </div>
                </Panel>
              )}

              {data.recommendedActions.length > 0 && (
                <Panel>
                  <PanelHeader title="Recommended actions" />
                  <div className="flex flex-col gap-3 p-4">
                    {data.recommendedActions.map((a, i) => (
                      <div key={i} className="border-l-2 border-border-2 pl-3">
                        <div className="text-[12.5px] font-semibold text-text">{a.title}</div>
                        <div
                          className="mt-0.5 text-[11.5px] leading-[1.5] text-dim"
                          style={{ textWrap: 'pretty' }}
                        >
                          {a.rationale}
                        </div>
                      </div>
                    ))}
                  </div>
                </Panel>
              )}
            </div>
          </div>

          {/* Read-only follow-up chat — a floating "Chat about this" dock, same
              UX as the investigation page. Only on a terminal hunt. */}
          {terminal && <HuntChatDock huntId={data.id} />}
        </div>
      )}
    </div>
  );
}

// ── Read-only follow-up chat about a completed hunt ─────────────────────────
// Same rendering as the investigation chat (the shared ChatPanelShell) but
// strictly read-only: a hunt chat owns its own thread state and can only
// answer questions — it can't ack, escalate, or change a verdict.
function HuntChatPanel({
  huntId,
  fill,
  onClose,
}: {
  huntId: string;
  fill?: boolean;
  onClose?: () => void;
}) {
  const [messages, setMessages] = useState<HuntChatMessage[]>([]);
  const [pending, setPending] = useState(false);
  const [draft, setDraft] = useState('');
  const pollTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const NET_ERR_TEXT = 'Could not reach the server — please try again.';

  // Apply a thread from the API; keep polling while the assistant works. The
  // backend runs the turn in the background and appends the reply to the thread.
  const applyThread = (thread: { messages: HuntChatMessage[]; pending: boolean }) => {
    setMessages(thread.messages.filter((m) => m.text || m.role === 'user'));
    setPending(thread.pending);
    if (pollTimer.current) clearTimeout(pollTimer.current);
    if (thread.pending) {
      pollTimer.current = setTimeout(() => {
        getHuntChat(huntId)
          .then(applyThread)
          .catch(() => {
            setPending(false);
            setMessages((c) => {
              const last = c[c.length - 1];
              if (last?.role === 'assistant' && last.text === NET_ERR_TEXT) return c;
              return [...c, { role: 'assistant', text: NET_ERR_TEXT }];
            });
          });
      }, 1500);
    }
  };

  // Load the existing thread once, and resume polling if a turn is still running.
  useEffect(() => {
    getHuntChat(huntId).then(applyThread).catch(() => undefined);
    return () => {
      if (pollTimer.current) clearTimeout(pollTimer.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [huntId]);

  const send = () => {
    const t = draft.trim();
    if (!t || pending) return;
    setMessages((c) => [...c, { role: 'user', text: t }]);
    setDraft('');
    setPending(true);
    postHuntChat(huntId, t)
      .then(applyThread)
      .catch(() => {
        setPending(false);
        setMessages((c) => [...c, { role: 'assistant', text: NET_ERR_TEXT }]);
      });
  };

  return (
    <ChatPanelShell
      title="Chat about this hunt"
      scopeLabel="read-only"
      placeholder="Ask a follow-up… e.g. which host was worst?"
      listSizeClass={fill ? 'flex-1' : 'max-h-[460px] min-h-[180px]'}
      emptyHint={
        <div className="text-[12.5px] leading-[1.55] text-dim" style={{ textWrap: 'pretty' }}>
          Ask a follow-up about this hunt — e.g. “which host was worst?” or “show me the DNS for
          host X”. The assistant answers from the hunt's evidence; it can't change the result.
        </div>
      }
      messages={messages}
      pending={pending}
      draft={draft}
      onDraft={setDraft}
      onSend={send}
      fill={fill}
      onClose={onClose}
    />
  );
}

// Floating "Chat about this" dock — a bottom-right launcher that opens the
// hunt chat as an overlay, sharing ChatDockShell with the investigation page
// so the follow-up-chat UX is identical across investigations and hunts.
function HuntChatDock({ huntId }: { huntId: string }) {
  return (
    <ChatDockShell label="Chat about this">
      {(close) => <HuntChatPanel huntId={huntId} fill onClose={close} />}
    </ChatDockShell>
  );
}
