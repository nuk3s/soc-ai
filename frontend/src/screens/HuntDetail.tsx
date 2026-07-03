import {
  AlertTriangle,
  ChevronDown,
  ChevronLeft,
  Crosshair,
  GitBranch,
  Loader2,
  MessageSquare,
  Send,
  ShieldAlert,
  Trash2,
  Wrench,
  X,
} from 'lucide-react';
import { type ReactNode, useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ConfidenceRing } from '../components/ConfidenceRing';
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
} from '../lib/api';
import { TIMELINE_GROUP_COLOR, tint } from '../lib/tokens';
import { useAsync } from '../lib/useAsync';
import type { HuntDetailData, HuntFinding, HuntStatus, TimelineStep } from '../lib/types';

const STATUS_META: Record<HuntStatus, { label: string; color: string; pulse?: boolean }> = {
  running: { label: 'Running', color: '#4b8bf5', pulse: true },
  complete: { label: 'Complete', color: '#3fb950' },
  error: { label: 'Error', color: '#f85149' },
  cancelled: { label: 'Cancelled', color: '#8b949e' },
  interrupted: { label: 'Interrupted', color: '#d29922' },
};

const SEV_COLOR: Record<string, string> = {
  critical: '#f85149',
  high: '#f0883e',
  medium: '#d29922',
  low: '#3fb950',
  info: '#8b949e',
};

function StatusPill({ status }: { status: HuntStatus }) {
  const m = STATUS_META[status] ?? STATUS_META.error;
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
const _SEV_ORDER = ['info', 'low', 'medium', 'high', 'critical'];
function huntDisposition(
  status: HuntStatus | undefined,
  findings: HuntFinding[],
): { label: string; color: string } {
  if (status === 'running') return { label: 'Hunting…', color: '#4b8bf5' };
  if (status !== 'complete') return { label: 'Inconclusive', color: '#8b949e' };
  const worst = findings.reduce(
    (w, f) => Math.max(w, _SEV_ORDER.indexOf((f.severity || 'info').toLowerCase())),
    -1,
  );
  if (worst >= 3) return { label: 'Malicious activity found', color: '#f85149' }; // high/critical
  if (worst === 2) return { label: 'Suspicious activity found', color: '#d29922' }; // medium
  if (worst === 1) return { label: 'Low-severity findings', color: '#d29922' }; // low
  return { label: 'No malicious activity found', color: '#3fb950' }; // info-only or clean
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
      {(f.hosts.length > 0 || f.citations.length > 0) && (
        <div className="mt-2 flex flex-wrap gap-1.5 font-mono text-[10.5px]">
          {f.hosts.map((h) => (
            <span key={h} className="rounded-chip bg-surface-3 px-1.5 py-px text-mono-amber">
              {h}
            </span>
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
  const [reloadKey, setReloadKey] = useState(0);
  const [cancelling, setCancelling] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  // useAsync captures pauseWhen at setup and can't see `data` there, so track
  // the current status in a ref and let pauseWhen consult it: stop polling once
  // the hunt reaches a terminal state.
  const statusRef = useRef<HuntStatus | undefined>(undefined);
  const { data, loading, error } = useAsync<HuntDetailData>(() => getHunt(id), [id, reloadKey], {
    refetchInterval: 3000,
    pauseWhen: () => {
      const s = statusRef.current;
      return s === 'complete' || s === 'error' || s === 'cancelled';
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

  const status = data?.status;
  const running = status === 'running';
  const failed = status === 'error' || status === 'cancelled' || status === 'interrupted';
  const complete = status === 'complete';
  // Terminal hunts (complete or errored/cancelled/interrupted) can be deleted
  // and support the read-only follow-up chat.
  const terminal = complete || failed;
  const statusColor = status ? (STATUS_META[status]?.color ?? '#8b949e') : '#8b949e';
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
                  <span className="text-text-2">{data.kind}</span>
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

            {/* toolbar: cancel (running) / delete (terminal) */}
            <div className="mt-4 flex items-center gap-2.5 border-t border-border-faint pt-3.5">
              <div className="flex-1" />
              {running && (
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
// Mirrors the investigation ChatPanel UX (thread + input + typing indicator,
// polls while the assistant works) but is strictly read-only: a hunt chat can
// only answer questions — it can't ack, escalate, or change a verdict.
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
  const listRef = useRef<HTMLDivElement>(null);
  const pollTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const didMountRef = useRef(false);
  const seedLengthRef = useRef(-1);

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

  // autoscroll on new messages / typing indicator (skip the initial mount)
  useEffect(() => {
    if (!didMountRef.current) {
      didMountRef.current = true;
      seedLengthRef.current = messages.length;
      return;
    }
    const el = listRef.current;
    if (el) el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' });
  }, [messages.length, pending]);

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
    <Panel className={`flex min-h-0 flex-col${fill ? ' h-full' : ''}`}>
      <PanelHeader
        icon={<MessageSquare size={15} />}
        title="Chat about this hunt"
        right={
          <div className="flex items-center gap-2.5">
            {messages.length > 0 && (
              <span className="font-mono text-[11px] text-accent">
                {messages.length} msg{messages.length !== 1 ? 's' : ''}
              </span>
            )}
            <div className="font-mono text-[11px] text-faint">read-only</div>
            {onClose && (
              <button
                onClick={onClose}
                aria-label="Close chat"
                className="flex text-dim hover:text-text"
              >
                <X size={15} />
              </button>
            )}
          </div>
        }
        className="py-[11px]"
      />
      <div
        ref={listRef}
        className={`flex flex-col gap-3 overflow-y-auto p-[15px]${
          fill ? ' flex-1' : ' max-h-[460px] min-h-[180px]'
        }`}
      >
        {messages.length === 0 && !pending && (
          <div className="text-[12.5px] leading-[1.55] text-dim" style={{ textWrap: 'pretty' }}>
            Ask a follow-up about this hunt — e.g. “which host was worst?” or “show me the DNS for
            host X”. The assistant answers from the hunt's evidence; it can't change the result.
          </div>
        )}
        {messages.map((m, i) => {
          const isNew = i >= seedLengthRef.current;
          return m.role === 'user' ? (
            <div
              key={i}
              className="max-w-[82%] min-w-0 self-end break-words rounded-[12px_12px_3px_12px] border border-accent-deep bg-[#1d3a6b] px-[13px] py-[9px] text-[13px] leading-[1.5]"
            >
              {m.text}
            </div>
          ) : (
            <div key={i} className={`max-w-[88%] min-w-0 self-start${isNew ? ' animate-fadeUp' : ''}`}>
              <div
                className="overflow-hidden break-words rounded-[12px_12px_12px_3px] border border-border-2 bg-surface-3 px-[13px] py-2.5 text-[13px] leading-[1.55] text-text-2 [&_pre]:max-w-full [&_pre]:overflow-x-auto"
                style={{ textWrap: 'pretty' }}
              >
                <Markdown>{m.text ?? ''}</Markdown>
              </div>
              {m.tools && (
                <div className="mt-1.5 flex items-center gap-1.5 font-mono text-[10.5px] text-faint">
                  <span className="text-accent">
                    <Wrench size={11} />
                  </span>
                  tools · {m.tools}
                </div>
              )}
            </div>
          );
        })}
        {pending && (
          <div className="flex items-center gap-1 self-start rounded-[12px_12px_12px_3px] border border-border-2 bg-surface-3 px-3.5 py-[11px]">
            <span className="h-1.5 w-1.5 animate-blink rounded-full bg-faint" />
            <span className="h-1.5 w-1.5 animate-blink rounded-full bg-faint" style={{ animationDelay: '.2s' }} />
            <span className="h-1.5 w-1.5 animate-blink rounded-full bg-faint" style={{ animationDelay: '.4s' }} />
          </div>
        )}
      </div>
      <div className="flex items-center gap-[9px] border-t border-border px-[13px] py-[11px]">
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') send();
          }}
          placeholder="Ask a follow-up… e.g. which host was worst?"
          className="flex-1 rounded-control border border-border-input bg-bg px-3 py-[9px] text-[13px] text-text outline-none focus:border-accent"
        />
        <button
          onClick={send}
          aria-label="Send"
          className="flex h-9 w-[38px] flex-none items-center justify-center rounded-control bg-accent text-white hover:bg-accent-deep"
        >
          <Send size={16} />
        </button>
      </div>
    </Panel>
  );
}

// Floating "Chat about this" dock — a bottom-right launcher that opens the
// hunt chat as an overlay, mirroring the investigation page's ChatDock so the
// follow-up-chat UX is identical across investigations and hunts.
function HuntChatDock({ huntId }: { huntId: string }) {
  const [open, setOpen] = useState(false);
  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="fixed bottom-6 right-6 z-40 flex items-center gap-2 rounded-pill border border-accent-deep bg-accent px-[18px] py-3 text-[13px] font-semibold text-white shadow-[0_12px_34px_rgba(75,139,245,.42)] transition-transform hover:-translate-y-0.5 hover:bg-accent-deep"
      >
        <MessageSquare size={16} />
        Chat about this
      </button>
    );
  }
  return (
    <div className="fixed bottom-6 right-6 z-40 h-[560px] max-h-[calc(100vh-96px)] w-[400px] max-w-[calc(100vw-32px)] animate-fadeUp drop-shadow-[0_24px_70px_rgba(0,0,0,.6)]">
      <HuntChatPanel huntId={huntId} fill onClose={() => setOpen(false)} />
    </div>
  );
}
