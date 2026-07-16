import {
  Activity,
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronDown,
  Copy,
  Download,
  Cpu,
  Crosshair,
  GitBranch,
  LayoutTemplate,
  Loader2,
  type LucideIcon,
  MessageSquare,
  RotateCw,
  Scale,
  Shield,
  Sparkles,
  Terminal,
  Triangle,
  Wrench,
  X,
  Zap,
} from 'lucide-react';
import { type ReactNode, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ChatDockShell, ChatPanelShell } from '../components/ChatDock';
import { ConfidenceRing } from '../components/ConfidenceRing';
import { Markdown } from '../components/Markdown';
import { EntityGraph } from '../components/EntityGraph';
import { Panel } from '../components/Panel';
import { KindBadge, RecordedRunChip, SeverityTag, VerdictPill } from '../components/Badges';
import { Spinner } from '../components/States';
import {
  type ChatThread,
  ackGroup,
  dismissInvestigationError,
  escalateGroup,
  executeAction,
  getChatThread,
  downloadInvestigationExport,
  overrideVerdict as submitOverride,
  postChat,
  getMe,
  requestMoreInfo,
  resolveInvestigation,
  startHunt,
} from '../lib/api';
import { clearChatDraft, loadChatDraft, saveChatDraft } from '../lib/chatDraft';
import { demoBlocked, useDemo } from '../lib/demo';
import { absTime } from '../lib/timeRange';
import { TIMELINE_GROUP_COLOR, VERDICT, tint } from '../lib/tokens';
import type {
  ActionTag,
  AlertMeta,
  ChatMessage,
  DetectionKind,
  HostSignal,
  Investigation as Inv,
  InvMeta,
  OracleAdjudication,
  RecommendedAction,
  Severity,
  SummarySegment,
  TimelineStep,
} from '../lib/types';

const SEV_COLOR: Record<Severity, string> = {
  critical: '#f04438',
  high: '#f79009',
  medium: '#eab308',
  low: '#6b87a8',
};


interface InvestigationProps {
  inv: Inv;
  layout?: 'drawer' | 'page';
  /** Called with the new investigation id when the analyst re-runs the hunt. */
  onReHunt?: (newId: string) => void;
  /** Called after a chat verdict proposal is applied, so the parent refetches inv. */
  onVerdictApplied?: () => void;
  /** Called with the detection (rule) name after a successful group-scoped ack —
   * lets the Alerts list hide the group optimistically while ES catches up. */
  onAcked?: (ruleName: string) => void;
}

const ACTION_ICON: Record<ActionTag, LucideIcon> = {
  ack: Check,
  escalate: Triangle,
  comment: MessageSquare,
};
const ACTION_ICON_COLOR: Record<ActionTag, string> = {
  ack: '#7ba893',
  escalate: '#f04438',
  comment: '#4b8bf5',
};
const ACTION_TAG_COLOR: Record<ActionTag, { color: string; bg: string }> = {
  ack: { color: '#8b94a3', bg: '#161c25' },
  escalate: { color: '#f04438', bg: 'rgba(240,68,56,.12)' },
  comment: { color: '#4b8bf5', bg: 'rgba(75,139,245,.12)' },
};

const STEP_ICON: Record<string, LucideIcon> = {
  'Prefetch & pivots': GitBranch,
  'Indicator enrichment': Shield,
  'Tool calls': Terminal,
  Decision: LayoutTemplate,
  Validators: CheckCircle2,
  Oracle: Sparkles,
};

function fmt(s: number) {
  const m = Math.floor(s / 60);
  const x = s % 60;
  return `${m < 10 ? '0' : ''}${m}:${x < 10 ? '0' : ''}${x}`;
}

export function Investigation({ inv, layout = 'drawer', onReHunt, onVerdictApplied, onAcked }: InvestigationProps) {
  const navigate = useNavigate();
  const v = VERDICT[inv.verdict];
  // Who is clicking — the just-executed action line used to hardcode
  // "· analyst ·" even for an admin session (dogfood 2026-07-15).
  const [me, setMe] = useState<string | null>(null);
  useEffect(() => {
    getMe()
      .then((m) => setMe(m.username))
      .catch(() => {});
  }, []);
  const demo = useDemo(); // demo deployment → label the verdict as a recorded run
  const [actions, setActions] = useState<
    Record<string, 'approved' | 'rejected' | 'executing' | 'failed'>
  >({});
  const [actionMsg, setActionMsg] = useState<Record<string, string>>({});
  // Settled-verdict fallback action bar: when a complete run recommended no
  // write actions, the analyst can still ack/escalate the whole group directly.
  const [settledAction, setSettledAction] = useState<'ack' | 'escalate' | null>(null);
  const [settledMsg, setSettledMsg] = useState<{ tone: 'ok' | 'err'; text: string } | null>(null);
  const [openSteps, setOpenSteps] = useState<Record<string, boolean>>({});
  const [flashStep, setFlashStep] = useState<string | null>(null);
  const [timelineOpen, setTimelineOpen] = useState(true);
  const [reasoningOpen, setReasoningOpen] = useState(false);
  const [chat, setChat] = useState<ChatMessage[]>(inv.seedChat);
  const [pending, setPending] = useState(false);
  // Restore any draft saved before the drawer last unmounted (close + reopen).
  const [draft, setDraft] = useState(() => loadChatDraft(inv.id));
  const [elapsed, setElapsed] = useState(0);
  // Client-side stuck-guard: flips true if the run is still 'investigating'
  // after a generous cap, so the spinner can't hang forever even if the backend
  // reaper hasn't yet marked it 'error'.
  const [stuck, setStuck] = useState(false);
  const chatTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // The investigation id the current `draft` belongs to. Lets the persist effect
  // skip the render where inv.id just changed (draft still holds the PREVIOUS
  // investigation's text then) so it can't clobber the new id's stored draft.
  const draftIdRef = useRef(inv.id);
  // Entity graph always starts collapsed — for most investigations the blast
  // radius is noise, and the collapsed bar narrative carries the gist.
  const [graphOpen, setGraphOpen] = useState(false);

  // Derived from the live status, NOT a state — so a 2.5s poll (which hands us a
  // new inv object with the same id) never resets it. The reset effect below is
  // keyed on inv.id so polling the same investigation doesn't jitter the pane or
  // restart the elapsed timer.
  const investigating = inv.status === 'investigating';
  // A terminal run that reached NO verdict — a reaped/errored run, an operator-
  // cancelled run, or one the client-side guard gave up on — renders the terminal
  // state, never an empty verdict pane (the "blank investigation" bug).
  const cancelled = inv.status === 'cancelled';
  const interrupted = inv.status === 'interrupted';
  const failed = inv.status === 'error' || cancelled || interrupted || (investigating && stuck);
  // Only spin while genuinely in-flight (not once we've decided it's stuck).
  const running = investigating && !stuck;

  // elapsed ticker while running
  useEffect(() => {
    if (!running) return;
    const t = setInterval(() => setElapsed((e) => e + 1), 1000);
    return () => clearInterval(t);
  }, [running]);

  // Stuck-guard timer: flips true only when the run is 'investigating' AND has
  // made NO visible progress (no new timeline step from the poll) for the cap.
  // The old guard was a flat wall-clock timer, so a legitimately long run on a
  // contended gateway (each turn can take minutes) got branded "seems stuck"
  // while it was still streaming steps — which taught analysts to distrust the
  // banner. Keyed on the latest step id: every new step resets the clock and
  // clears a prior stuck verdict; a fresh run id does too.
  const lastStepId = inv.timeline.length > 0 ? inv.timeline[inv.timeline.length - 1].id : '';
  useEffect(() => {
    if (!investigating) return;
    setStuck(false); // progress arrived (or a fresh run) — clear a stale verdict
    const STUCK_AFTER_MS = 5 * 60_000; // 5 min without a single new step
    const t = setTimeout(() => setStuck(true), STUCK_AFTER_MS);
    return () => clearTimeout(t);
  }, [investigating, inv.id, lastStepId]);

  // Persist the draft so it survives the component unmounting (drawer close).
  // Skip the render where inv.id JUST changed: at that point `draft` still holds
  // the PREVIOUS investigation's text (the reset effect below hasn't reloaded it
  // yet), and since this effect runs before that one, persisting here would
  // clobber the new id's stored draft — bleeding the old text into it.
  useEffect(() => {
    if (draftIdRef.current !== inv.id) {
      draftIdRef.current = inv.id;
      return;
    }
    saveChatDraft(inv.id, draft);
  }, [inv.id, draft]);

  // reset transient state only when the investigation IDENTITY changes (drawer
  // reuse / re-hunt) — never on a poll refresh of the same investigation.
  useEffect(() => {
    setActions({});
    setActionMsg({});
    setSettledAction(null);
    setSettledMsg(null);
    setOpenSteps({});
    setChat(inv.seedChat);
    setPending(false);
    setStuck(false);
    // Restore this investigation's saved draft (the drawer is reused across
    // investigations, so the previous one's draft must not bleed through).
    setDraft(loadChatDraft(inv.id));
    setErrDismiss('idle');
    setErrDismissMsg(null);
    // Seed from the REAL elapsed (backend) so opening the same run in the drawer
    // then the permalink doesn't reset the timer to 0:00.
    setElapsed(inv.elapsedSec ?? 0);
    setGraphOpen(false); // always start collapsed — the bar narrative carries the gist
    setTimelineOpen(true);
    setOverrideOpen(false);
    setOverrideVerdictVal(inv.verdict);
    setOverrideRationale('');
    setOverrideError(null);
    if (chatTimer.current) clearTimeout(chatTimer.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [inv.id]);

  // stop any chat poll when the component unmounts
  useEffect(() => () => {
    if (chatTimer.current) clearTimeout(chatTimer.current);
  }, []);

  const [reHunting, setReHunting] = useState(false);
  const [overrideOpen, setOverrideOpen] = useState(false);
  const [overrideVerdictVal, setOverrideVerdictVal] = useState<string>(inv.verdict);
  const [overrideRationale, setOverrideRationale] = useState('');
  const [overriding, setOverriding] = useState(false);
  const [overrideError, setOverrideError] = useState<string | null>(null);

  // Dismiss (acknowledge) a pipeline-error run: the Dashboard KPI stops counting
  // it, while the run itself stays a fallback under the Pipeline-error filter.
  // `done` locally bridges the gap until a poll returns inv.errorDismissed.
  const [errDismiss, setErrDismiss] = useState<'idle' | 'busy' | 'done'>('idle');
  const [errDismissMsg, setErrDismissMsg] = useState<string | null>(null);
  const errorDismissed = inv.errorDismissed || errDismiss === 'done';
  const dismissError = () => {
    if (errDismiss === 'busy') return;
    const blocked = demoBlocked(demo);
    if (blocked) {
      setErrDismissMsg(blocked);
      return;
    }
    setErrDismissMsg(null);
    setErrDismiss('busy');
    dismissInvestigationError(inv.id)
      .then(() => setErrDismiss('done'))
      .catch((e) => {
        setErrDismiss('idle');
        setErrDismissMsg(e instanceof Error ? e.message : 'dismiss failed');
      });
  };

  // Re-run the investigation: start a fresh hunt on the same alert and hand the
  // new investigation id to the container so it switches to (and polls) it.
  // `deep` forces the full tool-driven loop — offered when THIS run was a
  // zero-tool heuristic, because re-running a heuristic verdict through the
  // same fast path just repeats the heuristic (dogfood 2026-07-15).
  const startReRun = (deep: boolean) => {
    if (reHunting) return;
    setReHunting(true);
    startHunt(inv.groupId, deep ? { deep: true } : undefined)
      .then((newId) => onReHunt?.(newId))
      .catch(() => {})
      .finally(() => setReHunting(false));
  };
  const reRun = () => startReRun(false);
  const reRunDeep = () => startReRun(true);
  const wasHeuristic = inv.status === 'complete' && inv.meta?.toolCalls === 0;

  // The verdict consulted the rule-tuning tool (the rationale/summary cites
  // t_suggest_rule_tuning) — offer a direct link to the tuning screen.
  const tuningCited = /suggest_rule_tuning/.test(
    `${inv.rationale ?? ''} ${inv.summary.map((s) => ('v' in s ? s.v : '')).join(' ')}`,
  );

  // "Request more info": launch a FOCUSED re-investigation that targets the
  // open questions behind this needs_more_info verdict. Same navigate/poll
  // handoff as reRun — the container switches to the new investigation id.
  const [requestingInfo, setRequestingInfo] = useState(false);
  const requestInfo = () => {
    if (requestingInfo) return;
    setRequestingInfo(true);
    requestMoreInfo(inv.id)
      .then((newId) => onReHunt?.(newId))
      .catch(() => {})
      .finally(() => setRequestingInfo(false));
  };

  const NET_ERR_TEXT = 'Could not reach the server — please try again.';

  // Apply a chat thread from the API; keep polling while the assistant works.
  // The pending assistant turn comes back with empty text — drop it and let the
  // typing indicator stand in until the real reply lands.
  const applyThread = (thread: ChatThread) => {
    setChat(thread.messages.filter((m) => m.text || m.role === 'user'));
    setPending(thread.pending);
    if (chatTimer.current) clearTimeout(chatTimer.current);
    if (thread.pending) {
      chatTimer.current = setTimeout(() => {
        getChatThread(inv.id).then(applyThread).catch(() => {
          setPending(false);
          // Only push the error message if the last message isn't already it
          // (repeated poll failures must not stack duplicate error bubbles).
          setChat((c) => {
            const last = c[c.length - 1];
            if (last?.role === 'assistant' && last.text === NET_ERR_TEXT) return c;
            return [...c, { role: 'assistant', text: NET_ERR_TEXT }];
          });
        });
      }, 1500);
    }
  };

  const send = () => {
    const t = draft.trim();
    // Block double-submit while a turn is in flight (matches the hunt chat).
    if (!t || pending) return;
    setChat((c) => [...c, { role: 'user', text: t }]);
    setDraft('');
    clearChatDraft(inv.id); // sent — drop the persisted draft
    setPending(true);
    postChat(inv.id, t).then(applyThread).catch(() => {
      setPending(false);
      setChat((c) => [...c, { role: 'assistant', text: NET_ERR_TEXT }]);
    });
  };

  // A citation [n] in the narrative points at the n-th timeline step — its
  // evidence. Clicking jumps there, expands the step, and flashes it.
  const goToCite = (n: number) => {
    const step = inv.timeline[n - 1];
    if (!step) return;
    setTimelineOpen(true); // reveal the timeline if the analyst collapsed it
    setOpenSteps((s) => ({ ...s, [step.id]: true }));
    setFlashStep(step.id);
    requestAnimationFrame(() =>
      document.getElementById(`tl-${step.id}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' })
    );
    window.setTimeout(() => setFlashStep((cur) => (cur === step.id ? null : cur)), 1600);
  };

  const pendingCount = inv.actions.filter((a) => !actions[a.id]).length;
  const graphInteresting =
    inv.edges.some((e) => e.kind === 'lateral') || inv.nodes.some((n) => n.kind === 'compromised');

  // ── composable section blocks (arranged differently per layout) ──────────
  const toolbarEl = (
    <div className="mb-3.5 flex items-center gap-2.5">
      <div className="text-[11px] font-semibold uppercase tracking-[.06em] text-faint">soc·ai verdict</div>
      <div className="flex-1" />
      {!running && (
        <button
          onClick={() => { setOverrideVerdictVal(inv.verdict); setOverrideRationale(''); setOverrideError(null); setOverrideOpen(true); }}
          className="flex items-center gap-1.5 rounded-control border border-border-strong bg-surface-3 px-[11px] py-1.5 text-[12px] font-semibold text-dim hover:border-warn hover:text-text"
        >
          <Scale size={13} />
          Override verdict
        </button>
      )}
      <button
        onClick={reRun}
        disabled={reHunting}
        className="flex items-center gap-1.5 rounded-control border border-border-strong bg-surface-3 px-[11px] py-1.5 text-[12px] font-semibold text-dim hover:border-accent hover:text-text disabled:opacity-60"
      >
        {reHunting ? <Spinner size={13} /> : <RotateCw size={13} />}
        {reHunting ? 'Re-running…' : 'Re-run investigation'}
      </button>
      {wasHeuristic && (
        <button
          onClick={reRunDeep}
          disabled={reHunting}
          title="This verdict came from the zero-tool fast path — re-run with the full tool-driven investigation loop instead"
          className="flex items-center gap-1.5 rounded-control border border-border-strong bg-surface-3 px-[11px] py-1.5 text-[12px] font-semibold text-dim hover:border-accent hover:text-text disabled:opacity-60"
        >
          {reHunting ? <Spinner size={13} /> : <Crosshair size={13} />}
          Deep re-run
        </button>
      )}
      <button
        onClick={() => { void downloadInvestigationExport(inv.id); }}
        title="Download the decision record (tools, cited events, verdict — JSON with a sha256 integrity checksum)"
        className="flex items-center gap-1.5 rounded-control border border-border-strong bg-surface-3 px-[11px] py-1.5 text-[12px] font-semibold text-dim hover:border-accent hover:text-text"
      >
        <Download size={13} />
        Export
      </button>
    </div>
  );

  const runningEl = (
    <div
      className="relative mb-[18px] overflow-hidden rounded-panel-lg border p-[18px]"
      style={{ borderColor: 'rgba(75,139,245,.32)', background: 'linear-gradient(180deg,rgba(75,139,245,.08),rgba(75,139,245,.02))' }}
    >
      <div className="absolute left-0 right-0 top-0 h-0.5 overflow-hidden">
        <div className="h-full w-[35%] animate-scanline-slow" style={{ background: 'linear-gradient(90deg,transparent,#4b8bf5,transparent)' }} />
      </div>
      <div className="flex items-center gap-[11px]">
        <Spinner size={17} />
        <div className="text-[15px] font-semibold">Investigating…</div>
        <div className="flex-1" />
        <div className="font-mono text-[12.5px] text-dim">
          elapsed <span className="text-text">{fmt(elapsed)}</span>
        </div>
      </div>
      <div className="mt-[11px] flex items-center gap-[9px] font-mono text-[12px] text-dim">
        <span className="text-accent">steps</span> <span className="text-text-2">{inv.timeline.length}</span>
        <span className="text-ghost">·</span> <span className="text-accent">tool calls</span>{' '}
        <span className="text-text-2">{inv.meta?.toolCalls ?? 0}</span>
      </div>
      <div className="mt-3 flex flex-col gap-1.5 text-[12.5px] text-dim">
        {inv.timeline.slice(-3).map((s) => (
          <div key={s.id} className="flex items-center gap-2">
            <span className="text-success">✓</span> {s.title}
          </div>
        ))}
        <div className="flex items-center gap-2 text-text-2">
          <Spinner size={11} /> Working…
        </div>
      </div>
    </div>
  );

  // Terminal failure: a reaped/interrupted run (status 'error') OR one the
  // client-side stuck-guard gave up on. Replaces both the spinner and the
  // (empty) verdict so the analyst never stares at "Investigating…" forever.
  const failedEl = (
    <div
      className="relative mb-[18px] overflow-hidden rounded-panel-lg border p-[18px]"
      style={{ borderColor: 'rgba(240,68,56,.32)', background: 'linear-gradient(180deg,rgba(240,68,56,.07),rgba(240,68,56,.02))' }}
    >
      <div className="flex items-center gap-[11px]">
        <span className="flex text-danger"><AlertTriangle size={18} /></span>
        <div className="text-[15px] font-semibold">
          {stuck && inv.status === 'investigating'
            ? 'This investigation seems stuck'
            : interrupted
              ? 'This investigation was interrupted by a restart'
              : cancelled
                ? 'This investigation was cancelled before it finished'
                : 'This investigation failed or was interrupted'}
        </div>
        <div className="flex-1" />
        <div className="font-mono text-[12.5px] text-faint">elapsed {fmt(elapsed)}</div>
      </div>
      <div className="mt-2 text-[13px] leading-[1.55] text-dim" style={{ textWrap: 'pretty' }}>
        {interrupted
          ? 'No verdict yet — the service restarted while this was running. It will be re-investigated automatically if Auto-Investigate is on, or re-run it now.'
          : cancelled
            ? 'No verdict was reached — the run was stopped (an operator cancel, or the service restarting) before it finished. Re-run it to get a verdict.'
            : 'No verdict was reached. The run may have stalled or the agent crashed mid-flight — re-run it to try again.'}
      </div>
      <div className="mt-[14px]">
        <button
          onClick={reRun}
          disabled={reHunting}
          className="flex items-center gap-1.5 rounded-control border border-danger bg-[rgba(240,68,56,.1)] px-4 py-2 text-[13px] font-semibold text-[#fca5a5] hover:bg-[rgba(240,68,56,.18)] disabled:opacity-60"
        >
          {reHunting ? <Spinner size={13} color="#fca5a5" /> : <RotateCw size={13} />}
          {reHunting ? 'Re-running…' : 'Re-run investigation'}
        </button>
      </div>
    </div>
  );

  const verdictEl = (
    <>
    <div
      className="relative overflow-hidden rounded-panel-lg border p-5"
      style={{
        borderColor: v.border,
        background: `linear-gradient(180deg,${v.wash},rgba(11,14,19,0) 70%),#0b0e13`,
      }}
    >
      <div className="absolute left-0 top-0 h-full w-[3px]" style={{ background: v.color }} />
      <div className="mb-3.5 flex flex-wrap items-center gap-2.5">
        <VerdictPill verdict={inv.verdict} large />
        {demo && <RecordedRunChip />}
        {inv.sev && <SeverityTag sev={inv.sev} />}
        {/* min-w-0 + max-w-full + break-all: the badge may use the whole header
            row and wraps internally when genuinely out of space — the FULL
            destination is always visible, never clipped to a fragment. */}
        <span
          className="min-w-0 max-w-full rounded-badge border border-border-input px-2 py-[3px] font-mono text-[12px] text-dim"
          title={`source ${inv.host} → destination ${inv.ip}`}
        >
          <span className="break-all text-mono-amber">{inv.host}</span>
          <span className="text-faint"> → </span>
          <span className="break-all text-mono-green">{inv.ip}</span>
        </span>
        {inv.oracle?.escalated && (
          <OracleBadge oracle={inv.oracle} />
        )}
        {inv.status === 'complete' && inv.meta?.toolCalls === 0 && <HeuristicBadge />}
        <div className="flex-1" />
        <div className="flex items-center gap-[9px]">
          <ConfidenceRing conf={inv.conf} color={v.color} />
          <div>
            <div className="font-mono text-[18px] font-bold leading-none">{inv.conf.toFixed(2)}</div>
            <div className="text-[10.5px] uppercase tracking-[.05em] text-faint">confidence</div>
          </div>
        </div>
      </div>

      {/* rationale as headline */}
      <div className="text-[21px] font-semibold leading-[1.32] tracking-[-.015em]" style={{ textWrap: 'pretty' }}>
        {inv.rationale}
      </div>

      {/* summary with citations */}
      <p className="mt-3.5 text-[13.5px] leading-[1.6] text-[#aeb6c2]" style={{ textWrap: 'pretty' }}>
        <Summary segments={inv.summary} onCite={goToCite} />
      </p>
      {/* Close the tuning loop: a verdict that cites the rule-tuning tool
          ("tuning recommends mute") gets a direct path to the Mute button —
          the recommendation used to dead-end in prose (dogfood 2026-07-15). */}
      {tuningCited && (
        <button
          onClick={() => navigate('/config#detection-tuning')}
          className="mt-3 flex items-center gap-1.5 text-[12.5px] font-semibold text-accent hover:underline"
        >
          <Wrench size={13} />
          Review the detection-tuning suggestion for this rule
        </button>
      )}
    </div>
    {inv.oracle?.escalated && (
      <OracleCard oracle={inv.oracle} />
    )}
    {/* Pipeline-failure panel (E1.2). A fallback run is a needs_more_info the
        pipeline never reasoned to (model truncation, gateway 5xx). Render an
        honest "failed before reaching a verdict" panel + a Re-run (same
        startHunt path as the terminal-failure banner) INSTEAD of the amber
        open-questions block below — re-running is the fix, not "dig deeper". */}
    {inv.fallback && (
      <div
        className="mb-3 rounded-card border px-3.5 py-3"
        style={{ borderColor: 'rgba(240,68,56,.32)', background: 'rgba(240,68,56,.06)' }}
      >
        <div className="mb-1.5 flex items-center gap-2 text-[12px] font-semibold uppercase tracking-[.05em]" style={{ color: '#fca5a5' }}>
          <Wrench size={13} /> Pipeline error
        </div>
        <div className="mb-2.5 text-[13px] leading-[1.55] text-text-2" style={{ textWrap: 'pretty' }}>
          This run failed before reaching a verdict
          {inv.fallback.hint ? <>: {inv.fallback.hint}</> : '.'}
          {' '}It was recorded as needs_more_info as a placeholder — re-run it to get a real verdict.
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={reRun}
            disabled={reHunting}
            className="flex items-center gap-1.5 rounded-control border border-danger bg-[rgba(240,68,56,.1)] px-4 py-2 text-[12.5px] font-semibold text-[#fca5a5] hover:bg-[rgba(240,68,56,.18)] disabled:opacity-60"
          >
            {reHunting ? <Spinner size={13} color="#fca5a5" /> : <RotateCw size={13} />}
            {reHunting ? 'Re-running…' : 'Re-run investigation'}
          </button>
          {errorDismissed ? (
            <span className="flex items-center gap-1.5 text-[12.5px] text-dim">
              <Check size={13} /> Dismissed — no longer counted on the Dashboard
            </span>
          ) : (
            <button
              onClick={dismissError}
              disabled={errDismiss === 'busy'}
              title="Acknowledge this pipeline error — the Dashboard stops counting it; the run stays under the Investigations 'Pipeline error' filter"
              className="flex items-center gap-1.5 rounded-control border border-border-strong bg-surface-3 px-4 py-2 text-[12.5px] font-semibold text-dim hover:border-accent hover:text-text disabled:opacity-60"
            >
              {errDismiss === 'busy' ? <Spinner size={13} /> : <X size={13} />}
              {errDismiss === 'busy' ? 'Dismissing…' : 'Dismiss'}
            </button>
          )}
        </div>
        {errDismissMsg && (
          <div className="mt-2 text-[12px]" style={{ color: '#f04438' }}>
            {errDismissMsg}
          </div>
        )}
      </div>
    )}
    {/* Open-questions / follow-up block. Also shown for an `inconclusive`
        verdict (the self-consistency vote didn't converge) even without
        structured open questions — it's a terminal non-committed verdict like
        needs_more_info, and the request-more-info endpoint accepts it too.
        SUPPRESSED for a pipeline fallback — the panel above replaces it. */}
    {!inv.fallback && ((inv.openQuestions?.length ?? 0) > 0 || inv.verdict === 'inconclusive') && (
      <div
        className="mb-3 rounded-card border px-3.5 py-3"
        style={{ borderColor: 'rgba(245,166,35,.35)', background: 'rgba(245,166,35,.06)' }}
      >
        <div className="mb-1.5 text-[12px] font-semibold uppercase tracking-[.05em]" style={{ color: '#f5a623' }}>
          {inv.verdict === 'needs_more_info' || inv.verdict === 'inconclusive'
            ? 'Open questions'
            : 'Residual open questions'}
        </div>
        {(inv.openQuestions?.length ?? 0) > 0 ? (
          <ul className="mb-2.5 list-disc pl-5 text-[13px] text-text-2">
            {inv.openQuestions!.map((q, i) => <li key={i} className="mb-0.5">{q}</li>)}
          </ul>
        ) : (
          <div className="mb-2.5 text-[13px] text-text-2">
            The model could not converge on a verdict — dig deeper with a focused
            re-investigation, or resolve it in chat.
          </div>
        )}
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={requestInfo}
            disabled={requestingInfo}
            title="Launch a fresh investigation focused on the open questions above"
            className="flex items-center gap-1.5 rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold text-[#0b0f16] disabled:opacity-60"
            style={{ background: '#f5a623', borderColor: '#f5a623' }}
          >
            {requestingInfo ? <Spinner size={13} /> : <Crosshair size={13} />}
            {requestingInfo ? 'Requesting…' : 'Request more info'}
          </button>
          <button
            onClick={() => document.querySelector('[data-chat-panel]')?.scrollIntoView({ behavior: 'smooth' })}
            className="flex items-center gap-1.5 rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold text-[#cfe0ff]"
            style={{ background: 'rgba(75,139,245,.14)', borderColor: 'rgba(75,139,245,.4)' }}
          >
            <span className="flex" style={{ color: '#facc15' }}><Zap size={13} /></span> Resolve in chat
          </button>
        </div>
      </div>
    )}
    {inv.resolution?.resolved_via === 'manual' && (
      <div
        className="rounded-card border px-3.5 py-2.5 text-[12px] text-dim"
        style={{ borderColor: 'rgba(245,166,35,.35)', background: 'rgba(245,166,35,.06)' }}
      >
        <span style={{ color: '#f5a623' }}>Manually overridden</span> by{' '}
        <span className="font-mono text-text-2">{inv.resolution.resolved_by}</span>
        {' '}— was:{' '}
        <span className="font-mono text-text-2">{inv.resolution.original_verdict}</span>
      </div>
    )}
    {inv.validatorNote && (
      <div
        className="rounded-card border px-3.5 py-2.5 text-[12px] text-dim"
        style={{ borderColor: 'rgba(107,135,168,.3)', background: 'rgba(107,135,168,.05)' }}
      >
        <span className="font-semibold" style={{ color: '#8fa3bf' }}>Post-validator override</span>
        {' — '}
        {inv.validatorNote}
      </div>
    )}
    </>
  );

  // entity scope — collapsible (defaults closed; opens itself when lateral
  // movement / a compromised node makes the blast radius worth seeing). The
  // collapsed bar carries a one-line narrative so it's useful without expanding.
  const blastNarrative =
    inv.graphNote ??
    `${inv.nodes.length} entities, ${inv.edges.length} relationships${graphInteresting ? ' — lateral movement detected' : ''}`;
  const graphHeight = layout === 'page' ? 320 : 240;
  const entityEl = (
    <Panel>
      <button
        onClick={() => setGraphOpen((o) => !o)}
        aria-expanded={graphOpen}
        className="flex w-full items-start gap-[9px] px-[15px] py-[11px] text-left hover:bg-surface-hover"
      >
        <span className="flex pt-px text-accent"><Crosshair size={15} /></span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <div className="text-[13px] font-semibold">Entity scope — blast radius</div>
            <span className="font-mono text-[11px] text-faint">
              {inv.nodes.length} entities
              {!graphOpen && graphInteresting ? ' · lateral movement' : ''}
            </span>
          </div>
          {!graphOpen && (
            <div className="mt-1 text-[12px] leading-[1.5] text-dim" style={{ textWrap: 'pretty' }}>
              {blastNarrative}
            </div>
          )}
        </div>
        <span className="flex pt-0.5 text-ghost transition-transform" style={{ transform: graphOpen ? 'rotate(180deg)' : 'rotate(0deg)' }}>
          <ChevronDown size={15} />
        </span>
      </button>
      {graphOpen && (
        <div className="border-t border-border">
          <EntityGraph nodes={inv.nodes} edges={inv.edges} highlight={inv.host} height={graphHeight} showLegend={layout === 'page'} />
        </div>
      )}
    </Panel>
  );

  // Token-gated actions execute when the approval is approved; advisory ones (a
  // completed run's recommendations) execute on demand through the same write
  // path. The card's explicit Approve click IS the human consent — these write
  // to the live Security Onion grid.
  const runAdvisory = (a: RecommendedAction, index: number) => {
    const blocked = demoBlocked(demo);
    if (blocked) { setActionMsg((m) => ({ ...m, [a.id]: blocked })); return; } // demo: no doomed grid write
    setActions((s) => ({ ...s, [a.id]: 'executing' }));
    setActionMsg((m) => ({ ...m, [a.id]: '' }));
    executeAction(inv.id, index)
      .then((res) => {
        if (res.status === 'executed') {
          setActions((s) => ({ ...s, [a.id]: 'approved' }));
          setActionMsg((m) => ({ ...m, [a.id]: res.detail }));
          // The backend ack is group-scoped — let the Alerts list hide the
          // whole detection optimistically while the ES agg catches up.
          if (a.tag === 'ack') onAcked?.(inv.name);
        } else {
          setActions((s) => ({ ...s, [a.id]: 'failed' }));
          setActionMsg((m) => ({ ...m, [a.id]: res.error ?? 'execution failed' }));
        }
      })
      .catch((e) => {
        setActions((s) => ({ ...s, [a.id]: 'failed' }));
        setActionMsg((m) => ({ ...m, [a.id]: e instanceof Error ? e.message : 'request failed' }));
      });
  };
  const actionsEl = (
    <CollapsibleSection
      title="Recommended actions"
      meta={`human-in-the-loop · ${pendingCount} pending`}
    >
      <div className="flex flex-col gap-2.5">
        {inv.actions.map((a, i) => (
          <ActionCard
            key={a.id}
            action={a}
            decision={actions[a.id]}
            message={actionMsg[a.id]}
            executedBy={me ?? 'you'}
            onApprove={() => runAdvisory(a, i)}
            onReject={() => setActions((s) => ({ ...s, [a.id]: 'rejected' }))}
          />
        ))}
      </div>
    </CollapsibleSection>
  );

  // A complete run that recommended NO write actions still leaves the analyst
  // with a decision to make. This fallback bar routes an ack (close it out) or
  // an escalate (open a case) through the same group write path the Alerts
  // console uses — writing to the live Security Onion grid. The labeled button
  // click is the consent; no extra popup.
  const runSettled = (kind: 'ack' | 'escalate') => {
    setSettledAction(kind);
    setSettledMsg(null);
    const group = { name: inv.name, kind: inv.kind };
    const call =
      kind === 'ack'
        ? ackGroup(group).then((r) => `Acknowledged ${r.acked} of ${r.total} event${r.total === 1 ? '' : 's'}.`)
        : escalateGroup(group).then(
            (r) => `Escalated ${r.escalated} of ${r.total} event${r.total === 1 ? '' : 's'} to a case.`,
          );
    call
      .then((text) => {
        setSettledMsg({ tone: 'ok', text });
        if (kind === 'ack') onAcked?.(inv.name);
      })
      .catch((e) => setSettledMsg({ tone: 'err', text: e instanceof Error ? e.message : 'request failed' }))
      .finally(() => setSettledAction(null));
  };
  // Suppressed for a pipeline fallback: the run FAILED before reaching a
  // verdict — offering "verdict settled, acknowledge it" directly under the
  // "re-run to get a real verdict" panel contradicts the only sane next step.
  const settledActionEl =
    inv.status === 'complete' && inv.actions.length === 0 && !inv.fallback ? (
      <div
        className="rounded-card border px-3.5 py-3"
        style={{ borderColor: 'rgba(245,166,35,.35)', background: 'rgba(245,166,35,.06)' }}
      >
        <div className="mb-1.5 text-[12px] font-semibold uppercase tracking-[.05em]" style={{ color: '#f5a623' }}>
          Verdict settled — take action
        </div>
        <p className="mb-2.5 text-[13px] leading-[1.5] text-text-2">
          The investigation recommended no automatic actions. Acknowledge to close out
          this detection, or escalate it to a Security Onion case.
        </p>
        {inv.alertAcked && (
          <p className="mb-2.5 text-[12px] leading-[1.5] text-dim">
            <span style={{ color: '#7ba893' }}>✓ This alert is already acknowledged in Security Onion</span>
            {' '}— acknowledging here re-acks the whole detection group.
          </p>
        )}
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => runSettled('ack')}
            disabled={settledAction !== null}
            className="flex items-center gap-1.5 rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold text-text-2 hover:text-text disabled:opacity-60"
            style={{ borderColor: 'rgba(123,168,147,.4)', background: 'rgba(123,168,147,.10)' }}
          >
            {settledAction === 'ack' ? <Spinner size={13} /> : <Check size={13} />}
            {settledAction === 'ack' ? 'Acknowledging…' : 'Acknowledge'}
          </button>
          <button
            onClick={() => runSettled('escalate')}
            disabled={settledAction !== null}
            className="flex items-center gap-1.5 rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold disabled:opacity-60"
            style={{ borderColor: 'rgba(240,68,56,.4)', background: 'rgba(240,68,56,.10)', color: '#fca5a5' }}
          >
            {settledAction === 'escalate' ? <Spinner size={13} /> : <Triangle size={13} />}
            {settledAction === 'escalate' ? 'Escalating…' : 'Escalate to case'}
          </button>
          {settledMsg && (
            <span
              className="text-[12px] font-semibold"
              style={{ color: settledMsg.tone === 'ok' ? '#7ba893' : '#f04438' }}
            >
              {settledMsg.text}
            </span>
          )}
        </div>
      </div>
    ) : null;

  const timelineEl = (
    <CollapsibleSection
      title="Investigation timeline"
      meta={`${inv.timeline.length} steps · ${inv.elapsedLabel}`}
      open={timelineOpen}
      onToggle={() => setTimelineOpen((o) => !o)}
    >
      <Panel>
        {inv.timeline.map((step, i) => (
          <TimelineRow
            key={step.id}
            step={step}
            last={i === inv.timeline.length - 1}
            open={!!openSteps[step.id]}
            flash={flashStep === step.id}
            onToggle={() => setOpenSteps((s) => ({ ...s, [step.id]: !s[step.id] }))}
          />
        ))}
      </Panel>
    </CollapsibleSection>
  );

  const reasoning = inv.reasoning ?? [];
  const reasoningEl =
    reasoning.length > 0 ? (
      <CollapsibleSection
        title="Model reasoning"
        meta={`${reasoning.length} step${reasoning.length === 1 ? '' : 's'} · why it decided`}
        open={reasoningOpen}
        onToggle={() => setReasoningOpen((o) => !o)}
      >
        <Panel>
          <div className="flex flex-col gap-3 p-1">
            {reasoning.map((r, i) => (
              <div key={i} className="rounded-control border border-border-2 bg-bg p-2.5">
                <div className="mb-1 font-mono text-[10.5px] uppercase tracking-[.06em] text-faint">
                  turn {i + 1}
                </div>
                {/* The model writes its reasoning in markdown — render it,
                    don't dump the raw syntax (dogfood follow-up 2026-07-16). */}
                <div className="text-[12px] leading-relaxed text-dim">
                  <Markdown>{r}</Markdown>
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </CollapsibleSection>
    ) : null;

  const onResolved = () =>
    getChatThread(inv.id).then(applyThread).catch(() => {}).finally(() => onVerdictApplied?.());
  const chatProps = { messages: chat, pending, draft, onDraft: setDraft, onSend: send, invId: inv.id, onResolved };

  // ── Override verdict modal ────────────────────────────────────────────────
  const overrideModalEl = overrideOpen ? (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: 'rgba(0,0,0,.65)' }}
      onClick={(e) => { if (e.target === e.currentTarget) setOverrideOpen(false); }}
    >
      <div
        className="relative w-[440px] max-w-[calc(100vw-32px)] rounded-panel-lg border p-6"
        style={{ background: '#0e1117', borderColor: '#1c232e' }}
      >
        <button
          onClick={() => setOverrideOpen(false)}
          className="absolute right-4 top-4 text-ghost hover:text-text"
          aria-label="Close"
        >
          <X size={16} />
        </button>
        <div className="mb-4 text-[14px] font-semibold">Override verdict</div>
        <div
          className="mb-4 flex items-start gap-2 rounded-[7px] border px-3 py-2.5 text-[12.5px] leading-[1.5]"
          style={{ borderColor: 'rgba(240,68,56,.35)', background: 'rgba(240,68,56,.07)', color: '#fca5a5' }}
        >
          <AlertTriangle size={13} className="mt-px flex-none" />
          <span><span className="font-semibold">WARNING:</span> You are manually overriding the AI's verdict. This replaces the current verdict
          and is permanently recorded with your name.</span>
        </div>
        <div className="mb-3">
          <label className="mb-1.5 block text-[12px] font-semibold text-dim">New verdict</label>
          <select
            value={overrideVerdictVal}
            onChange={(e) => setOverrideVerdictVal(e.target.value)}
            className="w-full rounded-control border border-border-input bg-bg px-3 py-2 text-[13px] text-text outline-none focus:border-accent"
          >
            <option value="true_positive">true_positive</option>
            <option value="false_positive">false_positive</option>
            <option value="needs_more_info">needs_more_info</option>
          </select>
        </div>
        <div className="mb-5">
          <label className="mb-1.5 block text-[12px] font-semibold text-dim">
            Rationale <span className="text-faint font-normal">(optional — recorded)</span>
          </label>
          <textarea
            value={overrideRationale}
            onChange={(e) => setOverrideRationale(e.target.value)}
            rows={3}
            placeholder="Why are you overriding? e.g. analyst confirmed via manual PCAP review."
            className="w-full rounded-control border border-border-input bg-bg px-3 py-2 text-[13px] text-text outline-none focus:border-accent"
          />
        </div>
        {overrideError && (
          <div className="mb-3 rounded-[7px] border px-3 py-2 text-[12px] text-danger" style={{ borderColor: 'rgba(240,68,56,.35)', background: 'rgba(240,68,56,.07)' }}>
            {overrideError}
          </div>
        )}
        <div className="flex justify-end gap-2.5">
          <button
            onClick={() => setOverrideOpen(false)}
            className="rounded-control border border-border-strong bg-surface-3 px-4 py-2 text-[13px] font-semibold text-text-2 hover:text-text"
          >
            Cancel
          </button>
          <button
            disabled={overriding}
            onClick={() => {
              const blocked = demoBlocked(demo);
              if (blocked) { setOverrideError(blocked); return; } // demo: no doomed write
              setOverriding(true);
              setOverrideError(null);
              submitOverride(inv.id, overrideVerdictVal, overrideRationale || undefined)
                .then(() => { setOverrideOpen(false); onVerdictApplied?.(); })
                .catch((err: unknown) => {
                  const msg = err instanceof Error ? err.message : 'Override failed — please try again.';
                  setOverrideError(msg);
                })
                .finally(() => setOverriding(false));
            }}
            className="flex items-center gap-1.5 rounded-control border border-warn bg-[rgba(245,166,35,.12)] px-4 py-2 text-[13px] font-semibold text-warn hover:bg-[rgba(245,166,35,.2)] disabled:opacity-60"
          >
            {overriding ? <Spinner size={13} /> : <Check size={13} />}
            {overriding ? 'Applying…' : 'Confirm override'}
          </button>
        </div>
      </div>
    </div>
  ) : null;

  // analyst-context rail panels (only render when the data is present)
  const alertEl = inv.alert ? <AlertDetailsPanel alert={inv.alert} sev={inv.sev} kind={inv.kind} /> : null;
  const hostEl = inv.hostContext?.length ? <HostContextPanel host={inv.host} signals={inv.hostContext} /> : null;
  const metaEl = inv.meta ? <InvMetaPanel meta={inv.meta} id={inv.id} /> : null;

  // ── PAGE (permalink): two-column workstation layout ──────────────────────
  // Verdict spans full width as the hero. The wide main column carries the
  // analyst's first-class surfaces — the blast-radius graph (collapsed), actions,
  // and the timeline. The right rail holds collapsible reference panels (alert,
  // host, metadata). Chat is a floating dock (bottom-right), so it costs no
  // layout space and stays reachable however far you've scrolled.
  if (layout === 'page') {
    return (
      <div className="mx-auto max-w-workstation font-sans text-text">
        {toolbarEl}
        {failed ? (
          <>
            {failedEl}
            {/* Whatever partial steps ran before the failure are still useful. */}
            {inv.timeline.length > 0 && <div className="mt-[18px]">{timelineEl}</div>}
          </>
        ) : (
          <>
            {running && runningEl}
            {verdictEl}
            <div className="mt-[18px] grid grid-cols-1 items-start gap-[18px] lg:grid-cols-[minmax(0,1fr)_360px]">
              <div className="flex min-w-0 flex-col gap-[18px]">
                {inv.nodes.length > 0 && entityEl}
                {inv.actions.length > 0 ? actionsEl : settledActionEl}
                {timelineEl}
                {reasoningEl}
              </div>
              <div className="flex flex-col gap-[18px]">
                {alertEl}
                {hostEl}
                {metaEl}
              </div>
            </div>
            <ChatDock {...chatProps} />
          </>
        )}
        {overrideModalEl}
      </div>
    );
  }

  // ── DRAWER: compact single column ────────────────────────────────────────
  return (
    <div className="font-sans text-text" style={{ padding: '18px 18px 30px' }}>
      {toolbarEl}
      {failed ? (
        <>
          {failedEl}
          {/* Whatever partial steps ran before the failure are still useful. */}
          {inv.timeline.length > 0 && <div className="mt-5">{timelineEl}</div>}
        </>
      ) : (
        <>
          {running && runningEl}
          {verdictEl}
          {inv.nodes.length > 0 && <div className="mt-[18px]">{entityEl}</div>}
          <div className="mt-[18px]">{inv.actions.length > 0 ? actionsEl : settledActionEl}</div>
          <div className="mt-5">{timelineEl}</div>
          {reasoningEl && <div className="mt-5">{reasoningEl}</div>}
          <div className="mt-5">
            <ChatPanel {...chatProps} />
          </div>
        </>
      )}
      {overrideModalEl}
    </div>
  );
}

// Scoped follow-up chat. `fill` makes it stretch to its parent's height (the
// viewport-tall sticky rail) with an internally-scrolling message list; without
// it the message list is a fixed 260–460px band (the compact drawer).
// Rendering (header, bubbles, typing dots, input row) is the shared
// ChatPanelShell; this wrapper adds the investigation-specific bits — the
// data-chat-panel scroll target and the chat-proposed-verdict cards.
function ChatPanel({
  messages,
  pending,
  draft,
  onDraft,
  onSend,
  fill,
  onClose,
  invId,
  onResolved,
}: {
  messages: ChatMessage[];
  pending: boolean;
  draft: string;
  onDraft: (v: string) => void;
  onSend: () => void;
  fill?: boolean;
  onClose?: () => void;
  invId: string;
  onResolved: () => void;
}) {
  // Apply-verdict feedback, keyed by the proposal's message index: which one is
  // mid-apply, and a per-message error string so a failed apply surfaces (and
  // re-enables the button) instead of being silently swallowed.
  const [applyingIdx, setApplyingIdx] = useState<number | null>(null);
  const [applyError, setApplyError] = useState<Record<number, string>>({});

  const applyProposal = (idx: number, messageId: number | null | undefined, token: string | undefined) => {
    if (messageId == null || !token || applyingIdx != null) return;
    setApplyingIdx(idx);
    setApplyError((e) => {
      const { [idx]: _drop, ...rest } = e;
      return rest;
    });
    resolveInvestigation(invId, messageId, token)
      .then(onResolved)
      .catch((err: unknown) => {
        setApplyError((e) => ({
          ...e,
          [idx]: err instanceof Error ? err.message : 'Could not apply — please try again.',
        }));
      })
      .finally(() => setApplyingIdx(null));
  };

  return (
    // wrapper carries the scroll target; h-full in fill mode preserves the
    // height chain ChatDock relies on (Panel's h-full resolves against it)
    <div data-chat-panel className={fill ? 'h-full' : undefined}>
      <ChatPanelShell
        title="Chat about this investigation"
        scopeLabel="scoped to this investigation"
        placeholder="Ask a follow-up… e.g. why not a false positive?"
        listSizeClass={fill ? 'min-h-0 flex-1' : 'max-h-[460px] min-h-[260px]'}
        messages={messages}
        pending={pending}
        draft={draft}
        onDraft={onDraft}
        onSend={onSend}
        fill={fill}
        onClose={onClose}
        renderSpecial={(m, i) =>
          m.role !== 'user' && m.kind === 'verdict_proposal' && m.proposal ? (
            <div key={i} className="max-w-[88%] min-w-0 self-start break-words rounded-card border px-3 py-2.5"
                 style={{ borderColor: 'rgba(75,139,245,.35)', background: 'rgba(75,139,245,.06)' }}>
              <div className="mb-1 flex items-center gap-2 text-[12px] font-semibold text-text-2">
                Proposed verdict
                <VerdictPill verdict={m.proposal.verdict} conf={m.proposal.confidence} />
              </div>
              <div className="mb-2 text-[13px] text-text-2">{m.proposal.rationale}</div>
              {m.validation === 'pass' && !m.applied ? (
                <>
                  <button
                    disabled={applyingIdx === i}
                    onClick={() => applyProposal(i, m.messageId, m.token)}
                    className="flex items-center gap-1.5 rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold text-[#cfe0ff] disabled:opacity-60"
                    style={{ background: 'rgba(75,139,245,.14)', borderColor: 'rgba(75,139,245,.4)' }}
                  >
                    {applyingIdx === i && <Spinner size={12} />}
                    {applyingIdx === i ? 'Applying…' : 'Apply verdict'}
                  </button>
                  {applyError[i] && (
                    <div className="mt-1.5 text-[11.5px] text-danger">{applyError[i]}</div>
                  )}
                </>
              ) : m.applied ? (
                <div className="text-[12px] font-semibold text-success">✓ Applied</div>
              ) : (
                <div className="text-[12px] text-warn">Not evidence-backed{m.objection ? ` — ${m.objection}` : ''}</div>
              )}
            </div>
          ) : null
        }
      />
    </div>
  );
}

type ChatPanelProps = Parameters<typeof ChatPanel>[0];

// Floating chat: a launcher pinned bottom-right of the viewport that opens the
// scoped chat as a docked panel. Costs no layout space and stays reachable no
// matter how far you've scrolled the evidence.
function ChatDock(props: Omit<ChatPanelProps, 'fill' | 'onClose'>) {
  const msgCount = props.messages.length;
  return (
    <ChatDockShell label={msgCount > 0 ? `Chat · ${msgCount}` : 'Chat about this'}>
      {(close) => <ChatPanel {...props} fill onClose={close} />}
    </ChatDockShell>
  );
}

// ── analyst-context rail panels (page layout) ──────────────────────────────

function AlertDetailsPanel({ alert, sev, kind }: { alert: AlertMeta; sev?: Severity; kind: DetectionKind }) {
  const [copied, setCopied] = useState(false);

  const copyId = () => {
    if (!alert.id) return;
    navigator.clipboard.writeText(alert.id).then(() => {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    }).catch(() => {});
  };

  const rows: [string, ReactNode][] = [
    ['rule', <span className="text-text-2">{alert.rule}</span>],
    ['sid', alert.sid],
    ['classtype', alert.classtype],
    ['category', alert.category],
    ['source', <span className="text-mono-amber">{alert.src}</span>],
    ['dest', <span className="text-mono-green">{alert.dst}</span>],
    ['proto', alert.proto],
    ['action', alert.action],
    ['alert time', <span title={alert.time ?? undefined}>{absTime(alert.time)}</span>],
    ['events', `${alert.count}`],
  ];
  return (
    <CollapsiblePanel
      icon={<AlertTriangle size={15} />}
      title="Alert details"
      right={
        <div className="flex items-center gap-1.5">
          {sev && <SeverityTag sev={sev} />}
          <KindBadge kind={kind} />
        </div>
      }
      summary={alert.rule}
    >
      <div className="flex flex-col">
        {alert.id && (
          <div className="flex gap-3 border-b border-border-faint px-[15px] py-[7px] text-[12px]">
            <div className="w-[72px] flex-none text-faint">alert id</div>
            <div className="flex min-w-0 flex-1 items-center gap-1.5">
              <span className="min-w-0 flex-1 break-all font-mono text-[11.5px] text-text-2 select-all">
                {alert.id}
              </span>
              <button
                onClick={copyId}
                title="Copy alert id"
                aria-label="Copy alert id"
                className="flex-none rounded-[4px] p-[3px] text-ghost hover:bg-surface-3 hover:text-dim"
              >
                {copied ? <Check size={12} className="text-success" /> : <Copy size={12} />}
              </button>
            </div>
          </div>
        )}
        {rows.map(([k, val]) =>
          val == null ? null : (
            <div key={k} className="flex gap-3 border-b border-border-faint px-[15px] py-[7px] text-[12px] last:border-0">
              <div className="w-[72px] flex-none text-faint">{k}</div>
              <div className="min-w-0 flex-1 break-words font-mono text-text-2">{val}</div>
            </div>
          )
        )}
      </div>
    </CollapsiblePanel>
  );
}

function HostContextPanel({ host, signals }: { host: string; signals: HostSignal[] }) {
  return (
    <CollapsiblePanel
      icon={<Activity size={15} />}
      title="Host context"
      right={<div className="font-mono text-[11px] text-mono-amber">{host}</div>}
      summary={`${signals.length} risk signals on this host`}
    >
      <div className="flex flex-col gap-2.5 p-[14px]">
        {signals.map((s, i) => (
          <div key={i}>
            <div className="flex items-center gap-2 text-[12px]">
              <span className="font-mono text-faint">{s.time}</span>
              <span className="min-w-0 flex-1 truncate text-text-2" title={s.label}>{s.label}</span>
              <span className="flex-none font-mono text-[10.5px]" style={{ color: SEV_COLOR[s.tone] }}>{s.sev}</span>
            </div>
            <div className="mt-1 h-1 overflow-hidden rounded-full bg-surface-3">
              <div className="h-full origin-left animate-barGrow rounded-full" style={{ width: `${s.w}%`, background: SEV_COLOR[s.tone] }} />
            </div>
          </div>
        ))}
      </div>
    </CollapsiblePanel>
  );
}

// ── Oracle adjudication components ───────────────────────────────────────────

/** Compact pill shown in the verdict header row when Oracle was consulted. */
/** Muted chip flagging a verdict reached from prefetched context, no tool calls. */
function HeuristicBadge() {
  return (
    <span
      title="This verdict was reached from prefetched context without running investigation tools — it may be shallower. Disable 'Fast verdict' in Config to always investigate."
      className="flex cursor-help items-center gap-1.5 rounded-badge border border-border-input px-2 py-[3px] text-[11.5px] font-semibold text-faint"
      style={{ background: 'rgba(148,163,184,.07)' }}
    >
      <Wrench size={11} />
      heuristic · no tools
    </span>
  );
}

function OracleBadge({ oracle }: { oracle: OracleAdjudication }) {
  const overrode = oracle.changed;
  const hasVerdict = !!oracle.oracleVerdict;
  const label = overrode
    ? `Oracle overrode: ${oracle.localVerdict} → ${oracle.oracleVerdict}`
    : hasVerdict
      ? `Oracle upheld ${oracle.oracleVerdict}`
      : 'Oracle consulted';
  const borderColor = overrode ? 'rgba(139,92,246,.55)' : 'rgba(139,92,246,.3)';
  const bg = overrode ? 'rgba(139,92,246,.18)' : 'rgba(139,92,246,.07)';
  const textColor = overrode ? '#c4b5fd' : '#a78bfa';
  return (
    <span
      className="flex items-center gap-1.5 rounded-badge border px-2 py-[3px] text-[11.5px] font-semibold"
      style={{ borderColor, background: bg, color: textColor }}
    >
      <Scale size={11} />
      {label}
    </span>
  );
}

/** Broken-out Oracle adjudication card rendered below the verdict hero block. */
function OracleCard({ oracle }: { oracle: OracleAdjudication }) {
  const overrode = oracle.changed;
  return (
    <div
      className="rounded-card border px-3.5 py-3"
      style={{
        borderColor: 'rgba(139,92,246,.35)',
        background: 'rgba(139,92,246,.06)',
      }}
    >
      {/* header */}
      <div className="mb-2.5 flex items-center gap-2">
        <span style={{ color: '#a78bfa' }}><Scale size={14} /></span>
        <span className="text-[12px] font-semibold uppercase tracking-[.05em]" style={{ color: '#a78bfa' }}>
          Oracle adjudication
        </span>
        {oracle.model && (
          <span className="ml-auto font-mono text-[11px] text-faint">{oracle.model}</span>
        )}
      </div>

      {/* escalation reason */}
      {oracle.reason && (
        <div className="mb-2 text-[12px] text-dim">
          <span className="text-faint">Escalated because: </span>{oracle.reason}
        </div>
      )}

      {/* local → oracle verdict flow */}
      {(oracle.localVerdict || oracle.oracleVerdict) && (
        <div className="mb-2 flex flex-wrap items-center gap-2 text-[12.5px]">
          {oracle.localVerdict && (
            <span className="flex items-center gap-1.5">
              <span className="text-faint">Local:</span>
              <span className="rounded-badge bg-surface-3 px-2 py-[2px] font-mono text-[11.5px] text-text-2">
                {oracle.localVerdict}
              </span>
              {oracle.localConfidence != null && (
                <span className="font-mono text-[11px] text-faint">
                  ({oracle.localConfidence.toFixed(2)})
                </span>
              )}
            </span>
          )}
          {oracle.localVerdict && oracle.oracleVerdict && (
            <span className="text-faint">→</span>
          )}
          {oracle.oracleVerdict && (
            <span className="flex items-center gap-1.5">
              <span className="text-faint">Oracle:</span>
              <span
                className="rounded-badge px-2 py-[2px] font-mono text-[11.5px] font-semibold"
                style={{
                  background: overrode ? 'rgba(139,92,246,.18)' : 'rgba(139,92,246,.08)',
                  color: overrode ? '#c4b5fd' : '#a78bfa',
                }}
              >
                {oracle.oracleVerdict}
              </span>
              {oracle.oracleConfidence != null && (
                <span className="font-mono text-[11px] text-faint">
                  ({oracle.oracleConfidence.toFixed(2)})
                </span>
              )}
              <span
                className="rounded-badge px-1.5 py-[2px] text-[10.5px] font-semibold uppercase tracking-[.04em]"
                style={
                  overrode
                    ? { color: '#f59e0b', background: 'rgba(245,158,11,.12)' }
                    : { color: '#6ee7b7', background: 'rgba(110,231,183,.1)' }
                }
              >
                {overrode ? 'overrode' : 'upheld'}
              </span>
            </span>
          )}
          {!oracle.oracleVerdict && (
            <span className="text-[12px] text-faint italic">Oracle did not return a verdict</span>
          )}
        </div>
      )}

      {/* redaction notice */}
      {oracle.redacted && (
        <div className="mt-1 text-[11.5px] text-faint">
          🔒 {oracle.redactionNote || 'credentials redacted before cloud egress'}
        </div>
      )}
    </div>
  );
}

function InvMetaPanel({ meta, id }: { meta: InvMeta; id: string }) {
  const rows: [string, string][] = [
    ['id', id],
    ['model', meta.model],
    ['oracle', meta.oracle ?? '—'],
    ['tool calls', `${meta.toolCalls}`],
    ['pivots', `${meta.pivots}`],
    ['run by', meta.ranBy],
    ['ran at', absTime(meta.ranAt)],
  ];
  return (
    <CollapsiblePanel
      icon={<Cpu size={15} />}
      title="Investigation"
      summary={`${meta.model} · ${meta.toolCalls} tool calls`}
    >
      <div className="flex flex-col">
        {rows.map(([k, val]) => (
          <div key={k} className="flex gap-3 border-b border-border-faint px-[15px] py-[7px] text-[12px] last:border-0">
            <div className="w-[72px] flex-none text-faint">{k}</div>
            <div className="min-w-0 flex-1 break-words font-mono text-text-2">{val}</div>
          </div>
        ))}
      </div>
    </CollapsiblePanel>
  );
}

// ── reusable collapsibles ──────────────────────────────────────────────────

// Panel with a toggleable body. When collapsed, an optional one-line `summary`
// keeps it informative. `right` (badges/labels) shows in both states.
function CollapsiblePanel({
  icon,
  title,
  right,
  summary,
  defaultOpen = true,
  children,
}: {
  icon?: ReactNode;
  title: ReactNode;
  right?: ReactNode;
  summary?: ReactNode;
  defaultOpen?: boolean;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <Panel>
      <button
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex w-full items-start gap-[9px] px-[15px] py-[11px] text-left hover:bg-surface-hover"
      >
        {icon && <span className="flex pt-px text-accent">{icon}</span>}
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <div className="text-[13px] font-semibold">{title}</div>
            {right != null && (
              <>
                <div className="flex-1" />
                {right}
              </>
            )}
          </div>
          {!open && summary != null && (
            <div className="mt-1 truncate text-[12px] leading-[1.5] text-dim">{summary}</div>
          )}
        </div>
        <span className="flex pt-0.5 text-ghost transition-transform" style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)' }}>
          <ChevronDown size={15} />
        </span>
      </button>
      {open && <div className="border-t border-border">{children}</div>}
    </Panel>
  );
}

// Section block (uppercase title + mono meta) with a collapse toggle. Supports
// controlled (open/onToggle) or uncontrolled (defaultOpen) use.
function CollapsibleSection({
  title,
  meta,
  defaultOpen = true,
  open: openProp,
  onToggle,
  children,
}: {
  title: string;
  meta?: ReactNode;
  defaultOpen?: boolean;
  open?: boolean;
  onToggle?: () => void;
  children: ReactNode;
}) {
  const [openState, setOpenState] = useState(defaultOpen);
  const open = openProp ?? openState;
  const toggle = onToggle ?? (() => setOpenState((o) => !o));
  return (
    <div>
      <button onClick={toggle} aria-expanded={open} className="mb-[11px] flex w-full items-center gap-2 text-left">
        <div className="text-[13px] font-semibold uppercase tracking-[.05em] text-text-2">{title}</div>
        {meta != null && <div className="font-mono text-[11.5px] text-faint">{meta}</div>}
        <div className="flex-1" />
        <span className="flex text-ghost transition-transform" style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)' }}>
          <ChevronDown size={15} />
        </span>
      </button>
      {open && children}
    </div>
  );
}

function Summary({ segments, onCite }: { segments: SummarySegment[]; onCite: (n: number) => void }) {
  return (
    <>
      {segments.map((seg, i) => {
        if (seg.t === 'text') return <span key={i}>{seg.v}</span>;
        if (seg.t === 'mono')
          return (
            <span key={i} className="font-mono" style={{ color: seg.tone === 'green' ? '#7ba893' : '#e0a83a' }}>
              {seg.v}
            </span>
          );
        return (
          <sup
            key={i}
            role="button"
            tabIndex={0}
            title={`Jump to timeline step ${seg.n}`}
            onClick={() => onCite(seg.n)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                onCite(seg.n);
              }
            }}
            className="cursor-pointer rounded-[3px] px-px font-mono text-[10px] text-accent underline decoration-dotted underline-offset-2 outline-none hover:text-text hover:decoration-solid focus-visible:ring-1 focus-visible:ring-accent"
          >
            {' '}
            [{seg.n}]
          </sup>
        );
      })}
    </>
  );
}

function ActionCard({
  action,
  decision,
  message,
  executedBy,
  onApprove,
  onReject,
}: {
  action: RecommendedAction;
  decision?: 'approved' | 'rejected' | 'executing' | 'failed';
  message?: string;
  /** current username, for the just-executed attribution line. */
  executedBy?: string;
  onApprove: () => void;
  onReject: () => void;
}) {
  const Icon = ACTION_ICON[action.tag];
  const tagStyle = ACTION_TAG_COLOR[action.tag];
  // The system already carried this out (e.g. auto-ack). Render it done — never
  // offer the analyst an Approve/Execute button for an already-applied action.
  const applied = action.applied === true && !decision;
  const eff = applied ? 'approved' : decision;
  const base =
    eff === 'rejected'
      ? { border: '#2a3645', bg: '#0c0f15' }
      : eff === 'failed'
        ? { border: 'rgba(240,68,56,.35)', bg: 'rgba(240,68,56,.05)' }
        : eff === 'approved'
          ? { border: 'rgba(63,185,80,.32)', bg: 'rgba(63,185,80,.05)' }
          : { border: '#1c232e', bg: '#0b0e13' };
  const opacity = eff === 'rejected' ? 0.6 : 1;
  // 'failed' returns to the button row so the analyst can retry; 'executing'
  // shows an in-flight state; an applied/approved/rejected action is terminal.
  const showButtons = !applied && (!decision || decision === 'failed');

  return (
    <div
      className="rounded-panel border p-[14px_15px] transition-opacity"
      style={{ borderColor: base.border, background: base.bg, opacity }}
    >
      <div className="flex items-start gap-[11px]">
        <span className="mt-px flex" style={{ color: ACTION_ICON_COLOR[action.tag] }}>
          <Icon size={16} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-[14px] font-semibold">{action.title}</span>
            <span
              className="rounded-chip px-1.5 py-[1.5px] font-mono text-[10px] uppercase"
              style={{ color: tagStyle.color, background: tagStyle.bg }}
            >
              {action.tag}
            </span>
          </div>
          <div className="mt-1 text-[12.5px] leading-[1.5] text-dim">{action.rationale}</div>
        </div>
      </div>

      {decision === 'failed' && message && (
        <div className="mt-[10px] pl-[31px] font-mono text-[11.5px] leading-[1.5] text-danger">
          {message}
        </div>
      )}

      {showButtons ? (
        <>
          {action.pendingNote && (
            <div className="mt-[10px] pl-[31px] text-[12px] leading-[1.5] text-faint">
              {action.pendingNote}
            </div>
          )}
          <div className="mt-[13px] flex gap-[9px] pl-[31px]">
          <button
            onClick={onApprove}
            className="flex items-center gap-1.5 rounded-control border border-success-btn-border bg-success-btn px-4 py-2 text-[13px] font-semibold text-[#eafff2] hover:bg-[#22824c]"
          >
            <Check size={15} /> {decision === 'failed' ? 'Retry' : action.token ? 'Approve' : 'Execute'}
          </button>
          {!action.token && decision === 'failed' ? null : (
            <button
              onClick={onReject}
              className="flex items-center gap-1.5 rounded-control border border-border-strong bg-surface-3 px-4 py-2 text-[13px] font-semibold text-text-2 hover:border-danger hover:text-danger"
            >
              <X size={15} /> {action.token ? 'Reject' : 'Dismiss'}
            </button>
          )}
          </div>
        </>
      ) : decision === 'executing' ? (
        <div
          className="mt-[11px] flex items-center gap-2 pl-[31px] text-[12.5px] font-semibold"
          style={{ color: '#d29922' }}
        >
          <Loader2 size={14} className="animate-spin" /> Writing to Security Onion…
        </div>
      ) : (
        <div className="mt-[11px] pl-[31px]">
          <div
            className="flex items-center gap-2 text-[12.5px] font-semibold"
            style={{ color: eff === 'approved' ? '#3fb950' : '#f04438' }}
          >
            {applied
              ? `✓ ${action.appliedNote ?? 'Auto-acknowledged'}`
              : eff === 'approved'
                ? '✓ Executed'
                : '✕ Rejected'}{' '}
            {/* appliedNote carries its own attribution ("Executed · analyst",
                "Already acknowledged") — only the auto-ack default needs the
                system suffix. */}
            {(!applied || !action.appliedNote) && (
              <span className="font-mono text-[11px] font-normal text-faint">
                {applied ? '· system · automatic' : `· ${executedBy ?? 'you'} · just now`}
              </span>
            )}
          </div>
          {eff === 'approved' && message && (
            <div className="mt-1 text-[12px] leading-[1.5] text-dim">{message}</div>
          )}
        </div>
      )}
    </div>
  );
}

function TimelineRow({
  step,
  last,
  open,
  flash,
  onToggle,
}: {
  step: TimelineStep;
  last: boolean;
  open: boolean;
  flash?: boolean;
  onToggle: () => void;
}) {
  const color = TIMELINE_GROUP_COLOR[step.group];
  const Icon = STEP_ICON[step.group] ?? GitBranch;
  return (
    <button
      id={`tl-${step.id}`}
      onClick={onToggle}
      className="flex w-full scroll-mt-24 cursor-pointer gap-3 border-b border-border-faint px-[15px] py-3 text-left transition-colors hover:bg-surface-hover"
      style={flash ? { background: 'rgba(75,139,245,.12)', boxShadow: 'inset 2px 0 0 #4b8bf5' } : undefined}
    >
      <div className="flex flex-none flex-col items-center">
        <span
          className="flex h-[26px] w-[26px] items-center justify-center rounded-[7px] border"
          style={{ color, background: tint(color), borderColor: tint(color, 0.3) }}
        >
          <Icon size={14} />
        </span>
        {!last && <div className="mt-[5px] min-h-[8px] w-[1.5px] flex-1 bg-border-2" />}
      </div>
      <div className="min-w-0 flex-1 pt-[3px]">
        <div className="flex items-center gap-[9px]">
          <span className="text-[10px] font-semibold uppercase tracking-[.05em]" style={{ color }}>
            {step.group}
          </span>
          <div className="flex-1" />
          <span className="font-mono text-[11px] text-faint">{step.time}</span>
        </div>
        <div className="mt-[3px] text-[13.5px] font-medium" style={{ textWrap: 'pretty' }}>
          {step.title}
        </div>
        {open && (
          <pre className="mt-[9px] animate-fadeUp-slow whitespace-pre-wrap rounded-control border border-border bg-bg px-3 py-2.5 font-mono text-[11.5px] leading-[1.6] text-dim">
            {step.detail}
          </pre>
        )}
      </div>
      <span
        className="flex self-center text-ghost transition-transform"
        style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)' }}
      >
        <svg width={14} height={14} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.2} strokeLinecap="round" strokeLinejoin="round">
          <path d="M6 9l6 6 6-6" />
        </svg>
      </span>
    </button>
  );
}
