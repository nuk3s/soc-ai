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
  type LucideIcon,
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
import { type ReactNode, useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { AskSocAiButton, investigationStarters } from '../components/AskPanel';
import { ConfidenceRing } from '../components/ConfidenceRing';
import { DocumentChip } from '../components/DocumentDrawer';
import { DraftDetectionPane } from '../components/DraftDetectionPane';
import { Markdown } from '../components/Markdown';
import { EntityGraph } from '../components/EntityGraph';
import { Panel } from '../components/Panel';
import { SameFlowPanel } from '../components/SameFlowPanel';
import { KindBadge, RecordedRunChip, RunClassChip, SeverityTag, SyntheticEvalBadge, VerdictPill } from '../components/Badges';
import { BacktestReplayChip, isBacktestReplay } from '../components/BacktestReplayChip';
import { Spinner } from '../components/States';
import { ActionCard, type ActionDecision, type ActionDismissalState } from '../components/ActionCard';
import { EntityLink, EntityRefLink } from '../components/EntityLink';
import { FlowStrip } from '../components/FlowStrip';
import { investigationFlow } from '../lib/flowSteps';
import { guessEntityType } from '../lib/entityPath';
import {
  ApiError,
  ackGroup,
  dismissAction,
  dismissInvestigationError,
  draftInvestigationDetection,
  escalateGroup,
  executeAction,
  getAbout,
  downloadInvestigationExport,
  overrideVerdict as submitOverride,
  getMe,
  requestMoreInfo,
  restoreAction,
  startHunt,
} from '../lib/api';
import {
  ackMessage,
  ackWroteNothing,
  escalateMessage,
  escalateWroteNothing,
} from '../lib/groupWriteMessages';
import { plural } from '../lib/plural';
import { firstSentence, objectiveHeadline } from '../lib/text';
import { VERDICT_OPTIONS, confidenceWord, verdictLabel } from '../lib/labels';
import { useToast } from '../lib/toast';
import { gapSentence } from '../lib/openQuestions';
import { plainHeadline, toolWords } from '../lib/headline';
import {
  CHIP_SUBJECT_HUNT,
  ORACLE_REASON,
  SUBJECT_DOCUMENTS,
  SUBJECT_FINDINGS,
  SUBJECT_HUNT_LINK,
  SUBJECT_LEAD,
  SUBJECT_OBJECTIVE,
} from '../lib/tooltips';
import { useAsync } from '../lib/useAsync';
import { useChat, useChatScope } from '../lib/chatScope';
import { citedEventIds, splitEventIds } from '../lib/eventIds';
import { demoBlocked, useDemo } from '../lib/demo';
import { absTime } from '../lib/timeRange';
import { SEVERITY, TIMELINE_GROUP_COLOR, VERDICT, tint } from '../lib/tokens';
import type {
  AlertMeta,
  AlertSibling,
  DetectionKind,
  EntityRef,
  HostSignal,
  Investigation as Inv,
  InvestigationSubject,
  InvMeta,
  OracleAdjudication,
  RecommendedAction,
  Severity,
  SummarySegment,
  TimelineStep,
} from '../lib/types';

// Derived from the single app-wide severity ramp (lib/tokens) — no duplicate hexes.
const SEV_COLOR: Record<string, string> = Object.fromEntries(
  (Object.keys(SEVERITY) as Severity[]).map((k) => [k, SEVERITY[k].color]),
);


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
  /** Show a same-flow sibling on the screen around the report. The Alerts
   *  drawer passes it. Without it, Show links to the Alerts list. */
  onShowSibling?: (sibling: AlertSibling) => void;
}

/** The timeline groups in analyst words (dogfood 2026-10-06, first hour C2).
 *  The stored keys stay as they are: the colours and the counts read them. */
export const TIMELINE_GROUP_LABEL: Record<string, string> = {
  'Prefetch & pivots': 'Context gathered',
  'Indicator enrichment': 'Intel look-ups',
  'Tool calls': 'Follow-up queries',
  Validators: 'Checks',
  Decision: 'Verdict',
  Oracle: 'Oracle review',
};

const STEP_ICON: Record<string, LucideIcon> = {
  'Prefetch & pivots': GitBranch,
  'Indicator enrichment': Shield,
  'Tool calls': Terminal,
  Decision: LayoutTemplate,
  Validators: CheckCircle2,
  Oracle: Sparkles,
  Error: AlertTriangle,
};

function fmt(s: number) {
  const m = Math.floor(s / 60);
  const x = s % 60;
  return `${m < 10 ? '0' : ''}${m}:${x < 10 ? '0' : ''}${x}`;
}

/** "1m 19s" / "42s": the backend's elapsed-label shape, from the live ticker. */
function durationLabel(s: number) {
  const m = Math.floor(s / 60);
  const x = s % 60;
  return m > 0 ? `${m}m ${x}s` : `${x}s`;
}

/** The banner on a run a newer run replaced (dogfood 2026-10-06,
 *  investigation S1). "Request more info" and "Re-run" start a new run, and
 *  the older page kept its verdict and its live buttons at a bookmarked URL. */
export function supersededSentence(run: Pick<Inv, 'supersededRun'>['supersededRun']): string {
  if (run?.status === 'complete' && run.verdict) {
    const conf = run.conf != null ? ` (${run.conf.toFixed(2)})` : '';
    return `A newer run on this alert reached ${verdictLabel(run.verdict).toLowerCase()}${conf}.`;
  }
  if (run?.status === 'running') return 'A newer run on this alert is in progress.';
  return 'A newer run on this alert replaced this run.';
}

/** Why every action on a replaced run is off. */
export const SUPERSEDED_LOCK = 'A newer run replaced this run. Act on the newer run.';

/** Why Re-run is off on a run whose recorded cause a re-run cannot change. */
export const PERMANENT_FAILURE_LOCK = 'A re-run cannot change the recorded cause.';

/** The tooltip of a citation the validator could not resolve (R2-D5). */
export const UNRESOLVED_CITATION =
  'The validator did not resolve this citation. The run retrieved nothing that it names.';

/** The verdict an analyst set on this run, or null when the model set it. */
export function analystVerdictOf(
  inv: Pick<Inv, 'resolution' | 'verdict'>,
): { verdict: string; by: string } | null {
  const r = inv.resolution;
  if (!r || (r.resolved_via !== 'manual' && r.resolved_via !== 'chat')) return null;
  return { verdict: inv.verdict, by: r.resolved_by || 'An analyst' };
}

/** The analyst verdict that stands on the alert, on any run of it. The
 *  server reads every run (V1-A3). An older server sends no field, and the
 *  page then reads the resolution of this run. */
export function standingAnalystOf(
  inv: Pick<Inv, 'id' | 'resolution' | 'verdict' | 'standingAnalystVerdict'>,
): { verdict: string; by: string; investigationId: string } | null {
  const s = inv.standingAnalystVerdict;
  if (s) return { verdict: s.verdict, by: s.by || 'An analyst', investigationId: s.investigationId };
  const own = analystVerdictOf(inv);
  return own ? { ...own, investigationId: inv.id } : null;
}

/** The note on a run whose alert carries an analyst verdict on another run. */
export function standingAnalystSentence(a: { verdict: string; by: string }): string {
  return `${a.by} set the verdict of this alert to ${verdictLabel(a.verdict).toLowerCase()} on another run. That verdict stands.`;
}

/** The two actions that start a new run of the alert from this page. */
export type NewRunAction = 'rerun' | 'request_info';

/** What a new run can replace: the analyst verdict on any run of the alert,
 *  and, on a backtest replay, the live verdict of the alert. */
export interface NewRunStakes {
  analyst: { verdict: string; by: string; otherRun: boolean } | null;
  replay: boolean;
  live: { verdict?: string | null; conf?: number | null } | null;
}

/** What a new run does to the verdict of the alert, said before the run
 *  starts. One rule for Re-run and Request more info, on a live run and on a
 *  replay (R2-D1, R2-I5, V1-A2, V1-A3). Null when nothing needs a question. */
export function newRunConfirmText(action: NewRunAction, stakes: NewRunStakes): string[] | null {
  if (!stakes.analyst && !stakes.replay) return null;
  const lines: string[] = [];
  if (stakes.analyst) {
    lines.push(
      `${stakes.analyst.by} set the verdict of this alert to ${verdictLabel(stakes.analyst.verdict).toLowerCase()}.`,
    );
    if (stakes.analyst.otherRun) lines.push('That verdict is on another run of the alert.');
  }
  const name = action === 'rerun' ? 'A re-run' : 'Request more info';
  if (stakes.replay) {
    lines.push('This run is a backtest replay.');
    const live = stakes.live;
    if (live?.verdict) {
      const at = live.conf != null ? ` at ${live.conf.toFixed(2)}` : '';
      lines.push(`The live verdict of the alert is ${verdictLabel(live.verdict).toLowerCase()}${at}.`);
    } else {
      lines.push('The alert has no live verdict.');
    }
    lines.push(`${name} starts a live run. The verdict of the new run becomes the live verdict of the alert.`);
  } else {
    lines.push(
      `${name} starts a new run. The new run can reach another verdict, and the alert then shows that verdict.`,
    );
  }
  if (stakes.analyst) {
    lines.push('soc-ai does not acknowledge an alert that an analyst set to true positive.');
  }
  return lines;
}

/** The direction of the flow in the collapsed entity bar (R2-D10). Lateral
 *  movement is internal to internal. Null says nothing. */
export const GRAPH_SCOPE_LABEL: Record<string, string> = {
  lateral: 'lateral movement',
  inbound: 'inbound from an external source',
  outbound: 'outbound to an external host',
  external: 'external to external',
};

const GRAPH_SCOPE_SENTENCE: Record<string, string> = {
  lateral: 'The graph shows lateral movement.',
  inbound: 'The flow is inbound from an external source.',
  outbound: 'The flow is outbound to an external host.',
  external: 'Both ends of the flow are external.',
};

/** "Verdict changed to true positive. Recorded under alice." */
export function overrideToast(verdict: string, by: string): string {
  return `Verdict changed to ${verdictLabel(verdict).toLowerCase()}. Recorded under ${by}.`;
}

/** The thresholds behind the confidence word, in the tooltip. */
export const CONFIDENCE_TIP =
  'The confidence of the verdict. High is 0.80 and above. Medium is 0.70 to 0.79. ' +
  'Low is under 0.70. Under 0.70 the Oracle can review the verdict, and soc-ai ' +
  'acknowledges no false positive by itself.';

/** What the severity chip on the verdict card is. */
export const RULE_SEVERITY_TIP =
  'Rule severity. The detection rule sets it. It is not the confidence of the verdict.';

/** The four Alert details rows the drawer shows first. */
const BRIEF_ROWS = new Set(['rule', 'source', 'dest', 'user']);

/** How long a run takes on this grid, in one or two sentences. */
export function runEstimate(t: Inv['typicalRun']): string {
  if (!t) return 'A run takes 1 to 5 minutes.';
  const span =
    t.lowMin === t.highMin
      ? `about ${t.medianMin} minute${t.medianMin === 1 ? '' : 's'}`
      : `${t.lowMin} to ${t.highMin} minutes`;
  return `A run on this grid takes ${span}. The median of the last ${t.samples} runs is ${t.medianMin} minute${t.medianMin === 1 ? '' : 's'}.`;
}

/** What the Oracle is, on hover of the word. */
export const ORACLE_TIP =
  'The Oracle is a second model. soc-ai sends it a verdict to review when the confidence is low.';

/** The question "Resolve in chat" asks. */
export const RESOLVE_PROMPT = 'What would resolve this verdict?';

/** What each settled-bar write does, said in its confirm step. */
const SETTLED_SCOPE: Record<'ack' | 'escalate', string> = {
  ack: 'Acknowledge every unacknowledged alert of this rule.',
  escalate: 'Open one Security Onion case for each alert of this rule.',
};

/** Why Re-run is off while a run is in flight (fleet P4, 2026-10-01). */
export const RERUN_BUSY_REASON =
  'A run is in progress. Wait for it to finish before you start another run.';

/** The headline of a pipeline fallback. The stored summary names the failed
 *  phase and the exception class, which is internal detail (fleet P11). */
export const FALLBACK_HEADLINE = 'The pipeline stopped. This run has no verdict.';

// The fallback report's summary, for a row that lacks the fallback marker.
const FALLBACK_SUMMARY_RE = /^Synth-first pipeline fallback:/;

/** The count the page shows for tool calls: the rows of the "Tool calls"
 *  section. The backend counts the same rows, so the two cannot disagree. */
/** The ends of the alert, from its own fields, and the host that reported it.
 *
 *  The chip read the host name of the alert as the source and the source
 *  address as the destination when the alert named no destination. A grid
 *  node login failure read "source <node> to destination <attacker>". The
 *  reporter is named "on <host>" and never sits in a direction slot. */
export function alertEnds(
  inv: Pick<Inv, 'host' | 'ip' | 'srcIp' | 'dstIp' | 'reportedBy'>,
): { src: string | null; dst: string | null; on: string | null; title: string } | null {
  const shown = (v: string | null | undefined) => (v && v !== '\u2014' ? v : null);
  // An older server sends only the two display strings.
  const older = inv.srcIp === undefined && inv.dstIp === undefined && inv.reportedBy === undefined;
  const src = older ? shown(inv.host) : shown(inv.srcIp);
  const dst = older ? shown(inv.ip) : shown(inv.dstIp);
  const reporter = shown(inv.reportedBy);
  const on = reporter && reporter !== src && reporter !== dst ? reporter : null;
  if (!src && !dst && !on) return null;
  const title = [
    src ? `Source ${src}.` : 'The alert names no source.',
    dst ? `Destination ${dst}.` : 'The alert names no destination.',
    on ? `The host ${on} reported the alert.` : '',
  ]
    .filter(Boolean)
    .join(' ');
  return { src, dst, on, title };
}

export function toolCallCount(inv: Pick<Inv, 'timeline'>): number {
  return inv.timeline.filter((s) => s.group === 'Tool calls').length;
}

/** The hunt a promoted finding came from, named by the head line of its
 *  objective. The API cut the objective at 160 characters in the middle of a
 *  word, with no mark of the cut. The link shows the head line whole and the
 *  hover holds the whole objective. A deleted hunt reads as its id. */
function SourceHuntLink({ huntId, objective }: { huntId: string; objective?: string | null }) {
  const headline = objectiveHeadline(objective);
  return (
    <Link
      to={`/hunts/${huntId}`}
      data-testid="source-hunt-link"
      title={objective || undefined}
      className="break-words font-mono text-text-2 underline hover:text-text"
    >
      {headline || huntId}
    </Link>
  );
}

/** An IPv4 address inside running text. */
const IPV4_IN_TEXT = /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/;

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Split running text on the entities it names: every IPv4 address, and
 *  every value the run names (a host, a user, a domain) of three or more
 *  characters. Exported for tests. */
export function splitEntities(
  text: string,
  known: EntityRef[] = [],
): { t: 'text' | 'entity'; v: string; ref?: EntityRef }[] {
  const values = known.map((e) => e.value).filter((v) => v && v.length >= 3);
  const parts = [IPV4_IN_TEXT.source, ...values.sort((a, b) => b.length - a.length).map(escapeRe)];
  const re = new RegExp(`(${parts.join('|')})`, 'g');
  const out: { t: 'text' | 'entity'; v: string; ref?: EntityRef }[] = [];
  let last = 0;
  for (const m of text.matchAll(re)) {
    const at = m.index ?? 0;
    // A value inside a longer word is not that value: "dc01" in "dc01x".
    const before = text[at - 1] ?? ' ';
    const after = text[at + m[0].length] ?? ' ';
    if (/[\w.-]/.test(before) && !/^\d/.test(m[0])) continue;
    if (/[\w-]/.test(after) && !/^\d/.test(m[0])) continue;
    if (at > last) out.push({ t: 'text', v: text.slice(last, at) });
    out.push({ t: 'entity', v: m[0], ref: known.find((e) => e.value === m[0]) });
    last = at + m[0].length;
  }
  if (last < text.length) out.push({ t: 'text', v: text.slice(last) });
  return out;
}

/** Text with each entity it names as a link to its page. */
function EntityText({ text, entities }: { text: string; entities?: EntityRef[] }) {
  return (
    <>
      {splitEntities(text, entities).map((seg, i) =>
        seg.t === 'entity' ? (
          <EntityLink
            key={i}
            value={seg.v}
            type={seg.ref?.type}
            hostKey={seg.ref?.host_key}
            stopPropagation
            className="font-[inherit] text-[inherit]"
          />
        ) : (
          <span key={i}>{seg.v}</span>
        ),
      )}
    </>
  );
}

/** Text with each document id rendered as a control that opens the document,
 *  and each entity it names as a link to its page (dogfood 2026-10-06,
 *  hosts F1). */
function CitedText({ text, ids, entities }: { text: string; ids: string[]; entities?: EntityRef[] }) {
  return (
    <>
      {splitEventIds(text, ids).map((seg, i) =>
        seg.t === 'id' ? (
          <DocumentChip
            key={i}
            id={seg.v}
            className="rounded-chip border border-border-strong bg-surface-2 px-1 py-px align-baseline font-mono text-[0.72em] font-normal tracking-normal text-accent hover:bg-surface-3"
          />
        ) : (
          <EntityText key={i} text={seg.v} entities={entities} />
        ),
      )}
    </>
  );
}

/** The entity ref the server sent for one value, when it sent one. */
function refFor(inv: Pick<Inv, 'entities'>, value: string | null | undefined): EntityRef | undefined {
  if (!value) return undefined;
  return inv.entities?.find((e) => e.value === value);
}

/** One end of the alert as a link: the server's ref when it sent one, else
 *  the value with its type read from its shape. */
function EndLink({ inv, value, className }: { inv: Pick<Inv, 'entities'>; value: string; className?: string }) {
  const ref = refFor(inv, value);
  const cls = `font-[inherit] ${className ?? ''}`;
  return ref ? (
    <EntityRefLink entity={ref} className={cls} />
  ) : (
    <EntityLink value={value} stopPropagation className={cls} />
  );
}

export function Investigation({ inv, layout = 'drawer', onReHunt, onVerdictApplied, onAcked, onShowSibling }: InvestigationProps) {
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
  // The detection-bridge "Draft detection" affordance's kill switch, read the
  // same one-mount-GET way the Dashboard assistant gates on general_chat_enabled
  // (Dashboard.tsx `about`). Unlike that flag, sigma_authoring_enabled defaults
  // OFF, so an unsettled or failed probe must fail CLOSED (hidden), not open —
  // no `!!about.error` fallback here.
  const about = useAsync(getAbout, []);
  const sigmaAuthoringEnabled = about.data?.sigma_authoring_enabled === true;
  const demo = useDemo(); // demo deployment → label the verdict as a recorded run
  const [actions, setActions] = useState<Record<string, ActionDecision>>({});
  const [actionMsg, setActionMsg] = useState<Record<string, string>>({});
  // Dismissals this tab made or undid, over the server's record until the
  // next poll carries it. `null` is an undo.
  const [dismissals, setDismissals] = useState<Record<string, ActionDismissalState | null>>({});
  const [dismissMsg, setDismissMsg] = useState<Record<string, string>>({});
  // Settled-verdict fallback action bar: when a complete run recommended no
  // write actions, the analyst can still ack/escalate the whole group directly.
  const [settledAction, setSettledAction] = useState<'ack' | 'escalate' | null>(null);
  const [settledMsg, setSettledMsg] = useState<{ tone: 'ok' | 'info' | 'err'; text: string } | null>(null);
  // The settled bar writes to the whole detection group. It asks first, the
  // way Override verdict does (dogfood 2026-10-06, investigation S2).
  const [settledConfirm, setSettledConfirm] = useState<'ack' | 'escalate' | null>(null);
  const [openSteps, setOpenSteps] = useState<Record<string, boolean>>({});
  const [flashStep, setFlashStep] = useState<string | null>(null);
  const [timelineOpen, setTimelineOpen] = useState(true);
  const [reasoningOpen, setReasoningOpen] = useState(false);
  // A request from the chat to open the confirm of one action card.
  const [confirmRequest, setConfirmRequest] = useState<{ id: string; n: number } | null>(null);
  // The one chat panel lives in the shell. This page lends it the
  // investigation scope (useChatScope below) and opens it from "Resolve in
  // chat". The thread transport and the proposal cards live in the panel.
  const chatPanel = useChat();
  const [elapsed, setElapsed] = useState(0);
  // Client-side stuck-guard: flips true if the run is still 'investigating'
  // after a generous cap, so the spinner can't hang forever even if the backend
  // reaper hasn't yet marked it 'error'.
  const [stuck, setStuck] = useState(false);
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
  // A triage that DIED: the run ended in a failure state having reached no
  // verdict. Narrower than `failed` on purpose: a cancel was asked for and a
  // restart orphan is re-huntable by design, so neither is an unattended hole,
  // and neither belongs in the count the Dismiss button clears. This is the
  // client's read of the server's `noVerdict` predicate, on the drawer shape
  // (which carries status and verdict, not the list row's flag).
  const diedWithNoVerdict = inv.status === 'error' && inv.verdict === 'untriaged';
  // Only spin while genuinely in-flight (not once we've decided it's stuck).
  const running = investigating && !stuck;
  // A newer run replaced this one. The page stays a record: it names the
  // newer run and its verdict, and every write on it is off. A failed run
  // has its own forward link in the failure panel.
  const supersededLock = inv.supersededBy && !failed ? SUPERSEDED_LOCK : null;
  // Why Re-run is off on this record: a newer run replaced it, or the recorded
  // cause is one a re-run cannot change (R2-D4). The failure panel already
  // hides its own Re-run for both. The toolbar and the strip agree with it.
  const rerunLock = inv.supersededBy
    ? SUPERSEDED_LOCK
    : inv.status === 'error' && inv.failure?.permanent
      ? PERMANENT_FAILURE_LOCK
      : null;
  // The verdict an analyst set on this run. The label over the card reads it.
  const analystVerdict = analystVerdictOf(inv);
  // The analyst verdict on ANY run of the alert, and what a new run from
  // this page can replace. Re-run and Request more info ask first (V1-A3).
  const standingAnalyst = standingAnalystOf(inv);
  const newRunStakes: NewRunStakes = {
    analyst: standingAnalyst
      ? {
          verdict: standingAnalyst.verdict,
          by: standingAnalyst.by,
          otherRun: standingAnalyst.investigationId !== inv.id,
        }
      : null,
    replay: isBacktestReplay(inv.meta?.ranBy),
    live: inv.alertLiveRun ?? null,
  };
  // A verdict the model did not commit to. It never reads as settled, and it
  // always offers the two ways forward (fleet P2).
  const unsettledVerdict = inv.verdict === 'needs_more_info' || inv.verdict === 'inconclusive';
  const isFallback =
    !!inv.fallback || FALLBACK_SUMMARY_RE.test(inv.rationale ?? '');
  const citedIds = citedEventIds(inv.citations);
  // The headline in plain words: field paths out, tool ids named in words.
  const headline = plainHeadline(inv.rationale ?? '');
  // Each cited field with the validator's answer (R2-D5). An unresolved
  // citation read like a resolved one. A path the headline names and the
  // report does not cite has no answer: null.
  const citedPathItems: Array<{ path: string; resolved: boolean | null }> = [];
  for (const c of inv.citations ?? []) {
    const path = c.kind === 'path' ? c.target || c.text : '';
    if (path && !citedPathItems.some((i) => i.path === path)) {
      citedPathItems.push({ path, resolved: c.resolved ?? null });
    }
  }
  for (const path of headline.paths) {
    if (path && !citedPathItems.some((i) => i.path === path)) citedPathItems.push({ path, resolved: null });
  }
  const citedPaths = citedPathItems.map((i) => i.path);
  // A tool the report cites. A resolved tool citation did not render (R2-D5).
  const citedTools = Array.from(
    new Set(
      (inv.citations ?? [])
        .filter((c) => c.kind === 'tool' && c.resolved !== false && (c.target || c.text))
        .map((c) => c.target || c.text),
    ),
  );
  const unresolvedIds = new Set(
    (inv.citations ?? []).filter((c) => c.kind === 'id' && c.resolved === false).map((c) => (c.target ?? '').trim()),
  );
  const unresolvedCount = (inv.citations ?? []).filter((c) => c.resolved === false).length;
  // The gap the rationale or the summary names, for an unsettled verdict
  // with no recorded question.
  const gapFromText = gapSentence(
    inv.rationale,
    inv.summary.map((seg) => ('v' in seg ? seg.v : '')).join(' '),
  );
  const tools = toolCallCount(inv);

  // elapsed ticker while running
  useEffect(() => {
    if (!running) return;
    const t = setInterval(() => setElapsed((e) => e + 1), 1000);
    return () => clearInterval(t);
  }, [running]);
  // Each poll re-seeds the ticker from the server, so the ticker and the
  // server's label read the same time (two clocks differed by 2 s, P16).
  useEffect(() => {
    if (running && inv.elapsedSec != null) setElapsed(inv.elapsedSec);
  }, [running, inv.elapsedSec]);

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

  // reset transient state only when the investigation IDENTITY changes (drawer
  // reuse / re-hunt) — never on a poll refresh of the same investigation. The
  // chat panel keys its thread on the same id.
  useEffect(() => {
    setActions({});
    setActionMsg({});
    setDismissals({});
    setDismissMsg({});
    setSettledAction(null);
    setSettledMsg(null);
    setSettledConfirm(null);
    setOpenSteps({});
    setStuck(false);
    setErrDismiss('idle');
    setErrDismissMsg(null);
    // Seed from the REAL elapsed (backend) so opening the same run in the drawer
    // then the permalink doesn't reset the timer to 0:00.
    setElapsed(inv.elapsedSec ?? 0);
    setGraphOpen(false); // always start collapsed — the bar narrative carries the gist
    setTimelineOpen(true);
    setOverrideOpen(false);
    setOverrideVerdictVal('');
    setOverrideRationale('');
    setOverrideError(null);
    setReRunError(null);
    setRequestInfoError(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [inv.id]);

  const [reHunting, setReHunting] = useState(false);
  const [overrideOpen, setOverrideOpen] = useState(false);
  // Nothing preselected: a confirm on the current verdict changed nothing
  // and still read as an override (dogfood 2026-10-06, first hour C5).
  const [overrideVerdictVal, setOverrideVerdictVal] = useState<string>('');
  const [overrideRationale, setOverrideRationale] = useState('');
  const [overriding, setOverriding] = useState(false);
  const [overrideError, setOverrideError] = useState<string | null>(null);
  const { toast } = useToast();
  // An analyst set the verdict. The model's paragraph folds under a label.
  const overridden = inv.resolution?.resolved_via === 'manual';
  const [priorOpen, setPriorOpen] = useState(false);

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

  // One control, two panels. The E1.2 fallback panel below has always carried
  // it; the terminal-failure panel had no way to clear anything, which is how a
  // deployed instance reached 188 unacknowledged dead runs: the Dashboard could
  // not have counted them down even if it had counted them.
  const dismissControl = errorDismissed ? (
    <span className="flex items-center gap-1.5 text-[12.5px] text-dim">
      <Check size={13} /> Dismissed. The Dashboard does not count this run.
    </span>
  ) : (
    <button
      onClick={dismissError}
      disabled={errDismiss === 'busy'}
      title="This button acknowledges the failed run. The Dashboard stops counting the run. The run stays under the Investigations 'Pipeline error' filter, and you can still re-run it."
      className="flex items-center gap-1.5 rounded-control border border-border-strong bg-surface-3 px-4 py-2 text-[12.5px] font-semibold text-dim hover:border-accent hover:text-text disabled:opacity-60"
    >
      {errDismiss === 'busy' ? <Spinner size={13} /> : <X size={13} />}
      {errDismiss === 'busy' ? 'Dismissing' : 'Dismiss'}
    </button>
  );

  // Why a start that never landed is reported the way it is.
  //
  // Both of this screen's start buttons used to end in an empty catch, so a
  // POST /hunt that 503'd against a down grid changed not one pixel: the status
  // chip still read "complete · 1m 14s" over a re-run that never began (dogfood
  // D6, 2026-08-14). The analyst either trusts a stale verdict they believe is
  // being re-examined, or decides the button is dead and clicks it again.
  //
  // What is claimed depends on whether a server answered. An ApiError carries a
  // status, so the request reached the API and was REFUSED — quote the refusal,
  // because the 503's `detail.hint` is the sentence written for the analyst
  // ("…retry shortly") and api.ts already puts it on the error. Anything else is
  // a transport failure with NO response: api.ts's 20s budget fired, or the
  // network dropped. That cannot support "it did not start" — the backend may
  // have accepted the run and be working on it right now — so report that we got
  // no answer and name the surface that knows. Unknown is not failure.
  //
  // A durable strip, not a toast: this action leaves no other trace, and a
  // notice that fades takes the only evidence of the click with it.
  const [reRunError, setReRunError] = useState<string | null>(null);
  const [requestInfoError, setRequestInfoError] = useState<string | null>(null);
  // The confirm step of a new run that can replace a verdict.
  const [newRunAsk, setNewRunAsk] = useState<{ action: NewRunAction; deep: boolean } | null>(null);

  // Close a sentence somebody else wrote — the wire's `detail.hint`, or api.ts's
  // transport message. How it is punctuated is not ours to decide (api.ts's
  // network failure is a QUESTION), so add the full stop only when the author
  // left the sentence open. Twin of the helper in Alerts.tsx.
  const endSentence = (s: string): string => {
    const text = s.trim();
    return /[.!?…]$/.test(text) ? text : `${text}.`;
  };
  // `action` is the button's own label, so the report names what the analyst
  // just clicked rather than the endpoint behind it.
  const startFailure = (err: unknown, action: string): string => {
    const detail = err instanceof Error ? err.message.trim() : '';
    if (err instanceof ApiError) {
      return `The API refused ${action}. ${endSentence(detail || `The API answered ${err.status}`)}`;
    }
    return (
      `The API gave no answer to ${action}. The run may have started anyway. ` +
      `Check the Investigations list for a newer run of this alert before you start another. ${endSentence(
        detail || 'The request did not complete',
      )}`
    );
  };

  // Re-run the investigation: start a fresh hunt on the same alert and hand the
  // new investigation id to the container so it switches to (and polls) it.
  // `deep` forces the full tool-driven loop — offered when THIS run was a
  // zero-tool heuristic, because re-running a heuristic verdict through the
  // same fast path just repeats the heuristic (dogfood 2026-07-15).
  const startReRun = (deep: boolean, confirmed = false) => {
    if (reHunting) return;
    // A re-run replaces the verdict on the alert. Over an analyst verdict on
    // any run of the alert, and on a replay, it asks first and names the
    // verdict (R2-D1, R2-I5, V1-A2, V1-A3).
    if (!confirmed && newRunConfirmText('rerun', newRunStakes)) {
      setNewRunAsk({ action: 'rerun', deep });
      return;
    }
    // Defense in depth: every visible Re-run affordance is already hidden for
    // a promoted finding (toolbar, failedEl, the fallback panel), and the API
    // refuses it too (409 hunt_kind_no_rerun) — but a stray caller reaching
    // this function directly should still no-op rather than mint an
    // unlabeled kind='suricata' duplicate.
    if (inv.kind === 'hunt') return;
    // A second start while this run is in flight makes a duplicate run (P4).
    if (running) return;
    setReRunError(null);
    setReHunting(true);
    startHunt(inv.groupId, deep ? { deep: true } : undefined)
      .then((newId) => onReHunt?.(newId))
      .catch((err: unknown) => setReRunError(startFailure(err, 'Re-run investigation')))
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
  const startRequestInfo = (confirmed: boolean) => {
    if (requestingInfo) return;
    // The new run replaces the verdict of the alert. On a replay it is a live
    // run, and it replaced a live true positive with no word (V1-A2).
    if (!confirmed && newRunConfirmText('request_info', newRunStakes)) {
      setNewRunAsk({ action: 'request_info', deep: false });
      return;
    }
    setRequestInfoError(null);
    setRequestingInfo(true);
    requestMoreInfo(inv.id)
      .then((newId) => onReHunt?.(newId))
      .catch((err: unknown) => setRequestInfoError(startFailure(err, 'Request more info')))
      .finally(() => setRequestingInfo(false));
  };
  const requestInfo = () => startRequestInfo(false);

  // "Resolve in chat" opens the chat and asks the question (dogfood
  // 2026-10-06, C3). The panel sends it once the thread read lands, and a
  // turn already running gets the question in the box.
  const resolveInChat = () => chatPanel?.openChat({ ask: RESOLVE_PROMPT });

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

  // Genuinely-pending = no local decision AND not already carried out by the
  // system (auto-ack). An applied action renders as a terminal "✓ done" card, so
  // counting it as pending contradicted the card (dogfood FP-run finding).
  const pendingCount = inv.actions.filter(
    (a) =>
      actions[a.id] !== 'approved' &&
      a.applied !== true &&
      !(a.id in dismissals ? dismissals[a.id] : a.dismissed),
  ).length;
  const graphInteresting =
    inv.edges.some((e) => e.kind === 'lateral') || inv.nodes.some((n) => n.kind === 'compromised');
  // The direction of the flow, from the server (R2-D10). Every true positive
  // used to read "lateral movement", an external SQL injection source too.
  const scopeLabel = inv.graphScope ? GRAPH_SCOPE_LABEL[inv.graphScope] ?? null : null;

  // What this run investigated.
  //
  // A hunt subject replaces the alert panel rather than joining it: the rail
  // answers "what did this run investigate", and a hunt investigation has an
  // objective and a set of findings where an alert run has a rule and an
  // event. Two panels there would give one run two subjects.
  const huntSubject = inv.subject?.type === 'hunt' ? inv.subject : null;
  const ends = alertEnds(inv);

  // ── composable section blocks (arranged differently per layout) ──────────
  // The flow, under the header of the drawer and the page (owner,
  // 2026-10-07): Alert, Investigation, Verdict, Action in Security Onion. The
  // strip reads the run's own state, so a failed run names Re-run and never a
  // verdict.
  const flowEl = (
    <FlowStrip
      steps={investigationFlow(inv, {
        failed,
        actedHere:
          Object.values(actions).some((d) => d === 'approved') || settledMsg?.tone === 'ok',
        noWrites: isBacktestReplay(inv.meta?.ranBy),
      })}
      className="mb-3"
    />
  );
  // The toolbar wraps. In the drawer at 1280 px the buttons wrapped their
  // words and the Ask soc-ai button ran off the edge (R2-D19).
  const toolbarEl = (
    <div data-testid="verdict-toolbar" className="mb-3.5 flex flex-wrap items-center gap-x-2.5 gap-y-2 [&>button]:whitespace-nowrap">
      {/* Whose verdict the card shows (R2-D22). */}
      <div data-testid="verdict-source" className="whitespace-nowrap text-[11px] font-semibold uppercase tracking-[.06em] text-faint">
        {analystVerdict ? 'Analyst verdict' : 'soc-ai verdict'}
      </div>
      <div className="flex-1" />
      {!running && (
        <button
          onClick={() => { setOverrideVerdictVal(''); setOverrideRationale(''); setOverrideError(null); setOverrideOpen(true); }}
          disabled={!!supersededLock}
          title={supersededLock ?? undefined}
          className="flex items-center gap-1.5 rounded-control border border-border-strong bg-surface-3 px-[11px] py-1.5 text-[12px] font-semibold text-dim hover:border-warn hover:text-text disabled:opacity-60"
        >
          <Scale size={13} />
          Override verdict
        </button>
      )}
      {/* Re-run / Deep re-run: hidden for a promoted hunt finding. Re-promoting
          from the hunt page is the sanctioned re-run in this slice — startHunt
          would mint an unlabeled kind='suricata' duplicate on the anchor
          telemetry doc, and the API refuses these paths anyway (Task 6b). */}
      {inv.kind !== 'hunt' && (
        <button
          onClick={reRun}
          disabled={reHunting || running || !!rerunLock}
          title={running ? RERUN_BUSY_REASON : rerunLock ?? undefined}
          className="flex items-center gap-1.5 rounded-control border border-border-strong bg-surface-3 px-[11px] py-1.5 text-[12px] font-semibold text-dim hover:border-accent hover:text-text disabled:opacity-60"
        >
          {reHunting ? <Spinner size={13} /> : <RotateCw size={13} />}
          {reHunting ? 'Re-running' : 'Re-run investigation'}
        </button>
      )}
      {inv.kind !== 'hunt' && running && (
        <span className="text-[11.5px] text-faint">A run is in progress.</span>
      )}
      {inv.kind !== 'hunt' && wasHeuristic && (
        <button
          onClick={reRunDeep}
          disabled={reHunting || running || !!rerunLock}
          title={
            rerunLock ??
            'The model wrote this verdict with no tool call. Re-run it to investigate with the read tools.'
          }
          className="flex items-center gap-1.5 rounded-control border border-border-strong bg-surface-3 px-[11px] py-1.5 text-[12px] font-semibold text-dim hover:border-accent hover:text-text disabled:opacity-60"
        >
          {reHunting ? <Spinner size={13} /> : <Crosshair size={13} />}
          Deep re-run
        </button>
      )}
      {/* Named for its artifact: a complete TP hunt investigation can show the
          detection pane's "Download .yml" on the same screen, and a bare
          "Export" beside it reads as the same download. */}
      <button
        onClick={() => { void downloadInvestigationExport(inv.id); }}
        title="Download the decision record. The JSON file holds the tools, the cited events, the verdict and a sha256 integrity checksum."
        className="flex items-center gap-1.5 rounded-control border border-border-strong bg-surface-3 px-[11px] py-1.5 text-[12px] font-semibold text-dim hover:border-accent hover:text-text"
      >
        <Download size={13} />
        Export decision record
      </button>
      {/* The drawer covers the top bar and its Ask soc-ai button, so the
          drawer's own header row carries the same button. */}
      {layout === 'drawer' && <AskSocAiButton />}
    </div>
  );

  // The durable half of a start that never landed. Rendered directly under the
  // toolbar, so it sits with the button that produced it and above every other
  // Re-run on the screen (the terminal-failure banner's and the pipeline-error
  // panel's both call the same handler). Cleared by the next attempt and by a
  // switch to another investigation — a successful re-run navigates to the new
  // run, which resets it on the way through.
  const startFailureStrip = (text: string, onDismiss: () => void, margin: string) => (
    <div
      role="alert"
      className={`${margin} flex items-start gap-2.5 rounded-card border px-3.5 py-2.5 text-[13px]`}
      style={{ borderColor: 'rgba(240,68,56,.35)', background: 'rgba(240,68,56,.08)' }}
    >
      <span className="mt-px flex flex-shrink-0 text-danger"><AlertTriangle size={15} /></span>
      <div className="min-w-0 flex-1 break-words leading-[1.5] text-text-2">{text}</div>
      <button
        onClick={onDismiss}
        aria-label="Dismiss"
        className="mt-px flex flex-shrink-0 text-dim hover:text-text"
      >
        <X size={14} />
      </button>
    </div>
  );
  const reRunErrorEl = reRunError
    ? startFailureStrip(reRunError, () => setReRunError(null), 'mb-3.5')
    : null;

  // The finding the analyst promoted, first (dogfood 2026-10-06, hunting C4).
  // The page read as a hunt of the whole lead, with the raw model prompt as
  // its objective.
  const pf = inv.promotedFinding;
  const promotedFindingEl = pf ? (
    <div
      data-testid="promoted-finding"
      className="mb-3.5 rounded-card border px-3.5 py-3"
      style={{ borderColor: 'rgba(244,114,182,.35)', background: 'rgba(244,114,182,.06)' }}
    >
      <div className="text-[13.5px] font-semibold text-text">
        <span style={{ color: '#f472b6' }}>Promoted finding:</span> {pf.label}, {pf.title}
      </div>
      {pf.detail && (
        <div className="mt-1 text-[12.5px] leading-[1.5] text-text-2">
          <EntityText text={pf.detail} entities={inv.entities} />
        </div>
      )}
      {pf.attacker && pf.victim ? (
        <div data-testid="promoted-direction" className="mt-1.5 font-mono text-[12px] text-dim">
          <EntityLink value={pf.attacker} className="text-mono-amber" />
          <span className="text-faint"> → </span>
          <EntityLink value={pf.victim} className="text-mono-green" />
        </div>
      ) : (pf.hosts?.length ?? 0) > 0 ? (
        <div data-testid="promoted-hosts" className="mt-1.5 flex flex-wrap items-center gap-2 text-[12px] text-dim">
          <span>Hosts the finding names:</span>
          {pf.hosts!.map((h) => (
            <EntityLink key={h} value={h} />
          ))}
        </div>
      ) : null}
      {(pf.citations?.length ?? 0) > 0 && (
        <div data-testid="promoted-evidence" className="mt-1.5 flex flex-wrap items-center gap-1.5 text-[12px] text-faint">
          <span>Evidence:</span>
          {pf.citations!.map((id) => (
            <DocumentChip key={id} id={id} />
          ))}
        </div>
      )}
    </div>
  ) : null;

  const supersededEl =
    supersededLock && inv.supersededBy ? (
      <div
        role="status"
        data-testid="superseded-banner"
        className="mb-3.5 flex flex-wrap items-center gap-x-2 gap-y-1 rounded-card border px-3.5 py-2.5 text-[13px]"
        style={{ borderColor: 'rgba(75,139,245,.4)', background: 'rgba(75,139,245,.08)' }}
      >
        <span className="text-text-2">{supersededSentence(inv.supersededRun)}</span>
        <Link
          to={`/investigation/${inv.supersededBy}`}
          className="font-semibold text-accent underline hover:opacity-80"
        >
          Open it.
        </Link>
        <span className="text-dim">This page is a record. Its actions are off.</span>
      </div>
    ) : null;

  // The analyst verdict on another run of the alert (V1-A3). A newer model
  // run showed only its own verdict, and the analyst verdict stood unseen.
  const standingAnalystEl =
    standingAnalyst && standingAnalyst.investigationId !== inv.id ? (
      <div
        role="note"
        data-testid="standing-analyst-verdict"
        className="mb-3.5 flex flex-wrap items-center gap-x-2 gap-y-1 rounded-card border px-3.5 py-2.5 text-[13px]"
        style={{ borderColor: 'rgba(245,166,35,.35)', background: 'rgba(245,166,35,.06)' }}
      >
        <span className="text-text-2">{standingAnalystSentence(standingAnalyst)}</span>
        <Link
          to={`/investigation/${standingAnalyst.investigationId}`}
          className="font-semibold text-accent underline hover:opacity-80"
        >
          Open that run.
        </Link>
      </div>
    ) : null;

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
        <div className="text-[15px] font-semibold">Investigating</div>
        <div className="flex-1" />
        <div className="font-mono text-[12.5px] text-dim">
          elapsed <span className="text-text">{fmt(elapsed)}</span>
        </div>
      </div>
      <div className="mt-[11px] flex items-center gap-[9px] font-mono text-[12px] text-dim">
        <span className="text-accent">steps</span> <span className="text-text-2">{inv.timeline.length}</span>
        <span className="text-ghost">·</span> <span className="text-accent">tool calls</span>{' '}
        <span className="text-text-2">{tools}</span>
      </div>
      <div className="mt-3 flex flex-col gap-1.5 text-[12.5px] text-dim">
        {inv.timeline.slice(-3).map((s) => (
          <div key={s.id} className="flex items-center gap-2">
            <span className="text-success">✓</span> {s.title}
          </div>
        ))}
        <div data-testid="running-now" className="flex items-center gap-2 text-text-2">
          <Spinner size={11} />{' '}
          {inv.currentStep ? `Now ${inv.currentStep}.` : 'Working'}
        </div>
      </div>
      {/* How long a run takes here, from the store (dogfood 2026-10-06,
          first hour W11). The display sat on "Working" for minutes. */}
      <div data-testid="running-estimate" className="mt-3 text-[12px] leading-[1.5] text-dim">
        {runEstimate(inv.typicalRun)} You can close this page. Notifications tells you when the run ends.
      </div>
    </div>
  );

  // Substitute for a Re-run button on a promoted finding: the API refuses a
  // re-run of the anchor event once promotion owns its latest investigation
  // (409 hunt_kind_no_rerun), so offering the button is a click that
  // dead-ends. Points at the sanctioned path instead — re-promoting from the
  // hunt page — with the same link idiom as the provenance strip.
  const reRunOrPromoteLine = (className: string) => (
    <div className={className}>
      Open an investigation on this finding again from its hunt.
      {inv.huntId && (
        <>
          {' '}
          <SourceHuntLink huntId={inv.huntId} objective={inv.huntObjective} />
        </>
      )}
    </div>
  );

  // What the failed run recorded (RL11, RD13). The old copy guessed "the run
  // may have stalled, the agent may have crashed" while the timeline held the
  // real cause, and advised a re-run for a cause no re-run can change: an
  // alert that is no longer in the grid. A run a later run already replaced
  // needs no re-run either (D1).
  const failure = inv.status === 'error' ? inv.failure ?? null : null;
  const noRerunAdvice = !!inv.supersededBy || !!failure?.permanent;
  const tryAgain =
    inv.kind === 'hunt'
      ? 'Open an investigation on it again from its hunt.'
      : 'Re-run it to try again.';
  const failureSentence = failure?.permanent
      ? 'The run reached no verdict. A re-run cannot change the recorded cause.'
      : failure
        ? `The run reached no verdict. ${tryAgain}`
        : `The run reached no verdict. soc-ai recorded no cause. ${tryAgain}`;

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
              ? 'A restart interrupted this investigation'
              : cancelled
                ? 'This investigation stopped before it finished'
                : 'This investigation did not finish'}
        </div>
        {/* The verdict card carries this badge too, but a failed run renders
            THIS panel instead — the marker must survive every terminal state,
            or an errored synthetic run reads as a real failed investigation. */}
        {inv.isSynthEval && <SyntheticEvalBadge />}
        <RunClassChip runClass={inv.runClass} />
        <div className="flex-1" />
        <div className="font-mono text-[12.5px] text-faint">elapsed {fmt(elapsed)}</div>
      </div>
      <div className="mt-2 text-[13px] leading-[1.55] text-dim" style={{ textWrap: 'pretty' }}>
        {/* A hunt-kind row points at the "Re-promote this finding from its
            hunt" line right below instead of telling the analyst to
            "re-run it" here too — the API refuses a direct re-run of a
            promoted finding's anchor (409 hunt_kind_no_rerun), so the two
            instructions would mean different things at the same spot. */}
        {inv.supersededBy
          ? 'The run reached no verdict.'
          : interrupted
          ? inv.kind === 'hunt'
            ? 'There is no verdict. The service restarted during the run. soc-ai re-investigates this finding if Auto-Investigate is on. Open an investigation on it again from its hunt.'
            : 'There is no verdict. The service restarted during the run. soc-ai re-investigates this alert if Auto-Investigate is on. Re-run it now to get a verdict.'
          : cancelled
            ? inv.kind === 'hunt'
              ? 'The run reached no verdict. An operator cancel or a service restart stopped the run before it finished. Open an investigation on it again from its hunt.'
              : 'The run reached no verdict. An operator cancel or a service restart stopped the run before it finished. Re-run it to get a verdict.'
            : stuck && inv.status === 'investigating'
              ? `The run made no progress for 5 minutes. It may have stalled. ${tryAgain}`
              : failureSentence}
      </div>
      {failure && (
        <div data-testid="failure-cause" className="mt-2 text-[12.5px] leading-[1.5] text-dim">
          Recorded cause:{' '}
          <span className="break-words font-mono text-[12px] text-text-2">{failure.cause}</span>
          {failure.hint && <div className="mt-1">{failure.hint}</div>}
        </div>
      )}
      {inv.supersededBy && (
        <div data-testid="superseded-by" className="mt-2 text-[13px] leading-[1.5] text-text-2">
          A later run replaced this one.{' '}
          <Link
            to={`/investigation/${inv.supersededBy}`}
            className="font-semibold text-accent underline hover:opacity-80"
          >
            Open the later run
          </Link>
        </div>
      )}
      <div className="mt-[14px] flex flex-wrap items-center gap-2">
        {inv.kind === 'hunt' ? (
          !inv.supersededBy && reRunOrPromoteLine('text-[13px] leading-[1.5] text-dim')
        ) : noRerunAdvice ? null : (
          <button
            onClick={reRun}
            disabled={reHunting}
            className="flex items-center gap-1.5 rounded-control border border-danger bg-[rgba(240,68,56,.1)] px-4 py-2 text-[13px] font-semibold text-[#fca5a5] hover:bg-[rgba(240,68,56,.18)] disabled:opacity-60"
          >
            {reHunting ? <Spinner size={13} color="#fca5a5" /> : <RotateCw size={13} />}
            {reHunting ? 'Re-running' : 'Re-run investigation'}
          </button>
        )}
        {/* Only where there is something to clear. A cancel was asked for and a
            restart orphan is re-huntable, so neither is counted and neither can
            be dismissed. Offering the button there would invite an ack on a run
            that never needed one. */}
        {diedWithNoVerdict && dismissControl}
      </div>
      {diedWithNoVerdict && errDismissMsg && (
        <div className="mt-2 text-[12px]" style={{ color: '#f04438' }}>
          {errDismissMsg}
        </div>
      )}
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
        {isBacktestReplay(inv.meta?.ranBy) && <BacktestReplayChip />}
        {/* A run against planted synthetic scenarios must never read as a
            real one — badged right beside the verdict. */}
        {inv.isSynthEval && <SyntheticEvalBadge />}
        {/* What the run was allowed to spend, beside what it concluded. */}
        <RunClassChip runClass={inv.runClass} />
        {demo && <RecordedRunChip />}
        {/* What this run read, in one line. A hunt subject has no severity
            and no pair of endpoints: the severity and the two addresses on
            the header belonged to the first cited document, which is one of
            many the run read. The objective and the lead are the subject. */}
        {huntSubject ? (
          <>
            <span
              data-testid="verdict-subject"
              className="min-w-0 max-w-full text-[12.5px] text-dim"
              title={SUBJECT_OBJECTIVE}
            >
              {inv.promotedFinding
                ? `${inv.promotedFinding.label}, ${inv.promotedFinding.title}`
                : firstSentence(huntSubject.objective)}
            </span>
            {huntSubject.lead_id != null && (
              <Link
                data-testid="verdict-lead"
                to={`/leads/${huntSubject.lead_id}`}
                title={SUBJECT_LEAD}
                className="rounded-badge border border-border-input px-2 py-[3px] text-[12px] text-accent hover:underline"
              >
                Lead {huntSubject.lead_id}
              </Link>
            )}
          </>
        ) : null}
        {inv.oracle?.escalated && (
          <OracleBadge oracle={inv.oracle} />
        )}
        {inv.status === 'complete' && inv.meta?.toolCalls === 0 && <HeuristicBadge />}
        <div className="flex-1" />
        <div className="flex items-center gap-[9px]" title={CONFIDENCE_TIP}>
          <ConfidenceRing conf={inv.conf} color={v.color} />
          <div>
            <div className="font-mono text-[18px] font-bold leading-none">{inv.conf.toFixed(2)}</div>
            {/* The word under the number (dogfood 2026-10-06, W1): 0.62 read
                like 0.90. The thresholds are the server's. */}
            <div data-testid="confidence-word" className="text-[10.5px] uppercase tracking-[.05em] text-faint">
              {confidenceWord(inv.conf)} confidence
            </div>
          </div>
        </div>
      </div>

      {/* What the alert is: the rule's severity and the two ends. It sits
          apart from the verdict row, so the rule severity never reads as
          the verdict confidence (dogfood 2026-10-06, C2). */}
      {!huntSubject && (inv.sev || ends) && (
        <div data-testid="verdict-context" className="mb-3 flex flex-wrap items-center gap-2.5">
            {inv.sev && (
              <span data-testid="rule-severity" title={RULE_SEVERITY_TIP} className="inline-flex cursor-help items-center gap-1.5">
                <span className="text-[10.5px] uppercase tracking-[.05em] text-faint">rule severity</span>
                <SeverityTag sev={inv.sev} />
              </span>
            )}
            {/* min-w-0 + max-w-full + break-all: the badge may use the whole
                header row and wraps internally when genuinely out of space —
                the FULL destination is always visible, never clipped to a
                fragment. */}
            {ends && (
              <span
                data-testid="verdict-endpoints"
                className="min-w-0 max-w-full rounded-badge border border-border-input px-2 py-[3px] font-mono text-[12px] text-dim"
                title={ends.title}
              >
                {ends.src && ends.dst ? (
                  <>
                    <span data-testid="endpoint-src" className="break-all text-mono-amber"><EndLink inv={inv} value={ends.src} /></span>
                    <span className="text-faint"> → </span>
                    <span data-testid="endpoint-dst" className="break-all text-mono-green"><EndLink inv={inv} value={ends.dst} /></span>
                  </>
                ) : ends.src ? (
                  <>
                    <span className="text-faint">from </span>
                    <span data-testid="endpoint-src" className="break-all text-mono-amber"><EndLink inv={inv} value={ends.src} /></span>
                  </>
                ) : ends.dst ? (
                  <>
                    <span className="text-faint">to </span>
                    <span data-testid="endpoint-dst" className="break-all text-mono-green"><EndLink inv={inv} value={ends.dst} /></span>
                  </>
                ) : null}
                {ends.on && (
                  <>
                    <span className="text-faint">{ends.src || ends.dst ? ' on ' : 'on '}</span>
                    <span data-testid="endpoint-on" className="break-all text-text-2"><EndLink inv={inv} value={ends.on} /></span>
                  </>
                )}
              </span>
            )}
        </div>
      )}

      {/* rationale as headline */}
      <div className="text-[21px] font-semibold leading-[1.32] tracking-[-.015em]" style={{ textWrap: 'pretty' }}>
        {isFallback ? FALLBACK_HEADLINE : <CitedText text={headline.text} ids={citedIds} entities={inv.entities} />}
      </div>

      {/* summary with citations. A fallback's stored summary is the exception
          text; the pipeline-error panel below says what an analyst needs. */}
      {!isFallback && !overridden && (
        <p className="mt-3.5 text-[13.5px] leading-[1.6] text-[#aeb6c2]" style={{ textWrap: 'pretty' }}>
          <Summary segments={inv.summary} onCite={goToCite} ids={citedIds} entities={inv.entities} />
        </p>
      )}
      {/* After an analyst override the model's paragraph no longer explains
          the verdict. It stays readable, folded, under a label that says
          whose text it is (dogfood 2026-10-06, first hour S3). */}
      {!isFallback && overridden && (
        <div data-testid="pre-override-summary" className="mt-3.5 text-[12.5px] text-dim">
          <button
            onClick={() => setPriorOpen((o) => !o)}
            aria-expanded={priorOpen}
            className="flex items-center gap-1.5 font-semibold hover:text-text"
          >
            <ChevronDown size={13} style={{ transform: priorOpen ? 'rotate(180deg)' : 'none' }} />
            soc-ai said before the override
          </button>
          {priorOpen && (
            <p className="mt-1.5 leading-[1.6] text-[#8b94a3]" style={{ textWrap: 'pretty' }}>
              <Summary segments={inv.summary} onCite={goToCite} ids={citedIds} entities={inv.entities} />
            </p>
          )}
        </div>
      )}
      {/* Every document the report cites, each one opens the event (P3). */}
      {!isFallback && (citedIds.length > 0 || citedPaths.length > 0 || citedTools.length > 0) && (
        <div data-testid="cited-evidence" className="mt-3 flex flex-wrap items-center gap-1.5 text-[12px] text-faint">
          <span>Cited evidence:</span>
          {citedIds.map((id) =>
            unresolvedIds.has(id) ? (
              <span key={id} data-resolved="false" title={UNRESOLVED_CITATION} className="line-through opacity-70">
                <DocumentChip id={id} />
              </span>
            ) : (
              <DocumentChip key={id} id={id} />
            ),
          )}
          {/* A field of the alert the verdict cites. The headline names the
              evidence in words, and the path stays here (dogfood
              2026-10-06, C1). An unresolved one is struck through. */}
          {citedPathItems.map(({ path, resolved }) => (
            <span
              key={path}
              data-testid="cited-path"
              data-resolved={resolved === null ? undefined : String(resolved)}
              title={
                resolved === false
                  ? UNRESOLVED_CITATION
                  : 'A field of the alert that the verdict cites.'
              }
              className={`rounded-chip border bg-surface-2 px-1.5 py-px font-mono text-[11px] ${
                resolved === false
                  ? 'border-dashed border-border-strong text-faint line-through'
                  : 'border-border-strong text-text-2'
              }`}
            >
              {path}
            </span>
          ))}
          {citedTools.map((tool) => (
            <span
              key={tool}
              data-testid="cited-tool"
              title="A tool result that the verdict cites."
              className="rounded-chip border border-border-strong bg-surface-2 px-1.5 py-px text-[11px] text-text-2"
            >
              {toolWords(tool).replace(/^the /, '')}
            </span>
          ))}
          {unresolvedCount > 0 && (
            <span className="text-faint">
              {unresolvedCount === 1
                ? '1 citation did not resolve.'
                : `${unresolvedCount} citations did not resolve.`}
            </span>
          )}
        </div>
      )}
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
          This run failed before it reached a verdict
          {inv.fallback.hint ? <>: {inv.fallback.hint}</> : '.'}
          {' '}soc-ai recorded the verdict Needs more info as a placeholder.
          {/* Same re-run/re-promote split as failedEl above: the button (or
              the re-promote pointer) right below already says how to get a
              real verdict, so this sentence must agree with it instead of
              also instructing "re-run" for a row the API refuses to re-run. */}
          {inv.kind === 'hunt'
            ? ' Open an investigation on it again from its hunt.'
            : ' Re-run it to get a real verdict.'}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {inv.kind === 'hunt' ? (
            reRunOrPromoteLine('text-[12.5px] leading-[1.5] text-dim')
          ) : (
            <button
              onClick={reRun}
              disabled={reHunting || !!rerunLock}
              title={rerunLock ?? undefined}
              className="flex items-center gap-1.5 rounded-control border border-danger bg-[rgba(240,68,56,.1)] px-4 py-2 text-[12.5px] font-semibold text-[#fca5a5] hover:bg-[rgba(240,68,56,.18)] disabled:opacity-60"
            >
              {reHunting ? <Spinner size={13} color="#fca5a5" /> : <RotateCw size={13} />}
              {reHunting ? 'Re-running' : 'Re-run investigation'}
            </button>
          )}
          {dismissControl}
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
    {/* needs_more_info joins inconclusive here: prod held 49 such runs with
        no open questions, so the block and its Request more info button
        never rendered and the settled bar offered Acknowledge instead (P2). */}
    {!isFallback && ((inv.openQuestions?.length ?? 0) > 0 || unsettledVerdict) && (
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
        ) : inv.kind !== 'hunt' ? (
          <div data-testid="open-question-gap" className="mb-2.5 text-[13px] text-text-2">
            {/* The run recorded no question. The rationale names the gap, so
                the block shows that sentence (dogfood 2026-10-06, W2). */}
            {gapFromText ? (
              <ul className="list-disc pl-5">
                <li>{gapFromText}</li>
              </ul>
            ) : inv.verdict === 'needs_more_info' ? (
              'The model needs more evidence to settle this verdict.'
            ) : (
              'The model could not reach a verdict.'
            )}
            <div className="mt-1.5 text-[12.5px] text-dim">
              Start a focused re-investigation. You can also resolve it in chat.
            </div>
          </div>
        ) : null}
        {/* Honest wayfinding for a promoted finding: every re-run affordance
            (Re-run, Deep re-run, Request more info) is hidden for kind='hunt'
            because the API refuses them — so "dig deeper with a focused
            re-investigation" would name a path that does not exist on this
            screen. Say what actually refines a promoted finding instead. */}
        {inv.kind === 'hunt' && (
          <div className="mb-2.5 text-[13px] text-text-2">
            Open an investigation on this finding again from its hunt to refine it. You can
            also ask a follow-up in Ask soc-ai. This screen cannot re-run the investigation of
            a finding.
          </div>
        )}
        <div className="flex flex-wrap items-center gap-2">
          {/* A promoted finding has no re-run affordance in this slice — the
              server refuses it (409 hunt_kind_no_rerun); re-promote from the
              hunt page instead. */}
          {inv.kind !== 'hunt' && (
            <button
              onClick={requestInfo}
              disabled={requestingInfo || !!supersededLock}
              title={supersededLock ?? 'This button starts a new investigation. The new investigation targets the open questions above.'}
              className="flex items-center gap-1.5 rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold text-[#0b0f16] disabled:opacity-60"
              style={{ background: '#f5a623', borderColor: '#f5a623' }}
            >
              {requestingInfo ? <Spinner size={13} /> : <Crosshair size={13} />}
              {requestingInfo ? 'Requesting' : 'Request more info'}
            </button>
          )}
          <button
            onClick={resolveInChat}
            title={`Open Ask soc-ai and ask: ${RESOLVE_PROMPT}`}
            className="flex items-center gap-1.5 rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold text-[#cfe0ff]"
            style={{ background: 'rgba(75,139,245,.14)', borderColor: 'rgba(75,139,245,.4)' }}
          >
            <span className="flex" style={{ color: '#facc15' }}><Zap size={13} /></span> Resolve in chat
          </button>
        </div>
        {/* The focused re-investigation that never started, kept beside the
            button that was supposed to start it. */}
        {requestInfoError &&
          startFailureStrip(requestInfoError, () => setRequestInfoError(null), 'mt-2.5')}
      </div>
    )}
    {inv.kind === 'hunt' && inv.huntId && (
      <div
        className="rounded-card border px-3.5 py-2.5 text-[12px] text-dim"
        style={{ borderColor: 'rgba(244,114,182,.35)', background: 'rgba(244,114,182,.06)' }}
      >
        <span style={{ color: '#f472b6' }}>Promoted from hunt</span>
        {': '}
        <SourceHuntLink huntId={inv.huntId} objective={inv.huntObjective} />
      </div>
    )}
    {inv.resolution?.resolved_via === 'manual' && (
      <div
        className="rounded-card border px-3.5 py-2.5 text-[12px] text-dim"
        style={{ borderColor: 'rgba(245,166,35,.35)', background: 'rgba(245,166,35,.06)' }}
      >
        <span style={{ color: '#f5a623' }}>Analyst verdict</span>
        {'. Set by '}
        <span className="font-mono text-text-2">{inv.resolution.resolved_by}</span>
        {'. Previous verdict: '}
        <span className="text-text-2">{verdictLabel(inv.resolution.original_verdict)}</span>
        {'.'}
      </div>
    )}
    {inv.validatorNote && (
      <div
        className="rounded-card border px-3.5 py-2.5 text-[12px] text-dim"
        style={{ borderColor: 'rgba(107,135,168,.3)', background: 'rgba(107,135,168,.05)' }}
      >
        <span className="font-semibold" style={{ color: '#8fa3bf' }}>Post-validator override</span>
        {': '}
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
    `The graph has ${inv.nodes.length} entities and ${inv.edges.length} relationships.${scopeLabel && inv.verdict === 'true_positive' ? ` ${GRAPH_SCOPE_SENTENCE[inv.graphScope ?? ''] ?? ''}` : ''}`;
  const graphHeight = layout === 'page' ? 320 : 240;
  // Every entity the run names, as links: the server's refs when it sent
  // them, else the labels of the graph nodes.
  const scopeEntities: EntityRef[] = inv.entities?.length
    ? inv.entities
    : Array.from(new Set(inv.nodes.map((n) => n.label).filter((l) => l && l !== '?'))).map((v) => ({
        value: v,
        type: guessEntityType(v),
        role: '',
        host_key: null,
        href: '',
      }));
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
            <div className="text-[13px] font-semibold">Entity scope</div>
            <span className="font-mono text-[11px] text-faint">
              {inv.nodes.length} entities
              {!graphOpen && scopeLabel && (graphInteresting || inv.verdict === 'true_positive') ? ` · ${scopeLabel}` : ''}
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
      {scopeEntities.length > 0 && (
        <div data-testid="entity-scope-links" className="flex flex-wrap items-center gap-x-2.5 gap-y-1 border-t border-border-faint px-[15px] py-[8px] text-[12px]">
          {scopeEntities.map((e) => (
            <EntityRefLink key={`${e.type}:${e.value}`} entity={e} />
          ))}
        </div>
      )}
      {graphOpen && (
        <div className="border-t border-border">
          <EntityGraph nodes={inv.nodes} edges={inv.edges} highlight={inv.host} height={graphHeight} showLegend={layout === 'page'} />
        </div>
      )}
    </Panel>
  );

  // Advisory actions (a completed run's recommendations) execute on demand.
  // The card states the write and asks for a confirm first. The confirm IS
  // the human consent. These write to the live Security Onion grid.
  const runAdvisory = (a: RecommendedAction, index: number, scope: 'group' | 'alert') => {
    const blocked = demoBlocked(demo);
    if (blocked) { setActionMsg((m) => ({ ...m, [a.id]: blocked })); return; } // demo: no doomed grid write
    setActions((s) => ({ ...s, [a.id]: 'executing' }));
    setActionMsg((m) => ({ ...m, [a.id]: '' }));
    executeAction(inv.id, index, a.tag === 'ack' ? scope : undefined)
      .then((res) => {
        if (res.status === 'executed') {
          setActions((s) => ({ ...s, [a.id]: 'approved' }));
          setActionMsg((m) => ({ ...m, [a.id]: res.detail }));
          // A group ack covers the detection. Let the Alerts list hide the
          // whole detection optimistically while the ES agg catches up.
          if (a.tag === 'ack' && scope === 'group') onAcked?.(inv.name);
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
  // Dismiss and its undo go to the server, with the actor and the time
  // (dogfood 2026-10-06, first hour S4). The card changes when the server
  // answers. A failure leaves the card as it was and says why.
  const setDismissal = (a: RecommendedAction, index: number, dismiss: boolean) => {
    const blocked = demoBlocked(demo);
    if (blocked) { setDismissMsg((m) => ({ ...m, [a.id]: blocked })); return; }
    setActions((s) => ({ ...s, [a.id]: 'dismissing' }));
    setDismissMsg((m) => ({ ...m, [a.id]: '' }));
    (dismiss ? dismissAction(inv.id, index) : restoreAction(inv.id, index))
      .then((r) =>
        setDismissals((d) => ({ ...d, [a.id]: r.dismissed ? { by: r.by, at: r.at } : null })),
      )
      .catch((e) =>
        setDismissMsg((m) => ({
          ...m,
          [a.id]: e instanceof Error ? e.message : 'soc-ai did not store the change. Try again.',
        })),
      )
      .finally(() =>
        setActions((s) => {
          const { [a.id]: _drop, ...rest } = s;
          return rest;
        }),
      );
  };
  // The standing dismissal of one action: this tab's change, else the server's.
  const dismissalOf = (a: RecommendedAction): ActionDismissalState | null => {
    if (a.id in dismissals) return dismissals[a.id];
    return a.dismissed ? { by: a.dismissedBy ?? 'an analyst', at: a.dismissedAt ?? null } : null;
  };
  // Whether each write may run is the server's answer (blockedReason), from
  // the one rule the row of the pending-action list, the needs-you count and
  // the execute route read. The card read the kind of the run, and offered a
  // write on a lead run and on an alert a promoted lead anchors (V3-N2).
  // Dismiss stays: it writes nothing to Security Onion.
  const actionsEl = (
    <CollapsibleSection
      title="Recommended actions"
      meta={pendingCount === 1 ? '1 action waits for you' : `${pendingCount} actions wait for you`}
    >
      <div className="flex flex-col gap-2.5">
        {inv.actions.map((a, i) => (
          <ActionCard
            key={a.id}
            action={a}
            index={i}
            invId={inv.id}
            decision={actions[a.id]}
            message={actionMsg[a.id]}
            executedBy={me ?? 'you'}
            dismissal={dismissalOf(a)}
            dismissError={dismissMsg[a.id]}
            onExecute={(scope) => runAdvisory(a, i, scope)}
            onDismiss={() => setDismissal(a, i, true)}
            onUndoDismiss={() => setDismissal(a, i, false)}
            lockedReason={supersededLock ?? undefined}
            cases={inv.alertCases}
            casesComplete={inv.alertCasesComplete ?? false}
            confirmRequest={confirmRequest?.id === a.id ? confirmRequest.n : undefined}
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
  //
  // The message is the Alerts console's, not a second one written here. These
  // buttons call the same two endpoints, and those endpoints learned to
  // distinguish their outcomes — a case withheld from a duplicate, an alert
  // Security Onion had only acknowledged, a claim from an earlier escalate
  // whose outcome is unknown, a case created with nothing attached — while
  // this bar went on reading `escalated` and `total` and discarding the rest.
  //
  // So the drawer called an empty case a successful escalate ("Escalated 1 of
  // 1 event to a case") and never named the case id somebody has to close, and
  // an ack that changed nothing visible because Security Onion had already
  // recorded it read as a button that did not work.
  const runSettled = (kind: 'ack' | 'escalate') => {
    setSettledAction(kind);
    setSettledMsg(null);
    const group = { name: inv.name, kind: inv.kind };
    // A press that wrote nothing reads in the info tone and is no action
    // taken: a green line over "0 written" read as a write (R2-D15).
    const call: Promise<{ text: string; wrote: boolean }> =
      kind === 'ack'
        ? ackGroup(group).then((r) => ({ text: ackMessage(r, inv.name), wrote: !ackWroteNothing(r) }))
        : escalateGroup(group).then((r) => ({
            text: escalateMessage(r, inv.name),
            wrote: !escalateWroteNothing(r),
          }));
    call
      .then(({ text, wrote }) => {
        setSettledMsg({ tone: wrote ? 'ok' : 'info', text });
        if (kind === 'ack' && wrote) onAcked?.(inv.name);
      })
      .catch((e) => setSettledMsg({ tone: 'err', text: e instanceof Error ? e.message : 'request failed' }))
      .finally(() => setSettledAction(null));
  };
  // Suppressed for a pipeline fallback: the run FAILED before reaching a
  // verdict — offering "verdict settled, acknowledge it" directly under the
  // "re-run to get a real verdict" panel contradicts the only sane next step.
  // Also suppressed for kind='hunt': there is nothing in Security Onion to
  // ack — the promoted finding's anchor is telemetry, not an alert, and the
  // server refuses the write too (Task 6). This is the honest-UI half.
  const settledActionEl =
    inv.status === 'complete' &&
    inv.actions.length === 0 &&
    !isFallback &&
    !unsettledVerdict &&
    inv.kind !== 'hunt' &&
    // The server says no write from this page can reach Security Onion: a
    // promotion landed the run, or a promotion anchors its alert (V3-N2).
    !inv.writeBlockedReason &&
    // A backtest replay measures the model on an alert an analyst already
    // closed. Its page offers no write, so no group ack and no escalate.
    !isBacktestReplay(inv.meta?.ranBy) ? (
      <div
        className="rounded-card border px-3.5 py-3"
        style={{ borderColor: 'rgba(245,166,35,.35)', background: 'rgba(245,166,35,.06)' }}
      >
        <div className="mb-1.5 text-[12px] font-semibold uppercase tracking-[.05em]" style={{ color: '#f5a623' }}>
          No automatic action
        </div>
        <p className="mb-2.5 text-[13px] leading-[1.5] text-text-2">
          The investigation recommended no automatic actions. Acknowledge this detection to
          close it. Escalate this detection to open a Security Onion case.
        </p>
        {inv.alertAcked && (
          <p className="mb-2.5 text-[12px] leading-[1.5] text-dim">
            <span style={{ color: '#7ba893' }}>✓ Security Onion records this alert as acknowledged.</span>
            {' '}The Acknowledge button acknowledges the whole detection group again.
          </p>
        )}
        <div className="flex flex-wrap items-center gap-2">
          {settledConfirm ? (
            <div
              data-testid="settled-confirm"
              className="w-full rounded-[7px] border px-3 py-2.5"
              style={{ borderColor: 'rgba(245,166,35,.35)', background: 'rgba(245,166,35,.07)' }}
            >
              <div className="mb-2.5 flex items-start gap-2 text-[12.5px] leading-[1.5] text-warn">
                <AlertTriangle size={13} className="mt-px flex-none" />
                <span>This writes to Security Onion. {SETTLED_SCOPE[settledConfirm]}</span>
              </div>
              <div className="flex flex-wrap gap-2">
                <button
                  onClick={() => {
                    const kind = settledConfirm;
                    setSettledConfirm(null);
                    runSettled(kind);
                  }}
                  className="flex items-center gap-1.5 rounded-[7px] border border-warn bg-[rgba(245,166,35,.12)] px-[11px] py-1.5 text-[12.5px] font-semibold text-warn hover:bg-[rgba(245,166,35,.2)]"
                >
                  <Check size={13} /> {settledConfirm === 'ack' ? 'Confirm acknowledge' : 'Confirm escalate'}
                </button>
                <button
                  onClick={() => setSettledConfirm(null)}
                  className="rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-1.5 text-[12.5px] font-semibold text-text-2 hover:text-text"
                >
                  Cancel
                </button>
              </div>
            </div>
          ) : (
          <>
          <button
            onClick={() => setSettledConfirm('ack')}
            disabled={settledAction !== null || !!supersededLock}
            title={supersededLock ?? undefined}
            className="flex items-center gap-1.5 rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold text-text-2 hover:text-text disabled:opacity-60"
            style={{ borderColor: 'rgba(123,168,147,.4)', background: 'rgba(123,168,147,.10)' }}
          >
            {settledAction === 'ack' ? <Spinner size={13} /> : <Check size={13} />}
            {settledAction === 'ack' ? 'Acknowledging' : 'Acknowledge'}
          </button>
          <button
            onClick={() => setSettledConfirm('escalate')}
            disabled={settledAction !== null || !!supersededLock}
            title={supersededLock ?? undefined}
            className="flex items-center gap-1.5 rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold disabled:opacity-60"
            style={{ borderColor: 'rgba(240,68,56,.4)', background: 'rgba(240,68,56,.10)', color: '#fca5a5' }}
          >
            {settledAction === 'escalate' ? <Spinner size={13} /> : <Triangle size={13} />}
            {settledAction === 'escalate' ? 'Escalating' : 'Escalate to case'}
          </button>
          </>
          )}
          {settledMsg && (
            <span
              data-testid="settled-msg"
              data-tone={settledMsg.tone}
              className="text-[12px] font-semibold"
              style={{
                color:
                  settledMsg.tone === 'ok' ? '#7ba893' : settledMsg.tone === 'info' ? '#8b94a3' : '#f04438',
              }}
            >
              {settledMsg.text}
            </span>
          )}
        </div>
      </div>
    ) : null;

  // Draft-detection affordance (1.3 slice 3): a promoted hunt finding that
  // landed a CONFIRMED true_positive verdict can be turned into a Sigma rule
  // for export (never deployed by soc-ai — see DraftDetectionPane). Gated on
  // the SAME kind==='hunt' shape settledActionEl suppresses itself for (there
  // is no Security Onion alert here to draft "from" other than the finding's
  // own evidence) plus a settled TP verdict and the sigma_authoring_enabled
  // flag — a running/needs-more-info/FP run has nothing confirmed to codify
  // into a detection yet.
  const confirmedTpHunt =
    inv.kind === 'hunt' && inv.status === 'complete' && inv.verdict === 'true_positive';
  const canDraftDetection = confirmedTpHunt && sigmaAuthoringEnabled;
  // Explicitly off (the probe answered, flag false) — NOT `!sigmaAuthoringEnabled`,
  // which is also true while the probe is unsettled and must render nothing.
  const sigmaKnownOff = about.data?.sigma_authoring_enabled === false;
  const draftDetectionEl = canDraftDetection ? (
    <DraftDetectionPane
      onDraft={() => draftInvestigationDetection(inv.id)}
      provenance={
        inv.huntId ? (
          <div className="text-[12px] text-dim">
            This detection comes from a promoted finding. The hunt is{' '}
            <SourceHuntLink huntId={inv.huntId} objective={inv.huntObjective} />
          </div>
        ) : undefined
      }
    />
  ) : confirmedTpHunt && sigmaKnownOff ? (
    // The one investigation shape that COULD draft a detection, with the flag
    // off: a quiet pointer at the switch instead of rendering nothing — the
    // flag is hot-editable, so this is a live path, not a dead end.
    <div className="text-[12px] text-faint">
      Sigma export is off.{' '}
      <Link
        to="/config#triage-automation"
        state={{ highlightKey: 'sigma_authoring_enabled' }}
        className="underline hover:text-dim"
      >
        Turn it on in Settings
      </Link>
    </div>
  ) : null;

  const timelineEl = (
    <CollapsibleSection
      title="Investigation timeline"
      meta={`${plural(inv.timeline.length, 'step')} · ${running ? durationLabel(elapsed) : inv.elapsedLabel}`}
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
        title="Model notes"
        meta={`${reasoning.length} turn${reasoning.length === 1 ? '' : 's'} · not evidence`}
        open={reasoningOpen}
        onToggle={() => setReasoningOpen((o) => !o)}
      >
        <Panel>
          {/* The raw monologue carried the weight of the narrative (dogfood
              2026-10-06). It is marked as the model's notes and stays folded. */}
          <div data-testid="scratch-note" className="border-b border-border-faint px-3 py-2 text-[12px] text-dim">
            The model wrote these notes while it worked. The notes are not evidence. The
            verdict and the cited evidence are above.
          </div>
          <div className="flex flex-col gap-3 p-1 opacity-80">
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

  // The escalate a chat answer points at, inline in the chat (C4). It opens
  // the confirm of the escalate card, or of the settled bar.
  const escalateCard = inv.actions.find((a) => a.tag === 'escalate' && !a.applied && !a.dismissed);
  const canSettledEscalate =
    inv.status === 'complete' &&
    inv.actions.length === 0 &&
    !isFallback &&
    inv.kind !== 'hunt' &&
    !inv.writeBlockedReason;
  // An escalate card the server turned off is no target for the chat either.
  const escalateBlocked = !!escalateCard?.blockedReason || !!inv.writeBlockedReason;
  const escalateFromChat =
    supersededLock || inv.kind === 'hunt' || escalateBlocked || (!escalateCard && !canSettledEscalate)
      ? undefined
      : () => {
          if (escalateCard) {
            setConfirmRequest({ id: escalateCard.id, n: Date.now() });
            requestAnimationFrame(() =>
              document
                .querySelector(`[data-testid="action-card-${inv.actions.indexOf(escalateCard)}"]`)
                ?.scrollIntoView({ behavior: 'smooth', block: 'center' }),
            );
          } else {
            setSettledConfirm('escalate');
          }
        };
  // The panel's investigation scope: the verdict a proposal compares with,
  // the ids an answer may cite, and the two page actions it can call.
  useChatScope({
    scope: { kind: 'investigation', id: inv.id, name: inv.name },
    investigation: {
      verdict: inv.verdict,
      linkIds: citedIds,
      seed: inv.seedChat,
      onVerdictApplied,
      onEscalate: escalateFromChat,
    },
  });

  // ── New-run confirm (R2-D1, R2-I5, V1-A2, V1-A3) ────────────────────────
  const newRunLines = newRunAsk ? newRunConfirmText(newRunAsk.action, newRunStakes) : null;
  const newRunTitle = newRunAsk?.action === 'request_info' ? 'Request more info' : 'Re-run investigation';
  const confirmNewRun = () => {
    const ask = newRunAsk;
    setNewRunAsk(null);
    if (ask?.action === 'rerun') startReRun(ask.deep, true);
    else if (ask?.action === 'request_info') startRequestInfo(true);
  };
  const newRunConfirmEl =
    newRunAsk && newRunLines ? (
      <div
        className="fixed inset-0 z-50 flex items-center justify-center"
        style={{ background: 'rgba(0,0,0,.65)' }}
        onClick={(e) => { if (e.target === e.currentTarget) setNewRunAsk(null); }}
        onKeyDown={(e) => { if (e.key === 'Escape') setNewRunAsk(null); }}
      >
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="new-run-confirm-title"
          className="relative w-[440px] max-w-[calc(100vw-32px)] rounded-panel-lg border p-6"
          style={{ background: '#0e1117', borderColor: '#1c232e' }}
        >
          <div id="new-run-confirm-title" className="mb-3 text-[14px] font-semibold">
            {newRunTitle}
          </div>
          <div className="mb-5 flex flex-col gap-1.5 text-[13px] leading-[1.55] text-text-2">
            {newRunLines.map((line) => (
              <p key={line}>{line}</p>
            ))}
          </div>
          <div className="flex flex-wrap justify-end gap-2.5">
            <button
              autoFocus
              onClick={() => setNewRunAsk(null)}
              className="rounded-control border border-border-strong bg-surface-3 px-4 py-2 text-[13px] font-semibold text-text-2 hover:text-text"
            >
              {newRunStakes.analyst ? 'Keep the analyst verdict' : 'Cancel'}
            </button>
            <button
              onClick={confirmNewRun}
              className="flex items-center gap-1.5 rounded-control border border-warn bg-[rgba(245,166,35,.12)] px-4 py-2 text-[13px] font-semibold text-warn hover:bg-[rgba(245,166,35,.2)]"
            >
              {newRunAsk.action === 'rerun' ? <RotateCw size={13} /> : <Crosshair size={13} />}
              {newRunStakes.analyst ? 'Replace the analyst verdict' : 'Start a live run'}
            </button>
          </div>
        </div>
      </div>
    ) : null;

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
          <span><span className="font-semibold">WARNING:</span> This override replaces the current verdict
          and its recommended actions. soc-ai records the override with your name. You can override again later.</span>
        </div>
        <div className="mb-3">
          <label className="mb-1.5 block text-[12px] font-semibold text-dim">New verdict</label>
          <select
            value={overrideVerdictVal}
            onChange={(e) => setOverrideVerdictVal(e.target.value)}
            className="w-full rounded-control border border-border-input bg-bg px-3 py-2 text-[13px] text-text outline-none focus:border-accent"
          >
            <option value="" disabled>
              Choose a verdict
            </option>
            {VERDICT_OPTIONS.map((o) => (
              <option key={o.value} value={o.value} disabled={o.value === inv.verdict}>
                {o.value === inv.verdict ? `${o.label} (the current verdict)` : o.label}
              </option>
            ))}
          </select>
        </div>
        <div className="mb-5">
          <label className="mb-1.5 block text-[12px] font-semibold text-dim">
            Rationale <span className="text-faint font-normal">optional · recorded</span>
          </label>
          <textarea
            value={overrideRationale}
            onChange={(e) => setOverrideRationale(e.target.value)}
            rows={3}
            placeholder="Give your reason. Example: analyst confirmed the activity in a manual PCAP review."
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
            disabled={overriding || !overrideVerdictVal}
            onClick={() => {
              const blocked = demoBlocked(demo);
              if (blocked) { setOverrideError(blocked); return; } // demo: no doomed write
              setOverriding(true);
              setOverrideError(null);
              const chosen = overrideVerdictVal;
              submitOverride(inv.id, chosen, overrideRationale || undefined)
                .then((r) => {
                  setOverrideOpen(false);
                  // The save is confirmed where the analyst looks (first hour S3).
                  toast({
                    tone: 'success',
                    message: overrideToast(chosen, r.resolvedBy ?? me ?? 'you'),
                  });
                  onVerdictApplied?.();
                })
                .catch((err: unknown) => {
                  const msg = err instanceof Error ? err.message : 'The override failed. Try again.';
                  setOverrideError(msg);
                })
                .finally(() => setOverriding(false));
            }}
            className="flex items-center gap-1.5 rounded-control border border-warn bg-[rgba(245,166,35,.12)] px-4 py-2 text-[13px] font-semibold text-warn hover:bg-[rgba(245,166,35,.2)] disabled:opacity-60"
          >
            {overriding ? <Spinner size={13} /> : <Check size={13} />}
            {overriding ? 'Applying' : 'Confirm override'}
          </button>
        </div>
      </div>
    </div>
  ) : null;

  // analyst-context rail panels (only render when the data is present).
  const alertEl = huntSubject ? (
    <HuntSubjectPanel subject={huntSubject} promotedOrdinal={inv.promotedFinding?.ordinal} />
  ) : inv.alert ? (
    <AlertDetailsPanel alert={inv.alert} sev={inv.sev} kind={inv.kind} entities={inv.entities} windowHours={inv.hostContextWindowHours} />
  ) : null;
  // One panel per end of the alert, each named. A run stored before the per-end
  // split has only the pooled list, so its panel says it covers both ends.
  // The counts have a window. The panel stated none (R2-D21).
  const hostWindow =
    inv.hostContextWindowHours != null
      ? ` within ${inv.hostContextWindowHours} hours of the alert`
      : '';
  const hostEl = inv.hostContexts?.length ? (
    <>
      {inv.hostContexts.map((h) => (
        <HostContextPanel
          key={`${h.end}-${h.ip}`}
          host={h.ip}
          role={h.end === 'destination' ? 'destination' : 'source'}
          summary={h.end === 'destination' ? 'Destination of this alert' : 'Source of this alert'}
          sections={[
            { label: `Alerts with this host as source${hostWindow}`, signals: h.asSource },
            { label: `Alerts with this host as destination${hostWindow}`, signals: h.asDestination },
          ]}
        />
      ))}
    </>
  ) : inv.hostContext?.length ? (
    <HostContextPanel
      host="Both ends"
      summary={`${inv.hostContext.length} alert types on either end of this alert${hostWindow}`}
      sections={[{ label: `Alerts on either end of this alert${hostWindow}`, signals: inv.hostContext }]}
    />
  ) : null;
  const metaEl = inv.meta ? <InvMetaPanel meta={inv.meta} id={inv.id} toolCalls={tools} /> : null;
  // The other detections on the flow of this alert, with their verdicts
  // (R2-D9). A hunt has no alert, so no flow.
  const sameFlow = !huntSubject && inv.alert;
  // A run in flight has no verdict yet. The verdict card would read
  // an untriaged placeholder with no endpoints and 0.00 confidence (P16).
  const showVerdict = !(running && inv.verdict === 'untriaged');

  // ── PAGE (permalink): two-column workstation layout ──────────────────────
  // Verdict spans full width as the hero. The wide main column carries the
  // analyst's first-class surfaces — the blast-radius graph (collapsed), actions,
  // and the timeline. The right rail holds collapsible reference panels (alert,
  // host, metadata). The chat is the shell's Ask soc-ai panel, opened from
  // the top bar, so it costs no layout space.
  if (layout === 'page') {
    return (
      <div className="mx-auto max-w-workstation font-sans text-text">
        {flowEl}
        {toolbarEl}
        {reRunErrorEl}
        {supersededEl}
        {standingAnalystEl}
        {promotedFindingEl}
        {failed ? (
          <>
            {failedEl}
            {/* Whatever partial steps ran before the failure are still useful. */}
            {inv.timeline.length > 0 && <div className="mt-[18px]">{timelineEl}</div>}
          </>
        ) : (
          <>
            {running && runningEl}
            {showVerdict && verdictEl}
            <div className="mt-[18px] grid grid-cols-1 items-start gap-[18px] lg:grid-cols-[minmax(0,1fr)_360px]">
              <div className="flex min-w-0 flex-col gap-[18px]">
                {inv.nodes.length > 0 && entityEl}
                {inv.actions.length > 0 ? actionsEl : settledActionEl}
                {draftDetectionEl}
                {timelineEl}
                {reasoningEl}
              </div>
              <div className="flex flex-col gap-[18px]">
                {alertEl}
                {sameFlow && <SameFlowPanel invId={inv.id} verdict={inv.verdict} onShow={onShowSibling} />}
                {hostEl}
                {metaEl}
              </div>
            </div>
          </>
        )}
        {overrideModalEl}
        {newRunConfirmEl}
      </div>
    );
  }

  // ── DRAWER: compact single column ────────────────────────────────────────
  return (
    <div className="font-sans text-text" style={{ padding: '18px 18px 30px' }}>
      {flowEl}
      {toolbarEl}
      {reRunErrorEl}
      {supersededEl}
      {standingAnalystEl}
      {promotedFindingEl}
      {failed ? (
        <>
          {failedEl}
          {/* Whatever partial steps ran before the failure are still useful. */}
          {inv.timeline.length > 0 && <div className="mt-5">{timelineEl}</div>}
        </>
      ) : (
        <>
          {running && runningEl}
          {showVerdict && verdictEl}
          {!huntSubject && inv.alert && (
            <div data-testid="drawer-alert-details" className="mt-[18px]">
              <AlertDetailsPanel alert={inv.alert} sev={inv.sev} kind={inv.kind} entities={inv.entities} windowHours={inv.hostContextWindowHours} brief />
            </div>
          )}
          {sameFlow && <SameFlowPanel invId={inv.id} verdict={inv.verdict} className="mt-[18px]" onShow={onShowSibling} />}
          {inv.nodes.length > 0 && <div className="mt-[18px]">{entityEl}</div>}
          <div className="mt-[18px]">{inv.actions.length > 0 ? actionsEl : settledActionEl}</div>
          {draftDetectionEl && <div className="mt-[18px]">{draftDetectionEl}</div>}
          <div className="mt-5">{timelineEl}</div>
          {reasoningEl && <div className="mt-5">{reasoningEl}</div>}
        </>
      )}
      {overrideModalEl}
      {newRunConfirmEl}
    </div>
  );
}

/** Starter questions that fit the verdict. The Ask soc-ai panel owns them. */
export const starterQuestions = investigationStarters;

// ── analyst-context rail panels (page layout) ──────────────────────────────

/**
 * What a hunt investigation investigated.
 *
 * The alert panel below answers the same question for an alert run: which rule
 * fired, on which event. A hunt has neither. It has an objective, the findings
 * the investigation read, the documents those findings cite, and the lead the
 * hunt started from. The panel states all four, and every one of them is a
 * link or a count the analyst can check.
 */
function HuntSubjectPanel({
  subject,
  promotedOrdinal,
}: {
  subject: InvestigationSubject;
  /** The finding the analyst promoted. Its objective is the raw prompt of the
   *  hunt, so it folds behind "Show objective". */
  promotedOrdinal?: number;
}) {
  const [objectiveOpen, setObjectiveOpen] = useState(promotedOrdinal == null);
  const findings = subject.finding_ordinals.map((ordinal, i) => {
    // The title is what an analyst reads. A backend that sends the ordinals
    // alone still says which findings were read, and a made-up title would be
    // worse than the number.
    //
    // The ordinal is an identifier and it counts from zero. A person counts
    // from one, so the first finding of the hunt reads "Finding 1" and the
    // stored ordinal stays as it is.
    const title = subject.finding_titles?.[i];
    const number = ordinal + 1;
    return { ordinal, label: title ? `Finding ${number} · ${title}` : `Finding ${number}` };
  });
  return (
    <CollapsiblePanel
      icon={<GitBranch size={15} />}
      title={<span title={CHIP_SUBJECT_HUNT}>Subject: hunt</span>}
      summary={subject.objective}
    >
      <div data-testid="investigation-subject" className="flex flex-col">
        <div className="border-b border-border-faint px-[15px] py-[9px]">
          <div className="flex items-center gap-2 text-[10.5px] font-semibold uppercase tracking-[.05em] text-faint">
            objective
            {promotedOrdinal != null && (
              <button
                data-testid="show-objective"
                onClick={() => setObjectiveOpen((o) => !o)}
                aria-expanded={objectiveOpen}
                className="font-sans normal-case tracking-normal text-accent hover:underline"
              >
                {objectiveOpen ? 'Hide objective' : 'Show objective'}
              </button>
            )}
          </div>
          {objectiveOpen && (
            <div
              className="mt-1 text-[12.5px] leading-[1.5] text-text-2"
              title={SUBJECT_OBJECTIVE}
            >
              {subject.objective}
            </div>
          )}
        </div>
        <div className="border-b border-border-faint px-[15px] py-[9px]">
          <div className="text-[10.5px] font-semibold uppercase tracking-[.05em] text-faint">
            findings
          </div>
          <ul
            data-testid="subject-findings"
            title={SUBJECT_FINDINGS}
            className="mt-1 flex flex-col gap-1 text-[12.5px] leading-[1.5] text-text-2"
          >
            {findings.map((f) => (
              <li key={f.ordinal}>
                {f.label}
                {f.ordinal === promotedOrdinal && (
                  <span
                    data-testid="subject-promoted"
                    className="ml-1.5 rounded-badge border border-border-input px-1.5 py-px text-[10.5px] font-semibold text-accent"
                  >
                    promoted
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 px-[15px] py-[9px] text-[12px]">
          <Link
            to={`/hunts/${subject.hunt_id}`}
            title={SUBJECT_HUNT_LINK}
            className="font-mono text-[11.5px] text-accent underline hover:opacity-80"
          >
            {subject.hunt_id}
          </Link>
          {subject.lead_id != null && (
            <Link
              to={`/leads/${subject.lead_id}`}
              title={SUBJECT_LEAD}
              className="text-accent underline hover:opacity-80"
            >
              Lead {subject.lead_id}
            </Link>
          )}
          <span data-testid="subject-documents" className="text-dim" title={SUBJECT_DOCUMENTS}>
            {plural(subject.document_ids.length, 'document')}
          </span>
        </div>
      </div>
    </CollapsiblePanel>
  );
}

/** "192.0.2.1:443" splits into the address and the port. The address is the
 *  entity. Any other shape stays whole. */
export function splitEndpoint(value: string): { addr: string; port: string | null } {
  const m = value.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$/);
  return m ? { addr: m[1], port: m[2] } : { addr: value, port: null };
}

/** One end of the alert in Alert details: the address as a link, the port as text. */
function EndpointValue({ value, entities }: { value: string; entities?: EntityRef[] }) {
  const { addr, port } = splitEndpoint(value);
  return (
    <>
      <EndLink inv={{ entities }} value={addr} />
      {port && <span className="text-faint">:{port}</span>}
    </>
  );
}

function AlertDetailsPanel({
  alert,
  sev,
  kind,
  entities,
  brief = false,
  windowHours = null,
}: {
  alert: AlertMeta;
  sev?: Severity;
  kind: DetectionKind;
  entities?: EntityRef[];
  /** The drawer form: four lines, rule, source, destination and user, with
   *  the other fields behind a toggle (dogfood 2026-10-06, first hour W4). */
  brief?: boolean;
  /** The hours each side of the alert the fire count covers. */
  windowHours?: number | null;
}) {
  const [copied, setCopied] = useState(false);
  const [allFields, setAllFields] = useState(!brief);

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
    ['source', <span className="text-mono-amber"><EndpointValue value={alert.src} entities={entities} /></span>],
    ['dest', <span className="text-mono-green"><EndpointValue value={alert.dst} entities={entities} /></span>],
    ['user', alert.user ? <EntityLink value={alert.user} type="user" /> : null],
    ['host', alert.host ? <EndLink inv={{ entities }} value={alert.host} /> : null],
    ['proto', alert.proto],
    ['action', alert.action],
    // With the zone: a bare local time read as UTC (R2-D17).
    ['alert time', <span title={alert.time ?? undefined}>{absTime(alert.time, { zone: true })}</span>],
    // The count is the fires of this rule on either end of the alert in the
    // host-context window. It read "events 6" on a 13-event group (R2-D21).
    [
      'rule fires',
      `${alert.count} on either end${windowHours != null ? ` within ${windowHours} hours of the alert` : ''}`,
    ],
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
        {alert.id && allFields && (
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
        {rows
          .filter(([k]) => allFields || BRIEF_ROWS.has(k))
          .map(([k, val]) =>
            val == null ? (
              brief && !allFields && k === 'user' ? (
                <div key={k} className="flex gap-3 border-b border-border-faint px-[15px] py-[7px] text-[12px]">
                  <div className="w-[72px] flex-none text-faint">{k}</div>
                  <div className="min-w-0 flex-1 text-faint">The alert names no user.</div>
                </div>
              ) : null
            ) : (
              <div key={k} className="flex gap-3 border-b border-border-faint px-[15px] py-[7px] text-[12px] last:border-0">
                <div className="w-[72px] flex-none text-faint">{k}</div>
                <div className="min-w-0 flex-1 break-words font-mono text-text-2">{val}</div>
              </div>
            )
          )}
        {brief && (
          <button
            onClick={() => setAllFields((o) => !o)}
            className="px-[15px] py-[7px] text-left text-[12px] font-semibold text-accent hover:underline"
          >
            {allFields ? 'Show four fields' : 'Show all fields'}
          </button>
        )}
      </div>
    </CollapsiblePanel>
  );
}

function HostContextPanel({
  host,
  role,
  summary,
  sections,
}: {
  host: string;
  /** Which end of the alert this host is. Absent on a pooled list. */
  role?: string;
  summary: string;
  sections: { label?: string; signals: HostSignal[] }[];
}) {
  const shown = sections.filter((sec) => sec.signals.length > 0);
  return (
    <CollapsiblePanel
      icon={<Activity size={15} />}
      title="Host context"
      right={
        <div className="flex items-center gap-1.5 text-[11px]">
          {role ? <span className="text-faint">{role}</span> : null}
          {host === 'Both ends' ? (
            <span className="font-mono text-mono-amber">{host}</span>
          ) : (
            <span className="font-mono text-mono-amber"><EntityLink value={host} stopPropagation className="font-[inherit] text-[inherit]" /></span>
          )}
        </div>
      }
      summary={summary}
    >
      <div className="flex flex-col gap-2.5 p-[14px]">
        {shown.length === 0 ? (
          <div className="text-[12px] text-faint">No other alerts on this host in the window.</div>
        ) : null}
        {shown.map((sec, si) => (
          <div key={si} className="flex flex-col gap-2.5">
            {sec.label ? <div className="text-[11px] font-semibold text-faint">{sec.label}</div> : null}
            {sec.signals.map((s, i) => (
              <div key={i}>
                <div className="flex items-center gap-2 text-[12px]">
                  <span className="font-mono text-faint">{s.time}</span>
                  <span className="min-w-0 flex-1 break-words text-text-2" title={s.label}>{s.label}</span>
                  <span className="flex-none font-mono text-[10.5px]" style={{ color: SEV_COLOR[s.tone] }}>{s.sev}</span>
                </div>
                <div className="mt-1 h-1 overflow-hidden rounded-full bg-surface-3">
                  <div className="h-full origin-left animate-barGrow rounded-full" style={{ width: `${s.w}%`, background: SEV_COLOR[s.tone] }} />
                </div>
              </div>
            ))}
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
      title="The model wrote this verdict from the context that soc-ai gathered. It called no tool. Turn off 'Fast verdict' in Settings to investigate every alert with the tools."
      className="flex cursor-help items-center gap-1.5 rounded-badge border border-border-input px-2 py-[3px] text-[11.5px] font-semibold text-faint"
      style={{ background: 'rgba(148,163,184,.07)' }}
    >
      <Wrench size={11} />
      heuristic · no tools
    </span>
  );
}

function OracleBadge({ oracle }: { oracle: OracleAdjudication }) {
  // A withheld disagreement changed nothing: the local verdict stands.
  const overrode = oracle.changed && !oracle.withheld;
  const hasVerdict = !!oracle.oracleVerdict;
  const label = oracle.withheld
    ? `Oracle opinion: ${oracle.oracleVerdict}. The local verdict stands`
    : overrode
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
  // A withheld disagreement changed nothing: the local verdict stands.
  const overrode = oracle.changed && !oracle.withheld;
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
          <span className="text-faint">Escalated because: </span>
          {ORACLE_REASON[oracle.reason] ?? oracle.reason}
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
                {oracle.withheld ? 'opinion only' : overrode ? 'overrode' : 'upheld'}
              </span>
            </span>
          )}
          {!oracle.oracleVerdict && (
            <span className="text-[12px] text-faint italic">Oracle did not return a verdict</span>
          )}
        </div>
      )}

      {/* a disagreement with no evidence that resolves: an opinion, never an override */}
      {oracle.withheld && (
        <div data-testid="oracle-opinion-note" className="mb-1 text-[12px] text-dim">
          The Oracle cited no evidence that resolves. Its answer is an opinion. The local
          verdict stands, and soc-ai does not acknowledge the alert on it.
        </div>
      )}

      {/* redaction notice */}
      {oracle.redacted && (
        <div className="mt-1 text-[11.5px] text-faint">
          🔒 {oracle.redactionNote || 'soc-ai redacted the credentials before cloud egress.'}
        </div>
      )}
    </div>
  );
}

function InvMetaPanel({ meta, id, toolCalls }: { meta: InvMeta; id: string; toolCalls: number }) {
  const rows: [string, string][] = [
    ['id', id],
    ['model', meta.model],
    ['oracle', meta.oracle ?? '—'],
    ['tool calls', `${toolCalls}`],
    ['pivots', `${meta.pivots}`],
    ['run by', meta.ranBy],
    ['ran at', absTime(meta.ranAt, { zone: true })],
  ];
  return (
    <CollapsiblePanel
      icon={<Cpu size={15} />}
      title="Investigation"
      summary={`${meta.model} · ${plural(toolCalls, 'tool call')}`}
    >
      <div className="flex flex-col">
        {rows.map(([k, val]) => (
          <div key={k} className="flex gap-3 border-b border-border-faint px-[15px] py-[7px] text-[12px] last:border-0">
            {k === 'oracle' ? (
              <div
                data-testid="oracle-term"
                title={ORACLE_TIP}
                className="w-[72px] flex-none cursor-help text-faint underline decoration-dotted"
              >
                {k}
              </div>
            ) : (
              <div className="w-[72px] flex-none text-faint">{k}</div>
            )}
            <div
              data-testid={k === 'oracle' ? 'oracle-line' : undefined}
              className={`min-w-0 flex-1 break-words text-text-2 ${k === 'oracle' ? '' : 'font-mono'}`}
            >
              {val}
            </div>
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
            <div className="mt-1 break-words text-[12px] leading-[1.5] text-dim">{summary}</div>
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

function Summary({
  segments,
  onCite,
  ids = [],
  entities,
}: {
  segments: SummarySegment[];
  onCite: (n: number) => void;
  ids?: string[];
  entities?: EntityRef[];
}) {
  return (
    <>
      {segments.map((seg, i) => {
        if (seg.t === 'text')
          return (
            <span key={i}>
              <CitedText text={seg.v} ids={ids} entities={entities} />
            </span>
          );
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

/** A tool call that failed: "Event search: failed: unknown or forbidden
 *  field ...". Returns the tool noun, or null for any other step. */
export function failedToolStep(step: Pick<TimelineStep, 'group' | 'title'>): { tool: string } | null {
  if (step.group !== 'Tool calls') return null;
  const m = step.title.match(/^(.+?): failed(?::|$)/);
  return m ? { tool: m[1] } : null;
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
  const failedCheck = failedToolStep(step);
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
          <span data-testid="timeline-group" className="text-[10px] font-semibold uppercase tracking-[.05em]" style={{ color }}>
            {TIMELINE_GROUP_LABEL[step.group] ?? step.group}
          </span>
          <div className="flex-1" />
          <span className="font-mono text-[11px] text-faint">{step.time}</span>
        </div>
        {failedCheck ? (
          // A failed query folds (dogfood 2026-10-06, W4). The raw tool
          // error read as a fault of the run. soc·ai went on without it.
          <>
            <div data-testid="failed-check" className="mt-[3px] text-[13.5px] font-medium text-text-2">
              A follow-up check could not run
            </div>
            <div className="mt-0.5 text-[12px] text-dim">
              {failedCheck.tool}. soc-ai went on with the other checks.{' '}
              <span className="text-faint underline decoration-dotted">
                {open ? 'Hide the error' : 'Show the error'}
              </span>
            </div>
          </>
        ) : (
          <div className="mt-[3px] text-[13.5px] font-medium" style={{ textWrap: 'pretty' }}>
            {step.title}
          </div>
        )}
        {open && (
          <pre className="mt-[9px] animate-fadeUp-slow whitespace-pre-wrap rounded-control border border-border bg-bg px-3 py-2.5 font-mono text-[11.5px] leading-[1.6] text-dim">
            {failedCheck ? `${step.title}\n${step.detail}` : step.detail}
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
