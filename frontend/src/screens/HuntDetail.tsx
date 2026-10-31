import {
  AlertTriangle,
  ChevronDown,
  ChevronLeft,
  Crosshair,
  FileCode2,
  GitBranch,
  Loader2,
  MoreHorizontal,
  RotateCw,
  ShieldAlert,
  Sparkles,
  Trash2,
  Wrench,
  X,
} from 'lucide-react';
import { type ReactNode, Suspense, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { HuntKindBadge, RecordedRunChip, SyntheticEvalBadge } from '../components/Badges';
import { ConfidenceRing } from '../components/ConfidenceRing';
import { Definition } from '../components/Definition';
import { DocumentChip } from '../components/DocumentDrawer';
import { DraftDetectionPane } from '../components/DraftDetectionPane';
import { EventTimelinePanel, eventTimelineMeta } from '../components/EventTimeline';
import { LeadTimeline } from '../components/LeadTimeline';
import { Markdown } from '../components/Markdown';
import { Panel, PanelHeader } from '../components/Panel';
import {
  ErrorState,
  Freshness,
  LoadingState,
  NotFoundState,
  Spinner,
  StaleNotice,
} from '../components/States';
import { AnalyticPins, entityLine } from '../components/AnalyticPins';
import {
  ApiError,
  type AnalyticDraftResult,
  type AnalyticDraftReview,
  type LeadDetail,
  cancelHuntConsole,
  deleteHunt,
  draftAnalytic,
  draftFindingDetection,
  getAbout,
  getHunt,
  getHunts,
  getLead,
  isNotFound,
  promoteFinding,
  startHuntConsole,
} from '../lib/api';
import { DISMISS_REASONS, DismissLeadForm, openThreatTitles } from '../components/LeadsStrip';
import { FlowStrip } from '../components/FlowStrip';
import { useTabTitle } from '../lib/useTabTitle';
import { type FlowFinding, type FlowHunt, findingInvestigation, huntFlow } from '../lib/flowSteps';
import { useDemo } from '../lib/demo';
import { entityPath } from '../lib/entityPath';
import { HUNT_STATUS } from '../lib/statusMeta';
import {
  type HuntOutcomeKey,
  chipProps,
  confidenceText,
  confidenceWord,
  huntOutcome,
  outcomeLabel,
  outcomeMeta,
  verdictLabel,
  verdictMeta,
} from '../lib/labels';
import { objectiveHeadline } from '../lib/text';
import { HUNT_KIND, SEVERITY, TIMELINE_GROUP_COLOR, tint } from '../lib/tokens';
import {
  ACTION_OPEN_INVESTIGATION,
  CHIP_LEAD,
  CHIP_MITRE,
  CHIP_SEVERITY,
  COUNT_AFFECTED_HOSTS,
  COUNT_FINDINGS,
  COUNT_MITRE,
  COUNT_STEPS,
  DIFF_NEW,
  DIFF_PERSISTING,
  DIFF_RESOLVED,
  DIFF_STRIP,
  DISPOSITION,
  STEP_DETAIL,
  huntStatusTitle,
} from '../lib/tooltips';
import { useAsync } from '../lib/useAsync';
import { lazyWithReload } from '../lib/lazyWithReload';
import { useChatScope } from '../lib/chatScope';
import type {
  FindingInvestigationStatus,
  HuntDetailData,
  HuntDiff,
  HuntFinding,
  HuntStatus,
  Severity,
  TimelineStep,
} from '../lib/types';

// Derived from the single app-wide severity ramp (lib/tokens) — no second palette.
const SEV_COLOR: Record<string, string> = Object.fromEntries(
  (Object.keys(SEVERITY) as Severity[]).map((k) => [k, SEVERITY[k].color]),
);

// HuntVisuals statically imports recharts (~370 KB of the old 417 KB HuntDetail
// route chunk). It renders only when a hunt is complete AND has findings — a
// notification click on a finished-but-empty hunt fetched all of recharts to
// render nothing. Lazy-import it so the recharts chunk loads only when the
// "Visual summary" section actually mounts; the route chunk drops to ~40 KB.
// lazyWithReload (not bare lazy) so a first mount after a deploy self-heals the
// dead-hash chunk 404 with one reload instead of throwing to the error boundary.
const HuntVisuals = lazyWithReload(() =>
  import('../components/HuntVisuals').then((m) => ({ default: m.HuntVisuals })),
);

// Placeholder while the recharts chunk loads — one Panel-shaped shimmer, so the
// section reserves its space instead of jumping when the charts arrive.
function VisualsSkeleton() {
  return (
    <Panel className="animate-pulse">
      <div className="h-[220px] p-4">
        <div className="mb-3 h-3 w-40 rounded bg-surface-3" />
        <div className="h-[168px] rounded bg-surface-2" />
      </div>
    </Panel>
  );
}

function StatusPill({ status }: { status: HuntStatus }) {
  const m = HUNT_STATUS[status] ?? HUNT_STATUS.error;
  return (
    <span
      title={huntStatusTitle(status)}
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
// scannable TITLE (like an investigation's rule name) instead of the raw
// prompt. The full objective is still shown beneath + in the tooltip.
//
// The title is the objective's head line, whole. It was cut at 80 characters
// with an ellipsis, and the owner could not read the hunt's own name on its
// own page. The header has room, so the text wraps. A lead objective is a head
// sentence over a list of observations, and the list opens on a click.
const HUNT_TITLE_STRIP =
  /^(please\s+)?(look\s+for|look\s+into|hunt\s+for|hunt|search\s+for|search|find|check\s+for|check|investigate|show\s+me|scan\s+for|scan)\s+/i;
function huntTitle(objective: string): string {
  const raw = objectiveHeadline(objective);
  if (!raw) return 'Hunt';
  const s = raw.replace(HUNT_TITLE_STRIP, '').replace(/^(for|into|at|the)\s+/i, '').trim() || raw;
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// A long title steps down a size, so a paragraph-length objective reads as
// text and not as a wall of headline type.
const LONG_TITLE_CHARS = 140;

// The actor the catalog sweep loop stamps on every hunt it records
// (`SWEEP_ACTOR` in soc_ai/hunting/sweep.py). A hunt carrying it was produced
// by a declarative spec: one Elasticsearch query, no model call at any point,
// and every word of its findings lifted from the spec's own reviewed YAML.
//
// What it decides: the rendering that is specific to a SPEC-authored hunt.
// The finding detail is split at the seam findings.py composes (a model's
// prose has no such seam, so the split must never run on it), the timeline
// says "no steps by construction" rather than "no steps yet", and the hero
// explains why there is no confidence to score. `kind` cannot carry any of
// that: a catalog hunt is 'triggered', and so is every scheduled hunt the
// model runs. Every other hunt-creating path stamps `identify_caller()`,
// which returns a username, `token:<name>`, or 'anonymous', never this literal.
//
// What it does NOT decide: whether the confidence dial renders. That reads
// `confidence === null` off the field itself; the API preserves the absence
// (spec_report() omits the key, and the detail no longer coerces it to 0.0),
// so a model that genuinely scored zero keeps its 0.00 and a hunt nothing
// scored shows no number at all, whoever started it.
const CATALOG_ACTOR = 'hunt-catalog';

/** The hand that started a hunt, in screen words. The meta strip printed the
 *  raw actor "hunt-catalog". A system actor reads as soc-ai. */
export function starterWords(startedBy: string): string {
  if (startedBy === CATALOG_ACTOR) return 'the catalog sweep';
  if (startedBy.startsWith('system:')) return 'soc-ai';
  return startedBy;
}

// A catalog finding's detail arrives as ONE string: the spec's own prose,
// written and reviewed when the detection was authored, and then this run's
// result. Read as one paragraph the author's measurements ("the range
// currently holds only 14 documents") pass for fresh measurement and go
// quietly false as the grid grows, so the card sets the two apart.
//
// The seam is now DATA. soc_ai/hunting/findings.py appended the second half,
// so it knows where the first one ends, and it sends that half as
// `specRationale` with the document count as `matchedDocs`. The previous
// version matched the sentence a CANDIDATE finding ends with ("Matched N
// documents for …"), which no visibility-gap finding contains, so it never
// fired on one — and on a quiet grid every catalog finding is a gap. That is
// also the case where the spec's prose misleads most: the run saw nothing, so
// every number on screen was measured by the author, once, on a grid that has
// moved since.
//
// The prefix is CHECKED, not trusted: two fields of one stored record can
// disagree, and cutting on a prefix the detail does not start with would drop
// text. A mismatch renders whole, like a model's detail.
//
// The tail match survives for hunts recorded before the fields existed, and
// only for them: those rows still carry the composed string and nothing else.
// It stays greedy, so a description that itself contains "Matched N documents
// for" splits at the LAST occurrence, which is always the composed tail.
const CATALOG_RUN_TAIL = /^([\s\S]*\S)\s+(Matched (\d+) documents? for [\s\S]+)$/;

interface CatalogDetail {
  /** The spec's own prose. Authoring-time, not measured on this run. */
  rationale: string;
  /** What this run produced, and only that. */
  run: string;
  /** Documents this candidate matched, or null when the finding counted none
   *  (a visibility gap) or the row predates the field. */
  matched: number | null;
}

function splitCatalogDetail(f: HuntFinding): CatalogDetail | null {
  const detail = f.detail.trim();
  const rationale = (f.specRationale ?? '').trim();
  if (rationale && detail.startsWith(rationale) && detail !== rationale) {
    return {
      rationale,
      run: detail.slice(rationale.length).trim(),
      matched: typeof f.matchedDocs === 'number' ? f.matchedDocs : null,
    };
  }
  if (rationale) return null; // carried and mismatched: render whole, cut nothing.
  const m = detail.match(CATALOG_RUN_TAIL);
  if (m == null) return null;
  return { rationale: m[1], run: m[2], matched: Number(m[3]) };
}

// A hunt has no true/false-positive verdict. It has one outcome, and the
// backend names it (soc_ai/hunting/outcome.py) so the list, this page and the
// bell print the same word. A hunt that could not run read "No threat
// observed" with a green Complete chip, and a hunt that could not answer read
// the same with a 0.75 confidence ring (dogfood 2026-10-06 S1). The label and
// the colour come from lib/labels.ts, the one map every surface reads.

/** The finding that records a failed query and nothing else. The catalog
 *  composer titles it "<analytic>: could not run". It has no severity to act
 *  on, no evidence to promote and no behaviour to draft from. */
export function isRunFailure(f: Pick<HuntFinding, 'title' | 'category'>): boolean {
  return f.category === 'visibility_gap' && /: could not run$/.test(f.title);
}

/** The outcome the server sent (lib/labels.ts huntOutcome), or the same rule
 *  over the report when an older server sent none. */
export function pageOutcome(
  data: Pick<HuntDetailData, 'status' | 'findings' | 'outcome'>,
): HuntOutcomeKey {
  const sent = huntOutcome(data);
  if (sent) return sent;
  const findings = data.findings;
  if (findings.some((f) => (f.category ?? 'threat') === 'threat')) return 'threat_found';
  if (findings.length > 0 && findings.every(isRunFailure)) return 'could_not_run';
  if (findings.length > 0 && findings.every((f) => f.category === 'visibility_gap')) {
    return 'no_answer';
  }
  return 'no_threat';
}

function huntDisposition(
  outcome: HuntOutcomeKey,
  serverLabel?: string | null,
): { label: string; color: string } {
  const meta = outcomeMeta(outcome);
  // The server's label carries the counts, "2 of 3 findings are threats".
  return { label: serverLabel || outcomeLabel(outcome), color: meta.color };
}

/** The outcomes where the hunt tested its objective. Only these carry a
 *  confidence. A run that did not test it has nothing to be confident in. */
const TESTED: ReadonlySet<HuntOutcomeKey> = new Set<HuntOutcomeKey>([
  'threat_found',
  'no_threat',
  'threats_confirmed',
  'no_threat_confirmed',
]);

// The one sentence a stopped hunt shows. An error carries the stored reason.
// A cancel and a restart are their own reason, so the stored text is not
// needed to say them.
function stopSentence(status: HuntStatus | undefined, narrative?: string | null): string {
  if (status === 'cancelled') return 'A cancel request stopped this hunt before it finished.';
  if (status === 'interrupted') return 'A service restart stopped this hunt before it finished.';
  return narrative?.trim() || 'The hunt ended in an error. The server recorded no reason.';
}

function DispositionBadge({ label, color }: { label: string; color: string }) {
  return (
    <span
      data-testid="hunt-disposition"
      title={DISPOSITION}
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
function DiffCount({
  n,
  label,
  color,
  title,
}: {
  n: number;
  label: string;
  color: string;
  title: string;
}) {
  return (
    <span className="inline-flex items-baseline gap-1" title={title}>
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
            <span className="break-words min-w-0" style={{ textWrap: 'pretty' }} title={e.title}>
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
        <span
          className="text-[11px] font-semibold uppercase tracking-[.05em] text-text-2"
          title={DIFF_STRIP}
        >
          vs last run
        </span>
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <DiffCount n={diff.new.length} label="new" color="#f0883e" title={DIFF_NEW} />
          <span className="text-ghost">·</span>
          <DiffCount
            n={diff.persisting.length}
            label="persisting"
            color="#8b949e"
            title={DIFF_PERSISTING}
          />
          <span className="text-ghost">·</span>
          <DiffCount
            n={diff.resolved.length}
            label="resolved"
            color="#3fb950"
            title={DIFF_RESOLVED}
          />
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

// The draft in words: its title, its logic in one sentence, the YAML on a
// click, the false positives the drafter named, and two checks the server ran
// (dogfood 2026-10-06 W8).
function DraftReviewBlock({ review, yaml }: { review: AnalyticDraftReview; yaml: string }) {
  const [yamlOpen, setYamlOpen] = useState(false);
  return (
    <div data-testid="draft-analytic-review" className="mt-2 flex flex-col gap-1.5">
      <div className="text-text">{review.title}</div>
      <div className="text-dim" data-testid="draft-analytic-logic">
        {review.logic}
      </div>
      {review.repeats_alerts && (
        <div data-testid="draft-analytic-repeats" className="text-warn">
          {review.repeats_alerts}
        </div>
      )}
      {review.source && (
        <div data-testid="draft-analytic-source" className="text-warn">
          {review.source}
        </div>
      )}
      {review.false_positives.length > 0 && (
        <div className="text-dim">
          <span className="font-semibold text-text-2">False positives: </span>
          {review.false_positives.join(' ')}
        </div>
      )}
      <div>
        <button
          type="button"
          onClick={() => setYamlOpen((v) => !v)}
          aria-expanded={yamlOpen}
          className="text-[11.5px] font-semibold text-accent hover:underline"
        >
          {yamlOpen ? 'Hide the YAML' : 'Show the YAML'}
        </button>
        {yamlOpen && (
          <pre
            data-testid="draft-analytic-yaml"
            className="mt-1 max-h-[240px] overflow-auto rounded-control border border-border bg-bg p-2 font-mono text-[11px] leading-[1.5] text-text-2"
          >
            {yaml}
          </pre>
        )}
      </div>
    </div>
  );
}

// ── The investigation of each finding ─────────────────────────────────────
// A hunt investigates its subject findings as part of the hunt (2026-10-07).
// Each finding card states where its investigation is, in one line.

const LEGACY_RUN_STATUS: Record<string, FindingInvestigationStatus> = {
  running: 'running',
  complete: 'complete',
  error: 'failed',
  interrupted: 'failed',
  cancelled: 'cancelled',
};

/** Where the investigation of one finding is. An older server sends only the
 *  `investigation` card, and its run status answers. */
export function findingInvestigationStatus(f: HuntFinding): FindingInvestigationStatus | null {
  if (f.investigationStatus) return f.investigationStatus;
  const status = f.investigation?.status;
  return status ? (LEGACY_RUN_STATUS[status] ?? 'failed') : null;
}

/** "No action waits", "1 action waits", "2 actions wait". */
export function pendingActionsText(n: number): string {
  if (n <= 0) return 'No action waits';
  return n === 1 ? '1 action waits' : `${n} actions wait`;
}

/** The line above the findings while the hunt investigates them. */
export function findingsProgressLine(
  data: Pick<HuntDetailData, 'findingsInvestigated' | 'findingsTotal'>,
): string {
  return outcomeLabel('investigating', {
    investigated: data.findingsInvestigated,
    total: data.findingsTotal,
  });
}

/** "F2", "F2 and F3", "F2, F3 and F5": finding numbers from 0-based ordinals. */
function findingNumbers(ordinals: number[]): string {
  const names = ordinals.map((o) => `F${o + 1}`);
  if (names.length <= 1) return names.join('');
  return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
}

/** The note on a card whose investigation another finding reads too.
 *
 *  The range hunt of lead 18 (2026-10-19) linked one investigation to F1 and
 *  F2, and no card said so: each card read the verdict as its own. Null when
 *  the investigation is the finding's own. */
export function sharedInvestigationText(f: HuntFinding, ordinal: number): string | null {
  const others = (f.sharedWith ?? []).filter((o) => o !== ordinal);
  const subject = f.investigationSubject ?? null;
  if (subject != null && subject !== ordinal) {
    return `Shares the investigation of ${findingNumbers([subject])}.`;
  }
  if (others.length > 0) {
    const verb = others.length === 1 ? 'shares' : 'share';
    return `${findingNumbers(others)} ${verb} this investigation.`;
  }
  if (f.investigationOrigin === 'reused' && subject == null) {
    return 'Shares the investigation of an earlier hunt on the same subject.';
  }
  return null;
}

// The sentence for a finding with no verdict. The manual control on the card
// opens an investigation by hand.
const NO_VERDICT_LINE: Partial<Record<FindingInvestigationStatus, string>> = {
  running: 'The investigation runs.',
  queued: 'The investigation waits for a free slot.',
  failed: 'Investigation failed, re-run.',
  cancelled: 'Investigation cancelled, re-run.',
  over_cap: 'Over the cap, open by hand.',
};

function SharedInvestigationNote({ f, ordinal }: { f: HuntFinding; ordinal: number }) {
  const text = sharedInvestigationText(f, ordinal);
  if (!text) return null;
  return (
    <span
      data-testid="finding-shared-investigation"
      className="font-semibold"
      title="One investigation answers these findings. The findings name the same hosts and cite the same evidence."
    >
      {text}
    </span>
  );
}

function FindingInvestigationLine({
  f,
  huntId,
  ordinal,
}: {
  f: HuntFinding;
  huntId: string;
  ordinal: number;
}) {
  const status = findingInvestigationStatus(f);
  if (!status) return null;
  const invId = f.investigationId ?? f.investigation?.id ?? null;
  const verdict = f.verdict ?? f.investigation?.verdict ?? null;
  const conf = f.confidence ?? f.investigation?.conf ?? null;
  const link = invId ? (
    <Link
      to={`/investigation/${invId}`}
      state={{ from: `/hunts/${huntId}` }}
      data-testid="finding-investigation-link"
      className="font-semibold text-accent hover:underline"
    >
      Open the investigation
    </Link>
  ) : null;
  if (status === 'complete' && verdict) {
    const pending = f.pendingActions ?? 0;
    return (
      <div
        data-testid="finding-investigation"
        data-status={status}
        className="mb-1.5 flex flex-wrap items-center gap-2 font-sans text-[11.5px] text-dim"
      >
        <span
          data-testid="finding-verdict"
          {...chipProps(verdictMeta(verdict), { title: 'The verdict of the investigation.' })}
        >
          {verdictLabel(verdict)}
          {conf != null && <span className="font-mono opacity-80">{confidenceText(conf)}</span>}
        </span>
        {conf != null && (
          <span data-testid="finding-confidence">{`${confidenceWord(conf)} confidence`}</span>
        )}
        <span
          data-testid="finding-pending-actions"
          className={pending > 0 ? 'font-semibold text-warn' : undefined}
        >
          {pendingActionsText(pending)}
        </span>
        <SharedInvestigationNote f={f} ordinal={ordinal} />
        {link}
      </div>
    );
  }
  const line = NO_VERDICT_LINE[status] ?? 'The investigation reached no verdict.';
  const failed = status === 'failed' || status === 'cancelled';
  return (
    <div
      data-testid="finding-investigation"
      data-status={status}
      className="mb-1.5 flex flex-wrap items-center gap-2 font-sans text-[11.5px] text-dim"
    >
      <span className={failed ? 'font-semibold text-warn' : undefined}>{line}</span>
      {status === 'running' && <SharedInvestigationNote f={f} ordinal={ordinal} />}
      {status === 'running' && link}
    </div>
  );
}

// Rich finding card — mirrors the investigation timeline rows: a severity dot,
// the title, prose detail, and mono host/citation chips.
function FindingCard({
  f,
  huntId,
  ordinal,
  catalog,
  sigmaOn,
  sigmaOff,
  onChanged,
}: {
  f: HuntFinding;
  huntId: string;
  ordinal: number;
  /** Read the hunt again. A draft that finds an analytic already on the
   *  finding asks for it, so the card links the analytic the server names. */
  onChanged?: () => void;
  /** This finding came from a declarative spec, not a model (CATALOG_ACTOR).
   *  Its detail is a composed string whose halves have different provenance. */
  catalog: boolean;
  /** `sigma_authoring_enabled` (detection-bridge kill switch) — off by
   *  default, so the Draft-detection badge stays hidden until an operator
   *  opts in (see `HuntDetail`'s `about` fetch). */
  sigmaOn: boolean;
  /** The probe answered and the flag is EXPLICITLY off — distinct from
   *  `!sigmaOn`, which is also true while the probe is unsettled. Drives the
   *  quiet "authoring is off" pointer on a confirmed-TP card; an unsettled
   *  probe shows neither the button nor the pointer. */
  sigmaOff: boolean;
}) {
  // A failed query is the record that the run did not run. It has no severity
  // to act on and no evidence to promote, so the card shows neither: the
  // "medium" chip and the Investigate button on one read as a finding.
  const runFailure = isRunFailure(f);
  const color = runFailure ? '#8b949e' : (SEV_COLOR[f.severity] ?? SEV_COLOR.info);
  // Only a catalog finding's detail is a composed string with a known seam.
  const spec = catalog ? splitCatalogDetail(f) : null;
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [promoteErr, setPromoteErr] = useState<string | null>(null);
  // Draft an analytic (merge 5): the finding becomes one catalog analytic in
  // the local tier, as a candidate. A candidate does not run. The analyst
  // moves it to shadow from the Analytics tab, which is why the result line
  // links there.
  //
  // Two steps. The click drafts and dry-runs the analytic and stores nothing.
  // The confirm names the id and stores it. The one-click write aborted at the
  // client's 20 s budget while the server committed, and the live button then
  // wrote a duplicate.
  const [analyticBusy, setAnalyticBusy] = useState(false);
  const [analyticPreview, setAnalyticPreview] = useState<
    (AnalyticDraftResult & { notes?: string[] }) | null
  >(null);
  const [analyticDraft, setAnalyticDraft] = useState<AnalyticDraftResult | null>(null);
  const [analyticErr, setAnalyticErr] = useState<string | null>(null);
  const savedAnalytic = analyticDraft?.analytic_id ?? f.analyticId ?? null;
  const analyticFailed = (err: unknown) => {
    setAnalyticErr(err instanceof Error ? err.message : 'The analytic was not drafted.');
    // The finding already has an analytic. Read the hunt again, and the card
    // links the one the server names.
    if (err instanceof ApiError && err.reason === 'analytic_exists_for_finding') {
      setAnalyticPreview(null);
      onChanged?.();
    }
  };
  // Only a threat finding can become an analytic. A visibility gap reports
  // telemetry this grid does not have, and an observation is benign context.
  const isThreat = (f.category ?? 'threat') === 'threat';
  // Draft detection (1.3 slice 3): one-way open, like Investigate — once the
  // analyst has drafted a rule for this finding, the pane stays put rather
  // than unmounting on a toggle (which would silently re-draft on reopen).
  const [draftOpen, setDraftOpen] = useState(false);
  // Promotion state (E1.3 slice 1 dogfood fix): a finding already promoted
  // shows Investigating…/Open instead of a re-clickable Investigate that just
  // lands on the same investigation (idempotent server-side, but dishonest —
  // the analyst got no signal that a verdict may already exist). An
  // errored/cancelled/interrupted promotion frees the slot server-side
  // (mirrors inv_svc.blocks_rehunt), so only running/complete change the button.
  // The hunt investigates its findings (owner, 2026-10-07), and the server
  // names the investigation on the finding. An older server sends the
  // `investigation` block, and the helper reads either.
  const inv = findingInvestigation(f as FlowFinding);
  const invRunning = inv != null && inv.status === 'running';
  const invComplete = inv != null && inv.status === 'complete';
  // Confirm-first doctrine: a detection may be drafted ONLY from a finding
  // whose promoted investigation completed AND confirmed true_positive. An
  // unpromoted, running, or non-TP finding gets no draft affordance — the
  // Investigate/Open flow is how the analyst confirms first.
  const confirmedTP = invComplete && inv?.verdict === 'true_positive';

  return (
    <div
      className="relative overflow-hidden rounded-card border bg-surface-2 p-[14px_15px]"
      style={{ borderColor: tint(color, 0.28) }}
    >
      <div className="absolute left-0 top-0 h-full w-[3px]" style={{ background: color }} />
      <div className="mb-1.5 flex items-center gap-2">
        <span className="h-2 w-2 flex-none rounded-full" style={{ background: color }} />
        {/* The finding's number, the one the analytic's version note and the
            promoted investigation print. The note read "finding 1" for the
            second card. */}
        <span
          data-testid="finding-number"
          className="flex-none font-mono text-[11px] font-semibold text-faint"
          title="The number of this finding in the hunt report."
        >
          F{ordinal + 1}
        </span>
        <span className="text-[13.5px] font-semibold text-text" style={{ textWrap: 'pretty' }}>
          {f.title}
        </span>
        {runFailure ? (
          <span
            data-testid="finding-could-not-run"
            className="flex-none rounded-chip border border-border-2 bg-surface-3 px-1.5 py-px text-[10px] font-semibold uppercase tracking-[.04em] text-dim"
            title="A query of this run failed. The result is unknown. Hunt again when the grid is healthy."
          >
            could not run
          </span>
        ) : (
          f.category === 'visibility_gap' && (
            <span
              className="flex-none rounded-chip border border-border-2 bg-surface-3 px-1.5 py-px text-[10px] font-semibold uppercase tracking-[.04em] text-dim"
              title="A visibility gap names a type of telemetry that this grid or this host does not ship. The finding title names the type. The hunt observed no malicious activity here."
            >
              visibility gap
            </span>
          )
        )}
        {f.category === 'observation' && (
          <span
            className="flex-none rounded-chip border border-border-2 bg-surface-3 px-1.5 py-px text-[10px] font-semibold uppercase tracking-[.04em] text-dim"
            title="An observation records benign context. The hunt does not report it as a threat."
          >
            observation
          </span>
        )}
        {runFailure ? null : (invRunning || invComplete) && inv ? (
          // Already promoted. The investigation is a page, so this is a link:
          // it never re-promotes, and the address can be read before the click.
          <Link
            to={`/investigation/${inv.id}`}
            state={{ from: `/hunts/${huntId}` }}
            title={
              invRunning
                ? 'An investigation of this finding runs now. View it to follow the progress.'
                : 'This finding has an investigation. View it to read the verdict.'
            }
            className="ml-auto inline-flex items-center gap-1.5 font-sans text-[11px] font-semibold text-accent hover:underline"
          >
            <Sparkles size={12} />
            {invRunning ? 'Investigation running' : 'View investigation'}
          </Link>
        ) : (
          // Open an investigation: the manual control on a finding with no
          // investigation (owner, 2026-10-07). The hunt investigates what it
          // finds, so this is for a finding it left. It starts a full
          // investigation of the finding's cited evidence (E1.3 authoring
          // bridge). Idempotent server-side: a re-click lands on the same
          // investigation rather than minting a duplicate. Disabled when the
          // finding has no citations left to investigate (the post-hunt
          // citation gate can strip every one), since that request can only
          // ever 422. The route keeps its name, /findings/{n}/investigate.
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              if (busy) return;
              setBusy(true);
              setPromoteErr(null);
              promoteFinding(huntId, ordinal)
                .then((r) => navigate(`/investigation/${r.investigation_id}`, { state: { from: `/hunts/${huntId}` } }))
                .catch((err) => setPromoteErr(err instanceof Error ? err.message : 'The investigation did not start.'))
                .finally(() => setBusy(false));
            }}
            disabled={f.citations.length === 0}
            title={
              f.citations.length === 0
                ? 'This finding has no linked evidence events. An investigation needs at least one event.'
                : ACTION_OPEN_INVESTIGATION
            }
            className="ml-auto inline-flex items-center gap-1.5 rounded-badge border px-[9px] py-[3px] font-sans text-[11px] font-semibold text-accent disabled:opacity-50"
            style={{ borderColor: 'rgba(75,139,245,.3)', background: 'rgba(75,139,245,.07)' }}
          >
            <Sparkles size={12} />
            {busy ? 'Starting the investigation' : 'Open an investigation'}
          </button>
        )}
        {sigmaOn && confirmedTP && !draftOpen && (
          // Draft detection (1.3 slice 3): export-only, flag-gated — see
          // DraftDetectionPane. Confirm-first: offered ONLY once this finding's
          // promoted investigation completed with a true_positive verdict —
          // the same gate the Investigation pane and both backend routes
          // enforce. One-way open (no collapse) so a re-click never re-fires
          // the draft call.
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              setDraftOpen(true);
            }}
            title="Draft a Sigma detection rule from the evidence of this confirmed finding. Review the rule, edit it, and export it."
            className="inline-flex items-center gap-1.5 rounded-badge border px-[9px] py-[3px] font-sans text-[11px] font-semibold text-accent"
            style={{ borderColor: 'rgba(75,139,245,.3)', background: 'rgba(75,139,245,.07)' }}
          >
            <FileCode2 size={12} />
            Draft detection
          </button>
        )}
        {isThreat && savedAnalytic == null && analyticPreview == null && (
          // Draft an analytic (merge 5). The confirm-first rule of Draft
          // detection does not apply: the server drafts from any threat
          // finding, and a candidate never runs until an analyst moves it to
          // shadow. The click stores nothing. The confirm below stores it.
          <button
            type="button"
            data-testid="draft-analytic"
            onClick={(e) => {
              e.stopPropagation();
              if (analyticBusy) return;
              setAnalyticBusy(true);
              setAnalyticErr(null);
              draftAnalytic(huntId, ordinal, { preview: true })
                .then((r) => setAnalyticPreview(r))
                .catch(analyticFailed)
                .finally(() => setAnalyticBusy(false));
            }}
            disabled={analyticBusy}
            title="Draft a catalog analytic from this threat finding. You read the draft and confirm before soc-ai stores it. A draft does not run."
            className="inline-flex items-center gap-1.5 rounded-badge border px-[9px] py-[3px] font-sans text-[11px] font-semibold text-accent disabled:opacity-50"
            style={{ borderColor: 'rgba(75,139,245,.3)', background: 'rgba(75,139,245,.07)' }}
          >
            <Crosshair size={12} />
            {analyticBusy ? 'Drafting' : 'Draft an analytic'}
          </button>
        )}
        {sigmaOff && confirmedTP && (
          // The one card that COULD draft a detection, with the flag off:
          // point at the switch instead of rendering nothing — the flag is
          // hot-editable, so this is a live path, not a dead end.
          <span className="flex-none font-sans text-[10.5px] text-faint">
            Sigma export is off.{' '}
            <Link
              to="/config#triage-automation"
              state={{ highlightKey: 'sigma_authoring_enabled' }}
              className="underline hover:text-dim"
            >
              Turn it on in Settings
            </Link>
          </span>
        )}
        {!runFailure && (
          <span
            data-testid="finding-severity"
            title={CHIP_SEVERITY}
            className="flex-none rounded-chip border px-1.5 py-px text-[10px] font-semibold uppercase tracking-[.04em]"
            style={{ color, borderColor: `${color}55`, background: `${color}14` }}
          >
            {f.severity}
          </span>
        )}
      </div>
      {/* The investigation the hunt opened for this finding: its verdict, the
          confidence word, the actions that wait and the link. */}
      {!runFailure && <FindingInvestigationLine f={f} huntId={huntId} ordinal={ordinal} />}
      {promoteErr && (
        <div className="mb-1.5 font-mono text-[11px] text-danger">{promoteErr}</div>
      )}
      {analyticErr && (
        <div className="mb-1.5 font-mono text-[11px] text-danger">{analyticErr}</div>
      )}
      {analyticPreview && (
        // The confirm. It names the id, states that a candidate does not
        // run, and shows the dry run an analyst reads before the move to
        // shadow. A dry run that could not run says so; it never reads as zero.
        <div
          role="dialog"
          aria-label={`Save the analytic ${analyticPreview.analytic_id}`}
          data-testid="draft-analytic-confirm"
          className="mb-2 rounded-card border border-border-2 bg-surface-3 px-3 py-2.5 font-sans text-[12px] text-text-2"
        >
          <div className="font-semibold">
            Save the analytic <span className="font-mono">{analyticPreview.analytic_id}</span> as a
            draft?
          </div>
          <div className="mt-1 text-dim">
            A draft does not run. Move it to shadow in the Analytics tab to run it.
          </div>
          {/* The draft itself, before the save (W8). The box showed the id
              and one dry-run line, and the definition was readable only
              after the save. */}
          {analyticPreview.review && <DraftReviewBlock review={analyticPreview.review} yaml={analyticPreview.spec_yaml} />}
          {/* The pins sit above the dry run: a dry run of a pinned clause
              counts the one case again, and reads as proof. */}
          <AnalyticPins
            pins={analyticPreview.generalization?.pinned}
            label="This analytic is specific to one case."
            testId="draft-analytic-pins"
          />
          <div className="mt-1 text-dim">
            {analyticPreview.dry_run.ran
              ? `Dry run over ${analyticPreview.dry_run.window_days} days: ${analyticPreview.dry_run.hit_count} matches. ${entityLine(analyticPreview.dry_run)}`.trim()
              : 'The dry run did not run. The result is unknown.'}
          </div>
          {!analyticPreview.dry_run.ran && analyticPreview.dry_run.error && (
            <div className="mt-1 font-mono text-[11px] text-faint">
              {analyticPreview.dry_run.error}
            </div>
          )}
          {(analyticPreview.notes ?? []).map((n) => (
            <div key={n} className="mt-1 text-warn">
              {n}
            </div>
          ))}
          <div className="mt-2 flex items-center gap-2">
            <button
              type="button"
              data-testid="draft-analytic-save"
              disabled={analyticBusy}
              onClick={() => {
                if (analyticBusy) return;
                setAnalyticBusy(true);
                setAnalyticErr(null);
                draftAnalytic(huntId, ordinal, {
                  specYaml: analyticPreview.spec_yaml,
                  ...(analyticPreview.generalization?.retried ? { retried: true } : {}),
                })
                  .then((r) => {
                    setAnalyticDraft({ ...r, dry_run: analyticPreview.dry_run });
                    setAnalyticPreview(null);
                  })
                  .catch(analyticFailed)
                  .finally(() => setAnalyticBusy(false));
              }}
              className="rounded-control border border-accent bg-[rgba(75,139,245,.14)] px-[10px] py-1 text-[11.5px] font-semibold text-[#cfe0ff] disabled:opacity-60"
            >
              {analyticBusy
                ? 'Saving'
                : analyticPreview.generalization?.pinned.length
                  ? 'Save anyway'
                  : 'Save draft'}
            </button>
            <button
              type="button"
              disabled={analyticBusy}
              onClick={() => setAnalyticPreview(null)}
              className="rounded-control border border-border-strong bg-surface-2 px-[10px] py-1 text-[11.5px] font-semibold text-dim disabled:opacity-60"
            >
              Discard
            </button>
          </div>
        </div>
      )}
      {savedAnalytic && (
        // One line, and the link to the candidate itself.
        <div data-testid="draft-analytic-saved" className="mb-1.5 font-sans text-[11.5px] text-dim">
          {analyticDraft ? 'Draft ' : 'Analytic '}
          <Link
            to={`/hunts?tab=analytics&open=${encodeURIComponent(savedAnalytic)}`}
            className="font-mono underline hover:text-text-2"
          >
            {savedAnalytic}
          </Link>
          {analyticDraft
            ? analyticDraft.dry_run.ran
              ? ` saved. Dry run over ${analyticDraft.dry_run.window_days} days: ${analyticDraft.dry_run.hit_count} matches.`
              : ' saved. The dry run did not run. The result is unknown.'
            : ' was drafted from this finding.'}
        </div>
      )}
      {spec ? (
        <>
          {/* What this run actually matched. */}
          <div className="text-[12.5px] leading-[1.6] text-text-2" style={{ textWrap: 'pretty' }}>
            {spec.run}
          </div>
          {/* Why the analytic exists, in the author's words. Set apart and
              dated to its authoring, so its measurements are never read as this
              run's. The noun is the taxonomy's: "spec" is the older word. */}
          <div className="mt-2 rounded-card border border-border-2 bg-surface-3 px-3 py-2">
            <div className="text-[10px] font-semibold uppercase tracking-[.05em] text-faint">
              Why this analytic exists · the author wrote this text before this run
            </div>
            <div
              className="mt-1 text-[11.5px] leading-[1.55] text-dim"
              style={{ textWrap: 'pretty' }}
            >
              {spec.rationale}
            </div>
          </div>
        </>
      ) : (
        <div className="text-[12.5px] leading-[1.6] text-text-2" style={{ textWrap: 'pretty' }}>
          {f.detail}
        </div>
      )}
      {f.validatorNote && (
        <div
          className="mt-2 rounded-card border px-3 py-2 text-[11.5px] leading-[1.5] text-dim"
          style={{ borderColor: 'rgba(107,135,168,.3)', background: 'rgba(107,135,168,.05)' }}
        >
          {f.validatorNote}
        </div>
      )}
      {(f.hosts.length > 0 || f.citations.length > 0) && (
        <div
          data-tour="hunt-evidence"
          className="mt-2 flex flex-wrap gap-1.5 font-mono text-[10.5px]"
        >
          {f.hosts.map((h) => (
            // Host chip → the page that holds what this grid knows about the
            // entity. `entityPath` picks it: an address has a host page, a name
            // has the entity page. The chip linked every host to /entity/, so
            // one address had two pages and neither knew about the other.
            <Link
              key={h}
              to={entityPath('host', h)}
              title={`Pivot to ${h}`}
              className="rounded-chip bg-surface-3 px-1.5 py-px text-mono-amber hover:brightness-125"
            >
              {h}
            </Link>
          ))}
          {/* Document ids. They were dashed muted chips that did nothing,
              because the app had no document viewer to open an Elasticsearch
              _id in. A citation is the proof the finding is real, so each one
              opens its document in the drawer. */}
          {f.citations.map((c) => {
            // A model can cite a tool call, "t_origin_chain(10.99.0.40)". It
            // is no document, so it reads in words and opens nothing (K4).
            const words = citationWords(c);
            return words ? (
              <span
                key={c}
                data-testid="citation-words"
                title={`The finding cites a tool result: ${c}`}
                className="rounded-chip border border-border-2 bg-surface-3 px-1.5 py-px font-sans text-[11px] text-dim"
              >
                {words}
              </span>
            ) : (
              <DocumentChip key={c} id={c} />
            );
          })}
          {/* Three ids beside a narrative saying four documents matched, with
              nothing accounting for the fourth. execute.py caps top_hits at
              MAX_SAMPLE_IDS = 3 per bucket, so a candidate over three
              documents always cites a sample. Say which. */}
          {spec?.matched != null && spec.matched > f.citations.length && (
            <span
              className="px-0.5 py-px font-sans text-[11px] text-faint"
              title="A spec cites 3 sample documents for each match at most. These ids are a sample of the matching documents."
            >
              {`${f.citations.length} of ${spec.matched} matching documents`}
            </span>
          )}
        </div>
      )}
      {draftOpen && (
        <div className="mt-2.5">
          <DraftDetectionPane autoRun onDraft={() => draftFindingDetection(huntId, ordinal)} />
        </div>
      )}
    </div>
  );
}

// The nouns of the tools a model cites by name. A tool this map does not hold
// reads as its own words.
const CITED_TOOL: Record<string, string> = {
  origin_chain: 'Origin chain',
  decode_payload: 'Decoded payload',
  host_dossier: 'Host dossier',
  host_summary: 'Host summary',
  query_events_oql: 'Event search',
  query_zeek_logs: 'Zeek logs',
  get_event_raw: 'Document',
  get_alert_context: 'Alert context',
  get_rule_content: 'Rule text',
  prevalence: 'Prevalence',
  rule_prevalence: 'Rule prevalence',
  first_seen: 'First sighting',
  beacon_profile: 'Beacon profile',
  dns_entropy_scan: 'DNS entropy scan',
  run_analytic: 'Analytic run',
  enrich_ip: 'Reputation',
  enrich_domain: 'Domain reputation',
  enrich_hash: 'File-hash reputation',
};
const TOOL_CITATION = /^t_([a-z0-9_]+)\s*\((.*)\)\s*$/i;

/** A tool citation in words: "t_origin_chain(10.99.0.40)" reads "Origin chain
 *  of 10.99.0.40". null for a document id, which opens in the drawer. */
export function citationWords(citation: string): string | null {
  const m = citation.trim().match(TOOL_CITATION);
  if (!m) return null;
  const name = m[1].toLowerCase();
  const noun =
    CITED_TOOL[name] ?? name.replace(/_/g, ' ').replace(/^./, (ch) => ch.toUpperCase());
  const args = m[2]
    .split(',')
    .map((a) => a.replace(/^\s*[a-z_]+\s*=\s*/i, '').replace(/^["']|["']$/g, '').trim())
    .filter(Boolean);
  return args.length ? `${noun} of ${args.join(', ')}` : noun;
}

/** The help line over the finding cards. Each sentence names a control the
 *  page shows: the detection sentence only while detection authoring is on. */
export function findingsHelp(detectionAuthoring: boolean): string {
  return [
    'Open an investigation on a finding that has none.',
    detectionAuthoring ? 'Draft a detection from a confirmed true positive.' : null,
    'Draft an analytic from any threat finding.',
  ]
    .filter(Boolean)
    .join(' ');
}

/** "Step 8 · hunts on this grid take 5 to 8 minutes · now: the model reads
 *  the results". A part the server did not send is left out. */
export function runningLine(
  data: Pick<HuntDetailData, 'timeline' | 'currentStep' | 'typicalRun'>,
): string {
  const steps = data.timeline.filter((s) => s.group === 'Tool calls').length;
  const parts = [`Step ${Math.max(1, steps)}`];
  const t = data.typicalRun;
  if (t) {
    parts.push(
      t.lowMin === t.highMin
        ? `hunts on this grid take about ${t.lowMin} minute${t.lowMin === 1 ? '' : 's'}`
        : `hunts on this grid take ${t.lowMin} to ${t.highMin} minutes`,
    );
  }
  if (data.currentStep) parts.push(`now: ${data.currentStep}`);
  return parts.join(' · ');
}

// The decision a lead hunt exists for. The hunt page offered Re-hunt and
// Delete, and the analyst went back to the lead to dismiss it (dogfood
// 2026-10-06 W4). The bar calls the lead route the lead page calls. It shows
// while the lead is open and the hunt has ended: a running hunt has nothing
// for the analyst to decide yet.
//
// The bar offers no "Open an investigation" (owner, 2026-10-07). The hunt
// investigates its findings, and the manual control sits on a finding with no
// investigation.
export function LeadDecisionBar({
  lead,
  onChanged,
  threatTitles = [],
}: {
  lead: Pick<LeadDetail, 'id' | 'status' | 'dismiss_reasons'>;
  onChanged: () => void;
  /** The open threat findings of this hunt. The Dismiss form names them. */
  threatTitles?: string[];
}) {
  const [dismissing, setDismissing] = useState(false);
  if (lead.status !== 'open' && lead.status !== 'hunting') return null;
  const btn =
    'flex items-center gap-1.5 rounded-control border px-[11px] py-1.5 text-[12px] font-semibold disabled:opacity-60';
  return (
    <div
      data-testid="hunt-lead-decision"
      data-tour="hunt-lead-decision"
      role="region"
      aria-label={`Lead ${lead.id} decision`}
      className="mt-[18px] flex flex-col gap-2 rounded-panel-lg border px-[18px] py-3"
      style={{ borderColor: 'rgba(75,139,245,.35)', background: 'rgba(75,139,245,.06)' }}
    >
      <div className="flex flex-wrap items-center gap-2.5">
        <span className="text-[13px] font-semibold text-text">Lead {lead.id} waits on you.</span>
        <span className="text-[12px] text-dim">
          Read each finding and the verdict of its investigation. Dismiss the lead if it is noise.
        </span>
        <div className="flex-1" />
        <button
          type="button"
          data-testid="hunt-lead-dismiss"
          onClick={() => setDismissing((v) => !v)}
          aria-expanded={dismissing}
          className={`${btn} border-border-strong bg-surface-3 text-dim hover:text-text`}
        >
          Dismiss lead
        </button>
      </div>
      {dismissing && (
        <DismissLeadForm
          leadId={lead.id}
          reasons={lead.dismiss_reasons?.length ? lead.dismiss_reasons : DISMISS_REASONS}
          // The page is the hunt, so the form links no hunt.
          threat={threatTitles.length ? { huntId: null, titles: threatTitles } : null}
          onCancel={() => setDismissing(false)}
          onDone={() => {
            setDismissing(false);
            onChanged();
          }}
        />
      )}
    </div>
  );
}

function ActionRow({ title, rationale }: { title: string; rationale: string }) {
  return (
    <div className="border-l-2 border-border-2 pl-3">
      <div className="text-[12.5px] font-semibold text-text">{title}</div>
      <div className="mt-0.5 text-[11.5px] leading-[1.5] text-dim" style={{ textWrap: 'pretty' }}>
        {rationale}
      </div>
    </div>
  );
}

// The steps the console cannot take: a wider window, a replayed corpus, a
// sensor to turn on. The page listed them as recommended actions (C5).
function OperatorSteps({ steps }: { steps: { title: string; rationale: string }[] }) {
  const [open, setOpen] = useState(false);
  const n = steps.length;
  return (
    <div data-testid="hunt-operator-steps">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="text-[11.5px] font-semibold text-accent hover:underline"
      >
        {n === 1 ? '1 step needs the operator' : `${n} steps need the operator`}
      </button>
      {open && (
        <div className="mt-2 flex flex-col gap-3">
          <div className="text-[11.5px] text-dim">
            The console cannot take these steps. They need the grid, the sensors or the data
            pipeline.
          </div>
          {steps.map((a, i) => (
            <ActionRow key={i} title={a.title} rationale={a.rationale} />
          ))}
        </div>
      )}
    </div>
  );
}

// The actions an analyst seldom takes, behind one control. Delete sat beside
// Re-hunt at the same weight on every hunt page (dogfood 2026-10-06 W4).
function OverflowMenu({ onDelete }: { onDelete: () => void }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative">
      <button
        type="button"
        data-testid="hunt-more"
        aria-label="More actions"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className="flex items-center rounded-control border border-border-strong bg-surface-3 px-[9px] py-1.5 text-dim hover:text-text"
      >
        <MoreHorizontal size={14} />
      </button>
      {open && (
        <div
          role="menu"
          className="absolute right-0 top-full z-10 mt-1 min-w-[150px] rounded-control border border-border-strong bg-surface-2 py-1 shadow-lg"
        >
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              setOpen(false);
              onDelete();
            }}
            className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-[12px] text-dim hover:bg-surface-hover hover:text-danger"
          >
            <Trash2 size={13} />
            Delete hunt
          </button>
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
      aria-expanded={step.detail ? open : undefined}
      title={step.detail ? STEP_DETAIL : undefined}
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
  tour,
  children,
}: {
  title: string;
  meta?: ReactNode;
  defaultOpen?: boolean;
  /** The `data-tour` anchor of the section, for the page tour. */
  tour?: string;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div data-tour={tour}>
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
  const [objectiveOpen, setObjectiveOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [rehunting, setRehunting] = useState(false);
  const [rehuntError, setRehuntError] = useState<string | null>(null);

  // Draft-detection's kill switch — same one-mount-GET pattern the
  // Investigation screen reads it with (Investigation.tsx `about`). Defaults
  // off: an unsettled or failed probe fails CLOSED (hides every finding's
  // Draft-detection badge), not open.
  const about = useAsync(getAbout, []);
  const sigmaOn = about.data?.sigma_authoring_enabled === true;
  // Explicitly off (probe answered, flag false) — NOT the same as `!sigmaOn`,
  // which is also true mid-probe. Only the settled "off" answer earns the
  // quiet enable-it pointer on a confirmed-TP finding card.
  const sigmaOff = about.data?.sigma_authoring_enabled === false;

  // useAsync captures pauseWhen at setup and can't see `data` there, so track
  // the current status in a ref and let pauseWhen consult it: stop polling once
  // the hunt reaches a terminal state.
  const statusRef = useRef<HuntStatus | undefined>(undefined);
  // A 404 is an answer. The page for a bogus id polled it every 3 s for as
  // long as the tab stayed open.
  const notFoundRef = useRef(false);
  const { data, loading, error, lastUpdated, failCount } = useAsync<HuntDetailData>(() => getHunt(id), [id, reloadKey], {
    refetchInterval: 3000,
    pauseWhen: () => {
      if (notFoundRef.current) return true;
      // Pause once the hunt reaches ANY terminal state. Only 'running' is live;
      // enumerating the terminal set missed 'interrupted', which then polled
      // every 3s forever. Gate on a known status that is not 'running' so a new
      // terminal status can never reintroduce the leak.
      // An investigating hunt is live too: the investigations of its findings
      // run, and the findings section counts them.
      const s = statusRef.current;
      return s !== undefined && s !== 'running' && s !== 'investigating';
    },
  });
  statusRef.current = data?.status;
  notFoundRef.current = !data && isNotFound(error);

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
        setDeleteError(e instanceof Error ? e.message : 'The delete request failed. Try again.');
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
        setRehuntError(e instanceof Error ? e.message : 'The re-hunt did not start. Try again.');
        setRehunting(false);
      });
  };

  // The lead a lead hunt came from. The detail route may name it. A route
  // that does not is answered by the lead-hunt list, which carries the lead id
  // on every row. The page named no lead at all before this, so the hunt and
  // the lead that asked for it were two pages with nothing between them.
  const leadHunt = data?.kind === 'lead' || data?.starter === 'lead';
  const leadRows = useAsync(
    () => (leadHunt && data?.leadId == null ? getHunts({ kind: 'lead' }) : Promise.resolve(null)),
    [leadHunt, data?.leadId, id],
  );
  const leadId =
    data?.leadId ?? leadRows.data?.find((h) => h.id === id)?.leadId ?? null;
  const lead = useAsync(
    () => (leadId != null ? getLead(leadId) : Promise.resolve(null)),
    [leadId],
  );

  const status = data?.status;
  const running = status === 'running';
  const failed = status === 'error' || status === 'cancelled' || status === 'interrupted';
  const complete = status === 'complete';
  // Terminal hunts (complete or errored/cancelled/interrupted) can be deleted
  // and support the read-only follow-up chat.
  const terminal = complete || failed;
  const outcome: HuntOutcomeKey | null = data ? pageOutcome(data) : null;
  const disp = outcome ? huntDisposition(outcome, data?.outcome_label) : null;
  // The hero wears the outcome's colour once the hunt ended. A run that could
  // not reach the grid wore the green of "Complete".
  const statusColor =
    outcome && outcome !== 'running'
      ? outcomeMeta(outcome).color
      : status
        ? (HUNT_STATUS[status]?.color ?? '#8b949e')
        : '#8b949e';
  // The sentence under the outcome: why the hunt could not run, or the gap it
  // could not answer. The server writes it. A stopped hunt from an older
  // server falls back to its stop sentence.
  const outcomeHeadline =
    data?.outcome_headline || (failed ? stopSentence(data?.status, data?.narrative) : '');
  // The server's plain title: a catalog run reads "<analytic>, last 24 h" and
  // a lead hunt "Lead 6 hunt: domainadmin on SR-DC01". The bell and the list
  // read the same words. An older server sends none.
  const title = data ? huntTitle(data.title || data.objective) : '';
  // The findings the charts may count. A failed query is no finding of the
  // hunt: the breakdown counted one as "medium 1" on a run that never ran.
  const charted = data ? data.findings.filter((f) => !isRunFailure(f)) : [];
  // Declarative-spec run: no model touched this hunt at any point.
  const catalog = data?.startedBy === CATALOG_ACTOR;
  // The Ask soc-ai panel's hunt scope. The hunt chat answers from the report,
  // so a running hunt has no scope yet, and the panel offers the general
  // thread until the hunt ends.
  useChatScope(
    data && terminal ? { scope: { kind: 'hunt', id: data.id, name: title || data.objective } } : null,
  );
  // The tab names the hunt. Every tab read "soc·ai: SOC alert triage".
  useTabTitle(data ? `Hunt: ${title || data.objective}` : 'Hunt');

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

      {/* What a hunt is, under the title. An analyst who lands here from a link
          never saw the line the Hunt Console carries. */}
      <Definition of="hunt" className="mb-3.5" />

      {loading && !data ? (
        <LoadingState label="Loading hunt" />
      ) : /* A 404 is an answer, not an incident — and retrying one just fails
             again. Only a real failure keeps the alarm card and its Retry.

             Both branches are gated on `!data`, the same way HostDetail is: an
             error that arrives once the report is already on screen must not
             take it away. A hunt deleted in another tab while the analyst is
             reading it would otherwise replace the report they are mid-sentence
             in with a not-found card. These states answer "the first load
             failed", and only that. */
      error && !data && isNotFound(error) ? (
        <NotFoundState what="hunt" id={id} backTo="/hunts" backLabel="Back to Hunt Console" />
      ) : error && !data ? (
        <ErrorState error={error} onRetry={() => setReloadKey((k) => k + 1)} />
      ) : !data ? (
        <NotFoundState what="hunt" id={id} backTo="/hunts" backLabel="Back to Hunt Console" />
      ) : (
        <div className="mx-auto max-w-workstation">
          {/* Two ways this report can be older than it looks, and until now
              only one of them said so. StaleNotice counted BACKGROUND poll
              failures; a FOREGROUND refresh that failed left `error` set and
              the content untouched — correct, but completely silent, so the
              analyst went on reading stale findings with nothing on screen
              disagreeing. The foreground case is the louder of the two (they
              asked) so it wins the slot — but only the CLICK stopped: a hunt
              that is still running is still being polled every 3s underneath,
              and the next tick heals the page on its own. `retrying` says which
              of those the analyst is looking at, rather than the strip quietly
              flipping back later with no explanation. */}
          {error ? (
            <StaleNotice
              since={lastUpdated}
              onRefresh={() => setReloadKey((k) => k + 1)}
              reason="refresh-failed"
              retrying={running}
              className="mb-3"
            />
          ) : failCount >= 2 ? (
            <StaleNotice
              since={lastUpdated}
              onRefresh={() => setReloadKey((k) => k + 1)}
              className="mb-3"
            />
          ) : null}
          {/* The flow, under the header (owner, 2026-10-07). The hunt is the
              current step. A lead hunt reads Hit, Lead, Hunt, Investigations,
              Verdicts, Actions. A manual hunt starts at its objective. */}
          <FlowStrip steps={huntFlow(data as FlowHunt, leadId)} className="mb-3" />
          {/* ── hero: objective headline, meta strip, confidence ring ────── */}
          <div
            data-tour="hunt-hero"
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
                  {/* A running hunt has no outcome yet. The badge read
                      "RUNNING" beside the status chip "Running" (R3-D15), so
                      the status chip alone states it. An investigating hunt
                      states its counts on the badge, and the chip would
                      repeat the word. */}
                  {disp && outcome !== 'running' && (
                    <DispositionBadge label={disp.label} color={disp.color} />
                  )}
                  {/* A run whose every query failed is not "Complete". The
                      green chip beside it was the false all-clear. */}
                  {!(complete && outcome === 'could_not_run') && outcome !== 'investigating' && (
                    <StatusPill status={data.status} />
                  )}
                  <HuntKindBadge kind={data.kind} />
                  {/* The lead that asked for this hunt. The page named the
                      kind and not the lead, so the hunt and the lead were two
                      pages with nothing between them. */}
                  {leadId != null && (
                    <Link
                      data-testid="hunt-lead-chip"
                      to={`/leads/${leadId}`}
                      title={CHIP_LEAD}
                      className="rounded-chip border border-border-strong bg-surface-3 px-1.5 py-px text-[10.5px] font-semibold text-accent hover:underline"
                    >
                      Lead {leadId}
                    </Link>
                  )}
                  {/* A hunt run against planted synthetic scenarios must never
                      read as a real one — badged right beside the disposition. */}
                  {data.isSynthEval && <SyntheticEvalBadge />}
                  {demo && <RecordedRunChip />}
                  <Freshness at={lastUpdated} className="ml-auto" />
                </div>
                {/* The verdict said INCONCLUSIVE and the reason sat below the
                    objective in a banner that named no cause. The backend
                    stores the sentence that names the failure, so it goes
                    directly under the word it explains. */}
                {outcomeHeadline && (
                  <div
                    data-testid={failed ? 'hunt-failure-reason' : 'hunt-outcome-headline'}
                    className="mb-2.5 text-[13px] leading-[1.55] text-warn"
                    style={{ textWrap: 'pretty' }}
                  >
                    {outcomeHeadline}
                  </div>
                )}
                {/* generated title (from the objective) as the hero headline.
                    It wraps and never cuts. */}
                <div
                  data-testid="hunt-title"
                  className={`break-words font-semibold tracking-[-.015em] ${
                    title.length > LONG_TITLE_CHARS
                      ? 'text-[17px] leading-[1.4]'
                      : 'text-[21px] leading-[1.32]'
                  }`}
                  style={{ textWrap: 'pretty' }}
                  title={data.objective}
                >
                  {title}
                </div>
                {/* The objective a lead hunt carries is a paragraph of
                    generated prose. It pushed the findings below the fold on
                    every lead hunt, so it opens on a click. */}
                <div className="mt-1.5 text-[12.5px] text-dim" style={{ textWrap: 'pretty' }}>
                  <button
                    type="button"
                    data-testid="hunt-objective-toggle"
                    onClick={() => setObjectiveOpen((v) => !v)}
                    className="inline-flex items-center gap-1.5 text-[12px] font-semibold text-dim hover:text-text"
                  >
                    <Crosshair size={13} className="flex-none text-faint" />
                    {objectiveOpen ? 'Hide objective' : 'Show objective'}
                  </button>
                  {objectiveOpen && (
                    <div data-testid="hunt-objective" className="mt-1.5">
                      {data.objective}
                    </div>
                  )}
                </div>
                {/* meta strip */}
                <div className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-[12px] text-dim">
                  <span className="text-faint">started by</span>
                  <span className="text-text-2">{starterWords(data.startedBy)}</span>
                  <span className="text-ghost">·</span>
                  <span className="text-faint">elapsed</span>
                  <span className="text-text-2">{data.elapsedLabel}</span>
                  <span className="text-ghost">·</span>
                  <span className="text-faint">type</span>
                  <span className="text-text-2">{/* the analyst-facing name for the storage kind ('chat' → manual, 'triggered' → catalog), the same one the badge above wears */}{HUNT_KIND[data.kind]?.label ?? data.kind}</span>
                </div>
              </div>
              {/* Confidence ring — only meaningful once the hunt concludes,
                  and only when something actually scored it. A null
                  confidence is a report that carries none (the catalog path:
                  one query from a written spec, nothing to score), and the
                  dial used to render that absence as 0.00 in 18px type beside
                  the disposition, which reads as "the system has zero
                  confidence in this" rather than "nothing scored this". A
                  zero is a measurement and keeps its dial. A hunt that did
                  not test its objective (no answer, could not run) shows no
                  dial: a 0.75 beside "cannot be confirmed or ruled out" read
                  as an answer. */}
              {complete && data.confidence !== null && outcome && TESTED.has(outcome) && (
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
              {/* The explanation is the catalog's, so it keys on the actor:
                  "ran one query from a written spec" is only true of a
                  spec-authored hunt, and a model hunt whose report somehow
                  lost its confidence should show a gap, not this sentence. */}
              {complete && data.confidence === null && catalog && (
                <div className="max-w-[190px] flex-none text-right">
                  <div className="text-[10.5px] font-semibold uppercase tracking-[.05em] text-text-2">
                    no model call
                  </div>
                  <div
                    className="mt-1 text-[11px] leading-[1.45] text-faint"
                    style={{ textWrap: 'pretty' }}
                  >
                    This hunt ran one query from a written analytic. No model scored it.
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
                  data-tour="hunt-rehunt"
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
                  {rehunting ? 'Starting' : 'Re-hunt'}
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
                  {cancelling ? 'Cancelling' : 'Cancel hunt'}
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
                      {deleting ? 'Deleting' : 'Confirm delete'}
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
                  <OverflowMenu onDelete={() => setConfirmDelete(true)} />
                ))}
            </div>
          </div>

          {/* The lead decision, on the page that holds the hunt's answer. */}
          {terminal && lead.data && (
            <LeadDecisionBar
              lead={lead.data}
              onChanged={lead.refetch}
              threatTitles={openThreatTitles(data.findings)}
            />
          )}

          {/* running banner */}
          {/* W10: the step, the time a hunt takes on this grid, and what the
              hunt does now. The banner said one fixed sentence, and the
              newest step sat at the bottom of the timeline. */}
          {running && (
            <div
              data-testid="hunt-running-line"
              className="mt-[18px] flex items-center gap-2 overflow-hidden rounded-panel border border-border bg-surface-1 px-4 py-3 text-[13px] text-dim"
            >
              <Loader2 size={15} className="flex-none animate-spin text-accent" />
              {runningLine(data)}
            </div>
          )}

          {/* What a stopped hunt left behind. The reason sits under the
              status pill, once. This line names only what the page holds. */}
          {failed && (
            <div
              data-testid="hunt-stopped-banner"
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
                {data.findings.length > 0
                  ? 'The findings and the trace below are partial.'
                  : 'The trace below shows how far the hunt got.'}
              </div>
            </div>
          )}

          {/* ── two-column workstation layout ────────────────────────────── */}
          <div className="mt-[18px] grid grid-cols-1 items-start gap-[18px] lg:grid-cols-[minmax(0,1fr)_360px]">
            {/* main column: narrative, findings, timeline */}
            <div className="flex min-w-0 flex-col gap-[18px]">
              {/* What the lead is made of. The hunt page named the lead and
                  showed nothing of it, so an analyst reading the hunt had to
                  leave it to learn what the hunt was about. */}
              {lead.data && (
                <div data-testid="hunt-lead-timeline">
                  <LeadTimeline
                    lead={lead.data}
                    title={`Lead timeline · ${lead.data.observations.length} observation${
                      lead.data.observations.length === 1 ? '' : 's'
                    }`}
                    className=""
                  />
                </div>
              )}
              {/* An errored hunt's narrative IS the failure sentence, and it
                  already sits under the verdict. One sentence twice on one
                  page reads as two facts. */}
              {data.narrative && !failed && (
                <CollapsibleSection title="Narrative">
                  <Panel>
                    <div
                      className="p-4 text-[13.5px] leading-[1.6] text-text-2"
                      style={{ textWrap: 'pretty' }}
                    >
                      {/* The catalog composer writes plain text, and an index
                          pattern such as .ds-logs-*-so-* read as emphasis
                          (R3-D13). A model's narrative is Markdown. */}
                      {catalog ? (
                        <p data-testid="hunt-narrative-plain" className="whitespace-pre-line">
                          {data.narrative}
                        </p>
                      ) : (
                        <Markdown>{data.narrative}</Markdown>
                      )}
                    </div>
                  </Panel>
                </CollapsibleSection>
              )}

              {/* Deterministic charts from the findings — only once the hunt has
                  concluded WITH findings (a running or empty hunt has nothing
                  to plot, and a chart must never render from nothing). */}
              {complete && charted.length > 0 && (
                <CollapsibleSection title="Visual summary">
                  <Suspense fallback={<VisualsSkeleton />}>
                    <HuntVisuals
                      findings={charted}
                      affectedHosts={data.affectedHosts}
                      charts={data.charts}
                    />
                  </Suspense>
                </CollapsibleSection>
              )}

              {/* "vs last run" diff — only when a prior COMPLETE run of this
                  same objective exists (server omits diff otherwise). */}
              {complete && data.diff && <HuntDiffStrip diff={data.diff} />}

              <CollapsibleSection
                title="Findings"
                tour="hunt-findings"
                meta={
                  <span title={COUNT_FINDINGS}>
                    {`${data.findings.length} finding${data.findings.length === 1 ? '' : 's'}`}
                  </span>
                }
              >
                {data.findings.length === 0 ? (
                  <Panel className="px-4 py-3.5 text-[13px] text-dim">
                    {complete
                      ? 'No findings. The hunt found nothing notable for this objective.'
                      : failed
                        ? 'The hunt stopped before it recorded a finding.'
                        : 'No findings yet.'}
                  </Panel>
                ) : (
                  <div className="flex flex-col gap-2.5">
                    {/* The hunt investigates its findings as part of the hunt.
                        While the investigations run, one line counts them. */}
                    {data.status === 'investigating' && (
                      <div
                        data-testid="findings-progress"
                        className="flex items-center gap-2 rounded-panel border border-border bg-surface-1 px-3.5 py-2.5 text-[12.5px] text-dim"
                      >
                        <Loader2 size={14} className="flex-none animate-spin text-accent" />
                        {findingsProgressLine(data)}
                      </div>
                    )}
                    {/* Journey wayfinding: what these cards are FOR. One quiet
                        line, only once the hunt has concluded with findings. */}
                    {/* The detection sentence names a button that shows only
                        while detection authoring is on (C1). */}
                    {complete && (
                      <div
                        data-testid="findings-help"
                        className="text-[12px] leading-[1.5] text-faint"
                        style={{ textWrap: 'pretty' }}
                      >
                        {findingsHelp(sigmaOn)}
                      </div>
                    )}
                    {data.findings.map((f, i) => (
                      <FindingCard
                        key={i}
                        f={f}
                        huntId={data.id}
                        ordinal={i}
                        catalog={catalog}
                        sigmaOn={sigmaOn}
                        sigmaOff={sigmaOff}
                        onChanged={() => setReloadKey((k) => k + 1)}
                      />
                    ))}
                  </div>
                )}
              </CollapsibleSection>

              {/* The documents the findings cite, in event time, in UTC, with
                  the waves (change D). The step timeline below keeps the
                  order of the tool calls. */}
              {data.eventTimeline?.entries.length ? (
                <CollapsibleSection
                  title="Event timeline"
                  tour="hunt-event-timeline"
                  meta={eventTimelineMeta(data.eventTimeline)}
                >
                  <EventTimelinePanel timeline={data.eventTimeline} />
                </CollapsibleSection>
              ) : null}

              {/* A catalog hunt has no steps BY CONSTRUCTION — it is one query
                  from a spec, not an agent loop — so "0 steps" and "No steps
                  yet." promised a second act that never arrives on a hunt
                  already marked Complete. Say what it actually did instead.
                  The step clock is the recorder's UTC wall clock, and the
                  meta names its zone. */}
              <CollapsibleSection
                title="Hunt timeline"
                tour="hunt-timeline"
                meta={
                  <span title={COUNT_STEPS}>
                    {catalog && data.timeline.length === 0
                      ? `single query · ${data.elapsedLabel}`
                      : `${data.timeline.length} step${data.timeline.length === 1 ? '' : 's'} · ${data.elapsedLabel}${
                          data.timeline.length > 0 ? ' · step times in UTC' : ''
                        }`}
                  </span>
                }
                defaultOpen
              >
                <Panel>
                  {data.timeline.length === 0 ? (
                    <div className="px-[15px] py-3.5 text-[12.5px] text-dim">
                      {catalog
                        ? 'This hunt has no steps. A catalog hunt runs its analytic as one grid query.'
                        : 'No steps yet.'}
                    </div>
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
                    // A hunt that found no threat names hosts. It affected
                    // none (C5): "Affected hosts 2" sat over a hunt that
                    // found no traffic.
                    title={outcome === 'threat_found' ? 'Affected hosts' : 'Hosts named'}
                    right={
                      <span className="font-mono text-[11px] text-accent" title={COUNT_AFFECTED_HOSTS}>
                        {data.affectedHosts.length}
                      </span>
                    }
                  />
                  <div className="flex flex-wrap gap-1.5 p-4">
                    {data.affectedHosts.map((h) => (
                      // Host chip → the page that holds what this grid knows about the
            // entity. `entityPath` picks it: an address has a host page, a name
            // has the entity page. The chip linked every host to /entity/, so
            // one address had two pages and neither knew about the other.
                      <Link
                        key={h}
                        to={entityPath('host', h)}
                        title={`Pivot to ${h}`}
                        className="rounded-chip bg-surface-3 px-2 py-0.5 font-mono text-[11.5px] text-mono-amber hover:brightness-125"
                      >
                        {h}
                      </Link>
                    ))}
                  </div>
                </Panel>
              )}

              {/* A technique shows only beside a threat finding (C5). The
                  server sends none without one. An older server sent the
                  analytic's techniques whatever the run found. */}
              {outcome === 'threat_found' && data.mitreTechniques.length > 0 && (
                <Panel>
                  <PanelHeader
                    icon={<ShieldAlert size={15} />}
                    title="MITRE ATT&CK"
                    right={
                      <span className="font-mono text-[11px] text-accent" title={COUNT_MITRE}>
                        {data.mitreTechniques.length}
                      </span>
                    }
                  />
                  <div className="flex flex-wrap gap-1.5 p-4">
                    {data.mitreTechniques.map((m) => (
                      <span
                        key={m}
                        title={CHIP_MITRE}
                        className="rounded-chip border border-accent/40 bg-accent/10 px-2 py-0.5 font-mono text-[11.5px] text-accent"
                      >
                        {m}
                      </span>
                    ))}
                  </div>
                </Panel>
              )}

              {/* The panel lists what the analyst can do from the console
                  (C5). A step that needs the grid or the sensors sits apart,
                  behind a toggle. */}
              {(data.recommendedActions.length > 0 ||
                (data.operatorActions?.length ?? 0) > 0) && (
                <Panel>
                  <PanelHeader title="Recommended actions" />
                  <div className="flex flex-col gap-3 p-4">
                    {data.recommendedActions.map((a, i) => (
                      <ActionRow key={i} title={a.title} rationale={a.rationale} />
                    ))}
                    {(data.operatorActions?.length ?? 0) > 0 && (
                      <OperatorSteps steps={data.operatorActions ?? []} />
                    )}
                  </div>
                </Panel>
              )}
            </div>
          </div>

        </div>
      )}
    </div>
  );
}
