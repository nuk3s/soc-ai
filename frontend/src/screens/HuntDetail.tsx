import {
  AlertTriangle,
  ChevronDown,
  ChevronLeft,
  Crosshair,
  FileCode2,
  GitBranch,
  Loader2,
  RotateCw,
  ShieldAlert,
  Sparkles,
  Trash2,
  Wrench,
  X,
} from 'lucide-react';
import { type ReactNode, Suspense, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { HuntKindBadge, RecordedRunChip, SyntheticEvalBadge, VerdictPill } from '../components/Badges';
import { ChatDockShell, ChatPanelShell } from '../components/ChatDock';
import { ConfidenceRing } from '../components/ConfidenceRing';
import { Definition } from '../components/Definition';
import { DocumentChip } from '../components/DocumentDrawer';
import { DraftDetectionPane } from '../components/DraftDetectionPane';
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
import {
  type AnalyticDraftResult,
  type ChatThread,
  type HuntChatThread,
  cancelHuntConsole,
  deleteHunt,
  draftAnalytic,
  draftFindingDetection,
  getAbout,
  getHunt,
  getHuntChat,
  getHunts,
  getLead,
  isNotFound,
  postHuntChat,
  promoteFinding,
  startHuntConsole,
} from '../lib/api';
import { useDemo } from '../lib/demo';
import { entityPath } from '../lib/entityPath';
import { HUNT_STATUS } from '../lib/statusMeta';
import { HUNT_KIND, SEVERITY, TIMELINE_GROUP_COLOR, VERDICT, tint } from '../lib/tokens';
import {
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
import { useChatThread } from '../lib/useChatThread';
import type {
  HuntDetailData,
  HuntDiff,
  HuntFinding,
  HuntStatus,
  Severity,
  TimelineStep,
  Verdict,
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
  // One phrase for a gap, here and on the hunts list. The two read differently
  // and an analyst had to decide whether they meant the same thing.
  if (gaps.length > 0) return { label: 'No threat observed · visibility gap', color: '#8b949e' };
  return { label: 'No malicious activity found', color: '#3fb950' }; // observations-only or clean
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

// Rich finding card — mirrors the investigation timeline rows: a severity dot,
// the title, prose detail, and mono host/citation chips.
function FindingCard({
  f,
  huntId,
  ordinal,
  catalog,
  sigmaOn,
  sigmaOff,
}: {
  f: HuntFinding;
  huntId: string;
  ordinal: number;
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
  const color = SEV_COLOR[f.severity] ?? SEV_COLOR.info;
  // Only a catalog finding's detail is a composed string with a known seam.
  const spec = catalog ? splitCatalogDetail(f) : null;
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [promoteErr, setPromoteErr] = useState<string | null>(null);
  // Draft an analytic (merge 5): the finding becomes one catalog analytic in
  // the local tier, as a candidate. A candidate does not run. The analyst
  // moves it to shadow from the Analytics tab, which is why the result line
  // links there.
  const [analyticBusy, setAnalyticBusy] = useState(false);
  const [analyticDraft, setAnalyticDraft] = useState<AnalyticDraftResult | null>(null);
  const [analyticErr, setAnalyticErr] = useState<string | null>(null);
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
  const inv = f.investigation ?? null;
  const invRunning = inv != null && inv.status === 'running';
  const invComplete = inv != null && inv.status === 'complete';
  const chipVerdict: Verdict | null =
    invComplete && inv?.verdict && inv.verdict in VERDICT ? (inv.verdict as Verdict) : null;
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
        <span className="text-[13.5px] font-semibold text-text" style={{ textWrap: 'pretty' }}>
          {f.title}
        </span>
        {f.category === 'visibility_gap' && (
          <span
            className="flex-none rounded-chip border border-border-2 bg-surface-3 px-1.5 py-px text-[10px] font-semibold uppercase tracking-[.04em] text-dim"
            title="A visibility gap reports telemetry that this grid does not have. The hunt observed no malicious activity here."
          >
            visibility gap
          </span>
        )}
        {f.category === 'observation' && (
          <span
            className="flex-none rounded-chip border border-border-2 bg-surface-3 px-1.5 py-px text-[10px] font-semibold uppercase tracking-[.04em] text-dim"
            title="An observation records benign context. The hunt does not report it as a threat."
          >
            observation
          </span>
        )}
        {(invRunning || invComplete) && inv ? (
          // Already promoted. The investigation is a page, so this is a link:
          // it never re-promotes, and the address can be read before the click.
          <Link
            to={`/investigation/${inv.id}`}
            state={{ from: `/hunts/${huntId}` }}
            title={
              invRunning
                ? 'An investigation of this finding already runs. Open it to watch the progress.'
                : 'This finding has an investigation. Open it to read the verdict.'
            }
            className="ml-auto inline-flex items-center gap-1.5 font-sans text-[11px] font-semibold text-accent hover:underline"
          >
            <Sparkles size={12} />
            {invRunning ? 'Investigating…' : 'Open'}
          </Link>
        ) : (
          // Investigate: promotes this finding's cited evidence into a full
          // investigation (E1.3 authoring bridge). Idempotent server-side — a
          // re-click on an already-promoted finding lands on the same
          // investigation rather than minting a duplicate. Disabled when the
          // finding has no citations left to investigate (the post-hunt
          // citation gate can strip every one), since that request can only
          // ever 422.
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
                : 'Run a full investigation of the evidence that this finding cites.'
            }
            className="ml-auto inline-flex items-center gap-1.5 rounded-badge border px-[9px] py-[3px] font-sans text-[11px] font-semibold text-accent disabled:opacity-50"
            style={{ borderColor: 'rgba(75,139,245,.3)', background: 'rgba(75,139,245,.07)' }}
          >
            <Sparkles size={12} />
            {busy ? 'Starting…' : 'Investigate'}
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
        {isThreat && analyticDraft == null && (
          // Draft an analytic (merge 5). No confirm-first gate here: the
          // candidate never runs until an analyst moves it to shadow, so the
          // cost of a weak draft is a row the analyst rejects.
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              if (analyticBusy) return;
              setAnalyticBusy(true);
              setAnalyticErr(null);
              draftAnalytic(huntId, ordinal)
                .then((r) => setAnalyticDraft(r))
                .catch((err) =>
                  setAnalyticErr(
                    err instanceof Error ? err.message : 'The analytic was not drafted.',
                  ),
                )
                .finally(() => setAnalyticBusy(false));
            }}
            disabled={analyticBusy}
            title="Draft a catalog analytic from this finding. soc-ai stores it as a candidate. A candidate does not run until you move it to shadow."
            className="inline-flex items-center gap-1.5 rounded-badge border px-[9px] py-[3px] font-sans text-[11px] font-semibold text-accent disabled:opacity-50"
            style={{ borderColor: 'rgba(75,139,245,.3)', background: 'rgba(75,139,245,.07)' }}
          >
            <Crosshair size={12} />
            {analyticBusy ? 'Drafting…' : 'Draft an analytic'}
          </button>
        )}
        {sigmaOff && confirmedTP && (
          // The one card that COULD draft a detection, with the flag off:
          // point at the switch instead of rendering nothing — the flag is
          // hot-editable, so this is a live path, not a dead end.
          <span className="flex-none font-sans text-[10.5px] text-faint">
            Detection authoring is off.{' '}
            <Link
              to="/config#triage-automation"
              state={{ highlightKey: 'sigma_authoring_enabled' }}
              className="underline hover:text-dim"
            >
              Enable it in Config
            </Link>
          </span>
        )}
        {chipVerdict && <VerdictPill verdict={chipVerdict} conf={inv?.conf} />}
        <span
          title={CHIP_SEVERITY}
          className="flex-none rounded-chip border px-1.5 py-px text-[10px] font-semibold uppercase tracking-[.04em]"
          style={{ color, borderColor: `${color}55`, background: `${color}14` }}
        >
          {f.severity}
        </span>
      </div>
      {promoteErr && (
        <div className="mb-1.5 font-mono text-[11px] text-danger">{promoteErr}</div>
      )}
      {analyticErr && (
        <div className="mb-1.5 font-mono text-[11px] text-danger">{analyticErr}</div>
      )}
      {analyticDraft && (
        // One line, and the number an analyst reads before the move to shadow.
        // A dry run that could not run says so; it never reads as zero.
        <div className="mb-1.5 font-sans text-[11.5px] text-dim">
          {`Candidate ${analyticDraft.analytic_id} written. `}
          {analyticDraft.dry_run.ran
            ? `Dry run over ${analyticDraft.dry_run.window_days} days: ${analyticDraft.dry_run.hit_count} matches. `
            : 'The dry run did not run. The result is unknown. '}
          <Link to="/hunts?tab=analytics" className="underline hover:text-text-2">
            Open the Analytics tab
          </Link>
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
          <span className="font-semibold" style={{ color: '#8fa3bf' }}>
            Post-validator
          </span>
          {': '}
          {f.validatorNote}
        </div>
      )}
      {(f.hosts.length > 0 || f.citations.length > 0) && (
        <div className="mt-2 flex flex-wrap gap-1.5 font-mono text-[10.5px]">
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
          {f.citations.map((c) => (
            <DocumentChip key={c} id={c} />
          ))}
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
  const { data, loading, error, lastUpdated, failCount } = useAsync<HuntDetailData>(() => getHunt(id), [id, reloadKey], {
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
  const statusColor = status ? (HUNT_STATUS[status]?.color ?? '#8b949e') : '#8b949e';
  const disp = data ? huntDisposition(data.status, data.findings) : null;
  const title = data ? huntTitle(data.objective) : '';
  // Declarative-spec run: no model touched this hunt at any point.
  const catalog = data?.startedBy === CATALOG_ACTOR;

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
        <LoadingState label="Loading hunt…" />
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
                {failed && (
                  <div
                    data-testid="hunt-failure-reason"
                    className="mb-2.5 text-[13px] leading-[1.55] text-warn"
                    style={{ textWrap: 'pretty' }}
                  >
                    {data.narrative?.trim() || 'The hunt failed. No reason was recorded.'}
                  </div>
                )}
                {/* generated title (from the objective) as the hero headline */}
                <div
                  className="text-[21px] font-semibold leading-[1.32] tracking-[-.015em]"
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
                  <span className="text-text-2">{data.startedBy}</span>
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
                  zero is a measurement and keeps its dial. */}
              {complete && data.confidence !== null && (
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
              The hunt runs. It correlates events, enriches indicators, and maps them to MITRE. This
              view updates live.
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
                  ? 'A cancel request stopped this hunt before it finished. The page still shows the partial findings and the trace below.'
                  : status === 'interrupted'
                    ? 'A service restart interrupted this hunt. The page still shows the partial findings and the trace below.'
                    : 'This hunt ended in an error. The page still shows the partial findings and the trace below.'}
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
                  <Suspense fallback={<VisualsSkeleton />}>
                    <HuntVisuals
                      findings={data.findings}
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
                      : 'No findings yet.'}
                  </Panel>
                ) : (
                  <div className="flex flex-col gap-2.5">
                    {/* Journey wayfinding: what these cards are FOR. One quiet
                        line, only once the hunt has concluded with findings. */}
                    {complete && (
                      <div className="text-[12px] leading-[1.5] text-faint" style={{ textWrap: 'pretty' }}>
                        Promote a finding to investigate it. Draft a detection from a confirmed true
                        positive.
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
                      />
                    ))}
                  </div>
                )}
              </CollapsibleSection>

              {/* A catalog hunt has no steps BY CONSTRUCTION — it is one query
                  from a spec, not an agent loop — so "0 steps" and "No steps
                  yet." promised a second act that never arrives on a hunt
                  already marked Complete. Say what it actually did instead. */}
              <CollapsibleSection
                title="Hunt timeline"
                meta={
                  <span title={COUNT_STEPS}>
                    {catalog && data.timeline.length === 0
                      ? `single query · ${data.elapsedLabel}`
                      : `${data.timeline.length} step${data.timeline.length === 1 ? '' : 's'} · ${data.elapsedLabel}`}
                  </span>
                }
                defaultOpen
              >
                <Panel>
                  {data.timeline.length === 0 ? (
                    <div className="px-[15px] py-3.5 text-[12.5px] text-dim">
                      {catalog
                        ? 'This hunt has no steps. A catalog hunt runs its spec as a single Elasticsearch query.'
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
                    title="Affected hosts"
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

              {data.mitreTechniques.length > 0 && (
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
// Same rendering as the investigation chat (the shared ChatPanelShell) and now
// the same TRANSPORT (useChatThread) as every other chat surface. Strictly
// read-only: it can only answer questions — it can't ack, escalate, or change a
// verdict.

// Normalise the hunt thread's wire shape to the shared hook's ChatThread. The
// only difference is HuntChatMessage.tools is `string | null` where
// ChatMessage.tools is `string | undefined`, so drop the null. progress_tools
// carries straight through — the hunt chat now runs on the shared turn engine,
// so its thread exposes live tool progress like every other chat surface.
function toChatThread(t: HuntChatThread): ChatThread {
  return {
    messages: t.messages.map((m) => ({ role: m.role, text: m.text, tools: m.tools ?? undefined })),
    pending: t.pending,
    progress_tools: t.progress_tools,
  };
}

export function HuntChatPanel({
  huntId,
  fill,
  onClose,
}: {
  huntId: string;
  fill?: boolean;
  onClose?: () => void;
}) {
  // The shared transport slice — mount fetch, a poll that re-arms ONLY while a
  // turn is pending, send, and per-subject drafts. This panel used to keep its
  // own copy, and that copy re-armed the 1.5s poll from applyThread with no
  // alive guard: a response resolving after unmount re-armed a loop nothing
  // would ever clear, polling the endpoint (and setState-ing an unmounted
  // panel) forever. useChatThread's aliveRef closes that (lib/useChatThread.ts).
  // Live tool progress now flows: the hunt chat runs on the shared turn engine,
  // so its thread carries progress_tools (toChatThread passes it through) and the
  // ChatPanelShell footer renders what the agent is DOING during a long turn.
  const chat = useChatThread({
    subject: huntId,
    fetchThread: (id) => getHuntChat(id).then(toChatThread),
    sendMessage: (id, text) => postHuntChat(id, text).then(toChatThread),
  });

  return (
    <ChatPanelShell
      title="Chat about this hunt"
      scopeLabel="read-only"
      placeholder="Ask a follow-up question. Example: which host was worst?"
      listSizeClass={fill ? 'flex-1' : 'max-h-[460px] min-h-[180px]'}
      emptyHint={
        <div className="text-[12.5px] leading-[1.55] text-dim" style={{ textWrap: 'pretty' }}>
          Ask a follow-up question about this hunt. Example: “which host was worst?” or “show me
          the DNS for host X”. The assistant answers from the evidence of this hunt. The assistant
          cannot change the result.
        </div>
      }
      messages={chat.messages}
      pending={chat.pending}
      progressTools={chat.progressTools}
      draft={chat.draft}
      onDraft={chat.setDraft}
      onSend={chat.send}
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
    <ChatDockShell label="Chat about this hunt">
      {(close) => <HuntChatPanel huntId={huntId} fill onClose={close} />}
    </ChatDockShell>
  );
}
