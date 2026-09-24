import {
  AlertTriangle,
  ArrowUpRight,
  EyeOff,
  FileQuestion,
  Ghost,
  Radar,
  Scissors,
  Unlink,
} from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router-dom';

import { getHuntCatalog, type HuntCatalog, type HuntCatalogSpec } from '../lib/api';
import { useDemo } from '../lib/demo';
import { SEVERITY, tint } from '../lib/tokens';
import { absTime, ago } from '../lib/timeRange';
import type { Severity } from '../lib/types';
import { useAsync } from '../lib/useAsync';
import { CHIP_LEVEL, CHIP_LOCAL, CHIP_NOT_SWEPT, CHIP_SHIPPED } from '../lib/tooltips';
import { AnalyticDrawer, StatusDot } from './AnalyticDrawer';
import { StatusTag } from './Badges';
import { Panel, PanelHeader } from './Panel';
import { EmptyState, Freshness, LoadingState, StaleNotice } from './States';

// ---------------------------------------------------------------------------
// The analytic catalog — every declarative analytic and what its sweep trail
// says about it. The catalog runs unattended (a scheduler sweep, no model
// call), so the one screen an operator opens to check on operations has to say
// whether it is actually running. Four facts a row of zeros cannot carry on
// its own: whether the loop is ON at all (the status line), whether it is
// actually LANDING (the flag can be on with the loop dead; see SweepsTag),
// whether an analytic has EVER been swept ("not yet swept" — its eyesight is
// untested, not clean), whether the last sweep was BLIND (the precondition
// matched nothing, so the telemetry the analytic reads is absent, which is the
// opposite of a clean grid), and whether the last sweep failed to ACCOUNT for
// documents it saw — undecided (an exclusion could not be evaluated),
// unattributed (matched and grouped nowhere) or truncated (scopes the grid
// never returned). The first two zero every counter on the row, so the row is
// otherwise identical to a healthy quiet analytic's; the third leaves the
// counters non-zero and too small, which is worse, because an under-report
// reads as a total.
//
// A click on the title opens the same AnalyticDrawer the Analytics tab opens.
//
// Reads GET /hunt-catalog on a 5-minute cadence, the same as the Dashboard's
// setup-health card: a sweep runs hourly by default, so anything faster would
// be polling a value that cannot have moved.
// ---------------------------------------------------------------------------

// The catalog's level vocabulary is the backend's (`informational`, not
// `info`); everything else is the app's one severity ramp. A level this build
// does not know renders as info rather than throwing — the same rule
// HuntKindBadge follows, for the same reason: one unknown row must not blank
// the list.
const LEVEL_SEVERITY: Record<string, Severity> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  informational: 'info',
  info: 'info',
};

// The tier and the status of one analytic. A shipped analytic with no state
// row is shipped and live, which is the default for the whole catalog and the
// same default the backend applies. Rendered without the status, a retired
// analytic and a quiet live one are the same row of zeros.
function TierStatus({ spec }: { spec: HuntCatalogSpec }) {
  return (
    <>
      <span
        className="flex-none rounded-chip border border-border-faint px-1.5 py-px text-[10px] text-faint"
        title={(spec.tier ?? 'shipped') === 'local' ? CHIP_LOCAL : CHIP_SHIPPED}
      >
        {spec.tier ?? 'shipped'}
      </span>
      <span className="flex-none text-[11.5px] text-dim">
        <StatusDot status={spec.status ?? 'live'} />
      </span>
    </>
  );
}

function LevelPill({ level }: { level: string }) {
  const s = SEVERITY[LEVEL_SEVERITY[level] ?? 'info'];
  return (
    <span
      className="flex-none rounded-chip border px-1.5 py-0.5 font-mono text-[9.5px] font-semibold uppercase tracking-[.04em]"
      style={{ color: s.color, background: tint(s.color, 0.1), borderColor: tint(s.color, 0.3) }}
      title={CHIP_LEVEL}
    >
      {s.label}
    </span>
  );
}

// Amber, the SyntheticEvalBadge / DevBadge caution tone: "true story, but not
// the one you think". The blind marker and the overdue status tag both wear
// it: neither is a failure of the thing named, both are a fact the operator
// would otherwise read as clean.
const AMBER = '#f5a623';

const BLIND_TITLE =
  'The precondition matched nothing on the last sweep. The telemetry this analytic reads is absent. This is not a clean result.';

function BlindMarker() {
  return (
    <span
      className="inline-flex flex-none items-center gap-1 whitespace-nowrap rounded-chip border px-1.5 py-px text-[9.5px] font-semibold tracking-[.02em]"
      style={{ color: AMBER, borderColor: tint(AMBER, 0.4), background: tint(AMBER, 0.09) }}
      title={BLIND_TITLE}
    >
      <EyeOff size={9} strokeWidth={2.5} />
      blind
    </span>
  );
}

// Amber again, and for the same reason as blind: not a failure of the spec,
// but a fact the operator would otherwise misread. The hint on the status
// line tells a new install to run `spec-sweep --shadow` first, and a shadow
// sweep counts what it would have surfaced toward fresh and never toward
// fired, so the row then reads "fired 0 · fresh 2", which looks like a spec
// that finds things and refuses to report them. The count is on the chip
// because "2 of 24 sweeps" and "24 of 24" are different situations: the
// first is a hand-run beside a live loop, the second is a shadow week.
const shadowTitle = (n: number) =>
  `${n} of this analytic's sweeps in the last 24 h ${n === 1 ? 'was a shadow run' : 'were shadow runs'}. ` +
  'A shadow sweep counts a hit toward fresh and never toward fired. ' +
  'Fresh without fired here is the shadow reporting.';

function ShadowMarker({ count }: { count: number }) {
  return (
    <span
      className="inline-flex flex-none items-center gap-1 whitespace-nowrap rounded-chip border px-1.5 py-px text-[9.5px] font-semibold tracking-[.02em]"
      style={{ color: AMBER, borderColor: tint(AMBER, 0.4), background: tint(AMBER, 0.09) }}
      title={shadowTitle(count)}
    >
      <Ghost size={9} strokeWidth={2.5} />
      shadow ×{count}
    </span>
  );
}

// Amber, the third of the "true story, but not the one you think" family. A
// spec whose exclusion reads a field the grid does not always carry throws
// away every document missing it: those documents satisfied the detection's
// positive clauses, nothing could say whether the exclusion applies to them,
// and the run holding them is not an all-clear. The count is the NEWEST
// sweep's, so the chip goes away by itself when the condition does.
//
// Nothing else on the row can show this. Such a run matches nothing, buckets
// nothing and fires nothing, so it renders "fired 0 · fresh 0 · handled 0 ·
// last swept 2m ago" — the same row a healthy quiet spec renders, from the
// second sweep onward forever. Measured on a range: 5,240 documents an hour
// behind a row that looked clean.
const undecidedTitle = (n: number) =>
  `The last sweep found ${n} documents that match the positive clauses of this analytic. It could not ` +
  'evaluate them against an exclusion, because they carry no value for a field the exclusion reads. ' +
  'They were neither matched nor ruled out, so this is not a clean result. Open the hunt of this ' +
  'analytic to see which field. Then pin event.dataset, or declare absent: match on that clause.';

function UndecidedMarker({ count }: { count: number }) {
  return (
    <span
      className="inline-flex flex-none items-center gap-1 whitespace-nowrap rounded-chip border px-1.5 py-px text-[9.5px] font-semibold tracking-[.02em]"
      style={{ color: AMBER, borderColor: tint(AMBER, 0.4), background: tint(AMBER, 0.09) }}
      title={undecidedTitle(count)}
    >
      <FileQuestion size={9} strokeWidth={2.5} />
      {count} undecided
    </span>
  );
}

// Amber, the fourth of the family, and the sibling failure to undecided: these
// documents DID match the detection and then produced no scope bucket, so they
// are inside the sweep's matched count and inside no candidate. The gate then
// removes the candidates that did surface, and the row settles to "fired 0 ·
// fresh 0" over documents the spec genuinely hit. The executor counts them
// against the full candidate set before gating for exactly that reason, so the
// number here is a real hit nobody was ever told about, not gate arithmetic.
const unattributedTitle = (n: number) =>
  `The last sweep matched ${n} documents that it could not group into any scope. They belong ` +
  'to no candidate and reached no hunt. The analytic found something, and this row cannot show it. ' +
  "The scope field is usually missing or empty on those documents. Open the hunt of this analytic to " +
  'see which one. Then pin a scope that the dataset carries, or narrow the detection to that dataset.';

function UnattributedMarker({ count }: { count: number }) {
  return (
    <span
      className="inline-flex flex-none items-center gap-1 whitespace-nowrap rounded-chip border px-1.5 py-px text-[9.5px] font-semibold tracking-[.02em]"
      style={{ color: AMBER, borderColor: tint(AMBER, 0.4), background: tint(AMBER, 0.09) }}
      title={unattributedTitle(count)}
    >
      <Unlink size={9} strokeWidth={2.5} />
      {count} unattributed
    </span>
  );
}

// Amber, and the worst-reading of the four, because it is the only one where
// the counters are NOT zero. The grid stopped returning scope buckets at the
// executor's ceiling and reported the remainder as a lump sum
// (`sum_other_doc_count`), so "fired 3 · fresh 12" is a true count of what came
// back and a false count of what is there. Every other marker on this row says
// "this looks clean and is not"; this one says "this number is smaller than the
// truth", which is the harder thing to notice and the easier thing to act on.
const truncatedTitle = (n: number) =>
  `The last sweep hit its bucket ceiling. ${n} documents sit in scopes the grid never ` +
  'returned, so the counts on this row are a floor and not a total. The analytic fires more often ' +
  'than it appears to. Narrow the window or the detection until the grouping fits under the ceiling.';

function TruncatedMarker({ count }: { count: number }) {
  return (
    <span
      className="inline-flex flex-none items-center gap-1 whitespace-nowrap rounded-chip border px-1.5 py-px text-[9.5px] font-semibold tracking-[.02em]"
      style={{ color: AMBER, borderColor: tint(AMBER, 0.4), background: tint(AMBER, 0.09) }}
      title={truncatedTitle(count)}
    >
      <Scissors size={9} strokeWidth={2.5} />
      {count} truncated
    </span>
  );
}

// Red, the PipelineErrorChip tone: the sweep itself broke on this spec. The
// error text lives in the tooltip because it is a Python exception string,
// useful to whoever fixes it and noise to everyone else scanning the list.
function ErrorMarker({ error }: { error: string }) {
  return (
    <span
      className="inline-flex flex-none items-center gap-1 whitespace-nowrap rounded-chip border px-1.5 py-px text-[9.5px] font-semibold tracking-[.02em]"
      style={{ color: '#fca5a5', borderColor: 'rgba(240,68,56,.35)', background: 'rgba(240,68,56,.09)' }}
      title={error}
    >
      <AlertTriangle size={9} strokeWidth={2.5} />
      error
    </span>
  );
}

/** "60m", "61m", "2h", "24h" — minutes as the sweep runs them (the route
 *  reports the clamped window, which is what the trail rows record),
 *  collapsing to hours only past two hours and only on the hour. */
function minutesLabel(m: number): string {
  if (m >= 120 && m % 60 === 0) return `${m / 60}h`;
  return `${m}m`;
}

// "Sweeps on" is the config flag. Whether the loop is ALIVE is a different
// question, and the trail answers it: both backend paths that lose a sweep
// leave the flag true (a spec whose record fails is swallowed per spec, a
// whole sweep that throws is swallowed by the scheduler), so a dead loop and
// a healthy one look identical on the flag alone. The green tag is earned by
// a trail row younger than two intervals. One interval is the normal gap; two
// is a missed beat, the earliest moment the timestamp by itself can prove
// anything. No row at all is the same amber with a different reason.
function sweepOverdue(data: HuntCatalog, now: number): boolean {
  return (
    data.last_sweep_at === null ||
    now - Date.parse(data.last_sweep_at) > 2 * data.sweep_interval_minutes * 60_000
  );
}

const PROFILE_ROW_TITLE =
  'A stored behavioural profile of a host answers this analytic, so the catalog sweep does not run it. The hourly profile sweep runs it. This panel has no trail for that loop, so it reports nothing here. A count of zero would read as \u201cswept, found nothing\u201d.';

const COVERAGE_TITLE =
  'The newest run of the profile sweep, counted in analytic-entity evaluations. measured: soc-ai scored the entity against a real baseline. learning: the entity has under 7 days of history. blind: no baseline, no confident role, or no telemetry on the grid that can answer. n/a: the host\u2019s role is outside the analytic\u2019s scope. fired: evaluations that produced a departure.';

const OVERDUE_TITLE =
  'The newest sweep is more than two intervals old. Sweeps are enabled, and no sweep lands. soc-ai logs a failed sweep and continues, so the flag stays on. Check the application log.';
const NO_SWEEP_TITLE =
  'Sweeps are enabled and the trail has no rows. The first interval has not arrived yet, or no sweep has ever landed.';

function SweepsTag({ data }: { data: HuntCatalog }) {
  if (!data.sweeps_enabled) return <StatusTag color="#8b949e" label="Sweeps off" />;
  if (!sweepOverdue(data, Date.now())) return <StatusTag color="#3fb950" label="Sweeps on" />;
  if (data.last_sweep_at === null) {
    return (
      <span title={NO_SWEEP_TITLE}>
        <StatusTag color={AMBER} label="Sweeps on, no sweep recorded yet" />
      </span>
    );
  }
  return (
    <span title={OVERDUE_TITLE}>
      <StatusTag color={AMBER} label="Sweeps on, overdue" />
    </span>
  );
}

// The tag is the only conditional thing on this line. The interval and the
// look-back are configuration and the last sweep is the trail, and all three
// are true whether or not the scheduler is enabled: `soc-ai spec-sweep`, the
// command the off-branch hint tells the operator to type, writes the same
// trail rows with the same look-back. 1.5.1 built these spans inside the on
// branch only, so an operator sweeping by hand read "Sweeps off" over a row
// that had fired nine minutes earlier and concluded nothing was running.
function SweepsFacts({ data }: { data: HuntCatalog }) {
  const on = data.sweeps_enabled;
  return (
    <>
      {/* Off, the interval is a schedule that is not running; saying
          "every 60m" next to "Sweeps off" would claim a cadence. "once
          enabled" keeps the number (it is what the flag will start) and ties
          it to the hint that follows. */}
      <span className="text-dim">
        · every {minutesLabel(data.sweep_interval_minutes)}
        {!on && ' once enabled'}
      </span>
      <span className="text-dim">· looks back {minutesLabel(data.sweep_window_minutes)}</span>
      {/* On: the stale timestamp stays on the line when overdue (it is how
          the operator sizes the gap), and with no row the tag has already
          said it. Off: "never" renders, because nothing else on the line
          says the command in the hint has never been run, and running it is
          what makes this span move. */}
      {(data.last_sweep_at !== null || !on) && (
        <span className="text-dim" title={data.last_sweep_at ? absTime(data.last_sweep_at) : undefined}>
          · last sweep {ago(data.last_sweep_at)}
        </span>
      )}
    </>
  );
}

function SweepsLine({ data, demo }: { data: HuntCatalog; demo: boolean }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-x-2">
      <SweepsTag data={data} />
      <SweepsFacts data={data} />
      {!data.sweeps_enabled &&
        (demo ? (
          // The demo's config console is read-only, so "enable it in Config"
          // would send the reader to a control that will not take the change
          // (QualityCard's hint swaps the same way).
          <span className="text-dim">· the operator turns sweeps on in a live deployment.</span>
        ) : (
          <span className="text-dim">
            · run <code className="font-mono text-[12px]">soc-ai spec-sweep --shadow</code>, then turn them on in{' '}
            <Link to="/config#triage-automation" className="font-semibold text-accent hover:underline">
              Config → Triage automation
            </Link>
          </span>
        ))}
    </span>
  );
}

// The three counters' definitions. The window they cover is said once, on the
// legend above the list, not here: the 1.5.1 row carried "Last 24h" only in
// this tooltip, so the bare "fired 1 · fresh 2 · handled 1" had no visible
// window at all.
//
// "fresh" is NOT "hits not seen before", which is what this said until a
// live range showed one condition counted fresh twice. A sweep counts a hit
// fresh when no hunt had handled it at the time; a shadow sweep leaves it
// unhandled on purpose (the seed keeps the fire-once budget unspent), so the
// live sweep that follows counts the same condition fresh again. The
// counter is per sweep by design, and the words have to say so.
const COUNTS_TITLE =
  'fired: a live sweep matched and wrote an observation.\n' +
  'fresh: a match no observation had covered.\n' +
  'handled: a match an earlier observation already covered.';

// A `profile` spec is answered from stored behavioural baselines by
// `soc-ai priors`, not by the catalog sweep. Its trail fields describe a loop
// that no longer runs it, so rendering them is worse than rendering nothing:
// nine of them showed "fired 0 · fresh 0 · handled 0" and a 23-hour-old error
// chip under a green "Sweeps on", which reads as nine quiet specs rather than
// nine unswept ones.
//
// This panel cannot see the loop that DOES run them — there is no trail table
// for it yet — so the honest row says exactly that and nothing more. An
// unknown is not a zero.
const UNSCORED_TITLE =
  'The profile sweep could not score this analytic against one entity. Every host it applies to is unclassified, below the role confidence gate, or still learning. A row of zeros here is not evidence of a clean network.';

/** The analytic's title, and the way into its drawer. Operate listed an
 *  analytic and offered no way to read it. The Analytics tab opens the same
 *  drawer from the same click, so the two pages behave alike. */
function RowTitle({ spec, onOpen }: { spec: HuntCatalogSpec; onOpen: (id: string) => void }) {
  return (
    // Two lines below xl rather than a truncate: the tail is what tells
    // "Kerberos AS-REQ … (AS-REP roasting)" from the row above it, and a
    // truncate keeps the head. At xl+ it fits on one.
    <button
      type="button"
      onClick={() => onOpen(spec.id)}
      className="min-w-0 flex-1 text-left text-text-2 line-clamp-2 hover:text-accent hover:underline xl:line-clamp-1"
      title={spec.title}
    >
      {spec.title}
    </button>
  );
}

function ProfileSpecRow({ spec, onOpen }: { spec: HuntCatalogSpec; onOpen: (id: string) => void }) {
  const c = spec.coverage;
  return (
    <li className="flex items-center gap-2.5 px-[15px] py-3 text-[13px]">
      <RowTitle spec={spec} onOpen={onOpen} />
      <LevelPill level={spec.level} />
      <TierStatus spec={spec} />
      {c === null ? (
        <span className="flex-none text-[12px] text-dim" title={PROFILE_ROW_TITLE}>
          not yet run · <code className="font-mono text-[11.5px]">soc-ai priors</code>
        </span>
      ) : (
        <>
          {/* The counts the shadow log prints, on the screen. `measured` is
              the only state a departure can be scored in; when it is zero the
              row says so in amber rather than reading as a quiet spec. */}
          <span className="flex-none font-mono text-[11.5px] text-dim" title={COVERAGE_TITLE}>
            fired {c.fired} · measured {c.measured} · learning {c.learning} · blind {c.blind}
            {c.not_applicable > 0 && ` · n/a ${c.not_applicable}`}
          </span>
          <span className="flex-none text-[12px] text-dim" title={c.last_run_at ? absTime(c.last_run_at) : undefined}>
            last run {ago(c.last_run_at)}
          </span>
          {c.shadow && (
            // Plain "shadow", not "shadow ×N": on a swept row the count is
            // how many of the window's sweeps were shadow runs, and here every
            // run is, so a number would be a count of nothing.
            <span
              className="inline-flex flex-none items-center gap-1 whitespace-nowrap rounded-chip border px-1.5 py-px text-[9.5px] font-semibold tracking-[.02em]"
              style={{ color: AMBER, borderColor: tint(AMBER, 0.35), background: tint(AMBER, 0.09) }}
              title="Recorded in shadow. soc-ai writes departures as observations and leads. Nothing here triggers a hunt until somebody reads the shadow week."
            >
              <Ghost size={9} strokeWidth={2.5} />
              shadow
            </span>
          )}
          {c.measured === 0 && (
            <span
              className="inline-flex flex-none items-center gap-1 whitespace-nowrap rounded-chip border px-1.5 py-px text-[9.5px] font-semibold tracking-[.02em]"
              style={{ color: AMBER, borderColor: tint(AMBER, 0.35), background: tint(AMBER, 0.09) }}
              title={UNSCORED_TITLE}
            >
              <EyeOff size={9} strokeWidth={2.5} />
              unscored
            </span>
          )}
        </>
      )}
    </li>
  );
}

function SpecRow({ spec, onOpen }: { spec: HuntCatalogSpec; onOpen: (id: string) => void }) {
  return (
    <li className="flex items-center gap-2.5 px-[15px] py-3 text-[13px]">
      <RowTitle spec={spec} onOpen={onOpen} />
      <LevelPill level={spec.level} />
      <TierStatus spec={spec} />
      {spec.last_swept_at === null ? (
        // Null trail: the loop has never reached this spec. Zeros here would
        // read as "swept, saw nothing", which is the confusion the trail
        // exists to end.
        <span className="flex-none text-[12px] text-dim" title={CHIP_NOT_SWEPT}>
          not yet swept
        </span>
      ) : (
        <>
          <span className="flex-none font-mono text-[11.5px] text-dim" title={COUNTS_TITLE}>
            fired {spec.fired_24h} · fresh {spec.fresh_24h} · handled {spec.already_handled_24h}
          </span>
          {/* The age, not a boolean: "last fired never" on a critical spec
              means one thing checked two minutes ago and another checked
              last week, and the row is where an operator asks "was anyone
              looking, and when". */}
          <span className="flex-none text-[12px] text-dim" title={absTime(spec.last_swept_at)}>
            last swept {ago(spec.last_swept_at)}
          </span>
          <span
            className="flex-none text-[12px] text-dim"
            title={spec.last_fired_at ? absTime(spec.last_fired_at) : undefined}
          >
            last fired {ago(spec.last_fired_at)}
          </span>
        </>
      )}
      {spec.shadow_24h > 0 && <ShadowMarker count={spec.shadow_24h} />}
      {/* The three unaccounted-for counts, in the order the executor asks
          them: could not decide, could not group, could not fetch. A sweep
          can carry more than one, and each names a different repair, so they
          stack rather than collapsing into one "not clean" chip. */}
      {spec.undecided_docs > 0 && <UndecidedMarker count={spec.undecided_docs} />}
      {spec.unattributed_docs > 0 && <UnattributedMarker count={spec.unattributed_docs} />}
      {spec.truncated_docs > 0 && <TruncatedMarker count={spec.truncated_docs} />}
      {spec.blind && <BlindMarker />}
      {spec.last_error && <ErrorMarker error={spec.last_error} />}
    </li>
  );
}

export function HuntCatalogPanel() {
  const demo = useDemo();
  // The same drawer the Analytics tab opens. Operate listed an analytic and
  // offered no way to read it, so an operator had to change screens to answer
  // "what does this one look for".
  const [openId, setOpenId] = useState<string | null>(null);
  const catalog = useAsync(getHuntCatalog, [], { refetchInterval: 300_000 });
  const data = catalog.data;
  // An unknown evaluator is treated as swept: this panel describes the sweep,
  // and a spec a newer backend adds should appear with its trail rather than
  // being silently reclassified into a group that reports nothing.
  const specs = data?.specs ?? [];
  const profiled = specs.filter((s) => s.evaluator === 'profile');
  const swept = specs.filter((s) => s.evaluator !== 'profile');
  return (
    <Panel className="md:col-span-2">
      <PanelHeader
        icon={<Radar size={16} />}
        title="Analytics"
        right={<Freshness at={catalog.lastUpdated} />}
      />
      {!data ? (
        catalog.error ? (
          // A persistently rejecting read must not sit under "Reading…"
          // forever — that looks like a load in flight when the read has
          // failed outright. Quiet, not danger-red: this is "couldn't tell",
          // not a confirmed bad state. Same rule as the setup-health card.
          <div className="px-[15px] py-3 text-[13px] text-dim">Couldn't read the hunt catalog.</div>
        ) : (
          <LoadingState label="Reading the hunt catalog…" />
        )
      ) : (
        <>
          {/* Two degraded states, one marker (the Dashboard's counts wear the
              same pair). `error` with data on screen is a refresh the operator
              asked for and did not get: the notice's own button is this
              panel's only foreground refetch, so that click lands with the
              fail count still >= 2, and the stale branch first would render
              the same "retrying" line again, which is what made the failure
              silent. `retrying` is true either way: the 5-minute poll goes on
              underneath and its next success clears both. */}
          {catalog.error ? (
            <StaleNotice
              since={catalog.lastUpdated}
              onRefresh={catalog.refetch}
              reason="refresh-failed"
              retrying
              className="mx-[15px] mt-3"
            />
          ) : catalog.failCount >= 2 ? (
            <StaleNotice since={catalog.lastUpdated} onRefresh={catalog.refetch} className="mx-[15px] mt-3" />
          ) : null}
          <div className="border-b border-border px-[15px] py-3 text-[13px] text-text-2">
            <SweepsLine data={data} demo={demo} />
          </div>
          {data.specs.length === 0 ? (
            <EmptyState>No analytics are installed.</EmptyState>
          ) : (
            <>
              {/* One legend for the list: the window is a fact about every
                  row, so it is said once where the eye lands before the
                  rows, and the definitions ride on its tooltip. */}
              <div className="flex justify-end border-b border-border-faint px-[15px] py-1.5 text-[11px] text-dim">
                <span title={COUNTS_TITLE}>fired, fresh and handled cover the last 24 h</span>
              </div>
              <ul className="divide-y divide-border">
                {swept.map((spec) => (
                  <SpecRow key={spec.id} spec={spec} onOpen={setOpenId} />
                ))}
              </ul>
              {profiled.length > 0 && (
                <>
                  {/* Separated rather than interleaved, because the two
                      classes answer different questions and share no
                      vocabulary: every column on a swept row is a fact about
                      the catalog sweep, and none of them apply here. */}
                  <div className="flex items-center justify-between gap-2 border-y border-border-faint bg-surface-2/40 px-[15px] py-1.5 text-[11px] text-dim">
                    <span>Evaluated against behavioural profiles · {profiled.length}</span>
                    <span title={PROFILE_ROW_TITLE}>run by the hourly profile sweep · counts are analytic-host evaluations</span>
                  </div>
                  {/* The two chips on these rows are the vocabulary of the
                      layer, and a reader meets them here first. */}
                  {/* The three words on these rows, each defined once. `n/a`
                      had no definition anywhere in the app. */}
                  <div
                    data-testid="profile-legend"
                    className="border-b border-border-faint px-[15px] py-1.5 text-[11px] leading-[1.6] text-faint"
                  >
                    <div>
                      <span className="font-semibold text-dim">unscored</span>: the host has under
                      7 days of history, or no telemetry the analytic can read.
                    </div>
                    <div>
                      <span className="font-semibold text-dim">n/a</span>: the host&rsquo;s role is
                      outside the analytic&rsquo;s scope.
                    </div>
                    <div>
                      <span className="font-semibold text-dim">shadow</span>: the analytic would
                      have fired. soc-ai wrote it down and raised nothing.
                    </div>
                  </div>
                  <ul className="divide-y divide-border">
                    {profiled.map((spec) => (
                      <ProfileSpecRow key={spec.id} spec={spec} onOpen={setOpenId} />
                    ))}
                  </ul>
                </>
              )}
            </>
          )}
          <div className="border-t border-border px-[15px] py-3">
            {/* The sweep writes an observation. An observation from an
                analytic is an analytic hit, and the hits block at the top of
                the Hunts tab holds every one. The panel linked to the hunt
                rows the sweep wrote beside them, which read as agent runs. */}
            <div className="flex flex-wrap items-center gap-4">
              <Link to="/hunts" className="flex w-fit items-center gap-1 text-[12px] font-semibold text-accent hover:underline">
                Open analytic hits
                <ArrowUpRight size={13} />
              </Link>
              {/* The analyst half of the same list. This panel says whether an
                  analytic runs and what it can see. The Analytics tab says what
                  it found and lets an analyst change what it does. */}
              <Link to="/hunts?tab=analytics" className="flex w-fit items-center gap-1 text-[12px] font-semibold text-accent hover:underline">
                Open in Hunts
                <ArrowUpRight size={13} />
              </Link>
            </div>
          </div>
        </>
      )}
      {/* Mounted only while it is open. `Drawer` registers with the modal
          stack before it renders, so a closed drawer left mounted would put
          Operate inside the shell context. */}
      {openId !== null && (
        <AnalyticDrawer
          analyticId={openId}
          onClose={() => setOpenId(null)}
          onChanged={catalog.refetch}
        />
      )}
    </Panel>
  );
}
