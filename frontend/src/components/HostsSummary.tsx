// The network above the machine list: six cards and a role bar.
//
// The numbers come from GET /hosts/summary. They count MACHINES over the whole
// census, never the page on screen. Each card and each role segment is a link
// that applies the list filter it counts, so a number is always one click from
// the rows behind it. The server holds the rule that makes this true: each
// count equals the `total` of the list call with the matching filter.
//
// A failed read never renders a zero. The cards show the shared dash, because
// "0 machines" is a claim about the network that is false exactly when the
// endpoint is down.

import { AlertTriangle, RadioTower, Scale, Server, Sparkles, WifiOff } from 'lucide-react';
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { cn } from '../lib/cn';
import { provenanceTone, roleRail } from '../lib/hostColors';
import { roleLabel } from '../lib/hostDossier';
import { plural } from '../lib/plural';
import { absTime, ago } from '../lib/timeRange';
import type { MachineSummary } from '../lib/types';
import { Kpi, UNKNOWN, UNKNOWN_TONE } from './Kpi';
import { LoadingInline } from './States';

/** The Config anchor for the dossier's master switch and its schedule. Both
 *  are off by default, so every dead end on this screen points here. */
export const DOSSIER_CONFIG_HREF = '/config#host-dossier';

/** The bucket keys the summary's `roles` carries beside the role slugs. Each
 *  is also a value of the list's `role` filter. */
export const ROLE_BUCKETS = ['low_confidence', 'stale', 'unknown'] as const;

/** The words for the three buckets. None of them is a role: the bar read
 *  "stale 6" as if stale were a role (dogfood 2026-10-06). The bar groups
 *  them under "No confirmed role", and the Role menu reads the same words. */
export const ROLE_BUCKET_LABELS: Record<string, string> = {
  low_confidence: 'weak guess',
  stale: 'old guess',
  unknown: 'no role',
};

// ---- the role bar -----------------------------------------------------------

export interface RoleSlice {
  /** The `role` filter value this slice links to: a slug or a bucket. */
  filter: string;
  label: string;
  count: number;
  bucket: boolean;
}

/**
 * The bar's segments: the resolved roles biggest first, then the three
 * buckets. Every count comes off the wire. The client derives no remainder.
 */
export function roleSlices(summary: MachineSummary): RoleSlice[] {
  const buckets = new Set<string>(ROLE_BUCKETS);
  const known = Object.entries(summary.roles ?? {})
    .filter(([role, count]) => !buckets.has(role) && count > 0)
    .sort(([roleA, a], [roleB, b]) => b - a || roleA.localeCompare(roleB))
    .map(([role, count]) => ({ filter: role, label: roleLabel(role), count, bucket: false }));
  const tail: RoleSlice[] = [];
  for (const bucket of ROLE_BUCKETS) {
    const count = summary.roles?.[bucket] ?? 0;
    if (count > 0) {
      tail.push({ filter: bucket, label: ROLE_BUCKET_LABELS[bucket], count, bucket: true });
    }
  }
  return [...known, ...tail];
}

const BUCKET_TITLES: Record<string, string> = {
  low_confidence:
    'The sweep guessed a role for these machines. The evidence is too weak to assert it. Role-scoped analytics leave these machines unscored.',
  stale:
    'The sweep inferred a role for these machines. The evidence is older than the staleness window. Run a sweep to confirm it.',
  unknown: 'The sweep has no role for these machines.',
};

function sliceRail(s: RoleSlice): string {
  if (s.filter === 'low_confidence') return 'bg-warn/55';
  if (s.filter === 'stale') return 'bg-warn/30';
  if (s.filter === 'unknown') return roleRail(null);
  return roleRail(s.filter);
}

function RoleBar({
  summary,
  linkFor,
}: {
  summary: MachineSummary;
  linkFor: (patch: Record<string, string | null>) => string;
}) {
  const slices = roleSlices(summary);
  if (summary.machines <= 0 || slices.length === 0) return null;
  const hrefOf = (s: RoleSlice) => linkFor({ role: s.filter, activity: 'all' });
  const titleOf = (s: RoleSlice) =>
    `${s.label}: ${plural(s.count, 'machine')}. Show these machines.${BUCKET_TITLES[s.filter] ? ` ${BUCKET_TITLES[s.filter]}` : ''}`;
  const roles = slices.filter((s) => !s.bucket);
  const buckets = slices.filter((s) => s.bucket);
  const legendLink = (s: RoleSlice) => (
    <Link
      key={s.filter}
      to={hrefOf(s)}
      data-testid={`role-legend-${s.filter}`}
      title={titleOf(s)}
      className="flex items-center gap-1.5 text-[11.5px] text-dim hover:text-text"
    >
      <span className={cn('h-2 w-2 flex-none rounded-full', sliceRail(s))} />
      {s.label}
      <span className="font-mono text-[11px] font-semibold text-text-2">
        {s.count.toLocaleString()}
      </span>
    </Link>
  );
  return (
    <div data-testid="role-bar" className="mt-3 rounded-panel border border-border bg-surface-1 px-4 py-3">
      <div className="mb-2 flex items-baseline justify-between gap-2">
        <span className="text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
          Roles
        </span>
        {/* The population, named. The Role menu in the table counts the list
            on screen, and the two read "unknown 31" and "unknown 12" with
            nothing to say why (dogfood 2026-10-06). */}
        <span
          data-testid="role-bar-scope"
          className="text-[11px] text-faint"
          title="The role of each machine. An operator declaration replaces the sweep value."
        >
          across all {plural(summary.machines, 'machine')}, quiet ones too
        </span>
      </div>
      {/* Each segment is a link to the machines it counts. The legend below
          carries the same links with words, for a segment too thin to click. */}
      <div className="flex h-2.5 w-full overflow-hidden rounded-pill" aria-label="Role distribution">
        {slices.map((s) => (
          <Link
            key={s.filter}
            to={hrefOf(s)}
            data-testid={`role-seg-${s.filter}`}
            aria-label={`${s.label}: ${plural(s.count, 'machine')}`}
            title={titleOf(s)}
            className={cn('min-w-[6px] hover:opacity-80', sliceRail(s))}
            style={{ flexGrow: s.count, flexBasis: 0 }}
          />
        ))}
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-x-3.5 gap-y-1">
        {roles.map(legendLink)}
        {buckets.length > 0 && (
          <span
            data-testid="role-bar-unconfirmed"
            className="flex flex-wrap items-center gap-x-3.5 gap-y-1 border-l border-border pl-3.5"
          >
            <span className="text-[11px] text-faint">No confirmed role:</span>
            {buckets.map(legendLink)}
          </span>
        )}
      </div>
    </div>
  );
}

// ---- the cards --------------------------------------------------------------

/** A card that is a link to the filter it counts. */
function CardLink({
  to,
  testId,
  label,
  children,
}: {
  to: string;
  testId: string;
  label: string;
  children: ReactNode;
}) {
  return (
    <Link
      to={to}
      data-testid={testId}
      aria-label={label}
      className="block rounded-panel outline-none transition-colors hover:[&>div]:border-accent/60 focus-visible:[&>div]:border-accent"
    >
      {children}
    </Link>
  );
}

export interface HostsSummaryProps {
  /** The census summary, or null while in flight or after a cold failure. */
  summary: MachineSummary | null;
  /** True once the read has failed. */
  failed: boolean;
  /** A list URL that applies these filters. The screen owns the URL shape. */
  linkFor: (patch: Record<string, string | null>) => string;
  /** False when sweeps do not run on a schedule. Null when unknown. */
  scheduleEnabled?: boolean | null;
  /** True while the list holds a search. The cards count every machine, and
   *  the strip says so (dogfood 2026-10-06). */
  searchActive?: boolean;
}

/** One part of Needs attention: a count, its words and the filter it lists. */
export interface AttentionPart {
  key: 'stale' | 'failed' | 'never-built' | 'no-clean-build';
  count: number;
  text: string;
  /** The `health` filter that lists the machines of this part. */
  health: 'stale' | 'broken';
  title: string;
}

/** The parts of Needs attention. An older server sends no `out_of_date`;
 *  the part is then the remainder. */
export function attentionParts(summary: MachineSummary): { outOfDate: number; neverBuilt: number } {
  const neverBuilt = summary.never_built;
  const outOfDate = summary.out_of_date ?? Math.max(0, summary.needs_attention - neverBuilt);
  return { outOfDate, neverBuilt };
}

/**
 * The parts to show, each above zero. `never_built` counts every machine with
 * no clean build, and the card read "3 never built" over 3 failed builds
 * (dogfood 2026-10-19, R4-D16). `build_failed` splits the failed builds off.
 * An older server sends no `build_failed`, and one part names the total.
 */
export function attentionList(summary: MachineSummary): AttentionPart[] {
  const { outOfDate, neverBuilt } = attentionParts(summary);
  const out: AttentionPart[] = [];
  if (outOfDate > 0) {
    out.push({
      key: 'stale',
      count: outOfDate,
      text: `${outOfDate.toLocaleString()} out of date`,
      health: 'stale',
      title: 'A clean build older than the staleness window. A sweep confirms it again.',
    });
  }
  const BROKEN_LIST = 'The link lists every machine with no clean build.';
  if (summary.build_failed == null) {
    if (neverBuilt > 0) {
      out.push({
        key: 'no-clean-build',
        count: neverBuilt,
        text: `${neverBuilt.toLocaleString()} ${neverBuilt === 1 ? 'has' : 'have'} no clean build`,
        health: 'broken',
        title: 'The sweep never built these machines, or the last build failed.',
      });
    }
    return out;
  }
  const failed = Math.min(Math.max(0, summary.build_failed), neverBuilt);
  const never = neverBuilt - failed;
  if (failed > 0) {
    out.push({
      key: 'failed',
      count: failed,
      text: `${failed.toLocaleString()} failed to build`,
      health: 'broken',
      title: `The last build of these machines failed. ${BROKEN_LIST}`,
    });
  }
  if (never > 0) {
    out.push({
      key: 'never-built',
      count: never,
      text: `${never.toLocaleString()} never built`,
      health: 'broken',
      title: `The sweep has not built these machines yet. ${BROKEN_LIST}`,
    });
  }
  return out;
}

/** "37 need attention: 34 out of date, 3 failed to build". */
export function attentionSentence(summary: MachineSummary): string {
  if (summary.needs_attention === 0) return 'No machine needs attention.';
  const parts = attentionList(summary).map((p) => p.text);
  const head = `${summary.needs_attention.toLocaleString()} need attention`;
  return parts.length ? `${head}: ${parts.join(', ')}` : head;
}

export function HostsSummary({
  summary,
  failed,
  linkFor,
  scheduleEnabled,
  searchActive = false,
}: HostsSummaryProps) {
  const n = (v: number | undefined) => (summary == null || v == null ? UNKNOWN : v.toLocaleString());
  const tone = (good: string) => (summary == null ? UNKNOWN_TONE : good);
  const parts = summary ? attentionList(summary) : null;
  return (
    <div data-testid="hosts-summary" data-tour="hosts-summary" className="mb-3.5">
      {searchActive && (
        <div data-testid="hosts-summary-scope" className="mb-1.5 text-[11.5px] text-faint">
          The cards and the role bar count every machine. The search does not filter them.
        </div>
      )}
      <div
        className={cn(
          'grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6',
          searchActive && 'opacity-70',
        )}
      >
        <CardLink
          to={linkFor({ activity: 'all' })}
          testId="card-machines"
          label={`Machines: ${n(summary?.machines)}. Show every machine.`}
        >
          <Kpi
            testId="sum-machines"
            label="Machines"
            value={n(summary?.machines)}
            sub={
              summary == null
                ? UNKNOWN
                : summary.machines === 0
                  ? 'nothing swept yet'
                  : `${summary.named.toLocaleString()} named · ${summary.unnamed.toLocaleString()} unnamed`
            }
            icon={<Server size={16} />}
            tone={tone('text-accent')}
            title="Every machine in the census. One machine can hold many addresses."
          />
        </CardLink>
        <CardLink
          to={linkFor({ agent: 'yes', activity: 'all' })}
          testId="card-with-agent"
          label={`With an agent: ${n(summary?.with_agent)}. Show these machines.`}
        >
          <Kpi
            testId="sum-with-agent"
            label="With an agent"
            value={n(summary?.with_agent)}
            sub={summary == null ? UNKNOWN : 'an agent reports from the machine'}
            icon={<RadioTower size={16} />}
            tone={
              summary == null || summary.with_agent === 0 ? UNKNOWN_TONE : provenanceTone('hostlog')
            }
            title="An agent on the machine ships its own logs."
          />
        </CardLink>
        <CardLink
          to={linkFor({ agent: 'no', activity: 'all' })}
          testId="card-without-agent"
          label={`Without an agent: ${n(summary?.without_agent)}. Show these machines.`}
        >
          <Kpi
            testId="sum-without-agent"
            label="Without an agent"
            value={n(summary?.without_agent)}
            sub={summary == null ? UNKNOWN : 'network traffic only'}
            icon={<WifiOff size={16} />}
            tone={tone('text-text-2')}
            title="No agent reports from these machines. Everything soc-ai knows comes from the network."
          />
        </CardLink>
        <CardLink
          to={linkFor({ seen: 'new', activity: 'all' })}
          testId="card-new"
          label={`New in 7 days: ${n(summary?.new_7d)}. Show these machines.`}
        >
          <Kpi
            testId="sum-new"
            label="New in 7 days"
            value={n(summary?.new_7d)}
            sub={summary == null ? UNKNOWN : 'first seen in the last 7 days'}
            icon={<Sparkles size={16} />}
            tone={tone(summary && summary.new_7d > 0 ? 'text-accent' : 'text-text-2')}
          />
        </CardLink>
        {/* The number lists the machines it counts, and each part lists its
            own. The card read "37" over a link that listed 3 addresses
            (dogfood 2026-10-06). Three links in one card, so the card itself
            is not a link. */}
        <div data-testid="card-attention" className="rounded-panel">
          <Kpi
            testId="sum-attention"
            label="Needs attention"
            value={
              summary == null ? (
                UNKNOWN
              ) : (
                <Link
                  to={linkFor({ health: 'attention', activity: 'all' })}
                  data-testid="attention-all"
                  aria-label={`${attentionSentence(summary)}. Show these machines.`}
                  className="hover:underline"
                >
                  {summary.needs_attention.toLocaleString()}
                </Link>
              )
            }
            sub={
              summary == null || parts == null ? (
                UNKNOWN
              ) : summary.needs_attention === 0 ? (
                'every build is clean and current'
              ) : (
                parts.map((p, i) => (
                  <span key={p.key}>
                    {i > 0 && ', '}
                    <Link
                      to={linkFor({ health: p.health, activity: 'all' })}
                      data-testid={`attention-${p.key}`}
                      className="underline decoration-dim/50 underline-offset-2 hover:text-text"
                      title={p.title}
                    >
                      {p.text}
                    </Link>
                  </span>
                ))
              )
            }
            icon={<AlertTriangle size={16} />}
            tone={
              summary == null
                ? UNKNOWN_TONE
                : summary.never_built > 0
                  ? 'text-danger'
                  : summary.needs_attention > 0
                    ? 'text-warn'
                    : 'text-mono-green'
            }
            title={
              summary == null
                ? 'Machines the sweep cannot build, or builds from old evidence.'
                : `${attentionSentence(summary)}. Each number lists its machines.`
            }
          />
        </div>
        {/* A filter on the list, at 0 too: the click shows an empty list
            and says so. The queue link left the default list on screen and
            looked like a dead card (dogfood 2026-10-06). */}
        <CardLink
          to={linkFor({ conflict: 'yes', activity: 'all' })}
          testId="card-conflicts"
          label={`Conflicts: ${n(summary?.conflicts)}. Show these machines.`}
        >
          <Kpi
            testId="sum-conflicts"
            label="Conflicts"
            value={n(summary?.conflicts)}
            sub={
              summary == null
                ? UNKNOWN
                : summary.conflicts === 0
                  ? 'the two sources agree'
                  : 'a declaration and the sweep disagree'
            }
            icon={<Scale size={16} />}
            tone={
              summary == null ? UNKNOWN_TONE : summary.conflicts > 0 ? 'text-warn' : 'text-mono-green'
            }
            title="An operator declaration and the sweep disagree. Each one needs a decision."
          />
        </CardLink>
      </div>

      {summary != null && <RoleBar summary={summary} linkFor={linkFor} />}

      {/* The strip's one status line. */}
      {summary == null ? (
        <div className="mt-1.5 text-[12px] text-dim">
          {failed
            ? 'The counts could not be read. The machine list below is a separate query. The list still works.'
            : <LoadingInline>Counting the network</LoadingInline>}
        </div>
      ) : (
        <div className="mt-1.5 text-[11.5px] text-faint">
          {failed && 'Could not refresh. These are the last counts. '}
          {summary.last_sweep_at == null ? (
            <span title="No sweep has built a machine yet.">Never swept.</span>
          ) : (
            <span title={absTime(summary.last_sweep_at)}>Last swept {ago(summary.last_sweep_at)}</span>
          )}
          {scheduleEnabled === false && (
            <>
              {' · '}
              <Link
                to={DOSSIER_CONFIG_HREF}
                title="These counts change only after a sweep. With the schedule off, a sweep runs only when an admin starts one."
                className="underline decoration-faint/50 underline-offset-2 hover:text-text hover:decoration-dim"
              >
                automatic sweeps are off
              </Link>
              {/* The list reads the agent state and the last-seen time from
                  that sweep. The machine page reads live activity, so the two
                  disagreed with nothing to say which one was old. */}
              {summary.last_sweep_at != null && (
                <>
                  {' · '}
                  <span
                    data-testid="hosts-as-of"
                    title="The Agent and Last seen columns show the state at the last sweep. The machine page shows live activity."
                  >
                    the list shows the state as of{' '}
                    {absTime(summary.last_sweep_at, { zone: true })}
                  </span>
                </>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
