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

/** The Config anchor for the dossier's master switch and its schedule. Both
 *  are off by default, so every dead end on this screen points here. */
export const DOSSIER_CONFIG_HREF = '/config#host-dossier';

/** The bucket keys the summary's `roles` carries beside the role slugs. Each
 *  is also a value of the list's `role` filter. */
export const ROLE_BUCKETS = ['low_confidence', 'stale', 'unknown'] as const;

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
      tail.push({ filter: bucket, label: bucket.replace(/_/g, ' '), count, bucket: true });
    }
  }
  return [...known, ...tail];
}

const BUCKET_TITLES: Record<string, string> = {
  low_confidence:
    'The sweep guessed a role for these machines. The evidence is too thin to assert it. Role-scoped analytics leave these machines unscored.',
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
  return (
    <div data-testid="role-bar" className="mt-3 rounded-panel border border-border bg-surface-1 px-4 py-3">
      <div className="mb-2 flex items-baseline justify-between gap-2">
        <span className="text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
          Roles
        </span>
        <span className="text-[11px] text-faint" title="The role of each machine. An operator declaration wins over the sweep.">
          across {plural(summary.machines, 'machine')}
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
        {slices.map((s) => (
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
        ))}
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
  /** The broken-builds view. */
  brokenHref: string;
  /** The disagreement queue. */
  conflictsHref: string;
  /** False when sweeps do not run on a schedule. Null when unknown. */
  scheduleEnabled?: boolean | null;
}

export function HostsSummary({
  summary,
  failed,
  linkFor,
  brokenHref,
  conflictsHref,
  scheduleEnabled,
}: HostsSummaryProps) {
  const n = (v: number | undefined) => (summary == null || v == null ? UNKNOWN : v.toLocaleString());
  const tone = (good: string) => (summary == null ? UNKNOWN_TONE : good);
  return (
    <div data-testid="hosts-summary" className="mb-3.5">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
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
        <CardLink
          to={brokenHref}
          testId="card-attention"
          label={`Needs attention: ${n(summary?.needs_attention)}. Show the addresses with a broken build.`}
        >
          <Kpi
            testId="sum-attention"
            label="Needs attention"
            value={n(summary?.needs_attention)}
            sub={
              summary == null
                ? UNKNOWN
                : summary.never_built > 0
                  ? `${summary.never_built.toLocaleString()} broken or never built`
                  : 'no broken builds'
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
            title="Machines the sweep cannot build, or builds from old evidence. The link opens the addresses with no clean build."
          />
        </CardLink>
        <CardLink
          to={conflictsHref}
          testId="card-conflicts"
          label={`Conflicts: ${n(summary?.conflicts)}. Open the review queue.`}
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
                  : 'open the review queue'
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
            : 'Counting the network…'}
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
            </>
          )}
        </div>
      )}
    </div>
  );
}
