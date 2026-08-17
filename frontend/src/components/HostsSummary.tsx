// The network above the host list: four KPI cards and a role-distribution bar.
//
// The numbers still come from GET /dossiers/summary — the WHOLE table, never
// the page on screen (the table below is one SQL page of up to 5,000 hosts,
// and a count taken off it would describe fifty rows while reading as the
// network's; this app has shipped that defect twice).
//
// The rules the one-line strip enforced carry over unchanged:
//   * a count is a DOOR or it is a CAPTION — broken builds and open
//     disagreements link to the views that show exactly those rows, and no
//     door exists at zero;
//   * a failed read never renders a zero. The cards show the shared dash
//     instead, because "0 hosts" is a claim about the network that is false
//     exactly when the endpoint is down;
//   * ONE freshness line, from the data's own clock (MAX(last_built_at)).
//
// The cards are the same Kpi component the host page's strip uses — one idea
// at two altitudes, not two components that look alike.

import { AlertTriangle, RadioTower, Scale, Server } from 'lucide-react';
import { Link } from 'react-router-dom';
import { cn } from '../lib/cn';
import { provenanceTone, roleRail } from '../lib/hostColors';
import { roleLabel } from '../lib/hostDossier';
import { plural } from '../lib/plural';
import { absTime, ago } from '../lib/timeRange';
import type { DossierSummary } from '../lib/types';
import { Kpi, UNKNOWN, UNKNOWN_TONE } from './Kpi';

/** The Config anchor for the dossier's master switch and its schedule. BOTH
 *  are off by default, which is why every dead end on this screen points here:
 *  an empty host list, a Rebuild that swept nothing, and counts nothing will
 *  refresh are all one settings answer rather than a failure. */
export const DOSSIER_CONFIG_HREF = '/config#host-dossier';

/** The conflicts queue on this same screen — a disclosure, not a route;
 *  `?conflicts=1` opens it pre-revealed. */
const CONFLICTS_HREF = '/hosts?conflicts=1';

/** The broken-builds view: the same set the `never_built` count describes. */
export const BROKEN_BUILDS_HREF = '/hosts?health=broken';

// ---- the role-distribution bar ----------------------------------------------

interface RoleSlice {
  /** The resolved role word, or null for the unresolved remainder. */
  role: string | null;
  count: number;
}

/**
 * The bar's segments, biggest first, the gray remainder last.
 *
 * The wire's `roles` only holds RESOLVED roles, so the remainder is computed
 * here as `hosts - sum(counts)` — with one fold: the classifier can emit the
 * literal role "unknown" (soc_ai/dossier/infer.py), and to a reader that IS
 * the remainder. Two adjacent gray segments both meaning "don't know" would
 * look like a distinction the data is not making.
 */
export function roleSlices(summary: DossierSummary): RoleSlice[] {
  const known = Object.entries(summary.roles)
    .filter(([role, count]) => role.trim().toLowerCase() !== 'unknown' && count > 0)
    .sort(([roleA, a], [roleB, b]) => b - a || roleA.localeCompare(roleB))
    .map(([role, count]) => ({ role, count }));
  const unresolved = summary.hosts - known.reduce((total, s) => total + s.count, 0);
  return unresolved > 0 ? [...known, { role: null, count: unresolved }] : known;
}

function RoleBar({ summary }: { summary: DossierSummary }) {
  const slices = roleSlices(summary);
  if (summary.hosts <= 0 || slices.length === 0) return null;
  const label = (s: RoleSlice) => (s.role == null ? 'unknown' : roleLabel(s.role));
  return (
    <div data-testid="role-bar" className="mt-3 rounded-panel border border-border bg-surface-1 px-4 py-3">
      <div className="mb-2 flex items-baseline justify-between gap-2">
        <span className="text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
          Roles
        </span>
        <span
          className="text-[11px] text-faint"
          title="Each host's effective role: an operator's declaration where one exists, otherwise what the sweep concluded — the same answer the Role column below shows. Gray is every host whose role is not resolved."
        >
          across {plural(summary.hosts, 'host')}
        </span>
      </div>
      {/* The segments are proportional; the LEGIBLE labels live in the legend
          underneath, because a 2%-wide segment cannot carry its own words. */}
      <div className="flex h-2.5 w-full overflow-hidden rounded-pill" role="img" aria-label="role distribution">
        {slices.map((s) => (
          <div
            key={s.role ?? '∅'}
            data-testid={`role-seg-${s.role ?? 'unknown'}`}
            title={`${label(s)} — ${s.count.toLocaleString()} host${s.count === 1 ? '' : 's'}`}
            className={cn('min-w-[6px]', roleRail(s.role))}
            style={{ flexGrow: s.count, flexBasis: 0 }}
          />
        ))}
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-x-3.5 gap-y-1">
        {slices.map((s) => (
          <span key={s.role ?? '∅'} className="flex items-center gap-1.5 text-[11.5px] text-dim">
            <span className={cn('h-2 w-2 flex-none rounded-full', roleRail(s.role))} />
            {label(s)}
            <span className="font-mono text-[11px] font-semibold text-text-2">
              {s.count.toLocaleString()}
            </span>
          </span>
        ))}
      </div>
    </div>
  );
}

// ---- the strip --------------------------------------------------------------

export interface HostsSummaryProps {
  /** The whole-network summary, or null while in flight / after a cold fail. */
  summary: DossierSummary | null;
  /** True once the read has failed. With no summary behind it that is a cold
   *  failure; with one, a refresh that failed over good numbers. */
  failed: boolean;
  /** True while the disagreement banner is on screen directly below, already
   *  carrying the review action — the counts keep their words and give up
   *  their doors, or one control looks like two. */
  queueVisible: boolean;
}

export function HostsSummary({ summary, failed, queueVisible }: HostsSummaryProps) {
  const attention = summary == null ? null : summary.never_built + summary.conflicts;
  return (
    <div data-testid="hosts-summary" className="mb-3.5">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Kpi
          testId="sum-hosts"
          label="Hosts"
          value={summary == null ? UNKNOWN : summary.hosts.toLocaleString()}
          sub={
            summary == null ? (
              UNKNOWN
            ) : summary.hosts === 0 ? (
              'nothing swept yet'
            ) : (
              <span title="Hosts whose name will stand — an operator's, or one the sweep is sure enough of. Withheld names are not counted, so this agrees with the Host column below.">
                {`${summary.named.toLocaleString()} named · ${(summary.hosts - summary.named).toLocaleString()} unnamed`}
              </span>
            )
          }
          icon={<Server size={16} />}
          tone={summary == null ? UNKNOWN_TONE : 'text-accent'}
          title="Every host the sweep holds, whatever the table below is filtered to."
        />
        <Kpi
          testId="sum-reporting"
          label="Reporting"
          value={summary == null ? UNKNOWN : summary.reporting.toLocaleString()}
          sub={summary == null ? UNKNOWN : 'with agent logs'}
          icon={<RadioTower size={16} />}
          tone={
            summary == null || summary.reporting === 0
              ? UNKNOWN_TONE
              : provenanceTone('hostlog')
          }
          title={
            summary == null
              ? undefined
              : `An agent on the machine ships its own logs, so those pages can say more than traffic alone shows. No agent data from ${plural(summary.hosts - summary.reporting, 'host')}.`
          }
        />
        <Kpi
          testId="sum-attention"
          label="Needs attention"
          value={attention == null ? UNKNOWN : attention.toLocaleString()}
          sub={
            summary == null ? (
              UNKNOWN
            ) : attention === 0 ? (
              'no broken builds, no open disagreements'
            ) : (
              // The doors, exactly where the number is — a count with no way
              // to the rows it counts is a dead end.
              <span className="flex flex-col gap-0.5">
                {summary.never_built > 0 && (
                  <Link
                    data-testid="sum-broken"
                    to={BROKEN_BUILDS_HREF}
                    title="The sweep is not getting through to these hosts — never built, or the last build failed. Click to see which."
                    className="font-semibold text-danger hover:underline"
                  >
                    {summary.never_built.toLocaleString()} broken or never built
                  </Link>
                )}
                {summary.conflicts > 0 &&
                  (queueVisible ? (
                    <span data-testid="sum-review" className="font-semibold text-warn">
                      {summary.conflicts.toLocaleString()} need review
                    </span>
                  ) : (
                    <Link
                      data-testid="sum-review"
                      to={CONFLICTS_HREF}
                      title="Declared answers the sweep keeps disagreeing with — each wants a decision."
                      className="font-semibold text-warn hover:underline"
                    >
                      {summary.conflicts.toLocaleString()} need review
                    </Link>
                  ))}
              </span>
            )
          }
          icon={<AlertTriangle size={16} />}
          tone={
            summary == null
              ? UNKNOWN_TONE
              : summary.never_built > 0
                ? 'text-danger'
                : summary.conflicts > 0
                  ? 'text-warn'
                  : 'text-mono-green'
          }
        />
        <Kpi
          testId="sum-conflicts"
          label="Conflicts"
          value={summary == null ? UNKNOWN : summary.conflicts.toLocaleString()}
          sub={
            summary == null ? (
              UNKNOWN
            ) : summary.conflicts === 0 ? (
              'the lanes agree'
            ) : queueVisible ? (
              // The banner below already carries the action — a second door
              // 40px away is one control that looks like two.
              'in the review queue below'
            ) : (
              <Link
                to={CONFLICTS_HREF}
                title="Declared answers the sweep keeps disagreeing with — each wants a decision."
                className="font-semibold text-warn hover:underline"
              >
                open the review queue
              </Link>
            )
          }
          icon={<Scale size={16} />}
          tone={
            summary == null ? UNKNOWN_TONE : summary.conflicts > 0 ? 'text-warn' : 'text-mono-green'
          }
          title="Open disagreements between an operator's declaration and what the sweep keeps seeing."
        />
      </div>

      {summary != null && <RoleBar summary={summary} />}

      {/* The strip's ONE status/freshness line. Degraded states say what
          happened where the numbers would have dated themselves. */}
      {summary == null ? (
        <div className="mt-1.5 text-[12px] text-dim">
          {failed
            ? 'Counts could not be read — the host list below is a separate query and is unaffected.'
            : 'Counting the network…'}
        </div>
      ) : (
        <div className="mt-1.5 text-[11.5px] text-faint">
          {failed && 'Could not refresh — showing the last counts. '}
          {summary.last_built_at == null ? (
            <span title="No host in the table carries a build stamp — nothing has swept the network yet.">
              Never swept — nothing has built these hosts yet
            </span>
          ) : (
            <span title={absTime(summary.last_built_at)}>
              Last swept {ago(summary.last_built_at)}
            </span>
          )}
          {/* Only when it is off. A schedule that is running needs no comment,
              and a line that always says something stops being read at all. */}
          {!summary.schedule_enabled && (
            <>
              {' · '}
              <Link
                to={DOSSIER_CONFIG_HREF}
                title="These counts only change when the network is swept. With the schedule off, that is whenever somebody presses Rebuild."
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
