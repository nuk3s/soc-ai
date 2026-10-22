// What a host is DOING: who it talks to, how much, and who is on it.
//
// The live half of the host page. Everything here is read off Security Onion on
// the request that rendered it, so unlike the dossier above it has a real
// unavailable state — and the whole design of this file is about not answering
// when it was not told anything. An empty peer graph says "this host was quiet";
// a missing one says "we could not ask". Those must never look alike, because
// the first is a finding and the second is an outage.

import { Activity as ActivityIcon, AlertTriangle, RotateCw, Share2, Users } from 'lucide-react';
import { cn } from '../lib/cn';
import type { ActivityState } from '../lib/hostActivity';
import { absTime } from '../lib/timeRange';
import type { HostActivity, HostActivityRange, VolumePoint } from '../lib/types';
import { PeerGraph } from './PeerGraph';
import { Panel, PanelHeader } from './Panel';
import { sparklinePoints } from './QualityCard';
import { LoadingInline } from './States';

// ---- the volume sparkline ---------------------------------------------------

/**
 * Connection volume over the window.
 *
 * Reuses `sparklinePoints` from QualityCard, which plots a FIXED 0..1 domain —
 * right for a rate, wrong for a count, which has no natural ceiling. So the
 * series is normalised against its own peak here and the peak is printed beside
 * the line: an auto-scaled chart with no scale on it makes a quiet hour look
 * exactly like a busy one.
 *
 * The server pads the series to the whole window. An older server sends a
 * series that starts at the first active bucket. Nothing here assumes a
 * bucket count. The right label is the END of the newest bucket: a one-bucket
 * series read the same instant at both ends (dogfood 2026-10-19, R4-D8).
 */
function VolumeChart({
  volume,
  range,
  datasets,
}: {
  volume: VolumePoint[];
  range: HostActivityRange;
  datasets?: string[];
}) {
  const W = 260;
  const H = 54;
  const peak = volume.reduce((max, point) => Math.max(max, point.events), 0);
  const points = peak > 0 ? sparklinePoints(volume.map((p) => p.events / peak), W, H) : '';

  if (points === '') {
    return (
      <div className="px-[15px] py-3.5 text-[12.5px] leading-[1.6] text-dim">
        No connection records for this host in the last {range}.{' '}
        <span className="text-faint">
          The host was quiet, or its traffic is not in the events index.
        </span>
      </div>
    );
  }

  // No Array.prototype.at(): the app's tsconfig lib predates es2022.
  const coords = points.split(' ');
  const last = coords[coords.length - 1].split(',');
  const first = volume[0];
  const newest = volume[volume.length - 1];
  const bucketMs = range === '7d' ? 86_400_000 : 3_600_000;
  // The newest bucket may still be open. Its end is then now.
  const end = new Date(Math.min(new Date(newest.ts).getTime() + bucketMs, Date.now())).toISOString();

  return (
    <div className="px-[15px] py-3.5">
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="h-[54px] w-full text-mono-green"
        preserveAspectRatio="none"
        role="img"
        aria-label={`connection volume over the last ${range}`}
      >
        {/* `preserveAspectRatio="none"` stretches x to the panel width, which
            turned a round endpoint marker into a visible ellipse and made the
            line weight vary with the column width. A vertical tick survives the
            stretch, and non-scaling-stroke pins both to real pixels. */}
        <polyline
          points={points}
          fill="none"
          stroke="currentColor"
          strokeWidth={1.5}
          vectorEffect="non-scaling-stroke"
        />
        <line
          x1={Number(last[0])}
          y1={Number(last[1]) - 3.5}
          x2={Number(last[0])}
          y2={Number(last[1]) + 3.5}
          stroke="currentColor"
          strokeWidth={2.5}
          vectorEffect="non-scaling-stroke"
        />
      </svg>
      <div className="mt-2 flex items-baseline justify-between gap-2 font-mono text-[11px] text-faint">
        <span data-testid="volume-start">{absTime(first.ts)}</span>
        <span title="The bottom of the chart is zero. The top is the busiest interval.">
          peak {peak.toLocaleString()}
        </span>
        <span data-testid="volume-end">{absTime(end)}</span>
      </div>
      {/* The flow datasets behind the counts. The page never named them
          (dogfood 2026-10-19, R4-D21). */}
      {datasets && datasets.length > 0 && (
        <div data-testid="volume-datasets" className="mt-1 text-[11px] text-faint">
          The counts come from {joinWords(datasets)}.
        </div>
      )}
    </div>
  );
}

/** "a", "a and b", "a, b and c". */
function joinWords(items: readonly string[]): string {
  if (items.length <= 1) return items.join('');
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
}

// ---- the users card ---------------------------------------------------------

/**
 * Accounts seen authenticating on this host.
 *
 * `users === null` is the case this card exists for. It means the grid returned
 * no host-log authentication documents for the address — and the query is
 * WINDOW-scoped, so a host that ships auth logs and simply had a quiet day
 * answers null too. The copy therefore stops where the evidence does: it names
 * both possibilities rather than asserting the stronger, more interesting one.
 */
function UsersCard({
  users,
  truncated,
  range,
  datasets,
}: {
  users: HostActivity['users'];
  /** The server cut the ranked list — the wire's own flag, never re-inferred. */
  truncated: boolean;
  range: HostActivityRange;
  /** The host-log datasets the list reads. Absent on an older server. */
  datasets?: string[];
}) {
  // The card names the datasets it reads. It read Linux logons only and said
  // "no host logs" on a Windows domain controller (dogfood 2026-10-19, R4-D5).
  const named = datasets && datasets.length > 0 ? joinWords(datasets) : null;
  if (users === null) {
    return (
      <div className="px-[15px] py-3.5">
        <div className="text-[12.5px] text-dim">No logon in this window.</div>
        <div className="mt-1 text-[11.5px] leading-[1.5] text-faint">
          {named
            ? `This card reads ${named}. ${datasets!.length === 1 ? 'This dataset holds' : 'These datasets hold'} no logon for this address in the last ${range}.`
            : `The host logs hold no logon for this address in the last ${range}.`}{' '}
          A host with no logon and a host that ships no host logs both show this line.
        </div>
      </div>
    );
  }
  if (users.length === 0) {
    return (
      <div className="px-[15px] py-3.5 text-[12.5px] leading-[1.6] text-dim">
        Host logs reached the grid for this address. Nobody authenticated in the last {range}.
      </div>
    );
  }
  return (
    <div className="flex flex-col divide-y divide-border">
      {users.map((user) => (
        <div key={user.name} className="flex items-baseline gap-2 px-[15px] py-2">
          <span className="min-w-0 flex-1 break-all font-mono text-[12.5px] text-text-2">
            {user.name}
          </span>
          <span className="flex-none font-mono text-[11px] text-faint" title="Authentication events">
            {user.events.toLocaleString()}
          </span>
          <span className="flex-none font-mono text-[11px] text-faint">
            {absTime(user.last_seen)}
          </span>
        </div>
      ))}
      {/* The server ranks by event count and cuts the list, and SAYS SO on the
          wire — so this footnote states a cut that happened rather than
          guessing one from the length. Reading a cut list as "the accounts on
          this host" would be a stronger claim than the query made. */}
      {truncated && (
        <div className="px-[15px] py-2 text-[11px] text-faint">
          The {users.length} busiest accounts in this window.
        </div>
      )}
      {named && (
        <div data-testid="users-datasets" className="px-[15px] py-2 text-[11px] text-faint">
          From {named}.
        </div>
      )}
    </div>
  );
}

// ---- the row ----------------------------------------------------------------

export interface HostActivityRowProps {
  ip: string;
  activity: HostActivity | null;
  /** The one discriminant, shared with the KPI strip. */
  state: ActivityState;
  /** The grid's own words, for the two states that report a failure. */
  error: Error | null;
  /** Whether a request is in flight — a different question from `state`, and the
   *  reason a re-read dims a panel instead of emptying it. */
  loading: boolean;
  range: HostActivityRange;
  onRetry: () => void;
}

export function HostActivityRow({
  ip,
  activity,
  state,
  error,
  loading,
  range,
  onRetry,
}: HostActivityRowProps) {
  // A read that failed with nothing to fall back on. The grid's own words, and
  // NOT the page-level ErrorState: the dossier answered, and the twelve cards
  // below are still the point of the page — only this half is missing, and it
  // says so where it would have been.
  if (state === 'down') {
    return (
      <div
        data-testid="activity-degraded"
        role="status"
        className="mb-3 flex flex-wrap items-center gap-x-3 gap-y-2 rounded-panel border border-warn/35 bg-warn/[0.06] px-4 py-3"
      >
        <AlertTriangle size={15} className="flex-none text-warn" />
        <div className="min-w-0 flex-1">
          <div className="text-[12.5px] font-semibold text-warn">
            soc-ai could not read this host's live activity
          </div>
          {/* Two sentences, two elements: the grid's message is not guaranteed
              to end in punctuation, and concatenating produced "grid down
              Everything below…". */}
          <div className="mt-0.5 text-[11.5px] leading-[1.5] text-dim">{error?.message}</div>
          <div className="mt-0.5 text-[11.5px] leading-[1.5] text-faint">
            Everything below comes from the network sweep. This failure does not affect it.
          </div>
        </div>
        <button
          onClick={onRetry}
          disabled={loading}
          className="flex flex-none items-center gap-1.5 rounded-control border border-warn/40 px-2.5 py-1 text-[11.5px] font-semibold text-warn hover:bg-warn/15 disabled:opacity-60"
        >
          <RotateCw size={11} /> Retry
        </button>
      </div>
    );
  }

  // Reserves roughly the row's minimum height. One line replaced by ~600px made
  // every field card below jump on arrival; the KPI strip above already reserves
  // its own height, and this is the surface that did not.
  if (state === 'loading' || !activity) {
    return (
      <div className="mb-3 flex min-h-[300px] items-center justify-center rounded-panel border border-border bg-surface-1 px-4 text-[12.5px] text-faint">
        <LoadingInline>Reading this host's activity from the grid</LoadingInline>
      </div>
    );
  }

  return (
    <>
      {/* A refresh that failed on top of a good read. The panels below are still
          worth looking at — they are simply older than they claim to be — so the
          honest move is to keep them and date them, not to blank a surface the
          analyst was part-way through reading. */}
      {state === 'stale' && (
        <div
          data-testid="activity-stale"
          role="status"
          className="mb-3 flex items-center gap-2 rounded-control border-l-2 border-warn bg-warn/[0.08] px-3 py-1.5 text-[12px] text-warn"
        >
          <AlertTriangle size={13} className="flex-none" />
          <span className="min-w-0 flex-1">
            Could not re-read the grid. The activity below is the last good read.
            {error?.message && <span className="text-dim"> · {error.message}</span>}
          </span>
          <button
            onClick={onRetry}
            disabled={loading}
            className="flex flex-none items-center gap-1 rounded-control border border-warn/40 px-2 py-0.5 text-[11px] font-semibold hover:bg-warn/15 disabled:opacity-60"
          >
            <RotateCw size={11} /> Retry
          </button>
        </div>
      )}

      <div data-tour="host-activity" className="mb-3 grid grid-cols-1 gap-3 lg:grid-cols-3">
        <Panel className={cn('lg:col-span-2', loading && 'opacity-60')}>
          {/* No verdict chip here. A "latest False positive" chip on the
              peer graph read as the verdict on the host, beside an Alerts
              card that said nothing fired (dogfood 2026-10-06, S3). The
              first lines of the page carry the leads and the verdicts. */}
          <PanelHeader icon={<Share2 size={15} />} title={`Peers · ${range}`} />
          {activity.peers.length === 0 ? (
            <div className="px-[15px] py-8 text-center text-[12.5px] leading-[1.6] text-dim">
              No peer traffic for this host in the last {range}.
              <div className="mt-1 text-[11.5px] text-faint">
                The grid answered. This host exchanged nothing that the grid can see.
              </div>
            </div>
          ) : (
            <div data-testid="host-peer-graph">
              {/* Who this host talks to, how much, and which peers an alert
                  names. lib/peerGraph.ts shapes the diagram. */}
              <PeerGraph ip={ip} peers={activity.peers} />
              {/* The server ranks by traffic and cuts the list, and the wire
                  says when it did — so this footnote appears exactly when
                  peers fell off the end, not whenever the list happens to be
                  full. */}
              {activity.peers_truncated && (
                <div className="border-t border-border px-3.5 py-2 text-[11px] text-faint">
                  The {activity.peers.length} busiest peers in this window.
                </div>
              )}
            </div>
          )}
        </Panel>

        <div className="flex flex-col gap-3">
          <Panel className={cn(loading && 'opacity-60')}>
            <PanelHeader icon={<ActivityIcon size={15} />} title={`Volume · ${range}`} />
            <div data-testid="host-volume">
              <VolumeChart volume={activity.volume} range={range} datasets={activity.conn_datasets} />
            </div>
          </Panel>
          <Panel className={cn(loading && 'opacity-60')}>
            <PanelHeader icon={<Users size={15} />} title={`Users · ${range}`} />
            <div data-testid="host-users">
              <UsersCard
                users={activity.users}
                truncated={activity.users_truncated}
                range={range}
                datasets={activity.auth_datasets}
              />
            </div>
          </Panel>
        </div>
      </div>
    </>
  );
}
