// What a host is DOING: who it talks to, how much, and who is on it.
//
// The live half of the host page. Everything here is read off Security Onion on
// the request that rendered it, so unlike the dossier above it has a real
// unavailable state — and the whole design of this file is about not answering
// when it was not told anything. An empty peer graph says "this host was quiet";
// a missing one says "we could not ask". Those must never look alike, because
// the first is a finding and the second is an outage.

import { Activity as ActivityIcon, AlertTriangle, RotateCw, Share2, Users } from 'lucide-react';
import { Link } from 'react-router-dom';
import { cn } from '../lib/cn';
import type { ActivityState } from '../lib/hostActivity';
import { isPrivateIp } from '../lib/ip';
import { absTime } from '../lib/timeRange';
import type {
  EdgeKind,
  EntityKind,
  GraphEdge,
  GraphNode,
  HostActivity,
  HostActivityRange,
  HostPeer,
  Verdict,
  VolumePoint,
} from '../lib/types';
import { VerdictPill } from './Badges';
import { EntityGraph } from './EntityGraph';
import { Panel, PanelHeader } from './Panel';
import { sparklinePoints } from './QualityCard';

// ---- the peer graph ---------------------------------------------------------

/**
 * Lay the host and its peers out for EntityGraph.
 *
 * A pure seam, so the mapping decisions can be pinned without rendering SVG: the
 * subject on the left, its peers stacked down the right, one edge per direction
 * of traffic. Two things are deliberate.
 *
 * `alerted` maps to the `lateral` edge kind. That is EntityGraph's DANGER-styled
 * edge, and the style is what is being asked for — the word "lateral" is not a
 * claim this code is making about the traffic, which is why the edge is also
 * labelled "alerted" so the graph says what it means.
 *
 * A `both` peer gets two edges rather than one. EntityGraph has no bidirectional
 * arrow, and drawing one arrow for two-way traffic would pick a direction the
 * data does not.
 */
export function peerGraph(ip: string, peers: HostPeer[]): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes: GraphNode[] = [
    { id: ip, x: 8, y: 50, kind: 'host', label: ip, sub: 'this host' },
  ];
  const edges: GraphEdge[] = [];

  // The subject is never its own peer. The server filters this too (the right
  // layer), but a self-referential row would render here as a second node with
  // the same id and a zero-length edge from a node to itself, so the mapping is
  // independently correct about it rather than trusting its input.
  const others = peers.filter((peer) => peer.ip !== ip);

  others.forEach((peer, i) => {
    // One peer sits on the centre line; several spread evenly down the column.
    const y = others.length === 1 ? 50 : 8 + (84 * i) / (others.length - 1);
    // Internal peers are the square "internal host"; everything else takes the
    // warmer "outside the network" node style. That style's stock legend label is
    // "C2 / external", which would accuse every CDN of being command-and-control
    // — the graph is rendered with a `kindLabels` override that renames it.
    const kind: EntityKind = isPrivateIp(peer.ip) ? 'internal' : 'c2';
    nodes.push({
      id: peer.ip,
      x: 76,
      y,
      kind,
      // The network's name for the peer when it has one; the address otherwise.
      // A blank label would lose the only handle the reader has on the node.
      label: peer.hostname ?? peer.ip,
      sub: peer.ports.length > 0 ? peer.ports.slice(0, 3).join(', ') : undefined,
    });

    const edgeKind: EdgeKind = peer.alerted ? 'lateral' : 'flow';
    const label = peer.alerted ? 'alerted' : undefined;
    const inbound = peer.direction === 'in' || peer.direction === 'both';
    const outbound = peer.direction === 'out' || peer.direction === 'both';
    // EXACTLY ONE of the two edges carries the label. EntityGraph centres a
    // label on its own edge's midpoint, and a `both` peer's two edges are
    // collinear — the midpoints differ only by the arrowhead pullback, so
    // labelling both stacks the same word twice on one baseline about 19px
    // apart, and "alerted" is wider than that at fontSize 9. It renders as
    // smeared, doubled text. The outbound edge carries it when there is one;
    // an inbound-only peer would otherwise lose its label entirely.
    if (inbound) {
      edges.push({ from: peer.ip, to: ip, kind: edgeKind, label: outbound ? undefined : label });
    }
    if (outbound) {
      edges.push({ from: ip, to: peer.ip, kind: edgeKind, label });
    }
  });

  return { nodes, edges };
}

/** Tall enough that peers do not collide, short enough that a two-peer host does
 *  not get a page of whitespace.
 *
 *  46px of pitch per peer against a 34px node diameter. The server caps the
 *  list at 12 (MAX_PEERS in soc_ai/webui/host_activity.py), which wants 622 —
 *  so the upper clamp sits just above that rather than below it. A 560 cap
 *  would have squeezed a full list to 38px of pitch, which is 4px of air
 *  between nodes; the clamp is defence against the server's cap changing, not
 *  something that fires today. */
function graphHeight(peerCount: number): number {
  return Math.min(640, Math.max(240, peerCount * 46 + 70));
}

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
 * The server sets no `extended_bounds`, so the series does not necessarily span
 * the window. Nothing here assumes a bucket count.
 */
function VolumeChart({ volume, range }: { volume: VolumePoint[]; range: HostActivityRange }) {
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
        <span>{absTime(first.ts)}</span>
        <span title="The chart is scaled to its own busiest bucket">
          peak {peak.toLocaleString()}
        </span>
        <span>{absTime(newest.ts)}</span>
      </div>
    </div>
  );
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
}: {
  users: HostActivity['users'];
  /** The server cut the ranked list — the wire's own flag, never re-inferred. */
  truncated: boolean;
  range: HostActivityRange;
}) {
  if (users === null) {
    return (
      <div className="px-[15px] py-3.5">
        <div className="text-[12.5px] text-dim">No host-log users in this window.</div>
        <div className="mt-1 text-[11.5px] leading-[1.5] text-faint">
          Either nobody authenticated in the last {range}, or the grid holds no host logs for this
          address at all — this view cannot tell the two apart.
        </div>
      </div>
    );
  }
  if (users.length === 0) {
    return (
      <div className="px-[15px] py-3.5 text-[12.5px] leading-[1.6] text-dim">
        Host logs reached the grid for this address, and nobody authenticated in the last {range}.
      </div>
    );
  }
  return (
    <div className="flex flex-col divide-y divide-border">
      {users.map((user) => (
        <div key={user.name} className="flex items-baseline gap-2 px-[15px] py-2">
          <span className="min-w-0 flex-1 truncate font-mono text-[12.5px] text-text-2">
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
            This host's live activity could not be read
          </div>
          {/* Two sentences, two elements: the grid's message is not guaranteed
              to end in punctuation, and concatenating produced "grid down
              Everything below…". */}
          <div className="mt-0.5 text-[11.5px] leading-[1.5] text-dim">{error?.message}</div>
          <div className="mt-0.5 text-[11.5px] leading-[1.5] text-faint">
            Everything below comes from the network sweep and is unaffected.
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
        Reading this host's activity from the grid…
      </div>
    );
  }

  const { nodes, edges } = peerGraph(ip, activity.peers);
  const latest = activity.latest_investigation;

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
            Could not re-read the grid ({error?.message}) — the activity below is the last good
            read.
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

      <div className="mb-3 grid grid-cols-1 gap-3 lg:grid-cols-3">
        <Panel className={cn('lg:col-span-2', loading && 'opacity-60')}>
          <PanelHeader
            icon={<Share2 size={15} />}
            title={`Peers · ${range}`}
            right={
              latest ? (
                <Link
                  to={`/investigation/${encodeURIComponent(latest.id)}`}
                  title={`Most recent investigation naming this host · ${absTime(latest.ts)}`}
                  className="flex items-center gap-2 text-[11.5px] text-dim hover:text-text"
                >
                  latest
                  {/* A run links before it concludes, so a null verdict is "still
                      going", not "untriaged" — different things, different chips. */}
                  {latest.verdict ? (
                    <VerdictPill verdict={latest.verdict as Verdict} showConf={false} />
                  ) : (
                    <span className="rounded-pill border border-accent/40 bg-accent/10 px-2 py-px text-[11px] font-semibold text-accent">
                      investigating
                    </span>
                  )}
                </Link>
              ) : null
            }
          />
          {activity.peers.length === 0 ? (
            <div className="px-[15px] py-8 text-center text-[12.5px] leading-[1.6] text-dim">
              No peer traffic for this host in the last {range}.
              <div className="mt-1 text-[11.5px] text-faint">
                The grid answered — this host simply exchanged nothing it could see.
              </div>
            </div>
          ) : (
            <div data-testid="host-peer-graph">
              <EntityGraph
              nodes={nodes}
              edges={edges}
              height={graphHeight(activity.peers.length)}
              // The `c2` STYLE is right for "outside the network" and its label is
              // not: on this page every non-RFC1918 peer is a CDN, a package
              // mirror or a resolver until something says otherwise. Same
              // separation of style from claim as the `lateral` edge above.
              kindLabels={{ c2: 'external', internal: 'internal', host: 'this host' }}
            />
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
              <VolumeChart volume={activity.volume} range={range} />
            </div>
          </Panel>
          <Panel className={cn(loading && 'opacity-60')}>
            <PanelHeader icon={<Users size={15} />} title={`Users · ${range}`} />
            <div data-testid="host-users">
              <UsersCard users={activity.users} truncated={activity.users_truncated} range={range} />
            </div>
          </Panel>
        </div>
      </div>
    </>
  );
}
