// The four numbers that size a host, straight under the hero.
//
// They come from BOTH halves of the page and the strip does not hide that: the
// service count is the sweep's (cached, still answers with the grid down), the
// other three are read live off Security Onion. When the live read fails, those
// three show a dash. Never a zero — "0 users" and "we could not ask" are
// different statements, and only one of them is true when the grid is down.

import { Activity, Network, ShieldAlert, Users } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { ActivityState } from '../lib/hostActivity';
import type { HostActivity, HostActivityRange, VolumePoint } from '../lib/types';
// The card chrome and the dash live in Kpi.tsx, shared with the host list's
// strip: the two are one component at two altitudes, not two that look alike.
import { Kpi, UNKNOWN, UNKNOWN_TONE } from './Kpi';
import { sparklinePoints } from './QualityCard';

/**
 * Where the Alerts tile's number goes: the alerts console, narrowed to THIS
 * host.
 *
 * The narrowing rides `?q=`, an OQL clause `GET /alerts` passes through the
 * OQL trust boundary into the ES bool query (routes_alerts.list_alerts →
 * alerts_query.build_filter), and which the Alerts screen seeds from the URL
 * and shows as a dismissable chip. The clause spells OR-grouping the way every
 * OQL surface in this product does (`(source.ip:x OR destination.ip:x)` — the
 * chat agent's own pivot template).
 *
 * All three params are load-bearing, not decoration:
 *
 * - `range=7d` matches `host_activity.ALERT_WINDOW`, the fixed window the
 *   card's count is taken over, against a screen that defaults to 24h.
 * - `hide_acked=false` because the count is a raw grid count with no ack join
 *   at all, while Alerts hides acknowledged groups by default — drop it and a
 *   host whose only detections have been acked reads "3" and lands on an
 *   empty list.
 * - `q` matches the count's host scope — `_detection_scope` counts documents
 *   with this address on either side of the flow. One residue it cannot
 *   carry: the count ALSO matches host-shaped detections by the endpoint
 *   agent's nested address (Sigma process rules observe no flow), a path OQL
 *   deep links do not spell. On a host whose only detections are host-shaped,
 *   the count can honestly exceed the click-through's rows — the count is
 *   right and the list is the narrower read, not the other way round.
 */
export function alertsHref(ip: string): string {
  const clause = `(source.ip:${ip} OR destination.ip:${ip})`;
  return `/alerts?range=7d&hide_acked=false&q=${encodeURIComponent(clause)}`;
}

/** How many ports fit under the count before the rest becomes a number. Three
 *  is what a two-line sub holds at this width without wrapping a fourth onto a
 *  line of its own. */
const PORTS_SHOWN = 3;

/**
 * The Events card's in-card sparkline: the volume panel's shape, at card scale.
 *
 * Same normalisation as the panel's chart (`sparklinePoints` plots a fixed 0..1
 * domain, wrong for a count) — the series is scaled to its own peak, and since
 * a 40px chart has no room to print that scale, the tooltip carries it along
 * with the window. No axes, no ticks: this is the day's shape beside the total,
 * and the full-size chart three rows down owns the detail.
 *
 * Returns nothing over an empty or all-zero series: a flat line would claim a
 * measured quiet day where the sub-line already says "silent on the wire".
 */
function EventsSparkline({ volume, range }: { volume: VolumePoint[]; range: HostActivityRange }) {
  const W = 120;
  const H = 40;
  const peak = volume.reduce((max, point) => Math.max(max, point.events), 0);
  if (peak <= 0) return null;
  const points = sparklinePoints(volume.map((p) => p.events / peak), W, H, 3);
  return (
    <div
      data-testid="kpi-events-spark"
      title={`Connection volume over the last ${range}, scaled to its busiest bucket (peak ${peak.toLocaleString()}).`}
      className="mt-2"
    >
      <svg
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="none"
        className="h-[40px] w-full text-mono-green opacity-70"
        role="img"
        aria-label={`connection volume over the last ${range}`}
      >
        <polyline
          points={points}
          fill="none"
          stroke="currentColor"
          strokeWidth={1.5}
          vectorEffect="non-scaling-stroke"
        />
      </svg>
    </div>
  );
}

/** "gw, db-01 and 6 more" is a list; "8 peers" is the shape of a host's day.
 *  The list lives on the peer graph three rows down — this only has to say how
 *  wide the day was, and be honest when the wire number is a floor. */
function peerSub(peers: number, truncated: boolean): { text: string; title: string } {
  // The wire says when the server's ranked list was cut. "12 peers" over a
  // host that talked to four hundred is the same overclaim the peer-graph
  // footnote exists to avoid — and a full-but-uncut list of exactly the cap
  // is NOT a floor, which only the flag can know.
  if (truncated) {
    return {
      text: `${peers}+ peers`,
      title: `The grid returned its ${peers} busiest peers and cut the rest, so this is a floor rather than a total — the peer graph below says the same.`,
    };
  }
  return {
    text: `${peers} peer${peers === 1 ? '' : 's'}`,
    title: 'Distinct addresses this host exchanged traffic with in the window.',
  };
}

export interface HostKpisProps {
  /** The host the strip describes — the Alerts card deep-links on it. */
  ip: string;
  /** Ports this host offers, per the sweep, already spelled the house way
   *  ("tcp/8006") and in the payload's own busiest-first order. Null when the
   *  field never resolved — "we do not know" is not "none", and they send an
   *  operator to different places. */
  services: string[] | null;
  activity: HostActivity | null;
  /** The one discriminant, shared with the activity row so the strip and the row
   *  can never describe the live half differently. */
  state: ActivityState;
  range: HostActivityRange;
}

export function HostKpis({ ip, services, activity, state, range }: HostKpisProps) {
  // One sentence for the state the live numbers are in, reused by all three so
  // they cannot drift apart. `stale` keeps its numbers: an error WITH data behind
  // it is a failed refresh, not an absence, and blanking them would throw away a
  // read the analyst already had.
  const liveSub =
    state === 'down'
      ? 'the grid could not be read'
      : state === 'stale'
        ? 'could not refresh — last good read'
        : state === 'loading'
          ? 'reading the grid…'
          : null;

  const users = activity?.users ?? null;
  // Summed off the same histogram the sparkline plots, so the number and the
  // chart cannot disagree. No fixed bucket count is assumed: the server sets no
  // extended_bounds, so a quiet host simply has fewer points.
  const events = activity ? activity.volume.reduce((total, point) => total + point.events, 0) : null;
  const peerCount = activity ? activity.peers.length : null;
  const peers =
    peerCount == null || activity == null ? null : peerSub(peerCount, activity.peers_truncated);
  const rest = services ? services.length - PORTS_SHOWN : 0;

  return (
    <div className="mb-3 grid grid-cols-2 gap-3 lg:grid-cols-4">
      <Kpi
        testId="kpi-services"
        label="Services"
        value={services == null ? UNKNOWN : services.length.toLocaleString()}
        sub={
          services == null ? (
            'the sweep has no answer for this host'
          ) : services.length === 0 ? (
            'nothing answers inbound'
          ) : (
            // WHICH ports, not "ports": tcp/8006 answers "is this the Proxmox
            // box?" from the strip, which is the question the count alone
            // sends a reader down the page to answer.
            <span title="The ports this host answers on, in the order the dossier holds them — the sweep ranks by connection count, so the busiest lead.">
              {services.slice(0, PORTS_SHOWN).join(', ')}
              {rest > 0 ? ` +${rest} more` : ''}
            </span>
          )
        }
        icon={<Network size={16} />}
        tone={services == null ? UNKNOWN_TONE : 'text-accent'}
      />
      <Kpi
        testId="kpi-users"
        label={`Users · ${range}`}
        value={users == null ? UNKNOWN : users.length.toLocaleString()}
        sub={
          liveSub ??
          // WINDOW-scoped: a host that ships auth logs but was quiet answers null
          // here too, so this may not claim the machine ships no host logs.
          (users == null
            ? 'no host-log users in this window'
            : users.length === 0
              ? 'nobody authenticated'
              : 'accounts seen authenticating')
        }
        icon={<Users size={16} />}
        tone={users == null ? UNKNOWN_TONE : 'text-kind-sigma'}
      />
      <Kpi
        testId="kpi-events"
        label={`Events · ${range}`}
        value={events == null ? UNKNOWN : events.toLocaleString()}
        sub={
          liveSub ??
          // Both halves come off the same aggregation, so "no records" and "no
          // peers" arrive together — but the strip says one sentence, not "0
          // connection records · 0 peers".
          (peers == null || (events === 0 && peerCount === 0) ? (
            'silent on the wire'
          ) : (
            <>
              connection records · <span title={peers.title}>{peers.text}</span>
            </>
          ))
        }
        icon={<Activity size={16} />}
        tone={events == null ? UNKNOWN_TONE : 'text-mono-green'}
        // Only under a number the grid answered: a sparkline beside a dash
        // would draw a reading that does not exist.
        chart={
          activity != null ? <EventsSparkline volume={activity.volume} range={range} /> : undefined
        }
      />
      <Kpi
        testId="kpi-alerts"
        label="Alerts · 7d"
        // Fixed at 7 days whatever the activity window is — an alert count is
        // the one number a shorter window would make less useful, not more.
        value={activity == null ? UNKNOWN : activity.alerts_7d.toLocaleString()}
        sub={
          <>
            <div>
              {liveSub ??
                (activity && activity.alerts_7d > 0 ? 'detections naming this host' : 'nothing fired')}
            </div>
            {/* Only under a number the grid actually answered: a link beneath a
                dash invites a click on a figure that does not exist. */}
            {activity != null && (
              <Link
                to={alertsHref(ip)}
                title="Opens the alerts console narrowed to detections naming this host as a flow endpoint, over the same seven days with acknowledged detections included. Detections from this machine's own agent (no flow) are in the count but carry no address the filter can match."
                className="mt-0.5 inline-block underline decoration-dim/50 underline-offset-2 hover:text-text hover:decoration-dim"
              >
                alerts for this host · 7d
              </Link>
            )}
          </>
        }
        icon={<ShieldAlert size={16} />}
        tone={
          activity == null
            ? UNKNOWN_TONE
            : activity.alerts_7d > 0
              ? 'text-danger'
              : 'text-mono-green'
        }
      />
    </div>
  );
}
