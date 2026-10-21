// ---------------------------------------------------------------------------
// The peer diagram on the host page, as data.
//
// The question the diagram answers: who does this machine talk to, how much,
// and which of those peers an alert names. So the host sits in the centre and
// its peers sit on a ring around it. The size of a peer and the width of its
// line both come from the connection events in the window. A peer that an
// alert names carries the red ring and the red line.
//
// The wire carries no verdict and no lead per peer. The diagram says only what
// the wire says: `alerted`. A peer opens its own page, and that page lists the
// verdicts and the leads that name it.
// ---------------------------------------------------------------------------

import { entityHref, guessEntityType } from './entityPath';
import type { GraphEdgeView, GraphNodeView, GraphView, LegendItem } from './graphLayout';
import { isPrivateIp } from './ip';
import type { HostPeer } from './types';

/** One colour per role. Red stays free for the threat. */
export const PEER_COLOR = {
  self: '#4b8bf5',
  internal: '#7ba893',
  external: '#a78bfa',
  threat: '#f04438',
  line: '#4a5869',
} as const;

export const PEER_SIZE = { self: 46, min: 18, max: 44 } as const;
export const PEER_LINE = { min: 1.5, max: 6.5 } as const;

const DIRECTION_WORDS: Record<HostPeer['direction'], string> = {
  out: 'Traffic: this host to the peer.',
  in: 'Traffic: the peer to this host.',
  both: 'Traffic: in both directions.',
};

const plural = (n: number, word: string) => `${n.toLocaleString()} ${word}${n === 1 ? '' : 's'}`;

/** A square-root scale, so a peer with four times the traffic is twice as wide. */
export function sqrtScale(value: number, max: number, lo: number, hi: number): number {
  if (max <= 0 || value <= 0) return lo;
  return Math.round((lo + (hi - lo) * Math.sqrt(Math.min(value, max) / max)) * 10) / 10;
}

export function peerGraphView(ip: string, peers: HostPeer[]): GraphView {
  // The subject is never its own peer. The server filters this too, but a row
  // for the host itself would draw a second node with the same id.
  const others = peers.filter((p) => p.ip !== ip);
  if (others.length === 0) return { nodes: [], edges: [], legend: [], layout: { mode: 'force' } };

  const maxEvents = others.reduce((m, p) => Math.max(m, p.events), 0);
  const total = others.reduce((sum, p) => sum + p.events, 0);

  const nodes: GraphNodeView[] = [
    {
      id: ip,
      lines: [
        { text: ip, tone: 'primary' },
        { text: 'this host', tone: 'secondary' },
      ],
      shape: 'circle',
      size: PEER_SIZE.self,
      color: PEER_COLOR.self,
      subject: true,
      tooltip: [ip, 'This host.', `${plural(others.length, 'peer')} in this window.`, `${plural(total, 'connection event')} with them.`],
    },
  ];
  const edges: GraphEdgeView[] = [];

  for (const peer of others) {
    const internal = isPrivateIp(peer.ip);
    const name = peer.hostname ?? peer.ip;
    const lines: GraphNodeView['lines'] = [{ text: name, tone: 'primary' }];
    if (peer.hostname) lines.push({ text: peer.ip, tone: 'secondary' });
    lines.push({ text: plural(peer.events, 'event'), tone: 'secondary' });
    if (peer.alerted) lines.push({ text: 'alerted', tone: 'threat' });

    const facts = [
      DIRECTION_WORDS[peer.direction],
      `${plural(peer.events, 'connection event')} in this window.`,
      peer.ports.length ? `Ports: ${peer.ports.join(', ')}.` : 'No port on record.',
    ];
    if (peer.alerted) facts.push('An alert in this window names this peer.');

    nodes.push({
      id: peer.ip,
      lines,
      shape: 'circle',
      size: sqrtScale(peer.events, maxEvents, PEER_SIZE.min, PEER_SIZE.max),
      color: internal ? PEER_COLOR.internal : PEER_COLOR.external,
      threat: peer.alerted,
      href: entityHref(peer.ip, guessEntityType(peer.ip)),
      tooltip: [
        peer.hostname ? `${peer.hostname} · ${peer.ip}` : peer.ip,
        internal ? 'Internal address.' : 'External address.',
        ...facts,
        'Select it to open its page.',
      ],
    });

    // One edge per peer. The arrowheads say the direction, so a peer that
    // talks both ways gets one line with two heads.
    edges.push({
      id: `${ip}->${peer.ip}`,
      source: ip,
      target: peer.ip,
      width: sqrtScale(peer.events, maxEvents, PEER_LINE.min, PEER_LINE.max),
      color: peer.alerted ? PEER_COLOR.threat : PEER_COLOR.line,
      threat: peer.alerted,
      arrows: peer.direction === 'both' ? 'both' : peer.direction === 'out' ? 'end' : 'start',
      tooltip: [`${ip} and ${name}`, ...facts],
    });
  }

  const legend: LegendItem[] = [{ kind: 'node', label: 'this host', color: PEER_COLOR.self, shape: 'circle', ring: 'subject' }];
  if (others.some((p) => isPrivateIp(p.ip))) {
    legend.push({ kind: 'node', label: 'internal', color: PEER_COLOR.internal, shape: 'circle' });
  }
  if (others.some((p) => !isPrivateIp(p.ip))) {
    legend.push({ kind: 'node', label: 'external', color: PEER_COLOR.external, shape: 'circle' });
  }
  if (others.some((p) => p.alerted)) {
    legend.push({ kind: 'line', label: 'an alert names this peer', color: PEER_COLOR.threat, width: 2.5 });
  }
  legend.push({ kind: 'note', label: 'Size and line width: connection events' });
  legend.push({ kind: 'note', label: 'Arrow: direction of traffic' });

  return { nodes, edges, legend, layout: { mode: 'ring', center: ip } };
}
