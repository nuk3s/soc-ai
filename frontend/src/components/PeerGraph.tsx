// The peer diagram on the host page: who this machine talks to, how much, and
// which peers an alert names. lib/peerGraph.ts shapes the data and
// components/Graph.tsx draws it. Graph.tsx states the library choice.
//
// The host page shows this diagram at once, so it imports Graph directly. The
// investigation graph in EntityGraph.tsx loads Graph on demand instead,
// because the Alerts page carries the investigation drawer.

import { useMemo } from 'react';
import { peerGraphView } from '../lib/peerGraph';
import type { HostPeer } from '../lib/types';
import { Graph } from './Graph';

export function PeerGraph({ ip, peers }: { ip: string; peers: HostPeer[] }) {
  const view = useMemo(() => peerGraphView(ip, peers), [ip, peers]);
  return (
    <Graph
      view={view}
      ariaLabel={`Peers of ${ip}`}
      emptyText="This host exchanged no traffic with another address in this window. There is nothing to draw."
    />
  );
}
