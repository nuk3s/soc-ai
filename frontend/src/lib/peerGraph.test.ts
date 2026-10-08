// The peer diagram answers three questions: who this machine talks to, how
// much, and which peers an alert names. Each test pins one of the answers in
// the shaped data, before anything draws.
import { describe, expect, it } from 'vitest';
import { PEER_COLOR, PEER_LINE, PEER_SIZE, peerGraphView, sqrtScale } from './peerGraph';
import type { HostPeer } from './types';

const HOST = '192.168.10.5';

function peer(o: Partial<HostPeer> & { ip: string }): HostPeer {
  return { hostname: null, direction: 'out', ports: [443], events: 10, alerted: false, ...o };
}

const PEERS: HostPeer[] = [
  peer({ ip: '192.168.10.1', hostname: 'gw', direction: 'both', ports: [53, 443], events: 1200 }),
  peer({ ip: '198.51.100.7', direction: 'out', ports: [443], events: 300, alerted: true }),
  peer({ ip: '203.0.113.9', hostname: 'mirror-for-the-package-updates.example.org', direction: 'in', ports: [], events: 0 }),
];

describe('peerGraphView: who this machine talks to', () => {
  it('draws the host and one node per peer', () => {
    const view = peerGraphView(HOST, PEERS);
    expect(view.nodes.map((n) => n.id)).toEqual([HOST, '192.168.10.1', '198.51.100.7', '203.0.113.9']);
    expect(view.layout).toEqual({ mode: 'ring', center: HOST });
    const hub = view.nodes[0];
    expect(hub.subject).toBe(true);
    expect(hub.size).toBe(PEER_SIZE.self);
    expect(hub.color).toBe(PEER_COLOR.self);
    expect(hub.href).toBeUndefined();
  });

  it('colours a peer by its role', () => {
    const view = peerGraphView(HOST, PEERS);
    const byId = Object.fromEntries(view.nodes.map((n) => [n.id, n]));
    expect(byId['192.168.10.1'].color).toBe(PEER_COLOR.internal);
    expect(byId['198.51.100.7'].color).toBe(PEER_COLOR.external);
    expect(byId['203.0.113.9'].color).toBe(PEER_COLOR.external);
  });

  it('names a peer by its host name, and keeps a long name whole', () => {
    const view = peerGraphView(HOST, PEERS);
    const mirror = view.nodes.find((n) => n.id === '203.0.113.9')!;
    expect(mirror.lines[0].text).toBe('mirror-for-the-package-updates.example.org');
    expect(mirror.lines[1].text).toBe('203.0.113.9');
    for (const n of view.nodes) {
      for (const l of n.lines) expect(l.text).not.toMatch(/…|\.\.\./);
    }
  });

  it('opens the page of the peer through the entity link logic', () => {
    const view = peerGraphView(HOST, PEERS);
    expect(view.nodes.find((n) => n.id === '198.51.100.7')!.href).toBe('/entity/198.51.100.7');
  });
});

describe('peerGraphView: how much', () => {
  it('sizes a node and widens a line by the connection events', () => {
    const view = peerGraphView(HOST, PEERS);
    const size = Object.fromEntries(view.nodes.map((n) => [n.id, n.size]));
    expect(size['192.168.10.1']).toBe(PEER_SIZE.max);
    expect(size['203.0.113.9']).toBe(PEER_SIZE.min);
    expect(size['198.51.100.7']).toBeGreaterThan(PEER_SIZE.min);
    expect(size['198.51.100.7']).toBeLessThan(PEER_SIZE.max);

    const width = Object.fromEntries(view.edges.map((e) => [e.target, e.width]));
    expect(width['192.168.10.1']).toBe(PEER_LINE.max);
    expect(width['203.0.113.9']).toBe(PEER_LINE.min);
  });

  it('scales by the square root, so four times the traffic is twice the growth', () => {
    expect(sqrtScale(25, 100, 0, 10)).toBe(5);
    expect(sqrtScale(100, 100, 0, 10)).toBe(10);
    expect(sqrtScale(0, 100, 4, 10)).toBe(4);
    expect(sqrtScale(5, 0, 4, 10)).toBe(4);
  });

  it('draws one edge per peer, with the arrowheads on the direction of traffic', () => {
    const view = peerGraphView(HOST, PEERS);
    expect(view.edges.length).toBe(3);
    const arrows = Object.fromEntries(view.edges.map((e) => [e.target, e.arrows]));
    expect(arrows).toEqual({ '192.168.10.1': 'both', '198.51.100.7': 'end', '203.0.113.9': 'start' });
    expect(view.edges.every((e) => e.source === HOST)).toBe(true);
  });

  it('puts the ports and the direction in the hover card', () => {
    const gw = peerGraphView(HOST, PEERS).nodes.find((n) => n.id === '192.168.10.1')!;
    expect(gw.tooltip).toContain('Ports: 53, 443.');
    expect(gw.tooltip).toContain('Traffic: in both directions.');
    expect(gw.tooltip).toContain('1,200 connection events in this window.');
  });
});

describe('peerGraphView: which peers an alert names', () => {
  it('marks the alerted peer and its line in red', () => {
    const view = peerGraphView(HOST, PEERS);
    const red = view.nodes.filter((n) => n.threat);
    expect(red.map((n) => n.id)).toEqual(['198.51.100.7']);
    expect(red[0].lines.some((l) => l.tone === 'threat' && l.text === 'alerted')).toBe(true);
    const redEdges = view.edges.filter((e) => e.threat);
    expect(redEdges.map((e) => e.target)).toEqual(['198.51.100.7']);
    expect(redEdges[0].color).toBe(PEER_COLOR.threat);
    expect(view.legend.some((l) => l.label === 'an alert names this peer')).toBe(true);
  });

  it('negative control: no alerted peer, no red anywhere', () => {
    const quiet = PEERS.map((p) => ({ ...p, alerted: false }));
    const view = peerGraphView(HOST, quiet);
    expect(view.nodes.some((n) => n.threat)).toBe(false);
    expect(view.edges.some((e) => e.threat || e.color === PEER_COLOR.threat)).toBe(false);
    expect(view.legend.some((l) => l.label === 'an alert names this peer')).toBe(false);
  });
});

describe('peerGraphView: nothing to draw', () => {
  it('draws nothing for a host with no peers, so the panel says so in words', () => {
    const view = peerGraphView(HOST, []);
    expect(view.nodes).toEqual([]);
    expect(view.edges).toEqual([]);
  });

  it('never draws the host as its own peer', () => {
    const view = peerGraphView(HOST, [peer({ ip: HOST, events: 50 }), ...PEERS]);
    expect(view.nodes.filter((n) => n.id === HOST).length).toBe(1);
    expect(view.edges.some((e) => e.target === HOST)).toBe(false);
  });

  it('a self row alone is no peer at all', () => {
    expect(peerGraphView(HOST, [peer({ ip: HOST })]).nodes).toEqual([]);
  });
});
