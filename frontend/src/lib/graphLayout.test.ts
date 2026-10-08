// The layout carries the owner's rule: labels never overlap and never cut.
// These tests hold the rule on the two shapes the console draws: a ring of
// peers around one host, and a free graph of findings and hosts up to the
// 200-node end of the range.
import { describe, expect, it } from 'vitest';
import {
  anyOverlap,
  layoutGraph,
  nodeBox,
  removeOverlaps,
  wrapLabel,
  type GraphEdgeView,
  type GraphNodeView,
  type GraphView,
} from './graphLayout';

function node(id: string, o: Partial<GraphNodeView> = {}): GraphNodeView {
  return {
    id,
    lines: [{ text: id }],
    shape: 'circle',
    size: 24,
    color: '#4b8bf5',
    tooltip: [id],
    ...o,
  };
}

function edge(source: string, target: string, o: Partial<GraphEdgeView> = {}): GraphEdgeView {
  return { id: `${source}->${target}`, source, target, width: 2, color: '#4a5869', arrows: 'none', tooltip: [], ...o };
}

/** The placed boxes, by centre, for the overlap check. */
function centres(view: GraphView) {
  const layout = layoutGraph(view);
  return {
    layout,
    boxes: Object.values(layout.nodes).map((p) => ({ x: p.x + p.w / 2, y: p.y + p.h / 2, w: p.w, h: p.h })),
  };
}

describe('wrapLabel', () => {
  it('keeps every character and cuts nothing', () => {
    const title = 'Kerberos replication request from a host that is not a domain controller';
    const lines = wrapLabel(title, 26);
    expect(lines.length).toBeGreaterThan(1);
    expect(lines.every((l) => l.length <= 26)).toBe(true);
    expect(lines.join(' ')).toBe(title);
    expect(lines.join('')).not.toMatch(/…|\.\.\./);
  });

  it('breaks a long name after a dot, and keeps it whole', () => {
    const name = 'build-runner-07.eu-west.corp.example.internal';
    const lines = wrapLabel(name, 26);
    expect(lines.join('')).toBe(name);
    expect(lines[0].endsWith('.')).toBe(true);
  });

  it('breaks a long token with no separator at the limit', () => {
    const token = 'a'.repeat(60);
    expect(wrapLabel(token, 26)).toEqual(['a'.repeat(26), 'a'.repeat(26), 'a'.repeat(8)]);
  });
});

describe('nodeBox', () => {
  it('grows with the longest line and with the number of lines', () => {
    const short = nodeBox({ size: 24, lines: [{ text: 'gw' }] });
    const long = nodeBox({ size: 24, lines: [{ text: 'a-much-longer-host-name' }, { text: '1,204 events', tone: 'secondary' }] });
    expect(long.w).toBeGreaterThan(short.w);
    expect(long.h).toBeGreaterThan(short.h);
    // A label wider than the shape sets the width.
    expect(long.w).toBeGreaterThan(24 + 12);
  });
});

describe('removeOverlaps', () => {
  it('separates boxes that start on the same point', () => {
    const boxes = Array.from({ length: 6 }, () => ({ x: 0, y: 0, w: 80, h: 40 }));
    expect(removeOverlaps(boxes)).toBe(true);
    expect(anyOverlap(boxes, 9)).toBe(false);
  });

  it('never moves a pinned box', () => {
    const boxes = [
      { x: 0, y: 0, w: 80, h: 40, pinned: true },
      { x: 5, y: 5, w: 80, h: 40 },
    ];
    removeOverlaps(boxes);
    expect(boxes[0]).toMatchObject({ x: 0, y: 0 });
    expect(anyOverlap(boxes)).toBe(false);
  });

  it('negative control: the check sees an overlap that is there', () => {
    expect(anyOverlap([{ x: 0, y: 0, w: 80, h: 40 }, { x: 40, y: 10, w: 80, h: 40 }])).toBe(true);
  });
});

describe('layoutGraph: the ring', () => {
  const peers = Array.from({ length: 12 }, (_, i) =>
    node(`10.20.${i}.${i + 40}`, {
      lines: [
        { text: `workstation-${i}.branch-office.example.internal` },
        { text: `10.20.${i}.${i + 40}`, tone: 'secondary' },
        { text: `${(i + 1) * 97} events`, tone: 'secondary' },
      ],
      size: 18 + i * 2,
    }),
  );
  const view: GraphView = {
    nodes: [node('192.0.2.10', { size: 46, subject: true }), ...peers],
    edges: peers.map((p) => edge('192.0.2.10', p.id, { arrows: 'both' })),
    legend: [],
    layout: { mode: 'ring', center: '192.0.2.10' },
  };

  it('places no box on top of another, labels included', () => {
    const { boxes } = centres(view);
    expect(boxes.length).toBe(13);
    expect(anyOverlap(boxes)).toBe(false);
  });

  it('keeps the host in the middle of its peers', () => {
    const { layout } = centres(view);
    const hub = layout.nodes['192.0.2.10'];
    const xs = peers.map((p) => layout.nodes[p.id].cx);
    const ys = peers.map((p) => layout.nodes[p.id].cy);
    expect(hub.cx).toBeGreaterThan(Math.min(...xs));
    expect(hub.cx).toBeLessThan(Math.max(...xs));
    expect(hub.cy).toBeGreaterThan(Math.min(...ys));
    expect(hub.cy).toBeLessThan(Math.max(...ys));
  });

  it('gives a two-way edge an arrowhead at each end', () => {
    const { layout } = centres(view);
    const e = layout.edges[view.edges[0].id];
    expect(e.arrowEnd).toBeDefined();
    expect(e.arrowStart).toBeDefined();
  });

  it('places one peer beside the host', () => {
    const one: GraphView = { ...view, nodes: view.nodes.slice(0, 2), edges: view.edges.slice(0, 1) };
    const { layout, boxes } = centres(one);
    expect(anyOverlap(boxes)).toBe(false);
    expect(layout.nodes[peers[0].id].cx).toBeGreaterThan(layout.nodes['192.0.2.10'].cx);
  });
});

describe('layoutGraph: the force layout', () => {
  /** 40 findings and 160 hosts: the 200-node end of the range. */
  function big(): GraphView {
    const nodes: GraphNodeView[] = [];
    const edges: GraphEdgeView[] = [];
    for (let f = 0; f < 40; f++) {
      nodes.push(
        node(`finding:${f}`, {
          shape: 'square',
          size: 30,
          glyph: `F${f + 1}`,
          lines: wrapLabel(`Finding number ${f + 1} names several hosts on the network`, 26).map((text) => ({ text })),
        }),
      );
    }
    for (let h = 0; h < 160; h++) nodes.push(node(`host:10.0.${h >> 4}.${h & 15}`, { size: 18 + (h % 5) * 4 }));
    for (let f = 0; f < 40; f++) {
      for (let k = 0; k < 4; k++) {
        const h = (f * 4 + k) % 160;
        edges.push(edge(`finding:${f}`, `host:10.0.${h >> 4}.${h & 15}`));
      }
    }
    return { nodes, edges, legend: [], layout: { mode: 'force' } };
  }

  it('places 200 nodes with no overlap', () => {
    const { boxes } = centres(big());
    expect(boxes.length).toBe(200);
    expect(anyOverlap(boxes)).toBe(false);
  });

  it('gives the same picture twice', () => {
    const a = layoutGraph(big());
    const b = layoutGraph(big());
    expect(a).toEqual(b);
  });

  it('gives an edge label its own box, clear of every node', () => {
    const view: GraphView = {
      nodes: [node('a', { seed: { x: 10, y: 50 } }), node('b', { seed: { x: 90, y: 50 } }), node('c', { seed: { x: 50, y: 50 } })],
      edges: [edge('a', 'b', { label: 'SMB lateral movement', arrows: 'end' })],
      legend: [],
      layout: { mode: 'force' },
    };
    const layout = layoutGraph(view);
    const label = layout.edges['a->b'].label!;
    expect(label.text).toBe('SMB lateral movement');
    const boxes = [
      ...Object.values(layout.nodes).map((p) => ({ x: p.x + p.w / 2, y: p.y + p.h / 2, w: p.w, h: p.h })),
      { x: label.x, y: label.y, w: label.w, h: label.h },
    ];
    expect(anyOverlap(boxes)).toBe(false);
    // The curve passes through the label.
    expect(layout.edges['a->b'].mid).toEqual({ x: label.x, y: label.y });
  });

  it('bows two edges between the same pair apart', () => {
    const view: GraphView = {
      nodes: [node('a'), node('b')],
      edges: [edge('a', 'b', { id: 'ab', arrows: 'end' }), edge('b', 'a', { id: 'ba', arrows: 'end' })],
      legend: [],
      layout: { mode: 'force' },
    };
    const layout = layoutGraph(view);
    expect(layout.edges.ab.path).toContain('Q');
    expect(layout.edges.ba.path).toContain('Q');
    expect(layout.edges.ab.mid).not.toEqual(layout.edges.ba.mid);
  });

  it('drops an edge to a node the view does not hold', () => {
    const layout = layoutGraph({
      nodes: [node('a')],
      edges: [edge('a', 'ghost')],
      layout: { mode: 'force' },
    });
    expect(Object.keys(layout.edges)).toEqual([]);
  });
});
