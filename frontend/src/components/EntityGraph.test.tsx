// EntityGraph is the investigation blast radius. Its stock vocabulary was
// written for the investigation, where an external node genuinely IS a C2
// candidate, and a caller that draws a CDN with the same style renames it.
//
// So the things pinned here are the seam that lets a caller name what ITS
// nodes mean, the rule that the danger wash is a statement about the graph's
// contents rather than decoration on every graph, and the shaping of the
// record's nodes and edges into the shared view.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { EDGE_KIND_STYLE, entityGraphView, graphHoldsDanger, KIND_STYLE } from '../lib/entityGraphView';
import type { GraphEdge, GraphNode } from '../lib/types';
import { EntityGraph } from './EntityGraph';

const mount = (nodes: GraphNode[], edges: GraphEdge[] = [], props = {}) =>
  render(
    <MemoryRouter>
      <EntityGraph nodes={nodes} edges={edges} {...props} />
    </MemoryRouter>,
  );

const PEERS: GraphNode[] = [
  { id: '192.168.10.5', x: 8, y: 50, kind: 'host', label: 'this host' },
  { id: '198.51.100.7', x: 76, y: 50, kind: 'c2', label: 'mirror' },
];

// EntityGraph loads Graph on demand, so every read waits for it.

/** The rendered legend row, as text. */
const legendText = async (): Promise<string> => (await screen.findByTestId('graph-legend')).textContent ?? '';

/** Every node's accessible name: the facts the hover card shows. */
const nodeNames = async (): Promise<string[]> =>
  (await screen.findAllByTestId('graph-node')).map((n) => n.getAttribute('aria-label') ?? '');

describe('EntityGraph: naming what a node means', () => {
  it('legends an external node as a C2 candidate by default', async () => {
    // The investigation blast radius depends on this wording; it must not change
    // underneath the screens that want it.
    mount(PEERS);
    expect(await legendText()).toContain('C2 / external');
  });

  it('lets a caller rename a kind for its own graph', async () => {
    mount(PEERS, [], { kindLabels: { c2: 'external' } });
    const text = await legendText();
    expect(text).toContain('external');
    expect(text).not.toContain('C2');
  });

  it('carries the caller name into the hover card too', async () => {
    // The card repeats the legend label, so renaming one and not the other
    // would just move the false claim somewhere less visible.
    mount(PEERS, [], { kindLabels: { c2: 'external' } });
    const names = await nodeNames();
    expect(names.some((t) => t.includes('198.51.100.7 · external'))).toBe(true);
    expect(names.some((t) => t.includes('C2'))).toBe(false);
  });

  it('shows a long label whole', async () => {
    const long = 'workstation-with-a-very-long-name.branch.example.internal';
    mount([{ id: '192.168.10.9', x: 50, y: 50, kind: 'internal', label: long }]);
    expect(await screen.findByText(long)).toBeInTheDocument();
  });
});

describe('EntityGraph: the danger wash says something', () => {
  /** The gradient layer sits on the diagram canvas. */
  const wash = async (): Promise<string> => ((await screen.findByTestId('graph-canvas')) as HTMLElement).style.background ?? '';

  it('does not tint a graph that contains nothing dangerous', async () => {
    // Every host peer graph carried a faint red radial wash regardless of what
    // was on it: colour asserting danger that no node or edge represents.
    mount(PEERS);
    expect(await wash()).toBe('');
  });

  it('tints a graph that holds a compromised node', async () => {
    mount([{ id: 'a', x: 20, y: 50, kind: 'compromised', label: 'a' }, ...PEERS]);
    expect(await wash()).toContain('gradient');
  });

  it('tints a graph that holds an intel-flagged node', async () => {
    mount([{ id: '198.51.100.7', x: 76, y: 50, kind: 'c2', label: 'bad', flagged: true }]);
    expect(await wash()).toContain('gradient');
  });

  it('tints a graph whose edges carry the danger style', async () => {
    mount(PEERS, [{ from: '192.168.10.5', to: '198.51.100.7', kind: 'lateral', label: 'alerted' }]);
    expect(await wash()).toContain('gradient');
  });

  it('negative control: the danger test reads the edges and the nodes', () => {
    expect(graphHoldsDanger(PEERS, [{ from: '192.168.10.5', to: '198.51.100.7', kind: 'flow' }])).toBe(false);
    expect(graphHoldsDanger(PEERS, [{ from: '192.168.10.5', to: '198.51.100.7', kind: 'lateral' }])).toBe(true);
  });
});

describe('entityGraphView: the record as a view', () => {
  const NODES: GraphNode[] = [
    { id: '192.168.10.5', x: 10, y: 50, kind: 'compromised', label: 'fin-ws-01', sub: 'source' },
    { id: '203.0.113.9', x: 90, y: 20, kind: 'c2', label: '203.0.113.9', flagged: true, flagSources: ['blocklist'] },
    { id: '192.168.10.2', x: 90, y: 80, kind: 'internal', label: 'dc-01' },
  ];
  const EDGES: GraphEdge[] = [
    { from: '192.168.10.5', to: '203.0.113.9', kind: 'beacon', label: ':8080 TCP' },
    { from: '192.168.10.5', to: '192.168.10.2', kind: 'lateral' },
    { from: '192.168.10.5', to: 'not-a-node', kind: 'flow' },
  ];

  it('styles a node by its kind and seeds the layout from the record', () => {
    const view = entityGraphView(NODES, EDGES, { highlight: '192.168.10.5' });
    const [src, c2, dc] = view.nodes;
    expect(src.color).toBe(KIND_STYLE.compromised.color);
    expect(src.threat).toBe(true);
    expect(src.subject).toBe(true);
    expect(src.seed).toEqual({ x: 10, y: 50 });
    expect(src.lines.map((l) => l.text)).toEqual(['fin-ws-01', 'source']);
    expect(c2.badge).toBe('!');
    expect(c2.tooltip).toContain('Flagged by: blocklist.');
    expect(dc.shape).toBe('square');
    expect(view.layout).toEqual({ mode: 'force' });
  });

  it('pivots a node on its id, never on its label', () => {
    const view = entityGraphView(NODES, EDGES);
    expect(view.nodes[0].href).toBe('/entity/192.168.10.5');
    expect(view.nodes.some((n) => n.href?.includes('fin-ws-01'))).toBe(false);
  });

  it('styles an edge by its kind, keeps its label, and drops an edge to no node', () => {
    const view = entityGraphView(NODES, EDGES);
    expect(view.edges.length).toBe(2);
    const [beacon, lateral] = view.edges;
    expect(beacon.color).toBe(EDGE_KIND_STYLE.beacon.color);
    expect(beacon.label).toBe(':8080 TCP');
    expect(beacon.arrows).toBe('end');
    expect(lateral.threat).toBe(true);
    expect(lateral.color).toBe(EDGE_KIND_STYLE.lateral.color);
  });

  it('draws one node for a repeated id', () => {
    const view = entityGraphView([...NODES, NODES[0]], []);
    expect(view.nodes.length).toBe(3);
  });

  it('draws nothing for an empty record, so the panel says so in words', async () => {
    mount([]);
    expect(await screen.findByTestId('graph-empty')).toHaveTextContent('names no related entity');
  });
});
