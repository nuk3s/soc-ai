// The shared diagram, rendered. React Flow draws DOM nodes and SVG edges, and
// it renders under happy-dom when each node carries its size and its handles,
// so these tests run the real library. Only useReactFlow is wrapped, to see
// the Reset view and zoom calls.
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useParams } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { GraphView } from '../lib/graphLayout';
import { peerGraphView } from '../lib/peerGraph';
import type { HostPeer } from '../lib/types';

const fitView = vi.fn(() => Promise.resolve(true));
const zoomIn = vi.fn(() => Promise.resolve(true));
vi.mock('@xyflow/react', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@xyflow/react')>();
  return {
    ...actual,
    useReactFlow: () => ({ ...actual.useReactFlow(), fitView, zoomIn }),
  };
});

// Imported after the mock is registered (vi.mock is hoisted regardless).
import { Graph } from './Graph';

const HOST = '192.168.10.5';
const PEERS: HostPeer[] = [
  { ip: '192.168.10.1', hostname: 'gw', direction: 'both', ports: [53], events: 900, alerted: false },
  { ip: '198.51.100.7', hostname: null, direction: 'out', ports: [443], events: 40, alerted: true },
];

function EntityPage() {
  const { id } = useParams();
  return <div>entity page for {id}</div>;
}

function mount(view: GraphView, emptyText = 'Nothing to draw.') {
  return render(
    <MemoryRouter initialEntries={['/']}>
      <Routes>
        <Route path="/" element={<Graph view={view} ariaLabel="Peers" emptyText={emptyText} />} />
        <Route path="/entity/:id" element={<EntityPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

afterEach(() => vi.clearAllMocks());

describe('Graph: drawing a view', () => {
  it('draws every node with its whole label, and every edge', () => {
    mount(peerGraphView(HOST, PEERS));
    const nodes = screen.getAllByTestId('graph-node');
    expect(nodes.map((n) => n.getAttribute('data-node-id'))).toEqual([HOST, '192.168.10.1', '198.51.100.7']);
    expect(screen.getByText('gw')).toBeInTheDocument();
    expect(screen.getByText('900 events')).toBeInTheDocument();
    const edges = screen.getAllByTestId('graph-edge');
    expect(edges.length).toBe(2);
    expect(edges.filter((e) => e.getAttribute('data-threat') === 'true').map((e) => e.getAttribute('data-edge-id'))).toEqual([
      `${HOST}->198.51.100.7`,
    ]);
    // The owner forbids a cut label anywhere in the diagram.
    expect(screen.getByTestId('graph-canvas').textContent).not.toMatch(/…|\.\.\./);
  });

  it('draws two arrowheads on a two-way edge and one on a one-way edge', () => {
    mount(peerGraphView(HOST, PEERS));
    const [both, out] = screen.getAllByTestId('graph-edge');
    expect(both.getAttribute('data-arrows')).toBe('both');
    expect(out.getAttribute('data-arrows')).toBe('end');
    // The line, one head per end and the hover path. A threat edge also has
    // its glow path.
    expect(both.querySelectorAll('path').length).toBe(1 + 2 + 1);
    expect(out.querySelectorAll('path').length).toBe(1 + 1 + 1 + 1);
  });

  it('shows the legend', () => {
    mount(peerGraphView(HOST, PEERS));
    const legend = screen.getByTestId('graph-legend');
    expect(legend).toHaveTextContent('this host');
    expect(legend).toHaveTextContent('internal');
    expect(legend).toHaveTextContent('external');
    expect(legend).toHaveTextContent('an alert names this peer');
  });
});

describe('Graph: the click and the hover', () => {
  it('makes a node a link to its page, through the entity link logic', () => {
    mount(peerGraphView(HOST, PEERS));
    const node = screen.getAllByTestId('graph-node').find((n) => n.getAttribute('data-node-id') === '198.51.100.7')!;
    expect(node.tagName).toBe('A');
    expect(node.getAttribute('href')).toBe('/entity/198.51.100.7');
    fireEvent.click(node);
    expect(screen.getByText('entity page for 198.51.100.7')).toBeInTheDocument();
  });

  it('gives the host itself no link, because the page is already its page', () => {
    mount(peerGraphView(HOST, PEERS));
    const hub = screen.getAllByTestId('graph-node').find((n) => n.getAttribute('data-node-id') === HOST)!;
    expect(hub.tagName).not.toBe('A');
    expect(hub.getAttribute('href')).toBeNull();
  });

  it('shows the facts in a card on hover, and hides it on leave', () => {
    const { container } = mount(peerGraphView(HOST, PEERS));
    expect(screen.queryByTestId('graph-tooltip')).toBeNull();
    const wrapper = container.querySelector('.react-flow__node[data-id="198.51.100.7"]') as HTMLElement;
    fireEvent.mouseEnter(wrapper);
    const card = screen.getByTestId('graph-tooltip');
    expect(card).toHaveTextContent('198.51.100.7');
    expect(card).toHaveTextContent('An alert in this window names this peer.');
    expect(card).toHaveTextContent('Ports: 443.');
    fireEvent.mouseLeave(wrapper);
    expect(screen.queryByTestId('graph-tooltip')).toBeNull();
  });

  it('shows the same card on keyboard focus', () => {
    mount(peerGraphView(HOST, PEERS));
    const gw = screen.getAllByTestId('graph-node').find((n) => n.getAttribute('data-node-id') === '192.168.10.1')!;
    fireEvent.focus(gw);
    expect(screen.getByTestId('graph-tooltip')).toHaveTextContent('Traffic: in both directions.');
    fireEvent.blur(gw);
    expect(screen.queryByTestId('graph-tooltip')).toBeNull();
  });

  it('names each node for a screen reader with its facts', () => {
    mount(peerGraphView(HOST, PEERS));
    expect(screen.getByRole('link', { name: /198\.51\.100\.7.*An alert in this window names this peer/ })).toBeInTheDocument();
  });
});

describe('Graph: the controls', () => {
  it('fits the whole diagram again on Reset view, and zooms on the zoom button', () => {
    mount(peerGraphView(HOST, PEERS));
    fireEvent.click(screen.getByRole('button', { name: /reset view/i }));
    expect(fitView).toHaveBeenCalledWith(expect.objectContaining({ duration: expect.any(Number) }));
    fireEvent.click(screen.getByRole('button', { name: 'Zoom in' }));
    expect(zoomIn).toHaveBeenCalled();
  });

  it('lets the page scroll under the wheel', () => {
    const { container } = mount(peerGraphView(HOST, PEERS));
    expect(within(container).getByText(/Hold Ctrl or Cmd and scroll to zoom/)).toBeInTheDocument();
  });
});

describe('Graph: the empty state', () => {
  it('says in words that there is nothing to draw, and draws no blank box', () => {
    mount(peerGraphView(HOST, []), 'This host exchanged no traffic with another address in this window.');
    const empty = screen.getByTestId('graph-empty');
    expect(empty).toHaveAttribute('role', 'status');
    expect(empty.textContent?.trim().length).toBeGreaterThan(20);
    expect(empty).toHaveTextContent('exchanged no traffic');
    expect(screen.queryByTestId('graph-canvas')).toBeNull();
    expect(document.querySelector('.react-flow')).toBeNull();
  });

  it('negative control: a view with nodes draws the canvas and no empty words', () => {
    mount(peerGraphView(HOST, PEERS), 'This host exchanged no traffic with another address in this window.');
    expect(screen.queryByTestId('graph-empty')).toBeNull();
    expect(screen.getByTestId('graph-canvas')).toBeInTheDocument();
  });
});
