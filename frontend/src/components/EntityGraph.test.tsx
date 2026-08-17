// EntityGraph is shared by three screens that mean different things by the same
// node. Its built-in vocabulary was written for the investigation blast radius,
// where an external node genuinely IS a C2 candidate — but a host page draws the
// package mirror and the DNS resolver with the same `c2` style, and the legend
// then tells an analyst that a CDN is command-and-control.
//
// So the two things pinned here are the seams that let a caller name what ITS
// nodes mean, and the rule that the danger wash is a statement about the graph's
// contents rather than decoration on every graph.
import { render } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
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

/** The rendered legend row, as text. */
const legendText = (container: HTMLElement): string =>
  Array.from(container.querySelectorAll('span'))
    .map((s) => s.textContent)
    .join(' | ');

describe('EntityGraph — naming what a node means', () => {
  it('legends an external node as a C2 candidate by default', () => {
    // The investigation blast radius depends on this wording; it must not change
    // underneath the screens that want it.
    const { container } = mount(PEERS);
    expect(legendText(container)).toContain('C2 / external');
  });

  it('lets a caller rename a kind for its own graph', () => {
    const { container } = mount(PEERS, [], { kindLabels: { c2: 'external' } });
    const text = legendText(container);
    expect(text).toContain('external');
    expect(text).not.toContain('C2');
  });

  it('carries the caller name into the node tooltip too', () => {
    // The tooltip repeats the legend label, so renaming one and not the other
    // would just move the false claim somewhere less visible.
    const { container } = mount(PEERS, [], { kindLabels: { c2: 'external' } });
    const titles = Array.from(container.querySelectorAll('title')).map((t) => t.textContent);
    expect(titles.some((t) => t?.includes('198.51.100.7 — external'))).toBe(true);
    expect(titles.some((t) => t?.includes('C2'))).toBe(false);
  });
});

describe('EntityGraph — the danger wash says something', () => {
  /** The gradient layer sits on the element wrapping the svg. */
  const wash = (container: HTMLElement): string =>
    (container.querySelector('svg')?.parentElement as HTMLElement | null)?.style.background ?? '';

  it('does not tint a graph that contains nothing dangerous', () => {
    // Every host peer graph carried a faint red radial wash regardless of what
    // was on it — colour asserting danger that no node or edge represents.
    const { container } = mount(PEERS);
    expect(wash(container)).toBe('');
  });

  it('tints a graph that holds a compromised node', () => {
    const { container } = mount([
      { id: 'a', x: 20, y: 50, kind: 'compromised', label: 'a' },
      ...PEERS,
    ]);
    expect(wash(container)).toContain('gradient');
  });

  it('tints a graph that holds an intel-flagged node', () => {
    const { container } = mount([
      { id: '198.51.100.7', x: 76, y: 50, kind: 'c2', label: 'bad', flagged: true },
    ]);
    expect(wash(container)).toContain('gradient');
  });

  it('tints a graph whose edges carry the danger style', () => {
    const { container } = mount(PEERS, [
      { from: '192.168.10.5', to: '198.51.100.7', kind: 'lateral', label: 'alerted' },
    ]);
    expect(wash(container)).toContain('gradient');
  });
});
