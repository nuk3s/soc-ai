// ---------------------------------------------------------------------------
// The blast-radius diagram on an investigation, as data.
//
// The record sends nodes with a kind and a start position, and edges with a
// kind and a short label. The kind is a style. The caller may rename a kind
// for its own graph, because the stock words were written for an
// investigation, where an external node is a command-and-control candidate.
//
// The record positions seed the force layout, so the composition the server
// chose stays, and the layout moves a node only as far as its label needs.
// ---------------------------------------------------------------------------

import { entityHref, guessEntityType } from './entityPath';
import type { GraphEdgeView, GraphNodeView, GraphView, LegendItem } from './graphLayout';
import type { EdgeKind, EntityKind, GraphEdge, GraphNode } from './types';

interface KindStyle {
  color: string;
  size: number;
  shape: 'circle' | 'square';
  label: string;
}

export const KIND_STYLE: Record<EntityKind, KindStyle> = {
  compromised: { color: '#f04438', size: 40, shape: 'circle', label: 'compromised' },
  c2: { color: '#e0a83a', size: 32, shape: 'circle', label: 'C2 / external' },
  internal: { color: '#7ba893', size: 32, shape: 'square', label: 'internal host' },
  host: { color: '#4b8bf5', size: 28, shape: 'circle', label: 'host' },
};

interface EdgeStyle {
  color: string;
  width: number;
  dash: boolean;
  label: string;
}

export const EDGE_KIND_STYLE: Record<EdgeKind, EdgeStyle> = {
  beacon: { color: '#e0a83a', width: 2, dash: true, label: 'beacon' },
  lateral: { color: '#f04438', width: 3, dash: true, label: 'lateral movement' },
  flow: { color: '#4a5869', width: 1.75, dash: false, label: 'flow' },
  enrich: { color: '#4b8bf5', width: 1.8, dash: true, label: 'enrichment' },
};

export function entityGraphView(
  nodes: GraphNode[],
  edges: GraphEdge[],
  options: { kindLabels?: Partial<Record<EntityKind, string>>; highlight?: string } = {},
): GraphView {
  const kindLabel = (k: EntityKind): string => options.kindLabels?.[k] ?? KIND_STYLE[k]?.label ?? k;
  const style = (k: EntityKind) => KIND_STYLE[k] ?? KIND_STYLE.host;

  // One node per id. The record is the authority, but a repeated id would draw
  // two boxes that the edges cannot tell apart.
  const seen = new Set<string>();
  const unique = nodes.filter((n) => (seen.has(n.id) ? false : (seen.add(n.id), true)));
  const ids = new Set(unique.map((n) => n.id));

  const viewNodes: GraphNodeView[] = unique.map((n) => {
    const s = style(n.kind);
    const lines: GraphNodeView['lines'] = [{ text: n.label || n.id, tone: 'primary' }];
    if (n.sub) lines.push({ text: n.sub, tone: 'secondary' });
    const tooltip = [`${n.id} · ${kindLabel(n.kind)}`];
    if (n.label && n.label !== n.id) tooltip.push(n.label);
    if (n.sub) tooltip.push(n.sub);
    if (n.flagged) tooltip.push(`Flagged by: ${(n.flagSources ?? []).join(', ') || 'threat intel'}.`);
    tooltip.push('Click to open its page.');
    return {
      id: n.id,
      lines,
      shape: s.shape,
      size: s.size,
      color: s.color,
      threat: n.kind === 'compromised' || Boolean(n.flagged),
      subject: options.highlight !== undefined && n.id === options.highlight,
      badge: n.flagged ? '!' : undefined,
      href: entityHref(n.id, guessEntityType(n.id)),
      tooltip,
      seed: { x: n.x, y: n.y },
    };
  });

  const viewEdges: GraphEdgeView[] = edges
    .filter((e) => ids.has(e.from) && ids.has(e.to) && e.from !== e.to)
    .map((e, i) => {
      const s = EDGE_KIND_STYLE[e.kind] ?? EDGE_KIND_STYLE.flow;
      return {
        id: `e${i}:${e.from}->${e.to}`,
        source: e.from,
        target: e.to,
        width: s.width,
        color: s.color,
        threat: e.kind === 'lateral',
        arrows: 'end' as const,
        dash: s.dash,
        label: e.label || undefined,
        tooltip: [`${e.from} to ${e.to}`, `Type: ${s.label}.`, ...(e.label ? [e.label] : [])],
      };
    });

  const legend: LegendItem[] = [];
  for (const k of [...new Set(unique.map((n) => n.kind))]) {
    const s = KIND_STYLE[k];
    if (!s) continue;
    legend.push({ kind: 'node', label: kindLabel(k), color: s.color, shape: s.shape });
  }
  if (unique.some((n) => n.flagged)) legend.push({ kind: 'badge', label: 'flagged by intel', mark: '!' });

  return { nodes: viewNodes, edges: viewEdges, legend, layout: { mode: 'force' } };
}

/** Whether the graph holds something dangerous. The red wash says so. */
export function graphHoldsDanger(nodes: GraphNode[], edges: GraphEdge[]): boolean {
  return (
    nodes.some((n) => n.flagged || n.kind === 'compromised') || edges.some((e) => e.kind === 'lateral')
  );
}
