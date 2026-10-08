// The investigation blast radius: the record's nodes and edges, with the kind
// as the style. lib/entityGraphView.ts shapes the data and components/Graph.tsx
// draws it. Graph.tsx states the library choice. The host page draws its peers
// through the same Graph, in PeerGraph.tsx.
//
// The diagram was a hand-drawn SVG on a fixed 600 px canvas. It cut each label
// at about twenty characters. It now shares one layout, one legend and one
// hover card with the peer diagram and the hunt map.
//
// Graph loads on demand. The Alerts page carries the investigation drawer, and
// the graph mounts only when the analyst opens the entity scope.

import { Suspense, useMemo } from 'react';
import { entityGraphView, graphHoldsDanger } from '../lib/entityGraphView';
import { lazyWithReload } from '../lib/lazyWithReload';
import type { EntityKind, GraphEdge, GraphNode } from '../lib/types';

const Graph = lazyWithReload(() => import('./Graph').then((m) => ({ default: m.Graph })));

interface EntityGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  /** The subject of the investigation. It gets the second ring. */
  highlight?: string;
  height?: number;
  showLegend?: boolean;
  /**
   * Rename a node kind for THIS graph, in the legend and in the hover card.
   *
   * The stock words were written for the investigation blast radius, where an
   * external node is a C2 candidate. A caller that draws a CDN with the same
   * style says what its own nodes are.
   */
  kindLabels?: Partial<Record<EntityKind, string>>;
}

export function EntityGraph({ nodes, edges, highlight, height, showLegend = true, kindLabels }: EntityGraphProps) {
  const view = useMemo(
    () => entityGraphView(nodes, edges, { kindLabels, highlight }),
    [nodes, edges, kindLabels, highlight],
  );
  return (
    <Suspense
      fallback={
        <div className="flex items-center justify-center text-[12px] text-faint" style={{ height: height ?? 240 }}>
          Loading the graph.
        </div>
      }
    >
      <Graph
        view={view}
        height={height}
        showLegend={showLegend}
        // The red wash is a statement: something on this graph is dangerous.
        tint={graphHoldsDanger(nodes, edges) ? 'danger' : undefined}
        ariaLabel="Entity graph of this investigation"
        emptyText="This investigation names no related entity. There is nothing to draw."
      />
    </Suspense>
  );
}
