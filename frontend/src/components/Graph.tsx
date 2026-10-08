// ---------------------------------------------------------------------------
// The one diagram component of the console.
//
// The peer diagram on the host page, the host and finding map on the hunt page
// and the blast radius on an investigation all draw through this file. A screen
// shapes its data into a GraphView (lib/graphLayout.ts), and this component
// draws it: a dark canvas, pan and zoom, a hover card with the facts, a link on
// every node that has a page, a Reset view control and a legend.
//
// Library: React Flow (@xyflow/react 12.12.0, MIT) with d3-force 3.0.0 (ISC)
// for the layout. Cytoscape.js 3.34.3 with cytoscape-fcose 2.2.0 was the other
// candidate. The choice and the reasons:
//
// - Labels. A React Flow node is a DOM element. Its label is real text in the
//   console font, it never truncates, and the layout knows its size before it
//   renders. A Cytoscape label is canvas text with one style per element.
// - Click. A React Flow node can hold a router <Link>, so a node is a real
//   link with an href: it opens in a new tab and takes keyboard focus. A
//   Cytoscape node is pixels on a canvas, with no link and no focus.
// - Tests. React Flow renders in happy-dom when each node carries its size and
//   its handles, so a test reads the nodes and the edges. Cytoscape needs a
//   canvas stub, and a test then reads nothing it drew.
// - Size. React Flow and d3-force add about 63 KB gzip. Cytoscape and fcose
//   add about 176 KB gzip. Both were measured with esbuild at the pinned
//   versions. Vite puts the diagram code in one shared chunk that loads with
//   the host page, the hunt map or the investigation graph, never at login.
// - Layout. Cytoscape brings label-aware layouts. React Flow brings none, so
//   lib/graphLayout.ts runs d3-force and then an overlap pass, and a test
//   proves that no two node boxes overlap. elkjs was ruled out: it is EPL-2.0.
// - Upkeep. Both projects ship often under MIT. npm audit --omit=dev shows no
//   new advisory for either.
//
// The attribution badge is off (proOptions.hideAttribution). The MIT licence
// allows it, and the credit stays here.
// ---------------------------------------------------------------------------

import {
  Background,
  BackgroundVariant,
  Handle,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Edge,
  type EdgeProps,
  type Node,
  type NodeProps,
} from '@xyflow/react';
import '@xyflow/react/dist/base.css';
import { Maximize2, Minus, Plus } from 'lucide-react';
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FocusEvent,
  type MouseEvent as ReactMouseEvent,
  type RefObject,
} from 'react';
import { Link } from 'react-router-dom';
import { cn } from '../lib/cn';
import {
  LINE_METRICS,
  layoutGraph,
  type Arrowhead,
  type GraphEdgeView,
  type GraphLine,
  type GraphNodeView,
  type GraphView,
  type LegendItem,
  type PlacedEdge,
  type PlacedNode,
} from '../lib/graphLayout';

const THREAT = '#f04438';
const SUBJECT_RING = '#4b8bf5';
/** Fit the whole drawing, and do not blow a small graph up past 115%. */
const FIT = { padding: 0.06, maxZoom: 1.15, minZoom: 0.12 } as const;

type FlowNodeData = { node: GraphNodeView; placed: PlacedNode };
type FlowNode = Node<FlowNodeData, 'entity'>;
type FlowEdgeData = { edge: GraphEdgeView; placed: PlacedEdge };
type FlowEdge = Edge<FlowEdgeData, 'link'>;

interface Hover {
  id: string;
  kind: 'node' | 'edge';
  lines: string[];
  /** Where the card goes, in pixels from the top-left of the diagram. */
  x: number;
  y: number;
  /** The card sits to the left of x when the right side has no room. */
  flip: boolean;
}

interface GraphContextValue {
  focusNodes: Set<string> | null;
  focusEdges: Set<string> | null;
  setHover: (h: Hover | null) => void;
  wrapRef: RefObject<HTMLDivElement>;
}

const GraphContext = createContext<GraphContextValue | null>(null);

function useGraph(): GraphContextValue {
  const ctx = useContext(GraphContext);
  if (!ctx) throw new Error('Graph parts render inside <Graph>.');
  return ctx;
}

const CARD_WIDTH = 300;

/** A hover card position beside a rectangle on the screen. */
function besideRect(wrap: HTMLElement | null, r: DOMRect): Pick<Hover, 'x' | 'y' | 'flip'> {
  const w = wrap?.getBoundingClientRect();
  const left = r.left - (w?.left ?? 0);
  const right = r.right - (w?.left ?? 0);
  const flip = w ? right + CARD_WIDTH + 12 > w.width : false;
  return { x: flip ? left - 8 : right + 8, y: Math.max(4, r.top - (w?.top ?? 0)), flip };
}

/** A hover card position beside the pointer. */
function besidePointer(wrap: HTMLElement | null, e: ReactMouseEvent): Pick<Hover, 'x' | 'y' | 'flip'> {
  const w = wrap?.getBoundingClientRect();
  const x = e.clientX - (w?.left ?? 0);
  const y = e.clientY - (w?.top ?? 0);
  const flip = w ? x + CARD_WIDTH + 24 > w.width : false;
  return { x: flip ? x - 14 : x + 14, y: y + 10, flip };
}

// ---- the node -------------------------------------------------------------------

const LINE_CLASS: Record<NonNullable<GraphLine['tone']>, string> = {
  primary: 'text-text-2',
  secondary: 'text-faint',
  threat: 'font-semibold text-danger',
};

function NodeShape({ node }: { node: GraphNodeView }) {
  const box = node.size + 12;
  const c = box / 2;
  const r = node.size / 2;
  const stroke = node.threat ? THREAT : node.color;
  const ring = (extra: number, color: string, cls?: string, dash?: string) =>
    node.shape === 'circle' ? (
      <circle cx={c} cy={c} r={r + extra} fill="none" stroke={color} strokeWidth={1.5} strokeDasharray={dash} className={cls} />
    ) : (
      <rect
        x={c - r - extra}
        y={c - r - extra}
        width={2 * (r + extra)}
        height={2 * (r + extra)}
        rx={7 + extra}
        fill="none"
        stroke={color}
        strokeWidth={1.5}
        strokeDasharray={dash}
        className={cls}
      />
    );
  return (
    <svg width={box} height={box} viewBox={`0 0 ${box} ${box}`} className="block overflow-visible" aria-hidden="true">
      {node.threat && ring(5, THREAT, 'animate-pulseRing')}
      {node.subject && !node.threat && ring(5, SUBJECT_RING, undefined, '3 3')}
      {node.shape === 'circle' ? (
        <>
          <circle cx={c} cy={c} r={r - 1} fill="#0b0e13" stroke={stroke} strokeWidth={2} />
          <circle cx={c} cy={c} r={r - 1} fill={node.color} fillOpacity={0.2} />
          {!node.glyph && <circle cx={c} cy={c} r={Math.max(3, r * 0.34)} fill={node.color} fillOpacity={0.95} />}
        </>
      ) : (
        <>
          <rect x={c - r + 1} y={c - r + 1} width={2 * r - 2} height={2 * r - 2} rx={6} fill="#0b0e13" stroke={stroke} strokeWidth={2} />
          <rect x={c - r + 1} y={c - r + 1} width={2 * r - 2} height={2 * r - 2} rx={6} fill={node.color} fillOpacity={0.2} />
          {!node.glyph && (
            <rect x={c - r * 0.34} y={c - r * 0.34} width={r * 0.68} height={r * 0.68} rx={2} fill={node.color} fillOpacity={0.95} />
          )}
        </>
      )}
      {node.glyph && (
        <text
          x={c}
          y={c}
          dominantBaseline="central"
          textAnchor="middle"
          fill={node.color}
          fontSize={node.size >= 30 ? 10 : 9}
          fontWeight={700}
          fontFamily="JetBrains Mono, monospace"
        >
          {node.glyph}
        </text>
      )}
      {node.badge && (
        <g>
          <circle cx={c + r * 0.78} cy={c - r * 0.78} r={6.5} fill={THREAT} stroke="#0b0e13" strokeWidth={1.5} />
          <text
            x={c + r * 0.78}
            y={c - r * 0.78}
            dominantBaseline="central"
            textAnchor="middle"
            fill="#fff"
            fontSize={9}
            fontWeight={700}
            fontFamily="JetBrains Mono, monospace"
          >
            {node.badge}
          </text>
        </g>
      )}
    </svg>
  );
}

function EntityNode({ data }: NodeProps<FlowNode>) {
  const { node, placed } = data;
  const { focusNodes, setHover, wrapRef } = useGraph();
  const faded = focusNodes !== null && !focusNodes.has(node.id);
  const shapeTop = placed.cy - placed.y;

  // The pointer hover comes from React Flow (onNodeMouseEnter in GraphCanvas).
  // Keyboard focus shows the same card.
  const handlers = {
    onFocus: (e: FocusEvent) =>
      setHover({ id: node.id, kind: 'node', lines: node.tooltip, ...besideRect(wrapRef.current, e.currentTarget.getBoundingClientRect()) }),
    onBlur: () => setHover(null),
  };

  const label = node.lines.length > 0 && (
    <div className={cn('flex flex-col items-center rounded-[4px] bg-surface-1/90 px-1', placed.labelAbove ? 'mb-1' : 'mt-1')}>
      {node.lines.map((l, i) => {
        const m = LINE_METRICS[l.tone ?? 'primary'];
        return (
          <span
            key={i}
            className={cn('whitespace-pre font-mono', LINE_CLASS[l.tone ?? 'primary'])}
            style={{ fontSize: m.font, lineHeight: `${m.height}px` }}
          >
            {l.text}
          </span>
        );
      })}
    </div>
  );
  const body = (
    <div
      className={cn('flex flex-col items-center transition-opacity duration-150', placed.labelAbove && 'justify-end')}
      style={{ width: placed.w, height: placed.h, opacity: faded ? 0.28 : node.dim ? 0.62 : 1 }}
    >
      {placed.labelAbove && label}
      <NodeShape node={node} />
      {!placed.labelAbove && label}
    </div>
  );

  const accessibleName = node.tooltip.join(' ');
  return (
    <>
      {/* Edges draw from the layout, so the handles only mark the shape centre. */}
      <Handle type="target" position={Position.Top} isConnectable={false} className="graph-handle" style={{ top: shapeTop, opacity: 0, pointerEvents: 'none' }} />
      <Handle type="source" position={Position.Top} isConnectable={false} className="graph-handle" style={{ top: shapeTop, opacity: 0, pointerEvents: 'none' }} />
      {node.href ? (
        <Link
          to={node.href}
          aria-label={accessibleName}
          data-testid="graph-node"
          data-node-id={node.id}
          data-threat={node.threat ? 'true' : undefined}
          className="block rounded-control outline-none focus-visible:ring-2 focus-visible:ring-focus"
          {...handlers}
        >
          {body}
        </Link>
      ) : (
        <div
          tabIndex={0}
          role="group"
          aria-label={accessibleName}
          data-testid="graph-node"
          data-node-id={node.id}
          data-threat={node.threat ? 'true' : undefined}
          className="rounded-control outline-none focus-visible:ring-2 focus-visible:ring-focus"
          {...handlers}
        >
          {body}
        </div>
      )}
    </>
  );
}

// ---- the edge -------------------------------------------------------------------

function ArrowHead({ a, color, width }: { a: Arrowhead; color: string; width: number }) {
  const len = 7 + width * 0.8;
  const half = 3.5 + width * 0.45;
  return <path d={`M0,0 L${-len},${-half} L${-len},${half} Z`} transform={`translate(${a.x},${a.y}) rotate(${a.angle})`} fill={color} />;
}

function LinkEdge({ data }: EdgeProps<FlowEdge>) {
  const { focusEdges, setHover, wrapRef } = useGraph();
  if (!data) return null;
  const { edge, placed } = data;
  const faded = focusEdges !== null && !focusEdges.has(edge.id);
  const lit = focusEdges !== null && focusEdges.has(edge.id);
  // The dash moves from the source to the target. An edge that points back at
  // its source moves the other way. A two-way edge does not move.
  const animation = edge.dash && edge.arrows !== 'both' ? `dash .6s linear infinite${edge.arrows === 'start' ? ' reverse' : ''}` : undefined;
  const show = (e: ReactMouseEvent) =>
    setHover({ id: edge.id, kind: 'edge', lines: edge.tooltip, ...besidePointer(wrapRef.current, e) });
  return (
    <g
      data-testid="graph-edge"
      data-edge-id={edge.id}
      data-threat={edge.threat ? 'true' : undefined}
      data-arrows={edge.arrows}
      style={{ opacity: faded ? 0.12 : 1, transition: 'opacity .15s' }}
    >
      {edge.threat && (
        <path d={placed.path} fill="none" stroke={edge.color} strokeOpacity={0.16} strokeWidth={edge.width + 7} strokeLinecap="round" />
      )}
      <path
        d={placed.path}
        fill="none"
        stroke={edge.color}
        strokeOpacity={edge.threat || lit ? 1 : 0.78}
        strokeWidth={edge.width}
        strokeDasharray={edge.dash ? '6 5' : undefined}
        strokeLinecap="round"
        style={animation ? { animation } : undefined}
      />
      {placed.arrowEnd && <ArrowHead a={placed.arrowEnd} color={edge.color} width={edge.width} />}
      {placed.arrowStart && <ArrowHead a={placed.arrowStart} color={edge.color} width={edge.width} />}
      {placed.label && (
        <g>
          <rect
            x={placed.label.x - placed.label.w / 2}
            y={placed.label.y - placed.label.h / 2}
            width={placed.label.w}
            height={placed.label.h}
            rx={4}
            fill="#0b0e13"
            fillOpacity={0.94}
            stroke={edge.color}
            strokeOpacity={0.45}
          />
          <text
            x={placed.label.x}
            y={placed.label.y}
            dominantBaseline="central"
            textAnchor="middle"
            fill={edge.threat ? THREAT : '#aeb6c2'}
            fontSize={LINE_METRICS.secondary.font}
            fontWeight={edge.threat ? 600 : 400}
            fontFamily="JetBrains Mono, monospace"
          >
            {placed.label.text}
          </text>
        </g>
      )}
      {/* A wide clear stroke over the line, so a thin edge is easy to hover. */}
      <path
        d={placed.path}
        fill="none"
        stroke="transparent"
        strokeWidth={Math.max(14, edge.width + 10)}
        style={{ pointerEvents: 'stroke' }}
        onMouseEnter={show}
        onMouseMove={show}
        onMouseLeave={() => setHover(null)}
      />
    </g>
  );
}

const NODE_TYPES = { entity: EntityNode };
const EDGE_TYPES = { link: LinkEdge };

// ---- the legend -----------------------------------------------------------------

function LegendSwatch({ item }: { item: LegendItem }) {
  if (item.kind === 'note') return null;
  if (item.kind === 'line') {
    return (
      <svg width={22} height={10} aria-hidden="true">
        <line x1={1} y1={5} x2={21} y2={5} stroke={item.color} strokeWidth={item.width ?? 2} strokeDasharray={item.dash ? '4 3' : undefined} strokeLinecap="round" />
      </svg>
    );
  }
  if (item.kind === 'badge') {
    return (
      <span className="flex h-[12px] w-[12px] items-center justify-center rounded-full bg-danger text-[8px] font-bold leading-none text-white">
        {item.mark}
      </span>
    );
  }
  const ring = item.ring === 'threat' ? THREAT : item.ring === 'subject' ? SUBJECT_RING : null;
  return (
    <svg width={14} height={14} viewBox="0 0 14 14" aria-hidden="true">
      {item.shape === 'circle' ? (
        <>
          {ring && <circle cx={7} cy={7} r={6.2} fill="none" stroke={ring} strokeWidth={1} strokeDasharray={item.ring === 'subject' ? '2 1.5' : undefined} />}
          <circle cx={7} cy={7} r={ring ? 4 : 5.5} fill={item.color} fillOpacity={0.25} stroke={item.color} strokeWidth={1.5} />
        </>
      ) : (
        <rect x={1.5} y={1.5} width={11} height={11} rx={3} fill={item.color} fillOpacity={0.25} stroke={item.color} strokeWidth={1.5} />
      )}
    </svg>
  );
}

function Legend({ items }: { items: LegendItem[] }) {
  return (
    <div
      data-testid="graph-legend"
      className="flex flex-wrap items-center gap-x-4 gap-y-1.5 border-t border-border px-3.5 py-[9px] font-mono text-[11px] text-dim"
    >
      {items.map((it) => (
        <span key={`${it.kind}:${it.label}`} className={cn('flex items-center gap-1.5', it.kind === 'note' && 'text-faint')}>
          <LegendSwatch item={it} />
          {it.label}
        </span>
      ))}
    </div>
  );
}

// ---- the diagram ----------------------------------------------------------------

export interface GraphProps {
  view: GraphView;
  /** What the diagram shows, for a screen reader. */
  ariaLabel: string;
  /** The words the panel shows when there is nothing to draw. */
  emptyText: string;
  /** A fixed height in pixels. Without it the height follows the drawing. */
  height?: number;
  showLegend?: boolean;
  /** A faint red wash: the graph holds something dangerous. */
  tint?: 'danger';
}

function useWidth(ref: RefObject<HTMLDivElement>): number {
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    setWidth(el.getBoundingClientRect().width);
    if (typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver((entries) => setWidth(entries[0]?.contentRect.width ?? 0));
    ro.observe(el);
    return () => ro.disconnect();
  }, [ref]);
  return width;
}

function Toolbar() {
  const rf = useReactFlow();
  const btn =
    'flex h-[26px] items-center gap-1 rounded-control border border-border-strong bg-surface-card/90 px-1.5 text-[11px] text-dim hover:border-accent/60 hover:text-text-2';
  return (
    <div className="absolute right-2 top-2 z-10 flex items-center gap-1">
      <button type="button" className={btn} aria-label="Zoom in" title="Zoom in" onClick={() => void rf.zoomIn({ duration: 160 })}>
        <Plus size={13} />
      </button>
      <button type="button" className={btn} aria-label="Zoom out" title="Zoom out" onClick={() => void rf.zoomOut({ duration: 160 })}>
        <Minus size={13} />
      </button>
      <button
        type="button"
        className={cn(btn, 'px-2')}
        title="Fit the whole diagram in the panel"
        onClick={() => void rf.fitView({ ...FIT, duration: 240 })}
      >
        <Maximize2 size={12} /> Reset view
      </button>
    </div>
  );
}

function GraphCanvas({ view, ariaLabel, height, showLegend = true, tint }: Omit<GraphProps, 'emptyText'>) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const width = useWidth(wrapRef);
  const rf = useReactFlow();

  // Callers rebuild the view on every render. The layout runs only when the
  // view says something new.
  const key = useMemo(() => JSON.stringify(view), [view]);
  const layout = useMemo(() => layoutGraph(view), [key]);

  const flowNodes = useMemo<FlowNode[]>(
    () =>
      view.nodes.map((n) => {
        const p = layout.nodes[n.id];
        const handleY = p.cy - p.y;
        return {
          id: n.id,
          type: 'entity',
          position: { x: p.x, y: p.y },
          data: { node: n, placed: p },
          width: p.w,
          height: p.h,
          draggable: false,
          selectable: false,
          connectable: false,
          focusable: false,
          // The size and the handles ride on the node, so the first render can
          // draw the edges before the browser measures anything.
          handles: [
            { type: 'source', position: Position.Top, x: p.w / 2, y: handleY, width: 1, height: 1 },
            { type: 'target', position: Position.Top, x: p.w / 2, y: handleY, width: 1, height: 1 },
          ],
        };
      }),
    [layout],
  );
  const flowEdges = useMemo<FlowEdge[]>(
    () =>
      view.edges
        .filter((e) => layout.edges[e.id])
        .map((e) => ({
          id: e.id,
          source: e.source,
          target: e.target,
          type: 'link',
          data: { edge: e, placed: layout.edges[e.id] },
          focusable: false,
          selectable: false,
        })),
    [layout],
  );

  const [hover, setHoverState] = useState<Hover | null>(null);
  const setHover = useCallback((h: Hover | null) => setHoverState(h), []);

  // Hover a node: it, its edges and its neighbours stay bright. Hover an edge:
  // the edge and its two ends stay bright.
  const { focusNodes, focusEdges } = useMemo(() => {
    if (!hover) return { focusNodes: null, focusEdges: null };
    const nodes = new Set<string>();
    const edges = new Set<string>();
    if (hover.kind === 'node') {
      nodes.add(hover.id);
      for (const e of view.edges) {
        if (e.source === hover.id || e.target === hover.id) {
          edges.add(e.id);
          nodes.add(e.source);
          nodes.add(e.target);
        }
      }
    } else {
      const e = view.edges.find((x) => x.id === hover.id);
      if (e) {
        edges.add(e.id);
        nodes.add(e.source);
        nodes.add(e.target);
      }
    }
    return { focusNodes: nodes, focusEdges: edges };
  }, [hover, view.edges]);

  // The panel is as tall as the drawing at the width it has, inside limits.
  const scale = width > 0 ? Math.min(FIT.maxZoom, width / layout.width) : 1;
  const h = height ?? Math.min(620, Math.max(220, Math.round(layout.height * scale) + 16));

  // Fit again when the panel changes size or the drawing changes.
  useEffect(() => {
    if (!width) return;
    const id = requestAnimationFrame(() => void rf.fitView(FIT));
    return () => cancelAnimationFrame(id);
  }, [rf, width, h, layout]);

  const ctx = useMemo<GraphContextValue>(
    () => ({ focusNodes, focusEdges, setHover, wrapRef }),
    [focusNodes, focusEdges, setHover],
  );

  return (
    <GraphContext.Provider value={ctx}>
      <div className="font-sans">
        <div
          ref={wrapRef}
          data-testid="graph-canvas"
          role="group"
          aria-label={ariaLabel}
          className="relative"
          style={{
            height: h,
            background: tint === 'danger' ? 'radial-gradient(60% 70% at 40% 45%,rgba(240,68,56,.07),transparent 72%)' : undefined,
          }}
        >
          <ReactFlow<FlowNode, FlowEdge>
            nodes={flowNodes}
            edges={flowEdges}
            nodeTypes={NODE_TYPES}
            edgeTypes={EDGE_TYPES}
            fitView
            fitViewOptions={FIT}
            minZoom={FIT.minZoom}
            maxZoom={2.5}
            nodesDraggable={false}
            nodesConnectable={false}
            nodesFocusable={false}
            edgesFocusable={false}
            elementsSelectable={false}
            // The page scrolls under the wheel. Ctrl or Cmd with the wheel zooms.
            zoomOnScroll={false}
            panOnScroll={false}
            preventScrolling={false}
            zoomActivationKeyCode={['Control', 'Meta']}
            deleteKeyCode={null}
            selectionKeyCode={null}
            multiSelectionKeyCode={null}
            panActivationKeyCode={null}
            // These handlers also give each node its pointer events. React Flow
            // turns them off on a node that nothing listens to.
            onNodeMouseEnter={(e, n) =>
              setHover({
                id: n.id,
                kind: 'node',
                lines: n.data.node.tooltip,
                ...besideRect(wrapRef.current, (e.currentTarget as Element).getBoundingClientRect()),
              })
            }
            onNodeMouseLeave={() => setHover(null)}
            onMoveStart={() => setHover(null)}
            proOptions={{ hideAttribution: true }}
            colorMode="dark"
            style={{ background: 'transparent' }}
          >
            <Background variant={BackgroundVariant.Dots} gap={22} size={1.1} color="#1d2531" />
          </ReactFlow>
          <Toolbar />
          <div className="pointer-events-none absolute bottom-1.5 left-2.5 z-10 text-[10.5px] text-ghost">
            Drag to move. Hold Ctrl or Cmd and scroll to zoom.
          </div>
          {hover && (
            <div
              role="tooltip"
              data-testid="graph-tooltip"
              className="pointer-events-none absolute z-20 rounded-control border border-border-strong bg-surface-card px-2.5 py-2 text-[12px] leading-[1.45] shadow-dropdown"
              style={{
                width: 'max-content',
                maxWidth: CARD_WIDTH,
                top: hover.y,
                left: hover.flip ? undefined : hover.x,
                right: hover.flip ? (wrapRef.current?.getBoundingClientRect().width ?? 0) - hover.x : undefined,
              }}
            >
              {hover.lines.map((line, i) => (
                <div
                  key={i}
                  className={i === 0 ? 'mb-0.5 font-mono text-[12px] text-text [overflow-wrap:anywhere]' : 'text-text-2'}
                >
                  {line}
                </div>
              ))}
            </div>
          )}
        </div>
        {showLegend && view.legend.length > 0 && <Legend items={view.legend} />}
      </div>
    </GraphContext.Provider>
  );
}

/**
 * Draw a GraphView. An empty view draws no box: it says in words that there
 * is nothing to draw, because a blank panel reads as a broken one.
 */
export function Graph({ emptyText, ...props }: GraphProps) {
  if (props.view.nodes.length === 0) {
    return (
      <div data-testid="graph-empty" role="status" className="px-[15px] py-8 text-center text-[12.5px] leading-[1.6] text-dim">
        {emptyText}
      </div>
    );
  }
  return (
    <ReactFlowProvider>
      <GraphCanvas {...props} />
    </ReactFlowProvider>
  );
}
