// ---------------------------------------------------------------------------
// The shape every console diagram draws, and the layout that places it.
//
// A diagram is a GraphView: nodes, edges and a legend. Each screen shapes its
// own data into one (lib/peerGraph.ts, lib/huntGraph.ts, lib/entityGraphView.ts)
// and components/Graph.tsx draws it. This file places the nodes. It is pure,
// so a test can prove the property the owner asked for: no two labels overlap.
//
// Every node label is part of the node box. The layout separates boxes, never
// points, so a label cannot sit on top of another node or another label. The
// label font is JetBrains Mono, a monospace face with an advance of 0.6 em, so
// the width of a line is known from its length before anything renders.
//
// d3-force places a free graph. The "ring" mode places one subject node in
// the centre and every other node on an ellipse around it. Both modes end with
// the same overlap pass, which runs until no two boxes touch.
// ---------------------------------------------------------------------------

import {
  forceLink,
  forceManyBody,
  forceSimulation,
  forceX,
  forceY,
  type SimulationLinkDatum,
  type SimulationNodeDatum,
} from 'd3-force';

// ---- the view -----------------------------------------------------------------

/** One line of a node label. Every line shows whole. Nothing is cut. */
export interface GraphLine {
  text: string;
  /** primary: the name. secondary: a fact under it. threat: a red fact. */
  tone?: 'primary' | 'secondary' | 'threat';
}

export interface GraphNodeView {
  id: string;
  lines: GraphLine[];
  /** A short mark inside the shape, such as "F2". */
  glyph?: string;
  shape: 'circle' | 'square';
  /** The diameter of the shape in pixels at zoom 1. */
  size: number;
  /** The role colour: the border and the fill of the shape. */
  color: string;
  /** The node carries a threat: a red ring. */
  threat?: boolean;
  /** The subject of the page: a second ring. */
  subject?: boolean;
  /** The node has no link to any other node and draws dim. */
  dim?: boolean;
  /** A small red mark on the shape, such as "!" for an intel hit. */
  badge?: string;
  /** The page that answers for this node. No href, no link. */
  href?: string;
  /** The facts the hover card shows, one per line. */
  tooltip: string[];
  /** A start position from the record, 0 to 100 on each axis. */
  seed?: { x: number; y: number };
}

export interface GraphEdgeView {
  id: string;
  source: string;
  target: string;
  /** Stroke width in pixels at zoom 1. */
  width: number;
  color: string;
  /** The edge carries a threat. The view gives it the red colour. */
  threat?: boolean;
  /** Where the arrowheads go. 'end' points at the target. */
  arrows: 'none' | 'end' | 'start' | 'both';
  /** A dashed line that moves along its direction. */
  dash?: boolean;
  /** A short word on the edge. It takes part in the layout like a node. */
  label?: string;
  tooltip: string[];
}

export type LegendItem =
  | { kind: 'node'; label: string; color: string; shape: 'circle' | 'square'; ring?: 'threat' | 'subject' }
  | { kind: 'line'; label: string; color: string; width?: number; dash?: boolean }
  | { kind: 'badge'; label: string; mark: string }
  | { kind: 'note'; label: string };

export type GraphLayoutMode = { mode: 'ring'; center: string } | { mode: 'force' };

export interface GraphView {
  nodes: GraphNodeView[];
  edges: GraphEdgeView[];
  legend: LegendItem[];
  layout: GraphLayoutMode;
}

// ---- text metrics ---------------------------------------------------------------

/** Font size, advance per character and line height for each label tone. */
export const LINE_METRICS = {
  primary: { font: 11, advance: 6.6, height: 15 },
  secondary: { font: 10, advance: 6, height: 13 },
  threat: { font: 10, advance: 6, height: 13 },
} as const;

/** The rendered label pads each line with 4px on each side. The estimate also
 *  takes 6% on top of the advance, for a fallback face if the web font fails. */
const LINE_PAD_X = 8;
const WIDTH_SAFETY = 1.06;
/** Room around the shape for the threat ring and the subject ring. */
const RING_ROOM = 12;
/** Space between the shape and the first label line. */
const LABEL_GAP = 4;

export function lineWidth(line: GraphLine): number {
  const m = LINE_METRICS[line.tone ?? 'primary'];
  return Math.ceil(line.text.length * m.advance * WIDTH_SAFETY) + LINE_PAD_X;
}

/** The size of a node box at zoom 1: the shape, its rings and every label line. */
export function nodeBox(node: Pick<GraphNodeView, 'size' | 'lines'>): { w: number; h: number; shapeBox: number } {
  const shapeBox = node.size + RING_ROOM;
  const textW = node.lines.reduce((max, l) => Math.max(max, lineWidth(l)), 0);
  const textH = node.lines.reduce((sum, l) => sum + LINE_METRICS[l.tone ?? 'primary'].height, 0);
  return {
    w: Math.max(shapeBox, textW),
    h: shapeBox + (node.lines.length ? LABEL_GAP + textH : 0),
    shapeBox,
  };
}

/**
 * Break a label into lines of at most `max` characters. Every character stays.
 *
 * Words join with a space. A word longer than `max` breaks after a dot, a dash,
 * a colon, a slash, an underscore or an at sign when one sits in the second
 * half of the line, and at `max` when none does. The result never ends a line
 * in an ellipsis: the owner forbids a cut label.
 */
export function wrapLabel(text: string, max = 26): string[] {
  const words = text.trim().split(/\s+/).filter(Boolean);
  const lines: string[] = [];
  let cur = '';
  for (const word of words) {
    let w = word;
    while (w.length > max) {
      if (cur) {
        lines.push(cur);
        cur = '';
      }
      let cut = max;
      for (let i = max; i > Math.floor(max / 2); i--) {
        if ('.-:/_@'.includes(w[i - 1])) {
          cut = i;
          break;
        }
      }
      lines.push(w.slice(0, cut));
      w = w.slice(cut);
    }
    if (!w) continue;
    if (!cur) cur = w;
    else if (cur.length + 1 + w.length <= max) cur += ' ' + w;
    else {
      lines.push(cur);
      cur = w;
    }
  }
  if (cur) lines.push(cur);
  return lines;
}

// ---- the layout ---------------------------------------------------------------

export interface PlacedNode {
  /** The top-left corner of the box. */
  x: number;
  y: number;
  w: number;
  h: number;
  /** The centre of the shape, where edges meet the node. */
  cx: number;
  cy: number;
  /** The label sits above the shape. The ring does this for its upper half,
   *  so an edge from the centre meets the shape before it meets the label. */
  labelAbove: boolean;
}

export interface Arrowhead {
  x: number;
  y: number;
  /** Degrees. 0 points along +x. */
  angle: number;
}

export interface PlacedEdge {
  path: string;
  /** The point half way along the edge. */
  mid: { x: number; y: number };
  arrowEnd?: Arrowhead;
  arrowStart?: Arrowhead;
  /** The box of the edge label, centre and size. */
  label?: { x: number; y: number; w: number; h: number; text: string };
}

export interface GraphLayout {
  nodes: Record<string, PlacedNode>;
  edges: Record<string, PlacedEdge>;
  /** The size of the drawing at zoom 1, margins included. */
  width: number;
  height: number;
}

interface Box extends SimulationNodeDatum {
  id: string;
  w: number;
  h: number;
  /** The shape centre, relative to the box centre. */
  shapeY: number;
  shapeBox: number;
  labelAbove: boolean;
  size: number;
  shape: 'circle' | 'square';
  ringed: boolean;
  seedX?: number;
  seedY?: number;
  x: number;
  y: number;
}

/** Space the overlap pass keeps between two boxes. */
const BOX_GAP = 10;
const MARGIN = 24;
const LABEL_BOX_H = 16;
/** How far apart two edges between the same pair bow. */
const PARALLEL_BOW = 22;
const ARROW_LEN = 8;

/** A d3 force that pushes overlapping boxes apart along their shallow axis. */
function rectCollide(gap: number, strength = 0.7) {
  let boxes: Box[] = [];
  function force() {
    for (let i = 0; i < boxes.length; i++) {
      const a = boxes[i];
      for (let j = i + 1; j < boxes.length; j++) {
        const b = boxes[j];
        const dx = b.x + (b.vx ?? 0) - (a.x + (a.vx ?? 0));
        const dy = b.y + (b.vy ?? 0) - (a.y + (a.vy ?? 0));
        const ox = (a.w + b.w) / 2 + gap - Math.abs(dx);
        const oy = (a.h + b.h) / 2 + gap - Math.abs(dy);
        if (ox <= 0 || oy <= 0) continue;
        if (ox < oy) {
          const s = (dx === 0 ? 1 : Math.sign(dx)) * ox * 0.5 * strength;
          a.vx = (a.vx ?? 0) - s;
          b.vx = (b.vx ?? 0) + s;
        } else {
          const s = (dy === 0 ? 1 : Math.sign(dy)) * oy * 0.5 * strength;
          a.vy = (a.vy ?? 0) - s;
          b.vy = (b.vy ?? 0) + s;
        }
      }
    }
  }
  force.initialize = (nodes: Box[]) => {
    boxes = nodes;
  };
  return force;
}

/**
 * Move boxes apart until no two overlap. A pinned box does not move; the other
 * box of the pair takes the full step. The pass ends when a sweep finds no
 * overlap, so the result is the guarantee and the force above is the shape.
 */
export function removeOverlaps(
  boxes: { x: number; y: number; w: number; h: number; pinned?: boolean }[],
  gap = BOX_GAP,
  maxSweeps = 400,
): boolean {
  for (let sweep = 0; sweep < maxSweeps; sweep++) {
    let moved = false;
    for (let i = 0; i < boxes.length; i++) {
      for (let j = i + 1; j < boxes.length; j++) {
        const a = boxes[i];
        const b = boxes[j];
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const ox = (a.w + b.w) / 2 + gap - Math.abs(dx);
        const oy = (a.h + b.h) / 2 + gap - Math.abs(dy);
        if (ox <= 0 || oy <= 0) continue;
        moved = true;
        // A tiny overshoot so floating-point rounding cannot leave a touch.
        const horizontal = ox < oy;
        const depth = (horizontal ? ox : oy) + 0.5;
        const sign = horizontal ? (dx === 0 ? 1 : Math.sign(dx)) : dy === 0 ? 1 : Math.sign(dy);
        const shareA = a.pinned ? 0 : b.pinned ? 1 : 0.5;
        const shareB = 1 - shareA;
        if (a.pinned && b.pinned) continue;
        if (horizontal) {
          a.x -= sign * depth * shareA;
          b.x += sign * depth * shareB;
        } else {
          a.y -= sign * depth * shareA;
          b.y += sign * depth * shareB;
        }
      }
    }
    if (!moved) return true;
  }
  return false;
}

/** Whether any two boxes overlap. Boxes are given by centre and size. */
export function anyOverlap(boxes: { x: number; y: number; w: number; h: number }[], gap = 0): boolean {
  for (let i = 0; i < boxes.length; i++) {
    for (let j = i + 1; j < boxes.length; j++) {
      const a = boxes[i];
      const b = boxes[j];
      if (
        Math.abs(b.x - a.x) < (a.w + b.w) / 2 + gap - 0.01 &&
        Math.abs(b.y - a.y) < (a.h + b.h) / 2 + gap - 0.01
      ) {
        return true;
      }
    }
  }
  return false;
}

/** The distance from a shape centre to its outline along a unit direction. */
function clipRadius(b: Box, ux: number, uy: number): number {
  const half = b.size / 2 + (b.ringed ? 5 : 1);
  if (b.shape === 'circle') return half;
  return half / Math.max(Math.abs(ux), Math.abs(uy), 1e-6);
}

function unit(x: number, y: number): [number, number] {
  const d = Math.hypot(x, y) || 1;
  return [x / d, y / d];
}

const r1 = (n: number) => Math.round(n * 10) / 10;

/**
 * Place a view. Deterministic: d3-force seeds its jitter from a fixed
 * generator, and every start position comes from the input order.
 */
export function layoutGraph(view: Pick<GraphView, 'nodes' | 'edges' | 'layout'>): GraphLayout {
  const known = new Set(view.nodes.map((n) => n.id));
  const edges = view.edges.filter((e) => known.has(e.source) && known.has(e.target) && e.source !== e.target);

  const boxes: Box[] = view.nodes.map((n) => {
    const { w, h, shapeBox } = nodeBox(n);
    return {
      id: n.id,
      w,
      h,
      // The box centre is the simulation point. The shape sits at the top.
      shapeY: shapeBox / 2 - h / 2,
      shapeBox,
      labelAbove: false,
      size: n.size,
      shape: n.shape,
      ringed: Boolean(n.threat || n.subject),
      seedX: n.seed ? (n.seed.x - 50) * 9 : undefined,
      seedY: n.seed ? (n.seed.y - 50) * 5 : undefined,
      x: 0,
      y: 0,
    };
  });
  const byId = new Map(boxes.map((b) => [b.id, b]));

  // An edge label is a small box of its own, tied to both ends of its edge.
  const labelBoxes = new Map<string, Box>();
  for (const e of edges) {
    if (!e.label) continue;
    labelBoxes.set(e.id, {
      id: `label:${e.id}`,
      w: lineWidth({ text: e.label, tone: 'secondary' }),
      h: LABEL_BOX_H,
      shapeY: 0,
      shapeBox: 0,
      labelAbove: false,
      size: 0,
      shape: 'square',
      ringed: false,
      x: 0,
      y: 0,
    });
  }

  if (view.layout.mode === 'ring') placeRing(boxes, view.layout.center);
  else placeForce(boxes, edges, labelBoxes, byId);

  // Ring labels start half way along their edge; the force mode placed its own.
  if (view.layout.mode === 'ring') {
    for (const e of edges) {
      const lb = labelBoxes.get(e.id);
      if (!lb) continue;
      const s = byId.get(e.source)!;
      const t = byId.get(e.target)!;
      lb.x = (s.x + t.x) / 2;
      lb.y = (s.y + t.y) / 2;
    }
  }

  const center = view.layout.mode === 'ring' ? view.layout.center : null;
  const all = [
    ...boxes.map((b) => ({ ref: b, x: b.x, y: b.y, w: b.w, h: b.h, pinned: b.id === center })),
    ...[...labelBoxes.values()].map((b) => ({ ref: b, x: b.x, y: b.y, w: b.w, h: b.h, pinned: false })),
  ];
  removeOverlaps(all);
  for (const a of all) {
    a.ref.x = a.x;
    a.ref.y = a.y;
  }

  // In a free layout, a node whose neighbours sit mostly below it puts its
  // label above its shape, so its edges meet the shape before the label. The
  // box does not change, so the overlap guarantee holds.
  if (view.layout.mode === 'force') {
    const pull = new Map<string, number>();
    for (const e of edges) {
      const s = byId.get(e.source)!;
      const t = byId.get(e.target)!;
      const d = Math.hypot(t.x - s.x, t.y - s.y) || 1;
      pull.set(s.id, (pull.get(s.id) ?? 0) + (t.y - s.y) / d);
      pull.set(t.id, (pull.get(t.id) ?? 0) + (s.y - t.y) / d);
    }
    for (const b of boxes) {
      if ((pull.get(b.id) ?? 0) > 0.25) {
        b.labelAbove = true;
        b.shapeY = b.h / 2 - b.shapeBox / 2;
      }
    }
  }

  // Translate so the drawing starts at the margin.
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (const a of all) {
    minX = Math.min(minX, a.x - a.w / 2);
    minY = Math.min(minY, a.y - a.h / 2);
    maxX = Math.max(maxX, a.x + a.w / 2);
    maxY = Math.max(maxY, a.y + a.h / 2);
  }
  if (!all.length) {
    minX = minY = 0;
    maxX = maxY = 0;
  }
  const ox = MARGIN - minX;
  const oy = MARGIN - minY;

  const nodes: Record<string, PlacedNode> = {};
  for (const b of boxes) {
    nodes[b.id] = {
      x: r1(b.x - b.w / 2 + ox),
      y: r1(b.y - b.h / 2 + oy),
      w: b.w,
      h: b.h,
      cx: r1(b.x + ox),
      cy: r1(b.y + b.shapeY + oy),
      labelAbove: b.labelAbove,
    };
  }

  // Edges between the same pair bow apart so neither hides the other.
  const pairKey = (e: GraphEdgeView) => [e.source, e.target].sort().join('\u0000');
  const groups = new Map<string, GraphEdgeView[]>();
  for (const e of edges) {
    const k = pairKey(e);
    groups.set(k, [...(groups.get(k) ?? []), e]);
  }

  const placed: Record<string, PlacedEdge> = {};
  for (const e of edges) {
    const s = byId.get(e.source)!;
    const t = byId.get(e.target)!;
    const p0 = { x: s.x + ox, y: s.y + s.shapeY + oy };
    const p2 = { x: t.x + ox, y: t.y + t.shapeY + oy };
    const mid = { x: (p0.x + p2.x) / 2, y: (p0.y + p2.y) / 2 };
    const lb = labelBoxes.get(e.id);

    // The point the edge passes through half way along.
    let through = mid;
    if (lb) {
      through = { x: lb.x + ox, y: lb.y + oy };
    } else {
      const group = groups.get(pairKey(e))!;
      if (group.length > 1) {
        const k = group.indexOf(e);
        const [a, b] = [e.source, e.target].sort();
        const pa = byId.get(a)!;
        const pb = byId.get(b)!;
        const [ux, uy] = unit(pb.x - pa.x, pb.y - pa.y);
        const bow = (k - (group.length - 1) / 2) * PARALLEL_BOW;
        through = { x: mid.x - uy * bow, y: mid.y + ux * bow };
      }
    }
    const curved = Math.hypot(through.x - mid.x, through.y - mid.y) > 0.5;
    // A quadratic curve through `through` at t = 0.5 has this control point.
    const c = curved ? { x: 2 * through.x - mid.x, y: 2 * through.y - mid.y } : null;

    const [sx, sy] = c ? unit(c.x - p0.x, c.y - p0.y) : unit(p2.x - p0.x, p2.y - p0.y);
    const [ex, ey] = c ? unit(p2.x - c.x, p2.y - c.y) : unit(p2.x - p0.x, p2.y - p0.y);
    const startTip = { x: p0.x + sx * (clipRadius(s, sx, sy) + 2), y: p0.y + sy * (clipRadius(s, sx, sy) + 2) };
    const endTip = { x: p2.x - ex * (clipRadius(t, ex, ey) + 2), y: p2.y - ey * (clipRadius(t, ex, ey) + 2) };
    const hasEnd = e.arrows === 'end' || e.arrows === 'both';
    const hasStart = e.arrows === 'start' || e.arrows === 'both';
    const start = hasStart ? { x: startTip.x + sx * (ARROW_LEN - 2), y: startTip.y + sy * (ARROW_LEN - 2) } : startTip;
    const end = hasEnd ? { x: endTip.x - ex * (ARROW_LEN - 2), y: endTip.y - ey * (ARROW_LEN - 2) } : endTip;

    const path = c
      ? `M${r1(start.x)},${r1(start.y)} Q${r1(c.x)},${r1(c.y)} ${r1(end.x)},${r1(end.y)}`
      : `M${r1(start.x)},${r1(start.y)} L${r1(end.x)},${r1(end.y)}`;
    const deg = (x: number, y: number) => r1((Math.atan2(y, x) * 180) / Math.PI);

    placed[e.id] = {
      path,
      mid: { x: r1(through.x), y: r1(through.y) },
      arrowEnd: hasEnd ? { x: r1(endTip.x), y: r1(endTip.y), angle: deg(ex, ey) } : undefined,
      arrowStart: hasStart ? { x: r1(startTip.x), y: r1(startTip.y), angle: deg(-sx, -sy) } : undefined,
      label: lb && e.label ? { x: r1(lb.x + ox), y: r1(lb.y + oy), w: lb.w, h: lb.h, text: e.label } : undefined,
    };
  }

  return {
    nodes,
    edges: placed,
    width: Math.ceil(maxX - minX + 2 * MARGIN),
    height: Math.ceil(maxY - minY + 2 * MARGIN),
  };
}

/**
 * The subject in the centre, every other node on an ellipse around it, in the
 * input order, clockwise from the right. The ellipse is 1.6 times as wide as
 * it is tall, because the console panels are wide. Its size comes from the
 * boxes it carries, so a ring of long names grows to fit them.
 */
function placeRing(boxes: Box[], center: string) {
  const hub = boxes.find((b) => b.id === center);
  const ring = boxes.filter((b) => b.id !== center);
  if (hub) {
    hub.x = 0;
    hub.y = 0;
  }
  if (!ring.length) return;
  const ASPECT = 1.6;
  const footprint = ring.reduce((sum, b) => sum + (b.w + b.h) / 2 + 28, 0);
  // Ramanujan's first estimate of an ellipse perimeter, solved for the minor axis.
  const perimeterPerMinor = Math.PI * (3 * (ASPECT + 1) - Math.sqrt((3 * ASPECT + 1) * (ASPECT + 3)));
  const maxW = Math.max(...ring.map((b) => b.w));
  const maxH = Math.max(...ring.map((b) => b.h));
  const hubW = hub?.w ?? 0;
  const hubH = hub?.h ?? 0;
  const ry = Math.max(footprint / perimeterPerMinor, hubH / 2 + maxH / 2 + 40, (hubW / 2 + maxW / 2 + 60) / ASPECT);
  const rx = ry * ASPECT;
  const n = ring.length;
  ring.forEach((b, i) => {
    // One node sits to the right; two sit left and right.
    const angle = (2 * Math.PI * i) / n;
    b.x = Math.cos(angle) * rx;
    b.y = Math.sin(angle) * ry;
    // A node in the upper part of the ring puts its label above its shape.
    if (Math.sin(angle) < -0.3) {
      b.labelAbove = true;
      b.shapeY = b.h / 2 - b.shapeBox / 2;
    }
  });
}

type Link = SimulationLinkDatum<Box> & { distance: number };

function placeForce(boxes: Box[], edges: GraphEdgeView[], labelBoxes: Map<string, Box>, byId: Map<string, Box>) {
  const nodes: Box[] = [...boxes, ...labelBoxes.values()];
  const seeded = boxes.some((b) => b.seedX !== undefined);

  // Start positions. A seeded node starts at its seed. Any other node starts on
  // a sunflower spiral in the input order, as d3 does, at a scale that suits
  // boxes this large.
  boxes.forEach((b, i) => {
    if (b.seedX !== undefined) {
      b.x = b.seedX;
      b.y = b.seedY ?? 0;
      return;
    }
    const r = 40 * Math.sqrt(0.5 + i);
    const a = i * Math.PI * (3 - Math.sqrt(5));
    b.x = r * Math.cos(a);
    b.y = r * Math.sin(a);
  });

  const spread = (b: Box) => Math.hypot(b.w, b.h) / 2;
  const links: Link[] = [];
  for (const e of edges) {
    const s = byId.get(e.source)!;
    const t = byId.get(e.target)!;
    const distance = (spread(s) + spread(t)) * 0.75 + 48;
    const lb = labelBoxes.get(e.id);
    if (lb) {
      // Half way along, a little off the line so the two ends pull it apart.
      lb.x = (s.x + t.x) / 2 + 1;
      lb.y = (s.y + t.y) / 2 + 1;
      links.push({ source: s, target: lb, distance: distance / 2 });
      links.push({ source: lb, target: t, distance: distance / 2 });
    } else {
      links.push({ source: s, target: t, distance });
    }
  }

  const sim = forceSimulation<Box>(nodes)
    .force(
      'link',
      forceLink<Box, Link>(links)
        .distance((l) => l.distance)
        .strength(0.55),
    )
    .force('charge', forceManyBody<Box>().strength(-320).distanceMax(700))
    .force('collide', rectCollide(BOX_GAP + 4))
    .stop();
  if (seeded) {
    // Keep the record's composition: each node leans towards its own seed.
    sim
      .force('x', forceX<Box>((b) => b.seedX ?? 0).strength((b) => (b.seedX !== undefined ? 0.25 : 0.04)))
      .force('y', forceY<Box>((b) => b.seedY ?? 0).strength((b) => (b.seedY !== undefined ? 0.25 : 0.06)));
  } else {
    sim.force('x', forceX<Box>(0).strength(0.05)).force('y', forceY<Box>(0).strength(0.08));
  }
  sim.tick(360);
  for (const b of nodes) {
    b.x = Number.isFinite(b.x) ? b.x : 0;
    b.y = Number.isFinite(b.y) ? b.y : 0;
  }
}
