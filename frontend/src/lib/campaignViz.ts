import type {
  CampaignChange,
  CampaignEdge,
  CampaignEvents,
  CampaignMember,
  CampaignParty,
  CampaignRelatedSession,
  CampaignStage,
} from './api';

// ---------------------------------------------------------------------------
// The geometry and the colors of the two campaign charts. Pure: no DOM and no
// clock, so a test can state each rule.
// ---------------------------------------------------------------------------

/** The five stages, lowest first. */
export const STAGE_SEQUENCE: readonly CampaignStage[] = [
  'reconnaissance',
  'attempt',
  'access',
  'action',
  'movement',
];

/** The color of a stage: one hue, five steps, the highest stage the lightest.
 *  A stage is a position in a sequence, so the reader must see the order in
 *  the color. The steps pass the ordinal checks on the dark surface: the
 *  lightness rises in equal steps, the hue holds, and the darkest step reads
 *  2.4:1 against the panel. */
export const STAGE_COLOR: Record<CampaignStage, string> = {
  reconnaissance: '#7a4200',
  attempt: '#a15b00',
  access: '#c77618',
  action: '#ed9235',
  movement: '#ffb96b',
};

/** The color of a mark with no proven stage. */
export const NO_STAGE_COLOR = '#5b6676';

/** The color of a pair of machines with an investigation outside the
 *  authorization of the campaign: the danger tone of the console (`--danger`).
 *  It adds no color to the palette. Its hue sits off the stage ramp, so an
 *  arrow outside never reads as a stage. */
export const OUTSIDE_COLOR = '#f04438';
/** The neutral tone of the console (`--text-2`): the shield of a listed
 *  machine and the band of the period of an authorization. */
export const LISTED_COLOR = '#cdd5e0';

export function stageRank(stage: CampaignStage | null | undefined): number {
  return stage ? STAGE_SEQUENCE.indexOf(stage) : -1;
}

export function stageColor(stage: CampaignStage | null | undefined): string {
  return stage ? (STAGE_COLOR[stage] ?? NO_STAGE_COLOR) : NO_STAGE_COLOR;
}

/** The highest stage of a set of stages, or null. */
export function highestStage(stages: Iterable<CampaignStage | null | undefined>): CampaignStage | null {
  let best: CampaignStage | null = null;
  for (const s of stages) if (s && stageRank(s) > stageRank(best)) best = s;
  return best;
}

// ── The attack graph ───────────────────────────────────────────────────────

/** The most targets that one column draws. The rest fold into one node. */
export const MAX_COLUMN_NODES = 14;

export interface GraphNode {
  key: string;
  /** 0 actors, 1 targets, 2 targets beyond the first target. */
  column: 0 | 1 | 2;
  x: number;
  y: number;
  party: CampaignParty | null;
  /** The machines that this node stands for when it is the fold of a column. */
  folded: CampaignParty[];
}

export interface GraphLink {
  key: string;
  source: GraphNode;
  target: GraphNode;
  /** The true positive investigations of the arrow. */
  runs: number;
  /** The alert events of the confirmed rules between the two ends. Null when
   *  the server sends no count. */
  alerts: number | null;
  stage: CampaignStage | null;
  firstAt: string | null;
  lastAt: string | null;
  beyond: boolean;
  fromDocuments: boolean;
  /** The sessions between two machines on the ports that no alert of the campaign is on. */
  related: boolean;
  port: number | null;
  /** The ports of a related line, lowest first. */
  ports: number[];
  documents: number;
  width: number;
  path: string;
  /** The three corners of the arrow head, as an SVG points string. */
  head: string;
  labelX: number;
  labelY: number;
}

export interface GraphLayout {
  width: number;
  height: number;
  columns: { column: 0 | 1 | 2; x: number; count: number }[];
  nodes: GraphNode[];
  links: GraphLink[];
}

export const NODE_WIDTH = 196;
export const NODE_HEIGHT = 46;
const ROW_GAP = 14;
const TOP = 34;
const BOTTOM = 14;
export const FOLD_KEY = 'fold:';
const HEAD_GAP = 5;

/** True when an investigation outside the authorization joins the two nodes
 *  of an arrow, in either direction. A folded node stands for each of its
 *  machines. */
export function linkOutside(
  link: Pick<GraphLink, 'source' | 'target' | 'related'>,
  outside: readonly { sourceKey: string | null; targetKey: string | null }[],
): boolean {
  if (link.related || outside.length === 0) return false;
  const keys = (n: GraphNode) => new Set(n.party ? [n.party.machineKey] : n.folded.map((p) => p.machineKey));
  const a = keys(link.source);
  const b = keys(link.target);
  return outside.some(
    (o) =>
      !!o.sourceKey &&
      !!o.targetKey &&
      ((a.has(o.sourceKey) && b.has(o.targetKey)) || (b.has(o.sourceKey) && a.has(o.targetKey))),
  );
}

/** The width of an arrow for its count: 1.5 px for a count of one, 7 px for
 *  the largest arrow of the graph. The square root keeps one large arrow from
 *  making every other arrow a hairline. */
export function linkWidth(count: number, most: number): number {
  if (count <= 0 || most <= 0) return 1.5;
  return 1.5 + 5.5 * Math.sqrt(Math.min(count, most) / most);
}

/** The sum of two counts that the server can leave out. */
function addCounts(a: number | null, b: number | null): number | null {
  return a === null && b === null ? null : (a ?? 0) + (b ?? 0);
}

function columnOf(party: CampaignParty): 0 | 1 | 2 {
  if (party.role === 'actor') return 0;
  return party.beyond ? 2 : 1;
}

/** Where each machine and each arrow of the graph sits.
 *
 *  Three columns: the actors, the targets, and the targets beyond the first
 *  target. A column orders its machines by the rows of the machines they
 *  connect to, so the arrows cross as little as the data allows. */
export function layoutGraph(
  parties: readonly CampaignParty[],
  edges: readonly CampaignEdge[],
  sessions: readonly CampaignRelatedSession[],
  width: number,
): GraphLayout {
  const byColumn: CampaignParty[][] = [[], [], []];
  for (const p of parties) byColumn[columnOf(p)].push(p);
  const used = byColumn.map((c) => c.length > 0);
  const columnCount = Math.max(2, used[2] ? 3 : 2);
  const inner = Math.max(width, NODE_WIDTH * columnCount + 80 * (columnCount - 1));
  const xOf = (column: number): number =>
    columnCount === 1 ? 0 : (column * (inner - NODE_WIDTH)) / (columnCount - 1);

  // The row of each actor decides the order of the targets, and so on.
  const order: Map<string, number> = new Map();
  byColumn[0].forEach((p, i) => order.set(p.machineKey, i));
  const neighbours = (key: string): number[] =>
    edges
      .filter((e) => e.target === key && order.has(e.source))
      .map((e) => order.get(e.source) as number);
  const stageInto = (key: string): number =>
    stageRank(highestStage(edges.filter((e) => e.target === key).map((e) => e.stage)));
  const acts = (key: string): boolean => edges.some((e) => e.source === key);
  for (const column of [1, 2] as const) {
    const scored = byColumn[column].map((p, i) => {
      const rows = neighbours(p.machineKey);
      const mean = rows.length > 0 ? rows.reduce((a, b) => a + b, 0) / rows.length : i;
      return { p, mean, i };
    });
    // In a row of equals, the machine where the campaign got furthest comes first.
    const rank = (a: (typeof scored)[number], b: (typeof scored)[number]): number =>
      stageInto(b.p.machineKey) - stageInto(a.p.machineKey) || b.p.memberRuns - a.p.memberRuns || a.i - b.i;
    if (scored.length > MAX_COLUMN_NODES) {
      // The fold takes the machines that matter least: a target that acts on
      // other hosts, a higher stage and more runs keep their own node.
      scored.sort((a, b) => Number(acts(b.p.machineKey)) - Number(acts(a.p.machineKey)) || rank(a, b));
      const kept = scored.slice(0, MAX_COLUMN_NODES - 1).sort((a, b) => a.mean - b.mean || rank(a, b));
      scored.splice(0, MAX_COLUMN_NODES - 1, ...kept);
    } else {
      scored.sort((a, b) => a.mean - b.mean || rank(a, b));
    }
    byColumn[column] = scored.map((s) => s.p);
    byColumn[column].forEach((p, i) => order.set(p.machineKey, i));
  }

  const nodes: GraphNode[] = [];
  const nodeOf: Map<string, GraphNode> = new Map();
  let tallest = 0;
  ([0, 1, 2] as const).forEach((column) => {
    const all = byColumn[column];
    const shown = all.length > MAX_COLUMN_NODES ? all.slice(0, MAX_COLUMN_NODES - 1) : all;
    const rest = all.slice(shown.length);
    const count = shown.length + (rest.length > 0 ? 1 : 0);
    tallest = Math.max(tallest, count);
    shown.forEach((party) => {
      const node: GraphNode = { key: party.machineKey, column, x: xOf(column), y: 0, party, folded: [] };
      nodes.push(node);
      nodeOf.set(party.machineKey, node);
    });
    if (rest.length > 0) {
      const node: GraphNode = { key: `${FOLD_KEY}${column}`, column, x: xOf(column), y: 0, party: null, folded: rest };
      nodes.push(node);
      for (const p of rest) nodeOf.set(p.machineKey, node);
    }
  });
  const height = TOP + tallest * NODE_HEIGHT + Math.max(0, tallest - 1) * ROW_GAP + BOTTOM;
  ([0, 1, 2] as const).forEach((column) => {
    const mine = nodes.filter((n) => n.column === column);
    const block = mine.length * NODE_HEIGHT + Math.max(0, mine.length - 1) * ROW_GAP;
    const start = TOP + (height - TOP - BOTTOM - block) / 2;
    mine.forEach((n, i) => {
      n.y = start + i * (NODE_HEIGHT + ROW_GAP);
    });
  });

  // Arrows that end at one fold node merge into one arrow.
  interface Raw {
    source: GraphNode;
    target: GraphNode;
    runs: number;
    alerts: number | null;
    stage: CampaignStage | null;
    firstAt: string | null;
    lastAt: string | null;
    beyond: boolean;
    fromDocuments: boolean;
    related: boolean;
    port: number | null;
    ports: number[];
    documents: number;
  }
  const raw: Map<string, Raw> = new Map();
  const add = (key: string, next: Raw): void => {
    const held = raw.get(key);
    if (!held) {
      raw.set(key, next);
      return;
    }
    held.runs += next.runs;
    held.alerts = addCounts(held.alerts, next.alerts);
    held.documents += next.documents;
    for (const port of next.ports) if (!held.ports.includes(port)) held.ports.push(port);
    held.ports.sort((a, b) => a - b);
    held.stage = highestStage([held.stage, next.stage]);
    held.beyond = held.beyond || next.beyond;
    held.fromDocuments = held.fromDocuments && next.fromDocuments;
    if (next.firstAt && (!held.firstAt || next.firstAt < held.firstAt)) held.firstAt = next.firstAt;
    if (next.lastAt && (!held.lastAt || next.lastAt > held.lastAt)) held.lastAt = next.lastAt;
  };
  for (const e of edges) {
    const source = nodeOf.get(e.source);
    const target = nodeOf.get(e.target);
    if (!source || !target || source === target) continue;
    add(`run|${source.key}|${target.key}`, {
      source,
      target,
      runs: e.runs,
      // A server of an earlier release sends no alert count.
      alerts: typeof e.alerts === 'number' ? e.alerts : null,
      stage: e.stage,
      firstAt: e.firstAt,
      lastAt: e.lastAt,
      beyond: e.beyond,
      fromDocuments: e.fromDocuments,
      related: false,
      port: null,
      ports: [],
      documents: 0,
    });
  }
  for (const s of sessions) {
    const source = nodeOf.get(s.source.machineKey);
    const target = nodeOf.get(s.target.machineKey);
    if (!source || !target || source === target || s.port === null) continue;
    add(`session|${source.key}|${target.key}`, {
      source,
      target,
      runs: 0,
      alerts: null,
      stage: null,
      firstAt: s.firstAt,
      lastAt: s.lastAt,
      beyond: false,
      fromDocuments: false,
      related: true,
      port: s.port,
      ports: [s.port],
      documents: s.documents,
    });
  }

  // The width follows the alert events when one arrow of the graph has them,
  // else the investigations. An arrow with no alert event in a graph of
  // alerts is a hairline.
  const arrows = [...raw.values()].filter((r) => !r.related);
  const byAlerts = arrows.some((r) => (r.alerts ?? 0) > 0);
  const weight = (r: Raw): number => (byAlerts ? (r.alerts ?? 0) : r.runs);
  const most = Math.max(1, ...arrows.map(weight));
  // Each arrow takes its own place on the side of a node, in the order of the
  // rows at its other end, so the arrows of one node fan out and do not cross.
  const entries = [...raw.entries()].map(([key, r]) => ({ key, r }));
  // A related line has no place of its own when its two machines have an
  // arrow: it runs under that arrow.
  const pairKey = (r: Raw): string => `${r.source.key}|${r.target.key}`;
  const runPairs = new Set(entries.filter((e) => !e.r.related).map((e) => pairKey(e.r)));
  const placed = entries.filter((e) => !e.r.related || !runPairs.has(pairKey(e.r)));
  const slotOf = (side: 'out' | 'in'): Map<string, number> => {
    const out: Map<string, number> = new Map();
    const groups: Map<string, { key: string; r: Raw }[]> = new Map();
    for (const e of placed) {
      const node = side === 'out' ? e.r.source : e.r.target;
      const right = e.r.target.x >= e.r.source.x;
      const id = `${node.key}|${side === 'out' ? right : !right}`;
      groups.set(id, [...(groups.get(id) ?? []), e]);
    }
    for (const group of groups.values()) {
      group.sort((a, b) => {
        const ya = side === 'out' ? a.r.target.y : a.r.source.y;
        const yb = side === 'out' ? b.r.target.y : b.r.source.y;
        return ya - yb || a.key.localeCompare(b.key);
      });
      const room = NODE_HEIGHT - 10;
      group.forEach((e, i) => out.set(pairKey(e.r), 5 + (room * (i + 1)) / (group.length + 1)));
    }
    return out;
  };
  const outSlot = slotOf('out');
  const inSlot = slotOf('in');
  const links: GraphLink[] = [];
  for (const { key, r } of entries) {
    const forward = r.target.x >= r.source.x;
    const width = r.related ? 1.5 : linkWidth(weight(r), most);
    const size = r.related ? 0 : 7 + width;
    const x0 = forward ? r.source.x + NODE_WIDTH : r.source.x;
    // The arrow stops short of the node, so its head shows.
    const tip = forward ? r.target.x - HEAD_GAP : r.target.x + NODE_WIDTH + HEAD_GAP;
    const x1 = forward ? tip - size * 0.7 : tip + size * 0.7;
    // A related line under an arrow sits just below the widest arrow of the graph.
    const under = r.related && runPairs.has(pairKey(r)) ? linkWidth(most, most) / 2 + 4 : 0;
    const y0 = r.source.y + (outSlot.get(pairKey(r)) ?? NODE_HEIGHT / 2) + under;
    const y1 = r.target.y + (inSlot.get(pairKey(r)) ?? NODE_HEIGHT / 2) + under;
    const bend = Math.max(40, Math.abs(x1 - x0) * 0.45) * (forward ? 1 : -1);
    const back = forward ? tip - size : tip + size;
    links.push({
      key,
      ...r,
      width,
      path: `M ${x0} ${y0} C ${x0 + bend} ${y0}, ${x1 - bend} ${y1}, ${x1} ${y1}`,
      head: r.related ? '' : `${tip},${y1} ${back},${y1 - size * 0.5} ${back},${y1 + size * 0.5}`,
      labelX: (x0 + x1) / 2,
      labelY: (y0 + y1) / 2,
    });
  }
  // The related sessions draw first, under the arrows.
  links.sort((a, b) => Number(b.related) - Number(a.related) || a.key.localeCompare(b.key));
  return {
    width: inner,
    height,
    columns: ([0, 1, 2] as const)
      .map((column) => ({ column, x: xOf(column), count: byColumn[column].length }))
      .filter((c) => c.column < columnCount),
    nodes,
    links,
  };
}

// ── The timeline ───────────────────────────────────────────────────────────

/** One point of a lane: one bucket of alert events, or one investigation. */
export interface TimePoint {
  id: string;
  t: number;
  stage: CampaignStage | null;
  label: string;
  /** The events that the point stands for. One when absent. */
  count?: number;
}

export interface TimeCluster {
  key: string;
  x0: number;
  x1: number;
  t0: number;
  t1: number;
  points: TimePoint[];
  stage: CampaignStage | null;
  /** The sum of the counts of the points. */
  count: number;
}

/** The points of one lane as marks that do not overlap.
 *
 *  Two points closer than `gap` pixels join one mark: at the scale of
 *  nineteen days, the alerts of one evening are one mark with their sum. A
 *  closer scale splits it. `scale` maps a time in ms to a pixel. */
export function clusterPoints(
  points: readonly TimePoint[],
  scale: (t: number) => number,
  gap: number,
): TimeCluster[] {
  const sorted = [...points].sort((a, b) => a.t - b.t || a.id.localeCompare(b.id));
  const out: TimeCluster[] = [];
  for (const p of sorted) {
    const x = scale(p.t);
    const count = p.count ?? 1;
    const last = out[out.length - 1];
    if (last && x - last.x1 < gap) {
      last.x1 = x;
      last.t1 = p.t;
      last.points.push(p);
      last.stage = highestStage([last.stage, p.stage]);
      last.count += count;
    } else {
      out.push({ key: p.id, x0: x, x1: x, t0: p.t, t1: p.t, points: [p], stage: p.stage, count });
    }
  }
  return out;
}

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
/** The steps a time axis can take. */
export const TICK_STEPS: readonly number[] = [
  MINUTE,
  5 * MINUTE,
  15 * MINUTE,
  30 * MINUTE,
  HOUR,
  3 * HOUR,
  6 * HOUR,
  12 * HOUR,
  DAY,
  2 * DAY,
  7 * DAY,
  14 * DAY,
  28 * DAY,
];

/** The ticks of a time axis: at most `most` of them, on round UTC times.
 *
 *  A step fits when the round times it puts inside the period are no more
 *  than `most`. A period that starts on a round time holds one tick more than
 *  the span over the step, so the count is of the ticks themselves. A period
 *  longer than the largest step allows takes a multiple of that step. */
export function timeTicks(t0: number, t1: number, most = 8): { step: number; ticks: number[] } {
  const room = Math.max(1, Math.floor(most));
  const count = (s: number): number => Math.floor(t1 / s) - Math.ceil(t0 / s) + 1;
  let step = TICK_STEPS.find((s) => count(s) <= room);
  if (step === undefined) {
    const largest = TICK_STEPS[TICK_STEPS.length - 1];
    let k = Math.max(2, Math.floor((t1 - t0) / (largest * room)));
    while (count(largest * k) > room) k += 1;
    step = largest * k;
  }
  const ticks: number[] = [];
  for (let t = Math.ceil(t0 / step) * step; t <= t1; t += step) ticks.push(t);
  return { step, ticks };
}

function two(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

/** The label of a tick in UTC: the date for a step of a day and more, the date
 *  and the time at midnight, else the time. */
export function tickLabel(t: number, step: number): string {
  const d = new Date(t);
  const date = `${two(d.getUTCMonth() + 1)}-${two(d.getUTCDate())}`;
  const time = `${two(d.getUTCHours())}:${two(d.getUTCMinutes())}`;
  if (step >= DAY) return date;
  return time === '00:00' ? `${date} ${time}` : time;
}

/** The left gutter of a time chart of the campaign page: the lane names. */
export const TIMELINE_GUTTER = 148;
/** The space right of the plot of a time chart. */
export const TIMELINE_RIGHT = 20;
/** The least padding of a time axis on each side. */
const AXIS_PAD_MIN = 10 * MINUTE;

/** A time axis from `lo` to `hi` with room on each side: 3 percent of the
 *  period, and at least 10 minutes. The timeline and the hunt marks of the
 *  campaign page read the one rule. */
export function padDomain(lo: number, hi: number): [number, number] {
  const pad = Math.max((hi - lo) * 0.03, AXIS_PAD_MIN);
  return [lo - pad, hi + pad];
}

/** The changes that can start a campaign hunt: the formation, which the hunt
 *  of the seed lead answers, a higher stage, a new machine, a reopen by new
 *  activity and activity beyond an authorization. A reopen by an analyst and
 *  a revoke start no hunt. Oldest first. */
export function huntChanges(changes: readonly CampaignChange[]): CampaignChange[] {
  return changes
    .filter((c) => {
      if (Number.isNaN(Date.parse(c.at))) return false;
      if (c.type === 'reopened') return c.detail?.cause !== 'analyst' && c.detail?.cause !== 'revoked';
      return c.type === 'formed' || c.type === 'stage' || c.type === 'party' || c.type === 'beyond';
    })
    .sort((a, b) => Date.parse(a.at) - Date.parse(b.at) || a.id - b.id);
}

/** One investigation of a lane, at its event time. */
export interface LaneInvestigation {
  runId: string;
  t: number;
  stage: CampaignStage | null;
  label: string;
  /** A finding or a lead of a hunt. */
  finding: boolean;
}

/** One lane of the timeline: one machine. */
export interface TimelineLane {
  key: string;
  party: CampaignParty | null;
  /** One point for each bucket with alert events. The point sits at the
   *  middle of its bucket and counts its alerts. */
  points: TimePoint[];
  /** The highest stage of the alert investigations of the machine. */
  stage: CampaignStage | null;
  /** The investigations of the machine with an event time, oldest first. */
  investigations: LaneInvestigation[];
}

/** The length of one bucket of the timeline in ms. */
export function bucketMs(timeline: CampaignEvents['timeline'] | null | undefined): number {
  const seconds = timeline?.bucketSeconds;
  return typeof seconds === 'number' && seconds > 0 ? seconds * 1000 : 0;
}

/** The machine of the lane of an investigation. An alert on the answer of a
 *  server has the server as its source. It belongs to the lane of the actor. */
function laneKeyOf(m: CampaignMember): string | null {
  return m.direction === 'reverse' ? m.targetKey : m.sourceKey;
}

/** The lanes of the timeline: one for each machine with alert events in the
 *  buckets of `timeline`, the actors first, each in the order of its first
 *  event. A lane takes the investigations of its machine: the highest stage of
 *  the alerts gives the lane its stage, and the findings give a mark the stage
 *  they prove inside its span. A verdict that differs is in no lane. */
export function timelineLanes(
  timeline: CampaignEvents['timeline'] | null | undefined,
  members: readonly CampaignMember[],
  parties: readonly CampaignParty[],
): TimelineLane[] {
  const half = bucketMs(timeline) / 2;
  const partyOf = new Map(parties.map((p) => [p.machineKey, p]));
  const runsOf: Map<string, LaneInvestigation[]> = new Map();
  for (const m of members) {
    const key = laneKeyOf(m);
    if (m.verdictDiffers || !key || !m.eventAt) continue;
    const t = Date.parse(m.eventAt);
    if (Number.isNaN(t)) continue;
    const finding = m.kind === 'finding' || m.kind === 'lead';
    runsOf.set(key, [...(runsOf.get(key) ?? []), { runId: m.runId, t, stage: m.stage, label: m.label, finding }]);
  }
  const lanes: TimelineLane[] = [];
  for (const lane of timeline?.lanes ?? []) {
    const points: TimePoint[] = [];
    for (const b of lane.buckets ?? []) {
      const at = Date.parse(b.at);
      if (Number.isNaN(at) || !(b.alerts > 0)) continue;
      points.push({ id: `${lane.machineKey}|${b.at}`, t: at + half, stage: null, label: b.at, count: b.alerts });
    }
    if (points.length === 0) continue;
    const investigations = [...(runsOf.get(lane.machineKey) ?? [])].sort(
      (a, b) => a.t - b.t || a.runId.localeCompare(b.runId),
    );
    lanes.push({
      key: lane.machineKey,
      party: partyOf.get(lane.machineKey) ?? null,
      points,
      stage: highestStage(investigations.filter((r) => !r.finding).map((r) => r.stage)),
      investigations,
    });
  }
  const rank = (key: string): number => (partyOf.get(key)?.role === 'actor' ? 0 : partyOf.has(key) ? 1 : 2);
  return lanes.sort(
    (a, b) =>
      rank(a.key) - rank(b.key) ||
      Math.min(...a.points.map((p) => p.t)) - Math.min(...b.points.map((p) => p.t)) ||
      a.key.localeCompare(b.key),
  );
}

/** The time span of a mark: from the start of its first bucket to the end of
 *  its last bucket. */
export function markSpan(cluster: Pick<TimeCluster, 't0' | 't1'>, bucket: number): { from: number; to: number } {
  return { from: cluster.t0 - bucket / 2, to: cluster.t1 + bucket / 2 };
}

/** True when `t` is inside the span. The end is open, so two spans that
 *  touch do not share a time. A span of one instant holds that instant. */
export function insideSpan(t: number, span: { from: number; to: number }): boolean {
  return t >= span.from && (t < span.to || t === span.from);
}

/** The investigations of a lane inside a span, oldest first. */
export function investigationsIn(lane: Pick<TimelineLane, 'investigations'>, span: { from: number; to: number }): LaneInvestigation[] {
  return lane.investigations.filter((r) => insideSpan(r.t, span));
}

/** The color stage of a mark: the highest of the stage of the lane and of
 *  each finding of the lane inside the span. Null with neither: the gray of
 *  no proven stage. */
export function markStage(
  lane: Pick<TimelineLane, 'stage' | 'investigations'>,
  span: { from: number; to: number },
): CampaignStage | null {
  return highestStage([
    lane.stage,
    ...investigationsIn(lane, span)
      .filter((r) => r.finding)
      .map((r) => r.stage),
  ]);
}
