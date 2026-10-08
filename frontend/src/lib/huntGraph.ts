// ---------------------------------------------------------------------------
// The host and finding map on the hunt page, as data.
//
// The question the map answers: how do the entities in the findings connect,
// and which link does a threat finding sit on. So a finding is a node, every
// host it names is a node, and a line joins the two. A finding that names two
// hosts sits between them, on the link the analyst follows. A threat finding
// draws its lines in red. A host that several findings name grows, and a line
// grows with the documents its finding cites.
//
// The force layout puts hosts that share findings close together. The map draws
// every host up to MAX_MAP_HOSTS and says when it drew fewer.
// ---------------------------------------------------------------------------

import { entityHref, guessEntityType } from './entityPath';
import type { GraphEdgeView, GraphNodeView, GraphView, LegendItem } from './graphLayout';
import { wrapLabel } from './graphLayout';
import { isIpKey, isPrivateIp } from './ip';
import { sqrtScale } from './peerGraph';
import { SEVERITY } from './tokens';
import type { HuntFinding, Severity } from './types';

/** The most hosts the map draws. More than this would not read at any zoom. */
export const MAX_MAP_HOSTS = 150;

export const HUNT_COLOR = {
  gap: '#6b7484',
  observation: '#6b87a8',
  internal: '#7ba893',
  external: '#a78bfa',
  name: '#4b8bf5',
  unnamed: '#6b7484',
  threat: '#f04438',
  line: '#4a5869',
} as const;

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const sevKey = (s: string | undefined): Severity => {
  const k = (s || 'info').toLowerCase();
  return (k in SEVERITY ? k : 'info') as Severity;
};
const sevRank = (s: string) => {
  const i = SEV_ORDER.indexOf(s);
  return i === -1 ? SEV_ORDER.length : i;
};

type Category = 'threat' | 'visibility_gap' | 'observation';
const category = (f: HuntFinding): Category =>
  f.category === 'visibility_gap' || f.category === 'observation' ? f.category : 'threat';
const CATEGORY_WORD: Record<Category, string> = {
  threat: 'threat',
  visibility_gap: 'visibility gap',
  observation: 'observation',
};

const plural = (n: number, word: string) => `${n.toLocaleString()} ${word}${n === 1 ? '' : 's'}`;

type HostRole = 'internal' | 'external' | 'name';
function hostRole(h: string): HostRole {
  if (!isIpKey(h)) return 'name';
  return isPrivateIp(h) ? 'internal' : 'external';
}
const ROLE_WORD: Record<HostRole, string> = {
  internal: 'Internal address.',
  external: 'External address.',
  name: 'Host name.',
};

export interface HuntMap {
  view: GraphView;
  /** Findings the map draws. */
  findings: number;
  /** Hosts the map draws. */
  hosts: number;
  /** Hosts the cap left off the map. */
  hostsCut: number;
}

interface HostStat {
  host: string;
  count: number;
  threats: number;
  worst: string;
}

export function findingNodeId(i: number): string {
  return `finding:${i}`;
}
export function hostNodeId(h: string): string {
  return `host:${h}`;
}

export function huntGraphView(findings: HuntFinding[], affectedHosts: string[] = []): HuntMap {
  const stats = new Map<string, HostStat>();
  for (const f of findings) {
    const sev = sevKey(f.severity);
    for (const h of new Set(f.hosts)) {
      const s = stats.get(h) ?? { host: h, count: 0, threats: 0, worst: sev };
      s.count += 1;
      if (category(f) === 'threat') s.threats += 1;
      if (sevRank(sev) < sevRank(s.worst)) s.worst = sev;
      stats.set(h, s);
    }
  }
  for (const h of affectedHosts) {
    if (!stats.has(h)) stats.set(h, { host: h, count: 0, threats: 0, worst: 'info' });
  }

  const ranked = [...stats.values()].sort(
    (a, b) => b.count - a.count || b.threats - a.threats || a.host.localeCompare(b.host),
  );
  const drawn = ranked.slice(0, MAX_MAP_HOSTS);
  const hostsCut = ranked.length - drawn.length;
  const empty: HuntMap = {
    view: { nodes: [], edges: [], legend: [], layout: { mode: 'force' } },
    findings: findings.length,
    hosts: 0,
    hostsCut: 0,
  };
  // No host to map: the panel says so in words.
  if (drawn.length === 0) return empty;
  const onMap = new Set(drawn.map((s) => s.host));

  const maxCount = drawn.reduce((m, s) => Math.max(m, s.count), 0);
  const maxCites = findings.reduce((m, f) => Math.max(m, f.citations.length), 0);

  const nodes: GraphNodeView[] = [];
  const edges: GraphEdgeView[] = [];

  findings.forEach((f, i) => {
    const sev = sevKey(f.severity);
    const cat = category(f);
    const color =
      cat === 'threat' ? SEVERITY[sev].color : cat === 'visibility_gap' ? HUNT_COLOR.gap : HUNT_COLOR.observation;
    const hosts = [...new Set(f.hosts)];
    nodes.push({
      id: findingNodeId(i),
      glyph: `F${i + 1}`,
      shape: 'square',
      size: 30,
      color,
      lines: [
        ...wrapLabel(f.title || `Finding ${i + 1}`, 26).map((text) => ({ text, tone: 'primary' as const })),
        { text: `${sev} · ${CATEGORY_WORD[cat]}`, tone: cat === 'threat' ? ('threat' as const) : ('secondary' as const) },
      ],
      dim: !hosts.some((h) => onMap.has(h)),
      tooltip: [
        `F${i + 1}: ${f.title}`,
        `${SEVERITY[sev].label} severity. Category: ${CATEGORY_WORD[cat]}.`,
        hosts.length ? `Names ${plural(hosts.length, 'host')}: ${hosts.join(', ')}.` : 'Names no host.',
        `Cites ${plural(f.citations.length, 'document')}.`,
      ],
    });
    for (const h of hosts) {
      if (!onMap.has(h)) continue;
      edges.push({
        id: `${findingNodeId(i)}->${h}`,
        source: findingNodeId(i),
        target: hostNodeId(h),
        width: maxCites > 0 ? sqrtScale(f.citations.length, maxCites, 1.5, 5) : 2,
        color: cat === 'threat' ? HUNT_COLOR.threat : HUNT_COLOR.line,
        threat: cat === 'threat',
        arrows: 'none',
        tooltip: [
          `F${i + 1} names ${h}.`,
          `${SEVERITY[sev].label} ${CATEGORY_WORD[cat]}.`,
          `The finding cites ${plural(f.citations.length, 'document')}.`,
        ],
      });
    }
  });

  for (const s of drawn) {
    const role = hostRole(s.host);
    const named = s.count > 0;
    nodes.push({
      id: hostNodeId(s.host),
      shape: 'circle',
      size: named ? sqrtScale(s.count, maxCount, 18, 40) : 16,
      color: named ? HUNT_COLOR[role] : HUNT_COLOR.unnamed,
      dim: !named,
      lines: [
        { text: s.host, tone: 'primary' },
        { text: named ? plural(s.count, 'finding') : 'no finding names it', tone: 'secondary' },
      ],
      href: entityHref(s.host, guessEntityType(s.host)),
      tooltip: named
        ? [
            s.host,
            ROLE_WORD[role],
            `Named in ${plural(s.count, 'finding')}.`,
            ...(s.threats ? [`Named in ${plural(s.threats, 'threat finding')}.`] : []),
            `Worst severity: ${s.worst}.`,
            'Click to open its page.',
          ]
        : [s.host, 'The hunt marked this host affected. No finding names it.', 'Click to open its page.'],
    });
  }

  const legend: LegendItem[] = [];
  const cats = new Set(findings.map(category));
  if (cats.has('threat')) {
    legend.push({ kind: 'node', label: 'threat finding · severity colour', color: SEVERITY.high.color, shape: 'square' });
  }
  if (cats.has('visibility_gap')) {
    legend.push({ kind: 'node', label: 'visibility gap', color: HUNT_COLOR.gap, shape: 'square' });
  }
  if (cats.has('observation')) {
    legend.push({ kind: 'node', label: 'observation', color: HUNT_COLOR.observation, shape: 'square' });
  }
  const roles = new Set(drawn.filter((s) => s.count > 0).map((s) => hostRole(s.host)));
  if (roles.has('internal')) legend.push({ kind: 'node', label: 'internal address', color: HUNT_COLOR.internal, shape: 'circle' });
  if (roles.has('external')) legend.push({ kind: 'node', label: 'external address', color: HUNT_COLOR.external, shape: 'circle' });
  if (roles.has('name')) legend.push({ kind: 'node', label: 'host name', color: HUNT_COLOR.name, shape: 'circle' });
  if (drawn.some((s) => s.count === 0)) {
    legend.push({ kind: 'node', label: 'affected, no finding names it', color: HUNT_COLOR.unnamed, shape: 'circle' });
  }
  if (edges.some((e) => e.threat)) {
    legend.push({ kind: 'line', label: 'a threat finding names this host', color: HUNT_COLOR.threat, width: 2.5 });
  }
  legend.push({ kind: 'note', label: 'Host size: findings that name it' });
  legend.push({ kind: 'note', label: 'Line width: documents the finding cites' });

  return {
    view: { nodes, edges, legend, layout: { mode: 'force' } },
    findings: findings.length,
    hosts: drawn.length,
    hostsCut,
  };
}
