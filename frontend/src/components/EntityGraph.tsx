// Reusable, prop-driven entity/network graph (Investigation blast-radius +
// Hunt detail). Recreated as React SVG per the prototype's coordinate math:
//   viewBox 0 0 600 H, margins 46×30; px = 46 + x/100*(600-92), py = 30 + y/100*(H-60)

import type { EdgeKind, EntityKind, GraphEdge, GraphNode } from '../lib/types';

interface EntityGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  highlight?: string;
  height?: number;
  showLegend?: boolean;
}

interface NodeStyle {
  c: string;
  r: number;
  square: boolean;
  pulse?: boolean;
}
const NODE_STYLE: Record<EntityKind, NodeStyle> = {
  compromised: { c: '#f04438', r: 20, square: false, pulse: true },
  c2: { c: '#e0a83a', r: 16, square: false },
  internal: { c: '#7ba893', r: 17, square: true },
  host: { c: '#4b8bf5', r: 12, square: false },
};

interface EdgeStyle {
  c: string;
  w: number;
  dash: string;
  anim: boolean;
}
const EDGE_STYLE: Record<EdgeKind, EdgeStyle> = {
  beacon: { c: '#e0a83a', w: 2, dash: '5 5', anim: true },
  lateral: { c: '#f04438', w: 3, dash: '6 5', anim: true },
  // flow was #242c39 (the border token) — near-invisible against the panel bg;
  // same neutral-gray language, one step brighter so the baseline edges read.
  flow: { c: '#2a3645', w: 1.5, dash: '0', anim: false },
  enrich: { c: '#4b8bf5', w: 1.8, dash: '4 4', anim: true },
};

const LEGEND: Record<EntityKind, { c: string; label: string; radius: string }> = {
  compromised: { c: '#f04438', label: 'compromised', radius: '50%' },
  c2: { c: '#e0a83a', label: 'C2 / external', radius: '50%' },
  internal: { c: '#7ba893', label: 'internal host', radius: '2px' },
  host: { c: '#4b8bf5', label: 'host', radius: '50%' },
};

// truncate for the on-canvas text; the full value stays in the hover <title>
const clip = (s: string, max: number) => (s.length > max ? s.slice(0, max - 1) + '…' : s);

export function EntityGraph({ nodes, edges, height = 320, showLegend = true }: EntityGraphProps) {
  const VW = 600;
  const VH = height;
  const mx = 46;
  const my = 30;
  const px = (x: number) => mx + (x / 100) * (VW - 2 * mx);
  const py = (y: number) => my + (y / 100) * (VH - 2 * my);
  const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));

  const presentKinds = [...new Set(nodes.map((n) => n.kind))];
  const anyFlagged = nodes.some((n) => n.flagged);

  return (
    <div className="font-sans">
      <div
        className="relative"
        style={{
          background:
            'radial-gradient(60% 70% at 32% 42%,rgba(240,68,56,.06),transparent 72%)',
        }}
      >
        <svg
          viewBox={`0 0 ${VW} ${VH}`}
          width="100%"
          style={{ height: 'auto', display: 'block' }}
          preserveAspectRatio="xMidYMid meet"
        >
          {/* one arrowhead per edge kind so flow direction reads at a glance */}
          <defs>
            {(Object.entries(EDGE_STYLE) as [EdgeKind, EdgeStyle][]).map(([k, s]) => (
              <marker
                key={k}
                id={`eg-arrow-${k}`}
                viewBox="0 0 8 8"
                refX={7}
                refY={4}
                markerWidth={8}
                markerHeight={8}
                markerUnits="userSpaceOnUse"
                orient="auto"
              >
                <path d="M0 0 L8 4 L0 8 Z" fill={s.c} />
              </marker>
            ))}
          </defs>
          {/* edges first */}
          {edges.map((e, i) => {
            const a = byId[e.from];
            const b = byId[e.to];
            if (!a || !b) return null;
            const es = EDGE_STYLE[e.kind];
            const x1 = px(a.x);
            const y1 = py(a.y);
            const x2 = px(b.x);
            const y2 = py(b.y);
            // pull the visible end back to the target's rim so the arrowhead
            // lands on the node edge instead of vanishing under it
            const tr = (NODE_STYLE[b.kind] ?? NODE_STYLE.host).r;
            const d = Math.hypot(x2 - x1, y2 - y1) || 1;
            const ex = x2 - ((x2 - x1) / d) * (tr + 5);
            const ey = y2 - ((y2 - y1) / d) * (tr + 5);
            const cx = (x1 + ex) / 2;
            const cy = (y1 + ey) / 2;
            return (
              <g key={'e' + i}>
                <title>{`${e.from} → ${e.to}${e.label ? ` · ${e.label}` : ''}`}</title>
                <line
                  x1={x1}
                  y1={y1}
                  x2={ex}
                  y2={ey}
                  stroke={es.c}
                  strokeWidth={es.w}
                  strokeDasharray={es.dash}
                  opacity={e.kind === 'flow' ? 0.7 : 0.92}
                  markerEnd={`url(#eg-arrow-${e.kind})`}
                  style={es.anim ? { animation: 'dash .6s linear infinite' } : undefined}
                />
                {e.label && (
                  <text
                    x={cx}
                    y={cy - 5}
                    fill={e.kind === 'flow' ? '#5b6473' : es.c}
                    fontSize={9}
                    fontFamily="JetBrains Mono, monospace"
                    textAnchor="middle"
                    fontWeight={e.kind === 'lateral' ? 600 : 400}
                  >
                    {clip(e.label, 20)}
                  </text>
                )}
              </g>
            );
          })}
          {/* nodes */}
          {nodes.map((n, i) => {
            const ns = NODE_STYLE[n.kind] ?? NODE_STYLE.host;
            const x = px(n.x);
            const y = py(n.y);
            // right-column peers stack tightly — put their two text lines beside
            // the node; the lone left (source) node keeps its label underneath
            const side = n.x >= 60;
            const tip = [
              `${n.id} — ${LEGEND[n.kind]?.label ?? n.kind}`,
              n.sub,
              n.flagged
                ? `flagged by: ${(n.flagSources ?? []).join(', ') || 'threat intel'}`
                : null,
            ]
              .filter(Boolean)
              .join('\n');
            return (
              <g key={'n' + i}>
                <title>{tip}</title>
                {ns.pulse && (
                  <circle
                    cx={x}
                    cy={y}
                    r={ns.r + 10}
                    fill="none"
                    stroke={ns.c}
                    strokeWidth={1}
                    opacity={0.4}
                    style={{ animation: 'pulseRing 2s infinite' }}
                  />
                )}
                {ns.square ? (
                  <>
                    <rect x={x - ns.r} y={y - ns.r} width={ns.r * 2} height={ns.r * 2} rx={4} fill="#0b0e13" stroke={ns.c} strokeWidth={2} />
                    <rect x={x - ns.r + 5} y={y - ns.r + 5} width={ns.r * 2 - 10} height={ns.r * 2 - 10} rx={2} fill={ns.c} opacity={0.22} />
                  </>
                ) : (
                  <>
                    <circle cx={x} cy={y} r={ns.r} fill="#0b0e13" stroke={ns.c} strokeWidth={2} />
                    <circle cx={x} cy={y} r={ns.r - 4} fill={ns.c} opacity={0.22} />
                  </>
                )}
                {/* flagged-by-intel badge (blocklist/MISP hit); sources in the tooltip */}
                {n.flagged && (
                  <g>
                    <circle cx={x + ns.r * 0.8} cy={y - ns.r * 0.8} r={6} fill="#f04438" stroke="#0b0e13" strokeWidth={1.5} />
                    <text x={x + ns.r * 0.8} y={y - ns.r * 0.8 + 2.8} fill="#fff" fontSize={8.5} fontWeight={700} fontFamily="JetBrains Mono, monospace" textAnchor="middle">
                      !
                    </text>
                  </g>
                )}
                {side ? (
                  <>
                    <text x={x + ns.r + 9} y={n.sub ? y - 1 : y + 3} fill="#8b94a3" fontSize={9.5} fontFamily="JetBrains Mono, monospace">
                      {clip(n.label, 20)}
                    </text>
                    {n.sub && (
                      <text x={x + ns.r + 9} y={y + 10} fill="#5b6473" fontSize={8.5} fontFamily="JetBrains Mono, monospace">
                        {clip(n.sub, 24)}
                      </text>
                    )}
                  </>
                ) : (
                  <>
                    <text x={x} y={y + ns.r + 13} fill="#8b94a3" fontSize={9.5} fontFamily="JetBrains Mono, monospace" textAnchor="middle">
                      {clip(n.label, 22)}
                    </text>
                    {n.sub && (
                      <text x={x} y={y + ns.r + 24} fill="#5b6473" fontSize={8.5} fontFamily="JetBrains Mono, monospace" textAnchor="middle">
                        {clip(n.sub, 26)}
                      </text>
                    )}
                  </>
                )}
              </g>
            );
          })}
        </svg>
      </div>
      {showLegend && (
        <div className="flex flex-wrap gap-4 border-t border-border px-3.5 py-[9px] font-mono text-[11px] text-dim">
          {presentKinds.map((k) => {
            const l = LEGEND[k];
            if (!l) return null;
            return (
              <span key={k} className="flex items-center gap-1.5">
                <span className="h-[9px] w-[9px]" style={{ background: l.c, borderRadius: l.radius }} />
                {l.label}
              </span>
            );
          })}
          {anyFlagged && (
            <span className="flex items-center gap-1.5">
              <span className="flex h-[11px] w-[11px] items-center justify-center rounded-full bg-danger text-[8px] font-bold leading-none text-white">
                !
              </span>
              flagged by intel
            </span>
          )}
        </div>
      )}
    </div>
  );
}
