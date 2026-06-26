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
  dc: { c: '#7ba893', r: 17, square: true },
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
  flow: { c: '#242c39', w: 1.5, dash: '0', anim: false },
  enrich: { c: '#4b8bf5', w: 1.8, dash: '4 4', anim: true },
};

const LEGEND: Record<EntityKind, { c: string; label: string; radius: string }> = {
  compromised: { c: '#f04438', label: 'compromised', radius: '50%' },
  c2: { c: '#e0a83a', label: 'C2 / external', radius: '50%' },
  dc: { c: '#7ba893', label: 'domain controller', radius: '2px' },
  host: { c: '#4b8bf5', label: 'host', radius: '50%' },
};

export function EntityGraph({ nodes, edges, height = 320, showLegend = true }: EntityGraphProps) {
  const VW = 600;
  const VH = height;
  const mx = 46;
  const my = 30;
  const px = (x: number) => mx + (x / 100) * (VW - 2 * mx);
  const py = (y: number) => my + (y / 100) * (VH - 2 * my);
  const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));

  const presentKinds = [...new Set(nodes.map((n) => n.kind))];

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
          {/* edges first */}
          {edges.map((e, i) => {
            const a = byId[e.from];
            const b = byId[e.to];
            if (!a || !b) return null;
            const es = EDGE_STYLE[e.kind];
            const cx = (px(a.x) + px(b.x)) / 2;
            const cy = (py(a.y) + py(b.y)) / 2;
            return (
              <g key={'e' + i}>
                <line
                  x1={px(a.x)}
                  y1={py(a.y)}
                  x2={px(b.x)}
                  y2={py(b.y)}
                  stroke={es.c}
                  strokeWidth={es.w}
                  strokeDasharray={es.dash}
                  opacity={e.kind === 'flow' ? 0.7 : 0.92}
                  style={es.anim ? { animation: 'dash .6s linear infinite' } : undefined}
                />
                {e.label && (
                  <text
                    x={cx}
                    y={cy - 5}
                    fill={es.c}
                    fontSize={9.5}
                    fontFamily="JetBrains Mono, monospace"
                    textAnchor="middle"
                    fontWeight={e.kind === 'lateral' ? 600 : 400}
                  >
                    {e.label}
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
            return (
              <g key={'n' + i}>
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
                <text x={x} y={y + ns.r + 13} fill="#8b94a3" fontSize={9.5} fontFamily="JetBrains Mono, monospace" textAnchor="middle">
                  {n.label}
                </text>
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
        </div>
      )}
    </div>
  );
}
