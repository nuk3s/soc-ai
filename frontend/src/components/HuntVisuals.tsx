// Deterministic "Visual summary" for a concluded hunt: a findings-by-severity
// breakdown, a host-involvement chart, and a dependency-free SVG map linking
// findings to the hosts they name (EntityGraph's visual language). Pure
// presentational — every aggregation is computed here from the findings the
// page already fetched; the parent only mounts this when the hunt is complete
// AND has findings, so a chart can never render from nothing.

import { BarChart3, LineChart as LineChartIcon, Network, Server } from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  type TooltipProps,
  XAxis,
  YAxis,
} from 'recharts';
import { useNavigate } from 'react-router-dom';
import type { HuntChart, HuntFinding } from '../lib/types';
import { Panel, PanelHeader } from './Panel';

// Hunt severity palette — mirrors HuntDetail's SEV_COLOR. Ordered worst-first
// so rank 0 = critical (chart rows + "worst severity" both read top-down).
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_COLOR: Record<string, string> = {
  critical: '#f85149',
  high: '#f0883e',
  medium: '#d29922',
  low: '#3fb950',
  info: '#8b949e',
};

// Category colors for the stacked breakdown: only 'threat' segments carry the
// severity color — gaps and observations stay deliberately muted so a wall of
// coverage statements never reads as red.
const GAP_COLOR = '#6b7484'; // verdict-untriaged grey
const OBS_COLOR = '#6b87a8'; // sev-low dim blue

const sevKey = (s: string | undefined): string => {
  const k = (s || 'info').toLowerCase();
  return k in SEV_COLOR ? k : 'info';
};
const sevRank = (s: string): number => SEV_ORDER.indexOf(s);

// truncate for axis/canvas text; the full value stays in the hover tooltip
const clip = (s: string, max: number) => (s.length > max ? s.slice(0, max - 1) + '…' : s);

// recharts defaults assume a light theme — style ticks/axes/tooltips
// explicitly against the dark surface tokens.
const TICK = { fill: '#8b94a3', fontSize: 11 };
const MONO_TICK = { fill: '#8b94a3', fontSize: 10.5, fontFamily: 'JetBrains Mono, monospace' };
const AXIS_LINE = { stroke: '#1c232e' };
const CURSOR = { fill: 'rgba(255,255,255,.04)' };
const TIP_BOX =
  'rounded-control border border-border-strong bg-surface-card px-2.5 py-2 text-[12px] shadow-dropdown';

// legend row shared by the panels (EntityGraph's legend treatment)
function LegendRow({ items }: { items: { swatch: string; round?: boolean; label: string }[] }) {
  return (
    <div className="flex flex-wrap gap-4 border-t border-border px-3.5 py-[9px] font-mono text-[11px] text-dim">
      {items.map((it) => (
        <span key={it.label} className="flex items-center gap-1.5">
          <span
            className="h-[9px] w-[9px]"
            style={{ background: it.swatch, borderRadius: it.round ? '50%' : '2px' }}
          />
          {it.label}
        </span>
      ))}
    </div>
  );
}

// ── Findings breakdown (severity × category) ────────────────────────────────

interface BreakdownRow {
  severity: string;
  threat: number;
  visibility_gap: number;
  observation: number;
}

function breakdownRows(findings: HuntFinding[]): BreakdownRow[] {
  const bySev: Record<string, BreakdownRow> = {};
  for (const f of findings) {
    const sev = sevKey(f.severity);
    const row = (bySev[sev] ??= { severity: sev, threat: 0, visibility_gap: 0, observation: 0 });
    // old reports may predate the category field — the backend defaults 'threat'
    const cat = f.category ?? 'threat';
    if (cat === 'visibility_gap') row.visibility_gap += 1;
    else if (cat === 'observation') row.observation += 1;
    else row.threat += 1;
  }
  // one bar per severity actually present, ordered critical → info
  return SEV_ORDER.filter((s) => bySev[s]).map((s) => bySev[s]);
}

function BreakdownTip({ active, payload }: TooltipProps<number, string>) {
  if (!active || !payload?.length) return null;
  const row = payload[0].payload as BreakdownRow;
  const color = SEV_COLOR[row.severity] ?? SEV_COLOR.info;
  const items: [string, number, string][] = [
    ['threat', row.threat, color],
    ['visibility gap', row.visibility_gap, GAP_COLOR],
    ['observation', row.observation, OBS_COLOR],
  ];
  return (
    <div className={TIP_BOX}>
      <div className="mb-1 font-semibold uppercase tracking-[.04em]" style={{ color }}>
        {row.severity}
      </div>
      {items
        .filter(([, n]) => n > 0)
        .map(([label, n, c]) => (
          <div key={label} className="flex items-center gap-1.5 text-text-2">
            <span className="h-[8px] w-[8px] rounded-[2px]" style={{ background: c }} />
            {label}
            <span className="ml-auto pl-3 font-mono text-dim">{n}</span>
          </div>
        ))}
    </div>
  );
}

function BreakdownChart({ rows }: { rows: BreakdownRow[] }) {
  return (
    <ResponsiveContainer width="100%" height={Math.max(rows.length * 38 + 26, 100)}>
      <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 18, bottom: 0, left: 4 }}>
        <XAxis type="number" allowDecimals={false} tick={TICK} axisLine={AXIS_LINE} tickLine={false} />
        <YAxis
          type="category"
          dataKey="severity"
          width={62}
          tick={TICK}
          axisLine={AXIS_LINE}
          tickLine={false}
        />
        <Tooltip cursor={CURSOR} content={<BreakdownTip />} isAnimationActive={false} />
        {/* threat segments take the row's severity color; the muted categories
            keep one fixed color each (no default recharts palette anywhere) */}
        <Bar dataKey="threat" stackId="cat" isAnimationActive={false}>
          {rows.map((r) => (
            <Cell key={r.severity} fill={SEV_COLOR[r.severity] ?? SEV_COLOR.info} />
          ))}
        </Bar>
        <Bar dataKey="visibility_gap" stackId="cat" fill={GAP_COLOR} isAnimationActive={false} />
        <Bar dataKey="observation" stackId="cat" fill={OBS_COLOR} isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer>
  );
}

// ── Host involvement ─────────────────────────────────────────────────────────

interface HostRow {
  host: string;
  /** how many findings name this host */
  count: number;
  /** worst severity among the findings naming it */
  worst: string;
}

function hostRows(findings: HuntFinding[]): HostRow[] {
  const byHost: Record<string, HostRow> = {};
  for (const f of findings) {
    const sev = sevKey(f.severity);
    for (const h of f.hosts) {
      const row = (byHost[h] ??= { host: h, count: 0, worst: sev });
      row.count += 1;
      if (sevRank(sev) < sevRank(row.worst)) row.worst = sev;
    }
  }
  // top 8 by involvement; severity then name break ties so the cut is stable
  return Object.values(byHost)
    .sort(
      (a, b) =>
        b.count - a.count || sevRank(a.worst) - sevRank(b.worst) || a.host.localeCompare(b.host),
    )
    .slice(0, 8);
}

function HostTip({ active, payload }: TooltipProps<number, string>) {
  if (!active || !payload?.length) return null;
  const row = payload[0].payload as HostRow;
  const color = SEV_COLOR[row.worst] ?? SEV_COLOR.info;
  return (
    <div className={TIP_BOX}>
      <div className="mb-0.5 font-mono text-mono-amber">{row.host}</div>
      <div className="text-text-2">
        named in {row.count} finding{row.count === 1 ? '' : 's'}
      </div>
      <div className="flex items-center gap-1.5 text-dim">
        worst severity
        <span className="font-semibold uppercase tracking-[.04em]" style={{ color }}>
          {row.worst}
        </span>
      </div>
    </div>
  );
}

function HostChart({ rows }: { rows: HostRow[] }) {
  return (
    <ResponsiveContainer width="100%" height={Math.max(rows.length * 32 + 26, 90)}>
      <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 18, bottom: 0, left: 4 }}>
        <XAxis type="number" allowDecimals={false} tick={TICK} axisLine={AXIS_LINE} tickLine={false} />
        <YAxis
          type="category"
          dataKey="host"
          width={118}
          tick={MONO_TICK}
          tickFormatter={(h: string) => clip(h, 16)}
          axisLine={AXIS_LINE}
          tickLine={false}
        />
        <Tooltip cursor={CURSOR} content={<HostTip />} isAnimationActive={false} />
        <Bar dataKey="count" barSize={14} radius={[0, 3, 3, 0]} isAnimationActive={false}>
          {rows.map((r) => (
            <Cell key={r.host} fill={SEV_COLOR[r.worst] ?? SEV_COLOR.info} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

// ── Host–finding map (dependency-free SVG, EntityGraph's visual language) ────

function HostFindingMap({ findings, hosts }: { findings: HuntFinding[]; hosts: HostRow[] }) {
  const navigate = useNavigate();
  const VW = 600;
  const mx = 46;
  const my = 26;
  const rows = Math.max(findings.length, hosts.length);
  const VH = Math.max(rows * 34 + 2 * my, 150);
  // even vertical spacing per column — counts are small (findings ≤ ~10,
  // hosts ≤ 8 after the top-8 cut), so no layout engine is needed
  const yAt = (i: number, n: number) => (n === 1 ? VH / 2 : my + (i / (n - 1)) * (VH - 2 * my));
  const FX = mx + 144; // finding column (labels to the left)
  const HX = VW - mx - 134; // host column (labels to the right)
  const hostIdx: Record<string, number> = Object.fromEntries(hosts.map((h, i) => [h.host, i]));

  const edges: { fi: number; hi: number }[] = [];
  findings.forEach((f, fi) => {
    for (const h of f.hosts) {
      const hi = hostIdx[h];
      if (hi !== undefined) edges.push({ fi, hi });
    }
  });

  return (
    <div className="font-sans">
      <svg
        viewBox={`0 0 ${VW} ${VH}`}
        width="100%"
        style={{ height: 'auto', display: 'block' }}
        preserveAspectRatio="xMidYMid meet"
      >
        {/* edges first so nodes draw over them */}
        {edges.map((e, i) => {
          const sev = sevKey(findings[e.fi].severity);
          return (
            <g key={'e' + i}>
              <title>{`F${e.fi + 1} → ${hosts[e.hi].host}`}</title>
              <line
                x1={FX + 12}
                y1={yAt(e.fi, findings.length)}
                x2={HX - 13}
                y2={yAt(e.hi, hosts.length)}
                stroke={SEV_COLOR[sev] ?? SEV_COLOR.info}
                strokeWidth={1.5}
                opacity={0.45}
              />
            </g>
          );
        })}
        {/* finding nodes — small severity squares, numbered F1/F2/…; a finding
            with no hosts simply sits unlinked in the column */}
        {findings.map((f, i) => {
          const sev = sevKey(f.severity);
          const c = SEV_COLOR[sev] ?? SEV_COLOR.info;
          const y = yAt(i, findings.length);
          const tip = [
            `F${i + 1} — ${f.title}`,
            `${sev} · ${f.category ?? 'threat'}`,
            f.hosts.length ? `hosts: ${f.hosts.join(', ')}` : 'no hosts named',
          ].join('\n');
          return (
            <g key={'f' + i}>
              <title>{tip}</title>
              <rect x={FX - 9} y={y - 9} width={18} height={18} rx={4} fill="#0b0e13" stroke={c} strokeWidth={2} />
              <rect x={FX - 5} y={y - 5} width={10} height={10} rx={2} fill={c} opacity={0.22} />
              <text x={FX} y={y + 3} fill={c} fontSize={8} fontWeight={700} fontFamily="JetBrains Mono, monospace" textAnchor="middle">
                F{i + 1}
              </text>
              <text x={FX - 17} y={y + 3} fill="#8b94a3" fontSize={9.5} fontFamily="JetBrains Mono, monospace" textAnchor="end">
                {clip(f.title, 24)}
              </text>
            </g>
          );
        })}
        {/* host nodes — circles, mono label; a count-0 host (affected but never
            named by a finding) renders dim + unlinked */}
        {hosts.map((h, i) => {
          const c = h.count > 0 ? '#4b8bf5' : '#6b7484';
          const y = yAt(i, hosts.length);
          const tip =
            h.count > 0
              ? `${h.host}\nnamed in ${h.count} finding${h.count === 1 ? '' : 's'} · worst ${h.worst}`
              : `${h.host}\naffected host — no finding names it`;
          return (
            // Clicking a host node pivots to its entity page (what we know about
            // this box). SVG <g> takes onClick; cursor signals it's interactive.
            <g
              key={'h' + i}
              onClick={() => navigate(`/entity/${encodeURIComponent(h.host)}`)}
              style={{ cursor: 'pointer' }}
            >
              <title>{tip}</title>
              <circle cx={HX} cy={y} r={10} fill="#0b0e13" stroke={c} strokeWidth={2} />
              <circle cx={HX} cy={y} r={6} fill={c} opacity={0.22} />
              <text x={HX + 19} y={y + 3} fill="#8b94a3" fontSize={9.5} fontFamily="JetBrains Mono, monospace">
                {clip(h.host, 18)}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// ── Agent-authored charts (E3.3) ─────────────────────────────────────────────
// The model may emit a numeric series a deterministic chart can't guess (a
// beacon-interval histogram, bytes-over-time) — but only charts whose citations
// resolved to gathered evidence reach us (the backend gate drops the rest). We
// still guard against an empty series here so a chart never renders from nothing.
// No default recharts palette: one fixed accent per chart, styled to the panels.

// small fixed palette (accent-blue lead, then muted supporting tones) — mirrors
// the file's SEV/accent language without recharts' rainbow default
const AGENT_CHART_COLORS = ['#4b8bf5', '#3fb950', '#d29922', '#a371f7', '#6b87a8'];

function AgentChartTip({ active, payload, label }: TooltipProps<number, string>) {
  if (!active || !payload?.length) return null;
  const v = payload[0].value;
  return (
    <div className={TIP_BOX}>
      <div className="mb-0.5 font-mono text-mono-amber">{String(label)}</div>
      <div className="font-mono text-text-2">{typeof v === 'number' ? v : String(v ?? '')}</div>
    </div>
  );
}

function AgentChart({ chart, color }: { chart: HuntChart; color: string }) {
  // recharts wants {x,y} rows; x is the category/time axis, y the value.
  const data = chart.series.map((p) => ({ x: p.x, y: p.y }));
  const isBar = chart.kind === 'bar';
  const height = 190;
  const common = (
    <>
      <CartesianGrid stroke="#1c232e" vertical={false} />
      <XAxis
        dataKey="x"
        tick={MONO_TICK}
        tickFormatter={(x: string) => clip(String(x), 12)}
        axisLine={AXIS_LINE}
        tickLine={false}
        interval="preserveStartEnd"
        minTickGap={14}
      />
      <YAxis
        tick={TICK}
        axisLine={AXIS_LINE}
        tickLine={false}
        width={44}
        label={
          chart.yLabel
            ? { value: clip(chart.yLabel, 22), angle: -90, position: 'insideLeft', fill: '#8b94a3', fontSize: 10.5 }
            : undefined
        }
      />
      <Tooltip cursor={CURSOR} content={<AgentChartTip />} isAnimationActive={false} />
    </>
  );
  return (
    <Panel>
      <PanelHeader
        icon={isBar ? <BarChart3 size={15} /> : <LineChartIcon size={15} />}
        title={
          // Machine-generated chart titles run long — two lines before the
          // ellipsis; the tooltip carries the full text.
          <span className="line-clamp-2" title={chart.title || 'Chart'}>
            {chart.title || 'Chart'}
          </span>
        }
        right={<span className="font-mono text-[11px] text-accent">{data.length}</span>}
      />
      <div className="px-2 pb-1 pt-3">
        <ResponsiveContainer width="100%" height={height}>
          {isBar ? (
            <BarChart data={data} margin={{ top: 4, right: 14, bottom: 2, left: 0 }}>
              {common}
              <Bar dataKey="y" fill={color} radius={[3, 3, 0, 0]} isAnimationActive={false} />
            </BarChart>
          ) : (
            // line + timeline both render as a value-over-x line
            <LineChart data={data} margin={{ top: 4, right: 14, bottom: 2, left: 0 }}>
              {common}
              <Line
                type="monotone"
                dataKey="y"
                stroke={color}
                strokeWidth={1.75}
                dot={{ r: 2, fill: color }}
                activeDot={{ r: 3.5 }}
                isAnimationActive={false}
              />
            </LineChart>
          )}
        </ResponsiveContainer>
      </div>
      {chart.xLabel && (
        <div className="border-t border-border px-3.5 py-[7px] font-mono text-[10.5px] text-dim">
          {clip(chart.xLabel, 60)}
        </div>
      )}
    </Panel>
  );
}

// ── Public component ─────────────────────────────────────────────────────────

interface HuntVisualsProps {
  /** the hunt's findings — the parent guarantees at least one */
  findings: HuntFinding[];
  /** hosts the hunt marked affected; backfills the map with unlinked hosts */
  affectedHosts?: string[];
  /** model-authored charts that survived the post-hunt chart gate (optional) */
  charts?: HuntChart[];
}

export function HuntVisuals({ findings, affectedHosts = [], charts = [] }: HuntVisualsProps) {
  const sevRows = breakdownRows(findings);
  const hostR = hostRows(findings);

  // the map's right column: the chart's top-8 hosts, backfilled (under the
  // same cap) with affected hosts no finding names
  const mapHosts = [...hostR];
  for (const h of affectedHosts) {
    if (mapHosts.length >= 8) break;
    if (!mapHosts.some((r) => r.host === h)) mapHosts.push({ host: h, count: 0, worst: 'info' });
  }

  const gaps = sevRows.reduce((n, r) => n + r.visibility_gap, 0);
  const obs = sevRows.reduce((n, r) => n + r.observation, 0);
  const breakdownLegend = [
    {
      // no single swatch color can say "severity" — a mini severity ramp does
      swatch: `linear-gradient(90deg,${SEV_COLOR.critical},${SEV_COLOR.medium},${SEV_COLOR.low})`,
      label: 'threat (severity color)',
    },
    ...(gaps > 0 ? [{ swatch: GAP_COLOR, label: 'visibility gap' }] : []),
    ...(obs > 0 ? [{ swatch: OBS_COLOR, label: 'observation' }] : []),
  ];

  // Agent charts render as an additional block AFTER the deterministic panels;
  // guard against an empty series (the backend already dropped uncited charts).
  const agentCharts = charts.filter((c) => c.series && c.series.length > 0);

  return (
    <div className="flex flex-col gap-[18px]">
      {/* Deterministic panels (unchanged) — always first. */}
      <div className="grid grid-cols-1 gap-[18px] xl:grid-cols-2">
        <Panel>
          <PanelHeader
            icon={<BarChart3 size={15} />}
            title="Findings breakdown"
            right={<span className="font-mono text-[11px] text-accent">{findings.length}</span>}
          />
          <div className="px-2 pt-3">
            <BreakdownChart rows={sevRows} />
          </div>
          <LegendRow items={breakdownLegend} />
        </Panel>

        <Panel>
          <PanelHeader
            icon={<Server size={15} />}
            title="Host involvement"
            right={<span className="font-mono text-[11px] text-accent">{hostR.length}</span>}
          />
          {hostR.length === 0 ? (
            <div className="px-4 py-3.5 text-[12.5px] text-dim">No findings name a host.</div>
          ) : (
            <div className="px-2 py-3">
              <HostChart rows={hostR} />
            </div>
          )}
        </Panel>

        <Panel className="xl:col-span-2">
          <PanelHeader
            icon={<Network size={15} />}
            title="Host–finding map"
            right={
              <span className="font-mono text-[11px] text-accent">
                {findings.length}F · {mapHosts.length}H
              </span>
            }
          />
          {mapHosts.length === 0 ? (
            <div className="px-4 py-3.5 text-[12.5px] text-dim">
              No hosts to map — no finding names a host.
            </div>
          ) : (
            <>
              <HostFindingMap findings={findings} hosts={mapHosts} />
              <LegendRow
                items={[
                  { swatch: SEV_COLOR.high, label: 'finding (severity color)' },
                  { swatch: '#4b8bf5', round: true, label: 'host' },
                ]}
              />
            </>
          )}
        </Panel>
      </div>

      {/* Agent-authored charts — series the model pulled from tool results that a
          deterministic chart can't guess. Every chart here already traced its
          source_citations to gathered evidence (backend gate); an invented series
          never reaches this point. Only render the block when some survived. */}
      {agentCharts.length > 0 && (
        <div className="grid grid-cols-1 gap-[18px] xl:grid-cols-2">
          {agentCharts.map((c, i) => (
            <AgentChart
              key={`${c.title}-${i}`}
              chart={c}
              color={AGENT_CHART_COLORS[i % AGENT_CHART_COLORS.length]}
            />
          ))}
        </div>
      )}
    </div>
  );
}
