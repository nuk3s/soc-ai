// Deterministic "Visual summary" for a concluded hunt: a findings-by-severity
// breakdown, a host-involvement chart, and a map that links each finding to
// the hosts it names (components/Graph.tsx, shaped by lib/huntGraph.ts). Pure
// presentational — every aggregation is computed here from the findings the
// page already fetched; the parent only mounts this when the hunt is complete
// AND has findings, so a chart can never render from nothing.

import { BarChart3, LineChart as LineChartIcon, Network, Server } from 'lucide-react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  LabelList,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  type TooltipProps,
  XAxis,
  YAxis,
} from 'recharts';
import { useMemo, type ReactNode } from 'react';
import type { HuntChart, HuntFinding, Severity } from '../lib/types';
import { SEVERITY } from '../lib/tokens';
import { huntGraphView } from '../lib/huntGraph';
import { mapCountLabel } from '../lib/tooltips';
import { Graph } from './Graph';
import { Panel, PanelHeader } from './Panel';

// Hunt severity colors derive from the single app-wide ramp (lib/tokens) — no
// second palette, so "low" is the same dim blue as everywhere else, never green.
// SEV_ORDER stays worst-first: rank 0 = critical (chart rows + "worst severity"
// both read top-down).
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_COLOR: Record<string, string> = Object.fromEntries(
  (Object.keys(SEVERITY) as Severity[]).map((k) => [k, SEVERITY[k].color]),
);

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

// Axis text shows whole. The hover tooltip repeats the value. A cut at a
// character count hid the end of a host name (owner, 2026-10-07).
const MONO_CHAR_PX = 6.4;
const hostAxisWidth = (rows: { host: string }[]) =>
  Math.min(300, Math.max(118, Math.round(Math.max(0, ...rows.map((r) => r.host.length)) * MONO_CHAR_PX + 14)));

// recharts defaults assume a light theme — style ticks/axes/tooltips
// explicitly against the dark surface tokens.
const TICK = { fill: '#8b94a3', fontSize: 11 };
const MONO_TICK = { fill: '#8b94a3', fontSize: 10.5, fontFamily: 'JetBrains Mono, monospace' };
// Always-visible value labels (the non-hover path): mono, a touch brighter than
// the ticks so a number reads off the bar without a pointer.
const VALUE_LABEL = { fill: '#c9d1d9', fontSize: 11, fontFamily: 'JetBrains Mono, monospace' };
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

// The non-hover path: every chart panel carries a collapsed <details> that
// re-renders the same series as a real <table>. It is the screen-reader and
// touch fallback for the hover tooltips, and stays in the DOM even when closed.
function TableDisclosure({
  caption,
  columns,
  rows,
}: {
  caption: string;
  columns: string[];
  rows: ReactNode[][];
}) {
  return (
    <details className="border-t border-border">
      <summary className="cursor-pointer select-none px-3.5 py-[9px] font-mono text-[11px] text-dim hover:text-text-2">
        View as table
      </summary>
      <div className="overflow-x-auto px-3.5 pb-3 pt-1">
        <table className="w-full border-collapse text-left text-[12px]">
          <caption className="sr-only">{caption}</caption>
          <thead>
            <tr>
              {columns.map((c) => (
                <th
                  key={c}
                  scope="col"
                  className="border-b border-border px-2 py-1 font-mono text-[10.5px] font-semibold uppercase tracking-[.04em] text-dim"
                >
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i}>
                {r.map((cell, j) => (
                  <td key={j} className="border-b border-border px-2 py-1 font-mono text-[11.5px] text-text-2">
                    {cell}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
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
      <BarChart accessibilityLayer aria-label="Findings by severity and category" data={rows} layout="vertical" margin={{ top: 4, right: 26, bottom: 0, left: 4 }}>
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
        <Bar dataKey="observation" stackId="cat" fill={OBS_COLOR} isAnimationActive={false}>
          {/* one total-per-severity label at the end of the stack — no hover needed */}
          <LabelList
            position="right"
            valueAccessor={(e: { payload?: BreakdownRow }) =>
              e.payload ? e.payload.threat + e.payload.visibility_gap + e.payload.observation : ''
            }
            style={VALUE_LABEL}
          />
        </Bar>
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
      <BarChart accessibilityLayer aria-label="Host involvement, findings per host, top 8 hosts" data={rows} layout="vertical" margin={{ top: 4, right: 30, bottom: 0, left: 4 }}>
        <XAxis type="number" allowDecimals={false} tick={TICK} axisLine={AXIS_LINE} tickLine={false} />
        <YAxis
          type="category"
          dataKey="host"
          width={hostAxisWidth(rows)}
          tick={MONO_TICK}
          axisLine={AXIS_LINE}
          tickLine={false}
        />
        <Tooltip cursor={CURSOR} content={<HostTip />} isAnimationActive={false} />
        <Bar dataKey="count" barSize={14} radius={[0, 3, 3, 0]} isAnimationActive={false}>
          {rows.map((r) => (
            <Cell key={r.host} fill={SEV_COLOR[r.worst] ?? SEV_COLOR.info} />
          ))}
          {/* top-8 cut means the axis never crowds — label every bar end */}
          <LabelList dataKey="count" position="right" style={VALUE_LABEL} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
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
        tickFormatter={(x: string) => String(x)}
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
            ? { value: chart.yLabel, angle: -90, position: 'insideLeft', fill: '#8b94a3', fontSize: 10.5 }
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
          // A machine-generated chart title runs long. It wraps and shows whole.
          <span className="break-words" title={chart.title || 'Chart'}>
            {chart.title || 'Chart'}
          </span>
        }
        right={<span className="font-mono text-[11px] text-accent">{data.length}</span>}
      />
      <div className="px-2 pb-1 pt-3">
        <ResponsiveContainer width="100%" height={height}>
          {isBar ? (
            <BarChart accessibilityLayer aria-label={chart.title || 'Chart'} data={data} margin={{ top: 4, right: 14, bottom: 2, left: 0 }}>
              {common}
              <Bar dataKey="y" fill={color} radius={[3, 3, 0, 0]} isAnimationActive={false}>
                {/* label each bar end only for short series that won't collide */}
                {data.length <= 8 && <LabelList dataKey="y" position="top" style={VALUE_LABEL} />}
              </Bar>
            </BarChart>
          ) : (
            // line + timeline both render as a value-over-x line
            <LineChart accessibilityLayer aria-label={chart.title || 'Chart'} data={data} margin={{ top: 4, right: 14, bottom: 2, left: 0 }}>
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
      <TableDisclosure
        caption={`${chart.title || 'Chart'} · data table`}
        columns={[chart.xLabel || 'x', chart.yLabel || 'value']}
        rows={data.map((p) => [String(p.x), typeof p.y === 'number' ? p.y : String(p.y ?? '')])}
      />
      {chart.xLabel && (
        <div className="border-t border-border px-3.5 py-[7px] font-mono text-[10.5px] text-dim">
          {chart.xLabel}
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
  // Distinct hosts NAMED by findings. hostRows caps at the top 8 by involvement,
  // so when more exist the Host-involvement panel is truncating — its header
  // says "top 8 of N" instead of a bare (capped) count.
  const hostsNamed = new Set(findings.flatMap((f) => f.hosts)).size;

  // The map draws every host a finding names, then the affected hosts no
  // finding names, up to MAX_MAP_HOSTS. lib/huntGraph.ts shapes it.
  const map = useMemo(() => huntGraphView(findings, affectedHosts), [findings, affectedHosts]);

  const gaps = sevRows.reduce((n, r) => n + r.visibility_gap, 0);
  const obs = sevRows.reduce((n, r) => n + r.observation, 0);
  const breakdownLegend = [
    {
      // no single swatch color can say "severity" — a mini severity ramp does
      swatch: `linear-gradient(90deg,${SEV_COLOR.critical},${SEV_COLOR.medium},${SEV_COLOR.low})`,
      label: 'threat · severity color',
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
          <TableDisclosure
            caption="Findings breakdown by severity and category"
            columns={['Severity', 'Threat', 'Visibility gap', 'Observation', 'Total']}
            rows={sevRows.map((r) => [
              r.severity,
              r.threat,
              r.visibility_gap,
              r.observation,
              r.threat + r.visibility_gap + r.observation,
            ])}
          />
        </Panel>

        <Panel>
          <PanelHeader
            icon={<Server size={15} />}
            title="Host involvement"
            right={
              <span className="font-mono text-[11px] text-accent">
                {hostsNamed > hostR.length ? `top ${hostR.length} of ${hostsNamed}` : hostR.length}
              </span>
            }
          />
          {hostR.length === 0 ? (
            <div className="px-4 py-3.5 text-[12.5px] text-dim">No findings name a host.</div>
          ) : (
            <>
              <div className="px-2 py-3">
                <HostChart rows={hostR} />
              </div>
              <LegendRow
                items={[
                  {
                    swatch: `linear-gradient(90deg,${SEV_COLOR.critical},${SEV_COLOR.medium},${SEV_COLOR.low})`,
                    label: 'bar color is the worst severity',
                  },
                ]}
              />
              <TableDisclosure
                caption="Host involvement · findings per host"
                columns={['Host', 'Findings', 'Worst severity']}
                rows={hostR.map((r) => [r.host, r.count, r.worst])}
              />
            </>
          )}
        </Panel>

        <Panel className="xl:col-span-2">
          <PanelHeader
            icon={<Network size={15} />}
            title="Host and finding map"
            right={
              <span className="font-mono text-[11px] text-accent">
                {mapCountLabel(map.findings, map.hosts)}
              </span>
            }
          />
          <Graph
            view={map.view}
            ariaLabel="Host and finding map of this hunt"
            emptyText="No hosts to map. No finding names a host."
          />
          {map.hostsCut > 0 && (
            <div className="border-t border-border px-3.5 py-2 text-[11px] text-faint">
              The map draws the {map.hosts} hosts that the most findings name. It leaves off {map.hostsCut} more.
            </div>
          )}
          {map.hosts > 0 && (
            <>
              <TableDisclosure
                caption="Host and finding map · each finding and the hosts it names"
                columns={['Finding', 'Severity', 'Category', 'Hosts']}
                rows={findings.map((f, i) => [
                  `F${i + 1}: ${f.title}`,
                  sevKey(f.severity),
                  f.category ?? 'threat',
                  f.hosts.length ? f.hosts.join(', ') : '—',
                ])}
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
