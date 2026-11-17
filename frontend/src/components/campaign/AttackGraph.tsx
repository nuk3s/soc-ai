import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowUpRight, Crosshair, EyeOff, Server, ShieldCheck } from 'lucide-react';
import type {
  CampaignAuthorizationRecord,
  CampaignBeyondRun,
  CampaignEdge,
  CampaignMember,
  CampaignPairEvents,
  CampaignParty,
  CampaignRelated,
} from '../../lib/api';
import {
  LISTED_MARK,
  OUTSIDE_MARK,
  alertsOfRules,
  alertsWords,
  findingsWords,
  outsideLinkSentence,
  otherAlertsSentence,
  partyName,
  recordsSentence,
  stageLabel,
} from '../../lib/campaignWords';
import { plural } from '../../lib/plural';
import {
  FOLD_KEY,
  LISTED_COLOR,
  NODE_HEIGHT,
  NODE_WIDTH,
  NO_STAGE_COLOR,
  OUTSIDE_COLOR,
  STAGE_COLOR,
  STAGE_SEQUENCE,
  highestStage,
  layoutGraph,
  linkOutside,
  stageColor,
  type GraphLink,
  type GraphNode,
} from '../../lib/campaignViz';
import { machineHref } from '../../lib/hostsList';
import { utcWindow } from '../../lib/timeRange';
import { useElementWidth } from '../../lib/useElementWidth';
import { Panel, PanelHeader } from '../Panel';
import { HoverTip } from './HoverTip';
import { sameSelection, type CampaignSelection } from './selection';

const COLUMN_TITLE = ['Actors', 'Targets', 'Beyond the first target'] as const;
/** The most arrows that carry a count on the chart. More read as noise. */
const MAX_LABELS = 8;

function documentsWords(n: number): string {
  return n === 1 ? '1 document' : `${n} documents`;
}

function portsWords(ports: number[]): string {
  return ports.length === 1 ? `port ${ports[0]}` : `ports ${ports.join(', ')}`;
}

function nodeName(node: GraphNode): string {
  if (node.party) return partyName(node.party);
  return node.folded.length === 1 ? '1 more host' : `${node.folded.length} more hosts`;
}

/** The most rule rows that the tooltip of an arrow lists. */
const MAX_RULES = 4;

/** The machine keys that a node stands for. */
function keysOf(node: GraphNode): Set<string> {
  return new Set(node.party ? [node.party.machineKey] : node.folded.map((p) => p.machineKey));
}

/** True when the two ends join the two nodes of the arrow, in either direction. */
function onLink(link: GraphLink, source: string | null, target: string | null): boolean {
  if (!source || !target) return false;
  const a = keysOf(link.source);
  const b = keysOf(link.target);
  return (a.has(source) && b.has(target)) || (b.has(source) && a.has(target));
}

/** What the grid holds between the two nodes of an arrow. */
interface LinkEvents {
  /** The confirmed rules, most alerts first. */
  rules: { name: string; alerts: number }[];
  otherAlerts: number;
  records: number | null;
  firstAt: string | null;
  lastAt: string | null;
}

function linkEvents(pairs: readonly CampaignPairEvents[], link: GraphLink): LinkEvents {
  const rules = new Map<string, number>();
  let otherAlerts = 0;
  let records: number | null = null;
  let firstAt: string | null = null;
  let lastAt: string | null = null;
  for (const p of pairs) {
    if (!onLink(link, p.source, p.target)) continue;
    for (const r of p.rules ?? []) {
      if (r.verdict === 'true_positive') rules.set(r.name, (rules.get(r.name) ?? 0) + r.alerts);
    }
    otherAlerts += p.otherAlerts ?? 0;
    if (typeof p.records === 'number') records = (records ?? 0) + p.records;
    if (p.firstAt && (!firstAt || p.firstAt < firstAt)) firstAt = p.firstAt;
    if (p.lastAt && (!lastAt || p.lastAt > lastAt)) lastAt = p.lastAt;
  }
  return {
    rules: [...rules.entries()]
      .map(([name, alerts]) => ({ name, alerts }))
      .sort((x, y) => y.alerts - x.alerts || x.name.localeCompare(y.name)),
    otherAlerts,
    records,
    firstAt,
    lastAt,
  };
}

/** The true positive findings of an arrow. An arrow that only a document
 *  shows has no investigation with its two ends: the findings that cite the
 *  document are its count. */
function findingsOf(members: readonly CampaignMember[], link: GraphLink): number {
  if (link.fromDocuments) return link.runs;
  return members.filter(
    (m) => !m.verdictDiffers && (m.kind === 'finding' || m.kind === 'lead') && onLink(link, m.sourceKey, m.targetKey),
  ).length;
}

/** The count that an arrow states: its alert events, else its findings, else none. */
function linkCount(members: readonly CampaignMember[], link: GraphLink): string | null {
  if ((link.alerts ?? 0) > 0) return alertsWords(link.alerts as number);
  const findings = findingsOf(members, link);
  return findings > 0 ? findingsWords(findings) : null;
}

/** The alert events of a machine: the sum over the pairs it is an end of. */
function machineAlerts(pairs: readonly CampaignPairEvents[], key: string): number {
  return pairs.reduce((n, p) => n + (p.source === key || p.target === key ? (p.alerts ?? 0) : 0), 0);
}

/** The key of the stage colors. Both charts wear it: a color alone must never
 *  carry the stage. `related` adds the dashed line of the attack graph. */
export function StageLegend({ related = false, agents = false }: { related?: boolean; agents?: boolean }) {
  return (
    <div data-testid="stage-legend" className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-dim">
      {STAGE_SEQUENCE.map((stage) => (
        <span key={stage} className="inline-flex items-center gap-1.5 whitespace-nowrap">
          <span aria-hidden className="h-[3px] w-4 rounded-full" style={{ background: STAGE_COLOR[stage] }} />
          {stageLabel(stage)}
        </span>
      ))}
      <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
        <span aria-hidden className="h-[3px] w-4 rounded-full" style={{ background: NO_STAGE_COLOR }} />
        No proven stage
      </span>
      {related && (
        <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
          <span aria-hidden className="h-0 w-4 border-t border-dashed" style={{ borderColor: NO_STAGE_COLOR }} />
          Related, not proven
        </span>
      )}
      {agents && (
        <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
          <EyeOff size={11} aria-hidden />
          No agent
        </span>
      )}
    </div>
  );
}

/** The key of the marks of an authorization, on a row of its own under the
 *  header: the shield of a listed machine and the danger line of a pair
 *  beyond the authorization. */
function AuthorizationLegend({ listed, outside }: { listed: boolean; outside: boolean }) {
  if (!listed && !outside) return null;
  return (
    <div data-testid="authorization-legend" className="flex flex-wrap items-center gap-x-4 gap-y-1 px-[15px] pt-2 text-[11px] text-dim">
      {listed && (
        <span data-testid="legend-listed" className="inline-flex items-center gap-1.5 whitespace-nowrap">
          <ShieldCheck size={11} aria-hidden style={{ color: LISTED_COLOR }} />
          {LISTED_MARK}
        </span>
      )}
      {outside && (
        <span data-testid="legend-outside" className="inline-flex items-center gap-1.5 whitespace-nowrap font-semibold text-danger">
          <span aria-hidden className="h-[3px] w-4 rounded-full" style={{ background: OUTSIDE_COLOR }} />
          {OUTSIDE_MARK}
        </span>
      )}
    </div>
  );
}

/** Who acted on what. The machines are the nodes: the actors on the left, the
 *  targets in the middle, and the hosts that a target acted on to the right.
 *  An arrow is the attack from one machine to another. It states the alert
 *  events of the grid between them, or its findings when it has no alert
 *  event. Its width states the count and its color states the highest stage.
 *  A dashed line is a session between two machines that the engine did not
 *  include. */
export function AttackGraph({
  parties,
  edges,
  related,
  members,
  pairs = [],
  selection,
  onSelect,
  authorization = null,
  outside = [],
}: {
  parties: CampaignParty[];
  edges: CampaignEdge[];
  related: CampaignRelated;
  members: CampaignMember[];
  /** The events between the machines. A server of an earlier release sends none. */
  pairs?: CampaignPairEvents[];
  selection: CampaignSelection | null;
  onSelect: (next: CampaignSelection | null) => void;
  /** The authorization on the campaign. A listed machine wears a shield. */
  authorization?: Pick<CampaignAuthorizationRecord, 'state' | 'machineKeys'> | null;
  /** The investigations outside the authorization. Their pairs wear the danger tone. */
  outside?: readonly CampaignBeyondRun[];
}) {
  const [ref, width] = useElementWidth<HTMLDivElement>(1080);
  const [hover, setHover] = useState<{ key: string; x: number; y: number } | null>(null);
  const layout = useMemo(
    () => layoutGraph(parties, edges, related.sessions, width),
    [parties, edges, related.sessions, width],
  );
  if (parties.length === 0) return null;

  // A revoked authorization lists no machine any more.
  const listed = new Set(authorization && authorization.state !== 'revoked' ? authorization.machineKeys : []);
  const outsideOf = (l: GraphLink) => outside.filter((o) => linkOutside(l, [o])).length;
  const arrows = layout.links.filter((l) => !l.related);
  const anyOutside = arrows.some((l) => outsideOf(l) > 0);
  const labelled = arrows.length <= MAX_LABELS;
  const hoveredLink = layout.links.find((l) => l.key === hover?.key) ?? null;
  const hoveredNode = layout.nodes.find((n) => n.key === hover?.key) ?? null;

  // An arrow that only a document shows holds no investigation, so it selects nothing.
  const linkSelection = (l: GraphLink): CampaignSelection | null =>
    l.source.party && l.target.party && !l.fromDocuments
      ? {
          kind: 'edge',
          source: l.source.party.machineKey,
          target: l.target.party.machineKey,
          label: `${nodeName(l.source)} to ${nodeName(l.target)}`,
        }
      : null;
  const nodeSelection = (n: GraphNode): CampaignSelection | null =>
    n.party ? { kind: 'machine', key: n.party.machineKey, label: nodeName(n) } : null;

  const lit = (l: GraphLink): boolean => {
    if (hoveredLink) return hoveredLink.key === l.key;
    if (hoveredNode) return l.source.key === hoveredNode.key || l.target.key === hoveredNode.key;
    if (selection?.kind === 'edge') return sameSelection(selection, linkSelection(l));
    if (selection?.kind === 'machine') {
      return l.source.party?.machineKey === selection.key || l.target.party?.machineKey === selection.key;
    }
    return true;
  };
  const dimmed = Boolean(hoveredLink || hoveredNode || selection?.kind === 'edge' || selection?.kind === 'machine');

  const point = (e: React.PointerEvent | React.FocusEvent, key: string) => {
    const box = ref.current?.getBoundingClientRect();
    const at = 'clientX' in e ? { x: e.clientX, y: e.clientY } : null;
    const target = (e.currentTarget as Element).getBoundingClientRect();
    setHover({
      key,
      x: (at ? at.x : target.left + target.width / 2) - (box?.left ?? 0),
      y: (at ? at.y : target.bottom) - (box?.top ?? 0),
    });
  };
  const toggle = (next: CampaignSelection | null) => {
    if (next) onSelect(sameSelection(selection, next) ? null : next);
  };

  return (
    <Panel>
      <PanelHeader
        // The title keeps one line: the legend beside it wraps first.
        title={<span className="whitespace-nowrap">Attack graph</span>}
        right={<StageLegend related={related.sessions.length > 0} agents={parties.some((p) => !p.hasAgent)} />}
      />
      <AuthorizationLegend listed={parties.some((p) => listed.has(p.machineKey))} outside={anyOutside} />
      <div className="overflow-x-auto px-[15px] pb-3 pt-2">
        <div
          ref={ref}
          data-testid="attack-graph"
          className="relative"
          style={{ height: layout.height, minWidth: layout.width > width ? layout.width : undefined }}
          onPointerLeave={() => setHover(null)}
        >
          {layout.columns.map((c) => (
            <div
              key={c.column}
              className="absolute top-0 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint"
              style={{ left: c.x, width: NODE_WIDTH }}
            >
              {COLUMN_TITLE[c.column]}
              <span className="ml-1.5 font-mono font-normal normal-case tracking-normal text-ghost">{c.count}</span>
            </div>
          ))}

          <svg
            width={layout.width}
            height={layout.height}
            className="absolute left-0 top-0"
            role="img"
            aria-label="The machines of the campaign and the alerts between them"
          >
            {layout.links.map((l) => {
              const out = outsideOf(l) > 0;
              const color = l.related ? NO_STAGE_COLOR : out ? OUTSIDE_COLOR : stageColor(l.stage);
              const on = lit(l);
              const count = l.related ? null : linkCount(members, l);
              return (
                <g
                  key={l.key}
                  opacity={dimmed && !on ? 0.18 : 1}
                  data-testid="graph-link"
                  data-related={l.related}
                  data-outside={out}
                >
                  <path
                    d={l.path}
                    fill="none"
                    stroke={color}
                    strokeWidth={l.width}
                    strokeLinecap="round"
                    strokeDasharray={l.related ? '4 5' : l.fromDocuments ? '1 6' : undefined}
                  />
                  {l.head && <polygon points={l.head} fill={color} />}
                  {/* The hit area is wider than the line. */}
                  <path
                    d={l.path}
                    fill="none"
                    stroke="transparent"
                    strokeWidth={Math.max(18, l.width + 12)}
                    className={`outline-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-accent ${
                      linkSelection(l) && !l.related ? 'cursor-pointer' : ''
                    }`}
                    tabIndex={0}
                    role="button"
                    aria-label={
                      l.related
                        ? `${nodeName(l.source)} to ${nodeName(l.target)}, ${portsWords(l.ports)}: ${documentsWords(l.documents)}. Related, not proven.`
                        : `${nodeName(l.source)} to ${nodeName(l.target)}${count ? `: ${count}` : ''}.${out ? ` ${OUTSIDE_MARK}.` : ''}`
                    }
                    onPointerMove={(e) => point(e, l.key)}
                    onFocus={(e) => point(e, l.key)}
                    onBlur={() => setHover(null)}
                    onClick={() => !l.related && toggle(linkSelection(l))}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && !l.related) toggle(linkSelection(l));
                    }}
                  />
                </g>
              );
            })}
            {labelled &&
              arrows.map((l) => {
                const text = linkCount(members, l);
                if (!text) return null;
                const out = outsideOf(l) > 0;
                const w = text.length * 6.4 + 14;
                return (
                  <g
                    key={`label-${l.key}`}
                    data-testid="graph-link-label"
                    pointerEvents="none"
                    opacity={dimmed && !lit(l) ? 0.25 : 1}
                  >
                    <rect
                      x={l.labelX - w / 2}
                      y={l.labelY - 10}
                      width={w}
                      height={20}
                      rx={10}
                      fill="rgb(var(--surface-1))"
                      stroke={out ? OUTSIDE_COLOR : 'rgb(var(--border-strong))'}
                      strokeWidth={out ? 1.5 : 1}
                    />
                    <text
                      x={l.labelX}
                      y={l.labelY + 4}
                      textAnchor="middle"
                      className={`font-mono text-[11px] ${out ? 'fill-danger font-semibold' : 'fill-text-2'}`}
                    >
                      {text}
                    </text>
                  </g>
                );
              })}
          </svg>

          {layout.nodes.map((n) => {
            const selected = selection?.kind === 'machine' && n.party?.machineKey === selection.key;
            const touched =
              !dimmed ||
              selected ||
              hoveredNode?.key === n.key ||
              layout.links.some((l) => lit(l) && (l.source.key === n.key || l.target.key === n.key));
            const Icon = n.column === 0 ? Crosshair : Server;
            const address = n.party?.addresses[0] ?? null;
            // How far the campaign got on this machine: the highest stage of the arrows into it.
            const reached = highestStage(
              layout.links.filter((l) => !l.related && l.target.key === n.key).map((l) => l.stage),
            );
            return (
              <div
                key={n.key}
                data-testid="graph-node"
                data-role={n.column === 0 ? 'actor' : 'target'}
                className={`absolute flex items-center gap-2 rounded-card border bg-surface-2 px-2.5 transition-opacity ${
                  selected ? 'border-accent' : 'border-border-strong'
                } ${touched ? '' : 'opacity-30'}`}
                style={{ left: n.x, top: n.y, width: NODE_WIDTH, height: NODE_HEIGHT }}
                onPointerMove={(e) => point(e, n.key)}
              >
                <button
                  type="button"
                  disabled={!n.party}
                  onClick={() => toggle(nodeSelection(n))}
                  onFocus={(e) => point(e, n.key)}
                  onBlur={() => setHover(null)}
                  aria-pressed={selected}
                  aria-label={`${nodeName(n)}: show its alerts`}
                  className="flex min-w-0 flex-1 items-center gap-2 text-left"
                >
                  <Icon size={15} className={n.column === 0 ? 'flex-none text-text-2' : 'flex-none text-dim'} />
                  <span className="min-w-0 flex-1">
                    <span className="block break-words text-[12.5px] font-semibold leading-tight text-text">
                      {nodeName(n)}
                    </span>
                    {n.party && (
                      <span className="mt-0.5 flex items-center gap-1.5 font-mono text-[10.5px] leading-tight text-faint">
                        {address && address !== nodeName(n) && <span className="whitespace-nowrap">{address}</span>}
                        {!n.party.hasAgent && (
                          <span role="img" aria-label="No agent" title="This machine has no agent" className="flex-none">
                            <EyeOff size={11} aria-hidden />
                          </span>
                        )}
                      </span>
                    )}
                  </span>
                </button>
                {n.party && listed.has(n.party.machineKey) && (
                  <span
                    role="img"
                    data-testid="node-listed"
                    aria-label={LISTED_MARK}
                    title={LISTED_MARK}
                    className="flex-none"
                  >
                    <ShieldCheck size={14} aria-hidden style={{ color: LISTED_COLOR }} />
                  </span>
                )}
                {reached && (
                  <span
                    data-testid="node-stage"
                    data-stage={reached}
                    title={`Stage reached on this machine: ${stageLabel(reached)}`}
                    aria-label={`Stage reached on this machine: ${stageLabel(reached)}`}
                    className="h-2.5 w-2.5 flex-none rounded-full"
                    style={{ background: stageColor(reached), boxShadow: '0 0 0 2px rgb(var(--surface-2))' }}
                  />
                )}
                {n.party && (
                  <Link
                    to={machineHref(n.party.machineKey)}
                    aria-label={`Open the host page of ${nodeName(n)}`}
                    title="Open the host page"
                    className="flex-none rounded-chip p-1 text-faint hover:bg-surface-3 hover:text-accent"
                  >
                    <ArrowUpRight size={13} />
                  </Link>
                )}
              </div>
            );
          })}

          {hover && (hoveredLink || hoveredNode) && (
            <HoverTip
              testId="graph-tooltip"
              container={ref.current}
              x={hover.x + 14}
              y={hover.y}
              width={280}
              gap={14}
            >
              {hoveredLink ? (
                <LinkTip
                  link={hoveredLink}
                  events={linkEvents(pairs, hoveredLink)}
                  findings={findingsOf(members, hoveredLink)}
                  outside={outsideOf(hoveredLink)}
                />
              ) : (
                hoveredNode && <NodeTip node={hoveredNode} pairs={pairs} />
              )}
            </HoverTip>
          )}
        </div>
      </div>
    </Panel>
  );
}

function LinkTip({
  link,
  events,
  findings,
  outside = 0,
}: {
  link: GraphLink;
  events: LinkEvents;
  findings: number;
  /** The investigations of the arrow outside the authorization. */
  outside?: number;
}) {
  // The period of the events, else the period of the investigations.
  const first = events.firstAt ?? link.firstAt;
  const last = events.lastAt ?? link.lastAt;
  const window = first && last ? utcWindow(first, last) : null;
  const alerts = link.alerts ?? 0;
  const count =
    alerts > 0
      ? events.rules.length > 0
        ? alertsOfRules(alerts, events.rules.length)
        : alertsWords(alerts)
      : findings > 0
        ? findingsWords(findings)
        : null;
  const other = otherAlertsSentence(events.otherAlerts);
  return (
    <>
      <div className="font-semibold text-text">
        {nodeName(link.source)} to {nodeName(link.target)}
      </div>
      {link.related ? (
        <>
          <div className="mt-1 text-text-2">
            <span className="font-semibold text-text">{documentsWords(link.documents)}</span> on{' '}
            {portsWords(link.ports)}
          </div>
          <div className="mt-0.5 text-dim">
            Related, not proven. No alert of the campaign is on {link.ports.length === 1 ? 'this port' : 'these ports'}.
          </div>
        </>
      ) : (
        <>
          <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-text-2">
            {count && (
              <span data-testid="link-tip-count" className="font-semibold text-text">
                {count}
              </span>
            )}
            <span className="inline-flex items-center gap-1.5">
              <span aria-hidden className="h-[3px] w-3 rounded-full" style={{ background: stageColor(link.stage) }} />
              {link.stage ? stageLabel(link.stage) : 'No proven stage'}
            </span>
          </div>
          {outside > 0 && (
            <div data-testid="link-tip-outside" className="mt-1 font-semibold text-danger">
              {outsideLinkSentence(outside)}
            </div>
          )}
          {link.fromDocuments && (
            <div className="mt-0.5 text-dim">
              An alert document of a finding shows this arrow. No investigation has these two ends.
            </div>
          )}
          {events.rules.length > 0 && (
            <ul data-testid="link-tip-rules" className="mt-1 space-y-0.5">
              {events.rules.slice(0, MAX_RULES).map((r) => (
                <li key={r.name} className="flex items-baseline gap-2 text-dim">
                  <span className="flex-none font-mono text-[10.5px] tabular-nums text-text-2">
                    {r.alerts.toLocaleString()}
                  </span>
                  <span className="min-w-0 break-words">{r.name}</span>
                </li>
              ))}
            </ul>
          )}
          {other && <div className="mt-1 text-dim">{other}</div>}
          {events.records !== null && <div className="mt-1 text-dim">{recordsSentence(events.records)}</div>}
        </>
      )}
      {window && <div className="mt-1 font-mono text-[10.5px] text-faint">{window}</div>}
    </>
  );
}

function NodeTip({ node, pairs }: { node: GraphNode; pairs: readonly CampaignPairEvents[] }) {
  if (!node.party) {
    return (
      <>
        <div className="font-semibold text-text">{nodeName(node)}</div>
        <div className="mt-1 break-words text-dim">{node.folded.map((p) => partyName(p)).join(', ')}</div>
      </>
    );
  }
  const p = node.party;
  // A server of an earlier release sends no events: the tip then counts the investigations.
  const count =
    pairs.length > 0 ? alertsWords(machineAlerts(pairs, p.machineKey)) : plural(p.memberRuns, 'investigation');
  return (
    <>
      <div className="font-semibold text-text">{partyName(p)}</div>
      <div className="mt-1 text-text-2">
        <span data-testid="node-tip-count" className="font-semibold text-text">
          {count}
        </span>
        {p.beyond ? ' beyond the first target' : ''}
      </div>
      {p.addresses.length > 0 && <div className="mt-0.5 break-all font-mono text-[10.5px] text-faint">{p.addresses.join(', ')}</div>}
      <div className="mt-1 text-dim">
        {p.hasAgent ? 'This machine has an agent.' : 'This machine has no agent. soc-ai cannot read processes or files on it.'}
      </div>
    </>
  );
}

export { FOLD_KEY };
