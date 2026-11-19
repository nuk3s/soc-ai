import { useMemo, useRef, useState } from 'react';
import type {
  CampaignAuthorizationRecord,
  CampaignChange,
  CampaignHuntAnswer,
  CampaignEvents,
  CampaignLadderStep,
  CampaignMember,
  CampaignParty,
  CampaignStage,
} from '../../lib/api';
import {
  alertsWords,
  authorizationExpired,
  changeMarkLabel,
  changeMarkWords,
  expiryMarkLabel,
  huntAnswerMarkLabel,
  huntAnswerSentence,
  partyName,
  periodBandWords,
  provedWords,
  stageFlagWords,
  stageLabel,
  timelineNote,
} from '../../lib/campaignWords';
import {
  LISTED_COLOR,
  TIMELINE_GUTTER,
  TIMELINE_RIGHT,
  bucketMs,
  clusterPoints,
  highestStage,
  investigationsIn,
  markSpan,
  markStage,
  padDomain,
  stageColor,
  stageRank,
  tickLabel,
  timeTicks,
  timelineLanes,
  type TimeCluster,
  type TimelineLane,
} from '../../lib/campaignViz';
import { utcStamp, utcWindow } from '../../lib/timeRange';
import { useElementWidth } from '../../lib/useElementWidth';
import { Panel, PanelHeader } from '../Panel';
import { StageLegend } from './AttackGraph';
import { HoverTip } from './HoverTip';
import { sameSelection, type CampaignSelection } from './selection';

const GUTTER = TIMELINE_GUTTER;
const RIGHT = TIMELINE_RIGHT;
const LANE = 36;
const FLAG_ROW = 17;
const AXIS = 26;
const MARK = 14;
/** The changes that draw a mark on the time axis. */
const MARKED: ReadonlySet<string> = new Set(['decided', 'reopened', 'case', 'case_comment']);
/** A case decision this close to a case change is the same case. */
const CASE_TWIN_MS = 60_000;

/** Two buckets closer than this many pixels are one mark. */
const CLUSTER_GAP = 18;
const MINUTE = 60_000;
/** The most titles of findings that the tooltip of a mark lists. */
const MAX_FINDINGS = 3;

function iso(t: number): string {
  return new Date(t).toISOString();
}

/** A span in UTC: one time for an instant, else the window. */
function spanWords(span: { from: number; to: number }): string {
  return span.from === span.to ? utcStamp(iso(span.from)) : utcWindow(iso(span.from), iso(span.to));
}

function laneName(lane: TimelineLane): string {
  return lane.party ? partyName(lane.party) : lane.key;
}

/** The ink of a count inside a mark: dark on the three light steps of the
 *  ramp, light on the two dark steps and on the gray of no stage. */
function inkOn(stage: CampaignStage | null): string {
  return stageRank(stage) >= 2 ? '#0b0e13' : '#e6e9ef';
}

interface Hover {
  lane: TimelineLane;
  cluster: TimeCluster;
  x: number;
  y: number;
}

/** When each actor acted. One lane for each machine with alert events, on one
 *  time axis in UTC. A mark is one bucket of alert events, or the buckets that
 *  sit too close to draw apart, and it states their sum. Its color states the
 *  highest stage that soc-ai proved for the machine: the stage of its alerts,
 *  and the stage of each finding inside the span of the mark. The row above
 *  the lanes marks the first time the campaign reached each stage, and each
 *  decision and each reopen of the campaign. The axis covers the decisions
 *  too, so a close weeks after the last event stays on it. A drag across the
 *  chart zooms in.
 *
 *  An authorization draws its period as a band behind the lanes, from the
 *  first event of the campaign to the expiry, or to the revoke. The create is
 *  its decision mark, the revoke its reopen mark, and the expiry has a mark of
 *  its own. An event outside the band is outside the period. A future expiry
 *  does not stretch the axis: the band runs to now, and the mark of the
 *  expiry sits at the right edge with its day.
 *
 *  With no events, or a source of `none`, the chart does not render. */
export function CampaignTimeline({
  events,
  members,
  parties,
  ladder,
  changes,
  selection,
  onSelect,
  authorization = null,
  answer = null,
  since = null,
}: {
  events: CampaignEvents | null | undefined;
  members: CampaignMember[];
  parties: CampaignParty[];
  ladder: CampaignLadderStep[];
  /** The changes of the campaign. The decisions and the reopens are marks. */
  changes?: readonly CampaignChange[];
  selection: CampaignSelection | null;
  onSelect: (next: CampaignSelection | null) => void;
  /** The authorization on the campaign. Its period is a band. */
  authorization?: Pick<CampaignAuthorizationRecord, 'label' | 'at' | 'startsAt' | 'expiresAt' | 'state'> | null;
  /** The newest answer of a hunt that read the campaign. It is a mark at
   *  the time that the hunt started. */
  answer?: CampaignHuntAnswer | null;
  /** A campaign that opened again: the span after the boundary of the
   *  earlier decision is a band in the warning tone, with its words (SD3). */
  since?: { boundary: string; words: string } | null;
}) {
  const [ref, width] = useElementWidth<HTMLDivElement>(1080);
  const [zoom, setZoom] = useState<[number, number] | null>(null);
  const [drag, setDrag] = useState<{ from: number; to: number } | null>(null);
  const [hover, setHover] = useState<Hover | null>(null);
  const dragging = useRef(false);

  const note = timelineNote(events?.source);
  const timeline = note ? events?.timeline : null;
  const bucket = bucketMs(timeline);
  const lanes = useMemo(() => timelineLanes(timeline, members, parties), [timeline, members, parties]);
  // The decisions, the reopens, the case and the comments of soc-ai, oldest
  // first. A server can state the case as a decision and as a case change:
  // the case change then takes the one mark.
  const decisions = useMemo(() => {
    const all = changes ?? [];
    const caseTimes = all.filter((c) => c.type === 'case').map((c) => Date.parse(c.at));
    const twin = (c: CampaignChange) =>
      c.type === 'decided' &&
      c.detail?.decision === 'case' &&
      caseTimes.some((t) => Math.abs(t - Date.parse(c.at)) <= CASE_TWIN_MS);
    const marks = all
      .filter((c) => MARKED.has(c.type) && !twin(c))
      .map((c) => ({
        key: `change-${c.id}`,
        type: c.type as string,
        t: Date.parse(c.at),
        text: changeMarkLabel(c),
        words: changeMarkWords(c),
        color:
          c.type === 'reopened'
            ? 'rgb(var(--warn))'
            : c.type === 'case'
              ? 'rgb(var(--accent))'
              : 'rgb(var(--text-2))',
        comment: c.type === 'case_comment',
        id: c.id,
      }))
      .filter((d) => !Number.isNaN(d.t));
    // The newest hunt that read the campaign, in the tone of its answer.
    const answerAt = answer?.huntAt ? Date.parse(answer.huntAt) : Number.NaN;
    if (answer && !Number.isNaN(answerAt)) {
      marks.push({
        key: `answer-${answer.huntId}`,
        type: 'hunt_answer',
        t: answerAt,
        text: huntAnswerMarkLabel(answer.outcome),
        words: huntAnswerSentence('campaign', answer),
        color: answer.outcome === 'new_activity' ? 'rgb(var(--danger))' : 'rgb(var(--text-2))',
        comment: false,
        id: Number.MAX_SAFE_INTEGER,
      });
    }
    return marks.sort((a, b) => a.t - b.t || a.id - b.id);
  }, [changes, answer]);
  // The period of the authorization: from its start to the expiry, or to the
  // revoke, the newest revoke after the create.
  const period = useMemo(() => {
    if (!authorization) return null;
    const from = Date.parse(authorization.startsAt);
    const expiry = Date.parse(authorization.expiresAt);
    if (Number.isNaN(from) || Number.isNaN(expiry)) return null;
    let to = expiry;
    if (authorization.state === 'revoked') {
      const made = Date.parse(authorization.at);
      const revokes = (changes ?? [])
        .filter((c) => c.type === 'reopened' && c.detail?.cause === 'revoked')
        .map((c) => Date.parse(c.at))
        .filter((t) => !Number.isNaN(t) && (Number.isNaN(made) || t >= made));
      if (revokes.length > 0) to = Math.min(expiry, Math.max(...revokes));
    }
    const expired = authorizationExpired(authorization);
    return {
      from,
      to: Math.max(from, to),
      expiry,
      // A revoke before the expiry ends the period: the expiry then draws no mark.
      showExpiry: to === expiry,
      expired,
      words: periodBandWords(authorization.label, new Date(from).toISOString(), new Date(Math.max(from, to)).toISOString()),
      expiryWords: `${utcStamp(authorization.expiresAt)}: The authorization ${authorization.label.trim()} ${expired ? 'expired' : 'expires'}.`,
    };
  }, [authorization, changes]);
  const marks = useMemo(
    () =>
      period?.showExpiry
        ? [
            ...decisions,
            {
              key: 'expiry',
              type: 'expiry',
              t: period.expiry,
              text: expiryMarkLabel(period.expired),
              words: period.expiryWords,
              color: 'rgb(var(--text-2))',
              id: Number.MAX_SAFE_INTEGER,
              // A future expiry sits at the right edge of the chart.
              future: !period.expired,
            },
          ].sort((a, b) => a.t - b.t || a.id - b.id)
        : decisions,
    [decisions, period],
  );
  const full = useMemo<[number, number] | null>(() => {
    const times = lanes.flatMap((l) => l.points.map((p) => p.t));
    if (times.length === 0) return null;
    // A future expiry does not stretch the axis: the band then runs to now.
    const now = Date.now();
    const sinceAt = since ? Date.parse(since.boundary) : Number.NaN;
    const marks = [
      ...decisions.map((d) => d.t),
      ...(period ? [period.from, Math.min(period.to, now)] : []),
      ...(Number.isNaN(sinceAt) ? [] : [sinceAt]),
    ];
    const lo = Math.min(Math.min(...times) - bucket / 2, ...marks);
    const hi = Math.max(Math.max(...times) + bucket / 2, ...marks);
    return padDomain(lo, hi);
  }, [lanes, bucket, decisions, period, since]);
  if (!note || !full || lanes.length === 0) return null;

  const [d0, d1] = zoom ?? full;
  const plot = Math.max(240, width - GUTTER - RIGHT);
  const scale = (t: number): number => GUTTER + ((t - d0) / (d1 - d0)) * plot;
  const invert = (x: number): number => d0 + ((x - GUTTER) / plot) * (d1 - d0);

  // The first time of each reached stage, in two rows when two labels meet.
  const flags = ladder
    .filter((s) => s.reached && s.firstAt)
    .map((s) => ({
      stage: s.stage,
      t: Date.parse(s.firstAt as string),
      words: stageFlagWords(s.stage, s.firstAt as string, s.heldBy ?? null),
    }))
    .filter((f) => !Number.isNaN(f.t) && f.t >= d0 && f.t <= d1)
    .sort((a, b) => a.t - b.t || stageRank(a.stage) - stageRank(b.stage));
  // A name takes the first of three rows that has room. With no room it does
  // not draw: the mark, the ladder above and the hover still state the stage.
  const rowEnd = [-Infinity, -Infinity, -Infinity];
  const placed = flags.map((f) => {
    const x = scale(f.t);
    const labelWidth = stageLabel(f.stage).length * 6.3 + 18;
    const left = x + labelWidth > GUTTER + plot;
    const start = left ? x - labelWidth : x - 8;
    const row = rowEnd.findIndex((end) => start > end + 4);
    if (row >= 0) rowEnd[row] = start + labelWidth;
    return { ...f, x, row: Math.max(0, row), left, named: row >= 0 };
  });
  // The decisions take a row after the stages. A name with no room does not
  // draw: the mark, its hover and the Changes fold still state it.
  const placedDecisions = marks
    .filter((d) => d.t >= d0 && (d.t <= d1 || ('future' in d && d.future)))
    .map((d) => {
      // A mark after the end of the axis sits at the right edge and names its day.
      const clamped = d.t > d1;
      const x = clamped ? GUTTER + plot : scale(d.t);
      const text = clamped ? `${d.text} ${utcStamp(iso(d.t))}` : d.text;
      const labelWidth = text.length * 6.3 + 18;
      const left = x + labelWidth > GUTTER + plot;
      const start = left ? x - labelWidth : x - 8;
      const row = rowEnd.findIndex((end) => start > end + 4);
      if (row >= 0) rowEnd[row] = start + labelWidth;
      return { ...d, x, text, clamped, row: Math.max(0, row), left, named: row >= 0 };
    });
  const rowsUsed = [...placed, ...placedDecisions].map((f) => f.row);
  const flagRows = rowsUsed.length === 0 ? 0 : Math.max(...rowsUsed) + 1;
  const top = flagRows * FLAG_ROW + 8;
  const height = top + lanes.length * LANE + AXIS;
  const { step, ticks } = timeTicks(d0, d1, Math.max(3, Math.floor(plot / 84)));

  // The span of the picked mark. A mark is chosen when it overlaps the span
  // in the same lane, so the pick still shows after a zoom.
  const picked = selection?.kind === 'runs' ? (selection.span ?? null) : null;
  const laneX = (e: React.PointerEvent): number => {
    const box = ref.current?.getBoundingClientRect();
    return Math.min(GUTTER + plot, Math.max(GUTTER, e.clientX - (box?.left ?? 0)));
  };
  // A click selects the investigations of the machine inside the span of the mark.
  const pick = (lane: TimelineLane, c: TimeCluster) => {
    const span = markSpan(c, bucket);
    const runIds = investigationsIn(lane, span).map((r) => r.runId);
    const next: CampaignSelection = {
      kind: 'runs',
      runIds,
      label: `${laneName(lane)}, ${spanWords(span)}`,
      span: { lane: lane.key, ...span },
    };
    onSelect(sameSelection(selection, next) ? null : next);
  };

  return (
    <Panel>
      <PanelHeader
        title="Timeline"
        right={
          <div className="flex flex-wrap items-center justify-end gap-x-4 gap-y-1 text-[11px] text-faint">
            <StageLegend />
            {zoom && (
              <button
                type="button"
                data-testid="timeline-reset"
                onClick={() => setZoom(null)}
                className="rounded-control border border-border-strong bg-surface-2 px-2 py-0.5 text-[11px] text-text-2 hover:border-accent"
              >
                Show the whole period
              </button>
            )}
          </div>
        }
      />
      <div className="px-[15px] pb-2 pt-3">
        <div data-testid="timeline-note" className="mb-1 text-[11px] text-faint">
          {note}
        </div>
        <div
          ref={ref}
          data-testid="campaign-timeline"
          className="relative select-none"
          style={{ height }}
          onPointerLeave={() => setHover(null)}
        >
          <svg
            width={width}
            height={height}
            className="absolute left-0 top-0"
            role="img"
            aria-label="The alert events of each machine over time"
          >
            {/* The grid: one hairline for each tick, and one under each lane. */}
            {ticks.map((t) => (
              <line
                key={t}
                x1={scale(t)}
                x2={scale(t)}
                y1={top}
                y2={top + lanes.length * LANE}
                stroke="rgb(var(--border))"
                strokeWidth={1}
              />
            ))}
            {lanes.map((lane, i) => (
              <line
                key={lane.key}
                x1={GUTTER}
                x2={GUTTER + plot}
                y1={top + (i + 1) * LANE}
                y2={top + (i + 1) * LANE}
                stroke="rgb(var(--border))"
                strokeWidth={1}
              />
            ))}
            {ticks.map((t) => (
              <text
                key={`label-${t}`}
                x={scale(t)}
                y={top + lanes.length * LANE + 16}
                textAnchor="middle"
                className="fill-faint font-mono text-[10.5px]"
              >
                {tickLabel(t, step)}
              </text>
            ))}

            {/* The drag surface sits under the marks, so a mark still takes its own click. */}
            <rect
              data-testid="timeline-surface"
              x={GUTTER}
              y={top}
              width={plot}
              height={lanes.length * LANE}
              fill="transparent"
              className="cursor-crosshair"
              onPointerDown={(e) => {
                dragging.current = true;
                (e.currentTarget as Element).setPointerCapture?.(e.pointerId);
                const x = laneX(e);
                setDrag({ from: x, to: x });
                setHover(null);
              }}
              onPointerMove={(e) => {
                if (dragging.current) setDrag((d) => (d ? { ...d, to: laneX(e) } : d));
              }}
              onPointerUp={() => {
                dragging.current = false;
                if (drag && Math.abs(drag.to - drag.from) > 6) {
                  const a = invert(Math.min(drag.from, drag.to));
                  const b = invert(Math.max(drag.from, drag.to));
                  if (b - a >= MINUTE) setZoom([a, b]);
                }
                setDrag(null);
              }}
              onDoubleClick={() => setZoom(null)}
            />
            {drag && (
              <rect
                x={Math.min(drag.from, drag.to)}
                y={top}
                width={Math.abs(drag.to - drag.from)}
                height={lanes.length * LANE}
                fill="rgb(var(--accent) / 0.14)"
                stroke="rgb(var(--accent) / 0.5)"
                pointerEvents="none"
              />
            )}

            {/* The period of the authorization: a band behind the lanes and a
                bar on the axis, in the neutral tone. */}
            {period && period.to >= d0 && period.from <= d1 && (
              <g data-testid="timeline-period" pointerEvents="none" role="img" aria-label={period.words}>
                <title>{period.words}</title>
                <rect
                  x={Math.max(GUTTER, scale(period.from))}
                  y={top}
                  width={Math.max(1, Math.min(GUTTER + plot, scale(period.to)) - Math.max(GUTTER, scale(period.from)))}
                  height={lanes.length * LANE}
                  fill={LISTED_COLOR}
                  opacity={0.06}
                />
                <rect
                  data-testid="timeline-period-bar"
                  x={Math.max(GUTTER, scale(period.from))}
                  y={top + lanes.length * LANE - 3}
                  width={Math.max(1, Math.min(GUTTER + plot, scale(period.to)) - Math.max(GUTTER, scale(period.from)))}
                  height={3}
                  fill={LISTED_COLOR}
                  opacity={0.55}
                />
              </g>
            )}

            {/* The span after the earlier decision: a band behind the lanes
                and a bar on the axis, in the warning tone, to the right end. */}
            {since && !Number.isNaN(Date.parse(since.boundary)) && Date.parse(since.boundary) <= d1 && (
              <g data-testid="timeline-since" pointerEvents="none" role="img" aria-label={since.words}>
                <title>{since.words}</title>
                <rect
                  x={Math.max(GUTTER, scale(Date.parse(since.boundary)))}
                  y={top}
                  width={Math.max(1, GUTTER + plot - Math.max(GUTTER, scale(Date.parse(since.boundary))))}
                  height={lanes.length * LANE}
                  fill="rgb(var(--warn))"
                  opacity={0.07}
                />
                <rect
                  data-testid="timeline-since-bar"
                  x={Math.max(GUTTER, scale(Date.parse(since.boundary)))}
                  y={top + lanes.length * LANE - 3}
                  width={Math.max(1, GUTTER + plot - Math.max(GUTTER, scale(Date.parse(since.boundary))))}
                  height={3}
                  fill="rgb(var(--warn))"
                  opacity={0.55}
                />
              </g>
            )}

            {/* The first time of each stage: a hairline down the lanes, a mark and its name. */}
            {placed.map((f) => {
              const y = f.row * FLAG_ROW + 9;
              return (
                <g key={f.stage} data-testid="timeline-flag" data-stage={f.stage} role="img" aria-label={f.words}>
                  {/* The hover states the time of the mark and, for a stage
                      that a later stage holds, the earlier "by" time of the
                      ladder (dogfood 2026-11-17, N11). */}
                  <title>{f.words}</title>
                  <line
                    pointerEvents="none"
                    x1={f.x}
                    x2={f.x}
                    y1={y + 5}
                    y2={top + lanes.length * LANE}
                    stroke={stageColor(f.stage)}
                    strokeWidth={1}
                    opacity={0.55}
                  />
                  <rect
                    x={f.x - 4.5}
                    y={y - 4.5}
                    width={9}
                    height={9}
                    transform={`rotate(45 ${f.x} ${y})`}
                    fill={stageColor(f.stage)}
                    stroke="rgb(var(--surface-1))"
                    strokeWidth={2}
                  />
                  {f.named && (
                    <text
                      x={f.left ? f.x - 10 : f.x + 10}
                      y={y + 3.5}
                      textAnchor={f.left ? 'end' : 'start'}
                      className="fill-text-2 text-[11px]"
                      pointerEvents="none"
                    >
                      {stageLabel(f.stage)}
                    </text>
                  )}
                </g>
              );
            })}

            {/* Each decision and each reopen: a dashed hairline down the
                lanes, a square and its word. A close reads calm, a reopen
                wears the warning tone. */}
            {placedDecisions.map((d) => {
              const y = d.row * FLAG_ROW + 9;
              const color = d.color;
              const words = d.words;
              return (
                <g
                  key={d.key}
                  data-testid="timeline-decision"
                  data-type={d.type}
                  data-x={d.x}
                  role="img"
                  aria-label={words}
                >
                  <title>{words}</title>
                  {/* The line starts under the rows of names when a name sits
                      below this mark, so it never crosses that name. */}
                  {!d.clamped && (
                    <line
                      x1={d.x}
                      x2={d.x}
                      y1={d.row === flagRows - 1 ? y + 5 : top}
                      y2={top + lanes.length * LANE}
                      stroke={color}
                      strokeWidth={1}
                      strokeDasharray="3 3"
                      opacity={0.7}
                      pointerEvents="none"
                    />
                  )}
                  {'comment' in d && d.comment ? (
                    <circle cx={d.x} cy={y} r={3.5} fill={color} stroke="rgb(var(--surface-1))" strokeWidth={2} />
                  ) : (
                    <rect
                      x={d.x - 4}
                      y={y - 4}
                      width={8}
                      height={8}
                      rx={1.5}
                      fill={color}
                      stroke="rgb(var(--surface-1))"
                      strokeWidth={2}
                    />
                  )}
                  {d.named && (
                    <text
                      data-testid="timeline-decision-label"
                      x={d.left ? d.x - 10 : d.x + 10}
                      y={y + 3.5}
                      textAnchor={d.left ? 'end' : 'start'}
                      className="fill-text-2 text-[11px]"
                    >
                      {d.text}
                    </text>
                  )}
                </g>
              );
            })}

            {lanes.map((lane, i) => {
              const cy = top + i * LANE + LANE / 2;
              const name = laneName(lane);
              const visible = lane.points.filter((p) => p.t >= d0 && p.t <= d1);
              const clusters = clusterPoints(visible, scale, CLUSTER_GAP);
              return (
                <g key={lane.key} data-testid="timeline-lane" data-lane={lane.key}>
                  {clusters.map((c, index) => {
                    const x = c.x0 - MARK / 2;
                    const w = c.x1 - c.x0 + MARK;
                    const n = c.count;
                    const text = n.toLocaleString();
                    const fits = w >= text.length * 6.6 + 8;
                    // A count beside its mark needs room before the next mark. With no
                    // room it does not draw: the hover and the Alerts table state it.
                    const next = clusters[index + 1];
                    const room = next ? next.x0 - MARK / 2 - (x + w) : Infinity;
                    const beside = room >= text.length * 6.2 + 10;
                    const span = markSpan(c, bucket);
                    const stage = markStage(lane, span);
                    const chosen =
                      picked !== null && picked.lane === lane.key && span.from < picked.to && picked.from < span.to;
                    const fill = stageColor(stage);
                    return (
                      <g
                        key={c.key}
                        data-testid="timeline-mark"
                        data-alerts={n}
                        data-stage={stage ?? 'none'}
                        opacity={picked && !chosen ? 0.35 : 1}
                      >
                        <rect
                          x={x}
                          y={cy - MARK / 2}
                          width={w}
                          height={MARK}
                          rx={MARK / 2}
                          fill={fill}
                          stroke={chosen ? 'rgb(var(--accent))' : 'rgb(var(--surface-1))'}
                          strokeWidth={2}
                        />
                        {fits ? (
                          <text
                            x={x + w / 2}
                            y={cy + 3.5}
                            textAnchor="middle"
                            pointerEvents="none"
                            fill={inkOn(stage)}
                            className="font-mono text-[10px] font-semibold"
                          >
                            {text}
                          </text>
                        ) : (
                          beside && (
                            <text
                              x={x + w + 4}
                              y={cy + 3.5}
                              pointerEvents="none"
                              className="fill-dim font-mono text-[10px]"
                            >
                              {text}
                            </text>
                          )
                        )}
                        {/* The hit area is at least 24 px wide and as tall as the lane. */}
                        <rect
                          x={Math.min(x, x + w / 2 - 12)}
                          y={cy - LANE / 2 + 2}
                          width={Math.max(w, 24)}
                          height={LANE - 4}
                          fill="transparent"
                          className="cursor-pointer outline-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-accent"
                          tabIndex={0}
                          role="button"
                          aria-label={`${name}: ${alertsWords(n)}, ${spanWords(span)}. ${
                            stage ? stageLabel(stage) : 'No proven stage'
                          }.`}
                          onPointerMove={() => setHover({ lane, cluster: c, x: x + w / 2, y: cy + LANE / 2 })}
                          onFocus={() => setHover({ lane, cluster: c, x: x + w / 2, y: cy + LANE / 2 })}
                          onBlur={() => setHover(null)}
                          onClick={() => pick(lane, c)}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter') pick(lane, c);
                          }}
                        />
                      </g>
                    );
                  })}
                </g>
              );
            })}
          </svg>

          {/* The lane names are HTML, so a long name wraps and stays whole. */}
          {lanes.map((lane, i) => (
            <div
              key={lane.key}
              className="absolute left-0 flex items-center pr-3 text-[12px] font-semibold leading-tight text-text-2"
              style={{ top: top + i * LANE, height: LANE, width: GUTTER }}
            >
              <span className="break-words">{laneName(lane)}</span>
            </div>
          ))}

          {hover && (
            <HoverTip
              testId="timeline-tooltip"
              container={ref.current}
              x={hover.x - 145}
              y={hover.y}
              width={290}
              gap={6}
              rise={LANE}
            >
              <ClusterTip lane={hover.lane} cluster={hover.cluster} bucket={bucket} />
            </HoverTip>
          )}
        </div>
      </div>
    </Panel>
  );
}

function ClusterTip({ lane, cluster, bucket }: { lane: TimelineLane; cluster: TimeCluster; bucket: number }) {
  const span = markSpan(cluster, bucket);
  // The findings inside the span, the highest stage first.
  const findings = investigationsIn(lane, span)
    .filter((r) => r.finding)
    .sort((a, b) => stageRank(b.stage) - stageRank(a.stage) || a.t - b.t);
  const proved = highestStage(findings.map((f) => f.stage));
  const titles = [...new Set(findings.map((f) => f.label))];
  return (
    <>
      <div className="font-mono text-[10.5px] text-faint">{spanWords(span)}</div>
      <div className="mt-1 text-text-2">
        <span className="font-semibold text-text">{alertsWords(cluster.count)}</span> of {laneName(lane)}
      </div>
      {proved && (
        <div data-testid="timeline-proved" className="mt-1 inline-flex items-center gap-1.5 text-text-2">
          <span aria-hidden className="h-[3px] w-3 rounded-full" style={{ background: stageColor(proved) }} />
          {provedWords(proved)}
        </div>
      )}
      {titles.slice(0, MAX_FINDINGS).map((title) => (
        <div key={title} className="mt-1 break-words text-dim">
          {title}
        </div>
      ))}
    </>
  );
}
