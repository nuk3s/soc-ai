import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { CAMPAIGN_HUNTS_CAP, type CampaignChange, type CampaignHunt, type CampaignLead } from '../../lib/api';
import {
  CHANGES_LANE,
  HUNTS_HEADING,
  HUNTS_LANE,
  HUNT_MARKS_LABEL,
  LEADS_HEADING,
  LEAD_COVERED,
  LEAD_NOT_HUNTED,
  LEAD_OF_CAMPAIGN,
  LEAD_OF_CAMPAIGN_TITLE,
  OPEN_LEAD,
  changeSentence,
  huntFindingsWords,
  huntMarkWords,
  huntStarterLabel,
  huntsCapSentence,
} from '../../lib/campaignWords';
import {
  TIMELINE_GUTTER,
  TIMELINE_RIGHT,
  clusterPoints,
  highestStage,
  huntChanges,
  padDomain,
  stageColor,
  tickLabel,
  timeTicks,
  type TimeCluster,
  type TimePoint,
} from '../../lib/campaignViz';
import { statusLabel } from '../../lib/labels';
import { utcStamp } from '../../lib/timeRange';
import { useElementWidth } from '../../lib/useElementWidth';
import { LEAD_STATE_LABEL, LEAD_STATUS_LABEL, leadStatusLabel } from '../LeadsStrip';
import { HoverTip } from './HoverTip';

const ROW = 'px-[15px] py-2.5 text-[12.5px]';
const HEADING = 'px-[15px] pt-3 text-[11.5px] font-semibold text-dim';
const LANE = 34;
const AXIS = 26;
const MARK = 14;
/** Two marks closer than this many pixels are one mark. */
const CLUSTER_GAP = 18;
/** The tone of a hunt and of a change with no stage. */
const NEUTRAL = 'rgb(var(--text-2))';
/** The most hunts or changes that the hover of one mark lists. */
const MAX_IN_TIP = 5;

/** The word of the state of a lead, in the words of the lead pages: a closed
 *  lead reads Closed, a lead with a hunt of its own reads Hunted. */
function leadStateWord(l: CampaignLead): string {
  if (l.state === 'dismissed' || l.state === 'promoted') return LEAD_STATUS_LABEL[l.state];
  if (l.hunted) return LEAD_STATE_LABEL.hunted;
  return leadStatusLabel(l.state);
}

/** What soc-ai did about the activity of a campaign: the hunts on the time
 *  axis of the campaign beside the changes that can start a hunt, then the
 *  leads of the campaign, then the hunts. One hunt answers one change, so the
 *  two lanes show a hunt for each change. A lead of the campaign reads as
 *  handled by the campaign, with one link to the lead. A related lead is in
 *  the fold "Related, not proven". */
export function CampaignLeadsHunts({
  leads,
  hunts,
  changes,
  firstEvent,
  lastEvent,
}: {
  leads: readonly CampaignLead[];
  hunts: readonly CampaignHunt[];
  changes: readonly CampaignChange[];
  firstEvent: string;
  lastEvent: string;
}) {
  const own = leads.filter((l) => !l.related);
  return (
    <div data-testid="campaign-leads-hunts">
      {hunts.length > 0 && (
        <HuntMarks hunts={hunts} changes={changes} firstEvent={firstEvent} lastEvent={lastEvent} />
      )}
      {own.length > 0 && (
        <section>
          <h3 className={HEADING}>{LEADS_HEADING}</h3>
          <ul data-testid="campaign-leads" className="divide-y divide-border-faint">
            {own.map((l) => (
              <li key={l.id} data-testid={`campaign-lead-${l.id}`} className={ROW}>
                <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
                  <span
                    title={LEAD_OF_CAMPAIGN_TITLE}
                    className="flex-none rounded-chip border border-border-strong bg-surface-2 px-1.5 py-px text-[10.5px] font-semibold text-text-2"
                  >
                    {LEAD_OF_CAMPAIGN}
                  </span>
                  <span className="min-w-0 break-words text-text">{l.title}</span>
                  <span className="text-dim">{leadStateWord(l)}</span>
                  {!l.hunted && (
                    <span className="text-dim">{hunts.length > 0 ? LEAD_COVERED : LEAD_NOT_HUNTED}</span>
                  )}
                  <Link to={`/leads/${l.id}`} className="ml-auto font-semibold text-accent hover:underline">
                    {OPEN_LEAD}
                  </Link>
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}
      {hunts.length > 0 && (
        <section className={own.length > 0 ? 'border-t border-border-faint' : undefined}>
          <h3 className={HEADING}>{HUNTS_HEADING}</h3>
          <ul data-testid="campaign-hunts" className="divide-y divide-border-faint">
            {hunts.map((h) => (
              <li key={h.id} data-testid={`campaign-hunt-${h.id}`} className={ROW}>
                <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
                  <Link to={`/hunts/${h.id}`} className="font-semibold text-accent hover:underline">
                    {huntStarterLabel(h.starter)}
                  </Link>
                  <span className="font-mono text-[11.5px] text-faint">{utcStamp(h.startedAt)}</span>
                  <span className="text-text-2">{statusLabel(h.status)}</span>
                  <span className="text-dim">{huntFindingsWords(h.findings, h.threatFindings)}</span>
                </div>
              </li>
            ))}
          </ul>
          {hunts.length >= CAMPAIGN_HUNTS_CAP && (
            <div data-testid="campaign-hunts-cap" className={`${ROW} text-faint`}>
              {huntsCapSentence(CAMPAIGN_HUNTS_CAP)}
            </div>
          )}
        </section>
      )}
    </div>
  );
}

/** A hover opens under the lane of the hunts, for a mark of either lane, so
 *  it covers neither lane: a change and its hunt stay in view together. */
interface Hover {
  lane: 'hunts' | 'changes';
  cluster: TimeCluster;
  x: number;
  y: number;
}

/** The two lanes: the changes that can start a hunt, and the hunts. The axis
 *  reads the padding rule and the ticks of the timeline, and the gutter has
 *  its width, so a time sits at one x on both charts when the periods agree. */
function HuntMarks({
  hunts,
  changes,
  firstEvent,
  lastEvent,
}: {
  hunts: readonly CampaignHunt[];
  changes: readonly CampaignChange[];
  firstEvent: string;
  lastEvent: string;
}) {
  const [ref, width] = useElementWidth<HTMLDivElement>(1080);
  const [hover, setHover] = useState<Hover | null>(null);
  const navigate = useNavigate();
  const byId = new Map(hunts.map((h) => [h.id, h]));
  const huntPoints: TimePoint[] = hunts.flatMap((h) => {
    const t = Date.parse(h.startedAt ?? '');
    return Number.isNaN(t) ? [] : [{ id: h.id, t, stage: null, label: h.id }];
  });
  const changeOf = new Map<string, CampaignChange>();
  const changePoints: TimePoint[] = huntChanges(changes).map((c) => {
    changeOf.set(`change-${c.id}`, c);
    return { id: `change-${c.id}`, t: Date.parse(c.at), stage: c.type === 'stage' ? (c.detail?.to ?? null) : null, label: c.type };
  });
  if (huntPoints.length === 0) return null;

  const times = [
    ...huntPoints.map((p) => p.t),
    ...changePoints.map((p) => p.t),
    Date.parse(firstEvent),
    Date.parse(lastEvent),
  ].filter((t) => !Number.isNaN(t));
  const [d0, d1] = padDomain(Math.min(...times), Math.max(...times));
  const plot = Math.max(240, width - TIMELINE_GUTTER - TIMELINE_RIGHT);
  const scale = (t: number): number => TIMELINE_GUTTER + ((t - d0) / (d1 - d0)) * plot;
  const { step, ticks } = timeTicks(d0, d1, Math.max(3, Math.floor(plot / 84)));
  const huntMarks = clusterPoints(huntPoints, scale, CLUSTER_GAP);
  const changeMarks = clusterPoints(changePoints, scale, CLUSTER_GAP);
  const height = 2 * LANE + AXIS;
  const changeY = LANE / 2;
  const huntY = LANE + LANE / 2;
  const huntsOf = (c: TimeCluster) => c.points.map((p) => byId.get(p.id)).filter((h): h is CampaignHunt => !!h);
  const huntWords = (h: CampaignHunt) => huntMarkWords(h, statusLabel(h.status));

  return (
    <div className="px-[15px] pb-2 pt-3">
      <div
        ref={ref}
        data-testid="campaign-hunt-marks"
        className="relative select-none"
        style={{ height }}
        onPointerLeave={() => setHover(null)}
      >
        <svg width={width} height={height} className="absolute left-0 top-0" role="img" aria-label={HUNT_MARKS_LABEL}>
          {ticks.map((t) => (
            <line
              key={t}
              x1={scale(t)}
              x2={scale(t)}
              y1={0}
              y2={2 * LANE}
              stroke="rgb(var(--border))"
              strokeWidth={1}
            />
          ))}
          {[1, 2].map((i) => (
            <line
              key={i}
              x1={TIMELINE_GUTTER}
              x2={TIMELINE_GUTTER + plot}
              y1={i * LANE}
              y2={i * LANE}
              stroke="rgb(var(--border))"
              strokeWidth={1}
            />
          ))}
          {ticks.map((t) => (
            <text
              key={`label-${t}`}
              data-testid="hunt-axis-tick"
              x={scale(t)}
              y={2 * LANE + 16}
              textAnchor="middle"
              className="fill-faint font-mono text-[10.5px]"
            >
              {tickLabel(t, step)}
            </text>
          ))}

          {/* Each change that can start a hunt: a diamond, in the color of the
              stage that a stage change reached, else in the neutral tone. */}
          {changeMarks.map((c) => {
            const x = (c.x0 + c.x1) / 2;
            const list = c.points.map((p) => changeOf.get(p.id)).filter((v): v is CampaignChange => !!v);
            const stage = highestStage(list.map((v) => (v.type === 'stage' ? (v.detail?.to ?? null) : null)));
            const words = list.map((v) => `${utcStamp(v.at)}: ${changeSentence(v)}`).join(' ');
            return (
              <g
                key={c.key}
                data-testid="hunt-change-mark"
                data-types={list.map((v) => v.type).join(' ')}
                data-x={x}
              >
                <rect
                  x={x - 4.5}
                  y={changeY - 4.5}
                  width={9}
                  height={9}
                  transform={`rotate(45 ${x} ${changeY})`}
                  fill={stage ? stageColor(stage) : NEUTRAL}
                  stroke="rgb(var(--surface-1))"
                  strokeWidth={2}
                />
                <rect
                  x={x - 12}
                  y={2}
                  width={24}
                  height={LANE - 4}
                  fill="transparent"
                  tabIndex={0}
                  role="img"
                  aria-label={words}
                  className="outline-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-accent"
                  onPointerMove={() => setHover({ lane: 'changes', cluster: c, x, y: 2 * LANE })}
                  onFocus={() => setHover({ lane: 'changes', cluster: c, x, y: 2 * LANE })}
                  onBlur={() => setHover(null)}
                />
              </g>
            );
          })}

          {/* Each hunt: a mark in the neutral tone. Hunts that sit too close
              to draw apart are one mark with their count. */}
          {huntMarks.map((c) => {
            const x = c.x0 - MARK / 2;
            const w = c.x1 - c.x0 + MARK;
            const list = huntsOf(c);
            const single = list.length === 1 ? list[0] : null;
            const open = () => {
              if (single) navigate(`/hunts/${single.id}`);
            };
            return (
              <g
                key={c.key}
                data-testid="hunt-mark"
                data-hunts={list.map((h) => h.id).join(' ')}
                data-x={(c.x0 + c.x1) / 2}
              >
                <rect
                  x={x}
                  y={huntY - MARK / 2}
                  width={w}
                  height={MARK}
                  rx={MARK / 2}
                  fill={NEUTRAL}
                  stroke="rgb(var(--surface-1))"
                  strokeWidth={2}
                />
                {list.length > 1 && (
                  <text
                    x={x + w / 2}
                    y={huntY + 3.5}
                    textAnchor="middle"
                    pointerEvents="none"
                    fill="#0b0e13"
                    className="font-mono text-[10px] font-semibold"
                  >
                    {list.length.toLocaleString()}
                  </text>
                )}
                <rect
                  x={Math.min(x, x + w / 2 - 12)}
                  y={LANE + 2}
                  width={Math.max(w, 24)}
                  height={LANE - 4}
                  fill="transparent"
                  tabIndex={0}
                  role={single ? 'button' : 'img'}
                  aria-label={list.map(huntWords).join(' ')}
                  className={`outline-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-accent ${
                    single ? 'cursor-pointer' : ''
                  }`}
                  onPointerMove={() => setHover({ lane: 'hunts', cluster: c, x: x + w / 2, y: 2 * LANE })}
                  onFocus={() => setHover({ lane: 'hunts', cluster: c, x: x + w / 2, y: 2 * LANE })}
                  onBlur={() => setHover(null)}
                  onClick={open}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') open();
                  }}
                />
              </g>
            );
          })}
        </svg>

        {/* The lane names are HTML, so a name wraps and stays whole. */}
        {[CHANGES_LANE, HUNTS_LANE].map((name, i) => (
          <div
            key={name}
            className="absolute left-0 flex items-center pr-3 text-[12px] font-semibold leading-tight text-text-2"
            style={{ top: i * LANE, height: LANE, width: TIMELINE_GUTTER }}
          >
            <span className="break-words">{name}</span>
          </div>
        ))}

        {hover && (
          <HoverTip
            testId="hunt-mark-tooltip"
            container={ref.current}
            x={hover.x - 145}
            y={hover.y}
            width={290}
            gap={6}
            rise={LANE}
          >
            {hover.lane === 'hunts' ? (
              <HuntsTip hunts={huntsOf(hover.cluster)} />
            ) : (
              <ChangesTip
                changes={hover.cluster.points
                  .map((p) => changeOf.get(p.id))
                  .filter((v): v is CampaignChange => !!v)}
              />
            )}
          </HoverTip>
        )}
      </div>
    </div>
  );
}

function HuntsTip({ hunts }: { hunts: CampaignHunt[] }) {
  return (
    <>
      {hunts.slice(0, MAX_IN_TIP).map((h, i) => (
        <div key={h.id} className={i > 0 ? 'mt-1.5' : undefined}>
          <div className="font-mono text-[10.5px] text-faint">{utcStamp(h.startedAt)}</div>
          <div className="text-text-2">
            <span className="font-semibold text-text">{huntStarterLabel(h.starter)}</span>
            {`. ${statusLabel(h.status)}.`}
          </div>
          <div className="text-dim">{huntFindingsWords(h.findings, h.threatFindings)}</div>
        </div>
      ))}
      {hunts.length > MAX_IN_TIP && (
        <div className="mt-1.5 text-faint">{`${(hunts.length - MAX_IN_TIP).toLocaleString()} more in the list below.`}</div>
      )}
    </>
  );
}

function ChangesTip({ changes }: { changes: CampaignChange[] }) {
  return (
    <>
      {changes.slice(0, MAX_IN_TIP).map((c, i) => (
        <div key={c.id} className={i > 0 ? 'mt-1.5' : undefined}>
          <div className="font-mono text-[10.5px] text-faint">{utcStamp(c.at)}</div>
          <div className="break-words text-text-2">{changeSentence(c)}</div>
        </div>
      ))}
      {changes.length > MAX_IN_TIP && (
        <div className="mt-1.5 text-faint">{`${(changes.length - MAX_IN_TIP).toLocaleString()} more in the fold Changes.`}</div>
      )}
    </>
  );
}
