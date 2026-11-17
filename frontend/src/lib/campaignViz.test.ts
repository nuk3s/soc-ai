import { describe, expect, it } from 'vitest';
import type { CampaignEvents, CampaignMember } from './api';
import {
  FOLD_KEY,
  LISTED_COLOR,
  MAX_COLUMN_NODES,
  OUTSIDE_COLOR,
  STAGE_COLOR,
  STAGE_SEQUENCE,
  TICK_STEPS,
  bucketMs,
  clusterPoints,
  highestStage,
  huntChanges,
  insideSpan,
  investigationsIn,
  layoutGraph,
  linkOutside,
  linkWidth,
  markSpan,
  markStage,
  padDomain,
  stageColor,
  tickLabel,
  timeTicks,
  timelineLanes,
  type TimePoint,
} from './campaignViz';
import {
  ACTOR,
  BEYOND_KEY,
  CAMPAIGN,
  CAMPAIGN_AUTHORIZED,
  CLOSED_CHANGES,
  EVENTS,
  MEMBER,
  PARTIES,
  TARGET,
  edge,
  party,
  session,
} from '../test/campaign';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** The relative luminance of a #rrggbb color. */
function luminance(hex: string): number {
  const channel = (i: number) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
}

describe('the stage colors', () => {
  it('are five distinct values that grow lighter in the order of the stages', () => {
    const colors = STAGE_SEQUENCE.map((s) => stageColor(s));
    expect(STAGE_SEQUENCE).toEqual(['reconnaissance', 'attempt', 'access', 'action', 'movement']);
    expect(new Set(colors).size).toBe(5);
    expect(colors).toEqual(STAGE_SEQUENCE.map((s) => STAGE_COLOR[s]));
    const light = colors.map(luminance);
    for (let i = 1; i < light.length; i++) expect(light[i]).toBeGreaterThan(light[i - 1]);
    // NEGATIVE CONTROL: no stage wears the gray of no stage, and none is a stage color.
    expect(colors).not.toContain(stageColor(null));
  });
});

/** The hue of a #rrggbb color in degrees. */
function hue(hex: string): number {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const max = Math.max(r, g, b);
  const d = max - Math.min(r, g, b);
  if (d === 0) return 0;
  const h = max === r ? ((g - b) / d) % 6 : max === g ? (b - r) / d + 2 : (r - g) / d + 4;
  return (h * 60 + 360) % 360;
}

const contrast = (a: string, b: string) => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
};

describe('the colors of an authorization', () => {
  const PANEL = '#0b0e13';
  it('are the danger tone and the neutral tone of the console', () => {
    expect(OUTSIDE_COLOR).toBe('#f04438');
    expect(LISTED_COLOR).toBe('#cdd5e0');
  });

  it('keep the danger tone off the stage ramp and readable on the panel', () => {
    for (const stage of STAGE_SEQUENCE) {
      const gap = Math.abs(hue(OUTSIDE_COLOR) - hue(STAGE_COLOR[stage]));
      expect(Math.min(gap, 360 - gap)).toBeGreaterThanOrEqual(20);
      // NEGATIVE CONTROL: no stage wears the danger tone.
      expect(STAGE_COLOR[stage]).not.toBe(OUTSIDE_COLOR);
    }
    expect(contrast(OUTSIDE_COLOR, PANEL)).toBeGreaterThanOrEqual(3);
    expect(contrast(LISTED_COLOR, PANEL)).toBeGreaterThanOrEqual(4.5);
  });
});

describe('linkOutside', () => {
  const actor = party({ machineKey: 'agent:a', role: 'actor' });
  const web = party({ machineKey: 'net:192.0.2.20' });
  const db = party({ machineKey: 'net:192.0.2.40' });
  const layout = layoutGraph([actor, web, db], [edge('agent:a', 'net:192.0.2.20'), edge('agent:a', 'net:192.0.2.40')], [], 1080);
  const toWeb = layout.links.find((l) => l.target.party?.machineKey === 'net:192.0.2.20')!;
  const toDb = layout.links.find((l) => l.target.party?.machineKey === 'net:192.0.2.40')!;

  it('marks the arrow of a pair with an investigation outside, in either direction', () => {
    expect(linkOutside(toDb, [{ sourceKey: 'agent:a', targetKey: 'net:192.0.2.40' }])).toBe(true);
    expect(linkOutside(toDb, [{ sourceKey: 'net:192.0.2.40', targetKey: 'agent:a' }])).toBe(true);
  });

  it('leaves every other arrow in its stage color', () => {
    // NEGATIVE CONTROLS: another pair, an end with no machine, and no list.
    expect(linkOutside(toWeb, [{ sourceKey: 'agent:a', targetKey: 'net:192.0.2.40' }])).toBe(false);
    expect(linkOutside(toWeb, [{ sourceKey: 'agent:a', targetKey: null }])).toBe(false);
    expect(linkOutside(toWeb, [])).toBe(false);
  });
});

describe('highestStage', () => {
  it('takes the stage furthest along the sequence', () => {
    expect(highestStage(['attempt', null, 'action', 'access'])).toBe('action');
    expect(highestStage(['movement', 'reconnaissance'])).toBe('movement');
    // NEGATIVE CONTROL: no stage at all gives null.
    expect(highestStage([])).toBeNull();
    expect(highestStage([null, undefined])).toBeNull();
  });
});

describe('linkWidth', () => {
  it('is thin for a count of one of many, 7 px for the largest, and grows with the count', () => {
    expect(linkWidth(1, 100)).toBeLessThan(2.1);
    expect(linkWidth(100, 100)).toBeCloseTo(7);
    let last = 0;
    for (let count = 1; count <= 100; count++) {
      const w = linkWidth(count, 100);
      expect(w).toBeGreaterThan(last);
      last = w;
    }
    // NEGATIVE CONTROL: a count above the largest does not grow past 7 px.
    expect(linkWidth(500, 100)).toBeCloseTo(7);
    expect(linkWidth(0, 10)).toBe(1.5);
  });
});

describe('layoutGraph', () => {
  it('puts the actors left and the targets right, with no third column without a beyond party', () => {
    const parties = PARTIES.filter((p) => !p.beyond);
    const layout = layoutGraph(parties, CAMPAIGN.graph.edges, [], 960);
    expect(layout.columns.map((c) => c.column)).toEqual([0, 1]);
    const actor = layout.nodes.find((n) => n.key === ACTOR.machineKey);
    const target = layout.nodes.find((n) => n.key === TARGET.machineKey);
    expect(actor?.column).toBe(0);
    expect(target?.column).toBe(1);
    expect(actor?.x).toBe(0);
    expect(target!.x).toBeGreaterThan(actor!.x);
  });

  it('opens a third column for a beyond party', () => {
    const layout = layoutGraph(PARTIES, CAMPAIGN.graph.edges, [], 960);
    expect(layout.columns.map((c) => c.column)).toEqual([0, 1, 2]);
    const beyond = layout.nodes.find((n) => n.key === BEYOND_KEY);
    const target = layout.nodes.find((n) => n.key === TARGET.machineKey);
    expect(beyond?.column).toBe(2);
    expect(beyond!.x).toBeGreaterThan(target!.x);
  });

  it('folds a long column into one node and keeps a target with its own arrow out of the fold', () => {
    const targets = Array.from({ length: 20 }, (_, i) =>
      party({ machineKey: `net:t${i}`, name: `t${i}`, memberRuns: 20 - i }),
    );
    const onward = party({ machineKey: 'net:onward', name: 'onward', beyond: true });
    const edges = [
      ...targets.map((t, i) => edge(ACTOR.machineKey, t.machineKey, { runs: 20 - i })),
      // The machine that matters least by runs acts on another host.
      edge('net:t19', 'net:onward', { beyond: true, stage: 'movement' }),
    ];
    const layout = layoutGraph([PARTIES[1], ...targets, onward], edges, [], 960);
    const column = layout.nodes.filter((n) => n.column === 1);
    expect(column).toHaveLength(MAX_COLUMN_NODES);
    const fold = column.find((n) => n.key === `${FOLD_KEY}1`);
    expect(fold?.party).toBeNull();
    expect(fold?.folded).toHaveLength(20 - (MAX_COLUMN_NODES - 1));
    expect(column.some((n) => n.key === 'net:t19')).toBe(true);
    expect(fold?.folded.map((p) => p.machineKey)).not.toContain('net:t19');
    // The arrows into the folded machines merge into one arrow.
    const intoFold = layout.links.filter((l) => l.target.key === `${FOLD_KEY}1`);
    expect(intoFold).toHaveLength(1);
    expect(intoFold[0].runs).toBe(fold!.folded.reduce((n, p) => n + p.memberRuns, 0));
    // The fold sends no alert count, so the merged arrow has none.
    expect(intoFold[0].alerts).toBeNull();
    // NEGATIVE CONTROL: a column at the limit does not fold.
    const short = layoutGraph([PARTIES[1], ...targets.slice(0, MAX_COLUMN_NODES)], edges, [], 960);
    expect(short.nodes.some((n) => n.key.startsWith(FOLD_KEY))).toBe(false);
  });

  it('sizes the arrows by the alert events when one arrow has them', () => {
    const t1 = party({ machineKey: 'net:t1', name: 't1' });
    const t2 = party({ machineKey: 'net:t2', name: 't2' });
    const t3 = party({ machineKey: 'net:t3', name: 't3' });
    const edges = [
      edge(ACTOR.machineKey, 'net:t1', { runs: 10, alerts: 1 }),
      edge(ACTOR.machineKey, 'net:t2', { runs: 1, alerts: 1072 }),
      // A finding with no alert event between the two machines.
      edge(ACTOR.machineKey, 'net:t3', { runs: 3, alerts: 0 }),
    ];
    const layout = layoutGraph([PARTIES[1], t1, t2, t3], edges, [], 960);
    const width = (key: string) => layout.links.find((l) => l.target.key === key)!.width;
    expect(width('net:t2')).toBeCloseTo(7);
    expect(width('net:t1')).toBeLessThan(width('net:t2'));
    expect(layout.links.find((l) => l.target.key === 'net:t2')?.alerts).toBe(1072);
    // An arrow with no alert event is a hairline in a graph of alerts.
    expect(width('net:t3')).toBe(1.5);
  });

  it('sizes the arrows by the investigations when no arrow has an alert event', () => {
    const t1 = party({ machineKey: 'net:t1', name: 't1' });
    const t2 = party({ machineKey: 'net:t2', name: 't2' });
    // A server of an earlier release sends no alert count.
    const edges = [edge(ACTOR.machineKey, 'net:t1', { runs: 10 }), edge(ACTOR.machineKey, 'net:t2', { runs: 1 })];
    const layout = layoutGraph([PARTIES[1], t1, t2], edges, [], 960);
    const link = (key: string) => layout.links.find((l) => l.target.key === key)!;
    expect(link('net:t1').width).toBeCloseTo(7);
    expect(link('net:t2').width).toBeLessThan(link('net:t1').width);
    // NEGATIVE CONTROL: no count from the server stays no count. It does not read as zero alerts.
    expect(link('net:t1').alerts).toBeNull();
  });

  it('draws the sessions of one pair on three ports as one related link with three ports', () => {
    const sessions = [session(ACTOR, TARGET, 443, 2), session(ACTOR, TARGET, 22, 5), session(ACTOR, TARGET, 80, 3)];
    const layout = layoutGraph(PARTIES, CAMPAIGN.graph.edges, sessions, 960);
    const related = layout.links.filter((l) => l.related);
    expect(related).toHaveLength(1);
    expect(related[0].ports).toEqual([22, 80, 443]);
    expect(related[0].documents).toBe(10);
    // A related line draws first, under the arrows of the runs.
    expect(layout.links[0].related).toBe(true);
  });

  it('gives every link a path and every run link a head', () => {
    const layout = layoutGraph(PARTIES, CAMPAIGN.graph.edges, [session(ACTOR, TARGET, 22)], 960);
    expect(layout.links.length).toBe(2);
    for (const l of layout.links) expect(l.path).toMatch(/^M [\d.-]+ [\d.-]+ C /);
    const run = layout.links.find((l) => !l.related);
    expect(run?.head.split(' ')).toHaveLength(3);
    // NEGATIVE CONTROL: a related line has no head.
    expect(layout.links.find((l) => l.related)?.head).toBe('');
  });
});

describe('clusterPoints', () => {
  const at = Date.parse('2026-10-24T01:00:00Z');
  const points: TimePoint[] = [
    { id: 'b', t: at + 5 * MINUTE, stage: 'action', label: 'B', count: 40 },
    { id: 'a', t: at, stage: 'attempt', label: 'A', count: 2 },
  ];

  it('joins two points closer than the gap into one mark with the sum and the highest stage', () => {
    // One pixel for each hour: five minutes apart is less than one pixel.
    const scale = (t: number) => (t - at) / HOUR;
    const marks = clusterPoints(points, scale, 18);
    expect(marks).toHaveLength(1);
    expect(marks[0].points.map((p) => p.id)).toEqual(['a', 'b']);
    expect(marks[0].stage).toBe('action');
    expect(marks[0].count).toBe(42);
  });

  it('splits them on a wider scale', () => {
    // One pixel for each ten seconds: five minutes apart is 30 px.
    const scale = (t: number) => (t - at) / 10_000;
    const marks = clusterPoints(points, scale, 18);
    expect(marks.map((m) => m.points.length)).toEqual([1, 1]);
    expect(marks.map((m) => m.stage)).toEqual(['attempt', 'action']);
    expect(marks.map((m) => m.count)).toEqual([2, 40]);
  });

  it('counts a point with no count as one', () => {
    const scale = (t: number) => (t - at) / HOUR;
    const marks = clusterPoints(
      [
        { id: 'a', t: at, stage: null, label: 'A' },
        { id: 'b', t: at + MINUTE, stage: null, label: 'B' },
      ],
      scale,
      18,
    );
    expect(marks.map((m) => m.count)).toEqual([2]);
    // NEGATIVE CONTROL: the function does not change its input.
    expect(points.map((p) => p.count)).toEqual([40, 2]);
  });
});

describe('timeTicks', () => {
  it('never gives more ticks than asked, and steps on round times', () => {
    const start = Date.parse('2026-10-24T01:11:05Z');
    const spans = [MINUTE, 7 * MINUTE, HOUR, 8 * HOUR, 30 * HOUR, 3 * DAY, 19 * DAY, 90 * DAY, 700 * DAY];
    for (const most of [3, 5, 8, 10]) {
      for (const span of spans) {
        for (const t0 of [start, Math.floor(start / DAY) * DAY]) {
          const { step, ticks } = timeTicks(t0, t0 + span, most);
          expect(ticks.length, `${span} in ${most}`).toBeLessThanOrEqual(most);
          expect(ticks.length, `${span} in ${most}`).toBeGreaterThan(0);
          for (const t of ticks) {
            expect(t % step).toBe(0);
            expect(t).toBeGreaterThanOrEqual(t0);
            expect(t).toBeLessThanOrEqual(t0 + span);
          }
        }
      }
    }
  });

  it('takes the smallest step that fits', () => {
    const t0 = Date.parse('2026-10-24T00:00:00Z');
    expect(timeTicks(t0, t0 + 6 * HOUR, 8).step).toBe(HOUR);
    expect(timeTicks(t0, t0 + 19 * DAY, 8).step).toBe(7 * DAY);
    expect(TICK_STEPS).toContain(timeTicks(t0, t0 + 50 * MINUTE, 8).step);
  });
});

describe('tickLabel', () => {
  it('states the date for a day step, the date and time at midnight, else the time', () => {
    const midnight = Date.parse('2026-10-24T00:00:00Z');
    expect(tickLabel(midnight, DAY)).toBe('10-24');
    expect(tickLabel(midnight + 12 * HOUR, DAY)).toBe('10-24');
    expect(tickLabel(midnight, 6 * HOUR)).toBe('10-24 00:00');
    expect(tickLabel(midnight + 6 * HOUR + 5 * MINUTE, 5 * MINUTE)).toBe('06:05');
  });
});

describe('timelineLanes', () => {
  const member = (over: Partial<CampaignMember>): CampaignMember => ({ ...MEMBER, ...over });
  const timeline = (lanes: CampaignEvents['timeline']['lanes'], bucketSeconds = 600): CampaignEvents['timeline'] => ({
    bucketSeconds,
    lanes,
  });

  it('makes one point for each bucket with alerts, at the middle of the bucket', () => {
    const lanes = timelineLanes(EVENTS.timeline, CAMPAIGN.members, PARTIES);
    expect(lanes.map((l) => l.key)).toEqual([ACTOR.machineKey]);
    expect(lanes[0].points.map((p) => p.count)).toEqual([12, 31, 4]);
    expect(lanes[0].points[0].t).toBe(Date.parse('2026-10-24T00:45:00Z'));
    expect(bucketMs(EVENTS.timeline)).toBe(600_000);
  });

  it('puts the actors first and drops a bucket with no alert and a lane with no bucket', () => {
    const lanes = timelineLanes(
      timeline([
        { machineKey: TARGET.machineKey, buckets: [{ at: '2026-10-24T00:10:00Z', alerts: 3 }] },
        { machineKey: ACTOR.machineKey, buckets: [{ at: '2026-10-24T01:00:00Z', alerts: 5 }, { at: '2026-10-24T02:00:00Z', alerts: 0 }] },
        { machineKey: BEYOND_KEY, buckets: [{ at: '2026-10-24T03:00:00Z', alerts: 0 }] },
      ]),
      CAMPAIGN.members,
      PARTIES,
    );
    expect(lanes.map((l) => l.key)).toEqual([ACTOR.machineKey, TARGET.machineKey]);
    expect(lanes[0].party?.role).toBe('actor');
    expect(lanes[0].points.map((p) => p.count)).toEqual([5]);
  });

  it('gives a lane the highest stage of the alert investigations of its machine', () => {
    const members = [
      member({ runId: 'seed', stage: 'attempt', eventAt: '2026-10-24T01:00:00Z' }),
      // The answer of the server: web-1 is the source, actor-a the target.
      member({ runId: 'answer', stage: 'access', sourceKey: TARGET.machineKey, targetKey: ACTOR.machineKey, direction: 'reverse', eventAt: '2026-10-24T01:01:00Z' }),
      member({ runId: 'shell', kind: 'finding', stage: 'action', eventAt: '2026-10-24T05:00:00Z' }),
      member({ runId: 'differs', stage: 'movement', verdictDiffers: true, eventAt: '2026-10-24T00:00:00Z' }),
      member({ runId: 'no-time', eventAt: null }),
    ];
    const [lane] = timelineLanes(
      timeline([{ machineKey: ACTOR.machineKey, buckets: [{ at: '2026-10-24T01:00:00Z', alerts: 5 }] }]),
      members,
      PARTIES,
    );
    // The reverse alert is in the lane of the actor. The finding gives the lane no stage.
    expect(lane.stage).toBe('access');
    expect(lane.investigations.map((r) => r.runId)).toEqual(['seed', 'answer', 'shell']);
    expect(lane.investigations.map((r) => r.finding)).toEqual([false, false, true]);
    // NEGATIVE CONTROL: the verdict that differs and the investigation with no time are in no lane.
    expect(lane.investigations.map((r) => r.runId)).not.toContain('differs');
    expect(lane.investigations.map((r) => r.runId)).not.toContain('no-time');
  });

  it('draws no lane with no timeline', () => {
    expect(timelineLanes(undefined, CAMPAIGN.members, PARTIES)).toEqual([]);
    expect(timelineLanes(timeline([]), CAMPAIGN.members, PARTIES)).toEqual([]);
    expect(bucketMs(undefined)).toBe(0);
  });
});

describe('markStage', () => {
  const [lane] = timelineLanes(EVENTS.timeline, CAMPAIGN.members, PARTIES);
  const span = (from: string, to: string) => ({ from: Date.parse(from), to: Date.parse(to) });

  it('takes the stage of the lane when no finding is inside the span', () => {
    // The alerts of actor-a prove reconnaissance and attempt.
    expect(lane.stage).toBe('attempt');
    expect(markStage(lane, span('2026-10-24T00:40:00Z', '2026-10-24T01:20:00Z'))).toBe('attempt');
  });

  it('takes the stage of a finding inside the span when it is higher', () => {
    // The web shell finding at 2026-10-28 22:44:56 proves action on the target.
    expect(markStage(lane, span('2026-10-28T22:40:00Z', '2026-10-28T22:50:00Z'))).toBe('action');
    // NEGATIVE CONTROL: a span that ends before the finding keeps the stage of the lane.
    expect(markStage(lane, span('2026-10-28T22:30:00Z', '2026-10-28T22:44:56Z'))).toBe('attempt');
  });

  it('is the gray of no proven stage with neither', () => {
    const bare = { stage: null, investigations: [] };
    expect(markStage(bare, span('2026-10-28T22:40:00Z', '2026-10-28T22:50:00Z'))).toBeNull();
    expect(stageColor(markStage(bare, span('2026-10-28T22:40:00Z', '2026-10-28T22:50:00Z')))).toBe(stageColor(null));
  });
});

describe('the span of a mark', () => {
  it('runs from the start of its first bucket to the end of its last', () => {
    const t0 = Date.parse('2026-10-24T00:45:00Z');
    const t1 = Date.parse('2026-10-24T01:15:00Z');
    expect(markSpan({ t0, t1 }, 10 * MINUTE)).toEqual({
      from: Date.parse('2026-10-24T00:40:00Z'),
      to: Date.parse('2026-10-24T01:20:00Z'),
    });
  });

  it('holds its start and not its end, and holds the instant of a span of no length', () => {
    const s = { from: 100, to: 200 };
    expect(insideSpan(100, s)).toBe(true);
    expect(insideSpan(199, s)).toBe(true);
    expect(insideSpan(200, s)).toBe(false);
    expect(insideSpan(99, s)).toBe(false);
    expect(insideSpan(50, { from: 50, to: 50 })).toBe(true);
  });

  it('selects the investigations of the lane inside the span, oldest first', () => {
    const [lane] = timelineLanes(EVENTS.timeline, CAMPAIGN.members, PARTIES);
    const picked = investigationsIn(lane, { from: Date.parse('2026-10-24T00:40:00Z'), to: Date.parse('2026-10-24T01:20:00Z') });
    expect(picked.map((r) => r.runId)).toEqual(['run-actor', 'run-seed', 'run-session']);
  });
});

describe('padDomain', () => {
  it('adds 3 percent of the period on each side', () => {
    expect(padDomain(0, 100 * DAY)).toEqual([-3 * DAY, 103 * DAY]);
  });

  it('adds at least 10 minutes, so one instant still has an axis', () => {
    const t = Date.parse('2026-10-24T01:16:00Z');
    expect(padDomain(t, t)).toEqual([t - 10 * MINUTE, t + 10 * MINUTE]);
    // NEGATIVE CONTROL: a long period takes the percentage, not the floor.
    expect(padDomain(0, DAY)[0]).toBeLessThan(-10 * MINUTE);
  });
});

describe('huntChanges', () => {
  it('keeps the changes that can start a hunt, oldest first', () => {
    const kept = huntChanges([...CLOSED_CHANGES, ...(CAMPAIGN_AUTHORIZED.changes ?? [])]);
    expect(kept.map((c) => `${c.type}:${c.id}`)).toEqual([
      'formed:1',
      'formed:1',
      'party:2',
      'party:2',
      'stage:3',
      'stage:3',
      'reopened:7',
      'beyond:21',
    ]);
  });

  it('leaves out a decision, an acknowledgement, a reopen by an analyst and a revoke', () => {
    const kept = huntChanges([
      { id: 1, type: 'decided', at: '2026-11-14T21:00:00Z', detail: { decision: 'closed' } },
      { id: 2, type: 'acknowledged', at: '2026-11-14T21:01:00Z', detail: { alerts: 3 } },
      { id: 3, type: 'reopened', at: '2026-11-15T08:00:00Z', detail: { cause: 'analyst', by: 'admin' } },
      { id: 4, type: 'reopened', at: '2026-11-15T09:00:00Z', detail: { cause: 'revoked', by: 'admin' } },
      { id: 5, type: 'excluded', at: '2026-11-15T10:00:00Z', detail: { runId: 'r' } },
      { id: 6, type: 'reopened', at: 'not a time', detail: { cause: 'stage' } },
    ]);
    expect(kept).toEqual([]);
    // NEGATIVE CONTROL: a reopen by new activity starts a hunt.
    expect(
      huntChanges([{ id: 7, type: 'reopened', at: '2026-11-15T11:00:00Z', detail: { cause: 'activity' } }]),
    ).toHaveLength(1);
  });
});
