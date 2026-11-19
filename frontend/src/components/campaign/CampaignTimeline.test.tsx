import { fireEvent, render, screen, within } from '@testing-library/react';
import { useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import type { CampaignChange, CampaignEvents, CampaignMember } from '../../lib/api';
import { ACTOR, CAMPAIGN, CASE_AT, CASE_CHANGES, CLOSED_CHANGES, EVENTS, TARGET } from '../../test/campaign';
import { CampaignTimeline } from './CampaignTimeline';
import type { CampaignSelection } from './selection';

/** The timeline with the selection state of the page around it. */
function mount(
  events: CampaignEvents | undefined = EVENTS,
  members: CampaignMember[] = CAMPAIGN.members,
  changes?: CampaignChange[],
) {
  const onSelect = vi.fn();
  function Harness() {
    const [selection, setSelection] = useState<CampaignSelection | null>(null);
    return (
      <CampaignTimeline
        events={events}
        members={members}
        parties={CAMPAIGN.parties}
        ladder={CAMPAIGN.ladder}
        changes={changes}
        selection={selection}
        onSelect={(next) => {
          onSelect(next);
          setSelection(next);
        }}
      />
    );
  }
  const view = render(<Harness />);
  return { onSelect, ...view };
}

/** The events with a second lane: web-1 sends alert events to 192.0.2.30. */
const TWO_LANES: CampaignEvents = {
  ...EVENTS,
  timeline: {
    ...EVENTS.timeline,
    lanes: [
      { machineKey: TARGET.machineKey, buckets: [{ at: '2026-10-29T08:00:00Z', alerts: 2 }] },
      ...EVENTS.timeline.lanes,
    ],
  },
};

const marks = () => screen.getAllByTestId('timeline-mark');
const markButton = (i: number) => within(marks()[i]).getByRole('button');

describe('CampaignTimeline', () => {
  it('draws one lane for each machine with alert events, the actors first', () => {
    mount(TWO_LANES);
    const lanes = screen.getAllByTestId('timeline-lane');
    expect(lanes.map((l) => l.getAttribute('data-lane'))).toEqual([ACTOR.machineKey, TARGET.machineKey]);
    expect(screen.getByText('actor-a')).toBeInTheDocument();
    expect(screen.getByText('web-1')).toBeInTheDocument();
  });

  it('draws one flag for each reached stage', () => {
    mount();
    const flags = screen.getAllByTestId('timeline-flag');
    const reached = CAMPAIGN.ladder.filter((s) => s.reached).map((s) => s.stage);
    expect(flags.map((f) => f.getAttribute('data-stage'))).toEqual(reached);
    // NEGATIVE CONTROL: a stage that the campaign did not reach has no flag.
    expect(flags.some((f) => f.getAttribute('data-stage') === 'access')).toBe(false);
  });

  // N11: the Access mark sat at the first proof of the stage itself, and the
  // ladder stated an earlier "by" time from a later stage. The hover of the
  // mark states both.
  it('states the earlier "by" time of a held stage in the hover of its mark', () => {
    const ladder = CAMPAIGN.ladder.map((s) =>
      s.stage === 'reconnaissance'
        ? { ...s, heldBy: { at: '2026-10-24T00:10:00Z', stage: 'attempt' as const } }
        : s,
    );
    render(
      <CampaignTimeline
        events={EVENTS}
        members={CAMPAIGN.members}
        parties={CAMPAIGN.parties}
        ladder={ladder}
        selection={null}
        onSelect={() => {}}
      />,
    );
    const flags = screen.getAllByTestId('timeline-flag');
    const held = flags.find((f) => f.getAttribute('data-stage') === 'reconnaissance')!;
    expect(held).toHaveAccessibleName(
      'Reconnaissance by 2026-10-24 00:10:00 UTC. Attempt needs this stage and has proof at this time. ' +
        'First proof of this stage itself: 2026-10-24 00:40:00 UTC.',
    );
    expect(held.querySelector('title')?.textContent).toBe(held.getAttribute('aria-label'));
    // Negative control: a stage with no earlier hold states its own time only.
    const own = flags.find((f) => f.getAttribute('data-stage') === 'attempt')!;
    expect(own).toHaveAccessibleName('Attempt: 2026-10-24 01:11:05 UTC.');
  });

  it('states the alert sum of a mark and joins the buckets of one evening', () => {
    mount();
    // The buckets of 00:40 and 01:10 are one mark of 12 + 31 alerts. The bucket four days later is its own.
    expect(marks().map((m) => m.getAttribute('data-alerts'))).toEqual(['43', '4']);
    expect(within(marks()[0]).getByText('43')).toBeInTheDocument();
    expect(markButton(0)).toHaveAccessibleName('actor-a: 43 alerts, 2026-10-24 00:40 to 01:20 UTC. Attempt.');
    // A mark of one bucket states its count beside it.
    expect(within(marks()[1]).getByText('4')).toBeInTheDocument();
    // NEGATIVE CONTROL: the marks hold every alert event of the timeline and no investigation count.
    expect(marks().reduce((n, m) => n + Number(m.getAttribute('data-alerts')), 0)).toBe(EVENTS.alerts);
  });

  it('colors a mark by the stage of the lane, by a finding inside its span, or gray', () => {
    mount(TWO_LANES);
    const stages = marks().map((m) => [m.closest('[data-lane]')?.getAttribute('data-lane'), m.getAttribute('data-stage')]);
    expect(stages).toEqual([
      // The alerts of actor-a prove an attempt. No finding is inside the span.
      [ACTOR.machineKey, 'attempt'],
      // The web shell finding at 22:44:56 is inside the span and proves action on the target.
      [ACTOR.machineKey, 'action'],
      // web-1 has no alert investigation and no finding inside the span.
      [TARGET.machineKey, 'none'],
    ]);
    expect(within(marks()[2]).getByRole('button')).toHaveAccessibleName(
      'web-1: 2 alerts, 2026-10-29 08:00 to 08:10 UTC. No proven stage.',
    );
  });

  it('selects the investigations of the machine inside the span of a mark, and clears them on a second click', () => {
    const { onSelect } = mount();
    fireEvent.click(markButton(0));
    expect(onSelect).toHaveBeenLastCalledWith({
      kind: 'runs',
      runIds: ['run-actor', 'run-seed', 'run-session'],
      label: 'actor-a, 2026-10-24 00:40 to 01:20 UTC',
      span: {
        lane: ACTOR.machineKey,
        from: Date.parse('2026-10-24T00:40:00Z'),
        to: Date.parse('2026-10-24T01:20:00Z'),
      },
    });
    // The other mark dims.
    expect(marks()[1]).toHaveAttribute('opacity', '0.35');
    expect(marks()[0]).toHaveAttribute('opacity', '1');
    fireEvent.click(markButton(0));
    expect(onSelect).toHaveBeenLastCalledWith(null);
  });

  it('selects no investigation for a mark that holds none, and tells two such marks apart', () => {
    const { onSelect } = mount(TWO_LANES);
    fireEvent.click(markButton(2));
    expect(onSelect).toHaveBeenLastCalledWith(
      expect.objectContaining({ kind: 'runs', runIds: [], label: 'web-1, 2026-10-29 08:00 to 08:10 UTC' }),
    );
    // NEGATIVE CONTROL: a click on another mark selects it. It does not clear the pick.
    fireEvent.click(markButton(1));
    expect(onSelect).toHaveBeenLastCalledWith(expect.objectContaining({ runIds: ['run-shell'] }));
  });

  it('states the alerts of a mark and the stage that a finding inside it proves', () => {
    mount();
    fireEvent.focus(markButton(1));
    const tip = screen.getByTestId('timeline-tooltip');
    expect(tip).toHaveTextContent('2026-10-28 22:40 to 22:50 UTC');
    expect(tip).toHaveTextContent('4 alerts of actor-a');
    expect(within(tip).getByTestId('timeline-proved')).toHaveTextContent('soc-ai proved: Action on the target');
    expect(tip).toHaveTextContent('Command execution through the web shell');
    fireEvent.blur(markButton(1));
    // NEGATIVE CONTROL: a mark with no finding inside states no proof and no title.
    fireEvent.focus(markButton(0));
    const first = screen.getByTestId('timeline-tooltip');
    expect(first).toHaveTextContent('43 alerts of actor-a');
    expect(within(first).queryByTestId('timeline-proved')).toBeNull();
    expect(first).not.toHaveTextContent('Command execution');
  });

  it('states where the marks come from for the grid and for the stored events', () => {
    const { unmount } = mount();
    expect(screen.getByTestId('timeline-note')).toHaveTextContent(
      'The marks count the alert events of the grid. Times are in UTC. Drag across the chart to zoom in.',
    );
    unmount();
    mount({ ...EVENTS, source: 'stored', records: null });
    expect(screen.getByTestId('timeline-note')).toHaveTextContent(
      'soc-ai could not read the grid. The marks count the alert events that its investigations hold. ' +
        'Times are in UTC. Drag across the chart to zoom in.',
    );
  });

  it('zooms in on a drag and shows the whole period again on the button', () => {
    mount();
    expect(screen.queryByRole('button', { name: 'Show the whole period' })).toBeNull();
    expect(marks()).toHaveLength(2);
    const surface = screen.getByTestId('timeline-surface');
    // The plot starts at 148 px and spans about five days in 912 px. The
    // buckets of 00:40 and 01:10 on 2026-10-24 sit near 174 and 178 px.
    fireEvent.pointerDown(surface, { clientX: 165, pointerId: 1 });
    fireEvent.pointerMove(surface, { clientX: 185, pointerId: 1 });
    fireEvent.pointerUp(surface, { clientX: 185, pointerId: 1 });
    const reset = screen.getByRole('button', { name: 'Show the whole period' });
    // The zoom leaves the bucket of 2026-10-28 out and splits the two buckets of 2026-10-24.
    expect(marks().map((m) => m.getAttribute('data-alerts'))).toEqual(['12', '31']);
    fireEvent.click(reset);
    expect(screen.queryByRole('button', { name: 'Show the whole period' })).toBeNull();
    expect(marks().map((m) => m.getAttribute('data-alerts'))).toEqual(['43', '4']);
  });

  // NEGATIVE CONTROL: a click with no drag does not zoom.
  it('does not zoom on a click of the surface', () => {
    mount();
    const surface = screen.getByTestId('timeline-surface');
    fireEvent.pointerDown(surface, { clientX: 300, pointerId: 1 });
    fireEvent.pointerUp(surface, { clientX: 300, pointerId: 1 });
    expect(screen.queryByRole('button', { name: 'Show the whole period' })).toBeNull();
  });

  it('renders nothing with no events, with a source of none, or with an empty timeline', () => {
    for (const events of [
      undefined,
      { ...EVENTS, source: 'none' as const },
      { ...EVENTS, timeline: { bucketSeconds: 600, lanes: [] } },
      { ...EVENTS, timeline: { bucketSeconds: 600, lanes: [{ machineKey: ACTOR.machineKey, buckets: [] }] } },
    ]) {
      // A direct render: the default of mount() would fill in the events.
      const { container, unmount } = render(
        <CampaignTimeline
          events={events}
          members={CAMPAIGN.members}
          parties={CAMPAIGN.parties}
          ladder={CAMPAIGN.ladder}
          selection={null}
          onSelect={() => {}}
        />,
      );
      expect(container).toBeEmptyDOMElement();
      unmount();
    }
  });

  // NEGATIVE CONTROL: the marks come from the events. Investigations with no time do not remove them.
  it('draws the marks when no investigation has a time', () => {
    mount(EVENTS, CAMPAIGN.members.map((m) => ({ ...m, eventAt: null })));
    expect(marks().map((m) => m.getAttribute('data-alerts'))).toEqual(['43', '4']);
    expect(marks().map((m) => m.getAttribute('data-stage'))).toEqual(['none', 'none']);
  });
});

describe('CampaignTimeline decisions', () => {
  it('marks each decision and each reopen on the time axis, oldest first', () => {
    mount(EVENTS, CAMPAIGN.members, CLOSED_CHANGES);
    const markers = screen.getAllByTestId('timeline-decision');
    expect(markers.map((m) => m.getAttribute('data-type'))).toEqual(['decided', 'reopened', 'decided']);
    expect(markers.map((m) => m.getAttribute('aria-label'))).toEqual([
      '2026-10-30 10:00 UTC: analyst-2 closed the campaign. Reason: Accepted risk.',
      '2026-11-02 08:00 UTC: A later event opened the campaign again.',
      '2026-11-14 21:00 UTC: admin closed the campaign. Reason: Test that is over.',
    ]);
    expect(screen.getAllByTestId('timeline-decision-label').map((m) => m.textContent)).toEqual([
      'Closed',
      'Opened again',
      'Closed',
    ]);
  });

  it('widens the axis so that a close after the last event stays on it', () => {
    mount(EVENTS, CAMPAIGN.members, CLOSED_CHANGES);
    const svg = screen.getByTestId('campaign-timeline').querySelector('svg') as SVGSVGElement;
    const width = Number(svg.getAttribute('width'));
    const xs = screen.getAllByTestId('timeline-decision').map((m) => Number(m.getAttribute('data-x')));
    // In time order, and inside the plot.
    expect([...xs].sort((a, b) => a - b)).toEqual(xs);
    for (const x of xs) {
      expect(x).toBeGreaterThan(148);
      expect(x).toBeLessThanOrEqual(width - 20);
    }
    // The marks of the alert events sit left of the first close.
    const markXs = screen.getAllByTestId('timeline-mark').map((m) => Number(m.querySelector('rect')?.getAttribute('x')));
    expect(Math.max(...markXs)).toBeLessThan(xs[0]);
  });

  it('draws no marker for the other changes, nor with no changes', () => {
    const others = CLOSED_CHANGES.filter((c) => c.type !== 'decided' && c.type !== 'reopened');
    const { unmount } = mount(EVENTS, CAMPAIGN.members, others);
    expect(screen.queryAllByTestId('timeline-decision')).toEqual([]);
    unmount();
    mount();
    expect(screen.queryAllByTestId('timeline-decision')).toEqual([]);
  });

  it('marks a reopen by an analyst with the name of the analyst', () => {
    const byAnalyst: CampaignChange = { id: 20, type: 'reopened', at: '2026-11-15T09:00:00Z', detail: { cause: 'analyst', by: 'admin' } };
    mount(EVENTS, CAMPAIGN.members, [byAnalyst]);
    const markers = screen.getAllByTestId('timeline-decision');
    expect(markers).toHaveLength(1);
    expect(markers[0]).toHaveAttribute('aria-label', '2026-11-15 09:00 UTC: admin opened the campaign again.');
  });
});

describe('CampaignTimeline case', () => {
  it('marks the case and each comment of soc-ai, oldest first', () => {
    mount(EVENTS, CAMPAIGN.members, CASE_CHANGES);
    const markers = screen.getAllByTestId('timeline-decision');
    // The request and the refusal are no marks: the Changes fold states them.
    expect(markers.map((m) => m.getAttribute('data-type'))).toEqual(['case', 'case_comment', 'case_comment']);
    expect(markers.map((m) => m.getAttribute('aria-label'))).toEqual([
      '2026-11-15 09:00 UTC: analyst-2 opened the case case-0c41 in Security Onion with 21 alerts.',
      '2026-11-15 22:10 UTC: soc-ai added a comment to the case case-0c41 for a higher stage.',
      '2026-11-16 07:30 UTC: soc-ai added a comment to the case case-0c41 for a new machine.',
    ]);
    // A comment is a smaller round mark. The case is a square, as a decision.
    expect(markers.map((m) => (m.querySelector('circle') ? 'circle' : 'square'))).toEqual(['square', 'circle', 'circle']);
    const labels = screen.getAllByTestId('timeline-decision-label').map((m) => m.textContent);
    expect(labels[0]).toBe('Case');
    for (const label of labels.slice(1)) expect(label).toBe('Comment');
  });

  it('draws one mark for a case that the server states twice', () => {
    const decided: CampaignChange = { id: 40, type: 'decided', at: CASE_AT, detail: { decision: 'case', by: 'analyst-2' } };
    const { unmount } = mount(EVENTS, CAMPAIGN.members, [decided, ...CASE_CHANGES]);
    expect(screen.getAllByTestId('timeline-decision').map((m) => m.getAttribute('data-type'))).toEqual([
      'case',
      'case_comment',
      'case_comment',
    ]);
    unmount();
    // NEGATIVE CONTROL: a case decision with no case change keeps its mark.
    mount(EVENTS, CAMPAIGN.members, [decided]);
    const markers = screen.getAllByTestId('timeline-decision');
    expect(markers.map((m) => m.getAttribute('data-type'))).toEqual(['decided']);
    expect(screen.getAllByTestId('timeline-decision-label').map((m) => m.textContent)).toEqual(['Case']);
  });
});
