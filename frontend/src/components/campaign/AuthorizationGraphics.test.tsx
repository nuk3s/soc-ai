// The graphics of an authorized campaign: the attack graph marks a listed
// machine with a shield and draws a pair beyond the authorization in the
// danger tone. The timeline draws the period as a band and marks the create,
// the expiry and the revoke.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import type { CampaignAuthorizationRecord, CampaignChange, CampaignDetail } from '../../lib/api';
import { OUTSIDE_COLOR, stageColor } from '../../lib/campaignViz';
import { utcStamp } from '../../lib/timeRange';
import { forbiddenWords } from '../../test/analystWords';
import {
  AUTHORIZATION,
  CAMPAIGN_AUTHORIZED,
  EVENTS,
  TARGET,
  expiryIn,
} from '../../test/campaign';
import { AttackGraph } from './AttackGraph';
import { CampaignTimeline } from './CampaignTimeline';

function graph(c: CampaignDetail, authorization = c.authorization, outside = c.beyond) {
  render(
    <MemoryRouter>
      <AttackGraph
        parties={c.parties}
        edges={c.graph.edges}
        related={c.related}
        members={c.members}
        pairs={c.events?.pairs}
        selection={null}
        onSelect={() => {}}
        authorization={authorization}
        outside={outside}
      />
    </MemoryRouter>,
  );
}

/** The events with a lane for web-1 on 2026-10-29, where it acts on 192.0.2.30. */
const EVENTS_TWO_LANES = {
  ...EVENTS,
  timeline: {
    ...EVENTS.timeline,
    lanes: [...EVENTS.timeline.lanes, { machineKey: TARGET.machineKey, buckets: [{ at: '2026-10-29T08:00:00Z', alerts: 2 }] }],
  },
};

function timeline(authorization: Partial<CampaignAuthorizationRecord> | null, changes?: CampaignChange[]) {
  return render(
    <CampaignTimeline
      events={EVENTS_TWO_LANES}
      members={CAMPAIGN_AUTHORIZED.members}
      parties={CAMPAIGN_AUTHORIZED.parties}
      ladder={CAMPAIGN_AUTHORIZED.ladder}
      changes={changes ?? CAMPAIGN_AUTHORIZED.changes}
      selection={null}
      onSelect={() => {}}
      authorization={authorization ? { ...AUTHORIZATION, ...authorization } : null}
    />,
  );
}

const nodeOf = (name: string) =>
  screen.getAllByTestId('graph-node').find((n) => n.textContent?.includes(name)) as HTMLElement;

describe('the attack graph of an authorized campaign', () => {
  it('marks each listed machine with a shield and no other machine', () => {
    graph(CAMPAIGN_AUTHORIZED);
    expect(within(nodeOf('actor-a')).getByRole('img', { name: 'Listed in the authorization' })).toBeInTheDocument();
    expect(within(nodeOf('web-1')).getByTestId('node-listed')).toBeInTheDocument();
    // NEGATIVE CONTROL: 192.0.2.30 is no listed machine.
    expect(within(nodeOf('192.0.2.30')).queryByTestId('node-listed')).toBeNull();
    expect(screen.getByTestId('legend-listed')).toHaveTextContent('Listed in the authorization');
  });

  it('draws the pair beyond the authorization in the danger tone, and the pairs inside in their stage', () => {
    graph(CAMPAIGN_AUTHORIZED);
    const links = screen.getAllByTestId('graph-link').filter((g) => g.getAttribute('data-related') === 'false');
    const out = links.filter((g) => g.getAttribute('data-outside') === 'true');
    expect(out).toHaveLength(1);
    expect(out[0].querySelector('path')).toHaveAttribute('stroke', OUTSIDE_COLOR);
    expect(within(out[0]).getByRole('button', { name: /Beyond the authorization\.$/ })).toBeInTheDocument();
    // NEGATIVE CONTROL: the arrow of actor-a to web-1 keeps the color of its stage.
    const inside = links.find((g) => g.getAttribute('data-outside') === 'false') as Element;
    expect(inside.querySelector('path')).toHaveAttribute('stroke', stageColor('action'));
    expect(screen.getByTestId('legend-outside')).toHaveTextContent('Beyond the authorization');
    expect(forbiddenWords(screen.getByTestId('attack-graph'))).toEqual([]);
  });

  it('draws no shield for a revoked authorization and no danger with no investigation outside', () => {
    graph(CAMPAIGN_AUTHORIZED, { ...AUTHORIZATION, state: 'revoked' }, []);
    expect(screen.queryAllByTestId('node-listed')).toHaveLength(0);
    expect(screen.queryByTestId('legend-outside')).toBeNull();
    for (const g of screen.getAllByTestId('graph-link')) expect(g).toHaveAttribute('data-outside', 'false');
  });
});

describe('the timeline of an authorized campaign', () => {
  it('draws the period as a band from the first event to the expiry and marks the expiry', () => {
    timeline({});
    const band = screen.getByTestId('timeline-period');
    expect(band).toHaveAttribute(
      'aria-label',
      expect.stringContaining('The period of the authorization Red team test: 2026-10-24 00:40'),
    );
    const marks = screen.getAllByTestId('timeline-decision');
    expect(marks.map((m) => m.getAttribute('data-type'))).toContain('decided');
    const expiry = marks.find((m) => m.getAttribute('data-type') === 'expiry') as HTMLElement;
    expect(expiry).toHaveAttribute('aria-label', `${utcStamp(AUTHORIZATION.expiresAt)}: The authorization Red team test expires.`);
    // The create mark sits before the expiry mark. The future expiry sits at
    // the right edge and names its day.
    const created = marks.find((m) => m.getAttribute('data-type') === 'decided') as Element;
    expect(Number(created.getAttribute('data-x'))).toBeLessThan(Number(expiry.getAttribute('data-x')));
    expect(within(expiry).getByTestId('timeline-decision-label')).toHaveTextContent(
      `Expires ${utcStamp(AUTHORIZATION.expiresAt)}`,
    );
  });

  it('draws a past expiry at its time on the axis', () => {
    // NEGATIVE CONTROL: only a future expiry moves to the right edge.
    const expiresAt = '2026-11-14T22:00:00Z';
    timeline({ state: 'expired', expiresAt });
    const expiry = screen.getAllByTestId('timeline-decision').find((m) => m.getAttribute('data-type') === 'expiry') as HTMLElement;
    expect(within(expiry).getByTestId('timeline-decision-label').textContent).toBe('Expired');
    expect(expiry.querySelector('line')).not.toBeNull();
  });

  it('ends the band at the revoke and marks the revoke', () => {
    const revokeAt = '2026-11-15T09:00:00Z';
    const changes: CampaignChange[] = [
      { id: 30, type: 'reopened', at: revokeAt, detail: { cause: 'revoked', by: 'analyst-2' } },
      ...(CAMPAIGN_AUTHORIZED.changes ?? []),
    ];
    timeline({ state: 'revoked', expiresAt: expiryIn(7) }, changes);
    expect(screen.getByTestId('timeline-period')).toHaveAttribute(
      'aria-label',
      expect.stringContaining('to 2026-11-15 09:00 UTC'),
    );
    const marks = screen.getAllByTestId('timeline-decision');
    const revoke = marks.find((m) => m.getAttribute('data-type') === 'reopened') as Element;
    expect(revoke).toHaveAttribute(
      'aria-label',
      '2026-11-15 09:00 UTC: analyst-2 revoked the authorization. The campaign waits on a decision again.',
    );
    // NEGATIVE CONTROL: a revoke before the expiry ends the period, so the expiry has no mark.
    expect(marks.some((m) => m.getAttribute('data-type') === 'expiry')).toBe(false);
  });

  it('draws no band with no authorization', () => {
    // NEGATIVE CONTROL.
    timeline(null);
    expect(screen.queryByTestId('timeline-period')).toBeNull();
  });
});
