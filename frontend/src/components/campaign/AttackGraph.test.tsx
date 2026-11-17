import { fireEvent, render, screen, within } from '@testing-library/react';
import { useState } from 'react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { CampaignDetail, CampaignRuleEvents } from '../../lib/api';
import { STAGE_LABEL, STAGE_ORDER } from '../../lib/campaignWords';
import { ACTOR, CAMPAIGN, MEMBER, PAIR, TARGET, earlierCampaign, edge, pair, party } from '../../test/campaign';
import { AttackGraph } from './AttackGraph';
import type { CampaignSelection } from './selection';

/** The graph with the selection state of the page around it. */
function mount(campaign: CampaignDetail = CAMPAIGN) {
  const onSelect = vi.fn();
  function Harness() {
    const [selection, setSelection] = useState<CampaignSelection | null>(null);
    return (
      <AttackGraph
        parties={campaign.parties}
        edges={campaign.graph.edges}
        related={campaign.related}
        members={campaign.members}
        pairs={campaign.events?.pairs}
        selection={selection}
        onSelect={(next) => {
          onSelect(next);
          setSelection(next);
        }}
      />
    );
  }
  render(
    <MemoryRouter>
      <Harness />
    </MemoryRouter>,
  );
  return onSelect;
}

const NO_SESSIONS: CampaignDetail = {
  ...CAMPAIGN,
  related: { ...CAMPAIGN.related, sessions: [] },
};

describe('AttackGraph', () => {
  it('draws one node for each machine with its role', () => {
    mount();
    const nodes = screen.getAllByTestId('graph-node');
    expect(nodes).toHaveLength(3);
    const role = (name: string) =>
      screen.getByRole('button', { name: `${name}: show its alerts` }).closest('[data-testid="graph-node"]');
    expect(role('actor-a')).toHaveAttribute('data-role', 'actor');
    expect(role('web-1')).toHaveAttribute('data-role', 'target');
    expect(role('192.0.2.30')).toHaveAttribute('data-role', 'target');
    // The node links to the host page of its machine.
    expect(screen.getByRole('link', { name: 'Open the host page of actor-a' })).toHaveAttribute(
      'href',
      '/hosts/agent%3Aactor-a',
    );
    // The arrow into web-1 gives the node the stage the campaign reached on it.
    const web = role('web-1') as HTMLElement;
    expect(within(web).getByTestId('node-stage')).toHaveAttribute('data-stage', 'action');
    // NEGATIVE CONTROL: the actor has no arrow into it, so it states no stage.
    expect(within(role('actor-a') as HTMLElement).queryByTestId('node-stage')).toBeNull();
  });

  it('lists the five stages in the legend', () => {
    mount(NO_SESSIONS);
    const legend = screen.getByTestId('stage-legend');
    for (const stage of STAGE_ORDER) expect(legend).toHaveTextContent(STAGE_LABEL[stage]);
    expect(legend).toHaveTextContent('No proven stage');
    // NEGATIVE CONTROL: with no session, the key of a related line is absent.
    expect(legend).not.toHaveTextContent('Related, not proven');
    expect(screen.getAllByTestId('graph-link').every((l) => l.getAttribute('data-related') === 'false')).toBe(true);
  });

  it('shows the related key and a dashed link for a session', () => {
    mount();
    expect(screen.getByTestId('stage-legend')).toHaveTextContent('Related, not proven');
    const related = screen.getAllByTestId('graph-link').filter((l) => l.getAttribute('data-related') === 'true');
    expect(related).toHaveLength(1);
    expect(related[0].querySelector('path')).toHaveAttribute('stroke-dasharray', '4 5');
    expect(within(related[0]).getByRole('button')).toHaveAccessibleName(
      'actor-a to web-1, port 22: 14 documents. Related, not proven.',
    );
    // NEGATIVE CONTROL: the arrow of the attack is solid.
    const run = screen.getAllByTestId('graph-link').find((l) => l.getAttribute('data-related') === 'false');
    expect(run?.querySelector('path')).not.toHaveAttribute('stroke-dasharray');
  });

  it('selects a machine on a click and clears it on a second click', () => {
    const onSelect = mount();
    const actor = screen.getByRole('button', { name: 'actor-a: show its alerts' });
    fireEvent.click(actor);
    expect(onSelect).toHaveBeenLastCalledWith({ kind: 'machine', key: ACTOR.machineKey, label: 'actor-a' });
    expect(actor).toHaveAttribute('aria-pressed', 'true');
    fireEvent.click(actor);
    expect(onSelect).toHaveBeenLastCalledWith(null);
    expect(actor).toHaveAttribute('aria-pressed', 'false');
  });

  it('selects the arrow on a click', () => {
    const onSelect = mount();
    fireEvent.click(screen.getByRole('button', { name: 'actor-a to web-1: 47 alerts.' }));
    expect(onSelect).toHaveBeenLastCalledWith({
      kind: 'edge',
      source: ACTOR.machineKey,
      target: TARGET.machineKey,
      label: 'actor-a to web-1',
    });
    // NEGATIVE CONTROL: a related line selects nothing.
    onSelect.mockClear();
    fireEvent.click(screen.getByRole('button', { name: /Related, not proven\.$/ }));
    expect(onSelect).not.toHaveBeenCalled();
  });

  it('selects nothing for an arrow that only a document shows', () => {
    // No investigation has these two machines as its ends, so the table would show none.
    const edges = CAMPAIGN.graph.edges.map((e) => ({ ...e, fromDocuments: true }));
    const onSelect = mount({ ...CAMPAIGN, graph: { edges } });
    const arrow = screen.getByRole('button', { name: 'actor-a to web-1: 47 alerts.' });
    fireEvent.click(arrow);
    expect(onSelect).not.toHaveBeenCalled();
    fireEvent.focus(arrow);
    expect(screen.getByTestId('graph-tooltip')).toHaveTextContent(
      'An alert document of a finding shows this arrow. No investigation has these two ends.',
    );
  });

  it('states the alerts, the rules, the other alerts, the records and the period in the tooltip of an arrow', () => {
    mount();
    expect(screen.queryByTestId('graph-tooltip')).toBeNull();
    const arrow = screen.getByRole('button', { name: 'actor-a to web-1: 47 alerts.' });
    fireEvent.focus(arrow);
    const tip = screen.getByTestId('graph-tooltip');
    expect(tip).toHaveTextContent('actor-a to web-1');
    expect(within(tip).getByTestId('link-tip-count')).toHaveTextContent('47 alerts of 3 rules');
    expect(tip).toHaveTextContent('Action on the target');
    // The confirmed rules, most alerts first: the count, then the rule name.
    const rows = within(within(tip).getByTestId('link-tip-rules')).getAllByRole('listitem');
    expect(rows.map((r) => r.textContent)).toEqual([
      '30ET EXPLOIT PHP file upload',
      '12ET SCAN Nmap',
      '5ET WEB PHP shell request',
    ]);
    // NEGATIVE CONTROL: a rule that soc-ai did not confirm is no rule row.
    expect(within(tip).getByTestId('link-tip-rules')).not.toHaveTextContent('ET POLICY curl user agent');
    expect(tip).toHaveTextContent('soc-ai did not confirm 12 other alerts between these machines.');
    expect(tip).toHaveTextContent('1,840 grid records between the two machines.');
    // The period of the events.
    expect(tip).toHaveTextContent('2026-10-24 00:40 to 2026-10-28 22:46 UTC');
    fireEvent.blur(arrow);
    expect(screen.queryByTestId('graph-tooltip')).toBeNull();
  });

  it('lists at most four rules in the tooltip of an arrow', () => {
    const rules: CampaignRuleEvents[] = Array.from({ length: 6 }, (_, i) => ({
      name: `ET RULE ${i}`,
      alerts: 10 - i,
      firstAt: '2026-10-24T01:00:00Z',
      lastAt: '2026-10-24T02:00:00Z',
      verdict: 'true_positive',
    }));
    mount({
      ...CAMPAIGN,
      events: { ...CAMPAIGN.events!, pairs: [{ ...PAIR, rules, otherAlerts: 0, records: null }] },
    });
    fireEvent.focus(screen.getByRole('button', { name: 'actor-a to web-1: 47 alerts.' }));
    const tip = screen.getByTestId('graph-tooltip');
    expect(within(within(tip).getByTestId('link-tip-rules')).getAllByRole('listitem')).toHaveLength(4);
    expect(within(tip).getByTestId('link-tip-count')).toHaveTextContent('47 alerts of 6 rules');
    // NEGATIVE CONTROL: no other alert and no grid record state nothing.
    expect(tip).not.toHaveTextContent('did not confirm');
    expect(tip).not.toHaveTextContent('grid record');
  });

  it('labels an arrow with its alerts, and an arrow with no alert event with its findings', () => {
    const t2 = party({ machineKey: 'net:192.0.2.40', name: 'db-1' });
    // The finding of db-1 has no alert event between actor-a and db-1.
    const finding = { ...MEMBER, runId: 'run-db', kind: 'finding' as const, targetKey: t2.machineKey };
    mount({
      ...CAMPAIGN,
      parties: [...CAMPAIGN.parties, t2],
      members: [...CAMPAIGN.members, finding],
      related: { ...CAMPAIGN.related, sessions: [] },
      graph: {
        edges: [
          edge(ACTOR.machineKey, TARGET.machineKey, { runs: 4, alerts: 1072 }),
          edge(ACTOR.machineKey, t2.machineKey, { runs: 1, alerts: 0 }),
        ],
      },
      events: { ...CAMPAIGN.events!, pairs: [{ ...PAIR, alerts: 1072 }] },
    });
    const labels = screen.getAllByTestId('graph-link-label').map((l) => l.textContent);
    expect(labels.sort()).toEqual(['1 finding', '1,072 alerts']);
    const arrow = (name: string) =>
      screen.getByRole('button', { name }).closest('[data-testid="graph-link"]')!.querySelector('path')!;
    // The width follows the alerts: the arrow of 1,072 alerts is the widest, the arrow of a finding a hairline.
    expect(arrow('actor-a to web-1: 1,072 alerts.')).toHaveAttribute('stroke-width', '7');
    expect(arrow('actor-a to db-1: 1 finding.')).toHaveAttribute('stroke-width', '1.5');
    fireEvent.focus(screen.getByRole('button', { name: 'actor-a to db-1: 1 finding.' }));
    expect(within(screen.getByTestId('graph-tooltip')).getByTestId('link-tip-count')).toHaveTextContent('1 finding');
  });

  it('states no count on an arrow with no alert event and no finding', () => {
    mount({
      ...CAMPAIGN,
      members: CAMPAIGN.members.filter((m) => m.kind === 'alert'),
      graph: { edges: [edge(ACTOR.machineKey, TARGET.machineKey, { runs: 3, alerts: 0 })] },
    });
    expect(screen.queryAllByTestId('graph-link-label')).toHaveLength(0);
    expect(screen.getByRole('button', { name: 'actor-a to web-1.' })).toBeInTheDocument();
  });

  it('reads the findings of an arrow from a server of an earlier release', () => {
    // No alert count: the arrow counts its findings. The three alert investigations are no findings.
    mount(earlierCampaign());
    expect(screen.getAllByTestId('graph-link-label').map((l) => l.textContent)).toEqual(['1 finding']);
    fireEvent.focus(screen.getByRole('button', { name: 'actor-a to web-1: 1 finding.' }));
    const tip = screen.getByTestId('graph-tooltip');
    expect(tip).toHaveTextContent('1 finding');
    expect(within(tip).queryByTestId('link-tip-rules')).toBeNull();
    // The period of the investigations.
    expect(tip).toHaveTextContent('2026-10-24 00:40 to 2026-10-28 22:44 UTC');
  });

  it('states the alerts of a machine in its tooltip', () => {
    mount({
      ...CAMPAIGN,
      events: {
        ...CAMPAIGN.events!,
        pairs: [PAIR, pair(TARGET.machineKey, 'net:192.0.2.30', { alerts: 3 }), pair('net:x', 'net:y', { alerts: 99 })],
      },
    });
    fireEvent.focus(screen.getByRole('button', { name: 'web-1: show its alerts' }));
    expect(within(screen.getByTestId('graph-tooltip')).getByTestId('node-tip-count')).toHaveTextContent('50 alerts');
  });

  it('states the investigations of a machine in its tooltip when the server sends no events', () => {
    mount(earlierCampaign());
    fireEvent.focus(screen.getByRole('button', { name: 'web-1: show its alerts' }));
    expect(within(screen.getByTestId('graph-tooltip')).getByTestId('node-tip-count')).toHaveTextContent(
      '4 investigations',
    );
  });

  it('names the no-agent icon "No agent"', () => {
    mount();
    // web-1 and 192.0.2.30 have no agent. actor-a has one.
    expect(screen.getAllByRole('img', { name: 'No agent' })).toHaveLength(2);
    const actor = screen
      .getByRole('button', { name: 'actor-a: show its alerts' })
      .closest('[data-testid="graph-node"]') as HTMLElement;
    expect(within(actor).queryByRole('img', { name: 'No agent' })).toBeNull();
    expect(screen.getByTestId('stage-legend')).toHaveTextContent('No agent');
  });

  it('draws nothing with no machine', () => {
    const { container } = render(
      <MemoryRouter>
        <AttackGraph
          parties={[]}
          edges={[]}
          related={CAMPAIGN.related}
          members={[]}
          selection={null}
          onSelect={() => {}}
        />
      </MemoryRouter>,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('puts a machine beyond the first target in the third column', () => {
    mount();
    expect(screen.getByText('Beyond the first target')).toBeInTheDocument();
    const beyond = screen
      .getByRole('button', { name: '192.0.2.30: show its alerts' })
      .closest('[data-testid="graph-node"]') as HTMLElement;
    const web = screen
      .getByRole('button', { name: 'web-1: show its alerts' })
      .closest('[data-testid="graph-node"]') as HTMLElement;
    expect(parseFloat(beyond.style.left)).toBeGreaterThan(parseFloat(web.style.left));
  });
});
