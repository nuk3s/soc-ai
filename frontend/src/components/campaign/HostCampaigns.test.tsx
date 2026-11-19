import { render, screen, within } from '@testing-library/react';
import type { ReactElement } from 'react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import type { HostCampaignRole } from '../../lib/api';
import { utcWindow } from '../../lib/timeRange';
import { forbiddenWords } from '../../test/analystWords';
import { HOST_CAMPAIGNS, THREAT_CAMPAIGN } from '../../test/campaign';
import { HostCampaigns } from './HostCampaigns';

function mount(node: ReactElement) {
  return render(<MemoryRouter>{node}</MemoryRouter>);
}

describe('HostCampaigns', () => {
  it('shows one line for each campaign of the machine: the stage, the title, the role, the period and the alerts', () => {
    mount(<HostCampaigns campaigns={HOST_CAMPAIGNS} />);
    const strip = screen.getByTestId('host-campaigns');
    expect(within(strip).getByRole('heading', { name: 'Campaigns' })).toBeTruthy();
    const lines = within(strip).getAllByTestId('host-campaign');
    expect(lines).toHaveLength(2);
    const [first, second] = lines;
    expect(within(first).getByRole('img')).toHaveAccessibleName('Stage reached: Action on the target, 4 of 5');
    expect(within(first).getByRole('link', { name: 'actor-a against web-1' })).toHaveAttribute('href', '/campaigns/7');
    expect(within(first).getByTestId('campaign-state').textContent).toBe('Open');
    expect(within(first).getByTestId('host-campaign-role').textContent).toBe('Target');
    expect(within(first).getByTestId('host-campaign-period').textContent).toBe(
      utcWindow(HOST_CAMPAIGNS[0].firstEvent, HOST_CAMPAIGNS[0].lastEvent),
    );
    expect(within(first).getByTestId('host-campaign-alerts').textContent).toBe('47 alerts');
    // A campaign with no stored events states no alert count.
    expect(within(second).getByRole('img')).toHaveAccessibleName('No proven stage');
    expect(within(second).getByTestId('campaign-state').textContent).toBe('Ended');
    expect(within(second).getByTestId('host-campaign-role').textContent).toBe('Actor and target');
    expect(within(second).queryByTestId('host-campaign-alerts')).toBeNull();
    // The title wraps. It is never cut.
    expect(within(first).getByRole('link', { name: 'actor-a against web-1' }).className).toContain('break-words');
    expect(forbiddenWords(strip)).toEqual([]);
  });

  it('names each role in words', () => {
    const roles: [HostCampaignRole, string][] = [
      ['actor', 'Actor'],
      ['target', 'Target'],
      ['both', 'Actor and target'],
    ];
    for (const [role, word] of roles) {
      const { unmount } = mount(<HostCampaigns campaigns={[{ ...HOST_CAMPAIGNS[0], role }]} />);
      expect(screen.getByTestId('host-campaign-role').textContent).toBe(word);
      unmount();
    }
  });

  it('adds the authorized investigations from the confirmed threats of the host', () => {
    mount(<HostCampaigns campaigns={HOST_CAMPAIGNS} threats={[THREAT_CAMPAIGN]} />);
    const [first, second] = screen.getAllByTestId('host-campaign');
    expect(within(first).getByTestId('host-campaign-authorized').textContent).toBe('4 authorized');
    // The campaign waits, and its investigations do not: the decision chip
    // states the state of the campaign, and no line counts investigations
    // that wait on a decision.
    expect(within(first).queryByTestId('host-campaign-waiting')).toBeNull();
    expect(first.textContent).not.toMatch(/on a decision/);
    // NEGATIVE CONTROL. A campaign with no threat answer states no count.
    expect(within(second).queryByTestId('host-campaign-authorized')).toBeNull();
  });

  it('states one state chip for each campaign: the decision in force, else the status', () => {
    mount(
      <HostCampaigns
        campaigns={[
          { ...HOST_CAMPAIGNS[0], decision: null, waitsSince: '2026-10-24T00:40:00Z', state: 'open' },
          { ...HOST_CAMPAIGNS[1], decision: 'closed', waitsSince: null, state: 'closed' },
        ]}
      />,
    );
    const [waits, closed] = screen.getAllByTestId('host-campaign');
    const chip = within(waits).getByTestId('campaign-state');
    expect(chip.textContent).toBe('Open');
    expect(chip).toHaveAttribute('data-waits', 'true');
    expect(within(closed).getAllByTestId('campaign-state').map((c) => c.textContent)).toEqual(['Closed']);
    expect(within(closed).queryByText('Ended')).toBeNull();
  });

  // NEGATIVE CONTROL. A server that sends no decision gets the status with
  // no wait: the console never claims that a campaign waits.
  it('claims no wait for a server that sends no decision', () => {
    mount(<HostCampaigns campaigns={HOST_CAMPAIGNS} />);
    for (const chip of screen.getAllByTestId('campaign-state')) {
      expect(chip).toHaveAttribute('data-waits', 'false');
    }
  });

  // NEGATIVE CONTROL. A machine in no campaign, and a server of an earlier
  // release, show no strip.
  it('renders nothing with no campaign', () => {
    for (const campaigns of [[], undefined]) {
      const { container, unmount } = mount(<HostCampaigns campaigns={campaigns} />);
      expect(container).toBeEmptyDOMElement();
      unmount();
    }
  });
});
