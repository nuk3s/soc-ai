// One alert count at one time (SD5). Production, 2026-11-18: the Dashboard
// row and the Needs you row read 1,104 alerts and the campaign page read
// 1,118. The refresh loop now reads the grid after a rebuild. While the grid
// does not answer, each surface keeps the stored count and states its read.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { eventsFacts, gridReadWords } from '../../lib/campaignWords';
import { EVENTS, HOST_CAMPAIGNS, THREAT_CAMPAIGN } from '../../test/campaign';
import { campaignCountWords } from '../ConfirmedThreats';
import { HostCampaigns } from './HostCampaigns';

const READ = '2026-11-18T12:40:00Z';

describe('the stored alert count of a campaign', () => {
  it('states the time of the grid read when the count can be behind', () => {
    expect(gridReadWords({ alertsBehind: true, alertsReadAt: READ })).toBe(' at the grid read of 2026-11-18 12:40 UTC');
    expect(campaignCountWords({ ...THREAT_CAMPAIGN, alerts: 1104, alertsBehind: true, alertsReadAt: READ })).toBe(
      '1,104 alerts at the grid read of 2026-11-18 12:40 UTC',
    );
    expect(eventsFacts({ ...EVENTS, alerts: 1104, behind: true, readAt: READ })).toMatch(
      /^1,104 alerts of 3 confirmed rules at the grid read of 2026-11-18 12:40 UTC\. /,
    );
  });

  it('states no read time for a current count', () => {
    // NEGATIVE CONTROL: a count read after the last change of the campaign.
    expect(gridReadWords({ alertsBehind: false, alertsReadAt: READ })).toBe('');
    expect(campaignCountWords({ ...THREAT_CAMPAIGN, alerts: 1118, alertsBehind: false, alertsReadAt: READ })).toBe(
      '1,118 alerts',
    );
    expect(eventsFacts({ ...EVENTS, behind: false })).not.toContain('grid read');
  });

  it('states the read on the host page', () => {
    render(
      <MemoryRouter>
        <HostCampaigns campaigns={[{ ...HOST_CAMPAIGNS[0], alertsBehind: true, alertsReadAt: READ }]} />
      </MemoryRouter>,
    );
    expect(screen.getByTestId('host-campaign-alerts')).toHaveTextContent('47 alerts at the grid read of 2026-11-18 12:40 UTC');
  });
});
