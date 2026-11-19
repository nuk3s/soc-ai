// The one state chip of a campaign (DC1, round "decide once"). The campaign
// header showed "Open" above "admin closed this campaign", and the list and
// the Confirmed threats row showed "Open" beside "Closed".
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { CAMPAIGN_CASE, CAMPAIGN_CASE_PENDING, LINK } from '../../test/campaign';
import { CampaignStateChip } from './shared';

describe('CampaignStateChip', () => {
  it('states the decision in force, and only that', () => {
    render(<CampaignStateChip campaign={{ ...LINK, decision: 'closed', state: 'closed' }} />);
    const chip = screen.getByTestId('campaign-state');
    expect(chip.textContent).toBe('Closed');
    expect(chip).toHaveAttribute('data-waits', 'false');
    expect(chip).toHaveAttribute('title', 'An analyst closed this campaign, and new activity opens it again.');
    expect(screen.queryByText('Open')).toBeNull();
  });

  it('does not state that new activity opens a closed campaign that ended', () => {
    // Production 2026-11-19: campaigns 1 and 3 are closed and ended. An ended
    // campaign reads no grid and takes no new investigation, and the hover
    // text stated "new activity opens it again".
    render(<CampaignStateChip campaign={{ ...LINK, status: 'ended', decision: 'closed', state: 'closed' }} />);
    const chip = screen.getByTestId('campaign-state');
    expect(chip.textContent).toBe('Closed');
    expect(chip).toHaveAttribute(
      'title',
      'An analyst closed this campaign, and it ended. This campaign has no investigation event and no alert of a confirmed rule in the last 207 hours. New activity starts a new campaign.',
    );
  });

  it('states Open in the warning tone while the campaign waits', () => {
    // NEGATIVE CONTROL: a campaign with no decision, or one that an analyst
    // opened again, states the activity status as work.
    render(<CampaignStateChip campaign={{ ...LINK, decision: null, state: 'open' }} />);
    const chip = screen.getByTestId('campaign-state');
    expect(chip.textContent).toBe('Open');
    expect(chip).toHaveAttribute('data-waits', 'true');
    expect(chip.className).toMatch(/text-warn/);
    expect(chip.getAttribute('title')).toMatch(/waits on your decision\.$/);
    // The hover text states the end rule: a later alert of a confirmed rule is activity.
    expect(chip).toHaveAttribute(
      'title',
      'This campaign has an investigation event or an alert of a confirmed rule in the last 207 hours, and it waits on your decision.',
    );
  });

  it('states Ended for a campaign whose activity stopped', () => {
    render(<CampaignStateChip campaign={{ ...LINK, status: 'ended', decision: null, state: 'ended' }} />);
    const chip = screen.getByTestId('campaign-state');
    expect(chip.textContent).toBe('Ended');
    expect(chip).toHaveAttribute(
      'title',
      'This campaign has no investigation event and no alert of a confirmed rule in the last 207 hours, and it waits on your decision.',
    );
  });

  it('reads the decision when the server sends no state', () => {
    render(<CampaignStateChip campaign={{ ...LINK, status: 'ended', decision: 'authorized' }} />);
    const chip = screen.getByTestId('campaign-state');
    expect(chip.textContent).toBe('Authorized');
    expect(chip).toHaveAttribute('data-state', 'authorized');
  });

  it('states the expiry of an authorization in one sentence of the hover text', () => {
    render(
      <CampaignStateChip
        campaign={{
          ...LINK,
          decision: 'authorized',
          state: 'authorized',
          authorization: { expiresAt: '2026-11-01T09:00:00Z', state: 'expired' },
        }}
      />,
    );
    const chip = screen.getByTestId('campaign-state');
    expect(chip.textContent).toBe('Authorized');
    expect(chip).toHaveAttribute(
      'title',
      'The authorization of this campaign expired 2026-11-01 09:00 UTC, and a later event waits on you.',
    );
  });

  it('states the time of the case in the hover text', () => {
    render(<CampaignStateChip campaign={CAMPAIGN_CASE} />);
    const chip = screen.getByTestId('campaign-state');
    expect(chip.textContent).toBe('Case');
    expect(chip).toHaveAttribute('title', 'A Security Onion case holds this campaign since 2026-11-15 09:00 UTC.');
    // The chip never cuts its word.
    expect(chip.className).not.toMatch(/truncate|line-clamp|text-ellipsis/);
  });

  it('states a pending request for a case as a campaign that waits', () => {
    // NEGATIVE CONTROL: a request with no readable answer is no decision.
    render(<CampaignStateChip campaign={CAMPAIGN_CASE_PENDING} />);
    const chip = screen.getByTestId('campaign-state');
    expect(chip).toHaveAttribute('data-state', 'open');
    expect(chip).toHaveAttribute('data-waits', 'true');
  });

  it('claims no wait for a server that sends no decision', () => {
    render(<CampaignStateChip campaign={LINK} />);
    const chip = screen.getByTestId('campaign-state');
    expect(chip.textContent).toBe('Open');
    expect(chip).toHaveAttribute('data-waits', 'false');
  });

  it('states a merged campaign as merged, never as its old decision', () => {
    render(<CampaignStateChip campaign={{ ...LINK, status: 'merged', decision: 'closed', state: 'merged' }} />);
    expect(screen.getByTestId('campaign-state').textContent).toBe('Merged');
  });
});
