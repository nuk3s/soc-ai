// The decision chip of a campaign with a case: "Case", and the day of the
// case when the payload carries the case.
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { CAMPAIGN_CASE, CAMPAIGN_CASE_PENDING, LINK } from '../../test/campaign';
import { CampaignDecisionChip } from './shared';

describe('CampaignDecisionChip of a case', () => {
  it('states the day of the case when the payload carries it', () => {
    render(<CampaignDecisionChip campaign={CAMPAIGN_CASE} />);
    const chip = screen.getByTestId('campaign-decision-chip');
    expect(chip.textContent).toBe('Case since 2026-11-15');
    expect(chip).toHaveAttribute('data-state', 'case');
    expect(chip).toHaveAttribute('title', 'A Security Onion case is open for this campaign since 2026-11-15 09:00 UTC.');
    // The chip never cuts its word.
    expect(chip.className).not.toMatch(/truncate|line-clamp|text-ellipsis/);
  });

  it('states Case alone for a link that carries no case', () => {
    render(<CampaignDecisionChip campaign={{ ...LINK, decision: 'case' }} />);
    expect(screen.getByTestId('campaign-decision-chip').textContent).toBe('Case');
  });

  it('states a pending request as a campaign that waits', () => {
    // NEGATIVE CONTROL: a request with no readable answer is no decision.
    render(<CampaignDecisionChip campaign={CAMPAIGN_CASE_PENDING} />);
    const chip = screen.getByTestId('campaign-decision-chip');
    expect(chip).toHaveAttribute('data-state', 'waits');
    expect(chip.textContent).toBe('Waits on you');
  });
});
