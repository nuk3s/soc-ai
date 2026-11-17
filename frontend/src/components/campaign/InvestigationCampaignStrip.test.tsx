import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { forbiddenWords } from '../../test/analystWords';
import { LINK, LINK_DIFFERS } from '../../test/campaign';
import { InvestigationCampaignStrip } from './InvestigationCampaignStrip';

function mount(campaign: Parameters<typeof InvestigationCampaignStrip>[0]['campaign']) {
  return render(
    <MemoryRouter>
      <InvestigationCampaignStrip campaign={campaign} />
    </MemoryRouter>,
  );
}

describe('InvestigationCampaignStrip decisions', () => {
  it('states a closed campaign', () => {
    mount({ ...LINK, decision: 'closed', waitsSince: null });
    expect(screen.getByTestId('investigation-campaign-sentence')).toHaveTextContent(
      'Part of the campaign actor-a against web-1. An analyst closed the campaign.',
    );
    expect(screen.getByTestId('campaign-decision-chip')).toHaveTextContent('Closed');
    expect(forbiddenWords(screen.getByTestId('investigation-campaign'))).toEqual([]);
  });

  it('states a campaign that waits as work', () => {
    mount({ ...LINK, decision: null, waitsSince: '2026-10-24T00:40:00Z' });
    expect(screen.getByTestId('investigation-campaign-sentence')).toHaveTextContent(
      'Part of the campaign actor-a against web-1.',
    );
    expect(screen.getByTestId('investigation-campaign-sentence')).not.toHaveTextContent('closed');
    expect(screen.getByTestId('campaign-decision-chip')).toHaveTextContent('Waits on you');
  });

  it('keeps the sentence of a verdict that differs, and states no decision for an older server', () => {
    // NEGATIVE CONTROL. An absent field claims no decision.
    mount(LINK_DIFFERS);
    expect(screen.getByTestId('investigation-campaign-sentence')).toHaveTextContent(
      'Same session as the campaign actor-a against web-1. The verdict differs.',
    );
    expect(screen.queryByTestId('campaign-decision-chip')).toBeNull();
  });
});
