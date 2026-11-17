// "Activity beyond the authorization" is the one alarm of an authorized
// campaign: a danger banner under the decision bar with the count, and a fold
// that lists each investigation with its reason in words.
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import type { CampaignBeyondRun } from '../../lib/api';
import { forbiddenWords } from '../../test/analystWords';
import { ACTOR, BEYOND_RUN, CAMPAIGN_AUTHORIZED, CAMPAIGN_WAITS, PARTIES, TARGET } from '../../test/campaign';
import { BeyondBanner, CampaignBeyond } from './CampaignBeyond';
import { CampaignView } from './CampaignView';

const EXPIRED: CampaignBeyondRun = {
  runId: 'run-late',
  label: 'ET WEB PHP shell request',
  eventAt: '2026-11-30T08:00:00Z',
  sourceKey: ACTOR.machineKey,
  targetKey: TARGET.machineKey,
  why: 'expired',
};

const view = (ui: React.ReactElement) => render(<MemoryRouter>{ui}</MemoryRouter>);

describe('the investigations beyond the authorization', () => {
  it('states the count in the banner, in the danger tone', () => {
    view(<BeyondBanner beyond={[BEYOND_RUN, EXPIRED]} onShow={() => {}} />);
    const banner = screen.getByTestId('campaign-beyond-banner');
    expect(within(banner).getByTestId('campaign-beyond-count')).toHaveTextContent(
      'Activity beyond the authorization: 2 investigations.',
    );
    expect(within(banner).getByTestId('campaign-beyond-count').className).toContain('text-danger');
    expect(banner).toHaveTextContent('Each one keeps normal handling. Its actions wait on you');
    expect(forbiddenWords(banner)).toEqual([]);
  });

  it('shows no banner with no investigation outside', () => {
    // NEGATIVE CONTROL: no alarm for an authorization that covers everything.
    view(<BeyondBanner beyond={[]} onShow={() => {}} />);
    expect(screen.queryByTestId('campaign-beyond-banner')).toBeNull();
    view(<BeyondBanner beyond={undefined} />);
    expect(screen.queryByTestId('campaign-beyond-banner')).toBeNull();
  });

  it('lists each investigation with its machines and the reason in words, oldest first', () => {
    view(<CampaignBeyond beyond={[EXPIRED, BEYOND_RUN]} parties={PARTIES} />);
    const rows = screen.getAllByRole('listitem');
    expect(rows.map((r) => r.getAttribute('data-why'))).toEqual(['target', 'expired']);
    expect(rows[0]).toHaveTextContent('ET EXPLOIT SMB probe');
    expect(rows[0]).toHaveTextContent('web-1 to 192.0.2.30');
    expect(within(rows[0]).getByTestId('beyond-why')).toHaveTextContent('The target is not a listed machine.');
    expect(within(rows[1]).getByTestId('beyond-why')).toHaveTextContent(
      'The event is after the expiry of the authorization.',
    );
    expect(within(rows[0]).getByRole('link', { name: 'ET EXPLOIT SMB probe' })).toHaveAttribute(
      'href',
      '/investigation/run-beyond',
    );
  });

  it('puts the banner under the decision bar and the open fold first on the campaign page', () => {
    view(<CampaignView campaign={CAMPAIGN_AUTHORIZED} />);
    const header = screen.getByTestId('campaign-header');
    const bar = within(header).getByTestId('campaign-decision');
    const banner = within(header).getByTestId('campaign-beyond-banner');
    expect(bar.compareDocumentPosition(banner) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    const folds = screen.getAllByTestId(/^fold-[a-z]+$/);
    expect(folds[0]).toHaveAttribute('data-testid', 'fold-beyond');
    expect(folds[0]).toHaveAttribute('data-open', 'true');
    expect(folds[0]).toHaveAttribute('data-tone', 'danger');
    // A collapse, then the button of the banner opens the fold again.
    fireEvent.click(within(folds[0]).getByRole('button', { name: /Collapse Activity beyond the authorization/ }));
    expect(screen.getByTestId('fold-beyond')).toHaveAttribute('data-open', 'false');
    fireEvent.click(screen.getByRole('button', { name: 'Show the investigations' }));
    expect(screen.getByTestId('fold-beyond')).toHaveAttribute('data-open', 'true');
  });

  it('shows no fold and no banner on a campaign with no authorization', () => {
    // NEGATIVE CONTROL.
    view(<CampaignView campaign={CAMPAIGN_WAITS} />);
    expect(screen.queryByTestId('fold-beyond')).toBeNull();
    expect(screen.queryByTestId('campaign-beyond-banner')).toBeNull();
  });
});
