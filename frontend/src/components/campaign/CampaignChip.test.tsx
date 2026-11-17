import { fireEvent, render, screen } from '@testing-library/react';
import type { ReactNode } from 'react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { STAGE_COLOR } from '../../lib/campaignViz';
import { forbiddenWords } from '../../test/analystWords';
import { LINK, LINK_DIFFERS } from '../../test/campaign';
import { CampaignChip } from './CampaignChip';

function mount(node: ReactNode) {
  return render(<MemoryRouter>{node}</MemoryRouter>);
}

describe('CampaignChip', () => {
  it('links to the campaign and names its title and its stage', () => {
    mount(<CampaignChip campaign={LINK} />);
    const chip = screen.getByRole('link', {
      name: 'Campaign: actor-a against web-1. Stage reached: Action on the target, 4 of 5.',
    });
    expect(chip).toHaveAttribute('href', '/campaigns/7');
    expect(chip).toHaveAttribute('title', chip.getAttribute('aria-label'));
    expect(chip).toHaveTextContent(/^Campaign$/);
    expect(chip.querySelector('svg')).not.toBeNull();
    expect(screen.getByTestId('campaign-chip-dot').style.background).toBe(STAGE_COLOR.action);
    expect(chip).toHaveAttribute('data-differs', 'false');
  });

  it('states that the verdict differs on a session of the campaign', () => {
    mount(<CampaignChip campaign={LINK_DIFFERS} />);
    const chip = screen.getByRole('link');
    expect(chip.getAttribute('title')).toBe(
      'Campaign: actor-a against web-1. Stage reached: Action on the target, 4 of 5. ' +
        'Same session as this campaign. The verdict differs.',
    );
    expect(chip).toHaveAccessibleName(chip.getAttribute('title')!);
    expect(chip).toHaveAttribute('data-differs', 'true');
  });

  it('says "No proven stage" for a campaign with no stage, in the gray dot', () => {
    mount(<CampaignChip campaign={{ ...LINK, stage: null }} />);
    expect(screen.getByRole('link')).toHaveAccessibleName('Campaign: actor-a against web-1. No proven stage.');
    expect(screen.getByTestId('campaign-chip-dot').style.background).not.toBe(STAGE_COLOR.action);
  });

  // NEGATIVE CONTROL. An investigation in no campaign, and a server of an
  // earlier release, render no chip.
  it('renders nothing with no campaign', () => {
    for (const campaign of [null, undefined]) {
      const { container, unmount } = mount(<CampaignChip campaign={campaign} />);
      expect(container).toBeEmptyDOMElement();
      unmount();
    }
  });

  it('opens the campaign and does not open the row it sits on', () => {
    const onRow = vi.fn();
    mount(
      <div onClick={onRow} onKeyDown={onRow}>
        <CampaignChip campaign={LINK} />
      </div>,
    );
    fireEvent.click(screen.getByRole('link'));
    fireEvent.keyDown(screen.getByRole('link'), { key: 'Enter' });
    expect(onRow).not.toHaveBeenCalled();
  });

  it('holds no forbidden word', () => {
    const { container } = mount(
      <>
        <CampaignChip campaign={LINK} />
        <CampaignChip campaign={LINK_DIFFERS} />
      </>,
    );
    expect(forbiddenWords(container)).toEqual([]);
  });
});
