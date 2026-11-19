// A finding row of a campaign states the note of a machine name that the
// record of the finding does not support (dogfood 2026-11-17, AA2). Two rows
// of campaign 2 read "against blue" for an address that holds no name.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import type { CampaignMember } from '../lib/api';
import { CampaignFindings } from './campaign/CampaignFindings';

const NOTE = 'The text names web-2. The hosts of this finding do not include web-2.';

const member = (runId: string, label: string, nameNote: string | null): CampaignMember =>
  ({
    runId,
    kind: 'finding',
    label,
    verdict: 'true_positive',
    impact: null,
    stage: null,
    eventAt: '2026-10-28T11:30:43Z',
    verdictDiffers: false,
    huntId: 'hunt-1',
    nameNote,
  }) as unknown as CampaignMember;

describe('the findings of a campaign', () => {
  it('states the name note under the title of its finding', () => {
    render(
      <MemoryRouter>
        <CampaignFindings
          members={[member('run-a', 'Probes against web-2', NOTE), member('run-b', 'Probes against web-1', null)]}
        />
      </MemoryRouter>,
    );
    const noted = screen.getByTestId('finding-run-a');
    expect(within(noted).getByTestId('finding-name-note')).toHaveTextContent(NOTE);
    expect(within(noted).getByRole('link', { name: 'Probes against web-2' })).toBeInTheDocument();
    // NEGATIVE CONTROL: a finding with no note shows none.
    expect(within(screen.getByTestId('finding-run-b')).queryByTestId('finding-name-note')).toBeNull();
  });
});
