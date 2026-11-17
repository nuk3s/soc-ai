// Exclude, Include and Undo on the folds of the campaign page. Each row of
// Investigations has Exclude and an Authorized or an Included chip. Each
// investigation of "Related, not proven" has Include. The fold Excluded lists
// the excluded investigations with Undo. Each write states what it writes
// before the press.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../lib/api')>()),
  excludeFromCampaign: vi.fn(),
  includeInCampaign: vi.fn(),
  undoCampaignOverride: vi.fn(),
}));

import { excludeFromCampaign, includeInCampaign, undoCampaignOverride, type CampaignDetail } from '../../lib/api';
import { forbiddenWords } from '../../test/analystWords';
import { CAMPAIGN_AUTHORIZED, CAMPAIGN_WAITS, EXCLUDED_RUN } from '../../test/campaign';
import { CampaignView } from './CampaignView';

/** The authorized campaign, with run-actor included by an analyst. */
const CAMPAIGN: CampaignDetail = {
  ...CAMPAIGN_AUTHORIZED,
  members: CAMPAIGN_AUTHORIZED.members.map((m) => (m.runId === 'run-actor' ? { ...m, included: true } : m)),
};

function mount(c: CampaignDetail = CAMPAIGN) {
  const onDecided = vi.fn();
  render(
    <MemoryRouter>
      <CampaignView campaign={c} onDecided={onDecided} />
    </MemoryRouter>,
  );
  return onDecided;
}

const openFold = (testId: string, title: string) => {
  fireEvent.click(within(screen.getByTestId(testId)).getByRole('button', { name: `Expand ${title}` }));
  return screen.getByTestId(testId);
};

afterEach(() => {
  vi.mocked(excludeFromCampaign).mockReset();
  vi.mocked(includeInCampaign).mockReset();
  vi.mocked(undoCampaignOverride).mockReset();
});

describe('the rows of the Investigations fold', () => {
  it('show the Authorized, the Included and the Beyond chips', () => {
    mount();
    const fold = openFold('fold-investigations', 'Investigations');
    expect(within(screen.getByTestId('member-run-seed')).getByTestId('member-authorized')).toHaveTextContent('Authorized');
    expect(within(screen.getByTestId('member-run-actor')).getByTestId('member-included')).toHaveTextContent('Included');
    expect(within(screen.getByTestId('member-run-beyond')).getByTestId('member-outside')).toHaveTextContent(
      'Beyond the authorization',
    );
    // NEGATIVE CONTROL: the investigation outside wears no Authorized chip.
    expect(within(screen.getByTestId('member-run-beyond')).queryByTestId('member-authorized')).toBeNull();
    expect(forbiddenWords(fold)).toEqual([]);
  });

  it('asks for a reason, states what Exclude writes, then sends it', async () => {
    vi.mocked(excludeFromCampaign).mockResolvedValue(CAMPAIGN_WAITS);
    const onDecided = mount();
    openFold('fold-investigations', 'Investigations');
    fireEvent.click(within(screen.getByTestId('member-run-seed')).getByRole('button', { name: /^Exclude/ }));
    const confirm = screen.getByTestId('member-exclude-confirm');
    expect(confirm).toHaveTextContent('Exclude takes this investigation out of the campaign. It then gets normal handling');
    const press = within(confirm).getByRole('button', { name: 'Exclude' });
    // NEGATIVE CONTROL: no reason, no request.
    expect(press).toBeDisabled();
    fireEvent.change(within(confirm).getByLabelText('Reason'), { target: { value: ' A backup job. ' } });
    fireEvent.click(press);
    await waitFor(() => expect(onDecided).toHaveBeenCalledWith(CAMPAIGN_WAITS));
    expect(excludeFromCampaign).toHaveBeenCalledWith(CAMPAIGN.id, { runId: 'run-seed', reason: 'A backup job.' });
  });

  it('offers Undo on an included investigation, with no reason', async () => {
    vi.mocked(undoCampaignOverride).mockResolvedValue(CAMPAIGN_WAITS);
    mount();
    openFold('fold-investigations', 'Investigations');
    const row = screen.getByTestId('member-run-actor');
    expect(within(row).queryByRole('button', { name: /^Exclude/ })).toBeNull();
    fireEvent.click(within(row).getByRole('button', { name: /^Undo/ }));
    const confirm = screen.getByTestId('member-undo-confirm');
    expect(confirm).toHaveTextContent('Undo clears the include.');
    fireEvent.click(within(confirm).getByRole('button', { name: 'Undo' }));
    await waitFor(() => expect(undoCampaignOverride).toHaveBeenCalledWith(CAMPAIGN.id, 'run-actor'));
  });

  it('states the refusal of the server and keeps the confirm', async () => {
    vi.mocked(excludeFromCampaign).mockRejectedValue(new Error('The investigation is already excluded.'));
    const onDecided = mount();
    openFold('fold-investigations', 'Investigations');
    fireEvent.click(within(screen.getByTestId('member-run-seed')).getByRole('button', { name: /^Exclude/ }));
    const confirm = screen.getByTestId('member-exclude-confirm');
    fireEvent.change(within(confirm).getByLabelText('Reason'), { target: { value: 'Noise.' } });
    fireEvent.click(within(confirm).getByRole('button', { name: 'Exclude' }));
    expect(await within(confirm).findByRole('alert')).toHaveTextContent('The investigation is already excluded.');
    expect(onDecided).not.toHaveBeenCalled();
  });

  it('offers no write for a server of an earlier release', () => {
    // NEGATIVE CONTROL: no list of excluded investigations, no route to call.
    const { excluded: _e, ...older } = CAMPAIGN;
    mount(older);
    openFold('fold-investigations', 'Investigations');
    expect(screen.queryAllByRole('button', { name: /^Exclude/ })).toHaveLength(0);
    openFold('fold-related', 'Related, not proven');
    expect(screen.queryByRole('button', { name: /^Include/ })).toBeNull();
    expect(screen.queryByTestId('fold-excluded')).toBeNull();
  });
});

describe('Include and the Excluded fold', () => {
  it('includes an investigation of Related, not proven with a reason', async () => {
    vi.mocked(includeInCampaign).mockResolvedValue(CAMPAIGN_WAITS);
    mount();
    openFold('fold-related', 'Related, not proven');
    fireEvent.click(within(screen.getByTestId('related-run-run-nmi')).getByRole('button', { name: /^Include/ }));
    const confirm = screen.getByTestId('related-include-confirm');
    expect(confirm).toHaveTextContent('Include joins this investigation to the campaign. The campaign then holds it.');
    fireEvent.change(within(confirm).getByLabelText('Reason'), { target: { value: 'Same test.' } });
    fireEvent.click(within(confirm).getByRole('button', { name: 'Include' }));
    await waitFor(() =>
      expect(includeInCampaign).toHaveBeenCalledWith(CAMPAIGN.id, { runId: 'run-nmi', reason: 'Same test.' }),
    );
    // NEGATIVE CONTROL: a session and a named host are no investigation, so they offer no Include.
    expect(within(screen.getByTestId('related-session')).queryByRole('button')).toBeNull();
  });

  it('lists the excluded investigations with who, when and the reason, and undoes one', async () => {
    vi.mocked(undoCampaignOverride).mockResolvedValue(CAMPAIGN_WAITS);
    const onDecided = mount();
    const fold = openFold('fold-excluded', 'Excluded');
    const row = within(fold).getByTestId(`excluded-${EXCLUDED_RUN.runId}`);
    expect(row).toHaveTextContent('ET INFO curl download');
    expect(within(row).getByTestId('excluded-words')).toHaveTextContent(
      'analyst-2 excluded it on 2026-11-14 21:30 UTC. Reason: A backup job of the operator.',
    );
    fireEvent.click(within(row).getByRole('button', { name: /^Undo/ }));
    expect(screen.getByTestId('excluded-undo-confirm')).toHaveTextContent('Undo clears the exclude.');
    fireEvent.click(within(screen.getByTestId('excluded-undo-confirm')).getByRole('button', { name: 'Undo' }));
    await waitFor(() => expect(onDecided).toHaveBeenCalledWith(CAMPAIGN_WAITS));
    expect(undoCampaignOverride).toHaveBeenCalledWith(CAMPAIGN.id, EXCLUDED_RUN.runId);
    expect(forbiddenWords(fold)).toEqual([]);
  });
});
