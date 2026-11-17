// The dialog "Record authorized activity" of a campaign. It leads with the
// machines as a picture, then the numbers, then the form, and it states what
// the press writes before the press. What stays loud is as plain as what goes
// quiet.
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { CampaignAuthorizeDraft } from '../../lib/api';

vi.mock('../../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../lib/api')>()),
  getCampaignAuthorizeDraft: vi.fn(),
  authorizeCampaign: vi.fn(),
}));

import { ApiError, authorizeCampaign, getCampaignAuthorizeDraft } from '../../lib/api';
import { DEMO_ACTION_NOTE, DemoProvider } from '../../lib/demo';
import { utcStamp } from '../../lib/timeRange';
import { forbiddenWords } from '../../test/analystWords';
import { ACTOR, BEYOND_KEY, CAMPAIGN_AUTHORIZED, CAMPAIGN_WAITS, TARGET, expiryIn } from '../../test/campaign';
import { AuthorizeCampaignDialog, expiryFor } from './AuthorizeCampaignDialog';

const CAMPAIGN = { ...CAMPAIGN_WAITS, members: CAMPAIGN_AUTHORIZED.members, graph: CAMPAIGN_AUTHORIZED.graph };

const draft = (over: Partial<CampaignAuthorizeDraft> = {}): CampaignAuthorizeDraft => ({
  label: 'Red team test',
  expiresAt: expiryIn(7),
  maxExpiresAt: expiryIn(30),
  startsAt: CAMPAIGN.firstEvent,
  parties: [
    { machineKey: ACTOR.machineKey, role: 'actor', name: 'actor-a', address: '192.0.2.10', listed: true },
    { machineKey: TARGET.machineKey, role: 'target', name: 'web-1', address: '192.0.2.20', listed: true },
    { machineKey: BEYOND_KEY, role: 'target', name: null, address: '192.0.2.30', listed: true },
  ],
  inside: 4,
  outside: 1,
  waiting: 3,
  earlier: { id: 4, label: 'Old php2shell test', covers: 3, of: 5 },
  ...over,
});

function mount(opts: { demo?: boolean } = {}) {
  const onClose = vi.fn();
  const onAuthorized = vi.fn();
  render(
    <DemoProvider demo={opts.demo ?? false}>
      <AuthorizeCampaignDialog campaign={CAMPAIGN} open onClose={onClose} onAuthorized={onAuthorized} />
    </DemoProvider>,
  );
  return { onClose, onAuthorized };
}

const press = () => screen.getByRole('button', { name: 'Record authorized activity' });
const party = (name: RegExp) => screen.getByRole('checkbox', { name });

afterEach(() => {
  cleanup();
  vi.mocked(getCampaignAuthorizeDraft).mockReset();
  vi.mocked(authorizeCampaign).mockReset();
});

describe('the dialog Record authorized activity', () => {
  it('leads with the machines, then the numbers, then the form, and states what it writes', async () => {
    vi.mocked(getCampaignAuthorizeDraft).mockResolvedValue(draft());
    mount();
    const dialog = await screen.findByRole('dialog', { name: 'Record authorized activity' });
    const picture = await within(dialog).findByTestId('authorize-picture');
    // The actors on the left, the targets on the right, each one a check box, listed by default.
    // 192.0.2.30 is a target that only web-1 acted on: it takes the third column, as on the attack graph.
    expect(within(screen.getByTestId('authorize-actors')).getAllByRole('checkbox')).toHaveLength(1);
    expect(within(screen.getByTestId('authorize-targets')).getAllByRole('checkbox')).toHaveLength(1);
    expect(within(screen.getByTestId('authorize-further')).getAllByRole('checkbox')).toHaveLength(1);
    for (const box of within(picture).getAllByRole('checkbox')) expect(box).toBeChecked();
    // The picture comes before the numbers, and the numbers before the form.
    const inside = screen.getByTestId('authorize-inside');
    const label = screen.getByLabelText('Label');
    expect(picture.compareDocumentPosition(inside) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(inside.compareDocumentPosition(label) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();

    expect(inside).toHaveTextContent('4 investigations are inside. 3 of them wait on a decision today.');
    expect(screen.getByTestId('authorize-outside')).toHaveTextContent('1 is outside and stays loud.');
    expect(screen.getByTestId('authorize-period')).toHaveTextContent(
      `The period: ${utcStamp(CAMPAIGN.firstEvent)} to ${utcStamp(draft().expiresAt)}.`,
    );
    expect(screen.getByTestId('authorize-earlier')).toHaveTextContent(
      'The authorization Old php2shell test covers 3 of 5 investigations.',
    );
    expect(screen.getByTestId('authorize-expiry-limit')).toHaveTextContent('The latest expiry is');
    expect(screen.getByTestId('authorize-writes')).toHaveTextContent(
      'soc-ai stores the authorization on the campaign and an audit record.',
    );
    expect(label).toHaveValue('Red team test');
    expect(screen.queryByTestId('authorize-unlisted')).toBeNull();
    expect(forbiddenWords(dialog)).toEqual([]);
    expect(dialog.textContent ?? '').not.toMatch(/\bkinds?\b/i);
  });

  it('sends the listed machines, the label, the note and the expiry', async () => {
    vi.mocked(getCampaignAuthorizeDraft).mockResolvedValue(draft());
    vi.mocked(authorizeCampaign).mockResolvedValue(CAMPAIGN_AUTHORIZED);
    const { onAuthorized, onClose } = mount();
    await screen.findByTestId('authorize-picture');
    fireEvent.change(screen.getByLabelText('Note'), { target: { value: ' Ticket RT-42. ' } });
    fireEvent.click(press());
    await waitFor(() => expect(onAuthorized).toHaveBeenCalledWith(CAMPAIGN_AUTHORIZED));
    expect(onClose).toHaveBeenCalled();
    expect(authorizeCampaign).toHaveBeenCalledWith(CAMPAIGN.id, {
      label: 'Red team test',
      note: 'Ticket RT-42.',
      expiresAt: new Date(draft().expiresAt).toISOString(),
      machineKeys: [ACTOR.machineKey, TARGET.machineKey, BEYOND_KEY],
    });
  });

  it('draws an unlisted machine as loud and counts the investigations it is an end of', async () => {
    vi.mocked(getCampaignAuthorizeDraft).mockResolvedValue(draft());
    vi.mocked(authorizeCampaign).mockResolvedValue(CAMPAIGN_AUTHORIZED);
    mount();
    await screen.findByTestId('authorize-picture');
    fireEvent.click(party(/192\.0\.2\.30/));
    const row = party(/192\.0\.2\.30/).closest('[data-testid="authorize-party"]');
    expect(row).toHaveAttribute('data-listed', 'false');
    expect(row).toHaveTextContent('Not listed. Its investigations stay loud.');
    expect(screen.getByTestId('authorize-counts-scope')).toHaveTextContent(
      'The counts are for the scope with every machine listed.',
    );
    // web-1 against 192.0.2.30 is one investigation of the campaign.
    expect(screen.getByTestId('authorize-unlisted')).toHaveTextContent(
      '1 investigation has an unlisted machine as the source or the target. It is outside and stays loud.',
    );
    fireEvent.click(press());
    await waitFor(() => expect(authorizeCampaign).toHaveBeenCalled());
    expect(vi.mocked(authorizeCampaign).mock.calls[0][1].machineKeys).toEqual([ACTOR.machineKey, TARGET.machineKey]);
  });

  it('holds the press with no listed actor, and with no label', async () => {
    // NEGATIVE CONTROL: the server refuses a scope with no actor or no target, so the press waits.
    vi.mocked(getCampaignAuthorizeDraft).mockResolvedValue(draft());
    mount();
    await screen.findByTestId('authorize-picture');
    fireEvent.click(party(/actor-a/));
    expect(press()).toBeDisabled();
    expect(screen.getByTestId('authorize-needs-both')).toHaveTextContent('List at least one actor and one target.');
    fireEvent.click(party(/actor-a/));
    expect(press()).toBeEnabled();
    fireEvent.change(screen.getByLabelText('Label'), { target: { value: '   ' } });
    expect(press()).toBeDisabled();
    expect(authorizeCampaign).not.toHaveBeenCalled();
  });

  it('sends the picked day at the time of the default, and never later than the maximum', () => {
    const d = { expiresAt: '2026-11-21T10:15:00.000Z', maxExpiresAt: '2026-12-14T10:15:00.000Z' };
    expect(expiryFor('2026-11-25', d)).toBe('2026-11-25T10:15:00.000Z');
    expect(expiryFor('2027-01-30', d)).toBe('2026-12-14T10:15:00.000Z');
    // NEGATIVE CONTROL: an empty field sends no expiry.
    expect(expiryFor('', d)).toBeNull();
  });

  it('keeps the dialog and states the refusal of the server', async () => {
    vi.mocked(getCampaignAuthorizeDraft).mockResolvedValue(draft());
    vi.mocked(authorizeCampaign).mockRejectedValue(new ApiError('The campaign holds a decision.', 409, 'campaign_decided'));
    const { onAuthorized } = mount();
    await screen.findByTestId('authorize-picture');
    fireEvent.click(press());
    expect(await screen.findByRole('alert')).toHaveTextContent('The campaign holds a decision.');
    expect(onAuthorized).not.toHaveBeenCalled();
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });

  it('states that only an admin can record it when the draft answers 403', async () => {
    vi.mocked(getCampaignAuthorizeDraft).mockRejectedValue(new ApiError('Forbidden', 403, 'admin_required'));
    mount();
    expect(await screen.findByRole('alert')).toHaveTextContent('Only an admin can record authorized activity.');
    expect(screen.queryByRole('button', { name: 'Record authorized activity' })).toBeNull();
  });

  it('sends no request in the demo', async () => {
    vi.mocked(getCampaignAuthorizeDraft).mockResolvedValue(draft());
    mount({ demo: true });
    await screen.findByTestId('authorize-picture');
    fireEvent.click(press());
    expect(screen.getByRole('alert')).toHaveTextContent(DEMO_ACTION_NOTE);
    expect(authorizeCampaign).not.toHaveBeenCalled();
  });
});
