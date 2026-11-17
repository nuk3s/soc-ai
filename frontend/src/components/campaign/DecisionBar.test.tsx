import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DecisionBar } from './DecisionBar';

vi.mock('../../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../../lib/api')>('../../lib/api');
  return {
    ...actual,
    reopenCampaign: vi.fn(),
    revokeCampaignAuthorization: vi.fn(),
    getCampaignCloseScope: vi.fn(),
    acknowledgeCampaign: vi.fn(),
    retryCampaignCase: vi.fn(),
  };
});
import {
  acknowledgeCampaign,
  getCampaignCloseScope,
  reopenCampaign,
  retryCampaignCase,
  revokeCampaignAuthorization,
  type CampaignChange,
  type CampaignDetail,
} from '../../lib/api';
import { DEMO_ACTION_NOTE, DemoProvider } from '../../lib/demo';
import { forbiddenWords } from '../../test/analystWords';
import { utcStamp } from '../../lib/timeRange';
import {
  AUTHORIZATION,
  CAMPAIGN,
  CAMPAIGN_AUTHORIZED,
  CAMPAIGN_CASE,
  CAMPAIGN_CASE_FAILED,
  CAMPAIGN_CASE_PENDING,
  CAMPAIGN_CASE_READY,
  CAMPAIGN_CLOSED,
  CAMPAIGN_WAITS,
  CASE_URL,
  CLOSE_AT,
  expiryIn,
} from '../../test/campaign';

function mount(campaign: CampaignDetail, opts: { demo?: boolean; admin?: boolean } = {}) {
  const onCloseRequest = vi.fn();
  const onDecided = vi.fn();
  const onAuthorizeRequest = vi.fn();
  const onCaseRequest = vi.fn();
  const view = render(
    <DemoProvider demo={opts.demo ?? false}>
      <MemoryRouter>
        <DecisionBar
          campaign={campaign}
          onCloseRequest={onCloseRequest}
          onDecided={onDecided}
          onAuthorizeRequest={onAuthorizeRequest}
          onCaseRequest={onCaseRequest}
          canAuthorize={opts.admin ?? false}
        />
      </MemoryRouter>
    </DemoProvider>,
  );
  return { ...view, onCloseRequest, onDecided, onAuthorizeRequest, onCaseRequest };
}

/** The words an analyst reads, with "kind" banned beside the shared list. */
function banned(root: Element): string[] {
  const text = root.textContent ?? '';
  return [...forbiddenWords(root), ...(/\bkinds?\b/i.test(text) ? [text] : [])];
}

beforeEach(() => {
  vi.mocked(reopenCampaign).mockReset();
  vi.mocked(revokeCampaignAuthorization).mockReset();
  vi.mocked(acknowledgeCampaign).mockReset();
  vi.mocked(retryCampaignCase).mockReset();
  vi.mocked(getCampaignCloseScope).mockReset().mockResolvedValue({ alerts: 0, rules: 0, capped: false });
});

/** A campaign closed at CLOSE_AT. `asked`: the close asked for the
 *  acknowledgement. `ack`: the acknowledgement change after the close. */
function closedWith(asked: boolean, ack?: { alerts: number; failed: number }): CampaignDetail {
  const changes: CampaignChange[] = [
    { id: 8, type: 'decided', at: CLOSE_AT, detail: { decision: 'closed', reason: 'test_over', by: 'admin', acknowledge: asked } },
  ];
  if (ack) changes.unshift({ id: 9, type: 'acknowledged', at: '2026-11-14T21:01:30Z', detail: ack });
  return { ...CAMPAIGN_CLOSED, changes };
}

describe('Acknowledge the remaining alerts', () => {
  it('offers the rest with the count when the close asked for it and no acknowledgement followed', async () => {
    vi.mocked(getCampaignCloseScope).mockResolvedValue({ alerts: 1083, rules: 7, capped: false });
    const next = closedWith(true, { alerts: 1083, failed: 0 });
    vi.mocked(acknowledgeCampaign).mockResolvedValue(next);
    const { onDecided } = mount(closedWith(true));
    const button = await screen.findByTestId('campaign-acknowledge-rest');
    expect(button).toHaveTextContent('Acknowledge the remaining alerts');
    await waitFor(() => expect(within(button).getByTestId('campaign-acknowledge-count')).toHaveTextContent('1,083'));
    expect(getCampaignCloseScope).toHaveBeenCalledWith(CAMPAIGN_CLOSED.id);
    vi.mocked(getCampaignCloseScope).mockResolvedValue({ alerts: 0, rules: 7, capped: false });
    fireEvent.click(button);
    await waitFor(() => expect(onDecided).toHaveBeenCalledWith(next));
    expect(acknowledgeCampaign).toHaveBeenCalledWith(CAMPAIGN_CLOSED.id);
    // The press reads the scope again.
    await waitFor(() => expect(getCampaignCloseScope).toHaveBeenCalledTimes(2));
    expect(banned(screen.getByTestId('campaign-decision'))).toEqual([]);
  });

  it('offers the rest when the acknowledgement failed for some alerts', async () => {
    mount(closedWith(true, { alerts: 1081, failed: 2 }));
    const button = await screen.findByTestId('campaign-acknowledge-rest');
    // The grid counts none, so the button states no count.
    await waitFor(() => expect(getCampaignCloseScope).toHaveBeenCalled());
    expect(within(button).queryByTestId('campaign-acknowledge-count')).toBeNull();
  });

  it('offers the rest when the close scope still counts alerts', async () => {
    vi.mocked(getCampaignCloseScope).mockResolvedValue({ alerts: 5, rules: 1, capped: false });
    mount(closedWith(false));
    const button = await screen.findByTestId('campaign-acknowledge-rest');
    expect(await within(button).findByTestId('campaign-acknowledge-count')).toHaveTextContent('5');
  });

  it('offers nothing when no alert remains', async () => {
    // Negative controls: a close that asked for none, and an acknowledgement with no failure.
    const { unmount } = mount(closedWith(false));
    await waitFor(() => expect(getCampaignCloseScope).toHaveBeenCalledTimes(1));
    expect(screen.queryByTestId('campaign-acknowledge-rest')).toBeNull();
    unmount();
    vi.mocked(getCampaignCloseScope).mockResolvedValue({ alerts: null, rules: null, capped: false });
    mount(closedWith(true, { alerts: 40, failed: 0 }));
    await waitFor(() => expect(getCampaignCloseScope).toHaveBeenCalledTimes(2));
    expect(screen.queryByTestId('campaign-acknowledge-rest')).toBeNull();
  });

  it('reads no close scope for a campaign that waits', () => {
    mount(CAMPAIGN_WAITS);
    expect(getCampaignCloseScope).not.toHaveBeenCalled();
    expect(screen.queryByTestId('campaign-acknowledge-rest')).toBeNull();
  });

  it('states the failure of the press and sends no request in the demo', async () => {
    vi.mocked(acknowledgeCampaign).mockRejectedValue(new Error('This campaign is not closed.'));
    const { unmount } = mount(closedWith(true));
    fireEvent.click(await screen.findByTestId('campaign-acknowledge-rest'));
    expect(await screen.findByRole('alert')).toHaveTextContent('This campaign is not closed.');
    unmount();
    vi.mocked(acknowledgeCampaign).mockReset();
    mount(closedWith(true), { demo: true });
    fireEvent.click(await screen.findByTestId('campaign-acknowledge-rest'));
    expect(screen.getByRole('alert')).toHaveTextContent(DEMO_ACTION_NOTE);
    expect(acknowledgeCampaign).not.toHaveBeenCalled();
  });
});

describe('DecisionBar', () => {
  it('states that the campaign waits since its first event and offers the close', () => {
    const { onCloseRequest } = mount(CAMPAIGN_WAITS);
    const bar = screen.getByTestId('campaign-decision');
    expect(bar).toHaveAttribute('data-state', 'waits');
    expect(within(bar).getByTestId('campaign-decision-state')).toHaveTextContent(
      'This campaign waits on your decision since 2026-10-24 00:40 UTC.',
    );
    expect(within(bar).queryByRole('button', { name: 'Open again' })).toBeNull();
    fireEvent.click(within(bar).getByRole('button', { name: 'Close with a reason' }));
    expect(onCloseRequest).toHaveBeenCalledTimes(1);
    expect(banned(bar)).toEqual([]);
  });

  it('states who closed the campaign, when, the reason, the note and the acknowledged alerts', () => {
    mount(CAMPAIGN_CLOSED);
    const bar = screen.getByTestId('campaign-decision');
    expect(bar).toHaveAttribute('data-state', 'closed');
    expect(within(bar).getByTestId('campaign-decision-state')).toHaveTextContent(
      'admin closed this campaign on 2026-11-14 21:00 UTC. Reason: Test that is over.',
    );
    expect(within(bar).getByTestId('campaign-decision-note')).toHaveTextContent(
      'Note: The red team test ended on 2026-11-14.',
    );
    // The newest acknowledgement after the close: 1,083 alerts, 2 failed. The
    // 40 alerts of the earlier close do not count.
    expect(within(bar).getByTestId('campaign-decision-ack')).toHaveTextContent(
      'soc-ai acknowledged 1,083 alerts in Security Onion. soc-ai could not acknowledge 2 alerts.',
    );
    expect(within(bar).queryByRole('button', { name: 'Close with a reason' })).toBeNull();
    expect(within(bar).getByRole('button', { name: 'Open again' })).toBeInTheDocument();
    expect(banned(bar)).toEqual([]);
  });

  it('shows no acknowledgement that belongs to an earlier close', () => {
    // Negative control: the only acknowledgement is older than the close that stands.
    const older = (CAMPAIGN_CLOSED.changes ?? []).filter((c) => c.id !== 9);
    mount({ ...CAMPAIGN_CLOSED, changes: older });
    expect(screen.queryByTestId('campaign-decision-ack')).toBeNull();
  });

  it('states what Open again writes before the press, then sends it', async () => {
    const next = { ...CAMPAIGN_WAITS, waitsSince: '2026-11-15T08:00:00Z' };
    vi.mocked(reopenCampaign).mockResolvedValue(next);
    const { onDecided } = mount(CAMPAIGN_CLOSED);
    fireEvent.click(screen.getByRole('button', { name: 'Open again' }));
    const confirm = screen.getByTestId('campaign-reopen-confirm');
    expect(confirm).toHaveTextContent('Open again clears the close. The campaign then waits on your decision.');
    expect(reopenCampaign).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText('Note'), { target: { value: ' The test goes on. ' } });
    fireEvent.click(within(confirm).getByRole('button', { name: 'Open again' }));
    await waitFor(() => expect(onDecided).toHaveBeenCalledWith(next));
    expect(reopenCampaign).toHaveBeenCalledWith(CAMPAIGN_CLOSED.id, { note: 'The test goes on.' });
  });

  it('keeps the confirm and states the failure when Open again fails', async () => {
    vi.mocked(reopenCampaign).mockRejectedValue(new Error('The campaign holds no decision.'));
    const { onDecided } = mount(CAMPAIGN_CLOSED);
    fireEvent.click(screen.getByRole('button', { name: 'Open again' }));
    fireEvent.click(within(screen.getByTestId('campaign-reopen-confirm')).getByRole('button', { name: 'Open again' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('The campaign holds no decision.');
    expect(screen.getByTestId('campaign-reopen-confirm')).toBeInTheDocument();
    expect(onDecided).not.toHaveBeenCalled();
  });

  it('sends no request in the demo', () => {
    mount(CAMPAIGN_CLOSED, { demo: true });
    fireEvent.click(screen.getByRole('button', { name: 'Open again' }));
    fireEvent.click(within(screen.getByTestId('campaign-reopen-confirm')).getByRole('button', { name: 'Open again' }));
    expect(screen.getByRole('alert')).toHaveTextContent(DEMO_ACTION_NOTE);
    expect(reopenCampaign).not.toHaveBeenCalled();
  });

  it('states an authorized decision of a server with no authorization field with no button', () => {
    mount({ ...CAMPAIGN_CLOSED, decision: { type: 'authorized', by: 'admin', at: CLOSE_AT } });
    const bar = screen.getByTestId('campaign-decision');
    expect(bar).toHaveAttribute('data-state', 'authorized');
    expect(bar).toHaveTextContent('admin authorized this campaign on 2026-11-14 21:00 UTC.');
    expect(within(bar).queryByRole('button')).toBeNull();
  });

  it('offers Record authorized activity to an admin beside the close', () => {
    const { onAuthorizeRequest } = mount(CAMPAIGN_WAITS, { admin: true });
    const bar = screen.getByTestId('campaign-decision');
    const buttons = within(bar).getAllByRole('button').map((b) => b.textContent);
    expect(buttons).toEqual(['Record authorized activity', 'Close with a reason']);
    fireEvent.click(within(bar).getByRole('button', { name: 'Record authorized activity' }));
    expect(onAuthorizeRequest).toHaveBeenCalledTimes(1);
  });

  it('offers no authorization to an analyst and none on a closed campaign', () => {
    // NEGATIVE CONTROL: the button is for an admin, and only while the campaign waits.
    const { unmount } = mount(CAMPAIGN_WAITS);
    expect(screen.queryByRole('button', { name: 'Record authorized activity' })).toBeNull();
    unmount();
    mount(CAMPAIGN_CLOSED, { admin: true });
    expect(screen.queryByRole('button', { name: 'Record authorized activity' })).toBeNull();
  });

  it('states the label, who, when, the expiry and the investigations inside of an authorization', () => {
    mount(CAMPAIGN_AUTHORIZED);
    const bar = screen.getByTestId('campaign-decision');
    expect(bar).toHaveAttribute('data-state', 'authorized');
    expect(within(bar).getByTestId('campaign-decision-state')).toHaveTextContent(
      `admin authorized this campaign on 2026-11-14 21:00 UTC: Red team test. It expires ${utcStamp(AUTHORIZATION.expiresAt)}.`,
    );
    expect(within(bar).getByTestId('campaign-decision-inside')).toHaveTextContent('4 investigations inside.');
    expect(within(bar).getByTestId('campaign-decision-note')).toHaveTextContent('Note: Ticket RT-42.');
    expect(within(bar).getByRole('button', { name: 'Revoke' })).toBeInTheDocument();
    expect(within(bar).queryByRole('button', { name: 'Open again' })).toBeNull();
    expect(banned(bar)).toEqual([]);
  });

  it('states an expired authorization in the past tense and offers no revoke', () => {
    const expiresAt = expiryIn(-1);
    mount({ ...CAMPAIGN_AUTHORIZED, authorization: { ...AUTHORIZATION, state: 'expired', expiresAt } });
    const bar = screen.getByTestId('campaign-decision');
    expect(within(bar).getByTestId('campaign-decision-state')).toHaveTextContent(`It expired ${utcStamp(expiresAt)}.`);
    expect(within(bar).queryByRole('button', { name: 'Revoke' })).toBeNull();
  });

  it('reads a past expiry as expired when the server still states active', () => {
    // NEGATIVE CONTROL: the clock passed the expiry before the next rebuild.
    const expiresAt = expiryIn(-1);
    mount({ ...CAMPAIGN_AUTHORIZED, authorization: { ...AUTHORIZATION, expiresAt } });
    expect(screen.getByTestId('campaign-decision-state')).toHaveTextContent('It expired');
    expect(screen.queryByRole('button', { name: 'Revoke' })).toBeNull();
  });

  it('states what Revoke writes, asks for a reason, then sends it', async () => {
    vi.mocked(revokeCampaignAuthorization).mockResolvedValue(CAMPAIGN_WAITS);
    const { onDecided } = mount(CAMPAIGN_AUTHORIZED);
    fireEvent.click(screen.getByRole('button', { name: 'Revoke' }));
    const confirm = screen.getByTestId('campaign-revoke-confirm');
    expect(confirm).toHaveTextContent(
      'Revoke clears the mark of each investigation inside. The campaign then waits on your decision as one item.',
    );
    const submit = within(confirm).getByRole('button', { name: 'Revoke' });
    // NEGATIVE CONTROL: no reason, no request.
    expect(submit).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: ' The test ended early. ' } });
    fireEvent.click(submit);
    await waitFor(() => expect(onDecided).toHaveBeenCalledWith(CAMPAIGN_WAITS));
    expect(revokeCampaignAuthorization).toHaveBeenCalledWith(CAMPAIGN_AUTHORIZED.id, { reason: 'The test ended early.' });
  });

  it('keeps the revoke and states the failure when the server refuses it', async () => {
    vi.mocked(revokeCampaignAuthorization).mockRejectedValue(new Error('The campaign holds no authorization in force.'));
    const { onDecided } = mount(CAMPAIGN_AUTHORIZED);
    fireEvent.click(screen.getByRole('button', { name: 'Revoke' }));
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'Done.' } });
    fireEvent.click(within(screen.getByTestId('campaign-revoke-confirm')).getByRole('button', { name: 'Revoke' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('The campaign holds no authorization in force.');
    expect(screen.getByTestId('campaign-revoke-confirm')).toBeInTheDocument();
    expect(onDecided).not.toHaveBeenCalled();
  });

  it('sends no revoke in the demo', () => {
    mount(CAMPAIGN_AUTHORIZED, { demo: true });
    fireEvent.click(screen.getByRole('button', { name: 'Revoke' }));
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'Done.' } });
    fireEvent.click(within(screen.getByTestId('campaign-revoke-confirm')).getByRole('button', { name: 'Revoke' }));
    expect(screen.getByRole('alert')).toHaveTextContent(DEMO_ACTION_NOTE);
    expect(revokeCampaignAuthorization).not.toHaveBeenCalled();
  });

  it('shows no bar for a server with no decision field, nor for a merged campaign', () => {
    const { unmount } = mount(CAMPAIGN);
    expect(screen.queryByTestId('campaign-decision')).toBeNull();
    unmount();
    mount({ ...CAMPAIGN_WAITS, status: 'merged', mergedInto: 9 });
    expect(screen.queryByTestId('campaign-decision')).toBeNull();
  });

  it('states an ended campaign that waits as work too', () => {
    mount({ ...CAMPAIGN_WAITS, status: 'ended' });
    expect(screen.getByTestId('campaign-decision')).toHaveAttribute('data-state', 'waits');
  });
});

describe('The case of a campaign', () => {
  it('offers Open one case first, the admin button, then the close, in one visual weight', () => {
    const { onCaseRequest, onCloseRequest } = mount(CAMPAIGN_CASE_READY, { admin: true });
    const bar = screen.getByTestId('campaign-decision');
    expect(bar).toHaveAttribute('data-state', 'waits');
    const buttons = within(bar).getAllByRole('button');
    expect(buttons.map((b) => b.textContent)).toEqual([
      'Open one case',
      'Record authorized activity',
      'Close with a reason',
    ]);
    // None of the three is the default: one class for each.
    expect(new Set(buttons.map((b) => b.className)).size).toBe(1);
    fireEvent.click(within(bar).getByRole('button', { name: 'Open one case' }));
    expect(onCaseRequest).toHaveBeenCalledTimes(1);
    expect(onCloseRequest).not.toHaveBeenCalled();
    expect(banned(bar)).toEqual([]);
  });

  it('offers Open one case to an analyst beside the close', () => {
    mount(CAMPAIGN_CASE_READY);
    const buttons = within(screen.getByTestId('campaign-decision')).getAllByRole('button');
    expect(buttons.map((b) => b.textContent)).toEqual(['Open one case', 'Close with a reason']);
  });

  it('offers no case for a server with no case field, nor on a closed or an authorized campaign', () => {
    // NEGATIVE CONTROL: an older server has no case route. A close and an
    // authorization in force must be opened again or revoked first.
    const { unmount } = mount(CAMPAIGN_WAITS, { admin: true });
    expect(screen.queryByRole('button', { name: 'Open one case' })).toBeNull();
    unmount();
    const closed = mount({ ...CAMPAIGN_CLOSED, case: null });
    expect(screen.queryByRole('button', { name: 'Open one case' })).toBeNull();
    closed.unmount();
    mount({ ...CAMPAIGN_AUTHORIZED, case: null }, { admin: true });
    expect(screen.queryByRole('button', { name: 'Open one case' })).toBeNull();
  });

  it('states the open case: since when, who, the link, the alerts, the comments and the note', () => {
    mount(CAMPAIGN_CASE);
    const bar = screen.getByTestId('campaign-decision');
    expect(bar).toHaveAttribute('data-state', 'case');
    expect(within(bar).getByTestId('campaign-decision-state')).toHaveTextContent(
      'A case is open in Security Onion since 2026-11-15 09:00 UTC, opened by analyst-2.',
    );
    const link = within(bar).getByRole('link', { name: /Open the case/ });
    expect(link).toHaveAttribute('href', CASE_URL);
    expect(link).toHaveAttribute('target', '_blank');
    expect(link.getAttribute('rel')).toContain('noopener');
    expect(within(bar).getByTestId('campaign-case-alerts')).toHaveTextContent('21 alerts attached');
    expect(within(bar).getByTestId('campaign-case-comments')).toHaveTextContent('2 comments by soc-ai');
    expect(within(bar).getByTestId('campaign-decision-note')).toHaveTextContent('Note: Ticket IR-7.');
    expect(within(bar).getAllByRole('button').map((b) => b.textContent)).toEqual(['Open again']);
    expect(banned(bar)).toEqual([]);
  });

  it('states a case with no address as text and one alert in the singular', () => {
    mount({ ...CAMPAIGN_CASE, case: { ...CAMPAIGN_CASE.case!, url: null, alerts: 1, comments: 1 } });
    const bar = screen.getByTestId('campaign-decision');
    expect(within(bar).queryByRole('link')).toBeNull();
    expect(within(bar).getByTestId('campaign-case-alerts')).toHaveTextContent('1 alert attached');
    expect(within(bar).getByTestId('campaign-case-comments')).toHaveTextContent('1 comment by soc-ai');
  });

  it('states what Open again writes on a case before the press, then sends it', async () => {
    vi.mocked(reopenCampaign).mockResolvedValue(CAMPAIGN_CASE_READY);
    const { onDecided } = mount(CAMPAIGN_CASE);
    fireEvent.click(screen.getByRole('button', { name: 'Open again' }));
    const confirm = screen.getByTestId('campaign-reopen-confirm');
    expect(confirm).toHaveTextContent('Open again clears the decision. The case stays in Security Onion');
    expect(reopenCampaign).not.toHaveBeenCalled();
    fireEvent.click(within(confirm).getByRole('button', { name: 'Open again' }));
    await waitFor(() => expect(onDecided).toHaveBeenCalledWith(CAMPAIGN_CASE_READY));
    expect(reopenCampaign).toHaveBeenCalledWith(CAMPAIGN_CASE.id, { note: '' });
  });

  it('states a request with no readable answer and offers Try again as the one button', async () => {
    vi.mocked(retryCampaignCase).mockResolvedValue(CAMPAIGN_CASE_READY);
    const { onDecided } = mount(CAMPAIGN_CASE_PENDING, { admin: true });
    const bar = screen.getByTestId('campaign-decision');
    expect(bar).toHaveAttribute('data-state', 'case_pending');
    expect(within(bar).getByTestId('campaign-decision-state')).toHaveTextContent(
      'soc-ai could not read the answer of Security Onion.',
    );
    expect(bar).toHaveTextContent('analyst-2 asked for the case on 2026-11-15 09:00 UTC.');
    expect(bar).toHaveTextContent('The case can exist in Security Onion.');
    // NEGATIVE CONTROL: no second request and no other decision while the answer is unknown.
    expect(within(bar).getAllByRole('button').map((b) => b.textContent)).toEqual(['Try again']);
    fireEvent.click(within(bar).getByRole('button', { name: 'Try again' }));
    const confirm = screen.getByTestId('campaign-case-retry-confirm');
    expect(confirm).toHaveTextContent(
      'Press Try again only if no case has the title "soc-ai campaign: actor-a against web-1".',
    );
    expect(confirm).toHaveTextContent('Try again clears the request and writes an audit record.');
    expect(retryCampaignCase).not.toHaveBeenCalled();
    fireEvent.click(within(confirm).getByRole('button', { name: 'Try again' }));
    await waitFor(() => expect(onDecided).toHaveBeenCalledWith(CAMPAIGN_CASE_READY));
    expect(retryCampaignCase).toHaveBeenCalledWith(CAMPAIGN_CASE_PENDING.id);
    expect(banned(bar)).toEqual([]);
  });

  it('keeps the Try again confirm and states the failure, and sends nothing in the demo', async () => {
    vi.mocked(retryCampaignCase).mockRejectedValue(new Error('The campaign holds no open request.'));
    const { unmount, onDecided } = mount(CAMPAIGN_CASE_PENDING);
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    fireEvent.click(within(screen.getByTestId('campaign-case-retry-confirm')).getByRole('button', { name: 'Try again' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('The campaign holds no open request.');
    expect(screen.getByTestId('campaign-case-retry-confirm')).toBeInTheDocument();
    expect(onDecided).not.toHaveBeenCalled();
    unmount();
    vi.mocked(retryCampaignCase).mockReset();
    mount(CAMPAIGN_CASE_PENDING, { demo: true });
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    fireEvent.click(within(screen.getByTestId('campaign-case-retry-confirm')).getByRole('button', { name: 'Try again' }));
    expect(screen.getByRole('alert')).toHaveTextContent(DEMO_ACTION_NOTE);
    expect(retryCampaignCase).not.toHaveBeenCalled();
  });

  it('states a refused case with its reason and offers the case again', () => {
    const { onCaseRequest } = mount(CAMPAIGN_CASE_FAILED);
    const bar = screen.getByTestId('campaign-decision');
    expect(bar).toHaveAttribute('data-state', 'waits');
    expect(within(bar).getByTestId('campaign-case-failed')).toHaveTextContent(
      'Security Onion refused the case. soc-ai holds no case for this campaign. Reason: Security Onion answered 503.',
    );
    fireEvent.click(within(bar).getByRole('button', { name: 'Open one case' }));
    expect(onCaseRequest).toHaveBeenCalledTimes(1);
    expect(banned(bar)).toEqual([]);
  });

  it('states no refusal for a campaign with no case', () => {
    // NEGATIVE CONTROL: a case of null is no failure.
    mount(CAMPAIGN_CASE_READY);
    expect(screen.queryByTestId('campaign-case-failed')).toBeNull();
  });
});
