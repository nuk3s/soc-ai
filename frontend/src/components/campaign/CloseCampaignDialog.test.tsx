import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { CloseCampaignDialog } from './CloseCampaignDialog';

vi.mock('../../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../../lib/api')>('../../lib/api');
  return { ...actual, getCampaignCloseScope: vi.fn(), closeCampaign: vi.fn() };
});
import { ApiError, closeCampaign, getCampaignCloseScope } from '../../lib/api';
import { DEMO_ACTION_NOTE, DemoProvider } from '../../lib/demo';
import { forbiddenWords } from '../../test/analystWords';
import { CAMPAIGN_CLOSED, CAMPAIGN_WAITS } from '../../test/campaign';

function mount(opts: { demo?: boolean } = {}) {
  const onClose = vi.fn();
  const onClosed = vi.fn();
  render(
    <DemoProvider demo={opts.demo ?? false}>
      <CloseCampaignDialog campaign={CAMPAIGN_WAITS} open onClose={onClose} onClosed={onClosed} />
    </DemoProvider>,
  );
  return { onClose, onClosed };
}

const submit = () => screen.getByRole('button', { name: 'Close the campaign' });

beforeEach(() => {
  vi.mocked(getCampaignCloseScope).mockReset().mockResolvedValue({ alerts: 1083, rules: 7, capped: false });
  vi.mocked(closeCampaign).mockReset().mockResolvedValue(CAMPAIGN_CLOSED);
});

describe('CloseCampaignDialog', () => {
  it('offers the three reasons, the note and the acknowledgement with its count', async () => {
    mount();
    const dialog = screen.getByRole('dialog', { name: 'Close the campaign' });
    expect(getCampaignCloseScope).toHaveBeenCalledWith(CAMPAIGN_WAITS.id);
    const radios = screen.getAllByRole('radio');
    expect(radios.map((r) => r.closest('label')?.textContent)).toEqual([
      'Handled outside soc-ai',
      'Accepted risk',
      'Test that is over',
    ]);
    expect(radios.every((r) => !(r as HTMLInputElement).checked)).toBe(true);
    const ack = await screen.findByRole('checkbox', {
      name: 'Acknowledge 1,083 alerts of 7 rules in Security Onion',
    });
    expect(ack).toBeChecked();
    expect(dialog).toHaveTextContent('New activity opens this campaign again.');
    expect(dialog).toHaveTextContent('A close changes no verdict.');
    expect(screen.getByLabelText('Note')).toBeInTheDocument();
    expect(forbiddenWords(dialog)).toEqual([]);
    expect(dialog.textContent).not.toMatch(/\bkinds?\b/i);
  });

  it('states what the press writes and holds the press until a reason is chosen', async () => {
    mount();
    await screen.findByRole('checkbox');
    expect(submit()).toBeDisabled();
    fireEvent.click(screen.getByRole('radio', { name: 'Test that is over' }));
    expect(submit()).toBeEnabled();
    expect(screen.getByTestId('close-writes')).toHaveTextContent(
      'soc-ai stores the close and an audit record. Then soc-ai acknowledges 1,083 alerts in Security Onion.',
    );
    fireEvent.click(screen.getByRole('checkbox'));
    expect(screen.getByTestId('close-writes')).toHaveTextContent('soc-ai stores the close and an audit record.');
    expect(screen.getByTestId('close-writes')).not.toHaveTextContent('Security Onion');
  });

  it('sends the reason, the note and the acknowledgement, and gives back the answer', async () => {
    const { onClose, onClosed } = mount();
    await screen.findByRole('checkbox');
    fireEvent.click(screen.getByRole('radio', { name: 'Accepted risk' }));
    fireEvent.change(screen.getByLabelText('Note'), { target: { value: '  Known scanner.  ' } });
    fireEvent.click(submit());
    await waitFor(() => expect(onClosed).toHaveBeenCalledWith(CAMPAIGN_CLOSED));
    expect(closeCampaign).toHaveBeenCalledWith(CAMPAIGN_WAITS.id, {
      reason: 'accepted_risk',
      note: 'Known scanner.',
      acknowledge: true,
    });
    expect(onClose).toHaveBeenCalled();
  });

  it('states that soc-ai cannot read the count when the grid did not answer', async () => {
    vi.mocked(getCampaignCloseScope).mockResolvedValue({ alerts: null, rules: null, capped: false });
    mount();
    expect(await screen.findByTestId('close-scope-unread')).toHaveTextContent('soc-ai cannot read the count.');
    // An unknown count is no zero: the box stays, and it starts clear.
    const ack = screen.getByRole('checkbox', {
      name: 'Acknowledge the alerts of the confirmed rules in Security Onion',
    });
    expect(ack).not.toBeChecked();
    expect(screen.getByRole('dialog')).not.toHaveTextContent(/\b0 alerts\b/);
  });

  it('treats a failed scope read as an unknown count', async () => {
    vi.mocked(getCampaignCloseScope).mockRejectedValue(new Error('boom'));
    mount();
    expect(await screen.findByTestId('close-scope-unread')).toBeInTheDocument();
  });

  it('offers no acknowledgement when no alert waits for one', async () => {
    vi.mocked(getCampaignCloseScope).mockResolvedValue({ alerts: 0, rules: 0, capped: false });
    mount();
    expect(await screen.findByTestId('close-scope-none')).toHaveTextContent(
      'No alert of this campaign waits for an acknowledgement.',
    );
    expect(screen.queryByRole('checkbox')).toBeNull();
    fireEvent.click(screen.getByRole('radio', { name: 'Handled outside soc-ai' }));
    fireEvent.click(submit());
    await waitFor(() => expect(closeCampaign).toHaveBeenCalled());
    expect(vi.mocked(closeCampaign).mock.calls[0][1].acknowledge).toBe(false);
  });

  it('states the cap of the count', async () => {
    vi.mocked(getCampaignCloseScope).mockResolvedValue({ alerts: 2000, rules: 9, capped: true });
    mount();
    expect(await screen.findByTestId('close-scope-capped')).toHaveTextContent(
      'The count stops at 2,000 alerts. More alerts can exist.',
    );
  });

  it('states the refusal of the server and stays open', async () => {
    vi.mocked(closeCampaign).mockRejectedValue(
      new ApiError('The campaign holds a decision.', 409, 'campaign_decided'),
    );
    const { onClose, onClosed } = mount();
    await screen.findByRole('checkbox');
    fireEvent.click(screen.getByRole('radio', { name: 'Test that is over' }));
    fireEvent.click(submit());
    expect(await screen.findByRole('alert')).toHaveTextContent('The campaign holds a decision.');
    expect(onClosed).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('sends no request in the demo', async () => {
    mount({ demo: true });
    await screen.findByRole('checkbox');
    fireEvent.click(screen.getByRole('radio', { name: 'Test that is over' }));
    fireEvent.click(submit());
    expect(screen.getByRole('alert')).toHaveTextContent(DEMO_ACTION_NOTE);
    expect(closeCampaign).not.toHaveBeenCalled();
  });

  it('closes on Escape and on Cancel', async () => {
    const { onClose } = mount();
    fireEvent.keyDown(window, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onClose).toHaveBeenCalledTimes(2);
  });
});
