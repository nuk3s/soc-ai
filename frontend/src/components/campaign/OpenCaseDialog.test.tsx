// The dialog "Open one case". It shows the case as Security Onion holds it
// before the press: the title, the bottom line, the stage meter, the
// machines, the alerts with the skipped counts in words, the note, and what
// the press writes. The negative controls: no press before the count, no
// request before the press, no zero for a count soc-ai cannot read, no second
// case for a campaign that holds one, and no request in the demo.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../../lib/api')>('../../lib/api');
  return {
    ...actual,
    getCampaignCaseScope: vi.fn(),
    openCampaignCase: vi.fn(),
    getCampaign: vi.fn(),
  };
});
import {
  ApiError,
  getCampaign,
  getCampaignCaseScope,
  openCampaignCase,
  type CampaignCaseScope,
} from '../../lib/api';
import { DEMO_ACTION_NOTE, DemoProvider } from '../../lib/demo';
import { forbiddenWords } from '../../test/analystWords';
import {
  BEYOND_KEY,
  CAMPAIGN_CASE,
  CAMPAIGN_CASE_FAILED,
  CAMPAIGN_CASE_READY,
  CASE_ID,
  CASE_URL,
} from '../../test/campaign';
import { OpenCaseDialog } from './OpenCaseDialog';

const SCOPE: CampaignCaseScope = {
  title: 'soc-ai campaign: actor-a against web-1',
  alerts: 21,
  capped: false,
  skipped: { acknowledged: 3, escalated: 1, noAlert: 28 },
  existing: null,
};

function mount(opts: { demo?: boolean } = {}) {
  const onClose = vi.fn();
  const onOpened = vi.fn();
  render(
    <DemoProvider demo={opts.demo ?? false}>
      <MemoryRouter>
        <OpenCaseDialog campaign={CAMPAIGN_CASE_READY} open onClose={onClose} onOpened={onOpened} />
      </MemoryRouter>
    </DemoProvider>,
  );
  return { onClose, onOpened, dialog: screen.getByRole('dialog') };
}

/** The words an analyst reads, with "kind" banned beside the shared list. */
function banned(root: Element): string[] {
  const text = root.textContent ?? '';
  return [...forbiddenWords(root), ...(/\bkinds?\b/i.test(text) ? [text] : [])];
}

const submit = (name = 'Open one case') => within(screen.getByTestId('case-actions')).getByRole('button', { name });

beforeEach(() => {
  vi.mocked(getCampaignCaseScope).mockReset().mockResolvedValue(SCOPE);
  vi.mocked(openCampaignCase).mockReset();
  vi.mocked(getCampaign).mockReset();
});

describe('OpenCaseDialog', () => {
  it('shows the case as Security Onion holds it, in order, before the press', async () => {
    const { dialog } = mount();
    expect(within(dialog).getByText('Open one case', { selector: '[id]' })).toBeInTheDocument();
    const preview = await within(dialog).findByTestId('case-preview');
    expect(within(preview).getByTestId('case-title')).toHaveTextContent('soc-ai campaign: actor-a against web-1');
    expect(within(preview).getByTestId('case-bottom-line')).toHaveTextContent(CAMPAIGN_CASE_READY.bottomLine);
    expect(within(preview).getByTestId('case-stage')).toHaveTextContent('Stage reached: Action on the target, 4 of 5');
    expect(within(preview).getByTestId('case-period')).toHaveTextContent('2026-10-24 00:40 to 2026-10-28 22:44 UTC');
    // The machines, as the small picture of the authorize dialog: no check box.
    const picture = within(preview).getByTestId('case-picture');
    expect(within(picture).queryByRole('checkbox')).toBeNull();
    expect(within(screen.getByTestId('case-actors')).getByText('actor-a')).toBeInTheDocument();
    expect(within(screen.getByTestId('case-actors')).getByText('192.0.2.10')).toBeInTheDocument();
    expect(within(screen.getByTestId('case-targets')).getByText('web-1')).toBeInTheDocument();
    expect(within(screen.getByTestId('case-further')).getByText('192.0.2.30')).toBeInTheDocument();
    expect(screen.getByTestId('case-further').querySelector(`[data-machine="${BEYOND_KEY}"]`)).not.toBeNull();
    // The numbers, then the note.
    // The count comes from its own read, after the preview. Wait for it.
    expect(await within(preview).findByTestId('case-alerts')).toHaveTextContent('21 alerts go on the case.');
    expect(within(preview).getByTestId('case-skipped')).toHaveTextContent(
      '3 alerts are acknowledged.1 alert is on a case.28 records are not Security Onion alerts.',
    );
    const order = ['case-title', 'case-bottom-line', 'case-stage', 'case-picture', 'case-alerts', 'case-note'].map((id) =>
      within(preview).getByTestId(id),
    );
    for (let i = 1; i < order.length; i += 1) {
      expect(order[i - 1].compareDocumentPosition(order[i]) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    }
    const writes = within(dialog).getByTestId('case-writes');
    expect(writes).toHaveTextContent('The press writes to Security Onion.');
    expect(writes).toHaveTextContent('soc-ai writes one case, 21 alerts acknowledged and escalated, and one audit record.');
    expect(openCampaignCase).not.toHaveBeenCalled();
    expect(banned(dialog)).toEqual([]);
  });

  it('waits for the count before the press', () => {
    // NEGATIVE CONTROL: a press before the count would write an unknown scope.
    vi.mocked(getCampaignCaseScope).mockReturnValue(new Promise(() => {}));
    mount();
    expect(screen.getByText('soc-ai counts the alerts for the case.')).toBeInTheDocument();
    expect(submit()).toBeDisabled();
  });

  it('sends the note and hands the answer on', async () => {
    vi.mocked(openCampaignCase).mockResolvedValue(CAMPAIGN_CASE);
    const { onOpened, onClose } = mount();
    await screen.findByTestId('case-alerts');
    fireEvent.change(screen.getByLabelText('Note'), { target: { value: ' Ticket IR-7. ' } });
    fireEvent.click(submit());
    await waitFor(() => expect(onOpened).toHaveBeenCalledWith(CAMPAIGN_CASE));
    expect(openCampaignCase).toHaveBeenCalledWith(CAMPAIGN_CASE_READY.id, { note: 'Ticket IR-7.' });
    expect(onClose).toHaveBeenCalled();
  });

  it('states a count that soc-ai cannot read as unknown, never as zero', async () => {
    vi.mocked(getCampaignCaseScope).mockResolvedValue({ ...SCOPE, alerts: null });
    mount();
    expect(await screen.findByTestId('case-alerts')).toHaveTextContent('soc-ai cannot count the alerts for the case.');
    expect(screen.getByTestId('case-writes')).toHaveTextContent(
      'soc-ai writes one case, the alerts that soc-ai can read acknowledged and escalated, and one audit record.',
    );
    expect(screen.getByRole('dialog').textContent).not.toMatch(/\b0 alerts\b/);
    expect(submit()).toBeEnabled();
  });

  it('states a failed read of the scope as an unknown count, with the title of the campaign', async () => {
    vi.mocked(getCampaignCaseScope).mockRejectedValue(new Error('502'));
    mount();
    expect(await screen.findByTestId('case-alerts')).toHaveTextContent('soc-ai cannot count the alerts for the case.');
    expect(screen.getByTestId('case-title')).toHaveTextContent('soc-ai campaign: actor-a against web-1');
    expect(screen.queryByTestId('case-skipped')).toBeNull();
  });

  it('states a capped count and no alert in words', async () => {
    vi.mocked(getCampaignCaseScope).mockResolvedValue({ ...SCOPE, alerts: 25, capped: true });
    const { unmount } = render(
      <MemoryRouter>
        <OpenCaseDialog campaign={CAMPAIGN_CASE_READY} open onClose={() => {}} onOpened={() => {}} />
      </MemoryRouter>,
    );
    expect(await screen.findByTestId('case-capped')).toHaveTextContent(
      'The campaign holds more alerts. The case takes the 25 newest.',
    );
    unmount();
    vi.mocked(getCampaignCaseScope).mockResolvedValue({
      ...SCOPE,
      alerts: 0,
      skipped: { acknowledged: 0, escalated: 0, noAlert: 0 },
    });
    mount();
    expect(await screen.findByTestId('case-alerts')).toHaveTextContent('No alert goes on the case.');
    expect(screen.queryByTestId('case-skipped')).toBeNull();
    expect(screen.getByTestId('case-writes')).toHaveTextContent('soc-ai writes one case with no alert and one audit record.');
  });

  it('names the case that the campaign holds and opens no second one', async () => {
    vi.mocked(getCampaignCaseScope).mockResolvedValue({ ...SCOPE, existing: { id: CASE_ID, url: CASE_URL } });
    vi.mocked(openCampaignCase).mockResolvedValue(CAMPAIGN_CASE);
    const { onOpened } = mount();
    const existing = await screen.findByTestId('case-existing');
    expect(existing).toHaveTextContent(`Security Onion holds the case ${CASE_ID} of this campaign.`);
    const link = within(existing).getByRole('link', { name: /Open the case/ });
    expect(link).toHaveAttribute('href', CASE_URL);
    expect(link).toHaveAttribute('target', '_blank');
    expect(screen.queryByTestId('case-alerts')).toBeNull();
    expect(screen.getByTestId('case-writes')).toHaveTextContent('The press opens no second case in Security Onion.');
    fireEvent.click(submit('Record the case'));
    await waitFor(() => expect(onOpened).toHaveBeenCalledWith(CAMPAIGN_CASE));
  });

  it('keeps the dialog on a refusal, states it, and reads the campaign again', async () => {
    vi.mocked(openCampaignCase).mockRejectedValue(new ApiError('Security Onion refused the case.', 502, 'so_write_failed'));
    vi.mocked(getCampaign).mockResolvedValue(CAMPAIGN_CASE_FAILED);
    const { onOpened, onClose } = mount();
    await screen.findByTestId('case-alerts');
    fireEvent.click(submit());
    expect(await screen.findByRole('alert')).toHaveTextContent('Security Onion refused the case.');
    await waitFor(() => expect(onOpened).toHaveBeenCalledWith(CAMPAIGN_CASE_FAILED));
    expect(getCampaign).toHaveBeenCalledWith(CAMPAIGN_CASE_READY.id);
    expect(onClose).not.toHaveBeenCalled();
  });

  it('sends no request in the demo', async () => {
    mount({ demo: true });
    await screen.findByTestId('case-alerts');
    fireEvent.click(submit());
    expect(screen.getByRole('alert')).toHaveTextContent(DEMO_ACTION_NOTE);
    expect(openCampaignCase).not.toHaveBeenCalled();
  });
});
