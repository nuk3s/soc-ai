// The dialog that records authorized activity from one true positive run.
// The scope holds exact source addresses and exact rule names, and the dialog
// lists exactly what can match. It says why the server left a source address
// out, that a target with no agent follows its address, and how many earlier
// runs the scope matches. The earlier runs stay off until the analyst asks.
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AuthorizedDraft } from '../lib/api';

const draftMock = vi.hoisted(() => vi.fn());
const createMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAuthorizedDraft: draftMock,
  createAuthorizedActivity: createMock,
}));

import { ApiError } from '../lib/api';
import { AuthorizedActivityDialog } from './AuthorizedActivityDialog';

const RULE = 'ET EXPLOIT PHP php2shell Nested Empty File Control OOM (CVE-2026-109618)';
const CHUNKED =
  'ET EXPLOIT PHP php2shell Chunked Multipart Request without Content-Length (CVE-2026-109618)';
const HUNTING = 'ET HUNTING PHP Generic Upload Progress Session Manipulation';

const draft = (over: Partial<AuthorizedDraft> = {}): AuthorizedDraft => ({
  investigation_id: 'INV-1',
  allowed: true,
  reason: null,
  hint: null,
  rule_class: 'exploit_attempt',
  target: { address: '10.40.0.164', name: null, machine_key: 'ip:10.40.0.164', identity: 'address' },
  target_has_agent: false,
  sources: [
    {
      address: '10.50.0.26',
      name: 'agent-a',
      machine_key: 'agent:a-1',
      identity: 'agent',
      runs: 3,
      of_this_run: true,
    },
    {
      address: '10.50.0.52',
      name: 'agent-b',
      machine_key: 'agent:b-2',
      identity: 'agent',
      runs: 1,
      of_this_run: false,
    },
  ],
  excluded_sources: [
    {
      address: '10.50.0.27',
      reason: 'source_joined_by_name',
      hint: 'The source address 10.50.0.27 joined its machine by a DNS name only. A name does not prove the machine.',
    },
  ],
  rules: [
    { name: RULE, runs: 1, of_this_run: true },
    { name: CHUNKED, runs: 3, of_this_run: false },
    { name: HUNTING, runs: 1, of_this_run: false },
  ],
  earlier_runs: 0,
  this_run_outside: null,
  earlier_days_max: 30,
  default_days: 7,
  max_days: 30,
  expiry_choices: [1, 7, 14, 30],
  max_sources: 8,
  max_rules: 20,
  ...over,
});

/** The server counts the earlier runs of the chosen scope. */
function answerFor(q: { rules?: string[]; sources?: string[] }): AuthorizedDraft {
  const rules = (q.rules ?? []).includes(CHUNKED) ? 2 : 0;
  const sources = (q.sources ?? []).includes('10.50.0.52') ? 1 : 0;
  return draft({ earlier_runs: rules + sources });
}

const onClose = vi.fn();
const onSaved = vi.fn();

const mount = () =>
  render(<AuthorizedActivityDialog invId="INV-1" open onClose={onClose} onSaved={onSaved} />);

const box = (testId: string, name: RegExp) =>
  within(screen.getByTestId(testId)).getByRole('checkbox', { name });

afterEach(() => {
  cleanup();
  draftMock.mockReset();
  createMock.mockReset();
  onClose.mockReset();
  onSaved.mockReset();
});

describe('the authorized activity dialog', () => {
  it('lists exactly the addresses and the rules that can match', async () => {
    draftMock.mockImplementation((_id: string, q) => Promise.resolve(answerFor(q)));
    mount();
    const dialog = await screen.findByRole('dialog', { name: 'Record authorized activity' });
    await screen.findByLabelText('Label');
    expect(dialog.textContent).toContain('agent-a at 10.50.0.26 is the source of this investigation.');
    expect(dialog.textContent).toContain('3 true positive investigations on the target in the last 30 days.');
    expect(dialog.textContent).toContain(
      'A match needs one of these exact addresses, on the same machine as now.',
    );
    // Each rule is a whole name. No family and no prefix is on the page.
    const rules = screen.getByTestId('authorized-rules');
    expect(within(rules).getAllByRole('checkbox')).toHaveLength(3);
    expect(rules.textContent).toContain('A match needs one of these exact rule names');
    expect(rules.textContent).toContain(`${RULE} is the rule of this investigation.`);
    expect(dialog.textContent).not.toMatch(/family|stem|prefix/i);
    // The first read sends no rule and no source: the server's defaults.
    expect(draftMock).toHaveBeenCalledWith('INV-1', { rules: [], sources: [] });
    expect(draftMock).toHaveBeenCalledTimes(1);
  });

  it('says why a source address is left out', async () => {
    draftMock.mockResolvedValue(draft());
    mount();
    await screen.findByLabelText('Label');
    expect(screen.getByTestId('excluded-sources').textContent).toBe(
      'The source address 10.50.0.27 joined its machine by a DNS name only. A name does not prove the machine. It cannot be in a scope.',
    );
    // An address the draft left out has no checkbox.
    expect(within(screen.getByTestId('authorized-sources')).getAllByRole('checkbox')).toHaveLength(2);
  });

  it('says that a target with no agent follows its address', async () => {
    draftMock.mockResolvedValue(draft());
    mount();
    await screen.findByLabelText('Label');
    expect(screen.getByTestId('authorized-target').textContent).toContain(
      'The target has no agent. The record follows the address, so another device on this address is inside the scope until the expiry.',
    );
    cleanup();
    draftMock.mockResolvedValue(
      draft({
        target_has_agent: true,
        target: { address: '10.40.0.164', name: 'web', machine_key: 'agent:t-1', identity: 'agent' },
      }),
    );
    mount();
    await screen.findByLabelText('Label');
    expect(screen.getByTestId('authorized-target').textContent).toContain(
      'web at 10.40.0.164. The agent of this machine reports the address.',
    );
    expect(screen.getByTestId('authorized-target').textContent).not.toContain('no agent');
  });

  it('saves the rule and the source of the run, with the earlier runs off', async () => {
    draftMock.mockImplementation((_id: string, q) => Promise.resolve(answerFor(q)));
    createMock.mockResolvedValue({ id: 3, label: 'php2shell test' });
    mount();
    const save = () => screen.getByRole('button', { name: 'Record authorized activity' });
    await screen.findByLabelText('Label');
    // The label is required.
    expect(save()).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Label'), { target: { value: ' php2shell test ' } });
    // The rule and the source of the run cannot be removed.
    expect(box('authorized-rules', /is the rule of this investigation/)).toBeDisabled();
    expect(box('authorized-sources', /is the source of this investigation/)).toBeDisabled();
    expect(screen.getByTestId('apply-earlier')).toBeDisabled();
    fireEvent.click(save());
    await waitFor(() => expect(createMock).toHaveBeenCalledTimes(1));
    expect(createMock).toHaveBeenCalledWith({
      investigation_id: 'INV-1',
      label: 'php2shell test',
      note: null,
      sources: ['10.50.0.26'],
      rule_names: [RULE],
      expires_in_days: 7,
      apply_to_earlier: false,
    });
    await waitFor(() => expect(onSaved).toHaveBeenCalledWith({ id: 3, label: 'php2shell test' }));
    expect(onClose).toHaveBeenCalled();
  });

  it('counts the earlier runs again when the analyst adds a rule or a source', async () => {
    draftMock.mockImplementation((_id: string, q) => Promise.resolve(answerFor(q)));
    createMock.mockResolvedValue({ id: 3, label: 't' });
    mount();
    await screen.findByLabelText('Label');
    fireEvent.change(screen.getByLabelText('Label'), { target: { value: 't' } });
    fireEvent.click(box('authorized-rules', /Chunked Multipart/));
    await waitFor(() =>
      expect(screen.getByTestId('apply-earlier').parentElement?.textContent).toContain(
        'Apply the record to the 2 earlier investigations that this scope matches in the last 30 days.',
      ),
    );
    expect(draftMock).toHaveBeenLastCalledWith('INV-1', { rules: [CHUNKED], sources: [] });
    fireEvent.click(box('authorized-sources', /agent-b/));
    await waitFor(() =>
      expect(screen.getByTestId('apply-earlier').parentElement?.textContent).toContain(
        '3 earlier investigations',
      ),
    );
    // The checkbox is off until the analyst selects it.
    expect(screen.getByTestId('apply-earlier')).not.toBeChecked();
    fireEvent.click(screen.getByTestId('apply-earlier'));
    fireEvent.change(screen.getByLabelText('Expiry'), { target: { value: '14' } });
    fireEvent.click(screen.getByRole('button', { name: 'Record authorized activity' }));
    await waitFor(() => expect(createMock).toHaveBeenCalledTimes(1));
    expect(createMock.mock.calls[0][0]).toMatchObject({
      sources: ['10.50.0.26', '10.50.0.52'],
      rule_names: [RULE, CHUNKED],
      expires_in_days: 14,
      apply_to_earlier: true,
    });
  });

  it('says before the save when the run itself stays outside the record', async () => {
    draftMock.mockResolvedValue(
      draft({
        this_run_outside:
          'This activity is outside the authorized scope of this record: the report cites activity beyond the scope.',
      }),
    );
    mount();
    expect((await screen.findByTestId('this-run-outside')).textContent).toBe(
      'This investigation keeps normal handling under the record. This activity is outside the authorized scope of this record: the report cites activity beyond the scope.',
    );
  });

  it('says why a run cannot start a record, and shows no form', async () => {
    draftMock.mockResolvedValue(
      draft({
        allowed: false,
        reason: 'source_on_bridge',
        hint: 'The source address 10.89.0.1 is a container or bridge address. More than one machine can hold it.',
        target: null,
        sources: [],
        rules: [],
        excluded_sources: [],
      }),
    );
    mount();
    expect((await screen.findByTestId('authorized-refusal')).textContent).toBe(
      'The source address 10.89.0.1 is a container or bridge address. More than one machine can hold it.',
    );
    expect(screen.queryByLabelText('Label')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Record authorized activity' })).toBeNull();
    // The corner button and the footer button both close the dialog.
    expect(screen.getAllByRole('button', { name: 'Close' })).toHaveLength(2);
  });

  it('keeps the form and says that the save needs an admin', async () => {
    draftMock.mockResolvedValue(draft());
    createMock.mockRejectedValue(new ApiError('Admin role required.', 403, 'admin_required'));
    mount();
    await screen.findByLabelText('Label');
    fireEvent.change(screen.getByLabelText('Label'), { target: { value: 't' } });
    fireEvent.click(screen.getByRole('button', { name: 'Record authorized activity' }));
    expect((await screen.findByRole('alert')).textContent).toBe(
      'Only an admin can record authorized activity.',
    );
    expect(onSaved).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('renders nothing while it is closed', () => {
    render(<AuthorizedActivityDialog invId="INV-1" open={false} onClose={onClose} onSaved={onSaved} />);
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(draftMock).not.toHaveBeenCalled();
  });
});

describe('the authorized activity dialog of an investigation in a campaign', () => {
  const CAMPAIGN_LINK = { id: 7, title: 'actor-a against web-1', status: 'open' as const, stage: 'action' as const, differs: false };

  const mountIn = (campaign: typeof CAMPAIGN_LINK | null) =>
    render(
      <MemoryRouter>
        <AuthorizedActivityDialog invId="INV-1" open onClose={onClose} onSaved={onSaved} campaign={campaign} />
      </MemoryRouter>,
    );

  it('sends the admin to the campaign and reads no draft', () => {
    mountIn(CAMPAIGN_LINK);
    const note = screen.getByTestId('authorized-on-campaign');
    expect(note).toHaveTextContent('This investigation is part of the campaign actor-a against web-1.');
    const link = within(note).getByRole('link', { name: 'Record it on the campaign' });
    expect(link).toHaveAttribute('href', '/campaigns/7');
    expect(draftMock).not.toHaveBeenCalled();
    expect(screen.queryByLabelText('Label')).toBeNull();
    fireEvent.click(link);
    expect(onClose).toHaveBeenCalled();
  });

  it('keeps the form for an investigation in no campaign, and for a verdict that differs', async () => {
    // NEGATIVE CONTROLS: the old form stays where no campaign holds the investigation.
    draftMock.mockResolvedValue(draft());
    const { unmount } = mountIn(null);
    expect(await screen.findByLabelText('Label')).toBeInTheDocument();
    expect(screen.queryByTestId('authorized-on-campaign')).toBeNull();
    unmount();
    mountIn({ ...CAMPAIGN_LINK, differs: true });
    expect(await screen.findByLabelText('Label')).toBeInTheDocument();
    expect(screen.queryByTestId('authorized-on-campaign')).toBeNull();
  });
});
