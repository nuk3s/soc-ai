// The write and Dismiss on a row of the pending-action list (dogfood
// 2026-10-19, R1-I1). The needs-you line opens the list of the runs with a
// waiting action. The analyst opened each run to act and came back: two page
// changes per run. The row now offers the action in place, through the same
// client functions and routes as the action card.
//
// The negative controls: the first click never writes, Cancel and Escape
// write nothing, a replay row offers no write even when the server flag
// says it may, and a failed write keeps the row.
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DemoProvider } from '../lib/demo';
import { ToastProvider } from '../lib/toast';
import type { InvestigationRow, WaitingAction } from '../lib/types';

const executeAction = vi.hoisted(() => vi.fn());
const dismissAction = vi.hoisted(() => vi.fn());
const restoreAction = vi.hoisted(() => vi.fn());
const getActionScope = vi.hoisted(() => vi.fn());
vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  executeAction,
  dismissAction,
  restoreAction,
  getActionScope,
}));

import { ACTION_VERB } from './ActionCard';
import { WaitingActions, actionConfirmText, actionTargetText } from './WaitingActions';

const RULE = 'ET MALWARE Known C2 Beacon';

const escalate: WaitingAction = {
  id: 'a0',
  index: 0,
  type: 'escalate',
  label: 'Escalate to case',
  target: RULE,
  targetType: 'alert',
  rationale: 'The beacon matches a known C2 address.',
  executable: true,
  reason: null,
};

const ack: WaitingAction = {
  ...escalate,
  id: 'a1',
  index: 1,
  type: 'ack',
  label: 'Acknowledge',
  rationale: 'Close the noise of this rule.',
};

const comment: WaitingAction = {
  ...escalate,
  id: 'a2',
  index: 2,
  type: 'comment',
  label: 'Add comment',
  target: 'case-7',
  targetType: 'case',
  rationale: 'Add the second beacon to the case.',
};

const row = (over: Partial<InvestigationRow> = {}): InvestigationRow => ({
  id: 'INV-1',
  name: RULE,
  kind: 'suricata',
  verdict: 'true_positive',
  conf: 0.8,
  host: '192.0.2.10',
  dst: '198.51.100.7',
  status: 'complete',
  when: '2h',
  ranBy: 'scheduler',
  pendingActions: 1,
  waitingActions: [escalate],
  ...over,
});

function mount(r: InvestigationRow, opts: { demo?: boolean } = {}) {
  const onDone = vi.fn();
  const onRestored = vi.fn();
  render(
    <DemoProvider demo={opts.demo ?? false}>
      <ToastProvider>
        <WaitingActions row={r} onDone={onDone} onRestored={onRestored} />
      </ToastProvider>
    </DemoProvider>,
  );
  return { onDone, onRestored };
}

beforeEach(() => {
  executeAction.mockReset();
  dismissAction.mockReset();
  restoreAction.mockReset();
  getActionScope.mockReset();
});

describe('the row controls', () => {
  it('names the write on the button, the same word as the card, and the target', () => {
    mount(row({ waitingActions: [escalate, ack, comment] }));
    const line = screen.getByTestId('waiting-action-INV-1-0');
    expect(line.textContent).toContain(`The alert of ${RULE}`);
    expect(line.textContent).toContain('The beacon matches a known C2 address.');
    // The button names the write, the word of the action card. "Execute"
    // named nothing.
    expect(ACTION_VERB).toEqual({ ack: 'Acknowledge', escalate: 'Escalate to case', comment: 'Add comment' });
    expect(
      screen.getByRole('button', { name: 'Escalate to case', description: `The alert of ${RULE}` }),
    ).toBeTruthy();
    expect(
      screen.getByRole('button', { name: 'Acknowledge', description: `The alerts of ${RULE}` }),
    ).toBeTruthy();
    expect(
      screen.getByRole('button', { name: 'Add comment', description: 'Security Onion case case-7' }),
    ).toBeTruthy();
    expect(
      screen.getByRole('button', { name: 'Dismiss', description: `The alert of ${RULE}` }),
    ).toBeTruthy();
    expect(screen.queryByRole('button', { name: /Execute/ })).toBeNull();
  });

  it('puts the write and Dismiss in the Tab order', async () => {
    const user = userEvent.setup();
    mount(row());
    await user.tab();
    expect(document.activeElement?.textContent).toBe('Escalate to case');
    await user.tab();
    expect(document.activeElement?.textContent).toBe('Dismiss');
  });

  it('turns the write off and states the reason when the server says so', () => {
    const reason =
      'ana set the verdict of this alert to false positive. This run reached true positive. Override the verdict of this run to act.';
    mount(row({ waitingActions: [{ ...escalate, executable: false, reason }] }));
    const write = screen.getByRole('button', { name: 'Escalate to case' });
    expect(write).toBeDisabled();
    fireEvent.click(write);
    expect(screen.queryByTestId('waiting-action-confirm')).toBeNull();
    expect(screen.getByTestId('waiting-action-reason').textContent).toBe(reason);
    // Dismiss writes nothing to Security Onion. The row keeps it.
    expect(screen.getByRole('button', { name: 'Dismiss' })).toBeEnabled();
  });

  it('NEGATIVE CONTROL: a replay row offers no write, whatever the flag says', () => {
    mount(row({ ranBy: 'backtest', waitingActions: [{ ...escalate, executable: true }] }));
    expect(screen.queryByRole('button')).toBeNull();
    // With no button, the line names the type itself.
    expect(screen.getByTestId('waiting-action-INV-1-0').textContent).toContain('Escalate to case');
    expect(screen.getByTestId('waiting-action-reason').textContent).toBe(
      'Not executable. This run is a backtest replay.',
    );
    expect(executeAction).not.toHaveBeenCalled();
  });
});

describe('the confirm', () => {
  it('states the consequence of an escalate in one sentence and writes on confirm', async () => {
    executeAction.mockResolvedValue({
      status: 'executed',
      title: 'Escalate to case',
      detail: 'soc-ai created case 42. The alert is attached to it and marked escalated.',
      error: null,
      count: 1,
    });
    const { onDone } = mount(row());
    fireEvent.click(screen.getByRole('button', { name: 'Escalate to case' }));
    // The first click writes nothing.
    expect(executeAction).not.toHaveBeenCalled();
    expect(screen.getByTestId('waiting-action-confirm').textContent).toContain(
      `Open a Security Onion case for the alert of ${RULE}.`,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Open the case' }));
    await waitFor(() => expect(onDone).toHaveBeenCalledWith('INV-1:0'));
    expect(executeAction).toHaveBeenCalledWith('INV-1', 0, undefined);
    expect(
      await screen.findByText('soc-ai created case 42. The alert is attached to it and marked escalated.'),
    ).toBeTruthy();
  });

  it('counts the alerts of an ack and offers the one-alert ack', async () => {
    getActionScope.mockResolvedValue({
      tool: 'ack_alert',
      scope: 'group',
      count: 9,
      hosts: 2,
      held: 0,
      rangeLabel: 'the last 7 days',
      sentence: 'Acknowledge 9 alerts of this rule from the last 7 days, on 2 hosts.',
    });
    executeAction.mockResolvedValue({
      status: 'executed',
      title: 'Acknowledge alert',
      detail: 'Alert acknowledged in Security Onion.',
      error: null,
      count: 1,
    });
    mount(row({ waitingActions: [ack] }));
    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge' }));
    await waitFor(() =>
      expect(screen.getByTestId('waiting-action-confirm').textContent).toContain(
        `Acknowledge 9 alerts of ${RULE} in Security Onion.`,
      ),
    );
    expect(getActionScope).toHaveBeenCalledWith('INV-1', 1);
    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge this alert only' }));
    await waitFor(() => expect(executeAction).toHaveBeenCalledWith('INV-1', 1, 'alert'));
  });

  it('Cancel writes nothing', () => {
    mount(row());
    fireEvent.click(screen.getByRole('button', { name: 'Escalate to case' }));
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByTestId('waiting-action-confirm')).toBeNull();
    expect(executeAction).not.toHaveBeenCalled();
  });

  it('closes on Escape and returns the focus to the write button', async () => {
    const user = userEvent.setup();
    mount(row());
    const write = screen.getByRole('button', { name: 'Escalate to case' });
    await user.click(write);
    const confirm = screen.getByTestId('waiting-action-confirm');
    // The focus moves into the confirm, onto the button that writes nothing.
    expect(confirm.contains(document.activeElement)).toBe(true);
    expect(document.activeElement?.textContent).toBe('Cancel');
    await user.keyboard('{Escape}');
    expect(screen.queryByTestId('waiting-action-confirm')).toBeNull();
    expect(document.activeElement).toBe(write);
    expect(executeAction).not.toHaveBeenCalled();
  });

  it('keeps the row and states the error when the write fails', async () => {
    executeAction.mockResolvedValue({
      status: 'error',
      title: 'Escalate to case',
      detail: '',
      error: 'Security Onion refused the case.',
      count: null,
    });
    const { onDone } = mount(row());
    fireEvent.click(screen.getByRole('button', { name: 'Escalate to case' }));
    fireEvent.click(screen.getByRole('button', { name: 'Open the case' }));
    expect((await screen.findByRole('alert')).textContent).toBe('Security Onion refused the case.');
    expect(onDone).not.toHaveBeenCalled();
  });

  it('NEGATIVE CONTROL: the demo blocks the write before the request', () => {
    mount(row(), { demo: true });
    fireEvent.click(screen.getByRole('button', { name: 'Escalate to case' }));
    fireEvent.click(screen.getByRole('button', { name: 'Open the case' }));
    expect(executeAction).not.toHaveBeenCalled();
    expect(screen.getByRole('alert').textContent).toBe(
      'The read-only demo blocks this action. A live deployment runs it.',
    );
  });
});

describe('Dismiss', () => {
  it('asks what the card asks, then offers an undo', async () => {
    dismissAction.mockResolvedValue({ dismissed: true, by: 'ana', at: '2026-10-20T10:00:00Z' });
    restoreAction.mockResolvedValue({ dismissed: false, by: 'ana', at: '2026-10-20T10:01:00Z' });
    const { onDone, onRestored } = mount(row());
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
    expect(dismissAction).not.toHaveBeenCalled();
    expect(screen.getByTestId('waiting-action-confirm').textContent).toContain(
      'Dismiss this recommended action. soc-ai records your name and the time. You can undo it.',
    );
    fireEvent.click(screen.getByRole('button', { name: 'Confirm dismiss' }));
    await waitFor(() => expect(onDone).toHaveBeenCalledWith('INV-1:0'));
    expect(dismissAction).toHaveBeenCalledWith('INV-1', 0);
    expect(await screen.findByText(`You dismissed the escalation of ${RULE}.`)).toBeTruthy();
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Undo' }));
    });
    expect(restoreAction).toHaveBeenCalledWith('INV-1', 0);
    await waitFor(() => expect(onRestored).toHaveBeenCalledWith('INV-1:0'));
  });
});

// Verify 2026-10-20, V3-N4. The row called a finding or a lead "The alert
// of ...". The server names the type of the target, and the row says it.
describe('the target', () => {
  it('names a finding, a lead, an alert and a case', () => {
    const finding = { ...escalate, target: 'RC4 ticket for svc_sql', targetType: 'finding' as const };
    expect(actionTargetText(finding, RULE)).toBe('The finding RC4 ticket for svc_sql');
    const lead = { ...escalate, target: 'beacon pair', targetType: 'lead' as const };
    expect(actionTargetText(lead, RULE)).toBe('The lead beacon pair');
    // A lead title that names the lead already reads as it is.
    const named = { ...lead, target: 'Lead 17 on 192.0.2.50' };
    expect(actionTargetText(named, RULE)).toBe('Lead 17 on 192.0.2.50');
    expect(actionTargetText(escalate, RULE)).toBe(`The alert of ${RULE}`);
    expect(actionTargetText(comment, RULE)).toBe('Security Onion case case-7');
  });

  it('NEGATIVE CONTROL: a row of a finding never says "The alert of"', () => {
    mount(
      row({ waitingActions: [{ ...escalate, target: 'RC4 ticket for svc_sql', targetType: 'finding' }] }),
    );
    const line = screen.getByTestId('waiting-action-INV-1-0');
    expect(line.textContent).toContain('The finding RC4 ticket for svc_sql');
    expect(line.textContent).not.toContain('The alert of');
  });
});

// Verify 2026-10-20, V3-N9. Escape closed the confirm only while the focus
// was inside it. The analyst clicked the row, and Escape then did nothing.
describe('Escape on the row', () => {
  it('closes the confirm when the focus left it for the page', async () => {
    mount(row());
    fireEvent.click(screen.getByRole('button', { name: 'Escalate to case' }));
    expect(screen.getByTestId('waiting-action-confirm')).toBeTruthy();
    (document.activeElement as HTMLElement | null)?.blur();
    expect(document.activeElement).toBe(document.body);
    fireEvent.keyDown(document.body, { key: 'Escape' });
    expect(screen.queryByTestId('waiting-action-confirm')).toBeNull();
    expect(executeAction).not.toHaveBeenCalled();
  });

  it('closes the confirm when the focus is on another control of the row', () => {
    mount(row({ waitingActions: [escalate, ack] }));
    fireEvent.click(screen.getByRole('button', { name: 'Escalate to case' }));
    const other = screen.getByRole('button', { name: 'Acknowledge' });
    other.focus();
    fireEvent.keyDown(other, { key: 'Escape' });
    expect(screen.queryByTestId('waiting-action-confirm')).toBeNull();
  });

  it('NEGATIVE CONTROL: Escape on a control outside the row keeps the confirm', () => {
    render(
      <div>
        <button type="button">Outside</button>
      </div>,
    );
    mount(row());
    fireEvent.click(screen.getByRole('button', { name: 'Escalate to case' }));
    const outside = screen.getByRole('button', { name: 'Outside' });
    outside.focus();
    fireEvent.keyDown(outside, { key: 'Escape' });
    expect(screen.getByTestId('waiting-action-confirm')).toBeTruthy();
  });
});

// Verify 2026-10-20, V3-N2. The alert was on two cases, and the confirm said
// it opens a case. The execute route opens no second case. The confirm reads
// the cases from the scope route and names each one.
describe('the escalate confirm on an alert already on a case', () => {
  it('names and links the cases, and says no second case opens', async () => {
    getActionScope.mockResolvedValue({
      tool: 'escalate_to_case',
      scope: 'alert',
      count: 0,
      hosts: null,
      held: 0,
      rangeLabel: '',
      sentence: 'The alert is already on cases case-a, case-b. soc-ai opens no second case.',
      cases: [
        { id: 'case-a', url: 'https://so.example/#/case/case-a' },
        { id: 'case-b', url: null },
      ],
      casesComplete: true,
    });
    mount(row());
    fireEvent.click(screen.getByRole('button', { name: 'Escalate to case' }));
    const confirm = await screen.findByTestId('action-cases');
    expect(getActionScope).toHaveBeenCalledWith('INV-1', 0);
    expect(confirm.textContent).toBe('The alert is already on cases case-a, case-b.');
    expect(screen.getByRole('link', { name: 'case-a' })).toHaveAttribute(
      'href',
      'https://so.example/#/case/case-a',
    );
    expect(screen.getByTestId('waiting-action-confirm').textContent).toContain(
      'soc-ai opens no second case. The press records this action as done.',
    );
    expect(screen.getByRole('button', { name: 'Record as done' })).toBeTruthy();
  });

  it('NEGATIVE CONTROL: no case keeps the sentence that opens one', async () => {
    getActionScope.mockResolvedValue({
      tool: 'escalate_to_case',
      scope: 'alert',
      count: 1,
      hosts: null,
      held: 0,
      rangeLabel: '',
      sentence: 'Open one Security Onion case for this alert.',
      cases: [],
      casesComplete: true,
    });
    mount(row());
    fireEvent.click(screen.getByRole('button', { name: 'Escalate to case' }));
    await waitFor(() => expect(getActionScope).toHaveBeenCalled());
    expect(screen.queryByTestId('action-cases')).toBeNull();
    expect(screen.getByRole('button', { name: 'Open the case' })).toBeTruthy();
  });
});

describe('actionConfirmText', () => {
  it('states each write in one sentence', () => {
    expect(actionConfirmText(escalate, RULE, null, 'idle')).toBe(
      `Open a Security Onion case for the alert of ${RULE}.`,
    );
    const group = {
      tool: 'ack_alert',
      scope: 'group' as const,
      count: 1,
      hosts: 1,
      held: 0,
      rangeLabel: 'the last 7 days',
      sentence: '',
    };
    expect(actionConfirmText(ack, RULE, group, 'idle')).toBe(
      `Acknowledge 1 alert of ${RULE} in Security Onion.`,
    );
    expect(actionConfirmText(ack, RULE, { ...group, scope: 'alert' }, 'idle')).toBe(
      `Acknowledge the alert of ${RULE} in Security Onion.`,
    );
    expect(actionConfirmText(ack, RULE, null, 'loading')).toBe(
      'soc-ai is counting the alerts this ack covers.',
    );
    expect(
      actionConfirmText(
        { ...escalate, type: 'comment', label: 'Add comment', target: 'case-7', targetType: 'case' },
        RULE,
        null,
        'idle',
      ),
    ).toBe('Add a comment to Security Onion case case-7.');
  });
});
