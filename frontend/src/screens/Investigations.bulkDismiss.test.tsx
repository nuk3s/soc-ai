// Bulk Dismiss on the pending-action list (dogfood 2026-10-20). The analyst
// dismissed each waiting action on its own row: two presses and a confirm
// per action. The rows of the list now take a selection, and one Dismiss
// with one confirm dismisses the waiting actions of the selected rows. The
// press states a result per row and offers an Undo.
//
// The negative controls: the first press dismisses nothing, Cancel and
// Escape dismiss nothing, a failed dismissal keeps its row selected, and the
// plain list offers no Dismiss for the selection.
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '../lib/toast';
import type { InvestigationList, InvestigationRow, WaitingAction } from '../lib/types';

const action = (index: number, type: WaitingAction['type'], rule: string): WaitingAction => ({
  id: `a${index}`,
  index,
  type,
  label: type === 'ack' ? 'Acknowledge' : 'Escalate to case',
  target: rule,
  targetType: 'alert',
  rationale: 'The beacon matches a known C2 address.',
  executable: true,
  reason: null,
});

const row = (id: string, name: string, actions: WaitingAction[]): InvestigationRow => ({
  id,
  name,
  kind: 'suricata',
  verdict: 'true_positive',
  conf: 0.8,
  host: '192.0.2.10',
  dst: '198.51.100.7',
  status: 'complete',
  when: '2h',
  ts: new Date(Date.now() - 2 * 3_600_000).toISOString(),
  alertId: `ev-${id}`,
  isPrimary: true,
  fallback: false,
  ranBy: 'scheduler',
  pendingActions: actions.length,
  waitingActions: actions,
});

const list = (rows: InvestigationRow[]): InvestigationList => ({
  rows,
  total: rows.length,
  running: 0,
  truePositives: rows.length,
  totalAll: 40,
  active: false,
  limit: 50,
  offset: 0,
});

const listInvestigations = vi.hoisted(() => vi.fn());
const listSavedViews = vi.hoisted(() => vi.fn());
const dismissAction = vi.hoisted(() => vi.fn());
const restoreAction = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  listInvestigations,
  listSavedViews,
  dismissAction,
  restoreAction,
}));

import { bulkDismissConfirmText, bulkDismissResultText } from '../components/WaitingActionsBulk';
import { Investigations } from './Investigations';

const RULE_A = 'ET MALWARE Known C2 Beacon';
const RULE_B = 'ET TROJAN Second Stage Download';
const A = row('INV-A', RULE_A, [action(0, 'escalate', RULE_A)]);
const B = row('INV-B', RULE_B, [action(0, 'escalate', RULE_B), action(1, 'ack', RULE_B)]);

const mount = (url: string) =>
  render(
    <MemoryRouter initialEntries={[url]}>
      <ToastProvider>
        <Investigations />
      </ToastProvider>
    </MemoryRouter>,
  );

const DISMISSED = { dismissed: true, by: 'ana', at: '2026-10-20T10:00:00Z' };
const RESTORED = { dismissed: false, by: 'ana', at: '2026-10-20T10:01:00Z' };

beforeEach(() => {
  listInvestigations.mockReset();
  listSavedViews.mockReset();
  listSavedViews.mockResolvedValue([]);
  dismissAction.mockReset();
  restoreAction.mockReset();
});

/** Select the rows of the list: the header box is the first checkbox. */
async function selectRows(n: number) {
  await screen.findByTestId('waiting-actions-INV-A');
  const boxes = screen.getAllByRole('checkbox');
  for (let i = 1; i <= n; i += 1) fireEvent.click(boxes[i]);
}

describe('Dismiss for the selection on the pending-action list', () => {
  it('dismisses the waiting actions of the selected rows after one confirm', async () => {
    listInvestigations.mockResolvedValueOnce(list([A, B])).mockResolvedValue(list([]));
    dismissAction.mockResolvedValue(DISMISSED);
    mount('/investigations?range=30d&actions=pending');
    await selectRows(2);
    const strip = screen.getByTestId('list-toolbar-selection');
    fireEvent.click(within(strip).getByRole('button', { name: 'Dismiss actions (3)' }));
    // The first press dismisses nothing. It asks.
    expect(dismissAction).not.toHaveBeenCalled();
    const confirm = screen.getByTestId('bulk-dismiss-confirm');
    expect(confirm.textContent).toContain('Dismiss 3 recommended actions on 2 investigations.');
    // The focus goes to Cancel: Enter then dismisses nothing.
    expect(document.activeElement?.textContent).toBe('Cancel');
    await act(async () => {
      fireEvent.click(within(confirm).getByRole('button', { name: 'Confirm dismiss' }));
    });
    await waitFor(() => expect(dismissAction).toHaveBeenCalledTimes(3));
    expect(dismissAction.mock.calls).toEqual([
      ['INV-A', 0],
      ['INV-B', 0],
      ['INV-B', 1],
    ]);
    const result = await screen.findByTestId('bulk-dismiss-result');
    expect(result.textContent).toContain('Dismissed 3 recommended actions on 2 investigations.');
    // One line per row, with the name of the run.
    expect(within(result).getByTestId('bulk-dismiss-row-INV-A').textContent).toContain(RULE_A);
    expect(within(result).getByTestId('bulk-dismiss-row-INV-B').textContent).toContain(
      'Dismissed 2 actions.',
    );
    // The rows leave the list at once.
    await waitFor(() => expect(screen.queryByTestId('inv-name-INV-A')).toBeNull());
    expect(screen.queryByTestId('inv-name-INV-B')).toBeNull();
  });

  it('undoes the dismissals of the press', async () => {
    listInvestigations
      .mockResolvedValueOnce(list([A, B]))
      .mockResolvedValueOnce(list([]))
      .mockResolvedValue(list([A, B]));
    dismissAction.mockResolvedValue(DISMISSED);
    restoreAction.mockResolvedValue(RESTORED);
    mount('/investigations?range=30d&actions=pending');
    await selectRows(2);
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss actions (3)' }));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Confirm dismiss' }));
    });
    const result = await screen.findByTestId('bulk-dismiss-result');
    await act(async () => {
      fireEvent.click(within(result).getByRole('button', { name: 'Undo' }));
    });
    await waitFor(() => expect(restoreAction).toHaveBeenCalledTimes(3));
    expect(restoreAction.mock.calls).toEqual([
      ['INV-A', 0],
      ['INV-B', 0],
      ['INV-B', 1],
    ]);
    await waitFor(() =>
      expect(screen.getByTestId('bulk-dismiss-result').textContent).toContain(
        'Undid the dismissal of 3 recommended actions.',
      ),
    );
    // An undo is one press. It offers no second Undo.
    expect(within(screen.getByTestId('bulk-dismiss-result')).queryByRole('button', { name: 'Undo' })).toBeNull();
    await screen.findByTestId('inv-name-INV-A');
  });

  it('keeps a row that failed selected and states its error', async () => {
    listInvestigations.mockResolvedValue(list([A, B]));
    dismissAction.mockImplementation((id: string) =>
      id === 'INV-B' ? Promise.reject(new Error('soc-ai did not store the change.')) : Promise.resolve(DISMISSED),
    );
    mount('/investigations?range=30d&actions=pending');
    await selectRows(2);
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss actions (3)' }));
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Confirm dismiss' }));
    });
    const result = await screen.findByTestId('bulk-dismiss-result');
    expect(result.textContent).toContain('Dismissed 1 of 3 recommended actions.');
    expect(result.textContent).toContain('2 failed. Its investigation stays selected. Try it again.');
    expect(within(result).getByTestId('bulk-dismiss-row-INV-B').textContent).toContain(
      'soc-ai did not store the change.',
    );
    // The failed row stays on the list and in the selection.
    expect(screen.getByTestId('inv-name-INV-B')).toBeTruthy();
    expect(screen.getByTestId('list-toolbar-selection').textContent).toContain('1');
  });

  it('NEGATIVE CONTROL: Cancel and Escape dismiss nothing', async () => {
    listInvestigations.mockResolvedValue(list([A, B]));
    mount('/investigations?range=30d&actions=pending');
    await selectRows(1);
    const open = screen.getByRole('button', { name: /^Dismiss actions \(\d\)$/ });
    fireEvent.click(open);
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByTestId('bulk-dismiss-confirm')).toBeNull();
    expect(document.activeElement).toBe(open);
    fireEvent.click(open);
    fireEvent.keyDown(screen.getByTestId('bulk-dismiss-confirm'), { key: 'Escape' });
    expect(screen.queryByTestId('bulk-dismiss-confirm')).toBeNull();
    expect(dismissAction).not.toHaveBeenCalled();
  });

  it('NEGATIVE CONTROL: the plain list offers no Dismiss for the selection', async () => {
    listInvestigations.mockResolvedValue(list([{ ...A, waitingActions: undefined }]));
    mount('/investigations?range=30d');
    await screen.findByTestId('inv-name-INV-A');
    fireEvent.click(screen.getAllByRole('checkbox')[1]);
    const strip = screen.getByTestId('list-toolbar-selection');
    expect(within(strip).queryByRole('button', { name: /Dismiss actions/ })).toBeNull();
  });
});

describe('the words of the press', () => {
  it('states the count, the record and the undo', () => {
    const targets = [
      { runId: 'INV-A', name: RULE_A, actions: [action(0, 'escalate', RULE_A)] },
      { runId: 'INV-B', name: RULE_B, actions: [action(0, 'escalate', RULE_B), action(1, 'ack', RULE_B)] },
    ];
    expect(bulkDismissConfirmText(targets, 0)).toEqual([
      'Dismiss 3 recommended actions on 2 investigations.',
      'Dismiss writes nothing to Security Onion. soc-ai records your name and the time.',
      'You can undo the dismissal from the result line.',
    ]);
    expect(bulkDismissConfirmText(targets.slice(0, 1), 1)).toContain(
      '1 selected investigation is not on this list. The press skips it.',
    );
  });

  it('states a press that dismissed all, and an undo that failed in part', () => {
    expect(
      bulkDismissResultText({
        rows: [{ runId: 'INV-A', name: RULE_A, done: [0], failed: [] }],
        undo: null,
      }),
    ).toBe('Dismissed 1 recommended action on 1 investigation.');
    expect(
      bulkDismissResultText({
        rows: [
          { runId: 'INV-A', name: RULE_A, done: [0], failed: [] },
          { runId: 'INV-B', name: RULE_B, done: [], failed: [{ index: 0, error: 'x' }] },
        ],
        undo: null,
        undoOf: true,
      }),
    ).toBe('Undid the dismissal of 1 of 2 recommended actions. The undo did not complete for 1 action.');
  });
});
