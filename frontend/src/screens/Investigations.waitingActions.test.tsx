// The pending-action list offers each waiting action on its row (dogfood
// 2026-10-19, R1-I1). After the write or Dismiss the row leaves the list at
// once, the header count follows, and the list asks the server again. An
// undo of a dismissal brings the row back. The plain list offers no control.
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ToastProvider } from '../lib/toast';
import type { InvestigationList, InvestigationRow, WaitingAction } from '../lib/types';

const escalate = (rule: string): WaitingAction => ({
  id: 'a0',
  index: 0,
  type: 'escalate',
  label: 'Escalate to case',
  target: rule,
  targetType: 'alert',
  rationale: 'The beacon matches a known C2 address.',
  executable: true,
  reason: null,
});

const row = (id: string, name: string, over: Partial<InvestigationRow> = {}): InvestigationRow => ({
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
  pendingActions: 1,
  waitingActions: [escalate(name)],
  ...over,
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
const executeAction = vi.hoisted(() => vi.fn());
const dismissAction = vi.hoisted(() => vi.fn());
const restoreAction = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  listInvestigations,
  listSavedViews,
  executeAction,
  dismissAction,
  restoreAction,
}));

import { Investigations } from './Investigations';

const A = row('INV-A', 'ET MALWARE Known C2 Beacon');
const B = row('INV-B', 'ET TROJAN Second Stage Download');

const mount = (url: string) =>
  render(
    <MemoryRouter initialEntries={[url]}>
      <ToastProvider>
        <Investigations />
      </ToastProvider>
    </MemoryRouter>,
  );

beforeEach(() => {
  listInvestigations.mockReset();
  listSavedViews.mockReset();
  listSavedViews.mockResolvedValue([]);
  executeAction.mockReset();
  dismissAction.mockReset();
  restoreAction.mockReset();
});

describe('the waiting actions on the pending-action list', () => {
  it('asks the server for the pending rows and offers the action on each', async () => {
    listInvestigations.mockResolvedValue(list([A, B]));
    mount('/investigations?range=30d&actions=pending');
    await screen.findByTestId('waiting-actions-INV-A');
    expect(listInvestigations.mock.calls[0][0].pendingAction).toBe(true);
    expect(screen.getByTestId('waiting-actions-INV-B')).toBeTruthy();
    expect(screen.getByTestId('investigations-count').textContent).toContain('2 investigations');
  });

  it('takes the row off the list at once after the write, and the count follows', async () => {
    // The first read holds both runs. The read after the write holds one.
    listInvestigations.mockResolvedValueOnce(list([A, B])).mockResolvedValue(list([B]));
    let finish: (v: unknown) => void = () => {};
    executeAction.mockReturnValue(new Promise((resolve) => (finish = resolve)));
    mount('/investigations?range=30d&actions=pending');
    const actions = await screen.findByTestId('waiting-actions-INV-A');
    fireEvent.click(within(actions).getByRole('button', { name: 'Escalate to case' }));
    fireEvent.click(within(actions).getByRole('button', { name: 'Open the case' }));
    const reads = listInvestigations.mock.calls.length;
    await act(async () => {
      finish({
        status: 'executed',
        title: 'Escalate to case',
        detail: 'soc-ai created case 42. The alert is attached to it and marked escalated.',
        error: null,
        count: 1,
      });
    });
    await waitFor(() => expect(screen.queryByTestId('inv-name-INV-A')).toBeNull());
    expect(screen.getByTestId('inv-name-INV-B')).toBeTruthy();
    expect(screen.getByTestId('investigations-count').textContent).toContain('1 investigation ');
    // The list asks the server again. The server decides what still waits.
    await waitFor(() => expect(listInvestigations.mock.calls.length).toBeGreaterThan(reads));
  });

  it('brings the row back when the analyst undoes a dismissal', async () => {
    listInvestigations
      .mockResolvedValueOnce(list([A, B]))
      .mockResolvedValueOnce(list([B]))
      .mockResolvedValue(list([A, B]));
    dismissAction.mockResolvedValue({ dismissed: true, by: 'ana', at: '2026-10-20T10:00:00Z' });
    restoreAction.mockResolvedValue({ dismissed: false, by: 'ana', at: '2026-10-20T10:01:00Z' });
    mount('/investigations?range=30d&actions=pending');
    const actions = await screen.findByTestId('waiting-actions-INV-A');
    fireEvent.click(within(actions).getByRole('button', { name: 'Dismiss' }));
    fireEvent.click(within(actions).getByRole('button', { name: 'Confirm dismiss' }));
    await waitFor(() => expect(screen.queryByTestId('inv-name-INV-A')).toBeNull());
    await act(async () => {
      fireEvent.click(await screen.findByRole('button', { name: 'Undo' }));
    });
    expect(restoreAction).toHaveBeenCalledWith('INV-A', 0);
    expect(await screen.findByTestId('waiting-actions-INV-A')).toBeTruthy();
  });

  it('keeps a row whose other action still waits', async () => {
    const two = row('INV-C', 'ET POLICY Two Actions', {
      pendingActions: 2,
      waitingActions: [
        escalate('ET POLICY Two Actions'),
        { ...escalate('ET POLICY Two Actions'), id: 'a1', index: 1, rationale: 'A second case.' },
      ],
    });
    listInvestigations.mockResolvedValue(list([two]));
    dismissAction.mockResolvedValue({ dismissed: true, by: 'ana', at: '2026-10-20T10:00:00Z' });
    mount('/investigations?range=30d&actions=pending');
    const first = await screen.findByTestId('waiting-action-INV-C-0');
    fireEvent.click(within(first).getByRole('button', { name: 'Dismiss' }));
    fireEvent.click(within(first).getByRole('button', { name: 'Confirm dismiss' }));
    await waitFor(() => expect(screen.queryByTestId('waiting-action-INV-C-0')).toBeNull());
    expect(screen.getByTestId('waiting-action-INV-C-1')).toBeTruthy();
    expect(screen.getByTestId('inv-name-INV-C')).toBeTruthy();
  });

  it('states that no action waits when the last row leaves', async () => {
    listInvestigations.mockResolvedValueOnce(list([A])).mockResolvedValue(list([]));
    dismissAction.mockResolvedValue({ dismissed: true, by: 'ana', at: '2026-10-20T10:00:00Z' });
    mount('/investigations?range=30d&actions=pending');
    const actions = await screen.findByTestId('waiting-actions-INV-A');
    fireEvent.click(within(actions).getByRole('button', { name: 'Dismiss' }));
    fireEvent.click(within(actions).getByRole('button', { name: 'Confirm dismiss' }));
    expect(
      await screen.findByText('No recommended action waits for you in the last 30 days.'),
    ).toBeTruthy();
  });

  it('NEGATIVE CONTROL: the plain list offers no control', async () => {
    // An older server, or a row the server filled by mistake: the plain list
    // carries no actions field, and the screen offers nothing.
    listInvestigations.mockResolvedValue(list([{ ...A, pendingActions: null, waitingActions: null }]));
    mount('/investigations?range=30d');
    await screen.findByTestId('inv-name-INV-A');
    expect(screen.queryByTestId('waiting-actions-INV-A')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Escalate to case' })).toBeNull();
  });
});
