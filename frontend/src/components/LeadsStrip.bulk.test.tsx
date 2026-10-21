// Bulk decisions on the leads list (owner, 2026-10-20). Every lead decision
// was one lead at a time. The Hunts page now selects leads like the Alerts,
// Investigations and Hosts lists select their rows, and one press dismisses,
// hunts or reopens the selection.
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getLeads: vi.fn(),
  getLeadCount: vi.fn(),
  getNeedsYou: vi.fn(),
  bulkDismissLeads: vi.fn(),
  bulkReopenLeads: vi.fn(),
  bulkHuntLeads: vi.fn(),
  bulkDismissLeadsAgain: vi.fn(),
  getLeadBulkHuntPlan: vi.fn(),
}));

import {
  ApiError,
  bulkDismissLeads,
  bulkDismissLeadsAgain,
  bulkHuntLeads,
  bulkReopenLeads,
  getLeadBulkHuntPlan,
  getLeadCount,
  getLeads,
  getNeedsYou,
  type Lead,
} from '../lib/api';
import {
  LEAD_BULK_HUNT_CAP,
  LEAD_UNDO_WINDOW_MS,
  LeadsStrip,
  dismissConfirmText,
  huntConfirmText,
  reopenConfirmText,
} from './LeadsStrip';

const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

let nextId = 1;
const lead = (over: Partial<Lead> = {}): Lead => {
  const id = over.id ?? nextId++;
  return {
    id,
    status: 'open',
    formed_at: iso(2 * HOUR),
    updated_at: `2026-10-20T08:00:${String(id).padStart(2, '0')}Z`,
    entities: [['host', `192.0.2.${id}`]],
    kinds: ['novel_destination', 'off_hours'],
    weight_at_formation: 0.9,
    scope_count: 1,
    hunt_id: null,
    shadow: false,
    single_signal: false,
    observations: [],
    hunt_queued: false,
    ...over,
  };
};

const mount = (path = '/hunts') =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/hunts" element={<LeadsStrip paramBound />} />
      </Routes>
    </MemoryRouter>,
  );

const byTab = (rows: Partial<Record<string, Lead[]>>) => {
  vi.mocked(getLeads).mockImplementation(async (status = 'open') => rows[status] ?? []);
  vi.mocked(getLeadCount).mockImplementation(async (status = 'open') => ({
    status,
    entity: null,
    total: (rows[status] ?? []).length,
  }));
};

const bar = () => screen.getByTestId('leads-bulk-bar');
const confirmBox = () => screen.getByRole('dialog');

beforeEach(() => {
  nextId = 1;
  vi.mocked(getNeedsYou).mockReset().mockRejectedValue(new Error('offline'));
  vi.mocked(getLeads).mockReset();
  vi.mocked(getLeadCount).mockReset();
  vi.mocked(bulkDismissLeads).mockReset();
  vi.mocked(bulkReopenLeads).mockReset();
  vi.mocked(bulkHuntLeads).mockReset();
  vi.mocked(bulkDismissLeadsAgain).mockReset();
  vi.mocked(getLeadBulkHuntPlan)
    .mockReset()
    .mockResolvedValue({
      cap: 3,
      typical_run: { lowMin: 5, highMin: 8, medianMin: 6, samples: 20 },
    });
});

afterEach(() => {
  vi.useRealTimers();
});

describe('the selection on the leads list', () => {
  it('selects one lead, then every lead on the list, then none', async () => {
    const rows = [lead(), lead(), lead()];
    byTab({ needs_decision: rows });
    mount();
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select lead 1' }));
    expect(within(bar()).getByTestId('list-toolbar-selection').textContent).toContain(
      '1 lead selected',
    );
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select the 3 leads on this list' }));
    expect(within(bar()).getByTestId('list-toolbar-selection').textContent).toContain(
      '3 leads selected',
    );
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select the 3 leads on this list' }));
    expect(screen.queryByTestId('leads-bulk-bar')).toBeNull();
  });

  it('holds the bar sticky at the top of the strip while the analyst scrolls', async () => {
    byTab({ needs_decision: [lead(), lead()] });
    mount();
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select lead 2' }));
    expect(bar().className).toContain('sticky');
    expect(bar().className).toContain('top-0');
  });

  it('clears the selection when the tab changes', async () => {
    byTab({ needs_decision: [lead()], closed: [lead({ status: 'dismissed', dismissed_reason: 'lab_host' })] });
    mount();
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select lead 1' }));
    fireEvent.click(screen.getByRole('button', { name: 'Closed' }));
    await screen.findByRole('checkbox', { name: 'Select lead 2' });
    expect(screen.queryByTestId('leads-bulk-bar')).toBeNull();
  });

  it('offers the actions of each tab', async () => {
    byTab({
      needs_decision: [lead()],
      closed: [lead({ status: 'dismissed', dismissed_reason: 'lab_host' })],
      in_progress: [lead({ status: 'hunting', hunt_id: 'h-1', hunt_status: 'running' })],
    });
    mount();
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select lead 1' }));
    expect(within(bar()).getByRole('button', { name: 'Dismiss (1)' })).toBeTruthy();
    expect(within(bar()).getByRole('button', { name: 'Hunt (1)' })).toBeTruthy();
    expect(within(bar()).queryByRole('button', { name: /^Reopen/ })).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Closed' }));
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select lead 2' }));
    expect(within(bar()).getByRole('button', { name: 'Reopen (1)' })).toBeTruthy();
    expect(within(bar()).queryByRole('button', { name: /^Dismiss/ })).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'In progress' }));
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select lead 3' }));
    expect(bar().textContent).toContain('A lead under a running hunt takes no bulk decision.');
  });

  it('has no checkboxes on a host page', async () => {
    vi.mocked(getLeads).mockResolvedValue([lead()]);
    vi.mocked(getLeadCount).mockResolvedValue({ status: 'all', entity: '192.0.2.1', total: 1 });
    render(
      <MemoryRouter>
        <LeadsStrip entityKey="192.0.2.1" status="all" />
      </MemoryRouter>,
    );
    await screen.findByTestId('lead-1');
    expect(screen.queryByRole('checkbox')).toBeNull();
  });
});

describe('the keyboard', () => {
  it('reaches the row checkbox with Tab and toggles it with space', async () => {
    const user = userEvent.setup();
    byTab({ needs_decision: [lead(), lead()] });
    mount();
    const all = await screen.findByRole('checkbox', { name: 'Select the 2 leads on this list' });
    all.focus();
    await user.tab();
    const first = screen.getByRole('checkbox', { name: 'Select lead 1' });
    expect(document.activeElement).toBe(first);
    await user.keyboard(' ');
    expect(first.getAttribute('aria-checked')).toBe('true');
    // The bar is in the tab order too.
    expect(within(bar()).getByRole('button', { name: 'Dismiss (1)' }).tabIndex).toBe(0);
    await user.keyboard(' ');
    expect(first.getAttribute('aria-checked')).toBe('false');
  });
});

describe('the bulk Dismiss', () => {
  const rows = () => [
    lead(),
    lead(),
    lead({ shadow: true }),
    lead({
      status: 'hunting',
      hunt_id: 'h-4',
      hunt_status: 'complete',
      hunt_outcome: 'threats',
      hunt_threat_count: 1,
    }),
  ];

  it('states the count, the skips, the threat, the effect and the Undo window', async () => {
    byTab({ needs_decision: rows() });
    mount();
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select the 4 leads on this list' }));
    fireEvent.click(within(bar()).getByRole('button', { name: 'Dismiss (3)' }));
    const text = confirmBox().textContent ?? '';
    expect(text).toContain('Dismiss 3 leads. Each lead gets the reason and the note below.');
    expect(text).toContain('The press skips 1 shadow lead. Decide on a shadow lead from its own row.');
    // The confirm names the lead whose hunt found the threat (V3 STE).
    expect(text).toContain('An earlier hunt of lead 4 found a threat.');
    expect(text).toContain('The threat finding stays open on the hunt.');
    expect(text).toContain('The observations on these leads and their repeats form no new lead.');
    expect(text).toContain('You can undo the dismissal from the result line for 2 minutes.');
    // No reason is chosen when the confirm opens.
    const go = within(confirmBox()).getByRole('button', { name: 'Dismiss 3 leads' }) as HTMLButtonElement;
    expect(go.disabled).toBe(true);
  });

  it('closes the confirm on Escape and writes nothing', async () => {
    byTab({ needs_decision: rows() });
    mount();
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select lead 1' }));
    fireEvent.click(within(bar()).getByRole('button', { name: 'Dismiss (1)' }));
    expect(screen.getByRole('dialog')).toBeTruthy();
    fireEvent.keyDown(window, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(bulkDismissLeads).not.toHaveBeenCalled();
  });

  it('sends the ids, the count and the change tokens, names each outcome, and Undo reopens', async () => {
    const shown = rows();
    byTab({ needs_decision: shown });
    vi.mocked(bulkDismissLeads).mockResolvedValue({
      action: 'dismiss',
      done: [
        { id: 1, updated_at: '2026-10-20T09:00:01Z' },
        { id: 2, updated_at: '2026-10-20T09:00:02Z' },
      ],
      skipped: [
        { id: 3, reason: 'shadow', hint: 'This is a shadow lead.' },
        { id: 4, reason: 'changed', hint: 'The lead changed after the page loaded.' },
      ],
      failed: [],
    });
    vi.mocked(bulkReopenLeads).mockResolvedValue({
      action: 'reopen',
      done: [{ id: 1 }, { id: 2 }],
      skipped: [],
      failed: [],
    });
    mount();
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select the 4 leads on this list' }));
    fireEvent.click(within(bar()).getByRole('button', { name: 'Dismiss (3)' }));
    fireEvent.change(within(confirmBox()).getByLabelText('Reason'), {
      target: { value: 'benign_repeat' },
    });
    fireEvent.change(within(confirmBox()).getByPlaceholderText('Note, optional'), {
      target: { value: 'patch window' },
    });
    fireEvent.click(within(confirmBox()).getByRole('button', { name: 'Dismiss 3 leads' }));

    await waitFor(() => expect(bulkDismissLeads).toHaveBeenCalledTimes(1));
    const [press, reason, note] = vi.mocked(bulkDismissLeads).mock.calls[0];
    expect(press.ids).toEqual([1, 2, 3, 4]);
    expect(press.expected).toBe(4);
    expect(press.seen).toEqual(
      Object.fromEntries(shown.map((l) => [String(l.id), l.updated_at])),
    );
    expect(reason).toBe('benign_repeat');
    expect(note).toBe('patch window');

    const line = await screen.findByTestId('leads-bulk-result');
    expect(line.textContent).toContain('Dismissed 2 of 4 leads as "A benign repeat".');
    expect(line.textContent).toContain(
      'Skipped 1 shadow lead and 1 lead that changed after the page loaded.',
    );
    // The detail names each lead.
    fireEvent.click(within(line).getByRole('button', { name: 'Show detail' }));
    expect(line.textContent).toContain('Lead 4: The lead changed after the page loaded.');
    // The result line stays in the sticky bar after the selection clears.
    expect(bar().contains(line)).toBe(true);

    fireEvent.click(within(line).getByRole('button', { name: 'Undo (2)' }));
    await waitFor(() => expect(bulkReopenLeads).toHaveBeenCalledTimes(1));
    expect(vi.mocked(bulkReopenLeads).mock.calls[0][0]).toEqual({
      ids: [1, 2],
      expected: 2,
      seen: { '1': '2026-10-20T09:00:01Z', '2': '2026-10-20T09:00:02Z' },
    });
    await waitFor(() =>
      expect(screen.getByTestId('leads-bulk-result').textContent).toContain(
        'Undid the dismissal of 2 leads.',
      ),
    );
    expect(within(screen.getByTestId('leads-bulk-result')).queryByRole('button', { name: /^Undo/ })).toBeNull();
  });

  // Verify 2026-10-20, V3-N8. A failed Undo read "The console got no
  // answer. Read the list again to see what changed." with no word that the
  // Undo failed, and the Undo stayed on offer.
  it('says the undo did not complete, takes Undo away and reads the list again', async () => {
    byTab({ needs_decision: [lead(), lead()] });
    vi.mocked(bulkDismissLeads).mockResolvedValue({
      action: 'dismiss',
      done: [
        { id: 1, updated_at: '2026-10-20T09:00:01Z' },
        { id: 2, updated_at: '2026-10-20T09:00:02Z' },
      ],
      skipped: [],
      failed: [],
    });
    vi.mocked(bulkReopenLeads).mockRejectedValue(new TypeError('Failed to fetch'));
    mount();
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select the 2 leads on this list' }));
    fireEvent.click(within(bar()).getByRole('button', { name: 'Dismiss (2)' }));
    fireEvent.change(within(confirmBox()).getByLabelText('Reason'), { target: { value: 'lab_host' } });
    fireEvent.click(within(confirmBox()).getByRole('button', { name: 'Dismiss 2 leads' }));
    const line = await screen.findByTestId('leads-bulk-result');
    const reads = vi.mocked(getLeads).mock.calls.length;
    fireEvent.click(within(line).getByRole('button', { name: 'Undo (2)' }));
    await waitFor(() =>
      expect(screen.getByTestId('leads-bulk-result').textContent).toContain(
        'The undo did not complete.',
      ),
    );
    const text = screen.getByTestId('leads-bulk-result').textContent ?? '';
    expect(text).toContain('Dismissed 2 leads');
    expect(text).toContain('The list below shows the state of each lead now.');
    expect(within(screen.getByTestId('leads-bulk-result')).queryByRole('button', { name: /^Undo/ })).toBeNull();
    // The list reads the leads again, so it shows the state.
    await waitFor(() => expect(vi.mocked(getLeads).mock.calls.length).toBeGreaterThan(reads));
  });

  it('takes Undo away when the window ends', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    byTab({ needs_decision: [lead()] });
    vi.mocked(bulkDismissLeads).mockResolvedValue({
      action: 'dismiss',
      done: [{ id: 1, updated_at: '2026-10-20T09:00:01Z' }],
      skipped: [],
      failed: [],
    });
    mount();
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select lead 1' }));
    fireEvent.click(within(bar()).getByRole('button', { name: 'Dismiss (1)' }));
    fireEvent.change(within(confirmBox()).getByLabelText('Reason'), { target: { value: 'lab_host' } });
    fireEvent.click(within(confirmBox()).getByRole('button', { name: 'Dismiss 1 lead' }));
    const line = await screen.findByTestId('leads-bulk-result');
    expect(within(line).getByRole('button', { name: 'Undo (1)' })).toBeTruthy();
    act(() => {
      vi.advanceTimersByTime(LEAD_UNDO_WINDOW_MS + 1_000);
    });
    expect(within(screen.getByTestId('leads-bulk-result')).queryByRole('button', { name: /^Undo/ })).toBeNull();
    // The line itself stays until the analyst closes it.
    expect(screen.getByTestId('leads-bulk-result').textContent).toContain('Dismissed 1 lead');
  });

  it('states a changed selection and keeps the leads selected', async () => {
    byTab({ needs_decision: [lead(), lead()] });
    vi.mocked(bulkDismissLeads).mockRejectedValue(
      new ApiError(
        'The confirm named 2 leads. The request names 3. Select the leads again and confirm the new count.',
        409,
        'lead_selection_changed',
      ),
    );
    mount();
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select the 2 leads on this list' }));
    fireEvent.click(within(bar()).getByRole('button', { name: 'Dismiss (2)' }));
    fireEvent.change(within(confirmBox()).getByLabelText('Reason'), { target: { value: 'lab_host' } });
    fireEvent.click(within(confirmBox()).getByRole('button', { name: 'Dismiss 2 leads' }));
    const line = await screen.findByTestId('leads-bulk-result');
    expect(line.textContent).toContain('The confirm named 2 leads.');
    expect(within(bar()).getByTestId('list-toolbar-selection').textContent).toContain(
      '2 leads selected',
    );
  });
});

describe('the bulk Hunt', () => {
  it('states the cap, the count, the measured time, the skips and the missing Undo', async () => {
    const fresh = [lead(), lead(), lead(), lead(), lead()];
    const inFlight = lead({ status: 'hunting', hunt_id: 'h-6', hunt_status: 'running' });
    const hunted = lead({ status: 'hunting', hunt_id: 'h-7', hunt_status: 'complete' });
    byTab({ all: [...fresh, inFlight, hunted] });
    mount('/hunts?leads=all');
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select lead 1' }));
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select lead 6' }));
    for (const id of [2, 3, 4, 5, 7]) {
      fireEvent.click(screen.getByRole('checkbox', { name: `Select lead ${id}` }));
    }
    fireEvent.click(within(bar()).getByRole('button', { name: 'Hunt (6)' }));
    await waitFor(() => expect(confirmBox().textContent).toContain('Hunts on this grid take'));
    const text = confirmBox().textContent ?? '';
    expect(text).toContain(`Start ${LEAD_BULK_HUNT_CAP} hunts on leads 1, 2 and 3.`);
    expect(text).toContain('Each hunt is a model run. One press starts at most 3 hunts.');
    expect(text).toContain(
      'Hunts on this grid take 5 to 8 minutes. The time comes from the last 20 finished hunts.',
    );
    expect(text).toContain('Press Hunt again for the other 3 leads.');
    expect(text).toContain('The press skips 1 lead with a hunt in progress.');
    expect(text).toContain('A hunt start has no Undo. You can cancel a hunt on its page.');

    vi.mocked(bulkHuntLeads).mockResolvedValue({
      action: 'hunt',
      done: [
        { id: 1, hunt_id: 'new-1' },
        { id: 2, hunt_id: 'new-2' },
        { id: 3, hunt_id: 'new-3' },
      ],
      skipped: [
        { id: 6, reason: 'hunt_running', hint: 'A hunt runs on this lead.' },
        { id: 4, reason: 'over_cap', hint: 'One press starts at most 3 hunts.' },
        { id: 5, reason: 'over_cap', hint: 'One press starts at most 3 hunts.' },
        { id: 7, reason: 'over_cap', hint: 'One press starts at most 3 hunts.' },
      ],
      failed: [],
      cap: 3,
    });
    fireEvent.click(within(confirmBox()).getByRole('button', { name: 'Start 3 hunts' }));
    const line = await screen.findByTestId('leads-bulk-result');
    expect(line.textContent).toContain('Started 3 hunts.');
    expect(line.textContent).toContain(
      'Skipped 1 lead with a hunt in progress and 3 leads over the cap of 3.',
    );
    expect(within(line).queryByRole('button', { name: /^Undo/ })).toBeNull();
    fireEvent.click(within(line).getByRole('button', { name: 'Show detail' }));
    expect(within(line).getByRole('link', { name: 'Open the hunt of lead 1' }).getAttribute('href')).toBe(
      '/hunts/new-1',
    );
  });

  it('says so when the store holds too few hunts to state a time', async () => {
    vi.mocked(getLeadBulkHuntPlan).mockResolvedValue({ cap: 3, typical_run: null });
    byTab({ needs_decision: [lead()] });
    mount();
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select lead 1' }));
    fireEvent.click(within(bar()).getByRole('button', { name: 'Hunt (1)' }));
    await waitFor(() =>
      expect(confirmBox().textContent).toContain(
        'soc-ai has too few finished hunts to state a hunt time.',
      ),
    );
    expect(confirmBox().textContent).toContain('Start 1 hunt on lead 1.');
  });
});

describe('the bulk Reopen', () => {
  it('states the Undo and the leads it cannot restore, and Undo dismisses again', async () => {
    const analyst = [
      lead({ status: 'dismissed', dismissed_reason: 'lab_host' }),
      lead({ status: 'dismissed', dismissed_reason: 'known_change' }),
    ];
    const byHunt = lead({ status: 'dismissed', dismissed_reason: 'hunt_clean' });
    const promoted = lead({ status: 'promoted', investigation_id: 'inv-1' });
    byTab({ closed: [...analyst, byHunt, promoted] });
    mount('/hunts?leads=closed');
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select the 4 leads on this list' }));
    fireEvent.click(within(bar()).getByRole('button', { name: 'Reopen (3)' }));
    const text = confirmBox().textContent ?? '';
    expect(text).toContain('Reopen 3 leads. Each lead goes back to Needs decision.');
    expect(text).toContain('The history of each lead keeps the dismissal.');
    expect(text).toContain('The press skips 1 lead closed by an investigation.');
    expect(text).toContain(
      'You can undo the reopen from the result line for 2 minutes. Undo dismisses each lead again with its last reason.',
    );
    expect(text).toContain('Undo leaves open 1 lead that soc-ai closed after a clean hunt.');

    vi.mocked(bulkReopenLeads).mockResolvedValue({
      action: 'reopen',
      done: [
        { id: 1, updated_at: 't1', previous_reason: 'lab_host' },
        { id: 2, updated_at: 't2', previous_reason: 'known_change' },
        { id: 3, updated_at: 't3', previous_reason: 'hunt_clean' },
      ],
      skipped: [{ id: 4, reason: 'promoted', hint: 'An investigation closed this lead.' }],
      failed: [],
    });
    vi.mocked(bulkDismissLeadsAgain).mockResolvedValue({
      action: 'dismiss_again',
      done: [{ id: 1 }, { id: 2 }],
      skipped: [],
      failed: [],
    });
    fireEvent.click(within(confirmBox()).getByRole('button', { name: 'Reopen 3 leads' }));
    const line = await screen.findByTestId('leads-bulk-result');
    expect(line.textContent).toContain('Reopened 3 of 4 leads.');
    fireEvent.click(within(line).getByRole('button', { name: 'Undo (2)' }));
    await waitFor(() => expect(bulkDismissLeadsAgain).toHaveBeenCalledTimes(1));
    expect(vi.mocked(bulkDismissLeadsAgain).mock.calls[0][0]).toEqual({
      ids: [1, 2],
      expected: 2,
      seen: { '1': 't1', '2': 't2' },
    });
    await waitFor(() =>
      expect(screen.getByTestId('leads-bulk-result').textContent).toContain(
        'Undid the reopen of 2 leads. Each lead has its last reason again.',
      ),
    );
  });
});

describe('the words of the confirms', () => {
  it('names where to reopen a lead that an investigation closed', () => {
    const text = reopenConfirmText({
      action: 'reopen',
      act: [lead({ status: 'dismissed' })],
      skip: [{ lead: lead({ status: 'promoted' }), code: 'promoted' }],
    }).join(' ');
    expect(text).toContain('To reopen a lead that an investigation closed, use the row of that lead.');
  });

  it('names each lead whose earlier hunt found a threat', () => {
    const threat = (id: number) =>
      lead({
        id,
        status: 'hunting',
        hunt_id: `h-${id}`,
        hunt_status: 'complete',
        hunt_outcome: 'threats',
        hunt_threat_count: 1,
      });
    expect(
      dismissConfirmText({ action: 'dismiss', act: [threat(8)], skip: [] }).join(' '),
    ).toContain('An earlier hunt of lead 8 found a threat.');
    expect(
      dismissConfirmText({ action: 'dismiss', act: [threat(8), threat(9)], skip: [] }).join(' '),
    ).toContain('Earlier hunts of leads 8 and 9 found a threat.');
  });

  it('starts hunts on the named leads with no comma', () => {
    const plan = { cap: 3, typical_run: null };
    expect(
      huntConfirmText({ action: 'hunt', act: [lead({ id: 21 }), lead({ id: 16 })], skip: [] }, plan)[0],
    ).toBe('Start 2 hunts on leads 21 and 16.');
    expect(huntConfirmText({ action: 'hunt', act: [lead({ id: 21 })], skip: [] }, plan)[0]).toBe(
      'Start 1 hunt on lead 21.',
    );
  });
});
