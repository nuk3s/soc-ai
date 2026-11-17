// The bell orders its rows by urgency, and folds the routine ones
// (production review 2026-11-12, ui-core 5).
//
// The first 12 rows were 3 old analytic notices, 3 failed triages and 6 false
// positives, and the true positives were rows 35 to 37. The server now orders
// the rows: a dependency that is down, threats, decisions, failures, notices,
// runs in flight, closures, old notices. It folds the false positive closures into one row with a count
// and a link. The bell keeps the server order, and the fold row opens the list.
import { act, render, screen, within } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getWorkspaces: vi.fn(),
  getNotifications: vi.fn(),
  getHealth: vi.fn(),
  getNeedsYouCount: vi.fn(),
}));

import { getHealth, getNeedsYouCount, getNotifications, getWorkspaces } from '../lib/api';
import { describeNotifications, notificationKind } from '../lib/notifications';
import type { Notification } from '../lib/types';
import { Notifications } from '../screens/Notifications';
import { ShellProvider } from './ShellContext';
import { Topbar } from './Topbar';

const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString();

/** The server answer, already in the order of urgency. */
const ANSWER: Notification[] = [
  {
    id: 'inv-done:TP',
    tone: 'danger',
    title: 'Verdict true_positive: ET EXPLOIT Apache path traversal',
    when: '6h',
    href: '/investigation/TP',
    at: minutesAgo(360),
  },
  {
    id: 'inv-failed:DEAD-2',
    tone: 'danger',
    title: 'Triage failed, no verdict: ET TEST dead. 2 investigations failed the same way.',
    when: '2h',
    href: '/investigation/DEAD-2',
    at: minutesAgo(120),
  },
  {
    id: 'inv-fp:FP-1',
    tone: 'accent',
    title: '58 false positives closed in the last 24 hours',
    when: '5m',
    href: '/investigations?range=24h&verdict=false_positive',
    at: minutesAgo(5),
  },
  {
    id: 'analytic-held:3',
    tone: 'warn',
    title: 'soc-ai moved the analytic "Quiet spec" to shadow.',
    when: '25d',
    href: '/hunts?tab=analytics',
    group: 'hunting',
    at: minutesAgo(25 * 24 * 60),
  },
];

function Where() {
  const location = useLocation();
  return <div data-testid="where">{location.pathname + location.search}</div>;
}

const mount = async () => {
  render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <ShellProvider>
        <Topbar />
        <Where />
      </ShellProvider>
    </MemoryRouter>,
  );
  await act(async () => {
    await Promise.resolve();
  });
  act(() => screen.getByRole('button', { name: /^Notifications/ }).click());
};

const panel = () => screen.getByRole('dialog', { name: 'Notifications' });

beforeEach(() => {
  localStorage.clear();
  vi.mocked(getWorkspaces).mockResolvedValue([]);
  vi.mocked(getHealth).mockResolvedValue({
    es: { ok: true, detail: 'ok' },
    llm: { ok: true, detail: 'ok' },
  } as never);
  vi.mocked(getNeedsYouCount).mockResolvedValue({
    leads_needing_decision: 0,
    unread_shadow_hits: 0,
    untriaged_groups: 0,
    needs_more_info: 0,
    pending_actions: 0,
    decisions: 0,
    review: 0,
    total: 0,
    unknown: [],
    alert_window: '7d',
    verdict_window: '30d',
    alert_floor: false,
  });
  vi.mocked(getNotifications).mockResolvedValue(ANSWER);
});

afterEach(() => localStorage.clear());

describe('the bell in the order of urgency', () => {
  it('keeps the server order, so the true positive leads', async () => {
    await mount();
    const titles = await within(panel()).findAllByTestId('bell-title');
    expect(titles.map((t) => t.textContent)).toEqual([
      'True positive: ET EXPLOIT Apache path traversal',
      'Triage failed, no verdict: ET TEST dead. 2 investigations failed the same way.',
      '58 false positives closed in the last 24 hours',
      'soc-ai moved the analytic "Quiet spec" to shadow.',
    ]);
  });

  it('puts a dependency that is down above the true positive when the server does', async () => {
    vi.mocked(getNotifications).mockResolvedValue([
      {
        id: 'dep-down:llm:20261113090000',
        tone: 'danger',
        title: 'The model gateway does not answer. soc-ai cannot run an investigation until it answers.',
        when: '2h',
        href: null,
        at: minutesAgo(120),
      },
      ...ANSWER,
    ]);
    await mount();
    const titles = await within(panel()).findAllByTestId('bell-title');
    expect(titles.map((t) => t.textContent)).toEqual([
      'The model gateway does not answer. soc-ai cannot run an investigation until it answers.',
      'True positive: ET EXPLOIT Apache path traversal',
      'Triage failed, no verdict: ET TEST dead. 2 investigations failed the same way.',
      '58 false positives closed in the last 24 hours',
      'soc-ai moved the analytic "Quiet spec" to shadow.',
    ]);
  });

  it('opens the list of false positives from the fold row', async () => {
    await mount();
    const fold = await within(panel()).findByText('58 false positives closed in the last 24 hours');
    act(() => fold.click());
    expect(screen.getByTestId('where').textContent).toBe(
      '/investigations?range=24h&verdict=false_positive',
    );
  });
});

describe('the fold row on the Notifications screen', () => {
  it('puts the group of the most urgent row first', async () => {
    render(
      <MemoryRouter>
        <Notifications />
      </MemoryRouter>,
    );
    await screen.findByText(/Apache path traversal/);
    const headings = screen.getAllByTestId('notification-group').map((h) => h.textContent);
    expect(headings).toEqual(['Investigations', 'Hunting']);
  });

  // NEGATIVE CONTROL. With a system row first, System leads as before.
  it('keeps System first when the server puts a system row first', async () => {
    vi.mocked(getNotifications).mockResolvedValue([
      { id: 'dep-down:es:1', tone: 'danger', title: 'The grid does not answer.', when: '3m', href: null, at: minutesAgo(3) },
      ...ANSWER,
    ]);
    render(
      <MemoryRouter>
        <Notifications />
      </MemoryRouter>,
    );
    await screen.findByText(/Apache path traversal/);
    const headings = screen.getAllByTestId('notification-group').map((h) => h.textContent);
    expect(headings).toEqual(['System', 'Investigations', 'Hunting']);
  });

  it('files the fold under Investigations and names it in the header', () => {
    expect(notificationKind({ id: 'inv-fp:FP-1' })).toBe('investigation');
    expect(describeNotifications([{ id: 'inv-fp:FP-1' }, { id: 'inv-done:TP' }], false)).toBe(
      '2 notifications: 1 false positive summary and 1 completed investigation. Finished investigations and hunts cover the last 24 h.',
    );
  });
});
