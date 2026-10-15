import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getNotifications: vi.fn().mockResolvedValue([
    { id: 'inv:1', tone: 'accent', title: 'Investigation A running', href: '/investigation/1', when: '2m' },
    { id: 'inv:2', tone: 'warn', title: 'Investigation B needs info', href: '/investigation/2', when: '5m' },
  ]),
  // Nothing waits on the analyst, so Dismiss all has only the two events.
  getNeedsYouCount: vi.fn().mockResolvedValue({
    leads_needing_decision: 0,
    unread_shadow_hits: 0,
    untriaged_groups: 0,
    needs_more_info: 0,
    pending_actions: 0,
    total: 0,
    unknown: [],
    alert_window: '7d',
    verdict_window: '30d',
    alert_floor: false,
  }),
  markAllShadowHitsRead: vi.fn().mockResolvedValue({ read: 0 }),
}));

import { markAllShadowHitsRead } from '../lib/api';
import { Notifications } from './Notifications';

function renderNotifications() {
  return render(
    <MemoryRouter>
      <Notifications />
    </MemoryRouter>,
  );
}

/** The trigger, after the count has landed. */
async function trigger() {
  await screen.findByText('Nothing needs you.');
  return screen.getByRole('button', { name: 'Dismiss all' });
}

// "Clear all" became "Dismiss all" on 2026-10-14. It shares the bell's helper,
// so the two surfaces do one thing under one name.
describe('Notifications: Dismiss all', () => {
  beforeEach(() => localStorage.clear());
  afterEach(() => localStorage.clear());

  // A dismissal has no undo and no dismissed view, so Dismiss all asks once (D8).
  it('asks once, and Cancel keeps every row', async () => {
    renderNotifications();
    await screen.findByText('Investigation A running');
    fireEvent.click(await trigger());
    expect(screen.getByRole('group', { name: 'Confirm dismiss all' }).textContent).toContain('Hide 2 events?');
    expect(localStorage.getItem('soc-ai:dismissed-notifications')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.getByText('Investigation A running')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Dismiss all' })).toBeTruthy();
  });

  it('dismisses every visible notification after the confirm and shows the empty state', async () => {
    renderNotifications();
    await screen.findByText('Investigation A running');
    expect(screen.queryByText('Investigation B needs info')).toBeTruthy();

    fireEvent.click(await trigger());
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss all' }));

    await waitFor(() => {
      expect(screen.queryByText('Investigation A running')).toBeNull();
      expect(screen.queryByText('Investigation B needs info')).toBeNull();
    });
    // The screen reads the list again after a Dismiss all, then shows the
    // empty state.
    expect(await screen.findByText('No active notifications.')).toBeTruthy();
    // No shadow hit was unread, so the server was not asked to read any.
    expect(markAllShadowHitsRead).not.toHaveBeenCalled();
  });

  it('hides Dismiss all when there is nothing to dismiss', async () => {
    renderNotifications();
    await screen.findByText('Investigation A running');
    fireEvent.click(await trigger());
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss all' }));
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Dismiss all' })).toBeNull());
  });
});
