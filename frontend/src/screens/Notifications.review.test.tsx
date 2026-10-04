import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getNotifications: vi.fn().mockResolvedValue([
    { id: 'inv:1', tone: 'accent', title: 'Investigation A running', href: '/investigation/1', when: '2m' },
    { id: 'inv:2', tone: 'warn', title: 'Investigation B needs info', href: '/investigation/2', when: '5m' },
  ]),
}));

import { Notifications } from './Notifications';

function renderNotifications() {
  return render(
    <MemoryRouter>
      <Notifications />
    </MemoryRouter>,
  );
}

describe('Notifications — Clear all', () => {
  beforeEach(() => localStorage.clear());
  afterEach(() => localStorage.clear());

  // A dismissal has no undo and no dismissed view, so Clear all asks once (D8).
  it('asks once, and Cancel keeps every row', async () => {
    renderNotifications();
    await screen.findByText('Investigation A running');
    fireEvent.click(screen.getByRole('button', { name: /clear all/i }));
    expect(screen.getByText(/Dismiss 2 notifications\? You cannot undo this\./)).toBeTruthy();
    expect(localStorage.getItem('soc-ai:dismissed-notifications')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.getByText('Investigation A running')).toBeTruthy();
    expect(screen.getByRole('button', { name: /clear all/i })).toBeTruthy();
  });

  it('dismisses every visible notification after the confirm and shows the empty state', async () => {
    renderNotifications();
    await screen.findByText('Investigation A running');
    expect(screen.queryByText('Investigation B needs info')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: /clear all/i }));
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss all' }));

    await waitFor(() => {
      expect(screen.queryByText('Investigation A running')).toBeNull();
      expect(screen.queryByText('Investigation B needs info')).toBeNull();
    });
    expect(screen.getByText('No active notifications.')).toBeTruthy();
  });

  it('hides Clear all when there is nothing to clear', async () => {
    renderNotifications();
    await screen.findByText('Investigation A running');
    fireEvent.click(screen.getByRole('button', { name: /clear all/i }));
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss all' }));
    await waitFor(() => expect(screen.queryByRole('button', { name: /clear all/i })).toBeNull());
  });
});
