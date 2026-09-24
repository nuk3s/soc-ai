// The badge on the Hunts item counts what waits on the analyst: the unread
// shadow hits plus the leads that wait on a decision. It is the same number the
// Needs-you strip states at the top of the page, so the nav and the page cannot
// disagree. At zero there is no badge: a standing "0" teaches the eye to skip
// the spot where the number will be. A failed read is not a zero.
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getMe: vi.fn(() => Promise.resolve({ username: 'analyst', role: 'analyst', status: '' })),
  getAbout: vi.fn(() =>
    Promise.resolve({
      version: '1.5.1',
      repo_url: 'https://github.com/nuk3s/soc-ai',
      license: 'Apache-2.0',
      update_check_enabled: false,
    }),
  ),
  getNeedsYou: vi.fn(),
}));

import { emitNeedsYouChanged, getNeedsYou } from '../lib/api';
import { ShellProvider } from './ShellContext';
import { Sidebar } from './Sidebar';

function mount() {
  return render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <ShellProvider>
        <Sidebar />
      </ShellProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  localStorage.clear();
  vi.mocked(getNeedsYou).mockReset();
});

describe('Sidebar needs-you badge', () => {
  it('counts what waits on the analyst on the Hunts item', async () => {
    vi.mocked(getNeedsYou).mockResolvedValue({
      unread_shadow_hits: 2,
      leads_needing_decision: 2,
      total: 4,
    });
    mount();
    const badge = await screen.findByTestId('sidebar-needs-you');
    expect(badge.textContent).toBe('4');
    expect(badge.getAttribute('title')).toBe(
      'Unread shadow hits, plus leads that wait on a decision. Open Hunts to read them.',
    );
    expect(screen.getByText('Hunts').closest('a')!.contains(badge)).toBe(true);
  });

  it('shows no badge at zero', async () => {
    vi.mocked(getNeedsYou).mockResolvedValue({
      unread_shadow_hits: 0,
      leads_needing_decision: 0,
      total: 0,
    });
    mount();
    await waitFor(() => expect(getNeedsYou).toHaveBeenCalled());
    expect(screen.queryByTestId('sidebar-needs-you')).toBeNull();
  });

  // A failed read is not a zero. The badge went away on a 503 and the nav read
  // exactly like a quiet day.
  it('marks a failed read with a question mark, never with nothing', async () => {
    vi.mocked(getNeedsYou).mockRejectedValue(new Error('503'));
    mount();
    const badge = await screen.findByTestId('sidebar-needs-you');
    expect(badge.textContent).toBe('?');
    expect(badge.getAttribute('title')).toBe(
      'Could not read what needs you. Open Hunts to try again.',
    );
  });

  it('counts again when a hit is read or a lead changes', async () => {
    vi.mocked(getNeedsYou).mockResolvedValue({
      unread_shadow_hits: 2,
      leads_needing_decision: 2,
      total: 4,
    });
    mount();
    await screen.findByTestId('sidebar-needs-you');
    vi.mocked(getNeedsYou).mockResolvedValue({
      unread_shadow_hits: 1,
      leads_needing_decision: 2,
      total: 3,
    });
    emitNeedsYouChanged();
    await waitFor(() => expect(screen.getByTestId('sidebar-needs-you').textContent).toBe('3'));
  });
});
