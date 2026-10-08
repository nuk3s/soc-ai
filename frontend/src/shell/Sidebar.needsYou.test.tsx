// The badges on the Alerts, Investigations and Hunts items count what waits on
// the analyst. Each badge is a part of the one needs-you count that the
// Dashboard tile and the bell state, so the badges add up to that number. At
// zero there is no badge: a standing "0" teaches the eye to skip the spot where
// the number will be. A failed read is not a zero.
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
  getNeedsYouCount: vi.fn(),
}));

import { emitNeedsYouChanged, getNeedsYouCount, type NeedsYouCount } from '../lib/api';
import { ShellProvider } from './ShellContext';
import { Sidebar } from './Sidebar';

function count(parts: Partial<NeedsYouCount>): NeedsYouCount {
  const base: NeedsYouCount = {
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
    ...parts,
  };
  const keys = [
    'leads_needing_decision',
    'unread_shadow_hits',
    'untriaged_groups',
    'needs_more_info',
    'pending_actions',
  ] as const;
  base.total = keys.reduce((sum, k) => sum + (base[k] ?? 0), 0);
  return base;
}

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
  vi.mocked(getNeedsYouCount).mockReset();
});

describe('Sidebar needs-you badges', () => {
  it('counts the hunting part on the Hunts item', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue(
      count({ unread_shadow_hits: 2, leads_needing_decision: 2 }),
    );
    mount();
    const badge = await screen.findByTestId('sidebar-needs-you');
    expect(badge.textContent).toBe('4');
    expect(badge.getAttribute('title')).toBe(
      'Unread shadow hits, plus leads that wait on a decision. Open Hunts to read them.',
    );
    expect(screen.getByText('Hunts').closest('a')!.contains(badge)).toBe(true);
  });

  it('counts alert groups with no verdict on the Alerts item, with the window', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue(count({ untriaged_groups: 3 }));
    mount();
    const badge = await screen.findByTestId('sidebar-needs-you-alerts');
    expect(badge.textContent).toBe('3');
    expect(badge.getAttribute('title')).toBe(
      'Alert groups with no verdict in the last 7 days. The count hides acknowledged groups.',
    );
    expect(screen.getByText('Alerts').closest('a')!.contains(badge)).toBe(true);
  });

  it('counts needs-more-info verdicts and pending actions on the Investigations item', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue(count({ needs_more_info: 2, pending_actions: 1 }));
    mount();
    const badge = await screen.findByTestId('sidebar-needs-you-investigations');
    expect(badge.textContent).toBe('3');
    expect(screen.getByText('Investigations').closest('a')!.contains(badge)).toBe(true);
  });

  it('shows no badge at zero', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue(count({}));
    mount();
    await waitFor(() => expect(getNeedsYouCount).toHaveBeenCalled());
    expect(screen.queryByTestId('sidebar-needs-you')).toBeNull();
    expect(screen.queryByTestId('sidebar-needs-you-alerts')).toBeNull();
    expect(screen.queryByTestId('sidebar-needs-you-investigations')).toBeNull();
  });

  // A failed read is not a zero. The badge went away on a 503 and the nav read
  // exactly like a quiet day.
  it('marks a failed read with a question mark, never with nothing', async () => {
    vi.mocked(getNeedsYouCount).mockRejectedValue(new Error('503'));
    mount();
    const badge = await screen.findByTestId('sidebar-needs-you');
    expect(badge.textContent).toBe('?');
    expect(badge.getAttribute('title')).toBe('Could not read what needs you. Open the page to try again.');
    expect(screen.getByTestId('sidebar-needs-you-alerts').textContent).toBe('?');
  });

  // One part unknown: only its badge says so. The grid was down and the other
  // four parts came from the database.
  it('marks only the part the server could not read', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue({
      ...count({ leads_needing_decision: 1 }),
      untriaged_groups: null,
      unknown: ['untriaged_groups'],
    });
    mount();
    expect((await screen.findByTestId('sidebar-needs-you-alerts')).textContent).toBe('?');
    expect(screen.getByTestId('sidebar-needs-you').textContent).toBe('1');
  });

  it('counts again when a hit is read or a lead changes', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue(
      count({ unread_shadow_hits: 2, leads_needing_decision: 2 }),
    );
    mount();
    await screen.findByTestId('sidebar-needs-you');
    vi.mocked(getNeedsYouCount).mockResolvedValue(
      count({ unread_shadow_hits: 1, leads_needing_decision: 2 }),
    );
    emitNeedsYouChanged();
    await waitFor(() => expect(screen.getByTestId('sidebar-needs-you').textContent).toBe('3'));
  });
});
