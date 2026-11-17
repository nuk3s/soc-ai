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

// Production review 2026-11-12 (ui-core 4 and 7): the Hunts badge said 241
// for 233 unread hits and 8 leads, and the Investigations badge said 39 over a
// list of 64 other rows. Each badge now counts decisions and is a link to the
// list it counts. The hits have a grey badge of their own.
describe('Sidebar needs-you badges', () => {
  it('counts the leads on the Hunts item, and the hits on a grey badge', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue(
      count({ unread_shadow_hits: 236, leads_needing_decision: 1 }),
    );
    mount();
    const badge = await screen.findByTestId('sidebar-needs-you');
    expect(badge.textContent).toBe('1');
    expect(badge.getAttribute('title')).toBe(
      'Leads that wait on a decision. Select the badge to open them.',
    );
    expect(badge.getAttribute('href')).toBe('/hunts?leads=needs_decision#leads');
    expect(badge.getAttribute('style')).toContain('#d29922');
    const hits = screen.getByTestId('sidebar-review-hits');
    expect(hits.textContent).toBe('236');
    expect(hits.getAttribute('href')).toBe('/hunts?hits=unread#analytic-hits');
    expect(hits.getAttribute('aria-label')).toBe('236 shadow hits to review in Hunts');
    // NEGATIVE CONTROL. The review badge never takes the decision color.
    expect(hits.getAttribute('style')).not.toContain('#d29922');
    expect(hits.getAttribute('style')).toContain('#8b949e');
    // The badges sit beside the nav link. A link in a link is no link.
    expect(screen.getByText('Hunts').closest('a')!.contains(badge)).toBe(false);
  });

  it('shows the hits badge alone when no lead waits', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue(count({ unread_shadow_hits: 236 }));
    mount();
    expect((await screen.findByTestId('sidebar-review-hits')).textContent).toBe('236');
    expect(screen.queryByTestId('sidebar-needs-you')).toBeNull();
  });

  it('counts alert groups with no verdict on the Alerts item, with the window', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue(count({ untriaged_groups: 3 }));
    mount();
    const badge = await screen.findByTestId('sidebar-needs-you-alerts');
    expect(badge.textContent).toBe('3');
    expect(badge.getAttribute('title')).toBe(
      'Alert groups with no verdict in the last 7 days. The count hides acknowledged groups.',
    );
    expect(badge.getAttribute('href')).toBe('/alerts?range=7d&verdict=untriaged');
  });

  it('counts the runs of the Needs you view on the Investigations item, and opens it', async () => {
    // Two runs: one needs more info, one holds two actions.
    vi.mocked(getNeedsYouCount).mockResolvedValue({
      ...count({ needs_more_info: 1, pending_actions: 2 }),
      investigations_waiting: 2,
    });
    mount();
    const badge = await screen.findByTestId('sidebar-needs-you-investigations');
    expect(badge.textContent).toBe('2');
    expect(badge.getAttribute('href')).toBe('/investigations?view=needs_you&range=30d');
  });

  it('sums the two parts on an older server that sends no run count', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue(count({ needs_more_info: 2, pending_actions: 1 }));
    mount();
    expect((await screen.findByTestId('sidebar-needs-you-investigations')).textContent).toBe('3');
  });

  it('counts the campaigns with no decision on the Campaigns item, and opens them', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue({ ...count({}), campaigns: 2, decisions: 2 });
    mount();
    const badge = await screen.findByTestId('sidebar-needs-you-campaigns');
    expect(badge.textContent).toBe('2');
    expect(badge.getAttribute('href')).toBe('/campaigns?decision=waits');
    expect(badge.getAttribute('title')).toBe(
      'Campaigns that wait on your decision, at any age. Select the badge to open them.',
    );
    expect(badge.getAttribute('style')).toContain('#d29922');
    expect(screen.getByText('Campaigns').closest('a')!.contains(badge)).toBe(false);
  });

  it('shows no Campaigns badge for an older server, and an unknown mark for a failed part', async () => {
    // NEGATIVE CONTROL. An older server sends no part: no badge, never "?".
    vi.mocked(getNeedsYouCount).mockResolvedValue(count({ leads_needing_decision: 1 }));
    const { unmount } = mount();
    await screen.findByTestId('sidebar-needs-you');
    expect(screen.queryByTestId('sidebar-needs-you-campaigns')).toBeNull();
    unmount();
    vi.mocked(getNeedsYouCount).mockResolvedValue({ ...count({}), campaigns: null, unknown: ['campaigns'] });
    mount();
    expect((await screen.findByTestId('sidebar-needs-you-campaigns')).textContent).toBe('?');
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
      count({ unread_shadow_hits: 1, leads_needing_decision: 3 }),
    );
    emitNeedsYouChanged();
    await waitFor(() => expect(screen.getByTestId('sidebar-needs-you').textContent).toBe('3'));
    expect(screen.getByTestId('sidebar-review-hits').textContent).toBe('1');
  });
});

// Dogfood 2026-10-19 R1-D17. The collapsed rail hid every badge, so a rail
// with 34 things waiting read like a quiet day.
describe('Sidebar needs-you badges on the collapsed rail', () => {
  it('keeps a compact count on the icon and names it on the link', async () => {
    localStorage.setItem('soc-ai:navCollapsed', '1');
    vi.mocked(getNeedsYouCount).mockResolvedValue(count({ untriaged_groups: 5, leads_needing_decision: 140 }));
    mount();
    const alerts = await screen.findByTestId('sidebar-needs-you-alerts');
    expect(alerts.textContent).toBe('5');
    expect(screen.getByRole('link', { name: 'Alerts, 5 need you' })).toBeTruthy();
    expect(alerts.getAttribute('aria-label')).toBe('5 need you in Alerts');
    const hunts = screen.getByTestId('sidebar-needs-you');
    expect(hunts.textContent).toBe('99+');
    expect(screen.getByRole('link', { name: 'Hunts, 140 need you' })).toBeTruthy();
    // A zero part shows nothing on the rail either.
    expect(screen.queryByTestId('sidebar-needs-you-investigations')).toBeNull();
  });

  it('shows the decision badge on the rail and names the hits on the link', async () => {
    localStorage.setItem('soc-ai:navCollapsed', '1');
    vi.mocked(getNeedsYouCount).mockResolvedValue(count({ leads_needing_decision: 1, unread_shadow_hits: 236 }));
    mount();
    expect((await screen.findByTestId('sidebar-needs-you')).textContent).toBe('1');
    expect(screen.queryByTestId('sidebar-review-hits')).toBeNull();
    expect(
      screen.getByRole('link', { name: 'Hunts, 1 needs you, 236 shadow hits to review' }),
    ).toBeTruthy();
  });

  it('marks an unknown part on the collapsed rail', async () => {
    localStorage.setItem('soc-ai:navCollapsed', '1');
    vi.mocked(getNeedsYouCount).mockResolvedValue(count({ untriaged_groups: null, unknown: ['untriaged_groups'] }));
    mount();
    const alerts = await screen.findByTestId('sidebar-needs-you-alerts');
    expect(alerts.textContent).toBe('?');
    expect(screen.getByRole('link', { name: 'Alerts, could not count what needs you' })).toBeTruthy();
  });
});
