// The Notifications page tour points at real elements (tours/content.ts).
//
// The page renders with two notifications and a Needs-you count. Dismiss all
// then shows its button, and every anchor the tour names must be on the page,
// so a renamed or removed `data-tour` attribute fails here.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getNotifications: vi.fn().mockResolvedValue([
    {
      id: 'inv-done:INV-1',
      tone: 'danger',
      title: 'Verdict true_positive: ET MALWARE Example beacon from 192.0.2.10',
      when: '9m',
      href: '/investigation/INV-1',
    },
    {
      id: 'hunt-done:HUNT-1',
      tone: 'accent',
      title: 'Hunt finished: beaconing from 198.51.100.0/24',
      when: '20m',
      href: '/hunts/HUNT-1',
    },
  ]),
  getNeedsYouCount: vi.fn().mockResolvedValue({
    leads_needing_decision: 2,
    unread_shadow_hits: 1,
    untriaged_groups: 0,
    needs_more_info: 0,
    pending_actions: 0,
    total: 3,
    unknown: [],
    alert_window: '7d',
    verdict_window: '30d',
    alert_floor: false,
  }),
}));

import { NOTIFICATIONS_TOUR } from '../tours/content';
import { missingAnchors } from '../tours/testing';
import { Notifications } from './Notifications';

afterEach(() => localStorage.clear());

describe('the Notifications page tour', () => {
  it('finds every anchor it names', async () => {
    localStorage.clear();
    render(
      <MemoryRouter initialEntries={['/notifications']}>
        <Notifications />
      </MemoryRouter>,
    );
    expect(await screen.findAllByTestId('notification-row')).toHaveLength(2);
    await screen.findByTestId('needs-you-part-leads_needing_decision');
    await screen.findByRole('button', { name: 'Dismiss all' });

    expect(missingAnchors(NOTIFICATIONS_TOUR)).toEqual([]);
  });
});
