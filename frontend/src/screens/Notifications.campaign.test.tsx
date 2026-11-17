// The bell and the Notifications screen state one row for each change of a
// campaign: formed, a new stage, a new machine, a reopen. The row is a
// campaign row, it sits beside the true positives in the danger tone, and it
// opens the campaign page.
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getNotifications: vi.fn(),
  getWorkspaces: vi.fn().mockResolvedValue([]),
  getHealth: vi.fn().mockResolvedValue({ es: { ok: true, detail: 'ok' }, llm: { ok: true, detail: 'ok' } }),
  getNeedsYouCount: vi.fn().mockRejectedValue(new Error('not in this test')),
}));

import { getNotifications } from '../lib/api';
import { NOTIFICATION_KINDS, describeNotifications, isCampaignRow, notificationKind } from '../lib/notifications';
import type { Notification } from '../lib/types';
import { stageColor } from '../lib/campaignViz';
import { forbiddenWords } from '../test/analystWords';
import { ShellProvider } from '../shell/ShellContext';
import { Topbar } from '../shell/Topbar';
import { Notifications } from './Notifications';

const CAMPAIGN_ROW: Notification = {
  id: 'campaign:12',
  tone: 'danger',
  title: 'The campaign actor-a against web-1 reached the stage Action on the target.',
  when: '5m',
  href: '/campaigns/7',
  stage: 'action',
};

/** The color of the stage "Action on the target" on the campaign page. */
const ACTION_COLOR = stageColor('action');
const TP_ROW: Notification = {
  id: 'inv-done:I9',
  tone: 'danger',
  title: 'Verdict true_positive: ET SCAN Nmap',
  when: '1h',
  href: '/investigation/I9',
};

beforeEach(() => {
  localStorage.clear();
  vi.mocked(getNotifications).mockResolvedValue([CAMPAIGN_ROW, TP_ROW]);
});

describe('campaign rows of the notifications', () => {
  it('are campaign rows with their own type and noun', () => {
    expect(notificationKind(CAMPAIGN_ROW)).toBe('campaign');
    expect(isCampaignRow(CAMPAIGN_ROW)).toBe(true);
    // NEGATIVE CONTROL. A true positive row stays an investigation row.
    expect(notificationKind(TP_ROW)).toBe('investigation');
    expect(isCampaignRow(TP_ROW)).toBe(false);
    expect(NOTIFICATION_KINDS.map((k) => k.id)).toEqual(['system', 'host', 'campaign', 'investigation', 'hunting']);
    expect(NOTIFICATION_KINDS.find((k) => k.id === 'campaign')?.label).toBe('Campaigns');
    expect(describeNotifications([CAMPAIGN_ROW, { ...CAMPAIGN_ROW, id: 'campaign:13' }], false)).toBe(
      '2 notifications: 2 campaign changes.',
    );
  });

  it('render on the Notifications screen with the campaign mark, a link to the campaign and a group', async () => {
    render(
      <MemoryRouter>
        <Notifications />
      </MemoryRouter>,
    );
    const link = await screen.findByRole('link', { name: CAMPAIGN_ROW.title });
    expect(link.getAttribute('href')).toBe('/campaigns/7');
    const row = link.closest('[data-testid="notification-row"]') as HTMLElement;
    expect(within(row).getByTestId('notification-campaign')).toHaveTextContent('Campaign');
    expect(within(row).getByTestId('notification-tone').getAttribute('title')).toMatch(/urgent/i);
    expect(screen.getAllByTestId('notification-group').map((g) => g.textContent)).toContain('Campaigns');
    // NEGATIVE CONTROL. The true positive row wears no campaign mark.
    const tp = screen.getByRole('link', { name: /ET SCAN Nmap/ }).closest('[data-testid="notification-row"]') as HTMLElement;
    expect(within(tp).queryByTestId('notification-campaign')).toBeNull();
    expect(forbiddenWords(row)).toEqual([]);
  });

  it('render in the bell with the campaign mark and open the campaign', async () => {
    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <ShellProvider>
          <Topbar />
          <Routes>
            <Route path="/campaigns/:id" element={<div data-testid="campaign-page" />} />
            <Route path="*" element={null} />
          </Routes>
        </ShellProvider>
      </MemoryRouter>,
    );
    const bell = await screen.findByRole('button', { name: /^Notifications/ });
    await act(async () => {
      await Promise.resolve();
    });
    act(() => bell.click());
    const title = await screen.findByText(CAMPAIGN_ROW.title);
    const row = title.closest('[class*="border-b"]') as HTMLElement;
    const mark = within(row).getByTestId('notification-campaign');
    expect(mark).toHaveTextContent('Campaign');
    // The mark wears the color of the stage that the server sends.
    expect(mark).toHaveAttribute('data-stage', 'action');
    expect(mark.style.borderColor).toBe(ACTION_COLOR);
    fireEvent.click(title);
    expect(await screen.findByTestId('campaign-page')).toBeInTheDocument();
  });

  it('wear the color of the stage of the campaign on the Notifications screen', async () => {
    vi.mocked(getNotifications).mockResolvedValue([
      CAMPAIGN_ROW,
      { ...CAMPAIGN_ROW, id: 'campaign:13', title: 'The campaign scanner-2 against db-1 formed.', stage: null },
      { ...CAMPAIGN_ROW, id: 'campaign:14', title: 'The campaign web-1 against db-1 opened again.', stage: undefined },
    ]);
    render(
      <MemoryRouter>
        <Notifications />
      </MemoryRouter>,
    );
    await screen.findByRole('link', { name: CAMPAIGN_ROW.title });
    const [action, none, older] = screen.getAllByTestId('notification-campaign');
    expect(action).toHaveAttribute('data-stage', 'action');
    expect(action.style.borderColor).toBe(ACTION_COLOR);
    expect(action.getAttribute('title')).toBe('Stage reached: Action on the target');
    // A campaign with no proven stage wears the color of no stage.
    expect(none).toHaveAttribute('data-stage', 'none');
    expect(none.getAttribute('title')).toBe('No proven stage');
    // NEGATIVE CONTROL. An older server sends no stage: the mark stays neutral.
    expect(older.hasAttribute('data-stage')).toBe(false);
    expect(older.style.borderColor).toBe('');
  });

  it('state a row beyond the authorization as urgent and a stage under the authorization as informational', async () => {
    // The server sends one danger row for each investigation beyond the
    // authorization, and a neutral row for a higher stage between listed
    // machines while the authorization is in force.
    vi.mocked(getNotifications).mockResolvedValue([
      {
        ...CAMPAIGN_ROW,
        id: 'campaign:21',
        title: 'An investigation of the campaign actor-a against web-1 is beyond the authorization Red team test.',
      },
      { ...CAMPAIGN_ROW, id: 'campaign:22', tone: 'accent', title: 'The campaign actor-a against web-1 reached the stage Access.' },
    ]);
    render(
      <MemoryRouter>
        <Notifications />
      </MemoryRouter>,
    );
    const beyond = (await screen.findByRole('link', { name: /beyond the authorization/ })).closest(
      '[data-testid="notification-row"]',
    ) as HTMLElement;
    const stage = screen.getByRole('link', { name: /reached the stage Access/ }).closest(
      '[data-testid="notification-row"]',
    ) as HTMLElement;
    expect(within(beyond).getByTestId('notification-tone').getAttribute('title')).toMatch(/urgent/i);
    // NEGATIVE CONTROL: the neutral row is no alarm.
    expect(within(stage).getByTestId('notification-tone').getAttribute('title')).not.toMatch(/urgent/i);
    expect(notificationKind({ id: 'campaign:21' })).toBe('campaign');
    expect(forbiddenWords(beyond)).toEqual([]);
  });
});
