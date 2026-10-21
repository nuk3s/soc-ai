// The webhook section said turn on "Notifications enabled" above and "Pick
// the ... format above". The Settings page shows one section at a time, so
// "above" pointed at a section the operator could not see (dogfood
// 2026-10-19, R5-D18). The text now names the section, and the name is a
// link to it.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

const getNotifyWebhookMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getNotifyWebhook: getNotifyWebhookMock,
  clearNotifyWebhook: vi.fn(),
  saveNotifyWebhook: vi.fn(),
  testNotifyWebhook: vi.fn(),
}));

import { NotificationsPanel } from './NotificationsPanel';

afterEach(() => getNotifyWebhookMock.mockReset());

describe('NotificationsPanel section links', () => {
  it('links the sections it names and says no "above"', async () => {
    getNotifyWebhookMock.mockResolvedValue({ isSet: false, source: 'unset', can_store: true });
    const { container } = render(
      <MemoryRouter>
        <NotificationsPanel />
      </MemoryRouter>,
    );
    await screen.findByRole('button', { name: 'Set' });
    expect(container.textContent).not.toMatch(/\babove\b/);
    const links = within(container)
      .getAllByRole('link')
      .map((a) => [a.textContent, a.getAttribute('href')]);
    expect(links).toContainEqual(['Settings > Notifications', '/config#notifications']);
    expect(links).toContainEqual(['Settings > Egress policy', '/config#egress-policy']);
    expect(container.textContent).toContain(
      'turn on "Notifications enabled" in Settings > Notifications.',
    );
    expect(container.textContent).toContain(
      'Pick the generic JSON, Slack or Matrix format in Settings > Notifications.',
    );
  });
});
