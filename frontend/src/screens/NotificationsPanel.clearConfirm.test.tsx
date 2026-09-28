// The webhook URL is write-only: the panel only ever shows "Set", and the
// value cannot be read back. "Clear" sits directly beside "Replace", so one
// mis-click deleted the URL on the spot with nothing to undo — notifications
// silently stopped until the operator re-entered it. Every other destructive
// action in the app arms an inline two-step confirm; this panel does the same.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

const getNotifyWebhookMock = vi.hoisted(() => vi.fn());
const clearNotifyWebhookMock = vi.hoisted(() => vi.fn());
const saveNotifyWebhookMock = vi.hoisted(() => vi.fn());
const testNotifyWebhookMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getNotifyWebhook: getNotifyWebhookMock,
  clearNotifyWebhook: clearNotifyWebhookMock,
  saveNotifyWebhook: saveNotifyWebhookMock,
  testNotifyWebhook: testNotifyWebhookMock,
}));

import { NotificationsPanel } from './NotificationsPanel';

afterEach(() => {
  getNotifyWebhookMock.mockReset();
  clearNotifyWebhookMock.mockReset();
  saveNotifyWebhookMock.mockReset();
  testNotifyWebhookMock.mockReset();
});

describe('NotificationsPanel clear confirm', () => {
  it('arms a confirm on the first click instead of clearing the URL', async () => {
    getNotifyWebhookMock.mockResolvedValue({ isSet: true, source: 'db' });
    clearNotifyWebhookMock.mockResolvedValue({ ok: true, isSet: false });
    render(<NotificationsPanel />);

    fireEvent.click(await screen.findByRole('button', { name: 'Clear' }));

    expect(clearNotifyWebhookMock).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Confirm clear' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Clear' })).toBeNull();
  });

  it('clears the URL once the confirm is clicked', async () => {
    getNotifyWebhookMock.mockResolvedValue({ isSet: true, source: 'db' });
    clearNotifyWebhookMock.mockResolvedValue({ ok: true, isSet: false });
    render(<NotificationsPanel />);

    fireEvent.click(await screen.findByRole('button', { name: 'Clear' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm clear' }));

    await waitFor(() => expect(clearNotifyWebhookMock).toHaveBeenCalledTimes(1));
    expect(await screen.findByText('soc-ai cleared the webhook URL.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Confirm clear' })).toBeNull();
  });

  it('disarms on Cancel without touching the URL', async () => {
    getNotifyWebhookMock.mockResolvedValue({ isSet: true, source: 'db' });
    render(<NotificationsPanel />);

    fireEvent.click(await screen.findByRole('button', { name: 'Clear' }));
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(clearNotifyWebhookMock).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: 'Confirm clear' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Clear' })).toBeInTheDocument();
  });

  it('drops the armed confirm when the operator switches to Replace', async () => {
    getNotifyWebhookMock.mockResolvedValue({ isSet: true, source: 'db' });
    render(<NotificationsPanel />);

    fireEvent.click(await screen.findByRole('button', { name: 'Clear' }));
    fireEvent.click(screen.getByRole('button', { name: 'Replace' }));
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(screen.queryByRole('button', { name: 'Confirm clear' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Clear' })).toBeInTheDocument();
    expect(clearNotifyWebhookMock).not.toHaveBeenCalled();
  });
});
