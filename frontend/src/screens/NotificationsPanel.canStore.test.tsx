// Fleet dogfood 2026-10-01 (RC8): the webhook Save answered 400
// no_config_secret_key after the operator typed the URL. GET now says whether a
// save can store the URL, and the panel disables Set with the hint first.
import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

const getNotifyWebhookMock = vi.hoisted(() => vi.fn());
const saveNotifyWebhookMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getNotifyWebhook: getNotifyWebhookMock,
  clearNotifyWebhook: vi.fn(),
  saveNotifyWebhook: saveNotifyWebhookMock,
  testNotifyWebhook: vi.fn(),
}));

import { NotificationsPanel } from './NotificationsPanel';

afterEach(() => {
  getNotifyWebhookMock.mockReset();
  saveNotifyWebhookMock.mockReset();
});

const HINT =
  'Set CONFIG_SECRET_KEY on the server and restart soc-ai. soc-ai then stores the webhook URL encrypted.';

describe('NotificationsPanel store hint', () => {
  it('disables Set and shows the hint when the server cannot store the URL', async () => {
    getNotifyWebhookMock.mockResolvedValue({
      isSet: false,
      source: 'unset',
      can_store: false,
      store_hint: HINT,
    });
    render(<NotificationsPanel />);

    expect(await screen.findByTestId('webhook-store-hint')).toHaveTextContent(HINT);
    expect(screen.getByRole('button', { name: 'Set' })).toBeDisabled();
  });

  it('keeps Set enabled when the server can store the URL', async () => {
    // The control: a server that can store, or one older than the field.
    getNotifyWebhookMock.mockResolvedValue({ isSet: false, source: 'unset' });
    render(<NotificationsPanel />);

    expect(await screen.findByRole('button', { name: 'Set' })).toBeEnabled();
    expect(screen.queryByTestId('webhook-store-hint')).toBeNull();
  });

  it('does not claim the webhook is the one egress path', async () => {
    getNotifyWebhookMock.mockResolvedValue({ isSet: false, source: 'unset', can_store: true });
    render(<NotificationsPanel />);
    await screen.findByRole('button', { name: 'Set' });
    expect(screen.queryByText(/the one outbound egress path/)).toBeNull();
    expect(screen.getByText(/one of the outbound egress paths/)).toBeInTheDocument();
  });

  it('drops an old error line on Cancel', async () => {
    getNotifyWebhookMock.mockResolvedValue({ isSet: false, source: 'unset', can_store: true });
    saveNotifyWebhookMock.mockRejectedValue(new Error('The save failed.'));
    render(<NotificationsPanel />);
    fireEvent.click(await screen.findByRole('button', { name: 'Set' }));
    fireEvent.change(screen.getByPlaceholderText(/hooks.example.com/), {
      target: { value: 'https://hooks.example.test/x' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('The save failed.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByText('The save failed.')).toBeNull();
  });
});
