// A stored provider key is write-only: the panel only ever shows "Set", and the
// value cannot be read back. "Clear" sits directly beside "Replace", so one
// mis-click deleted the key on the spot with nothing to undo — enrichment
// quietly dropped to "Needs key" until the operator fetched a fresh one from
// the provider. Every other destructive action in the app arms an inline
// two-step confirm; this panel does the same, keyed per row.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ApiKeyField } from '../lib/api';

const getApiKeysMock = vi.hoisted(() => vi.fn());
const clearApiKeyMock = vi.hoisted(() => vi.fn());
const saveApiKeyMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getApiKeys: getApiKeysMock,
  clearApiKey: clearApiKeyMock,
  saveApiKey: saveApiKeyMock,
}));

import { ApiKeysPanel } from './ApiKeysPanel';

const MAXMIND: ApiKeyField = {
  key: 'maxmind_license_key',
  label: 'MaxMind',
  help: 'GeoLite2 license key.',
  isSet: true,
  source: 'db',
};

const SHODAN: ApiKeyField = {
  key: 'shodan_api_key',
  label: 'Shodan',
  help: 'Shodan API key.',
  isSet: true,
  source: 'db',
};

/** The row that carries a given key's label, so a test can scope its buttons. */
function row(label: string): HTMLElement {
  const el = screen.getByText(label).closest('div.border-b, div.last\\:border-0');
  if (!el) throw new Error(`no row for ${label}`);
  return el as HTMLElement;
}

afterEach(() => {
  getApiKeysMock.mockReset();
  clearApiKeyMock.mockReset();
  saveApiKeyMock.mockReset();
});

describe('ApiKeysPanel clear confirm', () => {
  it('arms a confirm on the first click instead of clearing the key', async () => {
    getApiKeysMock.mockResolvedValue([MAXMIND]);
    clearApiKeyMock.mockResolvedValue({ ok: true, isSet: false });
    render(<ApiKeysPanel />);

    fireEvent.click(await screen.findByRole('button', { name: 'Clear' }));

    expect(clearApiKeyMock).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Confirm clear' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument();
    // The one-click button is gone while the row is armed.
    expect(screen.queryByRole('button', { name: 'Clear' })).toBeNull();
  });

  it('clears the key once the confirm is clicked', async () => {
    getApiKeysMock.mockResolvedValue([MAXMIND]);
    clearApiKeyMock.mockResolvedValue({ ok: true, isSet: false });
    render(<ApiKeysPanel />);

    fireEvent.click(await screen.findByRole('button', { name: 'Clear' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm clear' }));

    await waitFor(() => expect(clearApiKeyMock).toHaveBeenCalledWith('maxmind_license_key'));
    expect(clearApiKeyMock).toHaveBeenCalledTimes(1);
    expect(await screen.findByText('soc-ai cleared the key.')).toBeInTheDocument();
    // The row is disarmed after the call settles.
    expect(screen.queryByRole('button', { name: 'Confirm clear' })).toBeNull();
  });

  it('disarms on Cancel without touching the key', async () => {
    getApiKeysMock.mockResolvedValue([MAXMIND]);
    render(<ApiKeysPanel />);

    fireEvent.click(await screen.findByRole('button', { name: 'Clear' }));
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(clearApiKeyMock).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: 'Confirm clear' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Clear' })).toBeInTheDocument();
  });

  it('arms one row at a time', async () => {
    getApiKeysMock.mockResolvedValue([MAXMIND, SHODAN]);
    render(<ApiKeysPanel />);
    await screen.findByText('Shodan');

    fireEvent.click(within(row('MaxMind')).getByRole('button', { name: 'Clear' }));
    expect(within(row('MaxMind')).getByRole('button', { name: 'Confirm clear' })).toBeTruthy();
    expect(within(row('Shodan')).queryByRole('button', { name: 'Confirm clear' })).toBeNull();

    // Arming the second row moves the confirm rather than stacking a second one.
    fireEvent.click(within(row('Shodan')).getByRole('button', { name: 'Clear' }));
    expect(within(row('Shodan')).getByRole('button', { name: 'Confirm clear' })).toBeTruthy();
    expect(within(row('MaxMind')).queryByRole('button', { name: 'Confirm clear' })).toBeNull();
    expect(clearApiKeyMock).not.toHaveBeenCalled();
  });

  it('drops the armed confirm when the operator switches to Replace', async () => {
    getApiKeysMock.mockResolvedValue([MAXMIND]);
    render(<ApiKeysPanel />);

    fireEvent.click(await screen.findByRole('button', { name: 'Clear' }));
    fireEvent.click(screen.getByRole('button', { name: 'Replace' }));
    // The edit row's own Cancel closes the editor; the clear confirm must not
    // come back armed underneath it.
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(screen.queryByRole('button', { name: 'Confirm clear' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Clear' })).toBeInTheDocument();
    expect(clearApiKeyMock).not.toHaveBeenCalled();
  });
});
