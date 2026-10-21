// A stored provider key is write-only: the panel only ever shows "Set", and the
// value cannot be read back. "Clear" sits directly beside "Replace", so one
// mis-click deleted the key on the spot with nothing to undo — enrichment
// quietly dropped to "Needs key" until the operator fetched a fresh one from
// the provider. Every other destructive action in the app arms an inline
// two-step confirm; this panel does the same, keyed per row.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
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

// Dogfood 2026-10-19 (R5-D17, R5-D21): the intro said every key was for "the
// opt-in online enrichment tools" and applied live, while the MISP key help
// said it needs a restart, and MaxMind, abuse.ch and crawl4ai are no online
// enrichment. The help strings rendered raw backticks.
const MISP: ApiKeyField = {
  key: 'misp_api_key',
  label: 'MISP API key',
  help: 'soc-ai builds the MISP client at startup, so a new key needs a restart.',
  isSet: false,
  source: 'unset',
};

const ABUSE: ApiKeyField = {
  key: 'abuse_ch_auth_key',
  label: 'abuse.ch auth key',
  help: '`soc-ai blocklists refresh` uses this key to download the URLhaus feed.',
  isSet: false,
  source: 'unset',
};

function renderInRouter() {
  return render(
    <MemoryRouter>
      <ApiKeysPanel />
    </MemoryRouter>,
  );
}

describe('ApiKeysPanel text', () => {
  it('says which keys apply live and which key needs a restart', async () => {
    getApiKeysMock.mockResolvedValue([MAXMIND]);
    renderInRouter();
    await screen.findByText('MaxMind');
    const intro = screen.getByTestId('api-keys-intro').textContent ?? '';
    expect(intro).toContain('The MISP key applies after a restart.');
    expect(intro).not.toContain('A new key applies live without a restart.');
    expect(intro).not.toContain('for the opt-in online enrichment tools');
    expect(
      within(screen.getByTestId('api-keys-intro'))
        .getByRole('link', { name: 'Settings > Online enrichment' })
        .getAttribute('href'),
    ).toBe('/config#online-enrichment');
  });

  it('renders a code span in a key help as code', async () => {
    getApiKeysMock.mockResolvedValue([ABUSE]);
    renderInRouter();
    await screen.findByText('abuse.ch auth key');
    const help = row('abuse.ch auth key');
    expect(help.querySelector('code')?.textContent).toBe('soc-ai blocklists refresh');
    expect(help.textContent).not.toContain('`');
  });

  it('tells the operator to restart after a new MISP key', async () => {
    getApiKeysMock.mockResolvedValue([MISP]);
    saveApiKeyMock.mockResolvedValue({ ok: true, isSet: true });
    renderInRouter();
    fireEvent.click(await screen.findByRole('button', { name: 'Set' }));
    fireEvent.change(screen.getByPlaceholderText('Paste the key here'), { target: { value: 'k' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('soc-ai saved the key. Restart soc-ai to apply it.')).toBeTruthy();
    expect(screen.queryByText(/applies live/)).toBeNull();
  });

  it('says a hot key applies live', async () => {
    getApiKeysMock.mockResolvedValue([{ ...SHODAN, isSet: false, source: 'unset' }]);
    saveApiKeyMock.mockResolvedValue({ ok: true, isSet: true });
    renderInRouter();
    fireEvent.click(await screen.findByRole('button', { name: 'Set' }));
    fireEvent.change(screen.getByPlaceholderText('Paste the key here'), { target: { value: 'k' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('soc-ai saved the key. The key applies live.')).toBeTruthy();
  });
});

// Dogfood round 2 (V2-4): with CONFIG_SECRET_KEY unset, Set opened a field
// and Save answered "Set CONFIG_SECRET_KEY to store API keys via the UI." GET
// now carries can_store, as the webhook panel reads it.
describe('ApiKeysPanel store hint', () => {
  const HINT =
    'Set CONFIG_SECRET_KEY on the server and restart soc-ai. soc-ai then stores the API keys encrypted.';

  it('turns off Set and Replace and states the reason when the server cannot store a key', async () => {
    getApiKeysMock.mockResolvedValue([
      { ...SHODAN, isSet: false, source: 'unset', can_store: false, store_hint: HINT },
      { ...MAXMIND, source: 'env', can_store: false, store_hint: HINT },
    ]);
    renderInRouter();
    expect((await screen.findByTestId('api-keys-store-hint')).textContent).toBe(HINT);
    const set = screen.getByRole('button', { name: 'Set' });
    const replace = screen.getByRole('button', { name: 'Replace' });
    expect(set).toBeDisabled();
    expect(replace).toBeDisabled();
    expect(set.getAttribute('title')).toBe(HINT);
    fireEvent.click(set);
    expect(screen.queryByPlaceholderText('Paste the key here')).toBeNull();
  });

  it('keeps Set on for a server that can store, or one older than the field', async () => {
    getApiKeysMock.mockResolvedValue([{ ...SHODAN, isSet: false, source: 'unset' }]);
    renderInRouter();
    expect(await screen.findByRole('button', { name: 'Set' })).toBeEnabled();
    expect(screen.queryByTestId('api-keys-store-hint')).toBeNull();
  });
});
