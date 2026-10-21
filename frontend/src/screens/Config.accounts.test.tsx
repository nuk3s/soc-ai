// The Settings page fixes of the 2026-10-19 dogfood, H1 and R5:
// - H1-D1: Reset password on your own row locked out the only admin.
// - H1-D5: nothing said the generated admin password was still in use.
// - H1-D12, R5-D11: tokens could not be told apart; revoke had no confirm;
//   Create token was enabled with authentication off.
// - R5-D7, R5-D8, R5-D22: no DEFAULT origin, no way back to the .env value,
//   no restart marker.
// - H1-D15, H1-I2: the Connections rows hid the current value.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('./AgentToolsPanel', () => ({ AgentToolsPanel: () => null }));
vi.mock('./ApiKeysPanel', () => ({ ApiKeysPanel: () => null }));
vi.mock('./DataSourcesPanel', () => ({ DataSourcesPanel: () => null }));
vi.mock('./TlsPanel', () => ({ TlsPanel: () => null }));
vi.mock('./EgressPolicyPanel', () => ({ EgressPolicyPanel: () => null }));
vi.mock('./NotificationsPanel', () => ({ NotificationsPanel: () => null }));
vi.mock('./RedactionPreviewPanel', () => ({ RedactionPreviewPanel: () => null }));
vi.mock('./DetectionTuningPanel', () => ({ DetectionTuningPanel: () => null }));
vi.mock('./MaintenancePanel', () => ({ MaintenancePanel: () => null }));
vi.mock('./RunbooksPanel', () => ({ RunbooksPanel: () => null }));

const ADMIN = { id: 1, username: 'admin', role: 'admin', disabled: false, status: '' };
const JORDAN = { id: 2, username: 'jordan', role: 'analyst', disabled: false, status: '' };

const SETTINGS = vi.hoisted((): import('../lib/types').SettingGroup[] => [
  {
    title: 'Memory',
    parent: 'Retrieval & Memory',
    items: [
      {
        key: 'memory_window_days',
        label: 'Memory window (days)',
        help: 'Each run reads the verdicts of this window.',
        source: 'db',
        base_source: 'env',
        base_value: 90,
        default: 30,
        apply: 'hot-apply',
        type: 'number',
        value: 60,
        bounds: '1 to 365',
        day1: true,
      },
      {
        key: 'chat_memory_k',
        label: 'Chat memory items',
        help: 'The chat reads this many memories.',
        source: 'default',
        base_source: 'default',
        base_value: 5,
        default: 5,
        apply: 'hot-apply',
        type: 'number',
        value: 5,
        bounds: '0 to 50',
        day1: true,
      },
      {
        key: 'misp_url',
        label: 'MISP URL',
        help: 'The MISP base URL.',
        source: 'db',
        base_source: 'default',
        base_value: '',
        default: '',
        apply: 'restart',
        type: 'text',
        value: 'https://misp.example.test',
        day1: true,
        pending_restart: true,
      },
    ],
  },
]);

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getConfig: vi.fn().mockResolvedValue({ groups: SETTINGS, tokens: [], users: [], dangerHost: '' }),
  listUsers: vi.fn().mockResolvedValue({ users: [] }),
  getMe: vi.fn(),
  listDangerSettings: vi.fn().mockResolvedValue([]),
  getGatewayModels: vi.fn().mockResolvedValue({ ok: true, models: [] }),
  getModelFitness: vi.fn().mockResolvedValue({ grade: 'pass', model: 'x', legs: [], detail: 'ok' }),
  getModelBattery: vi.fn().mockResolvedValue({ running: false, model: '', current_config: null, completed: 0, total: 4, result: null, stored_at: null }),
  getInternalIdentifiers: vi.fn().mockResolvedValue({ groups: [], last_scan: { running: false, last_scan: null, last_summary: null, note: null } }),
  resetUserPassword: vi.fn().mockResolvedValue({ ok: true, password: 'temp-pw-123' }),
  mintToken: vi.fn().mockResolvedValue('scai_minted'),
  revokeToken: vi.fn().mockResolvedValue({ ok: true }),
  clearSetting: vi.fn().mockResolvedValue({ ok: true, restart_required: false, removed: true }),
  testConnection: vi.fn().mockResolvedValue({ ok: true, detail: '3 models' }),
  getAgentTools: vi.fn().mockResolvedValue({
    tools: [{ name: 'get_pcap', category: 'pcap', read_only: true, description: 'Read packets.', requires: [], missing: [], available: true }],
  }),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getApiKeys: vi.fn().mockResolvedValue([]),
}));

import { Config } from './Config';
import {
  clearSetting,
  getConfig,
  getMe,
  listDangerSettings,
  listUsers,
  mintToken,
  resetUserPassword,
  revokeToken,
  testConnection,
} from '../lib/api';

function renderAt(hash: string) {
  return render(
    <MemoryRouter initialEntries={[{ pathname: '/config', hash }]}>
      <Config />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.mocked(getMe).mockResolvedValue({ username: 'admin', role: 'admin', status: '', signed_in: true });
  vi.mocked(listUsers).mockResolvedValue({ users: [ADMIN, JORDAN] });
  vi.mocked(resetUserPassword).mockClear();
  vi.mocked(mintToken).mockClear();
  vi.mocked(revokeToken).mockClear();
  vi.mocked(clearSetting).mockClear();
});

describe('Users', () => {
  it('your own row offers Change password, never Reset password', async () => {
    renderAt('#users');
    const own = (await screen.findByText('(you)')).closest('.border-b') as HTMLElement;
    expect(within(own).getByRole('button', { name: 'Change password' })).toBeInTheDocument();
    expect(within(own).queryByRole('button', { name: 'Reset password' })).toBeNull();
  });

  it('a reset of another user asks first and names the consequence', async () => {
    renderAt('#users');
    fireEvent.click(await screen.findByRole('button', { name: 'Reset password' }));
    const confirm = screen.getByTestId('reset-confirm');
    expect(confirm).toHaveTextContent('jordan');
    expect(confirm).toHaveTextContent('ends every session of this user');
    expect(confirm).toHaveTextContent('revokes the API tokens that this user created');
    expect(resetUserPassword).not.toHaveBeenCalled();
    fireEvent.keyDown(confirm, { key: 'Escape' });
    expect(screen.queryByTestId('reset-confirm')).toBeNull();
  });

  it('shows the new password once with a Copy control and refetches nothing', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    renderAt('#users');
    fireEvent.click(await screen.findByRole('button', { name: 'Reset password' }));
    const calls = vi.mocked(listUsers).mock.calls.length;
    fireEvent.click(screen.getByRole('button', { name: 'Reset the password' }));
    expect(await screen.findByText('temp-pw-123')).toBeInTheDocument();
    expect(resetUserPassword).toHaveBeenCalledWith(2);
    // A refetch after a reset could meet a 401 and leave the page before the
    // password showed. A reset changes no field of the list.
    expect(vi.mocked(listUsers).mock.calls.length).toBe(calls);
    fireEvent.click(screen.getByRole('button', { name: /Copy/ }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith('temp-pw-123'));
  });

  it('warns while the generated admin password is in use', async () => {
    vi.mocked(getMe).mockResolvedValue({
      username: 'admin',
      role: 'admin',
      status: '',
      signed_in: true,
      password_is_generated: true,
    });
    renderAt('#users');
    const banner = await screen.findByTestId('generated-password-banner');
    expect(banner).toHaveTextContent('You still use the generated admin password.');
    expect(within(banner).getByRole('button', { name: 'Change password' })).toBeInTheDocument();
  });
});

describe('API tokens', () => {
  it('names a token at creation and shows the name on the minted banner', async () => {
    renderAt('#api-tokens');
    fireEvent.click(await screen.findByRole('button', { name: 'Create token' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Enter a name for the token.');
    expect(mintToken).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText('Token name'), { target: { value: 'siem-export' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create token' }));
    expect(await screen.findByText('Copy the token siem-export now. soc-ai does not show it again.')).toBeInTheDocument();
    expect(mintToken).toHaveBeenCalledWith('siem-export');
    expect(screen.getByText('scai_minted')).toBeInTheDocument();
  });

  it('refuses a name the server would refuse', async () => {
    renderAt('#api-tokens');
    fireEvent.change(await screen.findByLabelText('Token name'), { target: { value: 'bad/name' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create token' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Use letters, digits, spaces, dots, dashes and underscores only.');
    expect(mintToken).not.toHaveBeenCalled();
  });

  it('with no signed-in user, says why there is no Create token', async () => {
    vi.mocked(getMe).mockResolvedValue({ username: 'anonymous', role: 'admin', status: '', signed_in: false });
    renderAt('#api-tokens');
    expect(await screen.findByTestId('token-blocked')).toHaveTextContent('Sign in as an admin to create a token.');
    expect(screen.queryByRole('button', { name: 'Create token' })).toBeNull();
    expect(screen.getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', '/login');
  });

  it('confirms a revoke by the token name, and says when there is no token', async () => {
    vi.mocked(getConfig).mockResolvedValueOnce({
      groups: SETTINGS,
      tokens: [{ id: 7, name: 'siem-export', prefix: 'scai_••••', created: '1d ago', used: 'never' }],
      users: [],
      dangerHost: '',
    });
    renderAt('#api-tokens');
    fireEvent.click(await screen.findByRole('button', { name: 'Revoke' }));
    const confirm = screen.getByTestId('revoke-confirm');
    expect(confirm).toHaveTextContent('Revoke the token siem-export?');
    expect(confirm).toHaveTextContent('You cannot undo this.');
    fireEvent.click(within(confirm).getByRole('button', { name: 'Revoke the token' }));
    await waitFor(() => expect(revokeToken).toHaveBeenCalledWith(7));
  });

  it('shows an empty state with no token', async () => {
    renderAt('#api-tokens');
    expect(await screen.findByTestId('tokens-empty')).toHaveTextContent('No API token exists.');
  });
});

describe('setting origins', () => {
  it('shows DB, ENV and DEFAULT, and names the value under a DB override', async () => {
    renderAt('#memory');
    const db = (await screen.findByText('Memory window (days)')).closest('[data-setting-key]') as HTMLElement;
    expect(within(db).getByTestId('source-badge')).toHaveTextContent('db');
    expect(within(db).getByTestId('origin-memory_window_days')).toHaveTextContent(
      'Saved in the console. The .env value is 90.',
    );
    const def = screen.getByText('Chat memory items').closest('[data-setting-key]') as HTMLElement;
    expect(within(def).getByTestId('source-badge')).toHaveTextContent('default');
  });

  it('Use the .env value removes the console value', async () => {
    renderAt('#memory');
    fireEvent.click(await screen.findByRole('button', { name: 'Use the .env value' }));
    await waitFor(() => expect(clearSetting).toHaveBeenCalledWith('memory_window_days'));
    expect(await screen.findByText(/Memory window \(days\) now uses the \.env value\./)).toBeInTheDocument();
  });

  it('marks a restart setting that waits for a restart', async () => {
    renderAt('#memory');
    expect(await screen.findByTestId('pending-restart-misp_url')).toHaveTextContent('waits for restart');
    const row = screen.getByText('MISP URL').closest('[data-setting-key]') as HTMLElement;
    expect(within(row).getByRole('button', { name: 'Use the default' })).toBeInTheDocument();
  });

  it('a number field names its setting', async () => {
    renderAt('#memory');
    expect(await screen.findByRole('spinbutton', { name: 'Memory window (days)' })).toHaveAttribute('max', '365');
  });
});

describe('the settings search', () => {
  it('finds a panel row and a control inside a setting row', async () => {
    renderAt('#memory');
    const box = (await screen.findAllByLabelText('Search settings'))[0];
    fireEvent.change(box, { target: { value: 'get_pcap' } });
    expect(await screen.findByTestId('search-result-tool:get_pcap')).toBeInTheDocument();
    fireEvent.change(box, { target: { value: 'maxmind' } });
    expect(await screen.findByTestId('search-result-section-data-sources')).toBeInTheDocument();
    // Escape clears the search.
    fireEvent.keyDown(box, { key: 'Escape' });
    expect((box as HTMLInputElement).value).toBe('');
  });
});

describe('Connections', () => {
  it('shows the current value, starts the edit from it, and tests the edited value', async () => {
    vi.mocked(listDangerSettings).mockResolvedValue([
      { key: 'litellm_base_url', label: 'Gateway URL', type: 'text', isSet: true, source: 'env', hot: false, value: 'http://gw.example.test:4000', required: true },
      { key: 'es_password', label: 'Elasticsearch password', type: 'secret', isSet: false, source: 'unset', hot: false, required: false },
    ]);
    renderAt('#danger-zone');
    expect((await screen.findAllByText('Connections')).length).toBeGreaterThan(0);
    await screen.findByTestId('conn-value-litellm_base_url');
    expect(screen.getByTestId('conn-value-litellm_base_url')).toHaveTextContent('http://gw.example.test:4000');
    // An optional secret that is not set is no fault: a neutral "Not set".
    const notSet = screen.getByText('Not set');
    expect(notSet).toHaveAttribute('title', 'This secret is optional.');

    fireEvent.click(screen.getAllByRole('button', { name: 'Edit' })[0]);
    const field = screen.getByLabelText('Value') as HTMLInputElement;
    expect(field.value).toBe('http://gw.example.test:4000');
    fireEvent.change(field, { target: { value: 'http://gw2.example.test:4000' } });
    fireEvent.click(screen.getByRole('button', { name: 'Test' }));
    await waitFor(() =>
      expect(testConnection).toHaveBeenCalledWith('llm', {
        key: 'litellm_base_url',
        value: 'http://gw2.example.test:4000',
      }),
    );
    expect(await screen.findByTestId('conn-edit-test')).toHaveTextContent('3 models');
  });
});
