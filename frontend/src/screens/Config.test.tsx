// F39 — three admin write paths (reset password, mint token, revoke token) call
// their mutation with no `.catch()`, unlike every sibling mutation in this file
// (createUser, setUserRole, toggleUserDisabled all surface the failure onto
// userError/tokenMsg). A rejected request left the banner silent and logged an
// unhandled rejection instead. The screen renders a dozen always-mounted child
// panels (AgentTools, ApiKeys, DataSources, …); they're stubbed out here since
// this test only cares about the Users / API tokens sections Config.tsx itself
// owns, and each stub keeps the test hermetic (no api mocking needed for panels
// this bug doesn't touch).
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

vi.mock('./AgentToolsPanel', () => ({ AgentToolsPanel: () => null }));
vi.mock('./ApiKeysPanel', () => ({ ApiKeysPanel: () => null }));
vi.mock('./DataSourcesPanel', () => ({ DataSourcesPanel: () => null }));
vi.mock('./EgressPolicyPanel', () => ({ EgressPolicyPanel: () => null }));
vi.mock('./NotificationsPanel', () => ({ NotificationsPanel: () => null }));
vi.mock('./RedactionPreviewPanel', () => ({ RedactionPreviewPanel: () => null }));
vi.mock('./DetectionTuningPanel', () => ({ DetectionTuningPanel: () => null }));
vi.mock('./MaintenancePanel', () => ({ MaintenancePanel: () => null }));
vi.mock('./RunbooksPanel', () => ({ RunbooksPanel: () => null }));

const USER = vi.hoisted(() => ({
  id: 1,
  username: 'analyst1',
  role: 'analyst',
  disabled: false,
  status: '',
}));

const TOKEN = vi.hoisted(() => ({
  id: 7,
  name: 'console',
  prefix: 'sk-abcd',
  created: '2026-01-01',
  used: 'never',
}));

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getConfig: vi.fn().mockResolvedValue({ groups: [], tokens: [TOKEN], users: [], dangerHost: '' }),
  listUsers: vi.fn().mockResolvedValue({ users: [USER] }),
  listDangerSettings: vi.fn().mockResolvedValue([]),
  getGatewayModels: vi.fn().mockResolvedValue({ ok: true, models: [] }),
  getInternalIdentifiers: vi.fn().mockResolvedValue({ groups: [], last_scan: { running: false, last_scan: null, last_summary: null, note: null } }),
  resetUserPassword: vi.fn().mockResolvedValue({ ok: true, password: 'temp-pw' }),
  mintToken: vi.fn().mockResolvedValue('minted-token-value'),
  revokeToken: vi.fn().mockResolvedValue({ ok: true }),
}));

import { Config } from './Config';
import { mintToken, resetUserPassword, revokeToken } from '../lib/api';

describe('Config admin write paths surface a failure instead of failing silently (F39)', () => {
  it('shows an error on the users strip when resetUserPassword rejects', async () => {
    vi.mocked(resetUserPassword).mockRejectedValueOnce(new Error('reset failed'));
    render(<Config />);
    const resetBtn = await screen.findByText('Reset pw');
    fireEvent.click(resetBtn);
    await screen.findByText('reset failed');
  });

  it('shows an error on the API tokens banner when mintToken rejects', async () => {
    vi.mocked(mintToken).mockRejectedValueOnce(new Error('mint failed'));
    render(<Config />);
    const mintBtn = await screen.findByText('+ Mint token');
    fireEvent.click(mintBtn);
    await screen.findByText('mint failed');
  });

  it('shows an error on the API tokens banner when revokeToken rejects', async () => {
    vi.mocked(revokeToken).mockRejectedValueOnce(new Error('revoke failed'));
    render(<Config />);
    const revokeBtn = await screen.findByText('Revoke');
    fireEvent.click(revokeBtn);
    await screen.findByText('revoke failed');
  });
});

// F69 — the reset-password banner shows a plaintext credential with only a
// manual ✕ dismiss, unlike the sibling mint-token banner (same file, ~30s
// auto-clear "so the secret doesn't linger on screen until reload"). An admin
// who resets a password and steps away leaves it on an unattended screen.
describe('reset-password banner auto-dismiss (F69)', () => {
  it('clears the plaintext password banner after 30s, like the mint-token banner', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      render(<Config />);
      const resetBtn = await screen.findByText('Reset pw');
      fireEvent.click(resetBtn);
      await screen.findByText('temp-pw');

      await vi.advanceTimersByTimeAsync(30000);

      expect(screen.queryByText('temp-pw')).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });
});
