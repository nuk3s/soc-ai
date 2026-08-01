// The About panel surfaces the running version + repo/license, and — only when
// an admin has opted in — a manual "check for updates" button that reaches
// GitHub. When the check is off the panel says so and shows no button (no
// outbound call is possible), which is the privacy-preserving default.
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

const STATE = vi.hoisted(() => ({
  about: {
    version: '1.2.5',
    repo_url: 'https://github.com/nuk3s/soc-ai',
    license: 'Apache-2.0',
    update_check_enabled: true,
  },
  update: {
    enabled: true,
    ok: true,
    current_version: '1.2.5',
    latest_version: '1.2.5',
    update_available: false,
    detail: 'up to date',
  },
}));

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAbout: vi.fn(() => Promise.resolve(STATE.about)),
  checkForUpdates: vi.fn(() => Promise.resolve(STATE.update)),
}));

import { checkForUpdates } from '../lib/api';
import { AboutPanel } from './AboutPanel';

describe('AboutPanel', () => {
  it('shows the running version, license, and a repo link', async () => {
    STATE.about = {
      version: '1.2.5',
      repo_url: 'https://github.com/nuk3s/soc-ai',
      license: 'Apache-2.0',
      update_check_enabled: false,
    };
    render(<AboutPanel />);
    expect(await screen.findByText(/1\.2\.5/)).toBeTruthy();
    expect(screen.getByText(/Apache-2\.0/)).toBeTruthy();
    const link = screen.getByRole('link', { name: /github/i }) as HTMLAnchorElement;
    expect(link.href).toContain('github.com/nuk3s/soc-ai');
  });

  it('hides the update-check button when the check is disabled', async () => {
    STATE.about = {
      version: '1.2.5',
      repo_url: 'https://github.com/nuk3s/soc-ai',
      license: 'Apache-2.0',
      update_check_enabled: false,
    };
    render(<AboutPanel />);
    await screen.findByText(/1\.2\.5/);
    expect(screen.queryByRole('button', { name: /check for updates/i })).toBeNull();
    expect(screen.getByText(/no outbound calls/i)).toBeTruthy();
  });

  it('refetches /about when refreshKey changes, so a live toggle takes effect', async () => {
    STATE.about = {
      version: '1.2.5',
      repo_url: 'https://github.com/nuk3s/soc-ai',
      license: 'Apache-2.0',
      update_check_enabled: false,
    };
    const { rerender } = render(<AboutPanel refreshKey={0} />);
    await screen.findByText(/no outbound calls/i);
    expect(screen.queryByRole('button', { name: /check for updates/i })).toBeNull();
    // Admin enables the hot toggle and clicks Apply → Config bumps its nonce →
    // refreshKey changes → the panel refetches and the button appears live.
    STATE.about = { ...STATE.about, update_check_enabled: true };
    rerender(<AboutPanel refreshKey={1} />);
    expect(await screen.findByRole('button', { name: /check for updates/i })).toBeTruthy();
  });

  it('checks GitHub and reports an available update when enabled', async () => {
    STATE.about = {
      version: '1.2.5',
      repo_url: 'https://github.com/nuk3s/soc-ai',
      license: 'Apache-2.0',
      update_check_enabled: true,
    };
    STATE.update = {
      enabled: true,
      ok: true,
      current_version: '1.2.5',
      latest_version: '9.9.9',
      update_available: true,
      detail: 'update available: 9.9.9',
    };
    render(<AboutPanel />);
    const btn = await screen.findByRole('button', { name: /check for updates/i });
    fireEvent.click(btn);
    expect(checkForUpdates).toHaveBeenCalled();
    expect(await screen.findByText(/update available: 9\.9\.9/)).toBeTruthy();
  });
});
