// Dogfood 2026-10-19, H1-D5 and H1-I1: production still signed in with the
// generated admin password. GET /me carried password_is_generated, but only
// Settings > Users showed a banner, and the operator does not open that page
// every day. The app shell now shows a slim banner on every page while the
// flag is true, with a Change password button that opens the dialog.
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { Link, MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getMe: vi.fn(),
  changePassword: vi.fn(),
  getAbout: vi.fn(() => new Promise(() => {})),
  getNeedsYouCount: vi.fn(() => Promise.resolve({ total: 0, unknown: [] })),
  getWorkspaces: vi.fn(() => Promise.resolve([])),
  getNotifications: vi.fn(() => Promise.resolve([])),
  getHealth: vi.fn(() => new Promise(() => {})),
}));

import { PASSWORD_CHANGED_EVENT, changePassword, getMe } from '../lib/api';
import type { Me } from '../lib/types';
import { AppShell } from './AppShell';
import { ShellProvider } from './ShellContext';

const BANNER_TEXT = 'This account still uses the generated password. Change it now.';

const GENERATED: Me = {
  username: 'admin',
  role: 'admin',
  status: '',
  signed_in: true,
  password_is_generated: true,
};
const CHANGED: Me = { ...GENERATED, password_is_generated: false };

function HostsScreen() {
  return (
    <div>
      hosts screen <Link to="/alerts">to alerts</Link>
    </div>
  );
}

function renderShell() {
  return render(
    <MemoryRouter initialEntries={['/hosts']}>
      <ShellProvider>
        <Routes>
          <Route element={<AppShell />}>
            <Route path="/hosts" element={<HostsScreen />} />
            <Route path="/alerts" element={<div>alerts screen</div>} />
          </Route>
        </Routes>
      </ShellProvider>
    </MemoryRouter>,
  );
}

const banner = () => screen.queryByTestId('generated-password-shell-banner');

beforeEach(() => {
  vi.clearAllMocks();
  window.sessionStorage.clear();
  vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new TypeError('offline'))));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the generated password banner in the shell', () => {
  it('shows on every page while the account uses the generated password', async () => {
    vi.mocked(getMe).mockResolvedValue(GENERATED);
    renderShell();
    await screen.findByText(/hosts screen/);
    expect(banner()).toHaveTextContent(BANNER_TEXT);

    fireEvent.click(screen.getByRole('link', { name: 'to alerts' }));
    await screen.findByText('alerts screen');
    expect(banner()).toHaveTextContent(BANNER_TEXT);
  });

  it('opens the change dialog and hides after a successful change', async () => {
    vi.mocked(getMe).mockResolvedValueOnce(GENERATED).mockResolvedValue(CHANGED);
    vi.mocked(changePassword).mockResolvedValue({ ok: true });
    renderShell();
    await screen.findByText(/hosts screen/);

    fireEvent.click(within(banner()!).getByRole('button', { name: 'Change password' }));
    const dialog = await screen.findByRole('dialog', { name: 'Change password' });
    fireEvent.change(within(dialog).getByLabelText('Current password'), {
      target: { value: 'generated-pw-1' },
    });
    fireEvent.change(within(dialog).getByLabelText('New password'), {
      target: { value: 'a-new-password' },
    });
    fireEvent.change(within(dialog).getByLabelText('Confirm new password'), {
      target: { value: 'a-new-password' },
    });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Change password' }));

    await waitFor(() => expect(changePassword).toHaveBeenCalledWith('generated-pw-1', 'a-new-password'));
    await waitFor(() => expect(banner()).toBeNull());
    expect(screen.queryByRole('dialog', { name: 'Change password' })).toBeNull();
  });

  it('stays when the operator closes the dialog with no change', async () => {
    vi.mocked(getMe).mockResolvedValue(GENERATED);
    renderShell();
    await screen.findByText(/hosts screen/);

    fireEvent.click(within(banner()!).getByRole('button', { name: 'Change password' }));
    const dialog = await screen.findByRole('dialog', { name: 'Change password' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));

    await act(async () => {});
    expect(banner()).toHaveTextContent(BANNER_TEXT);
  });

  it('hides for the session on Remind me later, and comes back in a new session', async () => {
    vi.mocked(getMe).mockResolvedValue(GENERATED);
    const first = renderShell();
    await screen.findByText(/hosts screen/);

    fireEvent.click(within(banner()!).getByRole('button', { name: 'Remind me later' }));
    expect(banner()).toBeNull();

    // A page reload in the same browser session keeps it hidden.
    first.unmount();
    const second = renderShell();
    await screen.findByText(/hosts screen/);
    expect(banner()).toBeNull();

    // A new browser session shows it again. The reminder is not a dismissal.
    second.unmount();
    window.sessionStorage.clear();
    renderShell();
    await screen.findByText(/hosts screen/);
    expect(banner()).toHaveTextContent(BANNER_TEXT);
  });

  it('hides when the password changes from another place', async () => {
    vi.mocked(getMe).mockResolvedValueOnce(GENERATED).mockResolvedValue(CHANGED);
    renderShell();
    await screen.findByText(/hosts screen/);
    expect(banner()).not.toBeNull();

    // The account menu and Settings > Users change the password too.
    await act(async () => {
      window.dispatchEvent(new CustomEvent(PASSWORD_CHANGED_EVENT));
    });

    await waitFor(() => expect(banner()).toBeNull());
  });

  it('does not show once the password is changed', async () => {
    vi.mocked(getMe).mockResolvedValue(CHANGED);
    renderShell();
    await screen.findByText(/hosts screen/);
    expect(banner()).toBeNull();
  });

  it('does not show with sign-in off', async () => {
    // No user row stands behind the session, so there is no password to
    // change. The flag is planted to prove the banner reads signed_in.
    vi.mocked(getMe).mockResolvedValue({
      username: 'anonymous',
      role: 'admin',
      status: '',
      signed_in: false,
      password_is_generated: true,
    });
    renderShell();
    await screen.findByText(/hosts screen/);
    expect(banner()).toBeNull();
  });
});
