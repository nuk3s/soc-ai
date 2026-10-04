// Sign-in off (API_AUTH_REQUIRED=false). /me answers signed_in: false. The
// account menu offered Change password and Sign out, and the palette offered
// Sign out. Change password 401'd into the global login redirect, and Sign out
// went to /app/login. Both left the analyst on a login page with no credentials
// to use (RD1, RD2). The status field said "saved" and stored nothing (RD4).
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Me } from '../lib/types';

const me = vi.fn<() => Promise<Me>>();

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getMe: () => me(),
  getAbout: vi.fn(() => new Promise(() => {})),
  getNeedsYou: vi.fn(() => Promise.resolve({ total: 0 })),
  getConfig: vi.fn(() => Promise.reject(new Error('403'))),
}));

import { CommandPalette } from './CommandPalette';
import { SessionProvider } from './Session';
import { ShellProvider, useShell } from './ShellContext';
import { Sidebar } from './Sidebar';

const ANON: Me = { username: 'anonymous', role: 'admin', status: '', signed_in: false };
const SIGNED_IN: Me = { username: 'ana', role: 'analyst', status: 'on shift', signed_in: true };

function OpenPalette() {
  const { openPalette } = useShell();
  return (
    <button type="button" onClick={openPalette}>
      open palette
    </button>
  );
}

function renderShell() {
  return render(
    <MemoryRouter>
      <ShellProvider>
        <SessionProvider>
          <Sidebar />
          <OpenPalette />
          <CommandPalette />
        </SessionProvider>
      </ShellProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  me.mockReset();
  localStorage.clear();
});

describe('Account menu with sign-in off', () => {
  it('offers no account action and says sign-in is off', async () => {
    me.mockResolvedValue(ANON);
    const user = userEvent.setup();
    renderShell();
    const trigger = await screen.findByRole('button', { name: 'Account menu. Anonymous session.' });
    await user.click(trigger);
    const menu = screen.getByRole('menu', { name: /account/i });
    expect(within(menu).getByText('Sign-in is off on this install.')).toBeInTheDocument();
    expect(within(menu).queryByRole('menuitem', { name: /change password/i })).toBeNull();
    expect(within(menu).queryByRole('menuitem', { name: /sign out/i })).toBeNull();
    expect(within(menu).queryByRole('button', { name: /set status/i })).toBeNull();
  });

  it('drops Sign out from the palette', async () => {
    me.mockResolvedValue(ANON);
    const user = userEvent.setup();
    renderShell();
    await screen.findByRole('button', { name: 'Account menu. Anonymous session.' });
    await user.click(screen.getByRole('button', { name: 'open palette' }));
    const input = await screen.findByRole('combobox');
    await user.type(input, 'sign');
    await waitFor(() => expect(screen.queryByText('Sign out')).toBeNull());
  });

  it('keeps every action for a signed-in user', async () => {
    me.mockResolvedValue(SIGNED_IN);
    const user = userEvent.setup();
    renderShell();
    const trigger = await screen.findByRole('button', { name: /you are signed in as ana/i });
    await user.click(trigger);
    const menu = screen.getByRole('menu', { name: /account/i });
    expect(within(menu).getByRole('menuitem', { name: /change password/i })).toBeInTheDocument();
    expect(within(menu).getByRole('menuitem', { name: /sign out/i })).toBeInTheDocument();
    expect(within(menu).getByRole('button', { name: /set status/i })).toBeInTheDocument();
    expect(within(menu).queryByText('Sign-in is off on this install.')).toBeNull();
    await user.keyboard('{Escape}');
    await user.click(screen.getByRole('button', { name: 'open palette' }));
    await user.type(await screen.findByRole('combobox'), 'sign');
    expect(await screen.findByText('Sign out')).toBeInTheDocument();
  });
});
