// The sidebar's account surface. Before this, the avatar was inert and BOTH
// sign-out and the status control lived inside `{!collapsed && …}` — so
// collapsing the rail hid the only way out of the app. The collapsed-rail cases
// below are that regression, pinned.
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// Typed with their real parameters: the mock factory below forwards through an
// arrow (imports are hoisted above these consts, so it cannot reference them
// eagerly), and vi.fn's inferred signature is what typechecks that forwarding.
const changePassword = vi.fn((_current: string, _next: string) => Promise.resolve({ ok: true }));
const setMyStatus = vi.fn((status: string) => Promise.resolve({ ok: true, status }));
const signOut = vi.fn(() => Promise.resolve());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getMe: vi.fn(() => Promise.resolve({ username: 'rmartin', role: 'admin', status: 'on shift' })),
  getAbout: vi.fn(() =>
    Promise.resolve({
      version: '1.2.6',
      repo_url: 'https://github.com/example/soc-ai',
      license: 'Apache-2.0',
      update_check_enabled: false,
    }),
  ),
  setMyStatus: (s: string) => setMyStatus(s),
  changePassword: (c: string, n: string) => changePassword(c, n),
  signOut: () => signOut(),
}));

import { ToastProvider } from '../lib/toast';
import { ShellProvider } from './ShellContext';
import { Sidebar } from './Sidebar';

const NAV_KEY = 'soc-ai:navCollapsed';

function renderSidebar() {
  return render(
    <MemoryRouter>
      <ToastProvider>
        <ShellProvider>
          <Sidebar />
        </ShellProvider>
      </ToastProvider>
    </MemoryRouter>,
  );
}

/** Open the account menu from the avatar trigger and return its container. */
async function openMenu(user: ReturnType<typeof userEvent.setup>) {
  const trigger = await screen.findByRole('button', { name: /account menu/i });
  expect(trigger).toHaveAttribute('aria-haspopup', 'menu');
  expect(trigger).toHaveAttribute('aria-expanded', 'false');
  await user.click(trigger);
  expect(trigger).toHaveAttribute('aria-expanded', 'true');
  return screen.getByRole('menu', { name: /account/i });
}

beforeEach(() => {
  changePassword.mockClear();
  setMyStatus.mockClear();
  signOut.mockClear();
  localStorage.clear();
});

describe('AccountMenu — expanded sidebar', () => {
  it('opens from the avatar and shows username, role as text, status, and both actions', async () => {
    const user = userEvent.setup();
    renderSidebar();

    // Closed until asked for — the avatar used to be inert.
    expect(screen.queryByRole('menu', { name: /account/i })).toBeNull();

    const menu = await openMenu(user);

    expect(within(menu).getByText('rmartin')).toBeInTheDocument();
    // The role is READABLE TEXT, not a hover title attribute.
    expect(within(menu).getByText('admin')).toBeInTheDocument();
    expect(within(menu).getByText(/on shift/)).toBeInTheDocument();
    expect(within(menu).getByRole('menuitem', { name: /change password/i })).toBeInTheDocument();
    expect(within(menu).getByRole('menuitem', { name: /sign out/i })).toBeInTheDocument();
  });

  it('renders the role as text rather than only a title attribute', async () => {
    const user = userEvent.setup();
    renderSidebar();
    const menu = await openMenu(user);

    const roleNode = within(menu).getByText('admin');
    // Present in the accessible text content — a title-only role fails this.
    expect(menu.textContent).toContain('admin');
    expect(roleNode.getAttribute('title')).toBeNull();
  });

  it('escape closes the menu', async () => {
    const user = userEvent.setup();
    renderSidebar();
    await openMenu(user);
    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('menu', { name: /account/i })).toBeNull());
  });

  it('keeps the existing status setter — commits the draft through setMyStatus', async () => {
    const user = userEvent.setup();
    renderSidebar();
    const menu = await openMenu(user);

    await user.click(within(menu).getByRole('button', { name: /set status/i }));
    const input = within(menu).getByRole('textbox', { name: /status/i });
    await user.clear(input);
    await user.type(input, 'triaging{Enter}');
    await waitFor(() => expect(setMyStatus).toHaveBeenCalledWith('triaging'));
  });

  it('signs out through the shared signOut helper', async () => {
    const user = userEvent.setup();
    renderSidebar();
    const menu = await openMenu(user);
    await user.click(within(menu).getByRole('menuitem', { name: /sign out/i }));
    await waitFor(() => expect(signOut).toHaveBeenCalled());
  });
});

describe('AccountMenu — collapsed rail (the regression this fixes)', () => {
  beforeEach(() => {
    localStorage.setItem(NAV_KEY, '1');
  });

  it('still opens from the avatar, so sign-out is reachable while collapsed', async () => {
    const user = userEvent.setup();
    renderSidebar();

    // Sanity: the rail really is collapsed (nav labels are hidden).
    await waitFor(() => expect(screen.queryByText('Dashboard')).toBeNull());

    const menu = await openMenu(user);
    expect(within(menu).getByRole('menuitem', { name: /sign out/i })).toBeInTheDocument();
    await user.click(within(menu).getByRole('menuitem', { name: /sign out/i }));
    await waitFor(() => expect(signOut).toHaveBeenCalled());
  });

  it('exposes the username and role as text while collapsed', async () => {
    const user = userEvent.setup();
    renderSidebar();
    await waitFor(() => expect(screen.queryByText('Dashboard')).toBeNull());
    const menu = await openMenu(user);
    expect(within(menu).getByText('rmartin')).toBeInTheDocument();
    expect(within(menu).getByText('admin')).toBeInTheDocument();
    expect(within(menu).getByRole('menuitem', { name: /change password/i })).toBeInTheDocument();
  });
});

describe('Change-password modal', () => {
  async function openModal(user: ReturnType<typeof userEvent.setup>) {
    renderSidebar();
    const menu = await openMenu(user);
    await user.click(within(menu).getByRole('menuitem', { name: /change password/i }));
    return screen.getByRole('dialog', { name: /change password/i });
  }

  it('rejects a new password below the minimum length, naming the minimum', async () => {
    const user = userEvent.setup();
    const dialog = await openModal(user);

    await user.type(within(dialog).getByLabelText(/current password/i), 'whatever-pw');
    await user.type(within(dialog).getByLabelText(/^new password/i), 'short');
    await user.type(within(dialog).getByLabelText(/confirm/i), 'short');
    await user.click(within(dialog).getByRole('button', { name: /change password/i }));

    expect(await within(dialog).findByRole('alert')).toHaveTextContent(/at least 8 characters/i);
    expect(changePassword).not.toHaveBeenCalled();
  });

  it('rejects a confirm that does not match', async () => {
    const user = userEvent.setup();
    const dialog = await openModal(user);

    await user.type(within(dialog).getByLabelText(/current password/i), 'whatever-pw');
    await user.type(within(dialog).getByLabelText(/^new password/i), 'a-good-password');
    await user.type(within(dialog).getByLabelText(/confirm/i), 'a-good-passwrod');
    await user.click(within(dialog).getByRole('button', { name: /change password/i }));

    expect(await within(dialog).findByRole('alert')).toHaveTextContent(/do not match/i);
    expect(changePassword).not.toHaveBeenCalled();
  });

  it('surfaces a wrong current password from the server, inline', async () => {
    changePassword.mockRejectedValueOnce(new Error('Current password is incorrect.'));
    const user = userEvent.setup();
    const dialog = await openModal(user);

    await user.type(within(dialog).getByLabelText(/current password/i), 'not-my-password');
    await user.type(within(dialog).getByLabelText(/^new password/i), 'a-good-password');
    await user.type(within(dialog).getByLabelText(/confirm/i), 'a-good-password');
    await user.click(within(dialog).getByRole('button', { name: /change password/i }));

    expect(await within(dialog).findByRole('alert')).toHaveTextContent(
      /current password is incorrect/i,
    );
    // Still open, still signed in — nothing navigated away.
    expect(screen.getByRole('dialog', { name: /change password/i })).toBeInTheDocument();
    expect(signOut).not.toHaveBeenCalled();
  });

  it('on success calls the API, closes, toasts, and stays signed in', async () => {
    const user = userEvent.setup();
    const dialog = await openModal(user);

    await user.type(within(dialog).getByLabelText(/current password/i), 'my-old-password');
    await user.type(within(dialog).getByLabelText(/^new password/i), 'a-good-password');
    await user.type(within(dialog).getByLabelText(/confirm/i), 'a-good-password');
    await user.click(within(dialog).getByRole('button', { name: /change password/i }));

    await waitFor(() =>
      expect(changePassword).toHaveBeenCalledWith('my-old-password', 'a-good-password'),
    );
    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: /change password/i })).toBeNull(),
    );
    expect(await screen.findByText(/password changed/i)).toBeInTheDocument();
    expect(signOut).not.toHaveBeenCalled();
  });

  it('uses password-type inputs for all three fields', async () => {
    const user = userEvent.setup();
    const dialog = await openModal(user);
    for (const label of [/current password/i, /^new password/i, /confirm/i]) {
      expect(within(dialog).getByLabelText(label)).toHaveAttribute('type', 'password');
    }
  });

  it('files a server rejection by its reason code, not by matching the prose', async () => {
    // Same wording as a wrong-current-password rejection, but a DIFFERENT code:
    // regex-on-the-message filed this under Current; `reason` puts it under New.
    changePassword.mockRejectedValueOnce(
      Object.assign(new Error('Current password rules: at least 12 characters.'), {
        reason: 'password_too_short',
      }),
    );
    const user = userEvent.setup();
    const dialog = await openModal(user);

    await user.type(within(dialog).getByLabelText(/current password/i), 'my-old-password');
    await user.type(within(dialog).getByLabelText(/^new password/i), 'a-good-password');
    await user.type(within(dialog).getByLabelText(/confirm/i), 'a-good-password');
    await user.click(within(dialog).getByRole('button', { name: /change password/i }));

    const alert = await within(dialog).findByRole('alert');
    expect(alert).toHaveTextContent(/at least 12 characters/i);
    // The alert sits in the New-password field's group, not Current's.
    expect(within(dialog).getByLabelText(/^new password/i).parentElement).toContainElement(alert);
  });

  it('does not carry a stale error into the next opening', async () => {
    // The regression: reject AFTER the analyst has cancelled, then reopen.
    let reject: (e: Error) => void = () => {};
    changePassword.mockImplementationOnce(
      () =>
        new Promise<{ ok: boolean }>((_res, rej) => {
          reject = rej;
        }),
    );
    const user = userEvent.setup();
    const dialog = await openModal(user);

    await user.type(within(dialog).getByLabelText(/current password/i), 'wrong-password');
    await user.type(within(dialog).getByLabelText(/^new password/i), 'a-good-password');
    await user.type(within(dialog).getByLabelText(/confirm/i), 'a-good-password');
    await user.click(within(dialog).getByRole('button', { name: /change password/i }));

    await user.click(within(dialog).getByRole('button', { name: /cancel/i }));
    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: /change password/i })).toBeNull(),
    );
    reject(
      Object.assign(new Error('Current password is incorrect.'), { reason: 'bad_credentials' }),
    );

    // Reopen: clean form, no leftover error above an empty field.
    const menu = await openMenu(user);
    await user.click(within(menu).getByRole('menuitem', { name: /change password/i }));
    const reopened = await screen.findByRole('dialog', { name: /change password/i });
    expect(within(reopened).queryByRole('alert')).toBeNull();
    expect(within(reopened).getByLabelText(/current password/i)).toHaveValue('');
  });

  it('traps Tab inside the dialog instead of leaking into the page behind', async () => {
    const user = userEvent.setup();
    const dialog = await openModal(user);
    // More tabs than the dialog has focusable elements: without a trap this
    // walks out into the sidebar nav behind the scrim.
    for (let i = 0; i < 8; i += 1) await user.tab();
    expect(dialog).toContainElement(document.activeElement as HTMLElement);
  });

  it('locks body scroll while open and releases it on close', async () => {
    const user = userEvent.setup();
    const dialog = await openModal(user);
    expect(document.body.style.overflow).toBe('hidden');
    await user.click(within(dialog).getByRole('button', { name: /cancel/i }));
    await waitFor(() => expect(document.body.style.overflow).not.toBe('hidden'));
  });

  it('returns focus to the account avatar on close, not to BODY', async () => {
    const user = userEvent.setup();
    const dialog = await openModal(user);
    await user.click(within(dialog).getByRole('button', { name: /cancel/i }));
    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: /change password/i })).toBeNull(),
    );
    // The menu item that opened it is long gone; the avatar trigger outlives it.
    await waitFor(() =>
      expect(document.activeElement).toBe(screen.getByRole('button', { name: /account menu/i })),
    );
  });
});
