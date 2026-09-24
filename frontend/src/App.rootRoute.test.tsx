/**
 * The bare root lands on the dashboard when no login is required, and on the
 * login screen when one is. Pinned because the range tester's first screen was
 * a password prompt on an instance with no passwords.
 */
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { ShellProvider } from './shell/ShellContext';

vi.mock('./lib/api', async () => {
  const actual = await vi.importActual<typeof import('./lib/api')>('./lib/api');
  return { ...actual, getMe: vi.fn() };
});
import { getMe } from './lib/api';

vi.mock('./screens/Dashboard', () => ({ Dashboard: () => <div data-testid="dashboard-screen" /> }));
vi.mock('./screens/Login', () => ({ Login: () => <div data-testid="login-screen" /> }));

function mount() {
  return render(
    <ShellProvider>
      <MemoryRouter initialEntries={['/']}>
        <App />
      </MemoryRouter>
    </ShellProvider>,
  );
}

describe('the bare root', () => {
  beforeEach(() => {
    vi.mocked(getMe).mockReset();
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('lands on the dashboard when the server answers /me without a session', async () => {
    vi.mocked(getMe).mockResolvedValue({ username: 'anonymous', role: 'admin', status: '', signed_in: false });
    mount();
    await waitFor(() => expect(screen.getByTestId('dashboard-screen')).toBeTruthy());
    expect(screen.queryByTestId('login-screen')).toBeNull();
  });

  it('lands on the login screen when /me is refused', async () => {
    vi.mocked(getMe).mockRejectedValue(new Error('401'));
    mount();
    await waitFor(() => expect(screen.getByTestId('login-screen')).toBeTruthy());
  });
});
