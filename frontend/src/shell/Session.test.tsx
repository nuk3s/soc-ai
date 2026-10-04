// The shell's auth gate (D14). An unauthenticated visit to /app/hosts fired ten
// protected GETs, and Back after sign-out fired 24, all 401s before the first
// one navigated to login. The shell now asks /me first and holds every other
// read, and the routed screen, until /me answers.
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getMe: vi.fn(),
  getAbout: vi.fn(() => new Promise(() => {})),
  getNeedsYou: vi.fn(() => Promise.resolve({ total: 0 })),
  getWorkspaces: vi.fn(() => Promise.resolve([])),
  getNotifications: vi.fn(() => Promise.resolve([])),
  getHealth: vi.fn(() => new Promise(() => {})),
}));

import { getAbout, getHealth, getMe, getNeedsYou, getNotifications, getWorkspaces } from '../lib/api';
import { AppShell } from './AppShell';
import { ShellProvider } from './ShellContext';

const screenRead = vi.fn();
function HostsScreen() {
  screenRead();
  return <div>hosts screen</div>;
}

function renderShell() {
  return render(
    <MemoryRouter initialEntries={['/hosts']}>
      <ShellProvider>
        <Routes>
          <Route element={<AppShell />}>
            <Route path="/hosts" element={<HostsScreen />} />
          </Route>
        </Routes>
      </ShellProvider>
    </MemoryRouter>,
  );
}

const protectedReads = () => [getAbout, getNeedsYou, getWorkspaces, getNotifications, getHealth];

beforeEach(() => {
  vi.clearAllMocks();
  // The demo probe and the update check use fetch directly. Both are open
  // endpoints, so the gate leaves them alone.
  vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new TypeError('offline'))));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('Shell auth gate', () => {
  it('sends no protected read and mounts no screen when /me answers 401', async () => {
    // request() navigates to login on a 401 and throws this Error.
    vi.mocked(getMe).mockRejectedValue(new Error('Unauthorized'));
    renderShell();
    await waitFor(() => expect(getMe).toHaveBeenCalled());
    // Let every settled promise run before the assertion.
    await new Promise((r) => setTimeout(r, 20));
    for (const fn of protectedReads()) expect(fn).not.toHaveBeenCalled();
    expect(screenRead).not.toHaveBeenCalled();
    expect(screen.queryByText('hosts screen')).toBeNull();
  });

  it('holds every read while /me is still in flight', async () => {
    vi.mocked(getMe).mockReturnValue(new Promise(() => {}));
    renderShell();
    await new Promise((r) => setTimeout(r, 20));
    for (const fn of protectedReads()) expect(fn).not.toHaveBeenCalled();
    expect(screenRead).not.toHaveBeenCalled();
  });

  it('starts the shell when sign-in is off', async () => {
    vi.mocked(getMe).mockResolvedValue({
      username: 'anonymous',
      role: 'admin',
      status: '',
      signed_in: false,
    });
    renderShell();
    expect(await screen.findByText('hosts screen')).toBeInTheDocument();
    await waitFor(() => {
      for (const fn of protectedReads()) expect(fn).toHaveBeenCalled();
    });
  });

  it('starts the shell when /me fails for a reason other than 401', async () => {
    // A down API must not lock the shell. The degraded surfaces need to mount
    // to say the API is down.
    vi.mocked(getMe).mockRejectedValue(new Error('Network error. Check that the soc-ai API is reachable.'));
    renderShell();
    expect(await screen.findByText('hosts screen')).toBeInTheDocument();
    await waitFor(() => expect(getNotifications).toHaveBeenCalled());
  });
});
