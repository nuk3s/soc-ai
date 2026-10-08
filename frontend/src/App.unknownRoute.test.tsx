// An address that is no page redirected to the Dashboard and said nothing
// (dogfood 2026-10-06). It now says "No page at this address." inside the
// shell, with a link to the Dashboard.
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { ShellProvider } from './shell/ShellContext';

vi.mock('./lib/api', async () => {
  const actual = await vi.importActual<typeof import('./lib/api')>('./lib/api');
  return {
    ...actual,
    getMe: vi.fn(),
    getAbout: vi.fn(() => new Promise(() => {})),
    getNeedsYouCount: vi.fn(() => new Promise(() => {})),
    getWorkspaces: vi.fn(() => Promise.resolve([])),
    getNotifications: vi.fn(() => Promise.resolve([])),
    getHealth: vi.fn(() => new Promise(() => {})),
  };
});
import { getMe } from './lib/api';

vi.mock('./screens/Dashboard', () => ({ Dashboard: () => <div data-testid="dashboard-screen" /> }));

function mount(path: string) {
  return render(
    <ShellProvider>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </ShellProvider>,
  );
}

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new TypeError('offline'))));
  vi.mocked(getMe).mockResolvedValue({ username: 'anonymous', role: 'admin', status: '', signed_in: false });
});

describe('an address that is no page', () => {
  it('says so and links to the Dashboard', async () => {
    mount('/no-such-page');
    const page = await screen.findByTestId('unknown-route');
    expect(page.textContent).toContain('No page at this address.');
    expect(page.textContent).toContain('/no-such-page');
    expect(screen.getByRole('link', { name: 'Open the Dashboard' }).getAttribute('href')).toBe('/dashboard');
    // No silent redirect.
    expect(screen.queryByTestId('dashboard-screen')).toBeNull();
  });

  // NEGATIVE CONTROL. A real page is not an unknown address.
  it('leaves a real page alone', async () => {
    mount('/dashboard');
    await waitFor(() => expect(screen.getByTestId('dashboard-screen')).toBeTruthy());
    expect(screen.queryByTestId('unknown-route')).toBeNull();
  });
});
