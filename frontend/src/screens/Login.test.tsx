// Login routes OUTSIDE AppShell (App.tsx), so it carries its own honesty
// banner. Demo mode does not force auth off — if a demo deployment ever runs
// with auth required, the FIRST screen a visitor sees must already say the
// results are recorded. Same fail-soft contract as the shell's banner.
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Login } from './Login';

// Pinned literally (not imported) so a copy edit can't silently self-approve.
const BANNER_COPY =
  'Demo — these investigations were run by soc-ai and recorded. Nothing here is live.';

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function mockDemoStatus(demo: boolean) {
  fetchMock.mockImplementation((input: RequestInfo | URL) => {
    if (String(input).endsWith('/demo-status')) {
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ demo }),
      } as Response);
    }
    return Promise.reject(new TypeError('offline'));
  });
}

function renderLogin() {
  return render(
    <MemoryRouter>
      <Login />
    </MemoryRouter>,
  );
}

describe('Login demo banner', () => {
  it('pins the honesty banner pre-auth when the backend reports demo mode', async () => {
    mockDemoStatus(true);
    renderLogin();
    const banner = await screen.findByRole('status');
    expect(banner).toHaveTextContent(BANNER_COPY);
    // The login form still renders beneath it.
    expect(screen.getByText('Sign in to console')).toBeInTheDocument();
  });

  it('renders no banner on a real (non-demo) deployment', async () => {
    mockDemoStatus(false);
    renderLogin();
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith('/api/v1/demo-status', expect.anything()),
    );
    expect(screen.queryByText(BANNER_COPY)).toBeNull();
  });
});
