// The demo honesty banner is the public demo's core invariant: EVERY screen
// must state plainly that what's shown is a recorded real run. It renders in
// the shell (so all routes get it), driven by one open GET /api/v1/demo-status,
// and must be absent — with zero other UI difference and zero console noise —
// on real deployments or when the backend can't be reached.
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AppShell } from './AppShell';
import { ShellProvider } from './ShellContext';

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

/**
 * Route the demo-status probe; every OTHER shell fetch (me, workspaces,
 * notifications) rejects like an unreachable backend — all of those callers
 * are fail-soft, so the shell still renders with placeholders.
 */
function mockFetch(demoStatus: 'true' | 'false' | 'down') {
  fetchMock.mockImplementation((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith('/demo-status')) {
      if (demoStatus === 'down') return Promise.reject(new TypeError('backend down'));
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({ demo: demoStatus === 'true' }),
      } as Response);
    }
    return Promise.reject(new TypeError('offline'));
  });
}

function renderShell() {
  return render(
    <MemoryRouter>
      <ShellProvider>
        <AppShell />
      </ShellProvider>
    </MemoryRouter>,
  );
}

describe('AppShell demo banner', () => {
  it('pins the honesty banner when the backend reports demo mode', async () => {
    mockFetch('true');
    renderShell();
    const banner = await screen.findByRole('status');
    expect(banner).toHaveTextContent(BANNER_COPY);
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/demo-status', expect.anything());
  });

  it('renders no banner on a real (non-demo) deployment', async () => {
    mockFetch('false');
    renderShell();
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith('/api/v1/demo-status', expect.anything()),
    );
    expect(screen.queryByText(BANNER_COPY)).toBeNull();
  });

  it('fails soft when the backend is unreachable — no banner, no crash', async () => {
    mockFetch('down');
    renderShell();
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith('/api/v1/demo-status', expect.anything()),
    );
    expect(screen.queryByText(BANNER_COPY)).toBeNull();
  });
});
