// The hosts view is only reachable if three things line up: the two routes are
// inside the shell's route group, the screens are code-split the same way their
// neighbours are, and the sidebar actually points at them. A missing route
// silently redirects to /dashboard (the catch-all), which reads as "the feature
// isn't deployed" rather than as a routing bug — so it is pinned here.
//
// The assertions key on the REQUEST each screen makes, not on its copy: phase 2
// replaces both screen bodies wholesale, and a test that pinned the stub's words
// would have to be rewritten to stay true rather than because anything broke.
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from '../App';
import { ShellProvider } from '../shell/ShellContext';

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  // Every request fails like an unreachable backend. Each shell caller (me,
  // health, workspaces, notifications, demo-status) is fail-soft, and the two
  // screens land on their error state — which is beside the point here: the
  // route is proven by the request having been ATTEMPTED at all.
  fetchMock = vi.fn(() => Promise.reject(new TypeError('offline')));
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <ShellProvider>
        <App />
      </ShellProvider>
    </MemoryRouter>,
  );
}

/** Did any request go to this path prefix? */
const asked = (prefix: string): boolean =>
  fetchMock.mock.calls.some((call) => String(call[0]).startsWith(prefix));

describe('hosts routes', () => {
  it('/hosts mounts the hosts screen, which reads the machine list', async () => {
    renderAt('/hosts');
    await waitFor(() => expect(asked('/api/v1/hosts?')).toBe(true));
    expect(asked('/api/v1/hosts/summary')).toBe(true);
  });

  it('/hosts/:key resolves an address to its machine first', async () => {
    renderAt('/hosts/192.168.10.8');
    await waitFor(() => expect(asked('/api/v1/hosts/resolve?value=192.168.10.8')).toBe(true));
    // An unreachable resolve read keeps the page of the address alone.
    await waitFor(() => expect(asked('/api/v1/dossiers/192.168.10.8')).toBe(true));
  });

  it('/hosts/:key reads a machine key straight, percent-encoded', async () => {
    renderAt('/hosts/agent%3Aea2db53b');
    await waitFor(() => expect(asked('/api/v1/hosts/agent%3Aea2db53b')).toBe(true));
    expect(asked('/api/v1/hosts/resolve')).toBe(false);
  });

  it('the sidebar links to the hosts view', async () => {
    renderAt('/hosts');
    const link = await screen.findByRole('link', { name: 'Hosts' });
    expect(link).toHaveAttribute('href', '/hosts');
  });
});
