// Login routes OUTSIDE AppShell (App.tsx), so it carries its own honesty
// banner. Demo mode does not force auth off — if a demo deployment ever runs
// with auth required, the FIRST screen a visitor sees must already say the
// results are recorded. Same fail-soft contract as the shell's banner.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Sign-in navigates; the destination IS the thing under test in the second
// describe, so useNavigate is stubbed rather than inspected via a router.
const navigateMock = vi.fn();
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return { ...actual, useNavigate: () => navigateMock };
});

import { POST_LOGIN_REDIRECT_KEY } from '../lib/api';
import { Login } from './Login';

// Pinned literally (not imported) so a copy edit can't silently self-approve.
const BANNER_COPY =
  'Demo — these investigations were run by soc-ai and recorded. Nothing here is live.';

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal('fetch', fetchMock);
  sessionStorage.clear();
  navigateMock.mockReset();
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

// A 401 mid-session stashes where the analyst was (api.ts::redirectToLogin) so
// sign-in can put them back. Login used to navigate to /dashboard flatly and
// never read the key, so following a colleague's link to a host page while
// signed out silently became "here is the dashboard" (#84).
describe('Login post-login redirect', () => {
  function mockSignIn() {
    fetchMock.mockImplementation((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/demo-status')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ demo: false }) } as Response);
      }
      if (url.endsWith('/login')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ username: 'ana', role: 'analyst' }),
        } as Response);
      }
      return Promise.reject(new TypeError('offline'));
    });
  }

  async function signIn() {
    mockSignIn();
    renderLogin();
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'ana' } });
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'pw' } });
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));
    await waitFor(() => expect(navigateMock).toHaveBeenCalled());
    return navigateMock.mock.calls[0][0] as string;
  }

  it('returns the analyst to the deep link the 401 captured, and consumes it', async () => {
    sessionStorage.setItem(POST_LOGIN_REDIRECT_KEY, '/app/hosts/198.51.100.5?field=role');
    expect(await signIn()).toBe('/hosts/198.51.100.5?field=role');
    // One sign-in per destination — a stale one must not hijack the next login.
    expect(sessionStorage.getItem(POST_LOGIN_REDIRECT_KEY)).toBeNull();
  });

  it('lands on the dashboard when nothing was captured', async () => {
    expect(await signIn()).toBe('/dashboard');
  });

  it.each([
    ['an absolute URL', 'https://evil.example/app/hosts'],
    ['a protocol-relative URL', '//evil.example/app/hosts'],
    ['a javascript: URL', 'javascript:alert(1)'],
    ['a backslash-smuggled authority', '/\\evil.example/app/hosts'],
    ['a path outside the SPA', '/api/v1/whoami'],
    ['the login screen itself', '/app/login'],
    // react-router matches routes case-insensitively and never sees the
    // fragment, so both of these ARE the login route. A guard that knows only
    // one spelling of it drops the analyst back on the screen they just signed
    // in from — which reads as a sign-in that failed.
    ['the login screen in another case', '/app/LOGIN'],
    ['the login screen with a fragment', '/app/login#back'],
  ])('refuses %s and falls back to the dashboard', async (_label, hostile) => {
    // Both sources of this value (sessionStorage, ?next=) are writable by
    // anyone who can hand the analyst a link, so the guard is an allow-list:
    // an in-app path under the SPA's own prefix, or nothing.
    sessionStorage.setItem(POST_LOGIN_REDIRECT_KEY, hostile);
    expect(await signIn()).toBe('/dashboard');
    // Cleared even when refused — it must not linger for the next sign-in.
    expect(sessionStorage.getItem(POST_LOGIN_REDIRECT_KEY)).toBeNull();
  });
});
