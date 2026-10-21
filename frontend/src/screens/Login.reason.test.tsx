// Dogfood 2026-10-19 H1-D18 / H1-I8 and H1-D19. A session expiry and a sign
// out both landed on the login page with no reason line, and the page put no
// focus on the Username field.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { getNotifications, signOut } from '../lib/api';
import { hadSession, loginReasonLine, markSignedIn } from '../lib/loginReason';
import { Login } from './Login';

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  vi.stubGlobal(
    'fetch',
    vi.fn(() => Promise.reject(new TypeError('offline'))),
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
  localStorage.clear();
});

const at = (search: string) =>
  render(
    <MemoryRouter initialEntries={[`/login${search}`]}>
      <Login />
    </MemoryRouter>,
  );

describe('loginReasonLine', () => {
  it('says the session ended and names the page to return to', () => {
    expect(loginReasonLine(`?next=${encodeURIComponent('/app/hunts')}&reason=expired`)).toBe(
      'Your session ended. Sign in to return to Hunts.',
    );
    expect(loginReasonLine(`?next=${encodeURIComponent('/app/leads/18')}&reason=expired`)).toBe(
      'Your session ended. Sign in to return to Lead 18.',
    );
    expect(loginReasonLine('?reason=expired')).toBe('Your session ended. Sign in again.');
  });

  it('says the analyst signed out', () => {
    expect(loginReasonLine('?reason=signed-out')).toBe('You signed out.');
  });

  it('names the page of a deep link on a first visit', () => {
    expect(loginReasonLine(`?next=${encodeURIComponent('/app/alerts?range=7d')}`)).toBe(
      'Sign in to open Alerts.',
    );
  });

  it('says nothing for a plain visit or a link out of the console', () => {
    expect(loginReasonLine('')).toBeNull();
    expect(loginReasonLine(`?next=${encodeURIComponent('https://evil.example/')}`)).toBeNull();
    expect(loginReasonLine('?reason=other')).toBeNull();
  });
});

describe('Login reason line', () => {
  it('shows the reason above the form', () => {
    at(`?next=${encodeURIComponent('/app/hunts')}&reason=expired`);
    expect(screen.getByTestId('login-reason').textContent).toBe(
      'Your session ended. Sign in to return to Hunts.',
    );
  });

  it('shows the sign-out line', () => {
    at('?reason=signed-out');
    expect(screen.getByTestId('login-reason').textContent).toBe('You signed out.');
  });

  it('shows no line on a plain visit', () => {
    at('');
    expect(screen.queryByTestId('login-reason')).toBeNull();
  });

  it('puts the focus on the Username field', () => {
    at('');
    expect(document.activeElement).toBe(screen.getByLabelText('Username'));
  });
});

describe('the redirects carry the reason', () => {
  const realLocation = window.location;
  afterEach(() => {
    Object.defineProperty(window, 'location', { configurable: true, value: realLocation });
  });
  const setLocation = (pathname: string) =>
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { pathname, search: '', hash: '', href: '' },
    });

  it('marks a 401 after a sign-in as an ended session', async () => {
    markSignedIn();
    setLocation('/app/hunts');
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({ status: 401 } as Response)));
    await expect(getNotifications()).rejects.toThrow('Unauthorized');
    expect(window.location.href).toBe(
      '/app/login?next=' + encodeURIComponent('/app/hunts') + '&reason=expired',
    );
  });

  it('leaves a first visit without the expiry reason', async () => {
    setLocation('/app/hunts');
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({ status: 401 } as Response)));
    await expect(getNotifications()).rejects.toThrow('Unauthorized');
    expect(window.location.href).toBe('/app/login?next=' + encodeURIComponent('/app/hunts'));
  });

  it('sends a sign out to the login page with its reason', async () => {
    markSignedIn();
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({ ok: true, status: 204, json: () => Promise.resolve({}) } as Response)));
    const navigate = vi.fn();
    await signOut(navigate);
    expect(navigate).toHaveBeenCalledWith('/login?reason=signed-out');
    expect(hadSession()).toBe(false);
  });
});
