// Regression tests for the FE3_lib review findings:
//   F42 — EntityGraph node click must pivot on the entity id, not the label.
//   F43 — a mid-session 401 must preserve the analyst's deep link (sessionStorage
//          + ?next=) instead of blindly hard-navigating and losing their place.
//   F63 — dismissNotification must not throw when localStorage writes are blocked.
//
// happy-dom (see vite.config.ts) lets us redefine window.location, which jsdom
// forbids — the 401 path asserts on window.location.href.
import { fireEvent, render } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { getNotifications, POST_LOGIN_REDIRECT_KEY, takePostLoginRedirect } from './api';
import { dismissNotification, getDismissed } from './notifications';

// EntityGraph calls useNavigate() — stub it so we can assert the pivot target.
const navigateMock = vi.fn();
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>();
  return { ...actual, useNavigate: () => navigateMock };
});

// Imported AFTER the mock is registered (vi.mock is hoisted regardless).
import { EntityGraph } from '../components/EntityGraph';
import type { GraphNode } from './types';

describe('EntityGraph node click (F42)', () => {
  afterEach(() => vi.clearAllMocks());

  it('pivots to the entity id, not the display label', () => {
    // Source node: identity is the IP, label is the hostname (host.name case).
    const node: GraphNode = {
      id: '192.0.2.8',
      x: 20,
      y: 50,
      kind: 'host',
      label: 'sensor-host',
    };
    const { container } = render(<EntityGraph nodes={[node]} edges={[]} showLegend={false} />);
    const clickable = container.querySelector('g[style*="cursor"]');
    expect(clickable).not.toBeNull();
    fireEvent.click(clickable as Element);
    expect(navigateMock).toHaveBeenCalledWith('/entity/192.0.2.8');
    expect(navigateMock).not.toHaveBeenCalledWith('/entity/sensor-host');
  });
});

describe('mid-session 401 redirect (F43)', () => {
  const realLocation = window.location;

  function setLocation(pathname: string) {
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { pathname, search: '', hash: '', href: '' },
    });
  }

  beforeEach(() => {
    sessionStorage.clear();
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({ status: 401 } as Response);
  });

  afterEach(() => {
    Object.defineProperty(window, 'location', { configurable: true, value: realLocation });
    vi.restoreAllMocks();
  });

  it('captures the current deep link (sessionStorage + ?next=) before navigating', async () => {
    setLocation('/app/runbooks');
    await expect(getNotifications()).rejects.toThrow('Unauthorized');
    expect(sessionStorage.getItem(POST_LOGIN_REDIRECT_KEY)).toBe('/app/runbooks');
    expect(window.location.href).toBe(
      '/app/login?next=' + encodeURIComponent('/app/runbooks'),
    );
  });

  it('does not re-navigate when already on the login screen', async () => {
    setLocation('/app/login');
    await expect(getNotifications()).rejects.toThrow('Unauthorized');
    expect(window.location.href).toBe('');
    expect(sessionStorage.getItem(POST_LOGIN_REDIRECT_KEY)).toBeNull();
  });

  it('falls back to ?next= when sessionStorage held nothing (#84)', () => {
    // The two sources exist because storage can be blocked; the param is what
    // survives that, and it goes through the same allow-list.
    sessionStorage.clear();
    expect(takePostLoginRedirect('?next=' + encodeURIComponent('/app/investigations'))).toBe(
      '/investigations',
    );
    expect(takePostLoginRedirect('?next=' + encodeURIComponent('https://evil.example/'))).toBeNull();
  });

  it('prefers the stored destination over a ?next= someone appended (#84)', () => {
    sessionStorage.setItem(POST_LOGIN_REDIRECT_KEY, '/app/alerts');
    expect(takePostLoginRedirect('?next=' + encodeURIComponent('/app/config'))).toBe('/alerts');
  });
});

describe('dismissNotification (F63)', () => {
  beforeEach(() => localStorage.clear());
  afterEach(() => vi.restoreAllMocks());

  it('persists a dismissed id when storage works', () => {
    dismissNotification('inv:42');
    expect(getDismissed().has('inv:42')).toBe(true);
  });

  it('does not throw when localStorage writes are blocked', () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('storage blocked', 'SecurityError');
    });
    expect(() => dismissNotification('inv:99')).not.toThrow();
  });
});
