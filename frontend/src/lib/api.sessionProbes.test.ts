// The resolve-once /about + /me caches (dogfood 1.3 F19). Every detail screen
// was re-fetching /about on mount just to gate a default-off flag; both
// answers are stable for a session. The cache must:
//  - share ONE fetch across repeated (and concurrent) calls;
//  - be invalidated by a config apply, so a hot flag flip is still honored;
//  - never cache a FAILURE — fail-closed callers hide the feature for that
//    mount, and the next mount deserves a fresh probe.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { getAbout, getMe, invalidateSessionProbes, setMyStatus, setSetting } from './api';

let fetchMock: ReturnType<typeof vi.fn>;

const ok = (body: unknown = {}) =>
  Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) } as Response);

beforeEach(() => {
  // The caches are module-level and this module is shared across the file's
  // tests — start each test from a cold cache.
  invalidateSessionProbes();
  fetchMock = vi.fn(() => ok());
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  invalidateSessionProbes();
  vi.unstubAllGlobals();
});

const aboutBody = (sigmaOn: boolean) => ({
  version: '1.3.0',
  repo_url: 'https://example.test/soc-ai',
  license: 'Apache-2.0',
  update_check_enabled: false,
  sigma_authoring_enabled: sigmaOn,
});

describe('getAbout cache', () => {
  it('fetches /about once and shares the answer across calls', async () => {
    fetchMock.mockImplementation(() => ok(aboutBody(false)));
    const [a, b] = await Promise.all([getAbout(), getAbout()]);
    const c = await getAbout();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(a.sigma_authoring_enabled).toBe(false);
    expect(b).toEqual(a);
    expect(c).toEqual(a);
  });

  it('re-fetches after a config apply, so a hot flag flip is honored', async () => {
    fetchMock.mockImplementation((input: RequestInfo | URL) =>
      String(input).endsWith('/about') ? ok(aboutBody(false)) : ok({ ok: true }),
    );
    expect((await getAbout()).sigma_authoring_enabled).toBe(false);

    // Operator flips the flag; the apply must drop the cached answer.
    fetchMock.mockImplementation((input: RequestInfo | URL) =>
      String(input).endsWith('/about') ? ok(aboutBody(true)) : ok({ ok: true }),
    );
    await setSetting('sigma_authoring_enabled', 'true');
    expect((await getAbout()).sigma_authoring_enabled).toBe(true);
    // 1 initial /about + 1 setSetting POST + 1 fresh /about.
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('does not cache a failed probe — the next call retries', async () => {
    fetchMock.mockImplementation(() => Promise.reject(new TypeError('boom')));
    await expect(getAbout()).rejects.toThrow(/network error/i);

    fetchMock.mockImplementation(() => ok(aboutBody(true)));
    expect((await getAbout()).sigma_authoring_enabled).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

describe('getMe cache', () => {
  it('fetches /me once and shares the answer across calls', async () => {
    fetchMock.mockImplementation(() => ok({ username: 'analyst', role: 'admin', status: '' }));
    await getMe();
    const me = await getMe();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(me.username).toBe('analyst');
  });

  it('re-fetches after a status change, so the account menu never shows the old status', async () => {
    fetchMock.mockImplementation(() => ok({ username: 'analyst', role: 'admin', status: '' }));
    await getMe();

    fetchMock.mockImplementation((input: RequestInfo | URL) =>
      String(input).endsWith('/me')
        ? ok({ username: 'analyst', role: 'admin', status: 'hunting' })
        : ok({ ok: true, status: 'hunting' }),
    );
    await setMyStatus('hunting');
    expect((await getMe()).status).toBe('hunting');
  });
});
