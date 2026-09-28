// Sign out against a backend that accepts the connection and never answers —
// the hung-Elasticsearch case request() documents and bounds with a 20s
// budget. logout() went to fetch directly, without that budget, and signOut
// only navigates to /login once logout settles: with the account menu already
// closed, the click did nothing for as long as the server stayed silent, and
// the session cookie stayed alive. Both tests stand in an already-aborted
// timeout signal for AbortSignal.timeout — fake timers do not drive it — so a
// call that carries the signal settles at once and one that does not hangs.
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { logout, signOut } from './api';

let fetchMock: ReturnType<typeof vi.fn>;
let timeoutSpy: MockInstance<typeof AbortSignal.timeout>;

/** A server that never replies: the request ends only when the caller aborts it. */
const silentServer = (_url: unknown, init?: RequestInit): Promise<Response> =>
  init?.signal?.aborted
    ? Promise.reject(new DOMException('aborted', 'AbortError'))
    : new Promise<Response>(() => {});

/** Bounds a promise that may never settle, so a regression fails fast. */
const within = <T,>(p: Promise<T>, ms = 50): Promise<T | 'hung'> =>
  Promise.race([p, new Promise<'hung'>((r) => setTimeout(() => r('hung'), ms))]);

beforeEach(() => {
  fetchMock = vi.fn(silentServer);
  vi.stubGlobal('fetch', fetchMock);
  timeoutSpy = vi.spyOn(AbortSignal, 'timeout').mockReturnValue(AbortSignal.abort());
});

afterEach(() => {
  timeoutSpy.mockRestore();
  vi.unstubAllGlobals();
});

describe('logout', () => {
  it('gives the request the same 20s budget as every other JSON call', async () => {
    expect(await within(logout())).not.toBe('hung');
    expect(timeoutSpy).toHaveBeenCalledWith(20_000);
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(init.signal?.aborted).toBe(true);
    expect(init.method).toBe('POST');
    expect(init.credentials).toBe('include');
  });
});

describe('signOut', () => {
  it('still lands on /login when the backend never answers', async () => {
    const navigate = vi.fn();
    expect(await within(signOut(navigate))).not.toBe('hung');
    expect(navigate).toHaveBeenCalledWith('/login');
  });
});
