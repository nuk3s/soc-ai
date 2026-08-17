// The saved-view endpoints are the ONE part of the API a signed-out caller is
// expected to be refused by, and that refusal must not be read as "your session
// expired".
//
// /api/v1/me/views 401s whenever there is no user row — which is the steady
// state of an API_AUTH_REQUIRED=false deployment (the Render demo pins exactly
// that, and every hermetic instance boots that way). The global 401 handler
// treated it like any other expiry and sent the browser to /app/login, so
// Alerts, Investigations, Hunts and Hosts — all four of which fetch saved views
// on mount — bounced to a login page nobody could sign in to, while
// Notifications (which fetches none) stayed usable. Verified live: on a no-auth
// instance /api/v1/notifications answers 200 and /api/v1/me/views answers 401
// {reason: 'no_session'}.
//
// So these three calls opt out of the redirect and surface the refusal as a
// normal ApiError instead; useSavedViews already knows to drop its controls on
// one. A real mid-session expiry is still caught — every other polled endpoint
// (the Topbar's 15s /notifications poll included) keeps the global handler.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ApiError,
  POST_LOGIN_REDIRECT_KEY,
  deleteSavedView,
  getNotifications,
  listSavedViews,
  saveView,
} from './api';

const realLocation = window.location;

function setLocation(pathname: string) {
  Object.defineProperty(window, 'location', {
    configurable: true,
    value: { pathname, search: '', hash: '', href: '' },
  });
}

/** A 401 in the house error shape, as routes_meta._require_user sends it. */
function noSession(): Response {
  return {
    ok: false,
    status: 401,
    statusText: 'Unauthorized',
    json: async () => ({
      detail: { reason: 'no_session', hint: 'Saved views belong to a signed-in user.' },
    }),
  } as unknown as Response;
}

beforeEach(() => {
  sessionStorage.clear();
  setLocation('/app/investigations');
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(noSession());
});

afterEach(() => {
  Object.defineProperty(window, 'location', { configurable: true, value: realLocation });
  vi.restoreAllMocks();
});

describe('a 401 from /me/views does not bounce the SPA to login', () => {
  it('rejects listSavedViews with an ApiError and leaves the analyst where they are', async () => {
    const err = await listSavedViews('investigations').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(401);
    // The machine-readable code, so callers branch on it instead of the prose.
    expect((err as ApiError).reason).toBe('no_session');
    expect(window.location.href).toBe('');
    expect(sessionStorage.getItem(POST_LOGIN_REDIRECT_KEY)).toBeNull();
  });

  it('rejects saveView with an ApiError instead of navigating', async () => {
    const err = await saveView('hunts', 'Beacons', { verdict: ['true_positive'] }).catch(
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(401);
    expect(window.location.href).toBe('');
  });

  it('rejects deleteSavedView with an ApiError instead of navigating', async () => {
    const err = await deleteSavedView(7).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(401);
    expect(window.location.href).toBe('');
  });
});

describe('every other endpoint keeps the global 401 handoff', () => {
  it('still sends an expired session to login, deep link and all', async () => {
    // The opt-out is scoped to saved views. Widening it would turn a real
    // mid-session expiry into a screen full of silent errors.
    await expect(getNotifications()).rejects.toThrow('Unauthorized');
    expect(window.location.href).toBe(
      '/app/login?next=' + encodeURIComponent('/app/investigations'),
    );
    expect(sessionStorage.getItem(POST_LOGIN_REDIRECT_KEY)).toBe('/app/investigations');
  });
});
