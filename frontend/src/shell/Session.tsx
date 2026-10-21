import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { ApiError, PASSWORD_CHANGED_EVENT, getMe } from '../lib/api';
import type { Me } from '../lib/types';

/**
 * The shell's auth gate.
 *
 * `pending`  /me has not answered yet, or it answered 401 and the login
 *            redirect is in flight. The shell renders its frame and NOTHING
 *            that reads a protected endpoint.
 * `ready`    /me answered (signed in, auth off, bearer token), or it failed for
 *            a reason other than 401. A down API must not lock the shell: the
 *            degraded surfaces need to mount to say so.
 *
 * Before this gate an unauthenticated visit to /app/hosts fired ten protected
 * GETs, each a 401 in the console, and Back after sign-out fired 24, all before
 * the first 401 navigated away (dogfood 2026-10-01, D14).
 */
export type SessionStatus = 'pending' | 'ready';

interface SessionState {
  status: SessionStatus;
  /** Null until /me answers, and when it failed for a non-401 reason. */
  me: Me | null;
  /** Read /me again. A password change calls it, so the shell banner for the
   *  generated password hides (H1-D5). The status stays `ready`. */
  refresh: () => void;
}

const Ctx = createContext<SessionState | null>(null);

// Outside a SessionProvider (unit tests that mount one shell piece) the shell
// runs ungated, the way it did before the gate existed.
const UNGATED: SessionState = { status: 'ready', me: null, refresh: () => {} };

function isUnauthorized(e: unknown): boolean {
  if (e instanceof ApiError) return e.status === 401;
  // request() navigates to login on a 401 and throws this plain Error.
  return e instanceof Error && e.message === 'Unauthorized';
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<Omit<SessionState, 'refresh'>>({ status: 'pending', me: null });
  // Bumped to read /me again. The first read opens the gate. A later read
  // keeps the gate open and keeps the last answer when it fails.
  const [reads, setReads] = useState(0);
  const refresh = useCallback(() => setReads((n) => n + 1), []);
  useEffect(() => {
    let alive = true;
    getMe()
      .then((me) => {
        if (alive) setState({ status: 'ready', me });
      })
      .catch((e: unknown) => {
        if (!alive) return;
        // A 401 leaves the gate shut: the redirect to login is already running.
        if (isUnauthorized(e)) return;
        setState((s) => (s.status === 'pending' ? { status: 'ready', me: null } : s));
      });
    return () => {
      alive = false;
    };
  }, [reads]);
  // A password change anywhere in the console changes password_is_generated.
  useEffect(() => {
    window.addEventListener(PASSWORD_CHANGED_EVENT, refresh);
    return () => window.removeEventListener(PASSWORD_CHANGED_EVENT, refresh);
  }, [refresh]);
  const value = useMemo(() => ({ ...state, refresh }), [state, refresh]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSession(): SessionState {
  return useContext(Ctx) ?? UNGATED;
}

/** True when /me says no user row stands behind this session: auth is off, or
 *  the caller is a bearer token. Undefined `signed_in` (an older backend) reads
 *  as signed in, so nothing disappears on a mixed deploy. */
export function isSignedOut(me: Me | null): boolean {
  return me?.signed_in === false;
}
