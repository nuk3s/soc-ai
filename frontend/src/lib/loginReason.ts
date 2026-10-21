// Why the login page shows. A session expiry and a sign out both landed on
// the login page with no word on why (dogfood 2026-10-19, H1-D18 and H1-I8).
//
// The reason travels in the login URL: `reason=expired` from the 401 handoff
// in lib/api.ts, `reason=signed-out` from signOut. A 401 says "expired" only
// when this browser signed in before. A first visit to a deep link also gets a
// 401, and "Your session ended" would be false there.
import { pageLabel } from '../shell/pages';

const HAD_SESSION_KEY = 'soc-ai:had-session';

/** The base path of the console ('/app'). */
const APP_BASE = import.meta.env.BASE_URL.replace(/\/$/, '');

/** Record that this browser signed in. */
export function markSignedIn(): void {
  try {
    localStorage.setItem(HAD_SESSION_KEY, '1');
  } catch {
    /* storage blocked: a later 401 reads as a first visit */
  }
}

/** Record that the analyst signed out. */
export function markSignedOut(): void {
  try {
    localStorage.removeItem(HAD_SESSION_KEY);
  } catch {
    /* storage blocked */
  }
}

/** True when this browser signed in before and did not sign out. */
export function hadSession(): boolean {
  try {
    return localStorage.getItem(HAD_SESSION_KEY) === '1';
  } catch {
    return false;
  }
}

/** The page a `next` value names, in the console's page words, or null for a
 *  value that is not a console path. */
function nextPage(next: string | null): string | null {
  if (!next || next.startsWith('//') || !next.startsWith(APP_BASE + '/')) return null;
  const path = next.slice(APP_BASE.length);
  if (path.toLowerCase().startsWith('/login')) return null;
  return pageLabel(path) || null;
}

/** The reason line of the login page, from its query string, or null. */
export function loginReasonLine(search: string): string | null {
  const params = new URLSearchParams(search);
  const reason = params.get('reason');
  const page = nextPage(params.get('next'));
  if (reason === 'signed-out') return 'You signed out.';
  if (reason === 'expired') {
    return page ? `Your session ended. Sign in to return to ${page}.` : 'Your session ended. Sign in again.';
  }
  return page ? `Sign in to open ${page}.` : null;
}
