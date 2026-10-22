// ---------------------------------------------------------------------------
// The tour state: the global opt-out and the version of each tour seen.
//
// A signed-in user keeps it on the server (GET/PUT /api/v1/me/tours), so the
// first sign-in holds across browsers. With authentication off, in the demo,
// or when the server has no user for the request, this browser keeps the same
// object in localStorage under STATE_KEY.
// ---------------------------------------------------------------------------
import type { Tour, ToursState } from './types';

/** The localStorage key of the tour state, when the browser keeps it. */
export const STATE_KEY = 'soc-ai.tours';

/** The automation switch. "1" blocks the auto-start in this browser. It is
 *  separate from the stored opt-out: a test harness sets it, an operator
 *  uses "Turn off tours". */
export const OFF_KEY = 'soc-ai.tours.off';

const TOUR_ID = /^[a-z][a-z0-9-]{0,47}$/;
const MAX_TOURS = 64;
const MAX_VERSION = 10_000;

export function defaultState(): ToursState {
  return { off: false, seen: {} };
}

/** Read any value as a tour state. Never throws. The server applies the same
 *  rules (soc_ai/store/user_tours.py). */
export function sanitizeState(raw: unknown): ToursState {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return defaultState();
  const obj = raw as { off?: unknown; seen?: unknown };
  const seen: Record<string, number> = {};
  if (obj.seen && typeof obj.seen === 'object' && !Array.isArray(obj.seen)) {
    for (const [id, version] of Object.entries(obj.seen as Record<string, unknown>)) {
      if (Object.keys(seen).length >= MAX_TOURS) break;
      if (
        TOUR_ID.test(id) &&
        typeof version === 'number' &&
        Number.isInteger(version) &&
        version >= 0 &&
        version <= MAX_VERSION
      ) {
        seen[id] = version;
      }
    }
  }
  return { off: obj.off === true, seen };
}

/** True when the operator has not seen this version of the tour. */
export function isPending(state: ToursState, tour: Tour): boolean {
  return (state.seen[tour.id] ?? 0) < tour.version;
}

/** The state with the tour marked seen at its current version. */
export function markSeen(state: ToursState, tour: Tour): ToursState {
  if ((state.seen[tour.id] ?? 0) >= tour.version) return state;
  return { ...state, seen: { ...state.seen, [tour.id]: tour.version } };
}

export function readBrowserState(): ToursState {
  try {
    const raw = localStorage.getItem(STATE_KEY);
    return raw ? sanitizeState(JSON.parse(raw)) : defaultState();
  } catch {
    return defaultState();
  }
}

export function writeBrowserState(state: ToursState): boolean {
  try {
    localStorage.setItem(STATE_KEY, JSON.stringify(state));
    return true;
  } catch {
    return false;
  }
}
