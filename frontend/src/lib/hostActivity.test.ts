// The host page's live half has four states and TWO components rendering them.
// They agreed by coincidence, not by construction, and the drift this codebase
// treats as serious is exactly the one that was available: a strip saying "last
// good read" above a row saying "could not be read". One function decides now,
// and this is what it decides.
import { describe, expect, it } from 'vitest';
import type { HostActivity } from './types';
import { activityState } from './hostActivity';

const DATA: HostActivity = {
  peers: [],
  volume: [],
  users: null,
  alerts_7d: 0,
  latest_investigation: null,
  peers_truncated: false,
  users_truncated: false,
};

describe('activityState', () => {
  it('is loading before anything has arrived', () => {
    expect(activityState(null, null)).toBe('loading');
  });

  it('is ok once the grid has answered', () => {
    expect(activityState(DATA, null)).toBe('ok');
  });

  it('is down when the read failed with nothing to fall back on', () => {
    expect(activityState(null, new Error('grid down'))).toBe('down');
  });

  it('is stale when a refresh failed OVER a good read', () => {
    // The distinction the whole thing exists for: useAsync keeps the last-good
    // data on a foreground failure, so an error beside data means "older than it
    // looks", not "absent".
    expect(activityState(DATA, new Error('grid down'))).toBe('stale');
  });

  it('does not consult the in-flight flag, because it is a different question', () => {
    // A retry over stale data clears `error` and keeps `data`, so the state is
    // already 'ok' while the request is still running; whether a request is in
    // flight governs dimming and disabling, not what the page HAS. Keeping the
    // two apart is what stops a re-read from blanking a populated panel.
    expect(activityState(DATA, null)).toBe('ok');
    expect(activityState(null, null)).toBe('loading');
  });
});
