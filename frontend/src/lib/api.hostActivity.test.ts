// The host page fetches identity and activity SEPARATELY on purpose: the
// dossier keeps answering while Security Onion is down, and this endpoint
// cannot. That split only pays off if this client spells the contract exactly —
// a `range` the server does not accept is a 422 the page would render as "this
// host did nothing", and a `users: null` flattened to `[]` on the way in would
// turn "we hold no host logs for this address" into "nobody logged in". Those
// are the two mistakes pinned here.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { getHostActivity } from './api';
import type { HostActivity } from './types';

let fetchMock: ReturnType<typeof vi.fn>;

const ok = (body: unknown = {}) =>
  Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) } as Response);

beforeEach(() => {
  fetchMock = vi.fn(() => ok());
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const url = (): string => String(fetchMock.mock.calls[0][0]);
const init = (): RequestInit => fetchMock.mock.calls[0][1] as RequestInit;

describe('getHostActivity', () => {
  it('asks the host activity sub-resource for the named window', async () => {
    await getHostActivity('192.168.10.202', '7d');
    expect(url()).toBe('/api/v1/dossiers/192.168.10.202/activity?range=7d');
  });

  it('defaults to the 24h window rather than leaving the server to guess', async () => {
    // The server's default is 24h too, but the bucket width of the volume chart
    // is derived from `range` — sending it always keeps the request and the
    // rendered chart describing the same window.
    await getHostActivity('192.168.10.202');
    expect(url()).toBe('/api/v1/dossiers/192.168.10.202/activity?range=24h');
  });

  it('escapes the address segment instead of forging a path', async () => {
    await getHostActivity('../refresh', '24h');
    expect(url()).toBe('/api/v1/dossiers/..%2Frefresh/activity?range=24h');
  });

  it('reads with the shared request helper, so it carries the client timeout', async () => {
    // A hung grid must not hold a browser connection open indefinitely — that is
    // what froze unrelated widgets in the 2026-08-05 dogfood.
    await getHostActivity('192.168.10.202');
    expect(init().method).toBeUndefined();
    expect(init().signal).toBeInstanceOf(AbortSignal);
  });

  it('parses peers, volume and users off the wire unchanged', async () => {
    fetchMock.mockReturnValue(
      ok({
        peers: [
          { ip: '192.168.10.1', hostname: 'gw', direction: 'both', ports: [53, 443], events: 1200, alerted: false },
          { ip: '198.51.100.7', hostname: null, direction: 'out', ports: [443], events: 4, alerted: true },
        ],
        volume: [
          { ts: '2026-08-07T08:00:00Z', events: 900 },
          { ts: '2026-08-07T09:00:00Z', events: 304 },
        ],
        users: [{ name: 'svc-backup', events: 12, last_seen: '2026-08-07T09:12:00Z' }],
        alerts_7d: 3,
        latest_investigation: { id: 'inv-1', verdict: 'false_positive', ts: '2026-08-06T22:00:00Z' },
        peers_truncated: true,
        users_truncated: false,
      }),
    );
    const activity: HostActivity = await getHostActivity('192.168.10.202', '24h');
    expect(activity.peers.length).toBe(2);
    expect(activity.peers[1].alerted).toBe(true);
    expect(activity.peers[1].hostname).toBeNull();
    expect(activity.peers[0].ports).toEqual([53, 443]);
    expect(activity.volume[1]).toEqual({ ts: '2026-08-07T09:00:00Z', events: 304 });
    expect(activity.users?.[0].name).toBe('svc-backup');
    expect(activity.alerts_7d).toBe(3);
    expect(activity.latest_investigation?.id).toBe('inv-1');
    // The truncation flags ride through untouched — the footnotes read THEM,
    // never a re-inferred length comparison.
    expect(activity.peers_truncated).toBe(true);
    expect(activity.users_truncated).toBe(false);
  });

  it('keeps a null users list null rather than folding it into an empty one', async () => {
    // "The grid holds no host-log authentication documents for this address" is
    // a different answer from "nobody logged in", and only the null carries it.
    fetchMock.mockReturnValue(
      ok({ peers: [], volume: [], users: null, alerts_7d: 0, latest_investigation: null }),
    );
    const activity = await getHostActivity('192.168.10.202');
    expect(activity.users).toBeNull();
    expect(activity.latest_investigation).toBeNull();
  });

  it('keeps a still-running investigation, whose verdict has not landed yet', async () => {
    fetchMock.mockReturnValue(
      ok({
        peers: [],
        volume: [],
        users: null,
        alerts_7d: 1,
        latest_investigation: { id: 'inv-2', verdict: null, ts: '2026-08-07T09:30:00Z' },
      }),
    );
    const activity = await getHostActivity('192.168.10.202');
    expect(activity.latest_investigation?.verdict).toBeNull();
  });

  it('rejects with the grid-unavailable hint so the page can degrade one half', async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      status: 503,
      statusText: 'Service Unavailable',
      json: () =>
        Promise.resolve({
          detail: {
            reason: 'grid_unavailable',
            hint: 'The Security Onion grid (Elasticsearch) is slow or unreachable — retry shortly.',
          },
        }),
    } as Response);
    await expect(getHostActivity('192.168.10.202')).rejects.toThrow(/slow or unreachable/);
  });
});
