// Wire contract for the promotion endpoint: POST a finding's ordinal within its
// hunt and the server returns the (possibly pre-existing) investigation id.
// Pinned here — same style as api.dossier.test.ts — so a mistyped path segment
// or a swapped verb reads as a failing test, not a 404 an analyst hits later.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { getHunts, promoteFinding } from './api';

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

describe('promoteFinding', () => {
  it('POSTs to the hunt finding investigate path and passes the response through', async () => {
    fetchMock = vi.fn(() => ok({ investigation_id: 'inv-1', existing: true }));
    vi.stubGlobal('fetch', fetchMock);

    const result = await promoteFinding('01HUNTX', 2);

    expect(url()).toBe('/api/v1/hunts/01HUNTX/findings/2/investigate');
    expect(init().method).toBe('POST');
    expect(result).toEqual({ investigation_id: 'inv-1', existing: true });
  });

  it('URL-encodes a hostile hunt id rather than forging a path', async () => {
    await promoteFinding('a/b', 0);
    expect(url()).toBe('/api/v1/hunts/a%2Fb/findings/0/investigate');
  });
});

// The Hunts screen sends `kind` when a chip other than All is active, so the
// table is the server's answer rather than a slice of the capped page. The
// default request must not change shape — an unrequested param is the kind of
// thing an older backend rejects with a 422.
describe('getHunts kind param', () => {
  it('sends no kind param unless one is given', async () => {
    await getHunts({ since: '2026-09-05T00:00:00Z' });
    expect(url()).toBe('/api/v1/hunts?since=2026-09-05T00%3A00%3A00Z');
  });

  it('threads kind into the query string when given', async () => {
    await getHunts({ kind: 'triggered' });
    expect(url()).toBe('/api/v1/hunts?kind=triggered');
  });
});
