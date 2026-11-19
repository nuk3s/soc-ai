// Dogfood 2026-11-17, N17: the entity page of an external address made a
// request to /hosts/resolve that answered 404. The console asks with
// `empty=true`, the server answers 200 with no key, and the callers read the
// same not-found error as before.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { isNotFound, resolveMachine } from './api';

let fetchMock: ReturnType<typeof vi.fn>;
let body: unknown = null;

beforeEach(() => {
  fetchMock = vi.fn(() =>
    Promise.resolve(new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })),
  );
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('resolveMachine', () => {
  it('asks for an empty answer and reads no key as not found', async () => {
    body = { key: null, primary_ip: null, matched: null };
    const err = await resolveMachine('203.0.113.9').catch((e: unknown) => e);
    expect(isNotFound(err)).toBe(true);
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/hosts/resolve?value=203.0.113.9&empty=true');
  });

  it('resolves a value that names a machine', async () => {
    // Negative control: a machine still resolves.
    body = { key: 'agent:web-1', primary_ip: '192.0.2.10', matched: 'address' };
    await expect(resolveMachine('192.0.2.10')).resolves.toEqual(body);
  });
});
