// Dogfood 2026-10-19, R2-D14: the action card of an investigation writes to
// Security Onion through executeAction, and that call kept the 20 s read
// budget. A slow ack or escalate then read as "failed" with a Retry while the
// write was still running. Every other Security Onion write waits 90 s and
// says on an abort that the change can still complete.
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import { ackGroup, executeAction, isRequestTimeout, SO_WRITE_TIMEOUT_MS } from './api';

let fetchMock: ReturnType<typeof vi.fn>;
let timeoutSpy: MockInstance<typeof AbortSignal.timeout>;

const ok = (body: unknown = {}) =>
  Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) } as Response);

beforeEach(() => {
  fetchMock = vi.fn(() => ok({ status: 'executed', title: 't', detail: '', error: null }));
  vi.stubGlobal('fetch', fetchMock);
  timeoutSpy = vi.spyOn(AbortSignal, 'timeout');
});

afterEach(() => {
  timeoutSpy.mockRestore();
  vi.unstubAllGlobals();
});

describe('the action card write budget', () => {
  it('waits as long as the group writes do', async () => {
    await executeAction('INV-1', 0, 'alert');
    expect(timeoutSpy.mock.calls[0][0]).toBe(SO_WRITE_TIMEOUT_MS);
  });

  it('says on an abort that the change can still complete', async () => {
    fetchMock.mockImplementation(() =>
      Promise.reject(new DOMException('The operation timed out.', 'TimeoutError')),
    );
    const err = await executeAction('INV-1', 0).catch((e: unknown) => e);
    expect(isRequestTimeout(err)).toBe(true);
    expect((err as Error).message).toMatch(/The change can still complete\./);
  });

  it('NEGATIVE CONTROL: it still posts the scope it was given', async () => {
    await executeAction('INV-1', 2, 'group');
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/investigations/INV-1/actions/2/execute');
    expect(init.body).toBe(JSON.stringify({ scope: 'group' }));
  });

  it('NEGATIVE CONTROL: the group writes keep the same budget', async () => {
    await ackGroup({ name: 'ET SCAN Test', kind: 'suricata' });
    expect(timeoutSpy.mock.calls[0][0]).toBe(SO_WRITE_TIMEOUT_MS);
  });
});
