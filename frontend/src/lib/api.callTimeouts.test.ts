// Per-call budgets (dogfood 2026-10-01). The 20 s default cut short calls the
// server was still working on: the audit chain verify (33 to 77 s), the model
// fitness check (26 to 53 s), and Security Onion writes on a slow grid, which
// landed 60 to 75 s after the console had already called them failed.
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest';
import {
  RequestTimeoutError,
  ackEvents,
  ackGroup,
  assignAlert,
  bulkSetDossierOverride,
  escalateGroup,
  getAlerts,
  getModelFitness,
  huntLead,
  isRequestTimeout,
  promoteFinding,
  promoteLead,
  startHunt,
  startHuntConsole,
  verifyAuditChain,
} from './api';

let fetchMock: ReturnType<typeof vi.fn>;
let timeoutSpy: MockInstance<typeof AbortSignal.timeout>;

const ok = (body: unknown = {}) =>
  Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) } as Response);

beforeEach(() => {
  fetchMock = vi.fn(() => ok({ investigation_id: 'INV-1' }));
  vi.stubGlobal('fetch', fetchMock);
  timeoutSpy = vi.spyOn(AbortSignal, 'timeout');
});

afterEach(() => {
  timeoutSpy.mockRestore();
  vi.unstubAllGlobals();
});

const budget = (): number => timeoutSpy.mock.calls[0][0];
const G = { name: 'ET SCAN Test', kind: 'suricata' as const };

describe('call budgets', () => {
  it.each([
    ['ack-group', () => ackGroup(G)],
    ['ack-events', () => ackEvents(['ev-1'])],
    ['escalate-group', () => escalateGroup(G)],
    ['assign', () => assignAlert('ET SCAN Test')],
    ['release', () => assignAlert('ET SCAN Test', true)],
    ['bulk declare', () => bulkSetDossierOverride(['192.0.2.1'], { field: 'role', value: 'server' } as never)],
  ])('a Security Onion write (%s) waits 90 s', async (_name, call) => {
    await call();
    expect(budget()).toBe(90_000);
  });

  it.each([
    ['POST /hunt', () => startHunt('ev-1')],
    ['finding promote', () => promoteFinding('H-1', 1)],
    ['lead promote', () => promoteLead(7)],
    ['lead hunt start', () => huntLead(7)],
    ['console hunt start', () => startHuntConsole('Look for beacons')],
  ])('a run start (%s) waits 60 s', async (_name, call) => {
    await call();
    expect(budget()).toBe(60_000);
  });

  it('the audit chain verify waits 150 s', async () => {
    await verifyAuditChain();
    expect(budget()).toBe(150_000);
  });

  it.each([false, true])('the model fitness check (force=%s) waits 90 s', async (force) => {
    await getModelFitness(force);
    expect(budget()).toBe(90_000);
  });

  it('NEGATIVE CONTROL: a plain read keeps the 20 s default', async () => {
    await getAlerts();
    expect(budget()).toBe(20_000);
  });
});

describe('the abort message', () => {
  const abort = () => {
    fetchMock.mockImplementation(() =>
      Promise.reject(new DOMException('The operation timed out.', 'TimeoutError')),
    );
  };

  it('a write abort says the change may still land, not that it failed', async () => {
    abort();
    const err = await escalateGroup(G).catch((e: unknown) => e);
    expect(isRequestTimeout(err)).toBe(true);
    expect((err as RequestTimeoutError).timeoutMs).toBe(90_000);
    expect((err as Error).message).toBe(
      'The request did not return in 90 s. The grid is slow. The change may still land. Check the row in a minute.',
    );
  });

  it('a read abort names its own budget', async () => {
    abort();
    const err = await verifyAuditChain().catch((e: unknown) => e);
    expect(isRequestTimeout(err)).toBe(true);
    expect((err as Error).message).toMatch(/^The request did not return in 150 s\. /);
  });

  it('NEGATIVE CONTROL: a network error is not a timeout', async () => {
    fetchMock.mockImplementation(() => Promise.reject(new TypeError('Failed to fetch')));
    const err = await escalateGroup(G).catch((e: unknown) => e);
    expect(isRequestTimeout(err)).toBe(false);
  });
});
