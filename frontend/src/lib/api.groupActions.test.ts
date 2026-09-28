// Wire contract for the two group-scoped WRITES. The Alerts screen fetches its
// rows and counts through alertQueryParams, which forwards the deep link's OQL
// filter (`q`) — the host page's Alerts KPI narrows the queue to one host with
// it. Acknowledge and Escalate must send the same filter, or the analyst sees
// three events for one host and the write lands on every event of the rule in
// the window, on every host. The backend already accepts and honours `q` on
// both bodies; these tests pin that the client actually sends it.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ackGroup, escalateGroup } from './api';

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
const body = (): Record<string, unknown> =>
  JSON.parse(String(init().body)) as Record<string, unknown>;

const GROUP = { name: 'ET SCAN Nmap', kind: 'suricata' } as const;

describe('ackGroup', () => {
  it('sends the active OQL filter so the write stays scoped to the rows on screen', async () => {
    await ackGroup(GROUP, { range: '24h', q: 'source.ip:10.0.0.5' });
    expect(url()).toBe('/api/v1/alerts/ack-group');
    expect(init().method).toBe('POST');
    expect(body()).toEqual({
      rule_name: 'ET SCAN Nmap',
      kind: 'suricata',
      range: '24h',
      q: 'source.ip:10.0.0.5',
    });
  });

  it('omits q when the queue is unfiltered', async () => {
    await ackGroup(GROUP, { range: '24h', severity: 'high' });
    expect(body()).toEqual({ rule_name: 'ET SCAN Nmap', kind: 'suricata', range: '24h', severity: 'high' });
    expect('q' in body()).toBe(false);
  });

  it('still spells a custom window as from_/to alongside the filter', async () => {
    await ackGroup(GROUP, {
      range: 'custom',
      from: '2026-08-01T00:00',
      to: '2026-08-02T00:00',
      q: 'host.name:web-01',
    });
    expect(body()).toEqual({
      rule_name: 'ET SCAN Nmap',
      kind: 'suricata',
      from_: '2026-08-01T00:00',
      to: '2026-08-02T00:00',
      q: 'host.name:web-01',
    });
  });
});

describe('escalateGroup', () => {
  it('sends the same filter as ackGroup — the two must not diverge', async () => {
    await escalateGroup(GROUP, { range: '7d', severity: 'critical', q: 'source.ip:10.0.0.5' });
    expect(url()).toBe('/api/v1/alerts/escalate-group');
    expect(init().method).toBe('POST');
    expect(body()).toEqual({
      rule_name: 'ET SCAN Nmap',
      kind: 'suricata',
      range: '7d',
      severity: 'critical',
      q: 'source.ip:10.0.0.5',
    });
  });

  it('omits q when the queue is unfiltered', async () => {
    await escalateGroup(GROUP, { range: '7d' });
    expect(body()).toEqual({ rule_name: 'ET SCAN Nmap', kind: 'suricata', range: '7d' });
  });

  it('never forwards hideAcked — the server hard-codes it for writes', async () => {
    await escalateGroup(GROUP, { range: '24h', hideAcked: true, q: 'x:1' });
    expect('hideAcked' in body()).toBe(false);
    expect('hide_acked' in body()).toBe(false);
  });
});
