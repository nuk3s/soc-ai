// Wire contract for the window of the alert reads. A custom window travels as
// range=custom with both bounds. The client sent the bounds alone, and the
// alerts route read the default 24 hours for the verdict counts of each group
// while the grid read the custom window (2026-10-14).
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { getAlertGroupEvents, getAlerts, listInvestigations } from './api';
import { rangeToSinceUntil } from './timeRange';

let fetchMock: ReturnType<typeof vi.fn>;

const ok = (body: unknown) =>
  Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) } as Response);

beforeEach(() => {
  fetchMock = vi.fn(() => ok({ groups: [], truncated: false, other_docs: 0 }));
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const params = (): URLSearchParams => new URL(String(fetchMock.mock.calls[0][0]), 'http://x').searchParams;

describe('the window of the alert reads', () => {
  it('sends a custom window as range=custom with both bounds', async () => {
    await getAlerts({ range: 'custom', from: '2026-10-01T00:00', to: '2026-10-02T00:00' });
    const p = params();
    expect(p.get('range')).toBe('custom');
    // The bounds name their zone. The picker gives a browser wall time.
    expect(p.get('from')).toBe(new Date('2026-10-01T00:00').toISOString());
    expect(p.get('to')).toBe(new Date('2026-10-02T00:00').toISOString());
  });

  it('sends the alert bounds and the investigation bounds as one instant (R1-D8)', async () => {
    // The alert read sent the bare wall time, which the server read in
    // so_timezone, and the investigation read sent UTC. One custom window
    // counted two spans when the browser and the grid sat in two zones.
    const custom = { from: '2026-10-08T00:00', to: '2026-10-09T00:00' };
    await getAlerts({ range: 'custom', ...custom });
    fetchMock.mockImplementation(() => ok({ rows: [], total: 0 }));
    await listInvestigations(rangeToSinceUntil('custom', custom));
    const alertParams = params();
    const invParams = new URL(String(fetchMock.mock.calls[1][0]), 'http://x').searchParams;
    expect(alertParams.get('from')).toBe(invParams.get('since'));
    expect(alertParams.get('to')).toBe(invParams.get('until'));
    expect(alertParams.get('from')).toMatch(/Z$/);
  });

  it('keeps a bound that already names its zone', async () => {
    await getAlerts({ range: 'custom', from: '2026-10-01T00:00:00+02:00', to: '2026-10-02T00:00:00Z' });
    const p = params();
    expect(p.get('from')).toBe('2026-10-01T00:00:00+02:00');
    expect(p.get('to')).toBe('2026-10-02T00:00:00Z');
  });

  it('sends a preset window as the preset alone', async () => {
    // NEGATIVE CONTROL. A preset has no bounds to send.
    await getAlerts({ range: '7d' });
    const p = params();
    expect(p.get('range')).toBe('7d');
    expect(p.has('from')).toBe(false);
    expect(p.has('to')).toBe(false);
  });

  it('sends the same custom window for the events of a group', async () => {
    fetchMock.mockImplementation(() => ok([]));
    await getAlertGroupEvents({ name: 'ET SCAN Nmap', kind: 'suricata' }, {
      range: 'custom',
      from: '2026-10-01T00:00',
      to: '2026-10-02T00:00',
    });
    const p = params();
    expect(p.get('range')).toBe('custom');
    expect(p.get('from')).toBe(new Date('2026-10-01T00:00').toISOString());
  });
});
