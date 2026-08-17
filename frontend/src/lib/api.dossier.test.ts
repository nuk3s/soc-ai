// The dossier keeps two physically separate lanes per field, and these eight
// helpers are the only place the SPA spells the wire contract that keeps them
// apart. Both ways of getting it wrong look like DATA rather than like a bug: a
// mistyped query param quietly returns the whole network instead of the filtered
// slice, and a mutation posted one path segment off is a 404 the operator reads
// as "no dossier for this host". So the URLs, the methods and the bodies are
// pinned here rather than left to whichever screen calls them.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  clearDossierOverride,
  getDossier,
  getDossierConflicts,
  getDossierRefreshStatus,
  listDossiers,
  setDossierOverride,
  snoozeDossierConflict,
  startDossierRefresh,
} from './api';

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

/** The path the one call under test asked for. */
const url = (): string => String(fetchMock.mock.calls[0][0]);
const init = (): RequestInit => fetchMock.mock.calls[0][1] as RequestInit;
/** Query params of that path, order-insensitively (insertion order is not a contract). */
const params = (): URLSearchParams => new URL(url(), 'http://console.invalid').searchParams;
const body = (): unknown => JSON.parse(String(init().body));

describe('listDossiers', () => {
  it('asks for the bare collection when nothing is filtered', async () => {
    await listDossiers();
    // No trailing "?" — the backend treats absent and empty differently for `q`,
    // and a naked question mark is the kind of thing a proxy log makes you chase.
    expect(url()).toBe('/api/v1/dossiers');
  });

  it('carries every filter, page bound and sort key as a query param', async () => {
    await listDossiers({ q: '10.9.8', role: 'hypervisor', source: 'operator', limit: 25, offset: 50, sort: 'stale' });
    expect(url().startsWith('/api/v1/dossiers?')).toBe(true);
    const p = params();
    expect(p.get('q')).toBe('10.9.8');
    expect(p.get('role')).toBe('hypervisor');
    expect(p.get('source')).toBe('operator');
    expect(p.get('limit')).toBe('25');
    expect(p.get('offset')).toBe('50');
    expect(p.get('sort')).toBe('stale');
  });

  it('spells the attention sort and the broken-builds filter the way the server does', async () => {
    // The hosts-kpi contract: `sort=attention` is the list's new default order
    // (broken builds, then open conflicts, then declared, then named, then the
    // rest), and `health=broken` filters to the same set the "never built or
    // errored" count describes. Both are spelled HERE and nowhere else — a
    // mistyped param would be silently ignored server-side and return the whole
    // network wearing a "broken builds" label.
    await listDossiers({ sort: 'attention', health: 'broken' });
    const p = params();
    expect(p.get('sort')).toBe('attention');
    expect(p.get('health')).toBe('broken');
  });

  it('drops an empty search but keeps an explicit offset of 0', async () => {
    // An empty search box is "no filter", not "match the empty string". Offset 0
    // is a real page (the first one) — dropping it as falsy is how a pager that
    // pages forward can never page back to the top.
    await listDossiers({ q: '', offset: 0 });
    const p = params();
    expect(p.has('q')).toBe(false);
    expect(p.get('offset')).toBe('0');
  });
});

describe('reads', () => {
  it('encodes the host key into the detail path', async () => {
    await getDossier('192.168.10.8');
    expect(url()).toBe('/api/v1/dossiers/192.168.10.8');
  });

  it('escapes a segment that is not an address instead of forging a path', async () => {
    // The route 404s a non-IP on purpose; it must reach the route to do that,
    // not get re-parsed into some other resource on the way.
    await getDossier('../refresh');
    expect(url()).toBe('/api/v1/dossiers/..%2Frefresh');
  });

  it('reads conflicts from their own collection path', async () => {
    await getDossierConflicts();
    // Declared BEFORE /dossiers/{ip} server-side; a client that spelled this as
    // an ip would be asking for a host called "conflicts".
    expect(url()).toBe('/api/v1/dossiers/conflicts');
  });

  it('passes a caller-set page bound to the conflicts list', async () => {
    await getDossierConflicts(5);
    expect(url()).toBe('/api/v1/dossiers/conflicts?limit=5');
  });
});

describe('operator lane', () => {
  it('declares a scalar field with a JSON POST', async () => {
    await setDossierOverride('192.168.10.8', { field: 'role', value: 'hypervisor', note: 'it is a PVE node' });
    expect(url()).toBe('/api/v1/dossiers/192.168.10.8/override');
    expect(init().method).toBe('POST');
    expect((init().headers as Record<string, string>)['Content-Type']).toBe('application/json');
    expect(body()).toEqual({ field: 'role', value: 'hypervisor', note: 'it is a PVE node' });
  });

  it('sends value_json alone for a structured field, with no empty scalar beside it', async () => {
    // services_offered / activity_profile / management_plane are declared through
    // value_json. Sending `value: ""` alongside would be a blank string the server
    // refuses, turning a legitimate structured override into a 400.
    await setDossierOverride('192.168.10.8', {
      field: 'services_offered',
      value_json: { tcp: [22, 8006] },
    });
    expect(body()).toEqual({ field: 'services_offered', value_json: { tcp: [22, 8006] } });
  });

  it('accepts the inference by DELETEing the field override', async () => {
    await clearDossierOverride('192.168.10.8', 'role');
    expect(url()).toBe('/api/v1/dossiers/192.168.10.8/override/role');
    expect(init().method).toBe('DELETE');
  });

  it('keeps the operator value by snoozing the conflict', async () => {
    await snoozeDossierConflict('192.168.10.8', 'os_family');
    expect(url()).toBe('/api/v1/dossiers/192.168.10.8/conflicts/os_family/snooze');
    expect(init().method).toBe('POST');
  });
});

describe('refresh', () => {
  it('starts a sweep with POST and polls the same path with GET', async () => {
    await startDossierRefresh();
    expect(url()).toBe('/api/v1/dossiers/refresh');
    expect(init().method).toBe('POST');

    fetchMock.mockClear();
    await getDossierRefreshStatus();
    expect(url()).toBe('/api/v1/dossiers/refresh');
    // No method at all — the shared request() default. Spelling GET here would
    // still work, but the poll and the start would stop being distinguishable
    // in a test that only looks at the path.
    expect(init().method).toBeUndefined();
  });
});

describe('errors', () => {
  it('rejects with the server hint so a 409 reads as a reason, not a status line', async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      status: 409,
      statusText: 'Conflict',
      json: () =>
        Promise.resolve({ detail: { reason: 'no_open_conflict', hint: "nothing currently disagrees with the 'role' override" } }),
    } as Response);
    await expect(snoozeDossierConflict('192.168.10.8', 'role')).rejects.toThrow(
      "nothing currently disagrees with the 'role' override",
    );
  });
});
