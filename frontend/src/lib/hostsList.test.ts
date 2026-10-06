// The Hosts list URL: one spelling for the list, the cards and the breadcrumb.
import { beforeEach, describe, expect, it } from 'vitest';
import {
  agentStaleTitle,
  listHref,
  listUrlToReturnTo,
  machineHref,
  machineQuery,
  patchListParams,
  readListState,
  rememberListUrl,
} from './hostsList';

beforeEach(() => sessionStorage.clear());

describe('the list URL', () => {
  it('reads the defaults from a bare URL', () => {
    expect(readListState(new URLSearchParams())).toEqual({
      q: '',
      sort: 'last_seen',
      dir: 'desc',
      role: '',
      agent: '',
      activity: 'active',
      seen: '',
      declared: '',
      page: 1,
    });
  });

  it('round-trips every control', () => {
    const qs = 'q=web01&sort=name&dir=desc&role=server&agent=yes&activity=all&seen=new&declared=no&page=3';
    const state = readListState(new URLSearchParams(qs));
    expect(machineQuery(state)).toEqual({
      q: 'web01',
      sort: 'name',
      dir: 'desc',
      role: 'server',
      agent: 'yes',
      activity: 'all',
      seen: 'new',
      declared: 'no',
      limit: 50,
      offset: 100,
    });
  });

  it('reads a value the API would refuse as the default', () => {
    const state = readListState(new URLSearchParams('sort=importance&dir=up&agent=maybe&page=-2'));
    expect(state).toMatchObject({ sort: 'last_seen', dir: 'desc', agent: '', page: 1 });
  });

  it('resets the page in the same write when anything else changes', () => {
    const next = patchListParams(new URLSearchParams('role=server&page=4'), { q: 'web01' });
    expect(next.toString()).toBe('role=server&q=web01');
    const paged = patchListParams(new URLSearchParams('role=server&page=4'), { page: 5 });
    expect(paged.toString()).toBe('role=server&page=5');
  });

  it('keeps defaults out of the URL', () => {
    expect(patchListParams(new URLSearchParams(), { sort: 'last_seen', dir: 'desc' }).toString()).toBe('');
    expect(patchListParams(new URLSearchParams(), { sort: 'name', dir: 'asc' }).toString()).toBe('sort=name');
    expect(patchListParams(new URLSearchParams(), { sort: 'last_seen', dir: 'asc' }).toString()).toBe('dir=asc');
    expect(patchListParams(new URLSearchParams('activity=all'), { activity: 'active' }).toString()).toBe('');
  });

  it('leaves the keys it does not own alone', () => {
    const next = patchListParams(new URLSearchParams('conflicts=1'), { role: 'server' });
    expect(next.get('conflicts')).toBe('1');
  });

  it('builds a card link over the default list', () => {
    expect(listHref({ agent: 'no', activity: 'all' })).toBe('/hosts?agent=no&activity=all');
    expect(listHref({})).toBe('/hosts');
  });

  it('percent-encodes a machine key in the path', () => {
    expect(machineHref('mac:aa:bb:cc:dd:ee:ff')).toBe('/hosts/mac%3Aaa%3Abb%3Acc%3Add%3Aee%3Aff');
  });
});

describe('the way back', () => {
  it('returns to the remembered list, and to /hosts without one', () => {
    expect(listUrlToReturnTo()).toBe('/hosts');
    rememberListUrl('?role=server');
    expect(listUrlToReturnTo()).toBe('/hosts?role=server');
  });

  it('refuses a stored value that is not the list', () => {
    sessionStorage.setItem('soc-ai:hosts-list:url', '/hosts/agent%3Aa1');
    expect(listUrlToReturnTo()).toBe('/hosts');
    sessionStorage.setItem('soc-ai:hosts-list:url', 'https://example.test/hosts');
    expect(listUrlToReturnTo()).toBe('/hosts');
  });
});

// The list reads the agent state from the last sweep (range dogfood
// 2026-10-05, M5 and C8). A report older than a day is marked.
describe('agentStaleTitle', () => {
  const NOW = Date.now();
  const hoursAgo = (h: number) => new Date(NOW - h * 3_600_000).toISOString();

  it('marks a report older than 24 h and says the sweep is off and when it ran', () => {
    const title = agentStaleTitle(hoursAgo(61), { scheduleEnabled: false, staleHours: 61.4 }, NOW);
    expect(title).toBe(
      'The agent last reported 61 h ago. The list shows the state at the last sweep. ' +
        'Automatic sweeps are off. The last sweep ran 61 h ago. The machine page shows live activity.',
    );
  });

  it('says when the sweep ran and nothing about a schedule that is on', () => {
    const title = agentStaleTitle(hoursAgo(30), { scheduleEnabled: true, staleHours: 2 }, NOW);
    expect(title).toContain('The last sweep ran 2 h ago.');
    expect(title).not.toContain('Automatic sweeps are off.');
  });

  it('marks no report from the last 24 h', () => {
    expect(agentStaleTitle(hoursAgo(23), { scheduleEnabled: false, staleHours: 61 }, NOW)).toBeNull();
    expect(agentStaleTitle(hoursAgo(1), { scheduleEnabled: false, staleHours: 61 }, NOW)).toBeNull();
  });

  it('marks nothing it cannot date', () => {
    expect(agentStaleTitle(null, { scheduleEnabled: false, staleHours: 61 }, NOW)).toBeNull();
    expect(agentStaleTitle('not a time', { scheduleEnabled: false, staleHours: 61 }, NOW)).toBeNull();
  });
});
