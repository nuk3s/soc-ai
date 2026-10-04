// The Hosts list URL: one spelling for the list, the cards and the breadcrumb.
import { beforeEach, describe, expect, it } from 'vitest';
import {
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
