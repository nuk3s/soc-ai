// The ⌘K palette promised "Search commands, screens, hosts…" but only matched
// its own static command labels — "teardrop" returned No matches while
// "GPL MISC Teardrop attack" sat in the list behind the modal (dogfood
// 2026-07-15). searchEntities matches investigations and alert groups by
// rule-name fragment or IP, case-insensitively.
import { describe, expect, it } from 'vitest';
import { searchEntities } from './paletteSearch';
import type { AlertGroup, InvestigationRow } from './types';

const inv = (over: Partial<InvestigationRow>): InvestigationRow =>
  ({
    id: 'INV-1',
    name: 'GPL MISC Teardrop attack',
    kind: 'suricata',
    verdict: 'false_positive',
    conf: 0.95,
    host: '79.127.183.235',
    dst: '192.0.2.119',
    status: 'complete',
    when: '8h ago',
    ...over,
  }) as InvestigationRow;

const grp = (over: Partial<AlertGroup>): AlertGroup =>
  ({
    id: 'es-1',
    name: 'ET USER_AGENTS Steam HTTP Client User-Agent',
    kind: 'suricata',
    sev: 'high',
    count: 9,
    verdict: 'false_positive',
    conf: 0.85,
    latest: '1h ago',
    inherited: false,
    events: [],
    src: '198.51.100.252',
    dst: '23.207.217.29',
    ...over,
  }) as AlertGroup;

describe('searchEntities', () => {
  it('matches an investigation by rule-name fragment, case-insensitively', () => {
    const hits = searchEntities('teardrop', [inv({})], []);
    expect(hits).toHaveLength(1);
    expect(hits[0].group).toBe('Investigations');
    expect(hits[0].to).toBe('/investigation/INV-1');
    expect(hits[0].label).toContain('Teardrop');
  });

  it('matches by IP across investigations and alert groups', () => {
    const hits = searchEntities('198.51.100.252', [inv({ host: '198.51.100.252' })], [grp({})]);
    expect(hits.map((h) => h.group)).toEqual(['Investigations', 'Alerts']);
    expect(hits[1].to).toBe('/alerts');
  });

  it('requires at least two characters and caps results', () => {
    expect(searchEntities('t', [inv({})], [])).toEqual([]);
    const many = Array.from({ length: 20 }, (_, i) => inv({ id: `INV-${i}` }));
    expect(searchEntities('teardrop', many, []).length).toBeLessThanOrEqual(8);
  });

  it('returns nothing for a non-matching query', () => {
    expect(searchEntities('zzz-nope', [inv({})], [grp({})])).toEqual([]);
  });
});
