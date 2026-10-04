// The ⌘K palette promised "Search commands, screens, hosts…" but only matched
// its own static command labels — "teardrop" returned No matches while
// "GPL MISC Teardrop attack" sat in the list behind the modal (dogfood
// 2026-07-15). searchEntities matches investigations and alert groups by
// rule-name fragment or IP, case-insensitively.
import { describe, expect, it } from 'vitest';
import { machineHitLabel, searchEntities } from './paletteSearch';
import type { AlertGroup, InvestigationRow, MachineRow } from './types';

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

  // The row read "… — false_positive 0.90 · 16m": a dash and the raw enum.
  it('names the verdict with its label and separates fields with a dot', () => {
    const [hit] = searchEntities('teardrop', [inv({ verdict: 'false_positive', conf: 0.9 })], []);
    expect(hit.label).toContain('· False positive 0.90 ·');
    expect(hit.label).not.toContain('false_positive');
    expect(hit.label).not.toMatch(/[—–]/);
    const [g] = searchEntities('198.51.100.252', [], [grp({})]);
    expect(g.label).not.toMatch(/[—–]/);
  });
});

describe('searchEntities — synthetic-evaluation marker', () => {
  // The palette's corpus is InvestigationRow[], which already carries
  // isSynthEval; a hit's label is the only thing the palette renders, so the
  // marker rides it — the badge's exact wording, never internal vocabulary.
  it('marks a synth-eval run in its label', () => {
    const hits = searchEntities('teardrop', [inv({ isSynthEval: true })], []);
    expect(hits[0].label).toContain('Synthetic evaluation data');
  });

  it('adds no marker to an ordinary run', () => {
    const hits = searchEntities('teardrop', [inv({ isSynthEval: false })], []);
    expect(hits[0].label).not.toContain('Synthetic');
  });
});

describe('machineHitLabel', () => {
  const row = (over: Partial<MachineRow>): MachineRow => ({
    key: 'ip:192.0.2.40',
    href: '/hosts/ip%3A192.0.2.40',
    name: null,
    name_source: null,
    names: [],
    primary_ip: '192.0.2.40',
    address_count: 1,
    addresses: ['192.0.2.40'],
    container_count: 0,
    agent: null,
    role: { value: null, label: null, confidence: null, state: 'unknown', guess: null, stale_hours: null },
    events: 0,
    first_seen: null,
    last_seen: null,
    flags: { declared: false, conflict: false, broken: false, new: false, rebound: false },
    ...over,
  });

  it('reads "<name> · <primary address> · <role>"', () => {
    const label = machineHitLabel(
      row({
        name: 'web01',
        role: { value: 'server', label: 'server', confidence: 0.9, state: 'inferred', guess: null, stale_hours: null },
      }),
    );
    expect(label).toBe('web01 · 192.0.2.40 · server');
  });

  it('leads with the address when the machine has no name, and drops an unknown role', () => {
    expect(machineHitLabel(row({}))).toBe('192.0.2.40');
  });

  it('names a withheld role with its state', () => {
    const label = machineHitLabel(
      row({
        role: { value: null, label: null, confidence: 0.3, state: 'low_confidence', guess: 'hypervisor', stale_hours: null },
      }),
    );
    expect(label).toBe('192.0.2.40 · low confidence: hypervisor');
  });
});
