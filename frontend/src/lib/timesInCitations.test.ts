// Dogfood 2026-11-17, F15: evidence chips showed a raw ISO time, and the steps
// of a hunt showed "18:42:01" with no zone. Both read in the UTC form of the
// page.
import { describe, expect, it } from 'vitest';
import { findingCitation } from './citations';
import { stepTimeUtc } from './timeRange';
import { citationWords } from './toolLabels';

describe('the UTC form in citations and steps', () => {
  it('writes the time of a tool citation in the UTC form of the page', () => {
    const raw = 't_query_events zeek.http destination.ip:192.0.2.10 groupby http.uri 2026-11-14T18:47:57Z';
    const words = citationWords(raw);
    expect(words).toContain('2026-11-14 18:47:57 UTC');
    expect(words).not.toContain('T18:47:57Z');
    const chip = findingCitation('t_query_events: zeek.http destination.ip:192.0.2.10 2026-11-14T18:47:57Z');
    expect(chip.kind === 'text' && chip.label).toContain('2026-11-14 18:47:57 UTC');
    // The hover keeps the words the finding wrote.
    expect(chip.kind === 'text' && chip.title).toContain('2026-11-14T18:47:57Z');
  });

  it('writes the time of a query citation in the UTC form of the page', () => {
    const chip = findingCitation('zeek.http groupby http.uri 2026-11-14T18:47:57Z');
    expect(chip.kind === 'text' && chip.label).toBe('zeek.http groupby http.uri 2026-11-14 18:47:57 UTC');
  });

  it('states the zone of a step time', () => {
    expect(stepTimeUtc('18:42:01')).toBe('18:42:01 UTC');
    // Negative controls: no time states no zone, and other text stays.
    expect(stepTimeUtc('')).toBe('');
    expect(stepTimeUtc(undefined)).toBe('');
    expect(stepTimeUtc('2m ago')).toBe('2m ago');
  });

  it('keeps a document id as a document', () => {
    // Negative control: an id with no time and no space opens the document.
    expect(findingCitation('AbCdEf0123456789xyz')).toEqual({ kind: 'document', id: 'AbCdEf0123456789xyz' });
  });
});
