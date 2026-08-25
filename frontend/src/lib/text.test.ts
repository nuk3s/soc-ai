import { describe, expect, it } from 'vitest';
import { middleEllipsis } from './text';

describe('middleEllipsis', () => {
  it('returns short strings unchanged', () => {
    expect(middleEllipsis('GPL ICMP Large ICMP Packet')).toBe('GPL ICMP Large ICMP Packet');
  });
  it('keeps the head AND the differentiating tail of a long rule name', () => {
    const name = "ET INFO Observed Let's Encrypt Certificate from Backup Intermediate, E2 (some very long trailer)";
    const out = middleEllipsis(name, 60);
    expect(out.length).toBeLessThanOrEqual(60);
    expect(out).toContain('…');
    expect(out.startsWith('ET INFO Observed')).toBe(true);
    expect(out.endsWith('long trailer)')).toBe(true);
  });
  it('never emits an ellipsis for a string exactly at the limit', () => {
    const s = 'x'.repeat(72);
    expect(middleEllipsis(s, 72)).toBe(s);
  });
  it('slices over code points, never splitting a surrogate pair', () => {
    const name = 'A'.repeat(10) + '😀'.repeat(40) + 'Z'.repeat(10);
    const out = middleEllipsis(name, 19);
    expect(Array.from(out).length).toBeLessThanOrEqual(19);
    // No lone (unpaired) surrogate — a split pair would render as U+FFFD.
    // eslint-disable-next-line no-misleading-character-class
    expect(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(out)).toBe(false);
  });
});
