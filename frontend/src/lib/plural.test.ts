import { describe, expect, it } from 'vitest';
import { plural } from './plural';

describe('plural', () => {
  it('agrees with a count of one', () => {
    expect(plural(1, 'investigation')).toBe('1 investigation');
    expect(plural(1, 'detection')).toBe('1 detection');
  });

  it('pluralises everything else, zero included', () => {
    expect(plural(0, 'investigation')).toBe('0 investigations');
    expect(plural(2, 'host')).toBe('2 hosts');
  });

  it('takes an irregular plural', () => {
    expect(plural(1, 'true positive')).toBe('1 true positive');
    expect(plural(3, 'entry', 'entries')).toBe('3 entries');
  });

  it('groups thousands, because these counts get large', () => {
    expect(plural(12345, 'event')).toBe('12,345 events');
  });
});
