// "0 investigated, 91 skipped" told the analyst nothing about WHY (dogfood
// 2026-07-15). The backend has the reasons; this formats them for the panel.
import { describe, expect, it } from 'vitest';
import { formatSkipReasons } from './skipReasons';

describe('formatSkipReasons', () => {
  it('formats known reasons, largest first', () => {
    expect(
      formatSkipReasons({ already_triaged: 80, inherited: 10, no_ip: 1 }),
    ).toBe('80 already triaged · 10 verdict inherited · 1 no IP to investigate');
  });

  it('passes through unknown codes readably', () => {
    expect(formatSkipReasons({ some_new_code: 3 })).toBe('3 some new code');
  });

  it('returns null when there is nothing to explain', () => {
    expect(formatSkipReasons(undefined)).toBeNull();
    expect(formatSkipReasons({})).toBeNull();
    expect(formatSkipReasons({ inherited: 0 })).toBeNull();
  });
});
