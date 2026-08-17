// "0 investigated, 91 skipped" told the analyst nothing about WHY (dogfood
// 2026-07-15). The backend has the reasons; this formats them for the panel.
import { describe, expect, it } from 'vitest';
import { formatSkipReasons } from './skipReasons';

describe('formatSkipReasons', () => {
  it('formats known reasons, largest first', () => {
    expect(
      formatSkipReasons({ already_triaged: 80, inherited: 10, running: 1 }),
    ).toBe('80 already triaged · 10 verdict inherited · 1 already running');
  });

  it('passes through unknown codes readably', () => {
    expect(formatSkipReasons({ some_new_code: 3 })).toBe('3 some new code');
  });

  // "no_ip" was RETIRED when the planner stopped dropping alerts with no
  // source/destination IP (autotriage.py::_cluster_events now degrades the key
  // instead). Historical status rows can still carry the code, so it must not
  // vanish or render as a raw snake_case token — the unknown-code fallback is
  // what keeps a retired reason legible.
  it('degrades a retired reason code to the humanized fallback', () => {
    const out = formatSkipReasons({ no_ip: 1 });
    expect(out).toBe('1 no ip');
    expect(out).not.toContain('no IP to investigate');
  });

  it('returns null when there is nothing to explain', () => {
    expect(formatSkipReasons(undefined)).toBeNull();
    expect(formatSkipReasons({})).toBeNull();
    expect(formatSkipReasons({ inherited: 0 })).toBeNull();
  });
});
