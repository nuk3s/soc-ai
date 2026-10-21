// An observation keeps the words of the sweep that wrote it. "3 documents in
// the last 24 h" on an observation 20 days old named a window that ended 20
// days ago (dogfood 2026-10-19, R4-D18). The row anchors the window to the
// time the sweep wrote it.
import { describe, expect, it } from 'vitest';
import { anchoredSummary } from './observationWords';
import { absoluteTime } from './timeRange';

const NOW = Date.parse('2026-10-19T10:00:00Z');
const OLD = '2026-09-29T10:21:00Z';

describe('anchoredSummary', () => {
  it('anchors a relative window of an old observation to its sweep', () => {
    expect(anchoredSummary('new port for this host: 4444. 3 documents in the last 24 h', OLD, NOW)).toBe(
      `new port for this host: 4444. 3 documents in the 24 h before ${absoluteTime(OLD)}`,
    );
    expect(anchoredSummary('The sweep did not see the host in the window', OLD, NOW)).toBe(
      `The sweep did not see the host in the window before ${absoluteTime(OLD)}`,
    );
  });

  it('keeps the words of an observation inside its own window', () => {
    // NEGATIVE CONTROL: a fresh observation reads as written.
    const fresh = new Date(NOW - 2 * 3_600_000).toISOString();
    expect(anchoredSummary('3 documents in the last 24 h', fresh, NOW)).toBe('3 documents in the last 24 h');
    expect(anchoredSummary('a sentence with no window', OLD, NOW)).toBe('a sentence with no window');
    expect(anchoredSummary('3 documents in the last 24 h', null, NOW)).toBe('3 documents in the last 24 h');
  });
});
