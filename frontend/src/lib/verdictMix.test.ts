// Pins the promotion panel's verdict-mix display contract: zero buckets are
// omitted (never "0 TP" noise), bucket order is FP > TP > NMI, and all-zero
// input degrades honestly instead of rendering an empty string.
import { describe, expect, it } from 'vitest';
import { dominantVerdictLabel, formatVerdictMix } from './verdictMix';

describe('formatVerdictMix', () => {
  it('joins non-zero buckets in FP > TP > NMI order', () => {
    expect(
      formatVerdictMix({ false_positive: 8, true_positive: 1, needs_more_info: 2 }),
    ).toBe('8 FP · 1 TP · 2 NMI');
  });

  it('omits zero buckets entirely', () => {
    expect(
      formatVerdictMix({ false_positive: 8, true_positive: 0, needs_more_info: 0 }),
    ).toBe('8 FP');
    expect(
      formatVerdictMix({ false_positive: 0, true_positive: 3, needs_more_info: 1 }),
    ).toBe('3 TP · 1 NMI');
  });

  it('degrades honestly on all-zero input', () => {
    expect(
      formatVerdictMix({ false_positive: 0, true_positive: 0, needs_more_info: 0 }),
    ).toBe('no verdicts');
  });
});

describe('dominantVerdictLabel', () => {
  it('maps the three buckets to their short chips', () => {
    expect(dominantVerdictLabel('false_positive')).toBe('mostly FP');
    expect(dominantVerdictLabel('true_positive')).toBe('mostly TP');
    expect(dominantVerdictLabel('needs_more_info')).toBe('mostly NMI');
  });
});
