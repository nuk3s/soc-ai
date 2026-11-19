// The parts of a set of true positives (round "decide once" part 2, OW2).
// The true positives view names the part that the analyst handled.
import { describe, expect, it } from 'vitest';
import { earlierPartWords, partPhrases, partsSentence } from './truePositiveParts';
import type { TruePositiveParts } from './types';

const parts = (over: Partial<TruePositiveParts> = {}): TruePositiveParts => ({
  total: 16,
  waiting: 15,
  decided: 0,
  authorized: 0,
  superseded: 0,
  other: 0,
  campaigns: [],
  ...over,
});

describe('partsSentence', () => {
  it('names the true positives that the analyst handled', () => {
    expect(partsSentence(parts({ waiting: 15, handled: 1 }))).toBe(
      '16 true positives. 15 wait. 1 is handled by the analyst.',
    );
  });

  it('control: no handled part and an older server state no such phrase', () => {
    expect(partsSentence(parts({ waiting: 16, handled: 0 }))).toBe('16 true positives. 16 wait.');
    expect(partPhrases(parts({ waiting: 16 })).map((p) => p.key)).toEqual(['waiting']);
  });
});

// Round 3 part 2 (W2): the earlier decision of a reopened campaign covered them.
describe('the part earlier', () => {
  const close = { decision: 'closed', decidedAt: '2026-11-15T01:01:12Z' };

  it('states the reopened campaign and the close that covered them', () => {
    expect(earlierPartWords({ investigations: 28, campaigns: 1, ...close })).toBe(
      '28 are in a campaign that opened again. The close of 2026-11-15 covered them.',
    );
    expect(earlierPartWords({ investigations: 1, campaigns: 1, ...close })).toBe(
      '1 is in a campaign that opened again. The close of 2026-11-15 covered it.',
    );
    expect(earlierPartWords({ investigations: 5, campaigns: 2 })).toBe(
      '5 are in 2 campaigns that opened again. The earlier decision of each campaign covered them.',
    );
    const p = parts({
      total: 36,
      waiting: 8,
      earlier: 28,
      earlierCampaigns: [{ id: 2, title: 'actor-a against web-1', investigations: 28, ...close }],
    });
    expect(partsSentence(p)).toBe(
      '36 true positives. 8 wait. 28 are in a campaign that opened again. The close of 2026-11-15 covered them.',
    );
    expect(partPhrases(p).find((x) => x.key === 'earlier')?.n).toBe(28);
  });

  it('control: no part earlier states no such phrase', () => {
    expect(partPhrases(parts({ earlier: 0 })).map((x) => x.key)).toEqual(['waiting']);
  });
});
