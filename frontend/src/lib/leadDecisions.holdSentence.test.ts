// The words for the reason a lead waits, for a server that sends the code only.
import { describe, expect, it } from 'vitest';

import { holdSentence } from './leadDecisions';

describe('the hold sentence', () => {
  it('states a link between leads (change E)', () => {
    expect(holdSentence({ hold_reason: 'lead_link' })).toBe(
      'The hunt linked this lead to other leads.',
    );
  });
});
