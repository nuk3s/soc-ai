// Dogfood 2026-10-19, round 2 (R2-A). One rule for every new run: a run that
// can replace an analyst verdict asks first. The bulk Re-investigate has no
// confirm, so the server skips the alert and the list names the reason.
import { describe, expect, it } from 'vitest';
import { rehuntSkipReason } from './Investigations';

describe('the bulk re-investigate names the analyst skip', () => {
  it('says an analyst verdict stands and where to re-run it', () => {
    expect(rehuntSkipReason('analyst_verdict')).toBe(
      'an analyst verdict stands on the alert. Re-run it from its page',
    );
  });

  it('says the grid did not answer for the anchor of a promotion', () => {
    // The anchor rule asks the grid whether the anchor document is an alert
    // (dogfood 2026-10-21). A grid that does not answer skips the run.
    expect(rehuntSkipReason('anchor_unread')).toBe(
      'soc-ai could not read the anchor document. Try again when the grid answers',
    );
  });

  it('names the remedy of a promoted finding and of a promoted lead', () => {
    // A finding run has Re-run on its page. A lead run has none, and Resolve
    // in chat on its page settles the verdict (2026-10-30).
    expect(rehuntSkipReason('hunt_kind')).toBe(
      'promoted finding. Use Re-run on the investigation of the finding',
    );
    expect(rehuntSkipReason('lead_kind')).toBe(
      'promoted lead. Use Resolve in chat on the investigation of the lead',
    );
  });

  it('NEGATIVE CONTROL: an unknown code reads as the code', () => {
    expect(rehuntSkipReason('a_new_code')).toBe('a_new_code');
  });
});
