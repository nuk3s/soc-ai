// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { campaignHolds, decisionState } from './campaignDecision';

const link = { status: 'open' as const, differs: false };

describe('campaignHolds', () => {
  it('holds an investigation of an active campaign that waits or that an analyst closed', () => {
    expect(campaignHolds({ ...link, decision: null })).toBe(true);
    expect(campaignHolds({ ...link, status: 'ended', decision: 'closed' })).toBe(true);
  });

  it('holds no investigation of an authorized campaign through the link', () => {
    // The mark of the authorization holds an investigation inside. One
    // outside keeps normal handling, so its actions wait.
    expect(campaignHolds({ ...link, decision: 'authorized' })).toBe(false);
  });

  it('holds no investigation of an earlier server, a verdict that differs or a merged campaign', () => {
    // NEGATIVE CONTROLS: the rule of part A stays as it is.
    expect(campaignHolds(link)).toBe(false);
    expect(campaignHolds({ ...link, differs: true, decision: null })).toBe(false);
    expect(campaignHolds({ ...link, status: 'merged', decision: null })).toBe(false);
    expect(campaignHolds(null)).toBe(false);
  });

  it('reads the decision state of an authorized campaign', () => {
    expect(decisionState({ status: 'open', decision: 'authorized' })).toBe('authorized');
  });
});
