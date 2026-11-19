// A decided campaign asks for nothing (round "decide once" part 2, OW4). The
// step strip of an investigation of a closed campaign named "Escalate to
// case" as the next step (dogfood 2026-11-17, N12).
import { describe, expect, it } from 'vitest';
import { investigationFlow } from './flowSteps';
import type { Investigation } from './types';

const inv = {
  id: 'INV-1',
  kind: 'suricata',
  status: 'complete',
  verdict: 'true_positive',
  actions: [{ id: 'a0', tag: 'escalate', title: 'Escalate to case', rationale: '', applied: false }],
  alertAcked: false,
} as unknown as Investigation;

const actionStep = (opts: Parameters<typeof investigationFlow>[1]) =>
  investigationFlow(inv, opts).find((s) => s.key === 'action');

describe('the action step of an investigation of a decided campaign', () => {
  it('names no write and states the decision', () => {
    const sentence = 'The analyst closed the campaign on 2026-11-15 14:02 UTC. No action waits.';
    const step = actionStep({ campaignDecided: sentence });
    expect(step?.state).toBe('done');
    expect(step?.control).toBeUndefined();
    expect(step?.title).toBe(sentence);
  });

  it('control: a campaign with no decision keeps the escalate as the next step', () => {
    const step = actionStep({ campaignDecided: null });
    expect(step?.state).toBe('next');
    expect(step?.control).toBeTruthy();
  });
});
