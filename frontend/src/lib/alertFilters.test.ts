// Optimistic hide after a drawer-initiated group ack: the acked group leaves
// the queue immediately (ES needs seconds-to-minutes to reflect the ack in the
// aggregation), but NEW events arriving after the ack re-surface it.
import { describe, expect, it } from 'vitest';
import { groupOutcome, hideOptimisticallyAcked, isInheritedOutcome, outcomeOf } from './alertFilters';
import type { AlertGroup } from './types';

const group = (over: Partial<AlertGroup>): AlertGroup =>
  ({
    id: 'es-1',
    name: 'ET TEST Rule',
    kind: 'suricata',
    sev: 'low',
    count: 3,
    verdict: 'false_positive',
    conf: 0.9,
    latest: '1m ago',
    inherited: false,
    events: [],
    ...over,
  }) as AlertGroup;

describe('hideOptimisticallyAcked', () => {
  const ackedAt = { 'ET TEST Rule': Date.parse('2026-07-15T12:00:00Z') };

  it('hides a just-acked group while Hide acknowledged is on', () => {
    const gs = [group({ latestTs: '2026-07-15T11:00:00Z' })];
    expect(hideOptimisticallyAcked(gs, ackedAt, true)).toEqual([]);
  });

  it('keeps the group when new events arrived after the ack', () => {
    const gs = [group({ latestTs: '2026-07-15T12:30:00Z' })];
    expect(hideOptimisticallyAcked(gs, ackedAt, true)).toHaveLength(1);
  });

  it('never hides when Hide acknowledged is off', () => {
    const gs = [group({ latestTs: '2026-07-15T11:00:00Z' })];
    expect(hideOptimisticallyAcked(gs, ackedAt, false)).toHaveLength(1);
  });

  it('ignores groups that were never acked this session', () => {
    const gs = [group({ name: 'ET OTHER Rule', latestTs: '2026-07-15T11:00:00Z' })];
    expect(hideOptimisticallyAcked(gs, ackedAt, true)).toHaveLength(1);
  });

  it('hides a group with no latestTs (cannot prove newer events)', () => {
    const gs = [group({ latestTs: undefined })];
    expect(hideOptimisticallyAcked(gs, ackedAt, true)).toEqual([]);
  });
});

// The legacy cases below carry no windowVerdict key: an older server.
// The verdict a group counts under (prod 2026-10-13). The rule "GPL SHELLCODE
// x86 setuid 0" held one true positive and five later false positives on
// other sources. The group took the verdict of its newest run, and the
// Dashboard said "True positive 0" beside an Investigations list of one.
describe('groupOutcome', () => {
  it('counts a group under its worst verdict when that is worse', () => {
    expect(groupOutcome(group({ verdict: 'false_positive', worstVerdict: 'true_positive' }))).toBe(
      'true_positive',
    );
  });

  it('keeps the standing verdict when nothing is worse', () => {
    expect(groupOutcome(group({ verdict: 'false_positive', worstVerdict: null }))).toBe('false_positive');
    expect(groupOutcome(group({ verdict: 'untriaged', conf: null }))).toBe('untriaged');
  });

  it('counts a pipeline fallback under the worse verdict it hides', () => {
    expect(
      groupOutcome(group({ verdict: 'needs_more_info', fallback: true, worstVerdict: 'true_positive' })),
    ).toBe('true_positive');
  });

  it('counts a pipeline fallback with nothing worse under no verdict', () => {
    // NEGATIVE CONTROL. The stored needs_more_info is not a verdict the
    // pipeline reached, so it must not count as one.
    expect(groupOutcome(group({ verdict: 'needs_more_info', fallback: true }))).toBeNull();
  });

  it('ignores a worst verdict the console does not know', () => {
    expect(groupOutcome(group({ verdict: 'false_positive', worstVerdict: 'bogus' }))).toBe('false_positive');
  });
});

// Runs made inside the page window decide the verdict of a group (owner rule,
// 2026-10-14). A group with no run in the window keeps the older verdict that
// covers it, and the console marks that verdict inherited.
describe('outcomeOf: the window verdict', () => {
  it('counts a group under its window verdict', () => {
    const o = outcomeOf(
      group({
        verdict: 'false_positive',
        invId: 'INV-FP',
        windowVerdict: 'true_positive',
        windowConf: 0.62,
        windowInvId: 'INV-TP',
      }),
    );
    expect(o).toEqual({ verdict: 'true_positive', conf: 0.62, invId: 'INV-TP', inherited: false, at: null });
  });

  it('does not count a true positive from outside the window', () => {
    // NEGATIVE CONTROL. The standing true positive ran after the end of a
    // custom window, and the runs inside the window are false positives. A
    // stale worst verdict does not count either.
    const g = group({
      verdict: 'true_positive',
      conf: 0.62,
      windowVerdict: 'false_positive',
      windowConf: 0.9,
      worstVerdict: 'true_positive',
    });
    expect(groupOutcome(g)).toBe('false_positive');
    expect(isInheritedOutcome(g)).toBe(false);
  });

  it('keeps the standing verdict of a group with no run in the window, inherited', () => {
    const g = group({
      verdict: 'false_positive',
      conf: 0.9,
      invId: 'INV-OLD',
      windowVerdict: null,
      verdictAt: '2026-10-11T09:00:00+00:00',
    });
    expect(outcomeOf(g)).toEqual({
      verdict: 'false_positive',
      conf: 0.9,
      invId: 'INV-OLD',
      inherited: true,
      at: '2026-10-11T09:00:00+00:00',
    });
    expect(isInheritedOutcome(g)).toBe(true);
  });

  it('keeps an untriaged group untriaged, not inherited', () => {
    const g = group({ verdict: 'untriaged', conf: null, windowVerdict: null });
    expect(groupOutcome(g)).toBe('untriaged');
    expect(isInheritedOutcome(g)).toBe(false);
  });

  it('counts a pipeline fallback with no window verdict under no verdict', () => {
    // NEGATIVE CONTROL. Inheritance does not turn the stored needs_more_info
    // of a fallback into a verdict.
    const g = group({ verdict: 'needs_more_info', fallback: true, windowVerdict: null });
    expect(groupOutcome(g)).toBeNull();
    expect(isInheritedOutcome(g)).toBe(false);
  });

  it('counts a pipeline fallback under the window verdict before it', () => {
    const g = group({ verdict: 'needs_more_info', fallback: true, windowVerdict: 'false_positive' });
    expect(groupOutcome(g)).toBe('false_positive');
  });

  it('reads a window verdict the console does not know as no window verdict', () => {
    const g = group({ verdict: 'false_positive', windowVerdict: 'bogus' });
    expect(groupOutcome(g)).toBe('false_positive');
    expect(isInheritedOutcome(g)).toBe(true);
  });

  it('keeps the worst-verdict rule for an older server, with nothing inherited', () => {
    const g = group({ verdict: 'false_positive', worstVerdict: 'true_positive', worstConf: 0.62, worstInvId: 'INV-TP' });
    expect(outcomeOf(g)).toEqual({ verdict: 'true_positive', conf: 0.62, invId: 'INV-TP', inherited: false, at: null });
    expect(isInheritedOutcome(group({ verdict: 'false_positive' }))).toBe(false);
  });
});
