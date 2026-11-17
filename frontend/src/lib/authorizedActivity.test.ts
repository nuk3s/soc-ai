// The words of authorized activity. One term on every surface, and a
// sentence that says what a revoke and an expiry do to a run.
import { describe, expect, it } from 'vitest';

import type { AuthorizedActivity } from './api';
import {
  AUTHORIZED_MARK,
  SOURCE_ADDRESS_NOTE,
  authorizedSentence,
  machineWords,
  markHolds,
  recordTimeSentence,
  ruleClassWords,
  ruleCountWords,
  runCountWords,
  targetWords,
} from './authorizedActivity';
import type { AuthorizationRef } from './types';

const ref = (over: Partial<AuthorizationRef> = {}): AuthorizationRef => ({
  id: 3,
  label: 'php2shell test',
  state: 'active',
  expiresAt: '2026-11-20T10:00:00+00:00',
  by: 'casey',
  ...over,
});

const record = (over: Partial<AuthorizedActivity> = {}): AuthorizedActivity => ({
  id: 3,
  label: 'php2shell test',
  note: null,
  state: 'active',
  sources: [{ address: '10.50.0.26', name: 'agent-a', machine_key: 'agent:a-1', identity: 'agent' }],
  target: { address: '10.40.0.164', name: null, machine_key: 'ip:10.40.0.164', identity: 'address' },
  rule_names: ['ET EXPLOIT PHP php2shell Nested Empty File Control OOM (CVE-2026-109618)'],
  rule_class: 'exploit_attempt',
  starts_at: '2026-11-13T10:00:00+00:00',
  expires_at: '2026-11-20T10:00:00+00:00',
  created_at: '2026-11-13T10:00:00+00:00',
  created_by: 'casey',
  revoked_at: null,
  revoked_by: null,
  revoke_reason: null,
  source_investigation_id: 'INV-1',
  runs_since_decision: 4,
  earlier_runs: 0,
  runs_total: 4,
  last_match_at: null,
  runs_href: '/investigations?authorization=3&range=all',
  ...over,
});

describe('the words of authorized activity', () => {
  it('uses the one term', () => {
    expect(AUTHORIZED_MARK).toBe('Authorized activity');
  });

  it('states the label, the analyst and the expiry of a run inside the scope', () => {
    expect(authorizedSentence(ref())).toBe(
      'php2shell test. casey recorded it. It expires on 2026-11-20 10:00 UTC. This investigation requests no case.',
    );
  });

  it('says that an expired authorization keeps the mark', () => {
    expect(authorizedSentence(ref({ state: 'expired' }))).toBe(
      'php2shell test. casey recorded it. It expired on 2026-11-20 10:00 UTC. This investigation keeps the mark. This investigation requests no case.',
    );
    expect(markHolds(ref({ state: 'expired' }))).toBe(true);
  });

  it('says that a revoke returns the run to normal handling', () => {
    expect(authorizedSentence(ref({ state: 'revoked' }))).toBe(
      'An analyst revoked the authorized activity "php2shell test". This investigation gets normal handling.',
    );
    expect(markHolds(ref({ state: 'revoked' }))).toBe(false);
    expect(markHolds(null)).toBe(false);
    expect(markHolds(undefined)).toBe(false);
  });

  it('names a machine by its name and its address', () => {
    expect(machineWords(record().sources[0])).toBe('agent-a at 10.50.0.26');
    expect(machineWords(record().target)).toBe('10.40.0.164');
  });

  it('says what the record does with each address', () => {
    expect(SOURCE_ADDRESS_NOTE).toBe(
      'The agent of this machine reports the address. The record holds this address only.',
    );
    // A target with no agent follows its address, and the dialog says so.
    expect(targetWords(false)).toBe(
      'The target has no agent. The record follows the address, so another device on this address is inside the scope until the expiry.',
    );
    expect(targetWords(true)).toBe(
      'The agent of this machine reports the address. The record holds this address only.',
    );
  });

  it('states the time of a card for each state', () => {
    const now = new Date('2026-11-14T10:00:00Z').getTime();
    expect(recordTimeSentence(record(), now)).toBe(
      'casey recorded it on 2026-11-13 10:00 UTC. It expires in 6 days, on 2026-11-20 10:00 UTC.',
    );
    const soon = new Date('2026-11-20T05:00:00Z').getTime();
    expect(recordTimeSentence(record(), soon)).toContain('It expires in 5 hours');
    expect(recordTimeSentence(record({ state: 'expired' }), now)).toBe(
      'casey recorded it on 2026-11-13 10:00 UTC. It expired on 2026-11-20 10:00 UTC. New investigations get normal handling.',
    );
    expect(
      recordTimeSentence(
        record({
          state: 'revoked',
          revoked_by: 'dana',
          revoked_at: '2026-11-15T08:00:00+00:00',
          revoke_reason: 'The test ended.',
        }),
        now,
      ),
    ).toBe(
      'casey recorded it on 2026-11-13 10:00 UTC. dana revoked it on 2026-11-15 08:00 UTC. Reason: The test ended.',
    );
  });

  it('counts the investigations since the decision, and the earlier investigations apart', () => {
    expect(runCountWords(record())).toBe('4 matching investigations since the decision');
    expect(runCountWords(record({ runs_since_decision: 1 }))).toBe(
      '1 matching investigation since the decision',
    );
    expect(runCountWords(record({ runs_since_decision: 0, earlier_runs: 2 }))).toBe(
      '0 matching investigations since the decision, and 2 earlier investigations',
    );
  });

  it('names the alert class in plain words and counts the rules of a card', () => {
    expect(ruleClassWords('exploit_attempt')).toBe('exploit attempt');
    expect(ruleClassWords('post_compromise')).toBe('post compromise');
    expect(ruleCountWords(record())).toBe('1 rule, class exploit attempt');
    expect(ruleCountWords(record({ rule_names: ['a', 'b'] }))).toBe('2 rules, class exploit attempt');
  });
});
