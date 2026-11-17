// The owner's word rule for every new string of the decision round: no "run",
// "member", the retired word for the whole network, or "kind", in any string
// an analyst reads. The test reads every constant and every sentence the new
// helpers build, for each value they take.
import { describe, expect, it } from 'vitest';
import type { CampaignChange, NeedsYouItemType } from './api';
import * as words from './campaignWords';
import * as items from './needsYouItems';
import { needsYouLines } from './needsYou';
import { NOTIFICATION_KINDS, describeNotifications } from './notifications';

const BANNED = /\b(runs?|members?|est[a]te|kinds?)\b/i;

const CHANGES: CampaignChange[] = [
  { id: 1, type: 'formed', at: '2026-11-01T00:00:00Z', detail: {} },
  { id: 2, type: 'stage', at: '2026-11-01T00:00:00Z', detail: { from: 'attempt', to: 'access' } },
  { id: 3, type: 'stage', at: '2026-11-01T00:00:00Z', detail: { to: 'access' } },
  { id: 4, type: 'party', at: '2026-11-01T00:00:00Z', detail: { names: ['db-1'] } },
  { id: 5, type: 'party', at: '2026-11-01T00:00:00Z', detail: { names: ['db-1', 'mail-1'] } },
  { id: 6, type: 'decided', at: '2026-11-01T00:00:00Z', detail: { decision: 'closed', reason: 'test_over', by: 'admin' } },
  { id: 7, type: 'decided', at: '2026-11-01T00:00:00Z', detail: { decision: 'authorized', by: 'admin' } },
  { id: 8, type: 'decided', at: '2026-11-01T00:00:00Z', detail: { decision: 'case', by: 'admin' } },
  ...(['activity', 'stage', 'party', 'analyst'] as const).map((cause, i) => ({
    id: 10 + i,
    type: 'reopened' as const,
    at: '2026-11-01T00:00:00Z',
    detail: { cause, by: 'admin' },
  })),
  { id: 20, type: 'acknowledged', at: '2026-11-01T00:00:00Z', detail: { alerts: 3, failed: 1 } },
];

function strings(): string[] {
  const out: string[] = [];
  for (const value of [...Object.values(words), ...Object.values(items)]) {
    if (typeof value === 'string') out.push(value);
    else if (value && typeof value === 'object' && !Array.isArray(value)) {
      for (const v of Object.values(value)) if (typeof v === 'string') out.push(v);
    }
  }
  for (const c of CHANGES) out.push(words.changeSentence(c), words.changeMarkLabel(c), words.changeMarkWords(c));
  for (const r of words.CLOSE_REASONS) {
    out.push(words.decisionSentence({ type: 'closed', reason: r, by: 'admin', at: '2026-11-01T00:00:00Z' }));
  }
  for (const t of ['authorized', 'case'] as const) {
    out.push(words.decisionSentence({ type: t, by: null, at: '2026-11-01T00:00:00Z' }));
  }
  out.push(
    words.waitsSentence('2026-11-01T00:00:00Z'),
    words.waitsSentence(null),
    words.decisionNote('A note.'),
    words.acknowledgedSentence({ alerts: 1, failed: 0 }),
    words.acknowledgeLabel({ alerts: 4, rules: 1 }),
    words.acknowledgeLabel({ alerts: null, rules: null }),
    words.scopeCappedSentence(2000),
    words.closeWritesSentence(true, 4),
    words.closeWritesSentence(true, null),
    words.closeWritesSentence(false, 4),
    items.needsYouTotalWords(1),
    items.needsYouTotalWords(14),
    items.needsYouTotalWords(14, true),
    items.needsYouTotalWords(0, true),
    items.needsYouUnreadWords(['campaign', 'investigation', 'lead', 'alerts']) ?? '',
  );
  // The line of the investigations that wait, one and many, at any age.
  for (const n of [1, 2]) {
    const inv = needsYouLines({
      leads_needing_decision: 0,
      unread_shadow_hits: 0,
      untriaged_groups: 0,
      needs_more_info: 0,
      pending_actions: n,
      investigations_waiting: n,
      decisions: n,
      total: n,
      unknown: [],
      alert_window: '7d',
      verdict_window: 'all',
      alert_floor: false,
    })[0];
    out.push(inv.text, inv.scope, inv.unknown);
  }
  for (const t of ['campaign', 'investigation', 'lead', 'alerts'] as NeedsYouItemType[]) {
    out.push(items.needsYouTypeLabel(t), items.needsYouOpenLabel(t));
  }
  for (const since of ['2026-11-14T11:00:00Z', '2026-09-01T00:00:00Z']) {
    out.push(items.waitAge(since, Date.parse('2026-11-14T12:00:00Z'))?.text ?? '');
  }
  const line = needsYouLines({
    campaigns: 2,
    leads_needing_decision: 0,
    unread_shadow_hits: 0,
    untriaged_groups: 0,
    needs_more_info: 0,
    pending_actions: 0,
    total: 2,
    unknown: [],
    alert_window: '7d',
    verdict_window: '30d',
    alert_floor: false,
  })[0];
  out.push(line.text, line.scope, line.unknown);
  out.push(...NOTIFICATION_KINDS.map((k) => k.label), describeNotifications([{ id: 'campaign:1' }], false));
  return out.filter((s) => s.trim());
}

describe('the strings of the decision round', () => {
  it('hold no banned word', () => {
    const all = strings();
    expect(all.length).toBeGreaterThan(50);
    expect(all.filter((s) => BANNED.test(s))).toEqual([]);
  });

  it('hold no dash and no parenthesis', () => {
    expect(strings().filter((s) => /[\u2013\u2014()]/.test(s))).toEqual([]);
  });
});
