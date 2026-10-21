// The first lines of the host page (dogfood 2026-10-19, R4-D7 and R4-D3).
// The hero said "Lead 6 waits on a decision. Its hunt found no threat." and
// then "1 more open lead names this host." The other lead was Lead 5, whose
// hunt found a threat. The page also had no line for 6 true-positive
// investigations of the machine.
import { describe, expect, it } from 'vitest';
import type { Lead } from './api';
import { investigationLines, leadLines, openLeads } from './hostSituation';

const lead = (id: number, over: Partial<Lead> = {}): Lead => ({
  id,
  status: 'open',
  formed_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  entities: [['host', '192.0.2.10']],
  kinds: ['alert'],
  weight_at_formation: 1,
  scope_count: 1,
  hunt_id: null,
  shadow: false,
  single_signal: false,
  observations: [],
  ...over,
});

const decided = (id: number, outcome: string, label: string, over: Partial<Lead> = {}) =>
  lead(id, { hunt_id: `h${id}`, hunt_status: 'complete', hunt_outcome: outcome, hunt_outcome_label: label, ...over });

describe('openLeads', () => {
  it('puts a lead whose hunt found a threat first', () => {
    const clean = decided(6, 'clean', 'No threat found');
    const threat = decided(5, 'threats', 'Threat found');
    expect(openLeads([clean, threat]).map((l) => l.id)).toEqual([5, 6]);
    const lines = leadLines([clean, threat]);
    expect(lines[0].text).toBe('Lead 5 waits on a decision. Its hunt found threats.');
    expect(lines[0].tone).toBe('alarm');
  });

  it('reads a threat count on a lead with no outcome code', () => {
    // An older server sends the count and the label only.
    const clean = decided(8, '', 'No threat found', { hunt_outcome: null });
    const threat = decided(7, '', 'Threat found', { hunt_outcome: null, hunt_threat_count: 2 });
    expect(openLeads([clean, threat]).map((l) => l.id)).toEqual([7, 8]);
  });

  it('keeps the newest first among leads of one rank', () => {
    // NEGATIVE CONTROL: two clean leads keep the old order.
    expect(openLeads([decided(3, 'clean', 'No threat found'), decided(4, 'clean', 'No threat found')]).map((l) => l.id)).toEqual([4, 3]);
  });
});

describe('investigationLines', () => {
  it('says how many investigations reached a true positive, over all time', () => {
    const lines = investigationLines(7, 6, '/investigations?entity=agent%3Aea2d&range=all');
    expect(lines).toEqual([
      {
        text: '6 investigations of this host reached a true-positive verdict.',
        to: '/investigations?entity=agent%3Aea2d&range=all',
        tone: 'alarm',
        scope: 'all time',
      },
    ]);
  });

  it('adds no line when no investigation reached a true positive', () => {
    // NEGATIVE CONTROL: the block below the hero carries the count.
    expect(investigationLines(7, 0, '/x')).toEqual([]);
    expect(investigationLines(0, 0, '/x')).toEqual([]);
  });
});
