import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getLeads: vi.fn(),
  getLeadCount: vi.fn(),
  getNeedsYou: vi.fn(),
}));

import { getLeadCount, getLeads, getNeedsYou, type Lead } from '../lib/api';
import { leadHuntResult } from '../lib/leadWords';
import { LeadsStrip } from './LeadsStrip';

// ---------------------------------------------------------------------------
// The lead row prints the hunt result (production review 2026-11-12, hunts
// F6). Seven of eight open leads waited after a hunt that found no threat, and
// the row of each read the same as the row of the one real item. The row now
// states the result in four words, then what the hunt said and what it could
// not check.
// ---------------------------------------------------------------------------

const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const lead = (over: Partial<Lead>): Lead => ({
  id: 1,
  status: 'open',
  formed_at: iso(5 * HOUR),
  updated_at: iso(5 * HOUR),
  entities: [['host', '192.0.2.10']],
  kinds: ['above_baseline'],
  weight_at_formation: 0.93,
  scope_count: 1,
  hunt_id: null,
  shadow: false,
  single_signal: false,
  observations: [],
  ...over,
});

const hunted = (over: Partial<Lead>): Lead =>
  lead({ status: 'hunting', hunt_id: 'H1', hunt_status: 'complete', hunt_count: 1, ...over });

const mount = (rows: Lead[]) => {
  vi.mocked(getLeads).mockResolvedValue(rows);
  return render(
    <MemoryRouter>
      <LeadsStrip status="all" />
    </MemoryRouter>,
  );
};

const resultOf = async (id: number) =>
  within(await screen.findByTestId(`lead-${id}`)).getByTestId(`lead-hunt-result-${id}`);

beforeEach(() => {
  vi.mocked(getLeads).mockReset();
  vi.mocked(getLeadCount).mockReset().mockRejectedValue(new Error('not asked'));
  vi.mocked(getNeedsYou).mockReset().mockResolvedValue({
    unread_shadow_hits: 0,
    leads_needing_decision: 0,
    total: 0,
    lead_auto_hunt: false,
  });
});

describe('the four results', () => {
  it('reads "found a threat" for a hunt with a threat finding', () => {
    expect(leadHuntResult(hunted({ hunt_outcome: 'threats', hunt_threat_count: 1 }))).toEqual({
      key: 'threat',
      words: 'found a threat',
    });
    // A hunt whose investigations confirmed a threat found one too.
    expect(leadHuntResult(hunted({ hunt_outcome: 'threats_confirmed' })).key).toBe('threat');
  });

  it('reads "found no threat" for a clean hunt', () => {
    expect(leadHuntResult(hunted({ hunt_outcome: 'clean' }))).toEqual({
      key: 'no_threat',
      words: 'found no threat',
    });
    expect(leadHuntResult(hunted({ hunt_outcome: 'no_threat_confirmed' })).key).toBe('no_threat');
  });

  it('reads "hunt failed" for a hunt that stopped', () => {
    for (const status of ['error', 'cancelled', 'interrupted'] as const) {
      expect(leadHuntResult(hunted({ hunt_status: status, hunt_outcome: 'failed' }))).toEqual({
        key: 'failed',
        words: 'hunt failed',
      });
    }
  });

  it('reads "not hunted" for a lead with no hunt', () => {
    expect(leadHuntResult(lead({}))).toEqual({ key: 'not_hunted', words: 'not hunted' });
    expect(leadHuntResult(lead({ status: 'fleet_condition' })).words).toBe('not hunted');
  });

  it('NEGATIVE CONTROL: claims no result for a hunt that still runs', () => {
    // "found no threat" over a running hunt is a false all-clear.
    const running = leadHuntResult(hunted({ hunt_status: 'running', hunt_outcome: null }));
    expect(running).toEqual({ key: 'running', words: 'the hunt runs now' });
    const investigating = leadHuntResult(
      hunted({ hunt_status: 'investigating' as Lead['hunt_status'], hunt_outcome: 'threats' }),
    );
    expect(investigating.key).toBe('running');
    expect(investigating.words).toBe('the hunt investigates its findings');
  });

  it('NEGATIVE CONTROL: reads a visibility gap and a hunt with no answer as neither clean nor a threat', () => {
    expect(leadHuntResult(hunted({ hunt_outcome: 'gap' }))).toEqual({
      key: 'no_threat_gap',
      words: 'found no threat, with a visibility gap',
    });
    expect(leadHuntResult(hunted({ hunt_outcome: 'no_answer' }))).toEqual({
      key: 'no_answer',
      words: 'the hunt gave no answer',
    });
    // A finished hunt with no outcome on record. An older server sends none.
    expect(leadHuntResult(hunted({ hunt_outcome: null }))).toEqual({
      key: 'unknown',
      words: 'hunted, with no result on record',
    });
  });

  it('lets an earlier threat outrank a newer clean hunt', () => {
    expect(leadHuntResult(hunted({ hunt_outcome: 'clean', hunt_count: 2, hunt_threat_count: 1 }))).toEqual({
      key: 'threat',
      words: 'found no threat. An earlier hunt found a threat',
    });
  });
});

describe('the lead row', () => {
  it('prints the result on every row, in every state', async () => {
    mount([
      lead({ id: 1 }),
      hunted({ id: 2, hunt_outcome: 'clean' }),
      hunted({ id: 3, hunt_outcome: 'threats', hunt_threat_count: 1 }),
      hunted({ id: 4, hunt_status: 'error', hunt_outcome: 'failed' }),
      lead({ id: 5, status: 'fleet_condition', scope_count: 34 }),
      lead({ id: 6, status: 'dismissed', dismissed_reason: 'known_change' }),
      hunted({ id: 7, status: 'dismissed', dismissed_reason: 'hunt_clean', hunt_outcome: 'clean' }),
    ]);
    expect((await resultOf(1)).textContent).toBe('Hunt result: not hunted.');
    expect((await resultOf(2)).textContent).toBe('Hunt result: found no threat.');
    expect((await resultOf(3)).textContent).toBe('Hunt result: found a threat.');
    expect((await resultOf(4)).textContent).toBe('Hunt result: hunt failed.');
    expect((await resultOf(5)).textContent).toBe('Hunt result: not hunted.');
    expect((await resultOf(6)).textContent).toBe('Hunt result: not hunted.');
    expect((await resultOf(7)).textContent).toBe('Hunt result: found no threat.');
    expect((await resultOf(3)).getAttribute('data-hunt-result')).toBe('threat');
  });

  it('states what the hunt said and what it could not check', async () => {
    mount([
      hunted({
        id: 12,
        hunt_outcome: 'clean',
        hunt_answer: 'No malicious indication.',
        hunt_not_checked: [
          'Container telemetry. The host has no agent.',
          'TLS payloads. The grid holds no decrypted flow.',
        ],
      }),
    ]);
    expect((await resultOf(12)).textContent).toBe(
      'Hunt result: found no threat. Answer: No malicious indication. ' +
        'Not checked: Container telemetry. The host has no agent. ' +
        'TLS payloads. The grid holds no decrypted flow.',
    );
  });

  it('NEGATIVE CONTROL: prints no answer line for a server that sends none', async () => {
    mount([hunted({ id: 9, hunt_outcome: 'clean' })]);
    const line = await resultOf(9);
    expect(line.textContent).not.toContain('Answer:');
    expect(line.textContent).not.toContain('Not checked:');
  });
});
