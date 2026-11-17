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
import { REPEATS_AFTER_CLOSE } from '../lib/tooltips';
import { LeadsStrip } from './LeadsStrip';

// ---------------------------------------------------------------------------
// The lead row prints two facts the API already sent. A held lead states why
// the finished hunt did not settle it. A closed lead states the observations
// that joined it after the close: a true-positive alert of a rule the lead
// held joins the closed lead and starts no hunt, and the row did not say so.
// ---------------------------------------------------------------------------

const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const lead = (over: Partial<Lead>): Lead => ({
  id: 1,
  status: 'open',
  formed_at: iso(50 * HOUR),
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

const mount = (rows: Lead[]) => {
  vi.mocked(getLeads).mockResolvedValue(rows);
  return render(
    <MemoryRouter>
      <LeadsStrip status="all" />
    </MemoryRouter>,
  );
};

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

describe('the hold sentence on the row', () => {
  it('prints why the finished hunt did not settle a held lead, under the hunt result', async () => {
    mount([
      lead({
        id: 7,
        status: 'hunting',
        hunt_id: 'H7',
        hunt_status: 'complete',
        hunt_outcome: 'clean',
        hunt_count: 1,
        hold_reason: 'partial_read',
        hold_sentence: 'The hunt could not read all evidence.',
      }),
    ]);
    const row = await screen.findByTestId('lead-7');
    const hold = within(row).getByTestId('lead-hold-7');
    expect(hold.textContent).toBe('The hunt could not read all evidence.');
    const result = within(row).getByTestId('lead-hunt-result-7');
    expect(result.compareDocumentPosition(hold) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('NEGATIVE CONTROL: prints no hold line on a lead with no hold', async () => {
    mount([lead({ id: 8, hold_reason: null, hold_sentence: null })]);
    const row = await screen.findByTestId('lead-8');
    expect(within(row).queryByTestId('lead-hold-8')).toBeNull();
  });
});

describe('the repeats after the close on the row', () => {
  it('prints the count and the newest repeat of a closed lead, with the rule in the tooltip', async () => {
    mount([
      lead({
        id: 9,
        status: 'dismissed',
        dismissed_reason: 'known_change',
        dismissed_at: iso(40 * HOUR),
        repeats_after_close: 4,
        last_repeat_at: iso(2 * HOUR),
      }),
    ]);
    const row = await screen.findByTestId('lead-9');
    const line = within(row).getByTestId('lead-repeats-9');
    expect(line.textContent).toBe('4 repeats after the close. Newest: 2h ago.');
    expect(line.getAttribute('title')).toBe(REPEATS_AFTER_CLOSE);
  });

  it('NEGATIVE CONTROL: prints nothing for a closed lead with zero repeats', async () => {
    mount([
      lead({
        id: 10,
        status: 'promoted',
        investigation_id: 'inv-10',
        repeats_after_close: 0,
        last_repeat_at: null,
      }),
    ]);
    const row = await screen.findByTestId('lead-10');
    expect(within(row).queryByTestId('lead-repeats-10')).toBeNull();
  });

  it('NEGATIVE CONTROL: prints nothing for an open lead, whatever the count says', async () => {
    mount([lead({ id: 11, status: 'open', repeats_after_close: 3, last_repeat_at: iso(HOUR) })]);
    const row = await screen.findByTestId('lead-11');
    expect(within(row).queryByTestId('lead-repeats-11')).toBeNull();
  });
});
