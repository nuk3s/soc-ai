import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getLeads: vi.fn(),
  getLeadCount: vi.fn(),
  getNeedsYou: vi.fn(),
  huntLead: vi.fn(),
}));

import { getLeadCount, getLeads, getNeedsYou, huntLead, type Lead } from '../lib/api';
import { FLEET_CONDITION_LINE, PILL_FLEET_CONDITION, TAB_FLEET_CONDITION } from '../lib/tooltips';
import {
  LEAD_ACTION,
  LEAD_BULK_ACTIONS,
  LEAD_STATE_TABS,
  LEAD_TABS,
  LeadsStrip,
  leadState,
  leadsOutsideTabs,
} from './LeadsStrip';

// ---------------------------------------------------------------------------
// F1 (production review 2026-11-12). 47 of 70 leads had the stored status
// `fleet_condition`. The console showed each as "New" and listed it in no tab:
// the tabs held 8 + 0 + 15 leads. A fleet condition has its own state word and
// its own tab, and the tab counts sum to the total.
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
  weight_at_formation: 1.59,
  scope_count: 1,
  hunt_id: null,
  shadow: false,
  single_signal: false,
  observations: [],
  ...over,
});

const FLEET = lead({ id: 69, status: 'fleet_condition', scope_count: 34, shadow: true });
const NEW = lead({ id: 70 });
const HUNTED = lead({ id: 12, status: 'hunting', hunt_id: 'H1', hunt_status: 'complete', hunt_outcome: 'clean' });

/** The production counts of the review: 8 + 0 + 15 + 47 = 70. */
const COUNTS: Record<string, number> = {
  needs_decision: 8,
  in_progress: 0,
  closed: 15,
  fleet_condition: 47,
  all: 70,
};

const mountBound = (path = '/hunts') =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/hunts" element={<LeadsStrip paramBound />} />
      </Routes>
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getLeads).mockReset().mockResolvedValue([FLEET, NEW, HUNTED]);
  vi.mocked(getLeadCount)
    .mockReset()
    .mockImplementation(async (status = 'open') => ({ status, entity: null, total: COUNTS[status] ?? 0 }));
  vi.mocked(getNeedsYou).mockReset().mockResolvedValue({
    unread_shadow_hits: 0,
    leads_needing_decision: 8,
    total: 8,
    lead_auto_hunt: true,
  });
  vi.mocked(huntLead).mockReset().mockResolvedValue({ hunt_id: 'H-NEW' });
});

describe('the state of a fleet condition lead', () => {
  it('is its own state, and is not New', () => {
    expect(leadState({ status: 'fleet_condition' })).toBe('fleet_condition');
  });

  it('NEGATIVE CONTROL: leaves the other five states as they were', () => {
    expect(leadState({ status: 'open' })).toBe('new');
    expect(leadState({ status: 'hunting', hunt_status: 'running' })).toBe('in_progress');
    expect(leadState({ status: 'hunting', hunt_status: 'complete' })).toBe('hunted');
    expect(leadState({ status: 'open', hunt_status: 'error', hunt_id: 'H' })).toBe('hunted');
    expect(leadState({ status: 'dismissed' })).toBe('dismissed');
    expect(leadState({ status: 'promoted' })).toBe('promoted');
  });

  it('wears the words "Fleet condition" on the pill, with the sentence that explains them', async () => {
    mountBound('/hunts?leads=all');
    const row = await screen.findByTestId('lead-69');
    const pill = within(row).getByTestId('lead-status');
    expect(pill.textContent).toBe('Fleet condition');
    expect(pill.getAttribute('data-lead-state')).toBe('fleet_condition');
    expect(pill.getAttribute('title')).toBe(PILL_FLEET_CONDITION);
    expect(PILL_FLEET_CONDITION).toContain('waits on no decision');
    // The number that made it a fleet condition.
    expect(within(row).getByTestId('lead-fleet-span-69').textContent).toBe('one departure on 34 hosts');
  });

  it('NEGATIVE CONTROL: a new lead and a hunted lead keep their pills', async () => {
    mountBound('/hunts?leads=all');
    const fresh = await screen.findByTestId('lead-70');
    expect(within(fresh).getByTestId('lead-status').textContent).toBe('New');
    expect(within(fresh).queryByTestId('lead-fleet-span-70')).toBeNull();
    const hunted = screen.getByTestId('lead-12');
    expect(within(hunted).getByTestId('lead-status').textContent).toBe('Hunted · No threat found');
  });

  it('offers a hunt and a dismissal, and the hunt is no primary act', async () => {
    mountBound('/hunts?leads=all');
    const row = await screen.findByTestId('lead-69');
    const hunt = within(row).getByRole('button', { name: LEAD_ACTION.hunt });
    expect(hunt.className).not.toContain('bg-accent');
    expect(within(row).getByRole('button', { name: LEAD_ACTION.dismiss })).toBeTruthy();
    fireEvent.click(hunt);
    await waitFor(() => expect(huntLead).toHaveBeenCalledWith(69));
  });
});

describe('the Fleet condition tab', () => {
  it('is one of five tabs, before All', () => {
    expect(LEAD_TABS.map((t) => t.label)).toEqual([
      'Needs decision',
      'In progress',
      'Closed',
      'Fleet condition',
      'All',
    ]);
    expect(LEAD_STATE_TABS).toEqual(['needs_decision', 'in_progress', 'closed', 'fleet_condition']);
  });

  it('asks the server for the fleet condition leads and prints what a fleet condition is', async () => {
    mountBound('/hunts?leads=fleet_condition');
    const line = await screen.findByTestId('leads-fleet-line');
    expect(line.textContent).toBe(FLEET_CONDITION_LINE);
    expect(FLEET_CONDITION_LINE).toContain('more than 8 hosts');
    expect(FLEET_CONDITION_LINE).toContain('waits on no decision');
    expect(getLeads).toHaveBeenCalledWith('fleet_condition');
    const tab = screen.getByRole('button', { name: /^Fleet condition/ });
    expect(tab.getAttribute('aria-pressed')).toBe('true');
    expect(tab.getAttribute('title')).toBe(TAB_FLEET_CONDITION);
    await waitFor(() =>
      expect(screen.getByTestId('leads-heading').textContent).toContain('47 fleet conditions · all time'),
    );
  });

  it('keeps the line over an empty list, and states the absence', async () => {
    vi.mocked(getLeads).mockResolvedValue([]);
    mountBound('/hunts?leads=fleet_condition');
    expect((await screen.findByTestId('leads-fleet-line')).textContent).toBe(FLEET_CONDITION_LINE);
    expect(
      await screen.findByText('No fleet condition. No departure is on more than 8 hosts at one time.'),
    ).toBeTruthy();
  });

  it('prints no line on another tab', async () => {
    mountBound('/hunts');
    await screen.findByTestId('lead-69');
    expect(screen.queryByTestId('leads-fleet-line')).toBeNull();
  });

  it('offers a bulk dismiss and no bulk hunt', () => {
    expect(LEAD_BULK_ACTIONS.fleet_condition).toEqual(['dismiss']);
  });
});

describe('the tab counts', () => {
  it('states a count on each tab, and the four state tabs sum to All', async () => {
    mountBound();
    await screen.findByTestId('lead-69');
    await waitFor(() => expect(screen.getByTestId('leads-tab-count-all').textContent).toBe('70'));
    const shown = LEAD_STATE_TABS.map((t) =>
      Number(screen.getByTestId(`leads-tab-count-${t}`).textContent),
    );
    expect(shown).toEqual([8, 0, 15, 47]);
    expect(shown.reduce((a, b) => a + b, 0)).toBe(70);
    // Every lead is in a state tab, so no remainder is printed.
    expect(screen.queryByTestId('leads-queued-note')).toBeNull();
    for (const tab of ['needs_decision', 'in_progress', 'closed', 'fleet_condition', 'all']) {
      expect(getLeadCount).toHaveBeenCalledWith(tab);
    }
  });

  it('prints the leads that wait on auto-hunt, so the printed counts still sum to All', async () => {
    vi.mocked(getLeadCount).mockImplementation(async (status = 'open') => ({
      status,
      entity: null,
      total: status === 'all' ? 73 : (COUNTS[status] ?? 0),
    }));
    mountBound();
    const note = await screen.findByTestId('leads-queued-note');
    expect(note.textContent).toBe('3 new leads wait on auto-hunt. The All tab lists them.');
    const shown = LEAD_STATE_TABS.map((t) =>
      Number(screen.getByTestId(`leads-tab-count-${t}`).textContent),
    );
    expect(shown.reduce((a, b) => a + b, 0) + 3).toBe(
      Number(screen.getByTestId('leads-tab-count-all').textContent),
    );
  });

  it('states no number on a tab whose count the server did not answer', async () => {
    vi.mocked(getLeadCount).mockImplementation(async (status = 'open') => {
      if (status === 'closed') throw new Error('offline');
      return { status, entity: null, total: COUNTS[status] ?? 0 };
    });
    mountBound();
    await waitFor(() => expect(screen.getByTestId('leads-tab-count-all').textContent).toBe('70'));
    expect(screen.queryByTestId('leads-tab-count-closed')).toBeNull();
    // A missing count is no zero. The console claims no remainder from it.
    expect(screen.queryByTestId('leads-queued-note')).toBeNull();
  });

  it('counts the remainder from whole answers only, and never under zero', () => {
    const counts = { needs_decision: 8, in_progress: 0, closed: 15, fleet_condition: 47, all: 70 };
    expect(leadsOutsideTabs(counts)).toBe(0);
    expect(leadsOutsideTabs({ ...counts, all: 72 })).toBe(2);
    expect(leadsOutsideTabs({ ...counts, all: 69 })).toBe(0);
    expect(leadsOutsideTabs({ ...counts, closed: null })).toBeNull();
    expect(leadsOutsideTabs({ ...counts, all: null })).toBeNull();
    expect(leadsOutsideTabs(null)).toBeNull();
  });
});
