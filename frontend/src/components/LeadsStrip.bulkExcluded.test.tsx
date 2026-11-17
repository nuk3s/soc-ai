// F4 (production review 2026-11-12). The bulk bar read "8 leads selected ·
// Dismiss (2) · Hunt (2)". Six of the eight leads were shadow leads, and the
// bar gave no reason: the reason showed only when a count was 0. The bar now
// prints which selected leads a press skips, and why.
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getLeads: vi.fn(),
  getLeadCount: vi.fn(),
  getNeedsYou: vi.fn(),
}));

import { getLeadCount, getLeads, getNeedsYou, type Lead } from '../lib/api';
import { LeadsStrip, bulkExcludedText } from './LeadsStrip';

const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

let nextId = 1;
const lead = (over: Partial<Lead> = {}): Lead => {
  const id = over.id ?? nextId++;
  return {
    id,
    status: 'open',
    formed_at: iso(2 * HOUR),
    updated_at: iso(2 * HOUR),
    entities: [['host', `192.0.2.${id}`]],
    kinds: ['above_baseline'],
    weight_at_formation: 0.9,
    scope_count: 1,
    hunt_id: null,
    shadow: false,
    single_signal: false,
    observations: [],
    hunt_queued: false,
    ...over,
  };
};
const shadow = () => lead({ shadow: true });
const closed = () => lead({ status: 'dismissed', dismissed_reason: 'known_change' });
const running = () => lead({ status: 'hunting', hunt_id: 'H', hunt_status: 'running' });

const mount = (path = '/hunts') =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/hunts" element={<LeadsStrip paramBound />} />
      </Routes>
    </MemoryRouter>,
  );

const byTab = (rows: Partial<Record<string, Lead[]>>) => {
  vi.mocked(getLeads).mockImplementation(async (status = 'open') => rows[status] ?? []);
  vi.mocked(getLeadCount).mockRejectedValue(new Error('not asked'));
};

const bar = () => screen.getByTestId('leads-bulk-bar');

beforeEach(() => {
  nextId = 1;
  vi.mocked(getNeedsYou).mockReset().mockRejectedValue(new Error('offline'));
  vi.mocked(getLeads).mockReset();
  vi.mocked(getLeadCount).mockReset();
});

describe('the sentence of the excluded leads', () => {
  it('states one reason for the leads that no offered action takes', () => {
    const rows = [lead(), lead(), ...Array.from({ length: 6 }, shadow)];
    expect(bulkExcludedText(['dismiss', 'hunt'], rows)).toBe(
      '6 shadow leads take no bulk action. Decide on a shadow lead from its own row.',
    );
    expect(bulkExcludedText(['dismiss', 'hunt'], [lead(), shadow()])).toBe(
      '1 shadow lead takes no bulk action. Decide on a shadow lead from its own row.',
    );
  });

  it('states each action apart when the actions skip different leads', () => {
    const rows = [lead(), shadow(), closed(), closed(), running()];
    expect(bulkExcludedText(['dismiss', 'hunt', 'reopen'], rows)).toBe(
      'Dismiss and Hunt skip 1 shadow lead, 2 closed leads and 1 lead with a hunt in progress. ' +
        'Reopen skips 2 open leads and 1 shadow lead. ' +
        'Decide on a shadow lead from its own row.',
    );
  });

  it('NEGATIVE CONTROL: prints nothing when every selected lead takes every action', () => {
    expect(bulkExcludedText(['dismiss', 'hunt'], [lead(), lead()])).toBeNull();
    expect(bulkExcludedText(['dismiss', 'hunt'], [])).toBeNull();
    expect(bulkExcludedText([], [shadow()])).toBeNull();
  });

  it('NEGATIVE CONTROL: names a skip of one action only on that action', () => {
    // A closed lead reopens. Dismiss and Hunt skip it, and Reopen does not.
    expect(bulkExcludedText(['dismiss', 'hunt', 'reopen'], [closed()])).toBe(
      'Dismiss and Hunt skip 1 closed lead.',
    );
  });
});

describe('the bulk bar', () => {
  it('prints the reason beside counts that are not 0', async () => {
    byTab({ needs_decision: [lead(), lead(), ...Array.from({ length: 6 }, shadow)] });
    mount();
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select the 8 leads on this list' }));
    expect(within(bar()).getByTestId('list-toolbar-selection').textContent).toContain('8 leads selected');
    expect(within(bar()).getByRole('button', { name: 'Dismiss (2)' })).toBeTruthy();
    expect(within(bar()).getByRole('button', { name: 'Hunt (2)' })).toBeTruthy();
    expect(within(bar()).getByTestId('leads-bulk-excluded').textContent).toBe(
      '6 shadow leads take no bulk action. Decide on a shadow lead from its own row.',
    );
  });

  it('follows the selection', async () => {
    byTab({ needs_decision: [lead(), shadow()] });
    mount();
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select lead 1' }));
    // NEGATIVE CONTROL: no skipped lead, no line.
    expect(within(bar()).queryByTestId('leads-bulk-excluded')).toBeNull();
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select lead 2' }));
    expect(within(bar()).getByTestId('leads-bulk-excluded').textContent).toBe(
      '1 shadow lead takes no bulk action. Decide on a shadow lead from its own row.',
    );
  });
});
