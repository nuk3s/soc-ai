// F3 (production review 2026-11-12). The block read "last 7 days · 249". 39
// of the 249 hits were from the last 7 days. The rest were older unread
// shadow hits, which the list holds at any age. Owner rule: every count obeys
// the time filter of its page, or it states its own window. The label now
// states the two counts apart.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAnalyticHits: vi.fn(),
  getHuntCatalog: vi.fn(),
  markShadowHitRead: vi.fn(),
}));

import { getAnalyticHits, getHuntCatalog, markShadowHitRead, type AnalyticHit } from '../lib/api';
import { ShellProvider } from '../shell/ShellContext';
import { AnalyticHits } from './AnalyticHits';

const DAY = 86_400_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const hit = (id: number, daysOld: number, over: Partial<AnalyticHit> = {}): AnalyticHit => ({
  id,
  analytic_id: 'prior-connection-rate',
  analytic_title: "A host's connection rate rises far above its own baseline",
  analytic_status: 'shadow',
  recorded_in_shadow: true,
  tier: 'shipped',
  entity_kind: 'host',
  entity_key: `192.0.2.${id}`,
  born_at: iso(daysOld * DAY),
  first_seen_at: iso(daysOld * DAY),
  occurrences: 1,
  summary: null,
  state: 'hit',
  missing: [],
  receipts: null,
  read: false,
  lead_id: null,
  lead_status: null,
  document_count: 1,
  document_ids: ['d1'],
  ...over,
});

/** The production counts of the review. */
const PROD = {
  hits: [hit(1, 2), hit(2, 35)],
  counts: { all: 249, unread: 233, live: 16, shadow: 233 },
  window: { days: 7, in_window: 39, older_unread: 210 },
};

const mount = (collapsed?: boolean) =>
  render(
    <MemoryRouter initialEntries={['/hunts']}>
      <ShellProvider>
        <Routes>
          <Route
            path="/hunts"
            element={
              collapsed === undefined ? (
                <AnalyticHits />
              ) : (
                <AnalyticHits collapsed={collapsed} onToggleCollapsed={() => {}} />
              )
            }
          />
        </Routes>
      </ShellProvider>
    </MemoryRouter>,
  );

const label = async () => (await screen.findByTestId('analytic-hits-window')).textContent;

beforeEach(() => {
  vi.mocked(getAnalyticHits).mockReset().mockResolvedValue(PROD);
  vi.mocked(getHuntCatalog).mockReset().mockRejectedValue(new Error('not read'));
  vi.mocked(markShadowHitRead).mockReset().mockResolvedValue({ ok: true });
});

describe('the label of the Analytic hits block', () => {
  it('states the hits of the window and the older unread hits apart', async () => {
    mount();
    await waitFor(async () =>
      expect(await label()).toBe('39 in the last 7 days · 210 older unread'),
    );
    // The two parts sum to the total the All chip states.
    expect(screen.getByRole('button', { name: /^All/ }).textContent).toBe('All249');
  });

  it('NEGATIVE CONTROL: never prints the sum under the words "last 7 days"', async () => {
    mount();
    await waitFor(async () => expect(await label()).toContain('39 in the last 7 days'));
    expect(screen.queryByText(/last 7 days · 249/)).toBeNull();
    expect(screen.queryByText(/249 in the last 7 days/)).toBeNull();
  });

  it('states a zero, so the second window is on the label on every load', async () => {
    vi.mocked(getAnalyticHits).mockResolvedValue({
      hits: [hit(1, 2)],
      counts: { all: 1, unread: 1, live: 0, shadow: 1 },
      window: { days: 7, in_window: 1, older_unread: 0 },
    });
    mount();
    await waitFor(async () => expect(await label()).toBe('1 in the last 7 days · 0 older unread'));
  });

  it('adds the unread total while the block is folded', async () => {
    mount(true);
    await waitFor(async () =>
      expect(await label()).toBe('39 in the last 7 days · 210 older unread · 233 unread in all'),
    );
  });

  it('takes an older hit that this session read off the older unread count', async () => {
    mount();
    const old = await screen.findByTestId('analytic-hit-2');
    fireEvent.click(within(old).getByRole('button', { name: 'Mark read' }));
    await waitFor(async () => expect(await label()).toBe('39 in the last 7 days · 209 older unread'));
    // NEGATIVE CONTROL: a hit inside the window leaves the older count as it is.
    const fresh = screen.getByTestId('analytic-hit-1');
    fireEvent.click(within(fresh).getByRole('button', { name: 'Mark read' }));
    await waitFor(() => expect(markShadowHitRead).toHaveBeenCalledTimes(2));
    expect(await label()).toBe('39 in the last 7 days · 209 older unread');
  });

  it('states both windows in words for a server that sends one total', async () => {
    vi.mocked(getAnalyticHits).mockResolvedValue({ hits: PROD.hits, counts: PROD.counts });
    mount();
    await waitFor(async () => expect(await label()).toBe('last 7 days and older unread · 249'));
  });
});
