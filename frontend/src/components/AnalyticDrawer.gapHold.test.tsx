// The hold card names the grid gap (2026-10-19).
//
// After the range outage the daily hit limit held a live analytic in shadow,
// and the card said only "The analytic wrote 5 hits in 24 hours". The operator
// found alone that every hit came from the outage (dogfood R1-I5, R3-I1). The
// card now states how many of the hits fall inside a grid gap, and it offers
// Return to live when the gap hits alone broke the limit. The click stays the
// operator's.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAnalytic: vi.fn(),
  getGridGapHits: vi.fn(),
  getHuntCatalog: vi.fn(),
  setAnalyticStatus: vi.fn(),
}));

import { getAnalytic, getGridGapHits, getHuntCatalog, setAnalyticStatus } from '../lib/api';
import type { AnalyticDetail } from '../lib/api';
import type { GridGapHold } from '../lib/types';
import { ShellProvider } from '../shell/ShellContext';
import { AnalyticDrawer } from './AnalyticDrawer';
import { RETURN_TO_LIVE_WHY } from './GridGapReview';

const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();
const REASON = 'The analytic wrote 5 hits in 24 hours. Its daily hit limit is 3.';

const HOLD: GridGapHold = {
  analytic_id: 'profile-connection-rate-collapsed',
  title: 'The connection rate of a host collapses',
  hits: 5,
  gap_hits: 5,
  budget: 3,
  return_offered: true,
  gap_ids: [7],
  held_at: iso(3_600_000),
};

const HELD: AnalyticDetail = {
  id: 'profile-connection-rate-collapsed',
  title: 'The connection rate of a host collapses',
  level: 'medium',
  evaluator: 'profile',
  scope_kind: 'host',
  tier: 'shipped',
  status: 'shadow',
  no_benign_baseline: false,
  observations_7d: 5,
  leads_7d: 1,
  hunted_7d: 1,
  dismissed_7d: 0,
  shadow_hits_7d: 0,
  unread_shadow_hits: 0,
  description: 'The connection rate of a host falls far below its own baseline.',
  spec_text: 'id: profile-connection-rate-collapsed\n',
  reason: REASON,
  held_by_system: REASON,
  ledger: {
    analytic_id: 'profile-connection-rate-collapsed',
    since: iso(30 * 86_400_000),
    observations: 5,
    entities: 5,
    shadow_hits: 0,
    unread_shadow_hits: 0,
    leads: 1,
    hunted: 1,
    promoted: 0,
    dismissed: {},
    docs_scanned: 0,
    runtime_ms: 0,
    sweeps: 0,
    coverage: {},
  },
  versions: [
    {
      from_status: 'live',
      to_status: 'shadow',
      who: 'system:self-heal',
      at: iso(3_600_000),
      why: REASON,
      has_receipts: false,
      system: true,
      evidence: { breaches: [{ rule: 'fire_budget', hits: 5, budget: 3 }] },
    },
  ],
  recent: [],
  gap_hold: HOLD,
};

const mount = () =>
  render(
    <MemoryRouter>
      <ShellProvider>
        <AnalyticDrawer analyticId={HELD.id} onClose={() => {}} />
      </ShellProvider>
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getAnalytic).mockReset().mockResolvedValue(HELD);
  vi.mocked(getHuntCatalog).mockReset().mockRejectedValue(new Error('no catalog in this test'));
  vi.mocked(getGridGapHits).mockReset().mockReturnValue(new Promise(() => {}));
  vi.mocked(setAnalyticStatus).mockReset().mockResolvedValue({ ...HELD, status: 'live' });
});

describe('the hold card, a hold from a grid gap', () => {
  it('states how many of the hits that broke the limit fall inside a grid gap', async () => {
    mount();
    const note = await screen.findByTestId('analytic-held-gap');
    expect(within(screen.getByTestId('analytic-held')).getByTestId('analytic-held-gap')).toBe(note);
    expect(note.textContent).toContain(
      '5 of the 5 hits that broke the daily hit limit fall inside a grid gap.',
    );
    expect(note.textContent).toContain(
      'Without them, the analytic stays inside its limit of 3 hits a day.',
    );
  });

  it('returns the analytic to live on the operator click only', async () => {
    mount();
    const note = await screen.findByTestId('analytic-held-gap');
    expect(setAnalyticStatus).not.toHaveBeenCalled();
    fireEvent.click(within(note).getByRole('button', { name: 'Return to live' }));
    await waitFor(() =>
      expect(setAnalyticStatus).toHaveBeenCalledWith(HELD.id, 'live', RETURN_TO_LIVE_WHY),
    );
    // The drawer reads the analytic again.
    await waitFor(() => expect(vi.mocked(getAnalytic).mock.calls.length).toBeGreaterThan(1));
  });

  it('offers no Return to live when the other hits alone break the limit', async () => {
    vi.mocked(getAnalytic).mockResolvedValue({
      ...HELD,
      gap_hold: { ...HOLD, hits: 9, return_offered: false },
    });
    mount();
    const note = await screen.findByTestId('analytic-held-gap');
    expect(note.textContent).toContain(
      '5 of the 9 hits that broke the daily hit limit fall inside a grid gap.',
    );
    expect(note.textContent).toContain('The other 4 hits alone break the limit of 3 hits a day.');
    expect(within(note).queryByRole('button', { name: 'Return to live' })).toBeNull();
  });

  it('opens the review of the gap from the card', async () => {
    mount();
    fireEvent.click(await screen.findByTestId('analytic-held-gap-review'));
    await waitFor(() => expect(getGridGapHits).toHaveBeenCalledWith(7));
  });

  it('says nothing about a gap on a hold no gap explains', async () => {
    vi.mocked(getAnalytic).mockResolvedValue({ ...HELD, gap_hold: null });
    mount();
    await screen.findByTestId('analytic-held');
    expect(screen.queryByTestId('analytic-held-gap')).toBeNull();
  });
});
