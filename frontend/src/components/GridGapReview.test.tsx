// The review of one grid gap (2026-10-19).
//
// The first sweep after the range outage wrote eight false hits. The operator
// opened each one and marked it benign, 24 actions, and found alone that the
// hold of a live analytic came from the outage (dogfood R1-I5, R3-I1, R3-I2,
// R4-I3). The drawer lists the hits of the gap, marks them benign in one write
// after a confirm that states the counts, and names each held analytic. Return
// to live stays a separate click.
//
// Round 2 (G-1): the range review listed 12 hits, and one confirm marked them
// all, two rate spikes and a collapse that ran on after the recovery among
// them. The drawer now selects only the hits inside the gap and marks only the
// selection.
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getGridGapHits: vi.fn(),
  getGridGaps: vi.fn(),
  markGridGapHitsBenign: vi.fn(),
  setAnalyticStatus: vi.fn(),
}));

import {
  getGridGapHits,
  getGridGaps,
  markGridGapHitsBenign,
  setAnalyticStatus,
} from '../lib/api';
import type { GridGap, GridGapHits, GridGapHold } from '../lib/types';
import { ShellProvider } from '../shell/ShellContext';
import { GridGapReviewDrawer, RETURN_TO_LIVE_WHY, gapHoldLine, gapHoldOffer } from './GridGapReview';
import { GridGapStrip } from './GridGapStrip';

const GAP: GridGap = {
  id: 7,
  source: 'operator',
  plane: null,
  started_at: '2026-10-15T13:36:00Z',
  ended_at: '2026-10-19T10:15:00Z',
  open: false,
  duration_s: 333_540,
  detail: 'The sensor VM was down.',
  hits_to_review: 2,
};

const OFFERED: GridGapHold = {
  analytic_id: 'profile-connection-rate-collapsed',
  title: 'The connection rate of a host collapses',
  hits: 5,
  gap_hits: 5,
  budget: 3,
  return_offered: true,
  gap_ids: [7],
  held_at: '2026-10-19T10:22:00Z',
};

const NOT_OFFERED: GridGapHold = {
  ...OFFERED,
  analytic_id: 'profile-plane-silence',
  title: 'A telemetry plane falls silent',
  hits: 9,
  gap_hits: 5,
  return_offered: false,
};

const REVIEW: GridGapHits = {
  gap: GAP,
  review_start: '2026-10-15T13:36:00Z',
  review_end: '2026-10-19T11:15:00Z',
  settle_minutes: 60,
  note: 'Grid gap from 2026-10-15 13:36 UTC to 2026-10-19 10:15 UTC',
  count: 2,
  hits: [
    {
      id: 89,
      analytic_id: 'profile-connection-rate-collapsed',
      analytic_title: 'The connection rate of a host collapses',
      entity_kind: 'host',
      entity_key: '192.0.2.10',
      kind: 'below_baseline',
      kind_label: 'rate collapsed',
      summary: null,
      recorded_in_shadow: false,
      lead_id: 5,
      event_start: '2026-10-18T11:00:00Z',
      event_end: '2026-10-19T10:00:00Z',
      born_at: '2026-10-19T10:21:38Z',
      inside_gap: true,
      selected_by_default: true,
      reasons: [],
    },
    {
      id: 94,
      analytic_id: 'model-cross-plane-silence',
      analytic_title: 'A telemetry plane falls silent',
      entity_kind: 'host',
      entity_key: '192.0.2.11',
      kind: 'telemetry_silence',
      kind_label: 'plane silent',
      summary: null,
      recorded_in_shadow: true,
      lead_id: null,
      event_start: '2026-10-16T13:00:00Z',
      event_end: '2026-10-19T10:00:00Z',
      born_at: '2026-10-19T10:21:38Z',
      inside_gap: true,
      selected_by_default: true,
      reasons: [],
    },
  ],
  selected_count: 2,
  leads: [5],
  held: [OFFERED, NOT_OFFERED],
};

const SPIKE_REASON = 'A gap does not explain a spike. Check for a back-fill burst.';
const EDGE_REASON = 'Part of this window is outside the gap.';

/** The shape of the live review of the range gap: hits inside the gap beside a
 *  spike inside it and a collapse that ran on after the recovery. */
const RANGE: GridGapHits = {
  ...REVIEW,
  count: 4,
  selected_count: 2,
  leads: [5, 7],
  hits: [
    {
      ...REVIEW.hits[0],
      id: 76,
      analytic_id: 'profile-connection-rate-spiked',
      analytic_title: 'The connection rate of a host spikes',
      entity_key: '198.51.100.254',
      kind: 'above_baseline',
      kind_label: 'rate spiked',
      lead_id: 7,
      event_start: '2026-10-15T15:00:00Z',
      event_end: '2026-10-15T16:00:00Z',
      inside_gap: true,
      selected_by_default: false,
      reasons: [SPIKE_REASON],
    },
    REVIEW.hits[1],
    REVIEW.hits[0],
    {
      ...REVIEW.hits[0],
      id: 100,
      entity_key: '203.0.113.123',
      lead_id: null,
      event_start: '2026-10-19T10:00:00Z',
      event_end: '2026-10-19T13:00:00Z',
      inside_gap: false,
      selected_by_default: false,
      reasons: [EDGE_REASON],
    },
  ],
};

const EMPTY: GridGapHits = { ...REVIEW, count: 0, hits: [], leads: [] };

async function settle() {
  await act(async () => {
    await new Promise((r) => setTimeout(r, 0));
  });
}

const mount = (gapId: number | null = 7, onChanged = vi.fn()) =>
  render(
    <MemoryRouter>
      <ShellProvider>
        <GridGapReviewDrawer gapId={gapId} onClose={() => {}} onChanged={onChanged} />
      </ShellProvider>
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getGridGapHits).mockReset().mockResolvedValue(REVIEW);
  vi.mocked(markGridGapHitsBenign).mockReset().mockResolvedValue({
    marked: 2,
    ids: [89, 94],
    leads: [5],
    note: REVIEW.note,
    held: [OFFERED, NOT_OFFERED],
  });
  vi.mocked(setAnalyticStatus).mockReset();
  vi.mocked(getGridGaps).mockReset();
});

describe('the hold lines', () => {
  it('counts the gap hits against the hits that broke the limit', () => {
    expect(gapHoldLine(OFFERED)).toBe(
      '5 of the 5 hits that broke the daily hit limit fall inside a grid gap.',
    );
    expect(gapHoldLine({ ...OFFERED, gap_hits: 1 })).toBe(
      '1 of the 5 hits that broke the daily hit limit falls inside a grid gap.',
    );
  });

  it('says when the gap hits alone broke the limit, and when they did not', () => {
    expect(gapHoldOffer(OFFERED)).toBe(
      'Without them, the analytic stays inside its limit of 3 hits a day.',
    );
    expect(gapHoldOffer(NOT_OFFERED)).toBe('The other 4 hits alone break the limit of 3 hits a day.');
    // The other hits fit the limit, and a second breach holds the analytic.
    expect(gapHoldOffer({ ...NOT_OFFERED, hits: 6 })).toBe(
      'The hold names another breach too. Read it under Versions.',
    );
  });

  it('does not lean on spikes inside the gap', () => {
    // On the range: 2 of the 4 hits were spikes inside the gap. A gap does not
    // explain a spike, so the card says why it offers no Return to live.
    const spikes = { ...NOT_OFFERED, hits: 4, gap_hits: 2, spike_hits: 2 };
    expect(gapHoldOffer(spikes)).toBe(
      'A gap does not explain the 2 spikes. Check for a back-fill burst before you approve the analytic.',
    );
  });
});

describe('GridGapReviewDrawer', () => {
  it('stays closed with no gap', () => {
    const { container } = mount(null);
    expect(container.textContent).toBe('');
    expect(getGridGapHits).not.toHaveBeenCalled();
  });

  it('names the gap, the rule and each hit with its event window', async () => {
    mount();
    const list = await screen.findByTestId('gap-hits');
    expect(getGridGapHits).toHaveBeenCalledWith(7);
    expect(
      screen.getByText('The grid held no data from 2026-10-15 13:36 to 2026-10-19 10:15 UTC.'),
    ).toBeTruthy();
    expect(
      screen.getByText(
        'The list holds the hits that measure a count or a silence. Their events overlap the gap or the 60 minutes after it.',
      ),
    ).toBeTruthy();
    expect(
      screen.getByText(
        'soc-ai selects each hit whose events lie inside that time. It does not select a spike.',
      ),
    ).toBeTruthy();
    const rows = within(list).getAllByRole('listitem');
    expect(rows).toHaveLength(2);
    expect(rows[0].textContent).toContain('192.0.2.10');
    expect(rows[0].textContent).toContain('Events 2026-10-18 11:00 to 2026-10-19 10:00 UTC.');
    expect(within(rows[0]).getByRole('link', { name: 'in lead 5' }).getAttribute('href')).toBe(
      '/leads/5',
    );
    expect(rows[1].textContent).toContain('shadow');
  });

  it('states the counts before it writes, then marks with the confirmed count', async () => {
    const onChanged = vi.fn();
    mount(7, onChanged);
    fireEvent.click(await screen.findByTestId('gap-mark-benign'));
    const confirm = screen.getByTestId('gap-mark-confirm');
    expect(confirm.textContent).toContain(
      `soc-ai marks 2 hits benign with the note "${REVIEW.note}".`,
    );
    expect(confirm.textContent).toContain('1 lead holds some of these hits.');
    expect(confirm.textContent).toContain('No analytic changes status. You cannot undo the marks.');
    // Nothing is written before the confirm.
    expect(markGridGapHitsBenign).not.toHaveBeenCalled();

    vi.mocked(getGridGapHits).mockResolvedValue(EMPTY);
    fireEvent.click(within(confirm).getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(screen.getByTestId('gap-mark-result')).toBeTruthy());
    expect(markGridGapHitsBenign).toHaveBeenCalledWith(7, [89, 94], 2);
    expect(screen.getByTestId('gap-mark-result').textContent).toBe('soc-ai marked 2 hits benign.');
    expect(onChanged).toHaveBeenCalled();
    // The review reads again and finds nothing left.
    await waitFor(() => expect(screen.getByTestId('gap-no-hits')).toBeTruthy());
    // The mark moved no analytic.
    expect(setAnalyticStatus).not.toHaveBeenCalled();
  });

  it('writes nothing when the operator cancels', async () => {
    mount();
    fireEvent.click(await screen.findByTestId('gap-mark-benign'));
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByTestId('gap-mark-confirm')).toBeNull();
    expect(markGridGapHitsBenign).not.toHaveBeenCalled();
  });

  it('shows the refusal when a selected hit left the gap list', async () => {
    const refusal =
      '1 of the selected hits is no longer in the gap list. Open the review again and select the hits again.';
    vi.mocked(markGridGapHitsBenign).mockRejectedValue(new Error(refusal));
    mount();
    fireEvent.click(await screen.findByTestId('gap-mark-benign'));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(await screen.findByText(refusal)).toBeTruthy();
    expect(screen.queryByTestId('gap-mark-result')).toBeNull();
  });

  it('leaves a spike and an edge hit unselected, with the reason under each', async () => {
    vi.mocked(getGridGapHits).mockResolvedValue(RANGE);
    mount();
    const list = await screen.findByTestId('gap-hits');
    const rows = within(list).getAllByRole('listitem');
    const box = (row: HTMLElement) => within(row).getByRole('checkbox') as HTMLInputElement;
    expect(rows.map((row) => box(row).checked)).toEqual([false, true, true, false]);
    expect(rows[0].textContent).toContain(SPIKE_REASON);
    expect(rows[3].textContent).toContain(EDGE_REASON);
    expect(rows[1].textContent).not.toContain(EDGE_REASON);
    expect(box(rows[0]).getAttribute('aria-label')).toBe(
      'Select the rate spiked hit on 198.51.100.254',
    );
    expect(screen.getByTestId('gap-mark-benign').textContent).toBe('Mark 2 of 4 hits benign');
  });

  it('marks only the selected hits, and the operator can add an unselected one', async () => {
    vi.mocked(getGridGapHits).mockResolvedValue(RANGE);
    mount();
    const list = await screen.findByTestId('gap-hits');
    const rows = within(list).getAllByRole('listitem');
    // The operator checks the edge hit and clears one inside hit.
    fireEvent.click(within(rows[3]).getByRole('checkbox'));
    fireEvent.click(within(rows[1]).getByRole('checkbox'));
    expect(screen.getByTestId('gap-mark-benign').textContent).toBe('Mark 2 of 4 hits benign');
    fireEvent.click(screen.getByTestId('gap-mark-benign'));
    const confirm = screen.getByTestId('gap-mark-confirm');
    expect(confirm.textContent).toContain(
      `soc-ai marks 2 hits benign with the note "${RANGE.note}".`,
    );
    expect(confirm.textContent).toContain('2 hits stay unmarked.');
    // Only lead 5 holds a selected hit.
    expect(confirm.textContent).toContain('1 lead holds some of these hits.');
    vi.mocked(markGridGapHitsBenign).mockResolvedValue({
      marked: 2,
      ids: [89, 100],
      leads: [5],
      note: RANGE.note,
      held: [],
    });
    fireEvent.click(within(confirm).getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(screen.getByTestId('gap-mark-result')).toBeTruthy());
    expect(markGridGapHitsBenign).toHaveBeenCalledWith(7, [89, 100], 2);
    // The marked hits leave the list. The two left out stay with the choice
    // the operator made, and a second pass can mark them.
    const after = within(screen.getByTestId('gap-hits')).getAllByRole('listitem');
    expect(after).toHaveLength(2);
    const boxes = after.map((row) => within(row).getByRole('checkbox') as HTMLInputElement);
    expect(boxes.map((box) => box.checked)).toEqual([false, false]);
    expect(screen.getByTestId('gap-mark-benign').textContent).toBe('Mark 0 of 2 hits benign');
    fireEvent.click(boxes[1]);
    expect(screen.getByTestId('gap-mark-benign').textContent).toBe('Mark 1 of 2 hits benign');
  });

  it('turns the mark off when no hit is selected', async () => {
    vi.mocked(getGridGapHits).mockResolvedValue({
      ...RANGE,
      hits: [RANGE.hits[0], RANGE.hits[3]],
      count: 2,
      selected_count: 0,
    });
    mount();
    const mark = (await screen.findByTestId('gap-mark-benign')) as HTMLButtonElement;
    expect(mark.disabled).toBe(true);
    expect(mark.textContent).toBe('Mark 0 of 2 hits benign');
    expect(mark.title).toBe('Select a hit to mark it benign.');
  });

  it('selects every hit from an older server that sends no selection', async () => {
    vi.mocked(getGridGapHits).mockResolvedValue({
      ...REVIEW,
      selected_count: undefined,
      hits: REVIEW.hits.map(({ selected_by_default, reasons, inside_gap, ...hit }) => hit),
    });
    mount();
    const list = await screen.findByTestId('gap-hits');
    const boxes = within(list).getAllByRole('checkbox') as HTMLInputElement[];
    expect(boxes.map((b) => b.checked)).toEqual([true, true]);
    expect(screen.getByTestId('gap-mark-benign').textContent).toBe('Mark 2 hits benign');
  });

  it('offers Return to live only where the gap hits alone broke the limit', async () => {
    vi.mocked(setAnalyticStatus).mockResolvedValue({} as never);
    const onChanged = vi.fn();
    mount(7, onChanged);
    const offered = await screen.findByTestId(`gap-hold-${OFFERED.analytic_id}`);
    const refused = screen.getByTestId(`gap-hold-${NOT_OFFERED.analytic_id}`);
    expect(within(refused).queryByRole('button', { name: 'Return to live' })).toBeNull();
    expect(refused.textContent).toContain('The other 4 hits alone break the limit of 3 hits a day.');
    // Nothing moves the analytic until the operator clicks.
    expect(setAnalyticStatus).not.toHaveBeenCalled();
    // The next read lists the analytic no more: it is live.
    vi.mocked(getGridGapHits).mockResolvedValue({ ...REVIEW, held: [NOT_OFFERED] });
    fireEvent.click(within(offered).getByRole('button', { name: 'Return to live' }));
    await waitFor(() =>
      expect(screen.queryByTestId(`gap-hold-${OFFERED.analytic_id}`)).toBeNull(),
    );
    expect(setAnalyticStatus).toHaveBeenCalledWith(OFFERED.analytic_id, 'live', RETURN_TO_LIVE_WHY);
    expect(onChanged).toHaveBeenCalled();
    // The answer stays on screen after the row leaves the list.
    expect(screen.getByTestId('gap-returned').textContent).toBe(
      `The analytic "${OFFERED.title}" is live again.`,
    );
  });

  it('offers no mark on an open gap', async () => {
    vi.mocked(getGridGapHits).mockResolvedValue({
      ...REVIEW,
      gap: { ...GAP, open: true, ended_at: null },
    });
    mount();
    expect(
      await screen.findByText('The gap is open. Review its hits after the grid comes back.'),
    ).toBeTruthy();
    expect(screen.queryByTestId('gap-mark-benign')).toBeNull();
  });
});

describe('the strip link', () => {
  const reply = (gaps: GridGap[]) => ({
    since: new Date(Date.now() - 7 * 86_400_000).toISOString(),
    until: new Date().toISOString(),
    gaps,
  });

  it('offers the review on a closed gap that wrote hits, and opens the drawer', async () => {
    vi.mocked(getGridGaps).mockResolvedValue(reply([GAP]));
    render(
      <MemoryRouter>
        <ShellProvider>
          <GridGapStrip range="7d" />
        </ShellProvider>
      </MemoryRouter>,
    );
    const link = await screen.findByTestId('grid-gap-review');
    expect(link.textContent).toBe('Review 2 hits in this gap');
    fireEvent.click(link);
    await screen.findByTestId('gap-hits');
    expect(getGridGapHits).toHaveBeenCalledWith(7);
  });

  it('offers no review on an open gap, on a gap with no hits, or on an older server', async () => {
    vi.mocked(getGridGaps).mockResolvedValue(
      reply([
        { ...GAP, id: 1, open: true, ended_at: null },
        { ...GAP, id: 2, hits_to_review: 0 },
        { ...GAP, id: 3, hits_to_review: undefined },
      ]),
    );
    render(
      <MemoryRouter>
        <GridGapStrip range="7d" />
      </MemoryRouter>,
    );
    await settle();
    expect(screen.getAllByTestId('grid-gap')).toHaveLength(3);
    expect(screen.queryByTestId('grid-gap-review')).toBeNull();
  });
});
