// F2 (production review 2026-11-12). 233 unread hits came from 3 analytics.
// Each of the 233 cards repeated "Approve analytic", "Reject analytic" and
// "Mark read", so the analyst pressed Mark read 233 times to clear the pile.
// The block now groups the hits by analytic: one header with the counts, one
// Approve, one Reject and one "Mark N read", and the rows fold under it.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAnalytic: vi.fn(),
  getAnalyticHits: vi.fn(),
  getHuntCatalog: vi.fn(),
  markAnalyticShadowHitsRead: vi.fn(),
  markShadowHitRead: vi.fn(),
  setAnalyticStatus: vi.fn(),
}));

import {
  ApiError,
  getAnalyticHits,
  getHuntCatalog,
  markAnalyticShadowHitsRead,
  markShadowHitRead,
  setAnalyticStatus,
  type AnalyticHit,
  type AnalyticHitGroup,
} from '../lib/api';
import { HIT_GROUP_APPROVE, HIT_GROUP_REJECT, hitGroupMarkRead } from '../lib/tooltips';
import { ShellProvider } from '../shell/ShellContext';
import { AnalyticHits, GROUP_PREVIEW, groupHits } from './AnalyticHits';

const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const RECEIPTS = {
  matched_ids: ['a1'],
  matched_fields: ['event.code'],
  dry_run: { window_days: 30, fires: 2, entities: ['192.0.2.1'] },
  overlap: [],
  baseline: null,
  complete: true,
  missing: [],
};

const RATE = 'prior-connection-rate';
const DROP = 'prior-connection-collapse';
const DCSYNC = 'identity-dcsync';

const hit = (id: number, analytic: string, over: Partial<AnalyticHit> = {}): AnalyticHit => ({
  id,
  analytic_id: analytic,
  analytic_title: `Title of ${analytic}`,
  analytic_status: analytic === DCSYNC ? 'live' : 'shadow',
  recorded_in_shadow: analytic !== DCSYNC,
  tier: 'shipped',
  entity_kind: 'host',
  entity_key: `192.0.2.${id}`,
  born_at: iso(id * HOUR),
  first_seen_at: iso(id * HOUR),
  occurrences: 1,
  summary: null,
  state: 'hit',
  missing: [],
  receipts: RECEIPTS,
  read: analytic === DCSYNC ? null : false,
  lead_id: null,
  lead_status: null,
  document_count: 1,
  ...over,
});

const group = (analytic: string, over: Partial<AnalyticHitGroup>): AnalyticHitGroup => ({
  analytic_id: analytic,
  analytic_title: `Title of ${analytic}`,
  analytic_status: analytic === DCSYNC ? 'live' : 'shadow',
  tier: 'shipped',
  analytic_exists: true,
  hits: 0,
  unread: 0,
  machines: 0,
  accounts: 0,
  newest_at: iso(HOUR),
  ...over,
});

/** The page the server answers: 7 of the 198 hits, and the three groups. */
const ROWS = [
  hit(1, RATE),
  hit(2, RATE),
  hit(3, DROP),
  hit(4, RATE),
  hit(5, RATE),
  hit(6, RATE),
  hit(7, DCSYNC),
];
const GROUPS = [
  group(RATE, { hits: 116, unread: 116, machines: 44 }),
  group(DROP, { hits: 66, unread: 66, machines: 20 }),
  group(DCSYNC, { hits: 16, unread: 0, machines: 3 }),
];
const PAGE = {
  hits: ROWS,
  counts: { all: 198, unread: 182, live: 16, shadow: 182 },
  window: { days: 7, in_window: 39, older_unread: 159 },
  groups: GROUPS,
};

const mount = () =>
  render(
    <MemoryRouter initialEntries={['/hunts']}>
      <ShellProvider>
        <Routes>
          <Route path="/hunts" element={<AnalyticHits />} />
        </Routes>
      </ShellProvider>
    </MemoryRouter>,
  );

const groupOf = async (analytic: string) => await screen.findByTestId(`analytic-group-${analytic}`);
const cardsIn = (el: HTMLElement) => within(el).queryAllByTestId(/^analytic-hit-\d+$/);

beforeEach(() => {
  vi.mocked(getAnalyticHits).mockReset().mockResolvedValue(PAGE);
  vi.mocked(getHuntCatalog).mockReset().mockRejectedValue(new Error('not read'));
  vi.mocked(markShadowHitRead).mockReset().mockResolvedValue({ ok: true });
  vi.mocked(markAnalyticShadowHitsRead).mockReset().mockResolvedValue({ read: 116 });
  vi.mocked(setAnalyticStatus).mockReset().mockResolvedValue({} as never);
});

describe('one header for each analytic', () => {
  it('states the hit count, the unread count and the machines of the whole list', async () => {
    mount();
    const rate = await groupOf(RATE);
    expect(within(rate).getByTestId('analytic-group-counts').textContent).toBe(
      '116 hits · 116 unread · 44 machines',
    );
    expect(within(rate).getByTestId('analytic-group-title').textContent).toBe(`Title of ${RATE}`);
    const live = await groupOf(DCSYNC);
    expect(within(live).getByTestId('analytic-group-counts').textContent).toBe('16 hits · 3 machines');
  });

  it('keeps the order of the server: the analytics with unread hits first', async () => {
    mount();
    await groupOf(RATE);
    const order = screen.getAllByTestId(/^analytic-group-[a-z]/).filter((el) =>
      [RATE, DROP, DCSYNC].some((id) => el.getAttribute('data-testid') === `analytic-group-${id}`),
    );
    expect(order.map((el) => el.getAttribute('data-testid'))).toEqual([
      `analytic-group-${RATE}`,
      `analytic-group-${DROP}`,
      `analytic-group-${DCSYNC}`,
    ]);
  });

  it('counts accounts for an analytic that hits user accounts', () => {
    const [only] = groupHits(
      [hit(1, DCSYNC, { entity_kind: 'user', entity_key: 'jdoe' })],
      [group(DCSYNC, { hits: 3, machines: 0, accounts: 2 })],
      new Set(),
    );
    expect(only.accounts).toBe(2);
    expect(only.machines).toBe(0);
  });
});

describe('one decision for each analytic', () => {
  it('offers one Approve, one Reject and one Mark N read on the header, and none on a card', async () => {
    mount();
    const rate = await groupOf(RATE);
    expect(within(rate).getAllByRole('button', { name: 'Approve analytic' })).toHaveLength(1);
    expect(within(rate).getAllByRole('button', { name: 'Reject analytic' })).toHaveLength(1);
    expect(within(rate).getAllByRole('button', { name: 'Mark 116 read' })).toHaveLength(1);
    // Two shadow analytics, so two of each on the whole block. Six cards of
    // those analytics are on the page.
    expect(screen.getAllByRole('button', { name: 'Approve analytic' })).toHaveLength(2);
    expect(screen.getAllByRole('button', { name: 'Reject analytic' })).toHaveLength(2);
    for (const card of cardsIn(rate)) {
      expect(within(card).queryByRole('button', { name: /analytic/ })).toBeNull();
    }
  });

  it('NEGATIVE CONTROL: offers no decision and no bulk read on a live analytic', async () => {
    mount();
    const live = await groupOf(DCSYNC);
    expect(within(live).queryByRole('button', { name: 'Approve analytic' })).toBeNull();
    expect(within(live).queryByRole('button', { name: 'Reject analytic' })).toBeNull();
    expect(within(live).queryByRole('button', { name: /^Mark \d+ read$/ })).toBeNull();
    expect(within(live).queryByTestId('analytic-group-effects')).toBeNull();
  });

  it('states the effect of each button in plain view and on the hover', async () => {
    mount();
    const rate = await groupOf(RATE);
    expect(within(rate).getByTestId('analytic-group-effects').textContent).toBe(
      `${HIT_GROUP_APPROVE} ${HIT_GROUP_REJECT} ${hitGroupMarkRead(116)}`,
    );
    expect(within(rate).getByRole('button', { name: 'Approve analytic' }).getAttribute('title')).toBe(
      HIT_GROUP_APPROVE,
    );
    expect(within(rate).getByRole('button', { name: 'Reject analytic' }).getAttribute('title')).toBe(
      HIT_GROUP_REJECT,
    );
    expect(within(rate).getByRole('button', { name: 'Mark 116 read' }).getAttribute('title')).toBe(
      hitGroupMarkRead(116),
    );
    expect(hitGroupMarkRead(116)).toBe(
      'Mark 116 read. The 116 unread hits of this analytic are marked read. The analytic keeps its status.',
    );
  });

  it('asks for the reason, posts the approval, then reads the unread hits of that analytic', async () => {
    mount();
    const rate = await groupOf(RATE);
    fireEvent.click(within(rate).getByRole('button', { name: 'Approve analytic' }));
    expect(within(rate).getByTestId('analytic-decision-note').textContent).toBe(
      'The analytic goes live with this reason. It raises what it finds. Its 116 unread hits are marked read.',
    );
    fireEvent.change(within(rate).getByPlaceholderText('Why it goes live'), {
      target: { value: 'matches the change window' },
    });
    fireEvent.click(within(rate).getByRole('button', { name: 'Confirm' }));
    await waitFor(() =>
      expect(setAnalyticStatus).toHaveBeenCalledWith(RATE, 'live', 'matches the change window'),
    );
    await waitFor(() => expect(markAnalyticShadowHitsRead).toHaveBeenCalledTimes(1));
    expect(vi.mocked(markAnalyticShadowHitsRead).mock.calls[0][0]).toBe(RATE);
    // The list reads again.
    await waitFor(() => expect(vi.mocked(getAnalyticHits).mock.calls.length).toBeGreaterThan(1));
  });

  it('retires the analytic on Reject, and reads no hit', async () => {
    mount();
    const drop = await groupOf(DROP);
    fireEvent.click(within(drop).getByRole('button', { name: 'Reject analytic' }));
    expect(within(drop).getByTestId('analytic-decision-note').textContent).toBe(
      'The analytic is retired with this reason. It stops running. Its hits leave this list.',
    );
    fireEvent.change(within(drop).getByPlaceholderText('Why it is rejected'), {
      target: { value: 'fires on every backup' },
    });
    fireEvent.click(within(drop).getByRole('button', { name: 'Confirm' }));
    await waitFor(() =>
      expect(setAnalyticStatus).toHaveBeenCalledWith(DROP, 'retired', 'fires on every backup'),
    );
    expect(markAnalyticShadowHitsRead).not.toHaveBeenCalled();
  });
});

describe('Mark N read', () => {
  it('reads the unread hits of one analytic in one write, with the count on the button', async () => {
    mount();
    const rate = await groupOf(RATE);
    fireEvent.click(within(rate).getByRole('button', { name: 'Mark 116 read' }));
    await waitFor(() => expect(markAnalyticShadowHitsRead).toHaveBeenCalledTimes(1));
    const [analytic, before, expected] = vi.mocked(markAnalyticShadowHitsRead).mock.calls[0];
    expect(analytic).toBe(RATE);
    expect(Number.isNaN(Date.parse(before))).toBe(false);
    expect(expected).toBe(116);
    // NEGATIVE CONTROL: no press for each hit, and no other analytic.
    expect(markShadowHitRead).not.toHaveBeenCalled();
    await waitFor(() => expect(vi.mocked(getAnalyticHits).mock.calls.length).toBeGreaterThan(1));
  });

  it('takes a hit that this session read off the count on the button', async () => {
    mount();
    const rate = await groupOf(RATE);
    fireEvent.click(within(cardsIn(rate)[0]).getByRole('button', { name: 'Mark read' }));
    await waitFor(() =>
      expect(within(rate).getByRole('button', { name: 'Mark 115 read' })).toBeTruthy(),
    );
    expect(within(rate).getByTestId('analytic-group-counts').textContent).toBe(
      '116 hits · 115 unread · 44 machines',
    );
    // NEGATIVE CONTROL: the other analytic keeps its count.
    expect(within(await groupOf(DROP)).getByRole('button', { name: 'Mark 66 read' })).toBeTruthy();
  });

  it('states the refusal of the server and marks nothing', async () => {
    vi.mocked(markAnalyticShadowHitsRead).mockRejectedValue(
      new ApiError(
        '2 new shadow hits arrived after the count. Open the list again and confirm the new count.',
        409,
        'shadow_hits_changed',
      ),
    );
    mount();
    const rate = await groupOf(RATE);
    fireEvent.click(within(rate).getByRole('button', { name: 'Mark 116 read' }));
    expect(await within(rate).findByTestId('analytic-group-failed')).toBeTruthy();
    expect(within(rate).getByTestId('analytic-group-failed').textContent).toContain(
      '2 new shadow hits arrived after the count.',
    );
  });
});

describe('the rows fold under the header', () => {
  it('shows three hits of an analytic, then the rest on request', async () => {
    mount();
    const rate = await groupOf(RATE);
    expect(GROUP_PREVIEW).toBe(3);
    expect(cardsIn(rate)).toHaveLength(3);
    fireEvent.click(within(rate).getByRole('button', { name: 'Show 2 more hits' }));
    expect(cardsIn(rate)).toHaveLength(5);
    fireEvent.click(within(rate).getByRole('button', { name: 'Show fewer hits' }));
    expect(cardsIn(rate)).toHaveLength(3);
  });

  it('NEGATIVE CONTROL: offers no fold on an analytic with three hits or fewer', async () => {
    mount();
    const drop = await groupOf(DROP);
    expect(cardsIn(drop)).toHaveLength(1);
    expect(within(drop).queryByRole('button', { name: /more hits|fewer hits/ })).toBeNull();
  });

  it('says how many hits of the analytic the list holds', async () => {
    mount();
    const rate = await groupOf(RATE);
    expect(within(rate).getByTestId('analytic-group-share').textContent).toBe(
      'The list holds 5 of the 116 hits of this analytic. Show more reads the next hits of the list.',
    );
  });

  it('keeps the header of an analytic whose hits are on a later page', async () => {
    vi.mocked(getAnalyticHits).mockResolvedValue({
      ...PAGE,
      groups: [...GROUPS, group('prior-later-page', { hits: 1, unread: 1, machines: 1 })],
    });
    mount();
    const later = await groupOf('prior-later-page');
    expect(cardsIn(later)).toHaveLength(0);
    expect(within(later).getByTestId('analytic-group-counts').textContent).toBe(
      '1 hit · 1 unread · 1 machine',
    );
    expect(within(later).getByTestId('analytic-group-share').textContent).toBe(
      'The list holds 0 of the 1 hit of this analytic. Show more reads the next hits of the list.',
    );
    // The hits of the analytic can still be read in one press.
    expect(within(later).getByRole('button', { name: 'Mark 1 read' })).toBeTruthy();
  });

  it('keeps every hit of the page in one group and in no other', async () => {
    mount();
    await groupOf(RATE);
    for (const analytic of [RATE, DROP, DCSYNC]) {
      const el = await groupOf(analytic);
      const toggle = within(el).queryByRole('button', { name: /more hits$/ });
      if (toggle) fireEvent.click(toggle);
    }
    expect(screen.getAllByTestId(/^analytic-hit-\d+$/)).toHaveLength(ROWS.length);
  });
});

describe('a server that sends no groups', () => {
  it('groups the hits it has read, and counts those hits', async () => {
    vi.mocked(getAnalyticHits).mockResolvedValue({ hits: ROWS, counts: PAGE.counts });
    mount();
    const rate = await groupOf(RATE);
    expect(within(rate).getByTestId('analytic-group-counts').textContent).toBe(
      '5 hits · 5 unread · 5 machines',
    );
    expect(within(rate).getByRole('button', { name: 'Mark 5 read' })).toBeTruthy();
    expect(within(rate).queryByTestId('analytic-group-share')).toBeNull();
  });
});
