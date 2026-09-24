// Analytic hits — one surface for the live hits and the shadow hits.
//
// The second dogfood found two faults the band could not fix: a card did not
// separate the analytic from the instance it fired on, and a live hit had no
// surface at all. These tests pin both, and they pin the rules that keep the
// surface honest: the real hit is never lighter than the provisional one, a hit
// with incomplete receipts reads "could not run" and is still listed, a failed
// read reads as a failure, and a hit a lead holds sends the analyst to the lead
// instead of starting a second hunt beside it.
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAnalytic: vi.fn(),
  getAnalyticHits: vi.fn(),
  getEvent: vi.fn(),
  markShadowHitRead: vi.fn(),
  setAnalyticStatus: vi.fn(),
  startHuntConsole: vi.fn(),
}));

import {
  ApiError,
  getAnalyticHits,
  markShadowHitRead,
  setAnalyticStatus,
  startHuntConsole,
  type AnalyticHit,
} from '../lib/api';
import {
  CHIP_LIVE,
  CHIP_LOCAL,
  CHIP_NO_LEAD,
  CHIP_RECORDED_IN_SHADOW,
  CHIP_SHADOW,
  CHIP_SHIPPED,
  UNREAD_DOT,
} from '../lib/tooltips';
import { ShellProvider } from '../shell/ShellContext';
import { AnalyticHits } from './AnalyticHits';

const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const RECEIPTS = {
  matched_ids: ['a1', 'a2'],
  matched_fields: ['event.code'],
  dry_run: { window_days: 30, fires: 2, entities: ['10.1.99.5'] },
  overlap: [],
  baseline: null,
  complete: true,
  missing: [],
};

const LIVE: AnalyticHit = {
  id: 41,
  analytic_id: 'identity-dcsync',
  analytic_title: 'A non-machine account requests directory replication: DCSync',
  analytic_status: 'live',
  recorded_in_shadow: false,
  tier: 'shipped',
  entity_kind: 'user',
  entity_key: 'domainadmin',
  born_at: iso(6 * HOUR),
  first_seen_at: iso(6 * HOUR),
  occurrences: 3,
  summary: null,
  state: 'hit',
  missing: [],
  receipts: RECEIPTS,
  read: null,
  lead_id: 6,
  lead_status: 'open',
  document_count: 2,
};

const SHADOW: AnalyticHit = {
  id: 42,
  analytic_id: 'local-ntlm-failures',
  analytic_title: 'Remote NTLM logon failures target localuser account',
  analytic_status: 'shadow',
  recorded_in_shadow: true,
  tier: 'local',
  entity_kind: 'host',
  entity_key: '10.1.99.5',
  born_at: iso(33 * HOUR),
  first_seen_at: iso(33 * HOUR),
  occurrences: 4,
  summary: 'The 30 day dry run would have fired 8 times on 1 host.',
  state: 'hit',
  missing: [],
  receipts: RECEIPTS,
  read: false,
  lead_id: null,
  lead_status: null,
  document_count: 8,
};

const COUNTS = { all: 2, unread: 1, live: 1, shadow: 1 };

function LocationProbe() {
  const l = useLocation();
  return <div data-testid="loc">{l.pathname + l.search}</div>;
}

const mount = (path = '/hunts') =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <ShellProvider>
        <Routes>
          <Route path="/hunts" element={<AnalyticHits />} />
        </Routes>
        <LocationProbe />
      </ShellProvider>
    </MemoryRouter>,
  );

const card = async (id: number) => await screen.findByTestId(`analytic-hit-${id}`);

beforeEach(() => {
  vi.mocked(getAnalyticHits)
    .mockReset()
    .mockResolvedValue({ hits: [LIVE, SHADOW], counts: COUNTS });
  vi.mocked(markShadowHitRead).mockReset().mockResolvedValue({ ok: true });
  vi.mocked(setAnalyticStatus).mockReset().mockResolvedValue({} as never);
  vi.mocked(startHuntConsole).mockReset().mockResolvedValue({ hunt_id: 'H9' });
});

describe('the block', () => {
  it('names the window, counts the hits and states the order', async () => {
    mount();
    await card(41);
    expect(screen.getByText(/last 7 days · 2/)).toBeTruthy();
    expect(
      screen.getByText(
        'What the analytics found. Live hits come first. Then shadow hits, unread first.',
      ),
    ).toBeTruthy();
  });

  it('asks the server for the window and reads the hits in the order it answers', async () => {
    mount();
    await card(41);
    expect(getAnalyticHits).toHaveBeenCalledWith({ days: 7, filter: 'all', limit: 50 });
    const cards = screen.getAllByTestId(/^analytic-hit-\d+$/);
    expect(cards.map((c) => c.getAttribute('data-testid'))).toEqual([
      'analytic-hit-41',
      'analytic-hit-42',
    ]);
  });

  it('counts each filter on its chip and writes the chip to the address', async () => {
    mount();
    await card(41);
    const unread = screen.getByRole('button', { name: /^Unread/ });
    expect(unread.textContent).toContain('1');

    fireEvent.click(unread);
    await waitFor(() => expect(screen.getByTestId('loc').textContent).toBe('/hunts?hits=unread'));
    await waitFor(() =>
      expect(getAnalyticHits).toHaveBeenCalledWith({ days: 7, filter: 'unread', limit: 50 }),
    );

    fireEvent.click(screen.getByRole('button', { name: /^All/ }));
    await waitFor(() => expect(screen.getByTestId('loc').textContent).toBe('/hunts'));
  });

  it('opens on the filter the address names', async () => {
    mount('/hunts?hits=shadow');
    await card(41);
    expect(getAnalyticHits).toHaveBeenCalledWith({ days: 7, filter: 'shadow', limit: 50 });
  });

  it('reads a failed list as a failure and never as a quiet week', async () => {
    vi.mocked(getAnalyticHits).mockRejectedValue(new ApiError('down', 503));
    mount();
    expect(await screen.findByText('Could not read the analytic hits.')).toBeTruthy();
  });

  it('states the absence when no analytic hit anything', async () => {
    vi.mocked(getAnalyticHits).mockResolvedValue({
      hits: [],
      counts: { all: 0, unread: 0, live: 0, shadow: 0 },
    });
    mount();
    expect(await screen.findByText(/No analytic hit in the last 7 days/)).toBeTruthy();
  });

  // A failed first read reads as a failure. A poll failing after a good read
  // kept the cards and the counts with nothing to date them, so a dead API read
  // as a fresh list. `failCount >= 2` is the house threshold.
  describe('on a failing poll', () => {
    beforeEach(() => vi.useFakeTimers());
    afterEach(() => vi.useRealTimers());

    const settle = () => act(async () => { await vi.advanceTimersByTimeAsync(0); });
    const poll = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });

    it('dates the hits it is still showing', async () => {
      vi.mocked(getAnalyticHits)
        .mockResolvedValueOnce({ hits: [LIVE, SHADOW], counts: COUNTS })
        .mockRejectedValue(new ApiError('down', 503));
      mount();
      await settle();
      expect(screen.queryByText(/This data is from/)).toBeNull();

      await poll(130_000);
      expect(screen.getByText(/This data is from/)).toBeTruthy();
      expect(screen.getByTestId('analytic-hit-41')).toBeTruthy();
    });

    it('rides out one missed poll without a marker', async () => {
      vi.mocked(getAnalyticHits)
        .mockResolvedValueOnce({ hits: [LIVE, SHADOW], counts: COUNTS })
        .mockRejectedValueOnce(new ApiError('down', 503))
        .mockResolvedValue({ hits: [LIVE, SHADOW], counts: COUNTS });
      mount();
      await settle();
      await poll(70_000);
      expect(screen.queryByText(/This data is from/)).toBeNull();
    });
  });
});

describe('the card', () => {
  it('names the analytic and the hit on two labelled lines', async () => {
    mount();
    const live = await card(41);
    expect(within(live).getByText('Analytic:')).toBeTruthy();
    expect(within(live).getByRole('button', { name: LIVE.analytic_title })).toBeTruthy();
    expect(within(live).getByText('Hit:')).toBeTruthy();
    const entity = within(live).getByText('domainadmin');
    expect(entity.getAttribute('href')).toBe('/entity/domainadmin');
    expect(within(live).getByText('2 documents')).toBeTruthy();
    expect(within(live).getByText(/first seen 6h ago/)).toBeTruthy();
    expect(within(live).getByText(/seen 3 times/)).toBeTruthy();
  });

  it('carries the status chips and the tier chips with their sentences', async () => {
    mount();
    const live = await card(41);
    expect(within(live).getByText('live').getAttribute('title')).toBe(CHIP_LIVE);
    expect(within(live).getByText('shipped').getAttribute('title')).toBe(CHIP_SHIPPED);

    const shadow = await card(42);
    expect(within(shadow).getByText('shadow').getAttribute('title')).toBe(CHIP_SHADOW);
    expect(within(shadow).getByText('local').getAttribute('title')).toBe(CHIP_LOCAL);
  });

  it('gives the live hit the weight and leaves the shadow hit provisional', async () => {
    mount();
    const live = await card(41);
    const shadow = await card(42);
    expect(within(live).getByRole('button', { name: LIVE.analytic_title }).className).toContain(
      'font-bold',
    );
    expect(within(shadow).getByRole('button', { name: SHADOW.analytic_title }).className).not.toContain(
      'font-bold',
    );
    expect(live.getAttribute('data-hit-status')).toBe('live');
    expect(shadow.getAttribute('data-hit-status')).toBe('shadow');
  });

  it('marks an unread shadow hit and never a live hit', async () => {
    mount();
    const shadow = await card(42);
    expect(within(shadow).getByTitle(UNREAD_DOT)).toBeTruthy();
    const live = await card(41);
    expect(within(live).queryByTitle(UNREAD_DOT)).toBeNull();
  });

  it('links the lead that holds the hit and offers no second hunt', async () => {
    mount();
    const live = await card(41);
    expect(within(live).getByText('Lead 6').getAttribute('href')).toBe('/leads/6');
    expect(within(live).getByText('Open lead 6').getAttribute('href')).toBe('/leads/6');
    expect(within(live).queryByRole('button', { name: 'Hunt this entity' })).toBeNull();
    expect(within(live).getByText('The lead holds this hit. Decide there.')).toBeTruthy();
  });

  // The note said "Decide there" over a lead that had been promoted a day
  // earlier. The decision was made, and the card sent the analyst to make it
  // again. The note follows the lead's status.
  it('follows the lead status in the note beside the lead link', async () => {
    const note = async (lead_status: string) => {
      vi.mocked(getAnalyticHits).mockResolvedValue({
        hits: [{ ...LIVE, lead_status }],
        counts: COUNTS,
      });
      const view = mount();
      const live = await card(41);
      const text = within(live).getByText(/lead/i, { selector: 'span' }).textContent;
      view.unmount();
      return text;
    };
    expect(await note('open')).toBe('The lead holds this hit. Decide there.');
    expect(await note('hunting')).toBe('The lead holds this hit. Decide there.');
    expect(await note('dismissed')).toBe('The lead that held this hit was dismissed.');
    expect(await note('promoted')).toBe('The lead that held this hit was promoted.');
  });

  it('offers the hunt on a hit that formed no lead, and says so', async () => {
    mount();
    const shadow = await card(42);
    expect(within(shadow).getByText('no lead').getAttribute('title')).toBe(CHIP_NO_LEAD);
    fireEvent.click(within(shadow).getByRole('button', { name: 'Hunt this entity' }));
    await waitFor(() => expect(startHuntConsole).toHaveBeenCalledTimes(1));
    expect(vi.mocked(startHuntConsole).mock.calls[0][0]).toContain('10.1.99.5');
  });

  it('states a summary that adds a fact', async () => {
    mount();
    const shadow = await card(42);
    expect(within(shadow).getByText(SHADOW.summary!)).toBeTruthy();
  });

  it('drops a summary that only repeats the analytic title', async () => {
    vi.mocked(getAnalyticHits).mockResolvedValue({
      hits: [
        { ...SHADOW, summary: SHADOW.analytic_title, receipts: { ...RECEIPTS, dry_run: null } },
      ],
      counts: COUNTS,
    });
    mount();
    const shadow = await card(42);
    expect(within(shadow).queryByTestId('analytic-hit-summary')).toBeNull();
  });

  // The dry run is the one fact the two lines do not carry, and it sat behind
  // Show evidence. A card whose stored summary says nothing new now states it.
  it('states the dry run when the stored summary adds nothing', async () => {
    vi.mocked(getAnalyticHits).mockResolvedValue({
      hits: [{ ...SHADOW, summary: `${SHADOW.entity_key} (3 documents)` }],
      counts: COUNTS,
    });
    mount();
    const shadow = await card(42);
    expect(within(shadow).getByTestId('analytic-hit-summary').textContent).toBe(
      'The 30 day dry run would have fired 2 times on 1 host. No live analytic read these documents.',
    );
  });

  it('keeps the stored summary when it carries a fact of its own', async () => {
    mount();
    const shadow = await card(42);
    expect(within(shadow).getByTestId('analytic-hit-summary').textContent).toBe(SHADOW.summary);
  });

  it('claims nothing about an overlap it cannot see on a live hit', async () => {
    mount();
    const live = await card(41);
    expect(within(live).getByTestId('analytic-hit-summary').textContent).toBe(
      'The 30 day dry run would have fired 2 times on 1 user.',
    );
  });

  it('hides a summary that only repeats the entity and the document count', async () => {
    vi.mocked(getAnalyticHits).mockResolvedValue({
      hits: [
        {
          ...SHADOW,
          summary: `${SHADOW.analytic_title}: ${SHADOW.entity_key} (3 documents)`,
          receipts: { ...RECEIPTS, dry_run: null },
        },
      ],
      counts: COUNTS,
    });
    mount();
    const shadow = await card(42);
    expect(within(shadow).queryByTestId('analytic-hit-summary')).toBeNull();
  });

  it('lists a hit whose evidence is incomplete and calls it could not run', async () => {
    vi.mocked(getAnalyticHits).mockResolvedValue({
      hits: [
        {
          ...SHADOW,
          state: 'could_not_run',
          missing: ['dry_run'],
          receipts: { ...RECEIPTS, dry_run: null, complete: false, missing: ['dry_run'] },
        },
      ],
      counts: COUNTS,
    });
    mount();
    const shadow = await card(42);
    expect(within(shadow).getByText('could not run')).toBeTruthy();
    expect(within(shadow).getByText(/This is not an all-clear/)).toBeTruthy();
    expect(within(shadow).queryByRole('button', { name: 'Approve analytic' })).toBeNull();
  });
});

describe('reading a shadow hit', () => {
  it('reads the hit when the evidence opens, and keeps the card in place', async () => {
    mount();
    const shadow = await card(42);
    fireEvent.click(within(shadow).getByRole('button', { name: 'Show evidence' }));
    await waitFor(() => expect(markShadowHitRead).toHaveBeenCalledWith(42));
    expect(within(shadow).queryByTitle(UNREAD_DOT)).toBeNull();
    // One load. The list does not reorder under the hand that is working it.
    expect(getAnalyticHits).toHaveBeenCalledTimes(1);
    expect(await screen.findByTestId('analytic-hit-42')).toBeTruthy();
  });

  it('offers Mark read on an unread hit and takes it away once it is read', async () => {
    mount();
    const shadow = await card(42);
    fireEvent.click(within(shadow).getByRole('button', { name: 'Mark read' }));
    await waitFor(() => expect(markShadowHitRead).toHaveBeenCalledWith(42));
    await waitFor(() =>
      expect(within(shadow).queryByRole('button', { name: 'Mark read' })).toBeNull(),
    );
  });

  it('states a failed read rather than showing the hit as read', async () => {
    vi.mocked(markShadowHitRead).mockRejectedValue(new ApiError('down', 503));
    mount();
    const shadow = await card(42);
    fireEvent.click(within(shadow).getByRole('button', { name: 'Mark read' }));
    expect(await within(shadow).findByText('The hit was not marked read. Try again.')).toBeTruthy();
    expect(within(shadow).getByTitle(UNREAD_DOT)).toBeTruthy();
  });

  // The counts came from the same fetch as the rows, and the read does not
  // refetch by design, so the chips held "Unread 1" over a list with no unread
  // dot until the next poll. The rows hold still; the numbers do not have to.
  it('takes the hit off the unread count without reordering the list', async () => {
    mount();
    const shadow = await card(42);
    expect(screen.getByRole('button', { name: /^Unread/ }).textContent).toContain('1');

    fireEvent.click(within(shadow).getByRole('button', { name: 'Mark read' }));
    await waitFor(() => expect(markShadowHitRead).toHaveBeenCalledWith(42));
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /^Unread/ }).textContent).toContain('0'),
    );
    // The other three chips are untouched: the hit is still a hit.
    expect(screen.getByRole('button', { name: /^All/ }).textContent).toContain('2');
    expect(screen.getByRole('button', { name: /^Shadow/ }).textContent).toContain('1');
    expect(getAnalyticHits).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId('analytic-hit-42')).toBeTruthy();
  });

  it('names the time a read hit was read', async () => {
    vi.mocked(getAnalyticHits).mockResolvedValue({
      hits: [{ ...SHADOW, read: true, read_at: iso(2 * HOUR) }],
      counts: COUNTS,
    });
    mount();
    const shadow = await card(42);
    expect(within(shadow).getByText('read 2h ago')).toBeTruthy();
    expect(within(shadow).getByText('read 2h ago').getAttribute('title')).toContain(
      "An analyst opened this hit's evidence or acted on it 2h ago.",
    );
  });
});

describe('deciding on a shadow analytic', () => {
  it('asks for the reason and posts the approval, and reads the hit', async () => {
    mount();
    const shadow = await card(42);
    fireEvent.click(within(shadow).getByRole('button', { name: 'Approve analytic' }));
    fireEvent.change(within(shadow).getByPlaceholderText('Why it goes live'), {
      target: { value: 'it proved itself' },
    });
    fireEvent.click(within(shadow).getByRole('button', { name: 'Confirm' }));
    await waitFor(() =>
      expect(setAnalyticStatus).toHaveBeenCalledWith(
        'local-ntlm-failures',
        'live',
        'it proved itself',
      ),
    );
    await waitFor(() => expect(markShadowHitRead).toHaveBeenCalledWith(42));
  });

  it('retires the analytic with a reason when it is rejected', async () => {
    mount();
    const shadow = await card(42);
    fireEvent.click(within(shadow).getByRole('button', { name: 'Reject analytic' }));
    fireEvent.change(within(shadow).getByPlaceholderText('Why it is rejected'), {
      target: { value: 'it fires on backups' },
    });
    fireEvent.click(within(shadow).getByRole('button', { name: 'Confirm' }));
    await waitFor(() =>
      expect(setAnalyticStatus).toHaveBeenCalledWith(
        'local-ntlm-failures',
        'retired',
        'it fires on backups',
      ),
    );
  });

  it('offers no analytic decision on a live hit', async () => {
    mount();
    const live = await card(41);
    expect(within(live).queryByRole('button', { name: 'Approve analytic' })).toBeNull();
    expect(within(live).queryByRole('button', { name: 'Reject analytic' })).toBeNull();
    expect(within(live).queryByRole('button', { name: 'Mark read' })).toBeNull();
  });
});

// The row flag holds the status of the last sighting. It stays until the
// analytic fires again, so the card wore the shadow chip and offered "Approve
// analytic" on an analytic the analyst had approved the day before. The chip
// and the two decisions read the analytic. The half, the border and the weight
// read the flag.
describe('a hit recorded in shadow whose analytic is live now', () => {
  const APPROVED: AnalyticHit = { ...SHADOW, analytic_status: 'live', recorded_in_shadow: true };

  const mountApproved = async () => {
    vi.mocked(getAnalyticHits).mockResolvedValue({ hits: [APPROVED], counts: COUNTS });
    mount();
    return await card(42);
  };

  it('wears the live chip and states where it was recorded', async () => {
    const hit = await mountApproved();
    expect(within(hit).getByText('live').getAttribute('title')).toBe(CHIP_LIVE);
    expect(within(hit).queryByText('shadow')).toBeNull();
    expect(within(hit).getByText('recorded in shadow').getAttribute('title')).toBe(
      CHIP_RECORDED_IN_SHADOW,
    );
  });

  it('offers neither decision on an analytic that is already live', async () => {
    const hit = await mountApproved();
    expect(within(hit).queryByRole('button', { name: 'Approve analytic' })).toBeNull();
    expect(within(hit).queryByRole('button', { name: 'Reject analytic' })).toBeNull();
  });

  it('stays on the shadow half it lists under, and stays readable', async () => {
    const hit = await mountApproved();
    expect(hit.getAttribute('data-hit-status')).toBe('shadow');
    expect(within(hit).getByRole('button', { name: SHADOW.analytic_title }).className).not.toContain(
      'font-bold',
    );
    expect(within(hit).getByTitle(UNREAD_DOT)).toBeTruthy();
    fireEvent.click(within(hit).getByRole('button', { name: 'Mark read' }));
    await waitFor(() => expect(markShadowHitRead).toHaveBeenCalledWith(42));
  });

  it('takes a read hit off the unread count like any hit of the shadow half', async () => {
    vi.mocked(getAnalyticHits).mockResolvedValue({ hits: [APPROVED], counts: COUNTS });
    mount();
    const hit = await card(42);
    expect(screen.getByRole('button', { name: /^Unread/ }).textContent).toContain('1');
    fireEvent.click(within(hit).getByRole('button', { name: 'Mark read' }));
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /^Unread/ }).textContent).toContain('0'),
    );
  });

  it('leaves the chip off a hit of an analytic that is still in shadow', async () => {
    mount();
    const shadow = await card(42);
    expect(within(shadow).getByText('shadow').getAttribute('title')).toBe(CHIP_SHADOW);
    expect(within(shadow).queryByText('recorded in shadow')).toBeNull();
    expect(within(shadow).getByRole('button', { name: 'Approve analytic' })).toBeTruthy();
    expect(within(shadow).getByRole('button', { name: 'Reject analytic' })).toBeTruthy();
  });

  it('leaves the chip off a hit that was born live', async () => {
    mount();
    const live = await card(41);
    expect(within(live).getByText('live').getAttribute('title')).toBe(CHIP_LIVE);
    expect(within(live).queryByText('recorded in shadow')).toBeNull();
    expect(live.getAttribute('data-hit-status')).toBe('live');
  });
});

// The page holds the fold, because a Needs-you link opens this block before it
// scrolls there. The block draws the chevron only when the page offers it.
describe('the fold', () => {
  const mountFolded = (collapsed: boolean) =>
    render(
      <MemoryRouter initialEntries={['/hunts']}>
        <ShellProvider>
          <AnalyticHits collapsed={collapsed} onToggleCollapsed={() => {}} />
        </ShellProvider>
      </MemoryRouter>,
    );

  it('keeps the title, the count and the unread figure while it is folded', async () => {
    mountFolded(true);
    expect(await screen.findByText(/last 7 days · 2 · 1 unread/)).toBeTruthy();
    expect(screen.getByTestId('define-hit')).toBeTruthy();
    expect(screen.queryByTestId('analytic-hit-41')).toBeNull();
    expect(screen.queryByRole('button', { name: /^Unread/ })).toBeNull();
  });

  it('draws the cards again when it is open', async () => {
    mountFolded(false);
    expect(await screen.findByTestId('analytic-hit-41')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Collapse Analytic hits' })).toBeTruthy();
  });

  it('carries no chevron where the page offers no fold', async () => {
    mount();
    await card(41);
    expect(screen.queryByRole('button', { name: /^Collapse /})).toBeNull();
  });
});
