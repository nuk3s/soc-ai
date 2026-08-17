// The Investigations screen as a QUERY, not a page. The list used to fetch the
// newest 100 rows and filter them client-side, so on a deployment whose newest
// 100 runs were one saturated outcome, every older errored run was unreachable
// under ANY filter (Status=error searched the same 100 rows and found nothing).
// These tests pin the cure: filters travel to the server, the header figures
// come from server-side counts over the same filter set (never from the page),
// and paging is real. The pipeline_error deep-link contract (dogfood
// 2026-07-15) is preserved: a matching non-primary row is a visible row.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { InvestigationList, InvestigationRow } from '../lib/types';

const row = (over: Partial<InvestigationRow>): InvestigationRow => ({
  id: 'INV-X',
  name: 'GPL ICMP Large ICMP Packet',
  kind: 'suricata',
  verdict: 'false_positive',
  conf: 0.95,
  host: '192.0.2.10',
  dst: '198.51.100.7',
  status: 'complete',
  when: '9h ago',
  ts: '2026-07-15T01:00:00+00:00',
  alertId: 'ev-icmp',
  isPrimary: true,
  fallback: false,
  ...over,
});

const list = (rows: InvestigationRow[], over: Partial<InvestigationList> = {}): InvestigationList => ({
  rows,
  total: rows.length,
  running: 0,
  truePositives: 0,
  totalAll: rows.length,
  active: false,
  limit: 50,
  offset: 0,
  ...over,
});

const listInvestigations = vi.hoisted(() => vi.fn());
const listSavedViews = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  listInvestigations,
  listSavedViews,
}));

import { Investigations } from './Investigations';

const mount = (url: string) =>
  render(
    <MemoryRouter initialEntries={[url]}>
      <Investigations />
    </MemoryRouter>,
  );

beforeEach(() => {
  listInvestigations.mockReset();
  listInvestigations.mockResolvedValue(list([]));
  listSavedViews.mockReset();
  listSavedViews.mockResolvedValue([]);
});

describe('Investigations server-side query', () => {
  it('sends the default 24h window to the server as `since`', async () => {
    mount('/investigations');
    await screen.findByText('No investigations yet');
    const q = listInvestigations.mock.calls[0][0];
    const age = Date.now() - new Date(q.since).getTime();
    expect(age).toBeGreaterThan(23.9 * 3600_000);
    expect(age).toBeLessThan(24.1 * 3600_000);
    expect(q.limit).toBe(50);
    expect(q.offset).toBe(0);
  });

  it('sends a Status filter change to the server and resets the page', async () => {
    mount('/investigations');
    fireEvent.click(await screen.findByRole('button', { name: 'Status' }));
    fireEvent.click(screen.getByLabelText('Error'));
    await waitFor(() => {
      const q = listInvestigations.mock.calls[listInvestigations.mock.calls.length - 1][0];
      expect(q.status).toEqual(['error']);
      expect(q.offset).toBe(0);
    });
  });

  it('renders the header figures from the server counts, not the page', async () => {
    // Two rows on the page; 500/3/7 in the filter set. Counting the page here
    // is exactly the phantom-untriaged bug this screen shipped twice.
    listInvestigations.mockResolvedValue(
      list([row({ id: 'a', alertId: 'ev-a' }), row({ id: 'b', alertId: 'ev-b' })], {
        total: 500,
        running: 3,
        truePositives: 7,
        totalAll: 900,
      }),
    );
    const { container } = mount('/investigations');
    await screen.findAllByText('GPL ICMP Large ICMP Packet');
    expect(container.textContent).toContain('500 investigations · 3 in progress · 7 true positives');
  });

  it('counts to one without saying "1 investigations"', async () => {
    // Reachable any time a filter or the search box narrows to a single run,
    // which the new search box makes ordinary. A header that cannot count to
    // one undermines every other number beside it.
    listInvestigations.mockResolvedValue(
      list([row({ id: 'a', alertId: 'ev-a' })], { total: 1, running: 1, truePositives: 1 }),
    );
    const { container } = mount('/investigations');
    await screen.findAllByText('GPL ICMP Large ICMP Packet');
    expect(container.textContent).toContain('1 investigation · 1 in progress · 1 true positive');
    expect(container.textContent).not.toContain('1 investigations');
  });

  it('pages with Previous/Next over the server total', async () => {
    const rows = Array.from({ length: 50 }, (_, i) => row({ id: `r${i}`, alertId: `ev-${i}` }));
    listInvestigations.mockResolvedValue(list(rows, { total: 120, totalAll: 120 }));
    const { container } = mount('/investigations');
    await screen.findAllByText('GPL ICMP Large ICMP Packet');
    expect(container.textContent).toContain('1–50 of 120');

    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await waitFor(() => {
      const q = listInvestigations.mock.calls[listInvestigations.mock.calls.length - 1][0];
      expect(q.offset).toBe(50);
    });
  });
});

describe('Investigations pipeline_error deep link', () => {
  it('queries the server for pipeline_error over a widened 30d window', async () => {
    mount('/investigations?verdict=pipeline_error');
    await screen.findByText(/No investigations/);
    const q = listInvestigations.mock.calls[0][0];
    expect(q.verdict).toEqual(['pipeline_error']);
    const age = Date.now() - new Date(q.since).getTime();
    expect(age).toBeGreaterThan(29 * 86_400_000); // the KPI counts with no time
    expect(age).toBeLessThan(31 * 86_400_000); // filter; 24h could hide its rows
  });

  it('surfaces a superseded (non-primary) fallback run as a visible row', async () => {
    // The filtered page holds ONLY the fallback retry — its primary sibling did
    // not match the filter. A retry without its primary on the page must be a
    // top-level row: tucking it under an absent parent rendered a blank table
    // (dogfood 2026-07-15).
    listInvestigations.mockResolvedValue(
      list([
        row({
          id: 'INV-SUPERSEDED-FB',
          verdict: 'needs_more_info',
          conf: 0.3,
          isPrimary: false,
          fallback: true,
        }),
      ]),
    );
    mount('/investigations?verdict=pipeline_error');
    expect(await screen.findByText('Pipeline error')).toBeTruthy();
    expect(screen.getAllByText('GPL ICMP Large ICMP Packet')).toHaveLength(1);
  });

  it('says so when the active filter matches nothing', async () => {
    listInvestigations.mockResolvedValue(list([], { total: 0, totalAll: 42 }));
    mount('/investigations?verdict=inconclusive');
    expect(await screen.findByText(/No investigations match the selected filters/i)).toBeTruthy();
  });

  it('distinguishes an empty store from an empty match', async () => {
    // An empty STORE gets the explainer and a way forward — the bare "No
    // investigations yet." told a new operator nothing about how a first
    // investigation comes to exist (dogfood B1). An empty MATCH keeps the
    // one-liner: the operator got here by setting a filter and knows it.
    listInvestigations.mockResolvedValue(list([], { total: 0, totalAll: 0 }));
    mount('/investigations');
    expect(await screen.findByText('No investigations yet')).toBeTruthy();
    expect(screen.getByRole('link', { name: /start from alerts/i })).toBeTruthy();
    expect(screen.queryByText(/No investigations match/i)).toBeNull();
  });
});

// The most recent call's query object — vitest keeps them in order.
const lastQuery = () =>
  listInvestigations.mock.calls[listInvestigations.mock.calls.length - 1][0];

describe('Investigations search', () => {
  // A3: the screen had Verdict/Status/Group-by and no free text, while Alerts
  // had a search box. The box is wired to the SERVER query — a client-side
  // filter over the fetched page is the exact defect the server-side query
  // replaced.
  it('sends the typed term to the server, debounced', async () => {
    mount('/investigations');
    await screen.findByText('No investigations yet');
    const box = screen.getByLabelText('Search investigations');
    fireEvent.change(box, { target: { value: 'cobalt' } });
    await waitFor(() =>
      expect(lastQuery().q).toBe('cobalt'),
    );
    // …and it resets paging, because page 3 of the old query means nothing
    // under the new one.
    expect(lastQuery().offset).toBe(0);
  });

  it('renders the rows the SERVER returned for the term, not a filtered page', async () => {
    listInvestigations.mockResolvedValue(
      list([row({ id: 'INV-CS', name: 'ET MALWARE Cobalt Strike Beacon' })], { totalAll: 12 }),
    );
    mount('/investigations');
    fireEvent.change(screen.getByLabelText('Search investigations'), {
      target: { value: 'cobalt' },
    });
    expect(await screen.findByText('ET MALWARE Cobalt Strike Beacon')).toBeTruthy();
    await waitFor(() =>
      expect(lastQuery().q).toBe('cobalt'),
    );
  });

  it('leaves `q` off the request when the box is empty', async () => {
    mount('/investigations');
    await screen.findByText('No investigations yet');
    expect(listInvestigations.mock.calls[0][0].q).toBeUndefined();
  });
});

describe('Investigations selection does not cost the filters', () => {
  // The shared toolbar briefly swapped the facet row out for the selection
  // strip. On this screen that meant ticking one row lost search, the time
  // range, Verdict, Status and Group-by — and blanked a typed search term that
  // was still narrowing the list server-side.
  it('keeps the search box, its term, and the facets while rows are selected', async () => {
    listInvestigations.mockResolvedValue(list([row({ id: 'INV-1' })], { totalAll: 3 }));
    mount('/investigations');
    await screen.findByText('GPL ICMP Large ICMP Packet');
    fireEvent.change(screen.getByLabelText('Search investigations'), { target: { value: 'icmp' } });
    await waitFor(() => expect(lastQuery().q).toBe('icmp'));

    fireEvent.click(screen.getAllByRole('checkbox')[1]);
    expect(await screen.findByText(/selected/i)).toBeTruthy();

    // Everything that produced this list is still on screen and still usable.
    expect(screen.getByLabelText('Search investigations')).toHaveValue('icmp');
    expect(screen.getByText('Group by detection')).toBeTruthy();
    // The multi-select triggers (the column headers also say "Verdict"/"Status").
    expect(screen.getByRole('button', { name: /^Verdict$/ })).toBeTruthy();
    expect(screen.getByRole('button', { name: /^Status$/ })).toBeTruthy();
  });

  it('says how many selected rows the current page cannot show', async () => {
    // Selection is id-keyed and outlives a filter change on purpose. Silently,
    // that is a trap: the strip says N, the rows are gone, and a bulk action
    // submits ids nothing on screen renders.
    listInvestigations.mockResolvedValue(
      list([row({ id: 'INV-A', name: 'Alpha' }), row({ id: 'INV-B', name: 'Bravo' })], {
        totalAll: 9,
      }),
    );
    mount('/investigations');
    await screen.findByText('Alpha');
    fireEvent.click(screen.getAllByRole('checkbox')[0]); // header: select the page
    expect(await screen.findByText(/2 selected|selected/i)).toBeTruthy();

    // A filter change swaps the page out from under the selection.
    listInvestigations.mockResolvedValue(list([row({ id: 'INV-C', name: 'Charlie' })], { totalAll: 9 }));
    fireEvent.change(screen.getByLabelText('Search investigations'), { target: { value: 'charlie' } });
    await screen.findByText('Charlie');
    expect(await screen.findByText(/2 not on this page/i)).toBeTruthy();
  });

  it('drops just the off-page rows without discarding the whole selection', async () => {
    listInvestigations.mockResolvedValue(
      list([row({ id: 'INV-A', name: 'Alpha' }), row({ id: 'INV-B', name: 'Bravo' })], { totalAll: 9 }),
    );
    mount('/investigations');
    await screen.findByText('Alpha');
    fireEvent.click(screen.getAllByRole('checkbox')[0]);
    listInvestigations.mockResolvedValue(list([row({ id: 'INV-A', name: 'Alpha' })], { totalAll: 9 }));
    fireEvent.change(screen.getByLabelText('Search investigations'), { target: { value: 'alpha' } });
    await waitFor(() => expect(screen.queryByText('Bravo')).toBeNull());

    fireEvent.click(await screen.findByText(/1 not on this page/i));
    await waitFor(() => expect(screen.queryByText(/not on this page/i)).toBeNull());
    // The visible pick survives; only the invisible one went.
    expect(screen.getByText(/selected/i)).toBeTruthy();
  });
});

describe('Investigations retry tucking', () => {
  it('still tucks a retry under its primary when BOTH are on the page', async () => {
    listInvestigations.mockResolvedValue(
      list([
        row({ id: 'INV-PRIMARY' }),
        row({ id: 'INV-RETRY', status: 'error', verdict: 'untriaged', isPrimary: false }),
      ]),
    );
    mount('/investigations');
    await screen.findAllByText('GPL ICMP Large ICMP Packet');
    // One top-level row plus a "1 earlier" reveal — the retry is not top-level.
    expect(screen.getAllByText('GPL ICMP Large ICMP Packet')).toHaveLength(1);
    const reveal = screen.getByRole('button', { name: /1 earlier/ });
    fireEvent.click(reveal);
    expect(screen.getByText('earlier run')).toBeTruthy();
  });
});

// "Untriaged" named a state this list cannot hold: a group nobody investigated
// has no row here, and the table renders an untriaged verdict as a bare
// em-dash rather than a pill — so the option could only ever return nothing.
// That work lives on /alerts now; a run that ENDED without a verdict is reached
// through the Status filter's Error/Interrupted options instead.
describe('Investigations verdict filter options', () => {
  it('no longer offers Untriaged, and keeps the Status escape hatch', async () => {
    mount('/investigations');
    // byRole, not byText: 'Verdict'/'Status' are also column headers.
    fireEvent.click(await screen.findByRole('button', { name: 'Verdict' }));
    expect(screen.queryByLabelText('Untriaged')).toBeNull();
    expect(screen.getByLabelText('Pipeline error')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Status' }));
    expect(screen.getByLabelText('Error')).toBeTruthy();
    expect(screen.getByLabelText('Interrupted')).toBeTruthy();
  });
});

// The chip rendered aria-pressed — a promise that the second press undoes the
// first — and went false→true once, then stayed true. This screen ships no
// "All" preset to get back to, so the only route to the unfiltered list was
// clearing the search box and every facet by hand.
describe('Investigations saved-view chip is a toggle', () => {
  const VIEW = {
    id: 7,
    screen: 'investigations' as const,
    name: 'Errored beacons',
    query: { q: 'beacon', status: ['error'], range: '7d' },
    created_at: null,
  };

  it('applies on the first click and CLEARS the filters on the second', async () => {
    listSavedViews.mockResolvedValue([VIEW]);
    mount('/investigations');
    await screen.findByText('No investigations yet');

    const chip = await screen.findByTitle('Apply the saved view "Errored beacons"');
    fireEvent.click(chip);
    await waitFor(() => expect(lastQuery().q).toBe('beacon'));
    expect(lastQuery().status).toEqual(['error']);
    expect(chip).toHaveAttribute('aria-pressed', 'true');
    // The title now names what the NEXT press does.
    expect(chip).toHaveAttribute(
      'title',
      'Clear the saved view "Errored beacons" and show everything',
    );

    fireEvent.click(chip);
    await waitFor(() => expect(lastQuery().q).toBeUndefined());
    expect(lastQuery().status).toEqual([]);
    expect(screen.getByLabelText('Search investigations')).toHaveValue('');
    expect(chip).toHaveAttribute('aria-pressed', 'false');

    // …and the window the view widened is back at this screen's own default.
    const age = Date.now() - new Date(lastQuery().since as string).getTime();
    expect(age).toBeLessThan(24.1 * 3600_000);
  });
});
