// Dogfood (scheduled-hunts-discoverability): a schedule created in the Hunt
// Console shows a green "on" pill even when the `hunt_schedules_enabled`
// global master switch (Config → Triage automation) is off — it reads as
// active but will never fire. GET /hunt-schedules now returns
// `masterSwitchEnabled` alongside the rows so the panel can render an honest
// state: a persistent banner with a real deep-link into Config, and a muted
// "on (paused)" pill instead of the plain accent "on".
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DemoProvider } from '../lib/demo';

const SCHEDULE = vi.hoisted(() => ({
  id: 1,
  objective: 'Nightly beacon sweep',
  intervalMinutes: 1440,
  enabled: true,
  lastRunAt: null,
  createdBy: 'alice',
  createdAt: '2026-07-01T00:00:00+00:00',
}));

const getHuntSchedulesMock = vi.hoisted(() => vi.fn());
const createHuntScheduleMock = vi.hoisted(() => vi.fn());
const updateHuntScheduleMock = vi.hoisted(() => vi.fn());
const deleteHuntScheduleMock = vi.hoisted(() => vi.fn());
const listSavedViewsMock = vi.hoisted(() => vi.fn().mockResolvedValue([]));

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunts: vi.fn().mockResolvedValue([]),
  getHuntStats: vi.fn().mockResolvedValue([]),
  getHuntTemplates: vi.fn().mockResolvedValue([]),
  getHuntSchedules: getHuntSchedulesMock,
  createHuntSchedule: createHuntScheduleMock,
  updateHuntSchedule: updateHuntScheduleMock,
  deleteHuntSchedule: deleteHuntScheduleMock,
  listSavedViews: listSavedViewsMock,
  // Merge 4 put two tabs and the shadow-hits band on this screen. Both read
  // the API, and the shared setup rejects every unmocked fetch, so they are
  // mocked here to their quiet state: no shadow hits, no analytics.
  getShadowHits: vi.fn().mockResolvedValue({ hits: [], unread: 0 }),
  getAnalytics: vi.fn().mockResolvedValue({ analytics: [], counts: {} }),
  getAnalytic: vi.fn(),
  // The spine of the Hunts tab reads three surfaces before the list. Each one
  // is mocked to its quiet state, so a test about the list is not a test about
  // them.
  getAnalyticHits: vi.fn().mockResolvedValue({
    hits: [],
    counts: { all: 0, unread: 0, live: 0, shadow: 0 },
  }),
  getNeedsYou: vi
    .fn()
    .mockResolvedValue({ unread_shadow_hits: 0, leads_needing_decision: 0, total: 0 }),
  getLeads: vi.fn().mockResolvedValue([]),
  getHuntCatalog: vi.fn().mockResolvedValue({
    specs: [],
    sweeps_enabled: true,
    sweep_interval_minutes: 60,
    sweep_window_minutes: 61,
    last_sweep_at: null,
  }),
}));

import { getAnalytic, getAnalytics, getHunts, getHuntStats, getLeads } from '../lib/api';
import { ShellProvider } from '../shell/ShellContext';
import { CHIP_CATALOG_RUN, TYPE_LEAD } from '../lib/tooltips';
import type { HuntsQuery } from '../lib/api';
import type { HuntRow } from '../lib/types';
import { Hunts } from './Hunts';

/** The address bar, so a test can read what a chip wrote there. */
function LocationProbe() {
  const l = useLocation();
  return <div data-testid="loc">{l.pathname + l.search}</div>;
}

function renderHunts(demo = false, path = '/hunts') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <DemoProvider demo={demo}>
        <ShellProvider>
          <Routes>
            <Route path="/hunts" element={<Hunts />} />
            <Route path="/config" element={<div>CONFIG SCREEN</div>} />
          </Routes>
          <LocationProbe />
        </ShellProvider>
      </DemoProvider>
    </MemoryRouter>,
  );
}

describe('ScheduledHunts master-switch discoverability', () => {
  it('shows a paused-globally banner and a muted pill when the master switch is off', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [SCHEDULE], masterSwitchEnabled: false });
    renderHunts();

    await screen.findByText('Nightly beacon sweep');
    expect(screen.getByText(/paused globally/i)).toBeTruthy();

    const row = screen.getByText('Nightly beacon sweep').closest('div')!.parentElement!.parentElement!;
    expect(within(row).getByText('on (paused)')).toBeTruthy();
    expect(within(row).queryByText(/^on$/)).toBeNull();
  });

  it('hides the banner and shows a plain "on" pill when the master switch is on', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [SCHEDULE], masterSwitchEnabled: true });
    renderHunts();

    await screen.findByText('Nightly beacon sweep');
    expect(screen.queryByText(/paused globally/i)).toBeNull();

    const row = screen.getByText('Nightly beacon sweep').closest('div')!.parentElement!.parentElement!;
    expect(within(row).getByText('on')).toBeTruthy();
    expect(within(row).queryByText('on (paused)')).toBeNull();
  });
});

// The "paused globally" banner CTA deep-links to a Config toggle that is itself
// demo-guarded (a dead-end in the read-only demo), so the banner is suppressed
// in demo mode ONLY. The "on (paused)" pills still render (that IS the 1.2.4
// feature); only the banner is hidden. Live (non-demo) behavior is unchanged.
describe('ScheduledHunts banner demo-suppression', () => {
  it('does NOT render the paused-globally banner in demo mode', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [SCHEDULE], masterSwitchEnabled: false });
    renderHunts(true);

    await screen.findByText('Nightly beacon sweep');
    expect(screen.queryByText(/paused globally/i)).toBeNull();
    // The "on (paused)" pill still renders — the banner is the only thing hidden.
    const row = screen.getByText('Nightly beacon sweep').closest('div')!.parentElement!
      .parentElement!;
    expect(within(row).getByText('on (paused)')).toBeTruthy();
  });

  it('DOES render the paused-globally banner outside demo mode', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [SCHEDULE], masterSwitchEnabled: false });
    renderHunts(false);

    await screen.findByText('Nightly beacon sweep');
    expect(screen.getByText(/paused globally/i)).toBeTruthy();
  });
});

// Two new 1.2.x write buttons (create/edit, toggle, delete) never fired a
// doomed write in demo mode — Hunts.tsx had zero useDemo/demoBlocked wiring
// until this fix. Each assertion below drives the real ScheduledHunts panel
// (not a miniature) through DemoProvider so it exercises the actual handler.
describe('ScheduledHunts demo guard', () => {
  it('shows the demo note and does not POST when creating a schedule', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
    renderHunts(true);

    await screen.findByText('No scheduled hunts. Add one below.');
    fireEvent.change(screen.getByPlaceholderText('New recurring hunt objective…'), {
      target: { value: 'find beacons' },
    });
    fireEvent.click(screen.getByText('Add'));

    await screen.findByText(/Not available in the read-only demo/);
    expect(createHuntScheduleMock).not.toHaveBeenCalled();
  });

  it('shows the demo note and does not PATCH when toggling a schedule', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [SCHEDULE], masterSwitchEnabled: true });
    renderHunts(true);

    const row = (await screen.findByText('Nightly beacon sweep')).closest('div')!.parentElement!
      .parentElement!;
    fireEvent.click(within(row).getByText('on'));

    await screen.findByText(/Not available in the read-only demo/);
    expect(updateHuntScheduleMock).not.toHaveBeenCalled();
  });

  it('shows the demo note and does not DELETE when removing a schedule', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [SCHEDULE], masterSwitchEnabled: true });
    renderHunts(true);

    const row = (await screen.findByText('Nightly beacon sweep')).closest('div')!.parentElement!
      .parentElement!;
    fireEvent.click(within(row).getByTitle('Delete schedule'));
    fireEvent.click(within(row).getByTitle('Confirm delete'));

    await screen.findByText(/Not available in the read-only demo/);
    expect(deleteHuntScheduleMock).not.toHaveBeenCalled();
  });
});


describe('Hunts selection does not cost the only filter', () => {
  // Hunts has exactly one facet — the time range. The shared toolbar's first
  // cut swapped the facet row out for the selection strip, so ticking a hunt
  // deleted the screen's entire filtering ability until the selection was
  // discarded.
  it('keeps the time-range filter on screen while hunts are selected', async () => {
    vi.mocked(getHunts).mockResolvedValue([
      {
        id: 'H1',
        objective: 'Look for hosts beaconing to rare external IPs',
        status: 'complete',
        findings: 2,
        hosts: 1,
        started: '20m',
        startedTs: '2026-08-12T10:00:00+00:00',
      } as unknown as HuntRow,
    ]);
    renderHunts();
    await screen.findByText('Look for hosts beaconing to rare external IPs');
    const boxes = screen.getAllByRole('checkbox');
    fireEvent.click(boxes[boxes.length - 1]);
    const strip = await screen.findByTestId('list-toolbar-selection');
    expect(within(strip).getByText(/Re-hunt selected \(1\)/)).toBeTruthy();
    // The presets are still there and still clickable — and NOT inside the strip.
    expect(screen.getByText('24h')).toBeTruthy();
    expect(screen.getByText('7d')).toBeTruthy();
    expect(within(strip).queryByText('24h')).toBeNull();
  });
});

// The header line used to read straight off GET /hunts/stats, which is
// unwindowed (all-time) — while the table below is server-filtered to the
// screen's time range. "89 hunts" over a 1-row table read as broken. The
// header must instead be derived from the same windowed rows the table shows.
describe('Hunts header counts the window, not all time', () => {
  it('the header line counts the WINDOW (the rows), not all time', async () => {
    vi.mocked(getHuntStats).mockResolvedValue([
      { label: 'Hunts', value: '89', sub: 'recent', tone: 'accent' },
      { label: 'Findings', value: '427', sub: 'surfaced', tone: 'warn' },
      { label: 'In progress', value: '0', sub: 'running now', tone: 'sigma' },
    ]);
    vi.mocked(getHunts).mockResolvedValue([
      {
        id: 'h1',
        objective: 'sweep',
        kind: 'scheduled',
        status: 'complete',
        findingCount: 3,
        affectedHosts: 2,
        confidence: 0.72,
        startedBy: 'scheduler',
        when: '1h',
        ts: '2026-08-22T06:14:40Z',
      },
    ]);
    renderHunts();
    const line = await screen.findByTestId('hunt-stats-line');
    await waitFor(() => expect(line.textContent).toContain('1 hunt'));
    expect(line.textContent).toContain('3 findings');
    expect(line.textContent).not.toContain('89');
  });
});

// Since 1.5.0 the declarative hunt catalog records Hunt(kind="triggered") rows
// with no model call. HuntRow.kind reached the browser and nothing read it, so
// a spec-authored hunt was indistinguishable from one an analyst typed except
// by its objective string. The list badges the two automated kinds; a manual
// hunt (storage kind 'chat') is the default and gets no badge at all.
// The badge reads the one copy of the sentence, Frame 7's. Two copies of a
// sentence drift, and one of them had already drifted.
const CATALOG_TITLE = CHIP_CATALOG_RUN;
const kindRow = (over: Partial<HuntRow>): HuntRow => ({
  id: 'h-1',
  objective: 'sweep',
  kind: 'chat',
  status: 'complete',
  findingCount: 0,
  affectedHosts: 0,
  confidence: null,
  startedBy: 'alice',
  when: '1h',
  ts: '2026-09-05T06:00:00Z',
  ...over,
});

describe('Hunts list — kind badge', () => {
  it('badges a catalog-recorded row and leaves the manual row unbadged', async () => {
    vi.mocked(getHunts).mockResolvedValue([
      kindRow({ id: 'h-manual', objective: 'typed by an analyst', kind: 'chat' }),
      kindRow({ id: 'h-catalog', objective: 'recorded by a spec', kind: 'triggered' }),
    ]);
    renderHunts();
    await screen.findByText('recorded by a spec');
    // Exactly one badge across two rows: the catalog row wears it, the manual
    // row does not. 'catalog' is the analyst-facing label for the storage
    // kind 'triggered' — today the catalog is the only thing that triggers one.
    const badges = screen.getAllByTitle(CATALOG_TITLE);
    expect(badges).toHaveLength(1);
    expect(badges[0].textContent).toBe('catalog');
    expect(screen.queryByText('manual')).toBeNull();
  });

  it('badges a scheduled row', async () => {
    vi.mocked(getHunts).mockResolvedValue([
      kindRow({ id: 'h-sched', objective: 'nightly sweep', kind: 'scheduled' }),
    ]);
    renderHunts();
    await screen.findByText('nightly sweep');
    expect(screen.getByText('scheduled')).toBeTruthy();
  });

  it('shows no kind badge on a manual-only list', async () => {
    vi.mocked(getHunts).mockResolvedValue([
      kindRow({ id: 'h-manual', objective: 'typed by an analyst', kind: 'chat' }),
    ]);
    renderHunts();
    await screen.findByText('typed by an analyst');
    expect(screen.queryByTitle(CATALOG_TITLE)).toBeNull();
    expect(screen.queryByText('catalog')).toBeNull();
    expect(screen.queryByText('scheduled')).toBeNull();
    expect(screen.queryByText('manual')).toBeNull();
  });
});

// The kind chips are the list's second facet after the time window, and like
// the window they are applied SERVER-SIDE. The backend caps the page at 100
// rows, so a client-side slice of that page hid any kind the newest hundred
// crowded out — 101 manual hunts newer than the one catalog hunt, and the
// Catalog chip read 0 over an empty state that said none existed. A chip click
// refetches with `kind`, so the table is the server's answer. One fetch cannot
// yield both the All count and each kind's count, so only the ACTIVE chip
// carries a number.
describe('Hunts list — kind filter chips', () => {
  const MIXED = [
    kindRow({ id: 'h-m1', objective: 'typed by an analyst', kind: 'chat' }),
    kindRow({ id: 'h-m2', objective: 'also typed by an analyst', kind: 'chat' }),
    kindRow({ id: 'h-s1', objective: 'nightly sweep', kind: 'scheduled' }),
    kindRow({ id: 'h-c1', objective: 'recorded by a spec', kind: 'triggered' }),
  ];
  // The leads strip and the hits block carry their own chips, and both hold one
  // called "All". A type chip is the one outside them.
  const chip = (label: string) => {
    const strip = screen.queryByTestId('leads-strip');
    const hits = document.getElementById('analytic-hits');
    const el = screen
      .getAllByText(label)
      .find((c) => !strip?.contains(c) && !hits?.contains(c))!;
    return el.closest('button')!;
  };
  // The count is the only all-digit span inside a kind chip.
  const chipCount = (label: string) => within(chip(label)).queryByText(/^\d+$/);
  // A server that honours ?kind=: the page for a kind is that kind's rows.
  const serverByKind = (rows: HuntRow[]) => async (q?: HuntsQuery) =>
    q?.kind ? rows.filter((h) => h.kind === q.kind) : rows;
  const lastQuery = () => vi.mocked(getHunts).mock.lastCall?.[0];

  afterEach(() => {
    vi.mocked(getHunts).mockReset();
    vi.mocked(getHunts).mockResolvedValue([]);
  });

  it('a chip click refetches with kind; All fetches without one', async () => {
    vi.mocked(getHunts).mockImplementation(serverByKind(MIXED));
    renderHunts();
    await screen.findByText('typed by an analyst');
    expect(lastQuery()).not.toHaveProperty('kind');

    fireEvent.click(chip('Schedule'));
    await waitFor(() => expect(lastQuery()).toMatchObject({ kind: 'scheduled' }));
    await waitFor(() => expect(screen.queryByText('typed by an analyst')).toBeNull());
    expect(screen.getByText('nightly sweep')).toBeTruthy();
    expect(chip('Schedule').getAttribute('aria-pressed')).toBe('true');
    expect(chip('All').getAttribute('aria-pressed')).toBe('false');

    fireEvent.click(chip('All'));
    await waitFor(() => expect(lastQuery()).not.toHaveProperty('kind'));
    await screen.findByText('typed by an analyst');
    expect(screen.getByText('nightly sweep')).toBeTruthy();
    expect(chip('All').getAttribute('aria-pressed')).toBe('true');
  });

  it('holds no Catalog chip, because the sweep records no hunt row now', async () => {
    vi.mocked(getHunts).mockImplementation(serverByKind(MIXED));
    renderHunts();
    await screen.findByText('typed by an analyst');
    expect(screen.queryByText('Catalog')).toBeNull();
    for (const label of ['All', 'Manual', 'Schedule', 'Lead']) {
      expect(chip(label)).toBeTruthy();
    }
  });

  it('shows a catalog hunt the capped All page never held', async () => {
    // The failure the server-side filter exists for: newer manual hunts push
    // the one catalog hunt off the 100-row page. A slice of that page has
    // nothing to show; the server's answer for ?kind=triggered is the row.
    const page = MIXED.filter((h) => h.kind === 'chat');
    const offPage = kindRow({ id: 'h-old', objective: 'older than the whole page', kind: 'triggered' });
    vi.mocked(getHunts).mockImplementation(async (q?: HuntsQuery) =>
      q?.kind === 'triggered' ? [offPage] : page,
    );
    renderHunts();
    await screen.findByText('typed by an analyst');
    expect(screen.queryByText('older than the whole page')).toBeNull();

    renderHunts(false, '/hunts?kind=triggered');
    expect(await screen.findByText('older than the whole page')).toBeTruthy();
    // The chip comes back for that address alone, so the page says which rows
    // it is showing.
    expect(screen.getByText('Catalog run', { exact: false })).toBeTruthy();
  });

  it('only the active chip carries a count', async () => {
    vi.mocked(getHunts).mockImplementation(serverByKind(MIXED));
    renderHunts();
    await screen.findByText('typed by an analyst');
    expect(chipCount('All')?.textContent).toBe('4');
    expect(chipCount('Manual')).toBeNull();
    expect(chipCount('Schedule')).toBeNull();

    fireEvent.click(chip('Manual'));
    await waitFor(() => expect(chipCount('Manual')?.textContent).toBe('2'));
    expect(chipCount('All')).toBeNull();
    expect(chipCount('Schedule')).toBeNull();
  });

  it('says why the table is empty when the chip, not the window, emptied it', async () => {
    vi.mocked(getHuntStats).mockResolvedValue([{ label: 'Hunts', value: '2', sub: 'recent', tone: 'accent' }]);
    vi.mocked(getHunts).mockImplementation(
      serverByKind([kindRow({ id: 'h-m1', objective: 'typed by an analyst', kind: 'chat' })]),
    );
    renderHunts();
    await screen.findByText('typed by an analyst');
    fireEvent.click(chip('Schedule'));
    expect(await screen.findByText(/No scheduled runs in this window/)).toBeTruthy();
    expect(screen.queryByText('typed by an analyst')).toBeNull();
  });
});

// The kind chip used to live in component state alone, so a reload reset it
// to All and nothing could link to a filtered list: the Operate panel's "Open
// catalog hunts" had to land on the unfiltered page. The chip now reads
// `?kind=` and writes it back, the way Hosts keeps `?health=broken` in the
// address bar. The URL is what the table shows; a saved view is an act that
// rewrites it, so the last explicit act wins and the address bar never
// describes a table that is not on screen.
describe('Hunts kind chip lives in the URL', () => {
  const MIXED = [
    kindRow({ id: 'h-m1', objective: 'typed by an analyst', kind: 'chat' }),
    kindRow({ id: 'h-s1', objective: 'nightly sweep', kind: 'scheduled' }),
    kindRow({ id: 'h-c1', objective: 'recorded by a spec', kind: 'triggered' }),
  ];
  // The leads strip and the hits block carry their own chips, and both hold one
  // called "All". A type chip is the one outside them.
  const chip = (label: string) => {
    const strip = screen.queryByTestId('leads-strip');
    const hits = document.getElementById('analytic-hits');
    const el = screen
      .getAllByText(label)
      .find((c) => !strip?.contains(c) && !hits?.contains(c))!;
    return el.closest('button')!;
  };
  const serverByKind = (rows: HuntRow[]) => async (q?: HuntsQuery) =>
    q?.kind ? rows.filter((h) => h.kind === q.kind) : rows;
  const lastQuery = () => vi.mocked(getHunts).mock.lastCall?.[0];
  const loc = () => screen.getByTestId('loc').textContent;

  afterEach(() => {
    vi.mocked(getHunts).mockReset();
    vi.mocked(getHunts).mockResolvedValue([]);
    listSavedViewsMock.mockReset();
    listSavedViewsMock.mockResolvedValue([]);
  });

  it('lands on the kind a deep link names', async () => {
    vi.mocked(getHunts).mockImplementation(serverByKind(MIXED));
    renderHunts(false, '/hunts?kind=triggered');
    expect(await screen.findByText('recorded by a spec')).toBeTruthy();
    expect(lastQuery()).toMatchObject({ kind: 'triggered' });
    expect(screen.queryByText('typed by an analyst')).toBeNull();
    expect(chip('Catalog').getAttribute('aria-pressed')).toBe('true');
    expect(chip('All').getAttribute('aria-pressed')).toBe('false');
  });

  it('writes a chip click to the address bar, and All drops the param', async () => {
    vi.mocked(getHunts).mockImplementation(serverByKind(MIXED));
    renderHunts();
    await screen.findByText('typed by an analyst');
    expect(loc()).toBe('/hunts');

    fireEvent.click(chip('Manual'));
    await waitFor(() => expect(loc()).toBe('/hunts?kind=chat'));
    await waitFor(() => expect(lastQuery()).toMatchObject({ kind: 'chat' }));

    fireEvent.click(chip('All'));
    await waitFor(() => expect(loc()).toBe('/hunts'));
    await waitFor(() => expect(lastQuery()).not.toHaveProperty('kind'));
  });

  it('treats a kind the chips do not know as All', async () => {
    vi.mocked(getHunts).mockImplementation(serverByKind(MIXED));
    renderHunts(false, '/hunts?kind=bogus');
    await screen.findByText('typed by an analyst');
    expect(lastQuery()).not.toHaveProperty('kind');
    expect(chip('All').getAttribute('aria-pressed')).toBe('true');
  });

  it('a saved view applied over a deep link wins, and the address bar follows it', async () => {
    listSavedViewsMock.mockResolvedValue([
      { id: 7, screen: 'hunts', name: 'Mine', query: { kind: 'chat', range: '24h' }, created_at: null },
    ]);
    vi.mocked(getHunts).mockImplementation(serverByKind(MIXED));
    renderHunts(false, '/hunts?kind=triggered');
    await screen.findByText('recorded by a spec');

    fireEvent.click(await screen.findByTitle('Apply the saved view "Mine"'));
    await waitFor(() => expect(loc()).toBe('/hunts?kind=chat'));
    await waitFor(() => expect(lastQuery()).toMatchObject({ kind: 'chat' }));
    expect(await screen.findByText('typed by an analyst')).toBeTruthy();
    expect(screen.queryByText('recorded by a spec')).toBeNull();
    expect(chip('Manual').getAttribute('aria-pressed')).toBe('true');
  });
});

// A catalog hunt's objective is stored as "[catalog] <spec-id>: <title>
// (<since> → <until>)" (hunting/sweep.py spells it). In a truncating list cell
// the machine prefix survived and the sentence did not: "[catalog]
// decoy-opencanary-interaction: Something connected to a de…". The prefix says
// nothing the row's catalog badge does not, so the LIST drops it at render
// time. The stored objective is untouched: it is the durable record of what
// ran and over what window, and re-hunt still sends it whole.
describe('Hunts list — catalog objective reads as its title', () => {
  const STORED =
    '[catalog] decoy-opencanary-interaction: Something connected to a decoy (2026-09-04T00:00:00Z → 2026-09-05T00:00:00Z)';
  const SHOWN = 'Something connected to a decoy (2026-09-04T00:00:00Z → 2026-09-05T00:00:00Z)';

  it('drops the machine prefix from a badged catalog row and keeps the window', async () => {
    vi.mocked(getHunts).mockResolvedValue([
      kindRow({ id: 'h-c1', objective: STORED, kind: 'triggered' }),
    ]);
    renderHunts();
    const cell = await screen.findByText(SHOWN);
    expect(screen.queryByText(STORED)).toBeNull();
    // The full stored objective is one hover away.
    expect(cell.getAttribute('title')).toBe(STORED);
    // The badge is still there to say where the row came from.
    expect(screen.getByTitle(CATALOG_TITLE)).toBeTruthy();
  });

  it('leaves a manual hunt alone even when its text looks like the prefix', async () => {
    // An analyst can type anything, including this shape. Only a row that
    // carries the catalog badge is stripped, so the badge and the trimmed
    // title are never seen apart.
    vi.mocked(getHunts).mockResolvedValue([
      kindRow({ id: 'h-m1', objective: STORED, kind: 'chat' }),
    ]);
    renderHunts();
    expect(await screen.findByText(STORED)).toBeTruthy();
    expect(screen.queryByText(SHOWN)).toBeNull();
  });

  it('shows a catalog row whose objective has no prefix as it is', async () => {
    vi.mocked(getHunts).mockResolvedValue([
      kindRow({ id: 'h-c2', objective: 'recorded by a spec', kind: 'triggered' }),
    ]);
    renderHunts();
    expect(await screen.findByText('recorded by a spec')).toBeTruthy();
  });
});

// Manual is the default kind and, on most grids, the majority of rows, so it
// wears no badge: a chip on nine rows in ten is noise, not a label. But an
// unbadged row then needs somewhere to be named, or the All view is a list
// where some rows say "scheduled" and "catalog" and the rest say nothing. The
// header line already describes the rows the table shows; under All it now
// breaks them down by kind, so the plain rows are accounted for as manual
// on the same line that counts them. Under a kind chip the chip names the
// kind, and the breakdown would only repeat it.
describe('Hunts header names the kinds under All', () => {
  // The leads strip and the hits block carry their own chips, and both hold one
  // called "All". A type chip is the one outside them.
  const chip = (label: string) => {
    const strip = screen.queryByTestId('leads-strip');
    const hits = document.getElementById('analytic-hits');
    const el = screen
      .getAllByText(label)
      .find((c) => !strip?.contains(c) && !hits?.contains(c))!;
    return el.closest('button')!;
  };
  const serverByKind = (rows: HuntRow[]) => async (q?: HuntsQuery) =>
    q?.kind ? rows.filter((h) => h.kind === q.kind) : rows;

  afterEach(() => {
    vi.mocked(getHunts).mockReset();
    vi.mocked(getHunts).mockResolvedValue([]);
  });

  it('breaks the count down by kind, manual included, in chip order', async () => {
    vi.mocked(getHunts).mockResolvedValue([
      kindRow({ id: 'h-m1', objective: 'typed by an analyst', kind: 'chat' }),
      kindRow({ id: 'h-m2', objective: 'also typed by an analyst', kind: 'chat' }),
      kindRow({ id: 'h-s1', objective: 'nightly sweep', kind: 'scheduled' }),
      kindRow({ id: 'h-c1', objective: 'recorded by a spec', kind: 'triggered' }),
    ]);
    renderHunts();
    const line = await screen.findByTestId('hunt-stats-line');
    await waitFor(() => expect(line.textContent).toContain('4 hunts'));
    // The API answers the plain list with agent runs only, so the breakdown
    // names the three types an agent produces.
    expect(line.textContent).toContain('(2 manual, 1 scheduled)');
    // The manual rows are still unbadged; the line is where they are named.
    expect(screen.queryByText('manual')).toBeNull();
  });

  it('names a single kind too, so an unbadged page is still accounted for', async () => {
    vi.mocked(getHunts).mockResolvedValue([
      kindRow({ id: 'h-m1', objective: 'typed by an analyst', kind: 'chat' }),
    ]);
    renderHunts();
    const line = await screen.findByTestId('hunt-stats-line');
    await waitFor(() => expect(line.textContent).toContain('1 hunt (1 manual)'));
  });

  it('drops the breakdown under a kind chip, which already names the kind', async () => {
    vi.mocked(getHunts).mockImplementation(
      serverByKind([
        kindRow({ id: 'h-m1', objective: 'typed by an analyst', kind: 'chat' }),
        kindRow({ id: 'h-c1', objective: 'recorded by a spec', kind: 'triggered' }),
      ]),
    );
    renderHunts();
    const line = await screen.findByTestId('hunt-stats-line');
    await waitFor(() => expect(line.textContent).toContain('(1 manual)'));

    fireEvent.click(chip('Manual'));
    await waitFor(() => expect(line.textContent).toContain('1 hunt'));
    expect(line.textContent).not.toContain('(');
    expect(line.textContent).not.toContain('manual');
  });
});

// Two empty states under a kind chip said the wrong thing. Under Scheduled at
// 24h the table read "No scheduled hunts in this window" directly above a
// panel titled "Scheduled hunts" listing three of them: the word meant runs
// above and schedules below. Under Manual it said "pick another kind above"
// while five manual hunts sat four weeks back and the time-range chips were
// right there. The chip is the analyst's question; the window is the control
// that would find the answer.
describe('Hunts empty state under a kind chip', () => {
  // The leads strip and the hits block carry their own chips, and both hold one
  // called "All". A type chip is the one outside them.
  const chip = (label: string) => {
    const strip = screen.queryByTestId('leads-strip');
    const hits = document.getElementById('analytic-hits');
    const el = screen
      .getAllByText(label)
      .find((c) => !strip?.contains(c) && !hits?.contains(c))!;
    return el.closest('button')!;
  };
  const serverByKind = (rows: HuntRow[]) => async (q?: HuntsQuery) =>
    q?.kind ? rows.filter((h) => h.kind === q.kind) : rows;
  const MANUAL_ONLY = [kindRow({ id: 'h-m1', objective: 'typed by an analyst', kind: 'chat' })];

  afterEach(() => {
    vi.mocked(getHunts).mockReset();
    vi.mocked(getHunts).mockResolvedValue([]);
    // Never leave this one bare: the panel's loader calls it on every mount,
    // and an undefined return is a crash in useAsync, not an empty panel.
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
  });

  it('says runs, not hunts, under Scheduled, so it cannot contradict the schedules panel', async () => {
    getHuntSchedulesMock.mockResolvedValue({
      schedules: [SCHEDULE],
      masterSwitchEnabled: true,
    });
    vi.mocked(getHuntStats).mockResolvedValue([{ label: 'Hunts', value: '1', sub: 'recent', tone: 'accent' }]);
    vi.mocked(getHunts).mockImplementation(serverByKind(MANUAL_ONLY));
    renderHunts();
    await screen.findByText('typed by an analyst');
    await screen.findByText('Nightly beacon sweep');

    fireEvent.click(chip('Schedule'));
    expect(await screen.findByText(/No scheduled runs in this window/)).toBeTruthy();
    expect(screen.queryByText(/No scheduled hunts/)).toBeNull();
  });

  it('points at the time range, not the kind chips, when a kind empties the window', async () => {
    vi.mocked(getHuntStats).mockResolvedValue([{ label: 'Hunts', value: '6', sub: 'recent', tone: 'accent' }]);
    vi.mocked(getHunts).mockImplementation(
      serverByKind([kindRow({ id: 'h-c1', objective: 'recorded by a spec', kind: 'triggered' })]),
    );
    renderHunts();
    await screen.findByText('recorded by a spec');

    fireEvent.click(chip('Manual'));
    const empty = await screen.findByText(/No manual hunts in this window/);
    expect(empty.textContent).toMatch(/Widen the time range/);
    expect(empty.textContent).not.toMatch(/pick another kind/);
  });
});


// Two tabs on one screen. A hunt is an investigation of one hypothesis. An
// analytic is one detection logic. The product recorded each analytic firing
// as a hunt, which is the inversion this tab strip ends.
const ANALYTIC_DETAIL = {
  id: 'identity-4769',
  title: 'A ticket request names a service account',
  level: 'medium',
  evaluator: 'match',
  scope_kind: 'host',
  tier: 'shipped',
  status: 'live',
  no_benign_baseline: false,
  observations_7d: 2,
  leads_7d: 1,
  hunted_7d: 0,
  dismissed_7d: 0,
  shadow_hits_7d: 0,
  unread_shadow_hits: 0,
  description: 'one detection logic',
  spec_text: 'id: identity-4769',
  reason: null,
  ledger: {
    analytic_id: 'identity-4769',
    since: '2026-09-11T00:00:00Z',
    observations: 2,
    entities: 1,
    shadow_hits: 0,
    unread_shadow_hits: 0,
    leads: 1,
    hunted: 0,
    promoted: 0,
    dismissed: {},
    docs_scanned: 10,
    runtime_ms: 5,
    sweeps: 3,
    coverage: {},
  },
  versions: [],
  recent: [],
};

describe('Hunts and Analytics tabs', () => {
  it('opens on the hunt list and shows no band while no shadow hit exists', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
    vi.mocked(getHunts).mockResolvedValue([
      {
        id: 'H1',
        objective: 'typed by an analyst',
        kind: 'chat',
        status: 'complete',
        findingCount: 0,
        affectedHosts: 0,
        confidence: null,
        when: '1m',
        ts: '2026-09-17T10:00:00+00:00',
        chatCount: 0,
      } as HuntRow,
    ]);
    renderHunts();
    await screen.findByText('typed by an analyst');
    expect(screen.queryByTestId('shadow-hits-band')).toBeNull();
    expect(screen.getByRole('button', { name: /^Hunts$/ })).toBeTruthy();
  });

  it('renders the Analytics tab from the address and hides the hunt list', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
    vi.mocked(getHunts).mockResolvedValue([
      {
        id: 'H1',
        objective: 'typed by an analyst',
        kind: 'chat',
        status: 'complete',
        findingCount: 0,
        affectedHosts: 0,
        confidence: null,
        when: '1m',
        ts: '2026-09-17T10:00:00+00:00',
        chatCount: 0,
      } as HuntRow,
    ]);
    renderHunts(false, '/hunts?tab=analytics');
    await screen.findByText(/retired: the analytic keeps its ledger and its reason/);
    expect(screen.queryByText('typed by an analyst')).toBeNull();
  });

  // The evidence of a shadow hit names the analytics that observed the same
  // documents. Each one is a link to its drawer, so the address has to be able
  // to open one.
  it('opens the analytic the address names', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
    vi.mocked(getHunts).mockResolvedValue([]);
    vi.mocked(getAnalytic).mockResolvedValue(ANALYTIC_DETAIL as never);
    renderHunts(false, '/hunts?tab=analytics&open=identity-4769');
    await waitFor(() => expect(getAnalytic).toHaveBeenCalledWith('identity-4769'));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByTestId('analytic-id').textContent).toBe('identity-4769');
  });

  it('takes the analytic out of the address when the drawer closes', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
    vi.mocked(getHunts).mockResolvedValue([]);
    vi.mocked(getAnalytic).mockResolvedValue(ANALYTIC_DETAIL as never);
    renderHunts(false, '/hunts?tab=analytics&open=identity-4769');
    await screen.findByRole('dialog');
    fireEvent.keyDown(window, { key: 'Escape' });
    await waitFor(() => expect(screen.getByTestId('loc').textContent).toBe('/hunts?tab=analytics'));
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('writes the tab into the address and takes it out again', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
    vi.mocked(getHunts).mockResolvedValue([]);
    renderHunts();
    await screen.findByRole('button', { name: /^Analytics/ });

    fireEvent.click(screen.getByRole('button', { name: /^Analytics/ }));
    await waitFor(() => expect(screen.getByTestId('loc').textContent).toBe('/hunts?tab=analytics'));

    fireEvent.click(screen.getByRole('button', { name: /^Hunts$/ }));
    await waitFor(() => expect(screen.getByTestId('loc').textContent).toBe('/hunts'));
  });
});

// A lead hunt's objective is the whole lead, written out: the entities, the
// kinds and up to twelve observation summaries. The cell truncated it to
// "[lead 3] Investigate 10.1.2.3. The lead formed…" and offered no way back to
// the lead. The cell now names the lead and links to it.
describe('Hunts list lead rows', () => {
  const LEAD_OBJECTIVE =
    '[lead 3] Investigate 10.1.10.21. The lead formed from a new destination and off hours.\n' +
    'Observations:\n- first connection to 140.82.121.4\n- active at 19:00';

  const LEAD_ROW = {
    id: 'H-LEAD',
    objective: LEAD_OBJECTIVE,
    kind: 'lead',
    status: 'complete',
    findingCount: 1,
    threatFindingCount: 1,
    outcome: 'threats',
    affectedHosts: 1,
    confidence: 0.8,
    startedBy: 'analyst',
    starter: 'lead',
    leadId: 3,
    when: '4m',
    ts: '2026-09-17T10:00:00+00:00',
    chatCount: 0,
  } as HuntRow;

  const show = async (rows: HuntRow[]) => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
    vi.mocked(getHunts).mockResolvedValue(rows);
    renderHunts();
    return screen.findByText('Started by');
  };

  // The cell names the lead and its entity, and it links to the HUNT: the
  // objective is the one link to the hunt page in the row. The lead keeps its
  // own link in the Started by cell.
  it('names the lead and its entity, and links to the hunt', async () => {
    await show([LEAD_ROW]);
    const link = await screen.findByRole('link', { name: 'Lead 3 on 10.1.10.21' });
    expect(link.getAttribute('href')).toBe('/hunts/H-LEAD');
    expect(screen.getByRole('link', { name: 'lead 3' }).getAttribute('href')).toBe('/leads/3');
  });

  it('keeps the whole objective on the cell for a hover', async () => {
    await show([LEAD_ROW]);
    const link = await screen.findByRole('link', { name: 'Lead 3 on 10.1.10.21' });
    expect(link.getAttribute('title')).toBe(LEAD_OBJECTIVE);
  });

  it('titles a truncated objective on every other row', async () => {
    const objective =
      'Hunt for internal hosts that beacon to rare external IPs in the last 24 h and name the cadence.';
    await show([{ ...LEAD_ROW, id: 'H2', kind: 'chat', starter: 'analyst', leadId: null, objective }]);
    expect((await screen.findByText(objective)).getAttribute('title')).toBe(objective);
  });

  it('reads the starter as the lead it came from', async () => {
    await show([LEAD_ROW]);
    expect(await screen.findByRole('link', { name: 'lead 3' })).toBeTruthy();
  });
});

// The status word for a complete hunt was derived on the client from an
// outcome code. The backend now names the outcome itself, and the client word
// disagreed with the hunt page beside it.
describe('Hunts list status word', () => {
  const base = {
    id: 'H9',
    objective: 'Hunt for lateral movement',
    kind: 'chat',
    status: 'complete',
    findingCount: 0,
    threatFindingCount: 0,
    affectedHosts: 0,
    confidence: null,
    startedBy: 'analyst',
    when: '4m',
    ts: '2026-09-17T10:00:00+00:00',
    chatCount: 0,
  } as HuntRow;

  const show = async (row: HuntRow) => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
    vi.mocked(getHunts).mockResolvedValue([row]);
    renderHunts();
    return screen.findByText('Started by');
  };

  it('uses the label the backend wrote', async () => {
    await show({ ...base, outcome: 'gap', outcome_label: 'No telemetry to read' });
    expect(await screen.findByText('No telemetry to read')).toBeTruthy();
  });

  it('falls back to the client word when the backend sends none', async () => {
    await show({ ...base, outcome: 'gap' });
    expect(await screen.findByText('No telemetry')).toBeTruthy();
  });

  it('names the gap in the findings tooltip with the one phrase', async () => {
    await show({ ...base, outcome: 'gap' });
    const cell = (await screen.findByText('No telemetry')).closest('.grid')!;
    const findings = within(cell as HTMLElement).getByTitle(
      /No threat observed · visibility gap/,
    );
    expect(findings).toBeTruthy();
  });
});

// The tab counted live and shadow and stopped. A candidate analytic and a
// retired one both fell into the total with no word beside them, so 18 · 16
// live · 1 shadow left two analytics unaccounted for. The screen and the panel
// also fetched the same list twice.
describe('Hunts analytics tab count', () => {
  const LIST = {
    analytics: Array.from({ length: 18 }, (_, i) => ({
      id: `a${i}`,
      title: `Analytic ${i}`,
      level: 'medium',
      evaluator: 'query',
      scope_kind: 'host',
      tier: 'shipped',
      status: i < 16 ? 'live' : i === 16 ? 'shadow' : 'candidate',
      no_benign_baseline: false,
      observations_7d: 0,
      leads_7d: 0,
      hunted_7d: 0,
      dismissed_7d: 0,
      shadow_hits_7d: 0,
      unread_shadow_hits: 0,
    })),
    counts: { live: 16, shadow: 1, candidate: 1 },
  };

  it('names every status the catalog holds', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
    vi.mocked(getHunts).mockResolvedValue([]);
    vi.mocked(getAnalytics).mockResolvedValue(LIST as never);
    renderHunts();
    await screen.findByText('18 · 16 live · 1 shadow · 1 candidate');
  });

  it('reads the list once for the tab and the panel together', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
    vi.mocked(getHunts).mockResolvedValue([]);
    vi.mocked(getAnalytics).mockClear().mockResolvedValue(LIST as never);
    renderHunts(false, '/hunts?tab=analytics');
    await screen.findByText('18 · 16 live · 1 shadow · 1 candidate');
    expect(vi.mocked(getAnalytics).mock.calls.length).toBe(1);
  });
});

// One navigation rule: a link goes to a page, a button acts, and no row is
// clickable as a whole. The hunt list was the last surface that broke it. The
// whole row navigated and the objective was a span, so the one word that names
// the hunt was the one word an analyst could not copy, middle-click or read as
// a destination.
describe('Hunts list navigation rule', () => {
  const outsideTheBlocks = (label: string) => {
    const strip = screen.queryByTestId('leads-strip');
    const hits = document.getElementById('analytic-hits');
    return screen.getAllByText(label).find((c) => !strip?.contains(c) && !hits?.contains(c))!;
  };

  it('makes the objective the link to the hunt page', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
    vi.mocked(getHunts).mockResolvedValue([
      kindRow({ id: 'H1', objective: 'typed by an analyst', findingCount: 3 }),
    ]);
    renderHunts();
    const objective = await screen.findByText('typed by an analyst');
    expect(objective.closest('a')?.getAttribute('href')).toBe('/hunts/H1');
  });

  it('leaves the rest of the row inert', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
    vi.mocked(getHunts).mockResolvedValue([
      kindRow({ id: 'H1', objective: 'typed by an analyst', findingCount: 3 }),
    ]);
    renderHunts();
    const row = (await screen.findByText('typed by an analyst')).closest('.grid') as HTMLElement;
    expect(row.className).not.toContain('cursor-pointer');
    fireEvent.click(within(row).getByText('3'));
    expect(screen.getByTestId('loc').textContent).toBe('/hunts');
  });

  // Frame 7's catalog-run sentence sat in the tooltips module, imported
  // nowhere, while the badge carried an older copy of it. The lead badge and
  // the Lead type chip had drifted the same way.
  it('reads the one copy of each type sentence', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
    vi.mocked(getHunts).mockResolvedValue([
      kindRow({ id: 'h-c', objective: 'recorded by the sweep', kind: 'triggered' }),
      kindRow({ id: 'h-l', objective: 'started from a lead', kind: 'lead', starter: 'lead', leadId: 5 }),
    ]);
    renderHunts(false, '/hunts?kind=triggered');
    const catalogRow = (await screen.findByText('recorded by the sweep')).closest(
      '.grid',
    ) as HTMLElement;
    const leadRow = screen.getByText('Lead 5').closest('.grid') as HTMLElement;
    expect(within(catalogRow).getByTitle(CHIP_CATALOG_RUN).textContent).toBe('catalog');
    expect(within(leadRow).getByTitle(TYPE_LEAD).textContent).toBe('lead');
  });

  it('sends a lead row to the hunt from the objective and to the lead from the starter', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
    vi.mocked(getHunts).mockResolvedValue([
      kindRow({
        id: 'H2',
        objective: '[lead 5] Investigate 10.1.99.5. The lead formed on two types.',
        kind: 'lead',
        starter: 'lead',
        leadId: 5,
      }),
    ]);
    renderHunts();
    const objective = await screen.findByText('Lead 5 on 10.1.99.5');
    expect(objective.closest('a')?.getAttribute('href')).toBe('/hunts/H2');
    expect(outsideTheBlocks('lead 5').closest('a')?.getAttribute('href')).toBe('/leads/5');
  });
});

// The bell's shadow-hit notice lands on `/hunts#shadow-hits`: the block scrolls
// into view with the filter on All, so the card the notice names sits somewhere
// in a list of every hit. The Dashboard card link sets `hits=unread` and lands
// on the same block. One anchor, one filter.
describe('Hunts #shadow-hits lands on the unread hits', () => {
  it('sets the unread filter when the address names no other', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
    vi.mocked(getHunts).mockResolvedValue([]);
    renderHunts(false, '/hunts#shadow-hits');
    await waitFor(() =>
      expect(screen.getByTestId('loc').textContent).toBe('/hunts?hits=unread'),
    );
  });

  it('leaves a filter the address already names alone', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
    vi.mocked(getHunts).mockResolvedValue([]);
    renderHunts(false, '/hunts?hits=live#shadow-hits');
    await screen.findByTestId('loc');
    expect(screen.getByTestId('loc').textContent).toBe('/hunts?hits=live');
  });
});

// The block opened on 24 h and read "0 hunts" under three leads that each
// offered Read hunt. The page then held three windows: 7 days of hits, all the
// leads, and one day of hunts. The hunt block reads 7 days now, and when the
// window still holds nothing the empty state names the leads that reach the
// older hunts rather than sending the analyst to the range chips alone.
describe('Hunts block window', () => {
  const HUNTED_LEAD = {
    id: 5,
    status: 'hunting',
    formed_at: '2026-09-01T00:00:00+00:00',
    updated_at: '2026-09-01T00:00:00+00:00',
    entities: [['host', '10.1.99.5']],
    kinds: ['catalog_match'],
    weight_at_formation: 0.9,
    scope_count: 1,
    hunt_id: 'H-OLD',
    hunt_status: 'complete',
    shadow: false,
    single_signal: false,
    observations: [],
  };

  it('asks the server for seven days', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
    vi.mocked(getHunts).mockClear().mockResolvedValue([]);
    renderHunts();
    await waitFor(() => expect(getHunts).toHaveBeenCalled());
    const since = vi.mocked(getHunts).mock.calls[0][0]!.since!;
    expect(Math.round((Date.now() - new Date(since).getTime()) / 86_400_000)).toBe(7);
  });

  it('keeps the window the address names', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
    vi.mocked(getHunts).mockClear().mockResolvedValue([]);
    renderHunts(false, '/hunts?range=24h');
    await waitFor(() => expect(getHunts).toHaveBeenCalled());
    const since = vi.mocked(getHunts).mock.calls[0][0]!.since!;
    expect(Math.round((Date.now() - new Date(since).getTime()) / 3_600_000)).toBe(24);
  });

  it('names the leads when the window holds no hunt and a lead has one', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
    vi.mocked(getHunts).mockResolvedValue([]);
    vi.mocked(getHuntStats).mockResolvedValue([
      { label: 'Hunts', value: '17', sub: 'recent', tone: 'accent' },
    ]);
    vi.mocked(getLeads).mockResolvedValue([HUNTED_LEAD] as never);
    renderHunts();
    expect(
      await screen.findByText('No hunts in the last 7 days. The leads above link to older hunts.'),
    ).toBeTruthy();
  });

  it('points at the time range when no lead holds a hunt either', async () => {
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
    vi.mocked(getHunts).mockResolvedValue([]);
    vi.mocked(getHuntStats).mockResolvedValue([
      { label: 'Hunts', value: '17', sub: 'recent', tone: 'accent' },
    ]);
    vi.mocked(getLeads).mockResolvedValue([{ ...HUNTED_LEAD, hunt_id: null, hunt_status: null }] as never);
    renderHunts();
    const empty = await screen.findByText(/No hunts in this window/);
    expect(empty.textContent).toMatch(/Widen the time range above/);
  });
});
