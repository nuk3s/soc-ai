// The four sections of the Hunts tab fold.
//
// The page is long: hits, leads, hunts, schedules. An analyst who works the
// leads should not scroll past fifty hit cards to reach them. A chevron folds a
// section, and the fold stays on this browser.
//
// A folded section still says what it is and how many it holds: the title, the
// count and the definition line stay. And a Needs-you link still lands on the
// work, so it unfolds the block it jumps to before it scrolls there.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DemoProvider } from '../lib/demo';

const HIT = vi.hoisted(() => ({
  id: 42,
  analytic_id: 'local-rare-service',
  analytic_title: 'A workstation reaches a service it has never reached',
  analytic_status: 'shadow',
  recorded_in_shadow: true,
  tier: 'local',
  entity_kind: 'host',
  entity_key: '10.1.10.21',
  born_at: new Date(Date.now() - 3_600_000).toISOString(),
  first_seen_at: new Date(Date.now() - 3_600_000).toISOString(),
  occurrences: 1,
  summary: null,
  state: 'hit',
  missing: [],
  receipts: {
    matched_ids: ['a1'],
    matched_fields: ['destination.port'],
    dry_run: { window_days: 30, fires: 1, entities: ['10.1.10.21'] },
    overlap: [],
    baseline: null,
    complete: true,
    missing: [],
  },
  read: false,
  lead_id: null,
  lead_status: null,
  document_count: 1,
}));

const LEAD = vi.hoisted(() => ({
  id: 7,
  status: 'open',
  formed_at: new Date(Date.now() - 5 * 3_600_000).toISOString(),
  updated_at: new Date(Date.now() - 5 * 3_600_000).toISOString(),
  entities: [['host', '10.1.10.21']],
  kinds: ['novel_destination', 'off_hours'],
  weight_at_formation: 1.07,
  scope_count: 1,
  hunt_id: null,
  shadow: false,
  single_signal: false,
  observations: [],
}));

const SCHEDULE = vi.hoisted(() => ({
  id: 1,
  objective: 'Nightly beacon sweep',
  intervalMinutes: 1440,
  enabled: true,
  lastRunAt: null,
  createdBy: 'analyst',
  createdAt: '2026-09-01T00:00:00+00:00',
}));

const needsYouMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunts: vi.fn().mockResolvedValue([]),
  getHuntStats: vi.fn().mockResolvedValue([]),
  getHuntTemplates: vi.fn().mockResolvedValue([]),
  getHuntSchedules: vi
    .fn()
    .mockResolvedValue({ schedules: [SCHEDULE], masterSwitchEnabled: true }),
  listSavedViews: vi.fn().mockResolvedValue([]),
  getAnalytics: vi.fn().mockResolvedValue({ analytics: [], counts: {} }),
  getAnalytic: vi.fn(),
  getAnalyticHits: vi
    .fn()
    .mockResolvedValue({ hits: [HIT], counts: { all: 1, unread: 1, live: 0, shadow: 1 } }),
  getNeedsYou: needsYouMock,
  getLeads: vi.fn().mockResolvedValue([LEAD]),
  getHuntCatalog: vi.fn().mockResolvedValue({
    specs: [],
    sweeps_enabled: true,
    sweep_interval_minutes: 60,
    sweep_window_minutes: 61,
    last_sweep_at: null,
  }),
}));

import { ShellProvider } from '../shell/ShellContext';
import { COLLAPSE_SECTION, EXPAND_SECTION } from '../lib/tooltips';
import { Hunts } from './Hunts';

function renderHunts(path = '/hunts') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <DemoProvider demo={false}>
        <ShellProvider>
          <Routes>
            <Route path="/hunts" element={<Hunts />} />
          </Routes>
        </ShellProvider>
      </DemoProvider>
    </MemoryRouter>,
  );
}

const chevron = (name: string) => screen.getByRole('button', { name });

beforeEach(() => {
  localStorage.clear();
  needsYouMock
    .mockReset()
    .mockResolvedValue({ unread_shadow_hits: 1, leads_needing_decision: 1, total: 2 });
});

afterEach(() => localStorage.clear());

describe('folding a section of the Hunts tab', () => {
  it('folds the hits and keeps the title, the count and the definition', async () => {
    renderHunts();
    await screen.findByTestId(`analytic-hit-${HIT.id}`);

    fireEvent.click(chevron('Collapse Analytic hits'));

    await waitFor(() => expect(screen.queryByTestId(`analytic-hit-${HIT.id}`)).toBeNull());
    const block = document.getElementById('analytic-hits')!;
    expect(block.textContent).toContain('Analytic hits');
    expect(block.textContent).toContain('1 unread');
    expect(within(block).getByTestId('define-hit')).toBeTruthy();
    // The filters describe a list nobody can see.
    expect(within(block).queryByRole('button', { name: /^Unread/ })).toBeNull();
  });

  it('folds the leads and keeps the count that says how many need a decision', async () => {
    renderHunts();
    await screen.findByTestId(`lead-${LEAD.id}`);

    fireEvent.click(chevron('Collapse Leads'));

    await waitFor(() => expect(screen.queryByTestId(`lead-${LEAD.id}`)).toBeNull());
    const strip = screen.getByTestId('leads-strip');
    expect(strip.textContent).toContain('1 needs a decision');
    expect(within(strip).getByTestId('define-lead')).toBeTruthy();
    expect(within(strip).queryByRole('button', { name: 'Needs decision' })).toBeNull();
  });

  it('folds the hunts and leaves the header with its count', async () => {
    renderHunts();
    await screen.findByText('Objective');

    fireEvent.click(chevron('Collapse Hunts'));

    await waitFor(() => expect(screen.queryByText('Objective')).toBeNull());
    expect(screen.getByTestId('define-hunt')).toBeTruthy();
    // The one act a folded section keeps: a new hunt.
    expect(screen.getByRole('button', { name: /New hunt/ })).toBeTruthy();
  });

  it('folds the scheduled hunts', async () => {
    renderHunts();
    await screen.findByText(SCHEDULE.objective);

    fireEvent.click(chevron('Collapse Scheduled hunts'));

    await waitFor(() => expect(screen.queryByText(SCHEDULE.objective)).toBeNull());
    expect(screen.getByTestId('define-schedule')).toBeTruthy();
    expect(screen.queryByPlaceholderText('New recurring hunt objective…')).toBeNull();
  });

  it('writes the fold to this browser and reads it on the next visit', async () => {
    const first = renderHunts();
    await screen.findByTestId(`analytic-hit-${HIT.id}`);
    fireEvent.click(chevron('Collapse Analytic hits'));
    await waitFor(() =>
      expect(localStorage.getItem('soc-ai.hunts.collapsed.hits')).toBe('1'),
    );

    first.unmount();
    renderHunts();
    await screen.findByTestId('define-hit');
    expect(screen.queryByTestId(`analytic-hit-${HIT.id}`)).toBeNull();
    expect(chevron('Expand Analytic hits')).toBeTruthy();
  });

  it('states on the chevron what a fold does and where it is kept', async () => {
    renderHunts();
    await screen.findByTestId(`analytic-hit-${HIT.id}`);
    const button = chevron('Collapse Analytic hits');
    expect(button.getAttribute('title')).toBe(COLLAPSE_SECTION);
    expect(button.getAttribute('aria-expanded')).toBe('true');
    const controls = button.getAttribute('aria-controls')!;
    expect(document.getElementById(controls)).toBeTruthy();

    fireEvent.click(button);
    await waitFor(() =>
      expect(chevron('Expand Analytic hits').getAttribute('aria-expanded')).toBe('false'),
    );
    expect(chevron('Expand Analytic hits').getAttribute('title')).toBe(EXPAND_SECTION);
  });

  it('unfolds the block a Needs-you link jumps to', async () => {
    localStorage.setItem('soc-ai.hunts.collapsed.hits', '1');
    renderHunts();
    const link = await screen.findByText('1 shadow hit is unread');
    expect(screen.queryByTestId(`analytic-hit-${HIT.id}`)).toBeNull();

    fireEvent.click(link);

    expect(await screen.findByTestId(`analytic-hit-${HIT.id}`)).toBeTruthy();
  });

  // The address keeps the fragment after the jump. The effect that opens a
  // block must not re-open the section the analyst folds under it.
  it('still folds a section the address names', async () => {
    renderHunts('/hunts#analytic-hits');
    await screen.findByTestId(`analytic-hit-${HIT.id}`);

    fireEvent.click(chevron('Collapse Analytic hits'));

    await waitFor(() => expect(screen.queryByTestId(`analytic-hit-${HIT.id}`)).toBeNull());
    expect(chevron('Expand Analytic hits')).toBeTruthy();
  });

  it('unfolds the leads a Needs-you link jumps to', async () => {
    localStorage.setItem('soc-ai.hunts.collapsed.leads', '1');
    renderHunts();
    const link = await screen.findByText('1 lead waits on a decision');
    expect(screen.queryByTestId(`lead-${LEAD.id}`)).toBeNull();

    fireEvent.click(link);

    expect(await screen.findByTestId(`lead-${LEAD.id}`)).toBeTruthy();
  });

  it('keeps the Analytics panel whole: it is the tab, not a section', async () => {
    renderHunts('/hunts?tab=analytics');
    await screen.findByTestId('define-analytic');
    expect(screen.queryByRole('button', { name: /^Collapse /})).toBeNull();
  });
});
