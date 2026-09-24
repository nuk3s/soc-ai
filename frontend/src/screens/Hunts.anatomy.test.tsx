// The Hunts page reads top to bottom as the pipeline: what needs the analyst,
// what the analytics found (Analytic hits), what is worth pursuing (Leads),
// what was pursued (Hunts). Each item appears once.
//
// These tests pin the ANATOMY, because a pixel offset is not something the DOM
// can measure: the order of the blocks, the one-line header, and the composer
// that is a drawer behind one button rather than a band at the top of the page.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { DemoProvider } from '../lib/demo';
import type { HuntRow, HuntStat } from '../lib/types';

const getHuntsMock = vi.hoisted(() => vi.fn());
const getHuntStatsMock = vi.hoisted(() => vi.fn());
const getHuntTemplatesMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunts: getHuntsMock,
  getHuntStats: getHuntStatsMock,
  getHuntTemplates: getHuntTemplatesMock,
  getHuntSchedules: vi.fn().mockResolvedValue({ schedules: [], masterSwitchEnabled: true }),
  // Quiet state for the two surfaces merge 4 added. With no shadow hits the
  // band renders nothing, so the band count above the toolbar stays 2.
  getShadowHits: vi.fn().mockResolvedValue({ hits: [], unread: 0 }),
  getAnalytics: vi.fn().mockResolvedValue({ analytics: [], counts: {} }),
  // The three surfaces above the list, in their quiet state.
  getAnalyticHits: vi.fn().mockResolvedValue({
    hits: [],
    counts: { all: 0, unread: 0, live: 0, shadow: 0 },
  }),
  getNeedsYou: vi
    .fn()
    .mockResolvedValue({ unread_shadow_hits: 0, leads_needing_decision: 0, total: 0 }),
  getLeads: vi.fn().mockResolvedValue([]),
}));

import { ShellProvider } from '../shell/ShellContext';
import { Hunts } from './Hunts';

const ROW: HuntRow = {
  id: 'H1',
  objective: 'Hunt for hosts beaconing to rare external IPs',
  kind: 'chat',
  status: 'complete',
  findingCount: 4,
  affectedHosts: 3,
  confidence: 0.7,
  startedBy: 'analyst',
  when: '8m',
  ts: '2026-08-12T10:00:00+00:00',
  chatCount: 0,
};

const STATS: HuntStat[] = [
  { label: 'Hunts', value: '7', sub: 'recent', tone: 'accent' },
  { label: 'Findings', value: '10', sub: 'surfaced', tone: 'warn' },
  { label: 'In progress', value: '1', sub: 'running now', tone: 'sigma' },
];

function renderHunts(path = '/hunts') {
  getHuntsMock.mockResolvedValue([ROW]);
  getHuntStatsMock.mockResolvedValue(STATS);
  getHuntTemplatesMock.mockResolvedValue([]);
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

const follows = (a: Element, b: Element) =>
  Boolean(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);

const composer = () => screen.queryByPlaceholderText(/hunt for beaconing to rare external IPs/i);

describe('Hunts page anatomy', () => {
  it('reads as the pipeline, top to bottom', async () => {
    renderHunts();
    await screen.findByText(ROW.objective);

    const stats = screen.getByTestId('hunt-stats-line');
    const needsYou = screen.getByTestId('needs-you');
    const hits = document.getElementById('analytic-hits')!;
    const leads = screen.getByTestId('leads-strip');
    // The hunt section states what a hunt is, where it used to state that the
    // list holds agent runs only. One sentence, not two saying one thing.
    const section = screen.getByTestId('define-hunt');
    const objectiveHeader = screen.getByText('Objective');

    expect(follows(stats, needsYou)).toBe(true);
    expect(follows(needsYou, hits)).toBe(true);
    expect(follows(hits, leads)).toBe(true);
    expect(follows(leads, section)).toBe(true);
    expect(follows(section, objectiveHeader)).toBe(true);
  });

  it('heads the hunt list with the shared toolbar', async () => {
    renderHunts();
    await screen.findByText(ROW.objective);

    const page = screen.getByTestId('hunt-stats-line').parentElement!.parentElement!;
    const objectiveHeader = screen.getByText('Objective');
    // The toolbar's own band: walk up from its chip row to the page's child.
    let toolbar = screen.getByTestId('list-toolbar-views') as HTMLElement;
    while (toolbar.parentElement && toolbar.parentElement !== page) {
      toolbar = toolbar.parentElement;
    }
    expect(follows(toolbar, objectiveHeader)).toBe(true);
  });

  it('states the KPI figures on one header line instead of a card band', async () => {
    renderHunts();
    await screen.findByText(ROW.objective);

    // One node carries all three figures — three cards cannot satisfy this.
    // The figures are derived from the windowed rows (ROW: 1 hunt, 4
    // findings, not running), NOT the unwindowed STATS fixture above (7/10/1)
    // — header and table must agree by construction.
    const stats = screen.getByTestId('hunt-stats-line');
    expect(within(stats).getByText('1')).toBeTruthy();
    expect(within(stats).getByText('4')).toBeTruthy();
    expect(within(stats).getByText('0')).toBeTruthy();
    expect(stats.textContent).toMatch(/1 hunt.*4 findings.*0 in progress/);
    // The card band's own sub-labels survive as hover context, not as layout.
    expect(within(stats).getByTitle('threat findings')).toBeTruthy();
  });

  it('keeps no composer on the page', async () => {
    renderHunts();
    await screen.findByText(ROW.objective);
    expect(composer()).toBeNull();
    expect(screen.queryByText('Starters')).toBeNull();
  });

  it('opens the composer in a drawer from the New hunt button', async () => {
    renderHunts();
    await screen.findByText(ROW.objective);

    fireEvent.click(screen.getByRole('button', { name: 'New hunt' }));
    expect(await screen.findByRole('dialog')).toBeTruthy();
    expect(composer()).toBeTruthy();
    expect(screen.getByText('Starters')).toBeTruthy();
  });

  it('opens the composer from the address, and closing it takes the address back', async () => {
    renderHunts('/hunts?new=1');
    await screen.findByText(ROW.objective);
    expect(await screen.findByRole('dialog')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(composer()).toBeNull();
  });
});

// Below 1100px the objective was the only track with no floor, so it took the
// whole shortfall and the row read "Hunt for hosts b…" while Findings and
// Hosts held 100px and 90px for a single digit each. jsdom has no layout
// engine, so the grid template is the check: the objective has the floor and
// the two counters are the tracks that yield.
describe('Hunts list column widths', () => {
  const gridOf = (el: HTMLElement) => el.style.gridTemplateColumns;

  it('floors the objective at 260px and lets the counters shrink first', async () => {
    renderHunts();
    await screen.findByText(ROW.objective);
    const header = screen.getByText('Objective').parentElement as HTMLElement;
    const template = gridOf(header);
    expect(template).toContain('minmax(260px, 1fr)');
    // Findings and Hosts carry a floor well under their preferred width, so
    // they are the tracks the browser takes the shortfall from.
    expect(template).toMatch(/minmax\(52px, 100px\)/);
    expect(template).toMatch(/minmax\(48px, 90px\)/);
    // The row uses the same template as its header. They drifted once.
    const row = screen.getByText(ROW.objective).closest('.grid') as HTMLElement;
    expect(gridOf(row)).toBe(template);
  });

  // The mockup reads Objective, Started by, Findings, Hosts, Status, Started:
  // who asked comes before what it found, because the first question about a
  // row is whose question it answers.
  it('reads the columns in the order the mockup draws them', async () => {
    renderHunts();
    await screen.findByText(ROW.objective);
    const header = screen.getByText('Objective').parentElement as HTMLElement;
    const words = Array.from(header.children)
      .map((c) => c.textContent?.trim())
      .filter(Boolean);
    expect(words).toEqual(['Objective', 'Started by', 'Findings', 'Hosts', 'Status', 'Started']);
  });
});
