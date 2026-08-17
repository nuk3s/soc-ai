// Hunts read as the odd one out of the four list screens (dogfood, 2026-08-12):
// it used the same shared ListToolbar as Alerts, Investigations and Hosts, but
// landed it ~495px down the page behind a three-card KPI band and a full-height
// composer, where the other three land theirs at y=133. The family resemblance
// only appeared once you scrolled — "a console with a list attached rather than
// a list screen".
//
// The fix keeps the console (the composer IS this screen's primary action) but
// gives it the family's anatomy: header line → compact composer → list section
// headed by the toolbar. These tests pin the ANATOMY — DOM order and the two
// shapes that cost the pixels (a KPI band that is one line, and a composer that
// is one row until you write in it) — because a pixel offset is not something
// jsdom can measure.
import { fireEvent, render, screen, within } from '@testing-library/react';
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
}));

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

function renderHunts() {
  getHuntsMock.mockResolvedValue([ROW]);
  getHuntStatsMock.mockResolvedValue(STATS);
  getHuntTemplatesMock.mockResolvedValue([]);
  return render(
    <MemoryRouter initialEntries={['/hunts']}>
      <DemoProvider demo={false}>
        <Routes>
          <Route path="/hunts" element={<Hunts />} />
        </Routes>
      </DemoProvider>
    </MemoryRouter>,
  );
}

const follows = (a: Element, b: Element) =>
  Boolean(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);

const composer = () => screen.getByPlaceholderText(/hunt for beaconing to rare external IPs/i);

describe('Hunts list-screen anatomy', () => {
  it('heads the list section with the shared toolbar, below the composer', async () => {
    renderHunts();
    await screen.findByText(ROW.objective);

    const stats = screen.getByTestId('hunt-stats-line');
    const objectiveHeader = screen.getByText('Objective');
    const page = stats.parentElement!.parentElement!;
    // The toolbar's own band: walk up from its chip row to the page's child.
    let toolbar = screen.getByTestId('list-toolbar-views') as HTMLElement;
    while (toolbar.parentElement && toolbar.parentElement !== page) {
      toolbar = toolbar.parentElement;
    }

    // header line → composer → toolbar → table: the family's order, and the
    // toolbar is the list section's top edge (nothing of the list precedes it).
    expect(follows(stats, composer())).toBe(true);
    expect(follows(composer(), toolbar)).toBe(true);
    expect(follows(toolbar, objectiveHeader)).toBe(true);

    // Order alone is not the contract — the toolbar was never out of order; it
    // was ~360px down because of what sat above it. So pin the COUNT: exactly
    // two bands precede the toolbar, the header and the composer. Re-add a KPI
    // card band (or any other Panel) above the list and this fails, which the
    // order assertions above would not.
    const bands = Array.from(page.children) as HTMLElement[];
    const above = bands.slice(0, bands.indexOf(toolbar));
    expect(above).toHaveLength(2);
    expect(above[0].contains(stats)).toBe(true);
    expect(above[1].contains(composer())).toBe(true);
  });

  it('states the KPI figures on one header line instead of a card band', async () => {
    renderHunts();
    await screen.findByText(ROW.objective);

    // One node carries all three figures — three cards cannot satisfy this.
    const stats = screen.getByTestId('hunt-stats-line');
    expect(within(stats).getByText('7')).toBeTruthy();
    expect(within(stats).getByText('10')).toBeTruthy();
    expect(within(stats).getByText('1')).toBeTruthy();
    expect(stats.textContent).toMatch(/7 hunts.*10 findings.*1 in progress/);
    // The card band's own sub-labels survive as hover context, not as layout.
    expect(within(stats).getByTitle('surfaced')).toBeTruthy();
  });

  it('keeps the composer one row until it is being written in', async () => {
    renderHunts();
    await screen.findByText(ROW.objective);

    const box = composer() as HTMLTextAreaElement;
    expect(Number(box.rows)).toBe(1);

    fireEvent.focus(box);
    expect(Number(box.rows)).toBeGreaterThan(1);
    expect(screen.getByText(/Shift\+Enter for a new line/i)).toBeTruthy();

    // Text keeps it open after the focus goes away — a written brief is never
    // collapsed out from under the analyst.
    fireEvent.change(box, { target: { value: 'hunt for lateral movement' } });
    fireEvent.blur(box);
    expect(Number(box.rows)).toBeGreaterThan(1);
  });

  it('forgets a dragged height when it collapses', async () => {
    // The box was `resize-y`, and an inline height beats `rows`: one drag of the
    // grip pinned the composer tall for the rest of the page's life, so the
    // toolbar sat LOWER than the 362px this batch was opened to fix. The drag is
    // a habit the old always-4-row box taught, so it will happen.
    renderHunts();
    await screen.findByText(ROW.objective);

    const box = composer() as HTMLTextAreaElement;
    fireEvent.focus(box);
    box.style.height = '220px'; // what the browser writes when you drag the grip

    fireEvent.blur(box);
    expect(Number(box.rows)).toBe(1);
    expect(box.style.height).toBe('');
    // ...and no grip to drag while it is one row.
    expect(box.className).toContain('resize-none');
  });
});
