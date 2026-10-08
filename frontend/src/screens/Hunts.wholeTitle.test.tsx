// The owner: "Hunts have severely shortened titles that end in '...'. This
// makes reading them almost impossible." The list row cut the objective to one
// line, and the schedule row and the re-hunt result cut it with no hover at
// all. Each one now wraps to two lines, the browser cuts at the width, and the
// whole objective stays in a `title` attribute.
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DemoProvider } from '../lib/demo';

const getHuntSchedulesMock = vi.hoisted(() => vi.fn());
const rehuntHuntsMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunts: vi.fn().mockResolvedValue([]),
  getHuntStats: vi.fn().mockResolvedValue([]),
  getHuntTemplates: vi.fn().mockResolvedValue([]),
  getHuntSchedules: getHuntSchedulesMock,
  rehuntHunts: rehuntHuntsMock,
  listSavedViews: vi.fn().mockResolvedValue([]),
  getShadowHits: vi.fn().mockResolvedValue({ hits: [], unread: 0 }),
  getAnalytics: vi.fn().mockResolvedValue({ analytics: [], counts: {} }),
  getAnalytic: vi.fn(),
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

import { getHunts } from '../lib/api';
import type { HuntRow } from '../lib/types';
import { ShellProvider } from '../shell/ShellContext';
import { TITLE_180, bareCuts, showsWhole } from '../test/wholeTitle';
import { Hunts } from './Hunts';

const ROW = {
  id: 'H-LONG',
  objective: TITLE_180,
  kind: 'chat',
  status: 'complete',
  findingCount: 1,
  threatFindingCount: 1,
  outcome: 'threats',
  affectedHosts: 1,
  confidence: 0.8,
  startedBy: 'analyst',
  starter: 'analyst',
  leadId: null,
  when: '4m',
  ts: '2026-10-05T10:00:00+00:00',
  chatCount: 0,
} as HuntRow;

const SHORT = 'Hunt for lateral movement';

function schedule(id: number, objective: string) {
  return {
    id,
    objective,
    intervalMinutes: 1440,
    enabled: true,
    lastRunAt: null,
    createdBy: 'alice',
    createdAt: '2026-07-01T00:00:00+00:00',
  };
}

function renderHunts() {
  return render(
    <MemoryRouter initialEntries={['/hunts']}>
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

describe('Hunts list keeps the whole hunt title', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
  });

  it('wraps a 180 character objective whole in its cell and holds it on the hover', async () => {
    vi.mocked(getHunts).mockResolvedValue([ROW]);
    renderHunts();
    const link = await screen.findByTestId('hunt-row-objective');
    expect(TITLE_180).toHaveLength(180);
    expect(link.textContent).toBe(TITLE_180);
    expect(link.getAttribute('title')).toBe(TITLE_180);
    // The objective wraps whole. A one-line `truncate` hid the hunt, and a
    // two-line clamp hid the rest of it (owner, 2026-10-07).
    expect(link.className).toContain('break-words');
    expect(link.className).not.toMatch(/\btruncate\b|line-clamp/);
    expect(link.parentElement?.className ?? '').not.toMatch(/\btruncate\b/);
    expect(showsWhole(document.body, TITLE_180)).toBe(true);
    expect(bareCuts(document.body, TITLE_180)).toEqual([]);
  });

  it('renders a short objective unchanged', async () => {
    vi.mocked(getHunts).mockResolvedValue([{ ...ROW, id: 'H-SHORT', objective: SHORT }]);
    renderHunts();
    const link = await screen.findByTestId('hunt-row-objective');
    expect(link.textContent).toBe(SHORT);
    expect(link.getAttribute('title')).toBe(SHORT);
  });

  it('holds a long schedule objective whole on the hover', async () => {
    getHuntSchedulesMock.mockResolvedValue({
      schedules: [schedule(7, TITLE_180), schedule(8, 'Nightly beacon sweep')],
      masterSwitchEnabled: true,
    });
    renderHunts();
    const cell = await screen.findByTestId('schedule-objective-7');
    expect(cell.textContent).toBe(TITLE_180);
    // The cell had no title attribute, so a cut objective was cut for good.
    expect(cell.getAttribute('title')).toBe(TITLE_180);
    // The objective shows whole and wraps. A clamp hid the rest of it.
    expect(cell.className).toContain('break-words');
    expect(cell.className).not.toMatch(/\btruncate\b|line-clamp/);
    expect(bareCuts(document.body, TITLE_180)).toEqual([]);
    // Negative control: a short schedule objective renders unchanged.
    expect(screen.getByTestId('schedule-objective-8').textContent).toBe('Nightly beacon sweep');
  });

  it('holds a re-run objective whole on the hover in the bulk re-hunt result', async () => {
    vi.mocked(getHunts).mockResolvedValue([ROW]);
    rehuntHuntsMock.mockResolvedValue({
      started: [{ old_id: 'H-LONG', new_id: 'H-NEW', objective: TITLE_180 }],
      skipped: [],
    });
    renderHunts();
    await screen.findByTestId('hunt-row-objective');
    const boxes = screen.getAllByRole('checkbox');
    fireEvent.click(boxes[boxes.length - 1]);
    const strip = await screen.findByTestId('list-toolbar-selection');
    fireEvent.click(within(strip).getByText(/Re-hunt selected \(1\)/));
    fireEvent.click(await screen.findByText('Show detail'));
    const line = await screen.findByTestId('rehunt-objective-H-NEW');
    expect(line.textContent).toBe(TITLE_180);
    expect(line.getAttribute('title')).toBe(TITLE_180);
    expect(line.className).not.toMatch(/\btruncate\b/);
    expect(bareCuts(document.body, TITLE_180)).toEqual([]);
  });
});
