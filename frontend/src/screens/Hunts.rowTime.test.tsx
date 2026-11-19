// Round 3 part 2, P1: the time of a Hunts row had a raw ISO time as its
// tooltip. A relative time states the UTC time and the local time with its
// zone in its tooltip.
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DemoProvider } from '../lib/demo';

const getHuntSchedulesMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunts: vi.fn().mockResolvedValue([]),
  getHuntStats: vi.fn().mockResolvedValue([]),
  getHuntTemplates: vi.fn().mockResolvedValue([]),
  getHuntSchedules: getHuntSchedulesMock,
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
import { Hunts } from './Hunts';


function row(id: string, over: Partial<HuntRow>): HuntRow {
  return {
    id,
    objective: `Daily hunt ${id}`,
    kind: 'scheduled',
    status: 'complete',
    findingCount: 6,
    threatFindingCount: 3,
    outcome: 'no_threat_confirmed',
    outcome_label: 'No threat confirmed',
    affectedHosts: 3,
    confidence: 0.7,
    startedBy: 'scheduler',
    starter: 'schedule',
    leadId: null,
    when: '1d',
    ts: '2026-11-03T18:38:51+00:00',
    chatCount: 0,
    ...over,
  } as HuntRow;
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

describe('Hunts row time', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
  });

  it('states the UTC time and the local time in the tooltip of the row time', async () => {
    vi.mocked(getHunts).mockResolvedValue([row('H-1', {}), row('H-2', { ts: '' })]);
    renderHunts();
    const when = await screen.findByTestId('hunt-when-H-1');
    expect(when.textContent).toBe('1d');
    const title = when.getAttribute('title') ?? '';
    expect(title).toMatch(/^2026-11-03 18:38 UTC\. Local time: 2026-11-0\d \d{2}:\d{2} \S+$/);
    expect(title).not.toContain('T18:38:51');
    // Negative control: a row with no time on record names no time.
    expect((await screen.findByTestId('hunt-when-H-2')).getAttribute('title')).toBeNull();
  });
});
