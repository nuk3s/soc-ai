// Prod, 2026-11-03: the daily hunt ran 36 model responses with no reasoning
// trace and wrote 3 false threat findings. Its row on the Hunts list read like
// every other row. A hunt that completed in a degraded state wears a mark on
// the row, in the word of the hunt page.
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

const NOTE =
  'The model returned no reasoning trace in this hunt. Earlier hunts carried one. ' +
  'Check each finding against its evidence.';

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

describe('Hunts list degraded mark', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getHuntSchedulesMock.mockResolvedValue({ schedules: [], masterSwitchEnabled: true });
  });

  it('marks the row of a degraded hunt and no other row', async () => {
    vi.mocked(getHunts).mockResolvedValue([
      row('H-WEAK', { degraded: 'no_reasoning_trace', degradedNote: NOTE }),
      row('H-FINE', { degraded: null, degradedNote: null }),
      row('H-OLD', {}),
    ]);
    renderHunts();
    const chip = await screen.findByTestId('hunt-degraded-H-WEAK');
    expect(chip.textContent).toBe('Degraded');
    expect(chip.getAttribute('title')).toBe(NOTE);
    expect(screen.queryByTestId('hunt-degraded-H-FINE')).toBeNull();
    expect(screen.queryByTestId('hunt-degraded-H-OLD')).toBeNull();
  });
});
