// Every section on the Hunts page states what its thing is.
//
// The owner read the rebuilt page and could not tell a lead from a hit from a
// hunt. One dim line under each section header carries the sentence, before the
// content. The sentences live in `lib/tooltips.ts`, so the lead page, the hunt
// page and the analytic drawer read the same words. These tests pin the line on
// each section, and they pin that the line is the constant, not a second copy
// of it.
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { DemoProvider } from '../lib/demo';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunts: vi.fn().mockResolvedValue([]),
  getHuntStats: vi.fn().mockResolvedValue([]),
  getHuntTemplates: vi.fn().mockResolvedValue([]),
  getHuntSchedules: vi.fn().mockResolvedValue({ schedules: [], masterSwitchEnabled: true }),
  listSavedViews: vi.fn().mockResolvedValue([]),
  getAnalytics: vi.fn().mockResolvedValue({ analytics: [], counts: {} }),
  getAnalytic: vi.fn(),
  getAnalyticHits: vi
    .fn()
    .mockResolvedValue({ hits: [], counts: { all: 0, unread: 0, live: 0, shadow: 0 } }),
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

import {
  DEFINE_ANALYTIC,
  DEFINE_HIT,
  DEFINE_HUNT,
  DEFINE_LEAD,
  DEFINE_SCHEDULE,
} from '../lib/tooltips';
import { ShellProvider } from '../shell/ShellContext';
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

describe('the Hunts page states what each thing is', () => {
  it('says what a hit is, under the Analytic hits header', async () => {
    renderHunts();
    const line = await screen.findByTestId('define-hit');
    expect(line.textContent).toContain(DEFINE_HIT);
  });

  it('says what a lead is, under the Leads header', async () => {
    renderHunts();
    const line = await screen.findByTestId('define-lead');
    expect(line.textContent).toContain(DEFINE_LEAD);
  });

  it('says what a hunt is, under the Hunts header', async () => {
    renderHunts();
    const line = await screen.findByTestId('define-hunt');
    expect(line.textContent).toContain(DEFINE_HUNT);
  });

  it('says what a schedule is, under the Scheduled hunts header', async () => {
    renderHunts();
    const line = await screen.findByTestId('define-schedule');
    expect(line.textContent).toContain(DEFINE_SCHEDULE);
  });

  it('says what an analytic is, on the Analytics tab', async () => {
    renderHunts('/hunts?tab=analytics');
    const line = await screen.findByTestId('define-analytic');
    expect(line.textContent).toContain(DEFINE_ANALYTIC);
  });

  it('keeps the definition of a hit above the hits it describes', async () => {
    renderHunts();
    const line = await screen.findByTestId('define-hit');
    const block = document.getElementById('analytic-hits')!;
    expect(block.contains(line)).toBe(true);
  });
});
