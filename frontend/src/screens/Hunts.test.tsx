// Dogfood (scheduled-hunts-discoverability): a schedule created in the Hunt
// Console shows a green "on" pill even when the `hunt_schedules_enabled`
// global master switch (Config → Triage automation) is off — it reads as
// active but will never fire. GET /hunt-schedules now returns
// `masterSwitchEnabled` alongside the rows so the panel can render an honest
// state: a persistent banner with a real deep-link into Config, and a muted
// "on (paused)" pill instead of the plain accent "on".
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

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

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunts: vi.fn().mockResolvedValue([]),
  getHuntStats: vi.fn().mockResolvedValue([]),
  getHuntTemplates: vi.fn().mockResolvedValue([]),
  getHuntSchedules: getHuntSchedulesMock,
}));

import { Hunts } from './Hunts';

function renderHunts() {
  return render(
    <MemoryRouter initialEntries={['/hunts']}>
      <Routes>
        <Route path="/hunts" element={<Hunts />} />
        <Route path="/config" element={<div>CONFIG SCREEN</div>} />
      </Routes>
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
