// Dogfood (scheduled-hunts-discoverability): a schedule created in the Hunt
// Console shows a green "on" pill even when the `hunt_schedules_enabled`
// global master switch (Config → Triage automation) is off — it reads as
// active but will never fire. GET /hunt-schedules now returns
// `masterSwitchEnabled` alongside the rows so the panel can render an honest
// state: a persistent banner with a real deep-link into Config, and a muted
// "on (paused)" pill instead of the plain accent "on".
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
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

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunts: vi.fn().mockResolvedValue([]),
  getHuntStats: vi.fn().mockResolvedValue([]),
  getHuntTemplates: vi.fn().mockResolvedValue([]),
  getHuntSchedules: getHuntSchedulesMock,
  createHuntSchedule: createHuntScheduleMock,
  updateHuntSchedule: updateHuntScheduleMock,
  deleteHuntSchedule: deleteHuntScheduleMock,
}));

import { Hunts } from './Hunts';

function renderHunts(demo = false) {
  return render(
    <MemoryRouter initialEntries={['/hunts']}>
      <DemoProvider demo={demo}>
        <Routes>
          <Route path="/hunts" element={<Hunts />} />
          <Route path="/config" element={<div>CONFIG SCREEN</div>} />
        </Routes>
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

    await screen.findByText('No scheduled hunts yet — add one below.');
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
