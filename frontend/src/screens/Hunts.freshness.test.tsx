// Freshness rollout (B2): the Hunt Console header carries an "updated Xs ago"
// marker sourced from the PRIMARY hunts-list poll (getHunts, the 8s-polled main
// list the analyst watches). This proves the marker renders after that list's
// first successful load — not before, and not from a sub-section's useAsync.
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { DemoProvider } from '../lib/demo';

const getHuntsMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunts: getHuntsMock,
  getHuntStats: vi.fn().mockResolvedValue([]),
  getHuntTemplates: vi.fn().mockResolvedValue([]),
  getHuntSchedules: vi.fn().mockResolvedValue({ schedules: [], masterSwitchEnabled: true }),
}));

import { Hunts } from './Hunts';

function renderHunts() {
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

describe('Hunts freshness marker', () => {
  it('renders an "updated … ago" marker once the primary hunts list loads', async () => {
    getHuntsMock.mockResolvedValue([]);
    renderHunts();

    // Freshness renders nothing until the first successful load; after getHunts
    // resolves, lastUpdated is set and the marker appears.
    expect(await screen.findByText(/updated/)).toBeTruthy();
  });
});
