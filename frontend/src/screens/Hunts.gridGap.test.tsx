// The Hunts page names a grid gap inside the page window (2026-10-19).
//
// The range grid was down for 93 hours. After it came back, an empty hunt list
// read as a quiet week. The strip above the list names each recorded gap that
// overlaps the window, and it shows over the empty state too.
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DemoProvider } from '../lib/demo';
import type { GridGap } from '../lib/types';
import { absoluteTime } from '../lib/timeRange';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunts: vi.fn().mockResolvedValue([]),
  getHuntStats: vi.fn().mockResolvedValue([]),
  getHuntTemplates: vi.fn().mockResolvedValue([]),
  getHuntSchedules: vi.fn().mockResolvedValue({ schedules: [], masterSwitchEnabled: true }),
  getGridGaps: vi.fn(),
}));

import { getGridGaps } from '../lib/api';
import { Hunts } from './Hunts';

const GAP: GridGap = {
  id: 1,
  source: 'probe',
  plane: null,
  started_at: '2026-10-15T13:36:00Z',
  ended_at: null,
  open: true,
  duration_s: 333_540,
  detail: 'Elasticsearch did not answer the health probe.',
};

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

beforeEach(() => {
  vi.mocked(getGridGaps).mockReset().mockImplementation(async (window) => ({
    since: window.since,
    until: window.until ?? new Date().toISOString(),
    gaps: [GAP],
  }));
});

describe('the Hunts grid gap strip', () => {
  it('names the gap above an empty hunt list', async () => {
    renderHunts();
    expect((await screen.findByTestId('grid-gap')).textContent).toBe(
      `The grid is unreadable since ${absoluteTime('2026-10-15T13:36:00Z')} (93 h so far). Counts in this window are incomplete.`,
    );
    expect(await screen.findByText('No hunts yet')).toBeTruthy();
  });

  it('reads the gaps for the page window', async () => {
    renderHunts();
    await waitFor(() => expect(getGridGaps).toHaveBeenCalled());
    const since = new Date(vi.mocked(getGridGaps).mock.calls[0][0].since).getTime();
    expect(Math.abs(Date.now() - 7 * 86_400_000 - since)).toBeLessThan(60_000);
  });
});
