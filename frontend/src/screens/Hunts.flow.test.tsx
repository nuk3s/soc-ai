// "How this flows" on the Hunts page.
//
// The page reads as the pipeline and never drew it. The link in the header and
// the link at the end of every definition line open one drawer with the chart.
// The address carries the drawer, the way `?new=1` carries the composer: a
// reload keeps it open, closing takes the parameter out, and a tab change
// clears it with the rest of the tab's filters.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
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

import { ShellProvider } from '../shell/ShellContext';
import { Hunts } from './Hunts';

/** The address bar, so a test can read what the link and the Close wrote. */
function LocationProbe() {
  const l = useLocation();
  return <div data-testid="loc">{l.pathname + l.search}</div>;
}

function renderHunts(path = '/hunts') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <DemoProvider demo={false}>
        <ShellProvider>
          <Routes>
            <Route path="/hunts" element={<Hunts />} />
          </Routes>
          <LocationProbe />
        </ShellProvider>
      </DemoProvider>
    </MemoryRouter>,
  );
}

const chart = () => screen.queryByTestId('hunting-flow-chart');
const address = () => screen.getByTestId('loc').textContent;

describe('How this flows', () => {
  it('opens the chart from the address', async () => {
    renderHunts('/hunts?flow=1');
    expect(await screen.findByTestId('hunting-flow-chart')).toBeTruthy();
  });

  it('keeps the drawer shut on the plain address', async () => {
    renderHunts();
    await screen.findByTestId('define-hunt');
    expect(chart()).toBeNull();
  });

  it('opens from the link in the Hunt Console header', async () => {
    renderHunts();
    const header = await screen.findByTestId('hunt-stats-line');
    fireEvent.click(within(header).getByRole('link', { name: 'How this flows' }));
    expect(await screen.findByTestId('hunting-flow-chart')).toBeTruthy();
    expect(address()).toBe('/hunts?flow=1');
  });

  it('carries the link at the end of every definition line', async () => {
    renderHunts();
    for (const thing of ['hit', 'lead', 'hunt', 'schedule']) {
      const line = await screen.findByTestId(`define-${thing}`);
      expect(within(line).getByRole('link', { name: 'How this flows' })).toBeTruthy();
    }
  });

  it('takes the parameter out when the drawer closes', async () => {
    renderHunts('/hunts?flow=1&hits=unread');
    await screen.findByTestId('hunting-flow-chart');
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(chart()).toBeNull());
    // The filter the address already carried stays. Only the drawer leaves.
    expect(address()).toBe('/hunts?hits=unread');
  });

  it('clears the parameter on a tab change', async () => {
    renderHunts('/hunts?flow=1');
    await screen.findByTestId('hunting-flow-chart');
    fireEvent.click(screen.getByRole('button', { name: /^Analytics/ }));
    await waitFor(() => expect(chart()).toBeNull());
    expect(address()).toBe('/hunts?tab=analytics');
  });
});
