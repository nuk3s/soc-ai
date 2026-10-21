// The landing page is the Dashboard, and it states the flow (owner, 2026-10-07:
// "What is the user flow?"). Under the Needs you tile one sentence names the
// flow in the analyst's words, and the link opens the chart on the Hunts page.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue({ groups: [], truncated: false, other_docs: 0 }),
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  listInvestigations: vi.fn().mockResolvedValue({
    rows: [], total: 0, running: 0, truePositives: 0, totalAll: 0, active: false, limit: 100, offset: 0,
  }),
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getHealth: vi.fn().mockResolvedValue(null),
  getDetectionTuningSummary: vi.fn().mockResolvedValue(null),
  getMe: vi.fn().mockResolvedValue({ username: 'ana', role: 'analyst', status: '' }),
  getPreflight: vi.fn().mockResolvedValue({ status: 'green', failing: 0, warned: 0, checked_at: '2026-10-07T00:00:00+00:00' }),
  getPreflightDetail: vi.fn().mockResolvedValue({ rows: [], checked_at: '2026-10-07T00:00:00+00:00' }),
  getNeedsYouCount: vi.fn(),
}));

import { getNeedsYouCount } from '../lib/api';
import { OVERVIEW_FLOW } from '../lib/tooltips';
import { Dashboard } from './Dashboard';

const mount = () =>
  render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <Dashboard />
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getNeedsYouCount).mockReset().mockResolvedValue({
    leads_needing_decision: 2,
    unread_shadow_hits: 0,
    untriaged_groups: 0,
    needs_more_info: 0,
    pending_actions: 0,
    total: 2,
    unknown: [],
    alert_window: '7d',
    verdict_window: '30d',
    alert_floor: false,
  });
});

describe('the Dashboard', () => {
  // The header read "Overview" under a nav item and a top bar that both read
  // "Dashboard": two names for one page (dogfood 2026-10-19, R1 STE 3).
  it('names the page "Dashboard", as the nav does', async () => {
    mount();
    expect(await screen.findByRole('heading', { name: 'Dashboard' })).toBeTruthy();
    // Negative control: the second name is gone from the page header.
    expect(screen.queryByText('Overview')).toBeNull();
  });

  it('states the flow under the Needs you tile and links to the chart', async () => {
    mount();
    const tile = await screen.findByTestId('kpi-needs-you');
    const line = within(tile).getByTestId('needs-you-flow');
    expect(line.textContent).toBe(
      'soc-ai investigates alerts and runs hunts. You make each decision in Needs you. ' +
        'soc-ai sends your actions to Security Onion. How this flows',
    );
    expect(line.textContent).toContain(OVERVIEW_FLOW);
    expect(within(line).getByRole('link', { name: 'How this flows' }).getAttribute('href')).toBe(
      '/hunts?flow=1',
    );
  });

  // The tile read "…" and "Reading what needs you…" while the count loaded.
  // The console shows no ellipsis.
  it('shows no ellipsis while the count loads', async () => {
    vi.mocked(getNeedsYouCount).mockReturnValue(new Promise(() => {}));
    mount();
    const tile = await screen.findByTestId('kpi-needs-you');
    expect(tile.textContent).toContain('Reading what needs you');
    expect(tile.textContent).not.toMatch(/…|\.\.\./);
  });
});
