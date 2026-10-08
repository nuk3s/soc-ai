// The landing page is the Overview, and it states the flow (owner, 2026-10-07:
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

describe('the Overview', () => {
  it('names the page "Overview"', async () => {
    mount();
    expect(await screen.findByText('Overview')).toBeTruthy();
    // Negative control: the old title is gone from the page header.
    expect(screen.queryByText('Dashboard')).toBeNull();
  });

  it('states the flow under the Needs you tile and links to the chart', async () => {
    mount();
    const tile = await screen.findByTestId('kpi-needs-you');
    const line = within(tile).getByTestId('needs-you-flow');
    expect(line.textContent).toBe(
      'Alerts and sweeps come in. soc-ai triages, hunts, and investigates what the hunts find. ' +
        'You decide in Needs you. Your actions go to Security Onion. How this flows',
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
