// One "Needs you" count everywhere (dogfood 2026-10-06). The landing page said
// "queue clear" while 11 leads waited, the bell said "None need attention", and
// only the Hunts badge knew. The Dashboard tile, the sidebar badges and the bell
// now read one provider. This test seeds one item of each part and reads the
// same total on all three surfaces.
import { act, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getNeedsYouCount: vi.fn(),
  // The shell.
  getMe: vi.fn().mockResolvedValue({ username: 'ana', role: 'analyst', status: '' }),
  getAbout: vi.fn().mockResolvedValue({
    version: '1.5.2',
    repo_url: 'https://github.com/nuk3s/soc-ai',
    license: 'Apache-2.0',
    update_check_enabled: false,
  }),
  getWorkspaces: vi.fn().mockResolvedValue([]),
  getNotifications: vi.fn(),
  getHealth: vi.fn().mockResolvedValue({
    es: { ok: true, detail: 'ok' },
    llm: { ok: true, detail: 'ok' },
    so: { ok: true, detail: 'ok' },
    pcap: null,
  }),
  // The Dashboard.
  getAlerts: vi.fn().mockResolvedValue({ groups: [], truncated: false, other_docs: 0 }),
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  listInvestigations: vi.fn().mockResolvedValue({
    rows: [], total: 0, running: 0, truePositives: 0, totalAll: 0, active: false, limit: 100, offset: 0,
  }),
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getDetectionTuningSummary: vi.fn().mockResolvedValue(null),
  getPreflight: vi.fn().mockResolvedValue({ status: 'green', failing: 0, warned: 0, checked_at: '2026-10-06T00:00:00+00:00' }),
  getPreflightDetail: vi.fn().mockResolvedValue({ rows: [], checked_at: '2026-10-06T00:00:00+00:00' }),
  getShadowHits: vi.fn().mockResolvedValue({ hits: [], unread: 1 }),
}));

import { getNeedsYouCount, getNotifications, type NeedsYouCount } from '../lib/api';
import { NeedsYouProvider } from '../lib/needsYou';
import { Dashboard } from '../screens/Dashboard';
import { ShellProvider } from './ShellContext';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';

/** One item of each part, as GET /needs-you answers it. */
const ONE_OF_EACH: NeedsYouCount = {
  leads_needing_decision: 1,
  unread_shadow_hits: 1,
  untriaged_groups: 1,
  needs_more_info: 1,
  pending_actions: 1,
  total: 5,
  unknown: [],
  alert_window: '7d',
  verdict_window: '30d',
  alert_floor: false,
};

function mount() {
  return render(
    <MemoryRouter initialEntries={['/dashboard']}>
      <ShellProvider>
        <NeedsYouProvider enabled>
          <Sidebar />
          <Topbar />
          <Dashboard />
        </NeedsYouProvider>
      </ShellProvider>
    </MemoryRouter>,
  );
}

const badge = (testId: string) => Number(screen.getByTestId(testId).textContent);

beforeEach(() => {
  localStorage.clear();
  vi.mocked(getNeedsYouCount).mockReset();
  vi.mocked(getNotifications).mockResolvedValue([
    { id: 'lead:18', tone: 'warn', title: 'Lead 18 formed on host-a: rare process', when: '3d', href: '/leads/18' },
    { id: 'shadow-hit:4', tone: 'warn', title: 'Shadow hit: rare logon on host-a', when: '1h', href: '/hunts?hits=unread' },
    { id: 'hunt-done:7', tone: 'accent', title: 'Hunt finished: no threat found. Sweep', when: '2h', href: '/hunts/7' },
  ]);
});

describe('One needs-you count on the tile, the badges and the bell', () => {
  it('reads the same total on all three surfaces', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue(ONE_OF_EACH);
    mount();

    // The tile: the total and one line per part.
    await waitFor(() => expect(screen.getByTestId('needs-you-total').textContent).toBe('5'));
    for (const key of ['leads', 'hits', 'alerts', 'nmi', 'actions']) {
      expect(screen.getByTestId(`needs-you-line-${key}`)).toBeTruthy();
    }
    expect(screen.getByTestId('kpi-needs-you').textContent).not.toContain('Nothing needs you');

    // The badges: Alerts 1, Investigations 2, Hunts 2. They add up to the tile.
    const sidebarTotal =
      badge('sidebar-needs-you-alerts') +
      badge('sidebar-needs-you-investigations') +
      badge('sidebar-needs-you');
    expect(sidebarTotal).toBe(5);
    expect(badge('sidebar-needs-you-investigations')).toBe(2);

    // The bell: the badge and the header state the same total.
    await waitFor(() => expect(screen.getByTestId('notif-badge').textContent).toBe('5'));
    act(() => screen.getByRole('button', { name: /^Notifications/ }).click());
    expect(screen.getByTestId('notif-summary').textContent).toBe('5 need you · 1 notification');

    // One read feeds all three. Three surfaces polling apart could each catch
    // a different moment.
    expect(getNeedsYouCount).toHaveBeenCalledTimes(1);
  });

  // NEGATIVE CONTROL. With nothing waiting, no surface claims work and no
  // surface hides that the read happened.
  it('says nothing needs you on every surface when every part is zero', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue({
      ...ONE_OF_EACH,
      leads_needing_decision: 0,
      unread_shadow_hits: 0,
      untriaged_groups: 0,
      needs_more_info: 0,
      pending_actions: 0,
      total: 0,
    });
    vi.mocked(getNotifications).mockResolvedValue([]);
    mount();
    await waitFor(() => expect(screen.getByTestId('needs-you-total').textContent).toBe('0'));
    expect(screen.getByTestId('kpi-needs-you').textContent).toContain('Nothing needs you.');
    expect(screen.queryByTestId('sidebar-needs-you')).toBeNull();
    expect(screen.queryByTestId('sidebar-needs-you-alerts')).toBeNull();
    expect(screen.queryByTestId('sidebar-needs-you-investigations')).toBeNull();
    expect(screen.queryByTestId('notif-badge')).toBeNull();
  });
});
