// The rule part of the one needs-you count (round 3, RC1). The rules with open
// false positives are one part of the count, and the Dashboard tile, the bell
// and the sidebar state the same sum. The line of the tile and of the bell
// reads "N rules wait on your decision" and opens the Needs you page with the
// filter Rules.
import { act, render, screen, waitFor, within } from '@testing-library/react';
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
  decisions: 4,
  review: 1,
  investigations_waiting: 2,
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

const WITH_RULES: NeedsYouCount = {
  ...ONE_OF_EACH,
  rules_waiting: 3,
  decisions: 7,
  total: 8,
};

beforeEach(() => {
  localStorage.clear();
  vi.mocked(getNeedsYouCount).mockReset();
  vi.mocked(getNotifications).mockResolvedValue([]);
});

describe('The rule part of the one needs-you count', () => {
  it('states the rule line on the tile and in the bell, and the sum on every surface', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue(WITH_RULES);
    mount();
    await waitFor(() => expect(screen.getByTestId('needs-you-total').textContent).toBe('7'));
    const line = await screen.findByTestId('needs-you-line-rules');
    expect(line.textContent).toBe('3 rules wait on your decision · at any age');
    expect(within(line).getByRole('link')).toHaveAttribute('href', '/needs-you?type=rule');
    // The lines add up to the number above them.
    const lines = within(screen.getByTestId('kpi-needs-you')).getAllByRole('listitem');
    expect(lines.reduce((sum, l) => sum + Number(l.textContent!.split(' ')[0]), 0)).toBe(7);
    // The rule line sits after the leads and before the alert groups.
    const keys = lines.map((l) => l.dataset.testid);
    expect(keys.indexOf('needs-you-line-rules')).toBe(keys.indexOf('needs-you-line-leads') + 1);
    expect(keys.indexOf('needs-you-line-alerts')).toBe(keys.indexOf('needs-you-line-rules') + 1);
    // The sidebar total states the same sum.
    expect(badge('sidebar-needs-you-total')).toBe(7);
    // The bell: the badge and the line.
    await waitFor(() => expect(screen.getByTestId('notif-badge').textContent).toBe('7'));
    act(() => screen.getByRole('button', { name: /^Notifications/ }).click());
    const part = await screen.findByTestId('needs-you-part-rules_waiting');
    expect(part.textContent).toBe('3 rules wait on your decision, at any age');
    expect(within(part).getByRole('link')).toHaveAttribute('href', '/needs-you?type=rule');
  });

  it('says one rule in the singular', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue({ ...WITH_RULES, rules_waiting: 1, decisions: 5 });
    mount();
    expect((await screen.findByTestId('needs-you-line-rules')).textContent).toBe(
      '1 rule waits on your decision · at any age',
    );
  });

  it('keeps the line of a rule part that the server could not count, and marks the count a floor', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue({
      ...WITH_RULES,
      rules_waiting: null,
      decisions: 4,
      unknown: ['rules_waiting'],
    });
    mount();
    expect((await screen.findByTestId('needs-you-line-rules')).textContent).toBe(
      'Could not count the rules with open false positives.',
    );
    await waitFor(() => expect(screen.getByTestId('needs-you-total').textContent).toBe('4+'));
  });

  // NEGATIVE CONTROL: an older server sends no rule part. No surface shows a
  // rule line, and the lines still add up to the count.
  it('shows no rule line for an older server', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue(ONE_OF_EACH);
    mount();
    await waitFor(() => expect(screen.getByTestId('needs-you-total').textContent).toBe('4'));
    expect(screen.queryByTestId('needs-you-line-rules')).toBeNull();
    const lines = within(screen.getByTestId('kpi-needs-you')).getAllByRole('listitem');
    expect(lines.reduce((sum, l) => sum + Number(l.textContent!.split(' ')[0]), 0)).toBe(4);
  });

  // NEGATIVE CONTROL: no rule waits. The line does not show.
  it('shows no rule line when no rule waits', async () => {
    vi.mocked(getNeedsYouCount).mockResolvedValue({ ...WITH_RULES, rules_waiting: 0, decisions: 4 });
    mount();
    await waitFor(() => expect(screen.getByTestId('needs-you-total').textContent).toBe('4'));
    expect(screen.queryByTestId('needs-you-line-rules')).toBeNull();
  });
});
