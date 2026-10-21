// The Overview names a grid gap inside the page window (2026-10-19).
//
// The range grid was down for 93 hours. After it came back, the Overview
// counted the hole as a quiet grid. The strip under the page header names each
// recorded gap that overlaps the window the time filter picks.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { GridGap } from '../lib/types';
import { absoluteTime } from '../lib/timeRange';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue({ groups: [], truncated: false, other_docs: 0 }),
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  listInvestigations: vi.fn(),
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getHealth: vi.fn().mockResolvedValue(null),
  getDetectionTuningSummary: vi.fn().mockResolvedValue(null),
  getMe: vi.fn().mockResolvedValue({ username: 'ana', role: 'analyst', status: '' }),
  getPreflight: vi.fn().mockResolvedValue({ status: 'green', failing: 0, warned: 0, checked_at: '2026-08-19T00:00:00+00:00' }),
  getPreflightDetail: vi.fn().mockResolvedValue({ rows: [], checked_at: '2026-08-19T00:00:00+00:00' }),
  getShadowHits: vi.fn().mockResolvedValue({ hits: [], unread: 0 }),
  getNeedsYouCount: vi.fn(),
  getGridGaps: vi.fn(),
}));

import { getGridGaps, getNeedsYouCount, listInvestigations } from '../lib/api';
import { Dashboard } from './Dashboard';

const GAP: GridGap = {
  id: 1,
  source: 'probe',
  plane: null,
  started_at: '2026-10-15T13:36:00Z',
  ended_at: '2026-10-19T10:15:00Z',
  open: false,
  duration_s: 333_540,
  detail: 'Elasticsearch did not answer the health probe.',
};

const NEEDS = {
  leads_needing_decision: 0,
  unread_shadow_hits: 0,
  untriaged_groups: 0,
  needs_more_info: 0,
  pending_actions: 0,
  total: 0,
  unknown: [],
  alert_window: '7d',
  verdict_window: '30d',
  alert_floor: false,
};

const mount = () =>
  render(
    <MemoryRouter initialEntries={['/']}>
      <Dashboard />
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getNeedsYouCount).mockResolvedValue(NEEDS);
  vi.mocked(listInvestigations).mockReset().mockImplementation(
    async () =>
      ({
        rows: [],
        total: 0,
        running: 0,
        truePositives: 0,
        totalAll: 0,
        active: false,
        limit: 100,
        offset: 0,
      }) as never,
  );
  vi.mocked(getGridGaps).mockReset().mockImplementation(async () => {
    const now = Date.now();
    return {
      since: new Date(now - 86_400_000).toISOString(),
      until: new Date(now).toISOString(),
      gaps: [GAP],
    };
  });
});

describe('the Overview grid gap strip', () => {
  it('names the gap under the page header', async () => {
    mount();
    expect((await screen.findByTestId('grid-gap')).textContent).toBe(
      `The grid was unreadable from ${absoluteTime('2026-10-15T13:36:00Z')} to ${absoluteTime('2026-10-19T10:15:00Z')} (93 h). Counts in this window are incomplete.`,
    );
  });

  it('reads the gaps for the window the time filter picks', async () => {
    mount();
    await screen.findByTestId('grid-gap-strip');
    const first = new Date(vi.mocked(getGridGaps).mock.calls[0][0].since).getTime();
    expect(Math.abs(Date.now() - 86_400_000 - first)).toBeLessThan(60_000);

    fireEvent.click(screen.getByText('7d'));
    await waitFor(() => expect(getGridGaps).toHaveBeenCalledTimes(2));
    const second = new Date(vi.mocked(getGridGaps).mock.calls[1][0].since).getTime();
    expect(Math.abs(Date.now() - 7 * 86_400_000 - second)).toBeLessThan(60_000);
  });
});
