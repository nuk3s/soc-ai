// The Dashboard page tour points at real elements (tours/content.ts).
//
// The screen renders with data: one alert group, one recent investigation and
// one grid gap inside the page window. Every anchor the tour names must then
// be on the page, so a renamed or removed `data-tour` attribute fails here.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { AlertGroup, GridGap, InvestigationList, InvestigationRow } from '../lib/types';

const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn(),
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  listInvestigations: vi.fn(),
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getHealth: vi.fn().mockResolvedValue(null),
  getDetectionTuningSummary: vi.fn().mockResolvedValue(null),
  getMe: vi.fn().mockResolvedValue({ username: 'ana', role: 'analyst', status: '' }),
  getPreflight: vi.fn(),
  getPreflightDetail: vi.fn(),
  getShadowHits: vi.fn().mockResolvedValue({ hits: [], unread: 0 }),
  getNeedsYouCount: vi.fn().mockResolvedValue({
    leads_needing_decision: 2,
    unread_shadow_hits: 0,
    untriaged_groups: 1,
    needs_more_info: 0,
    pending_actions: 0,
    total: 3,
    unknown: [],
    alert_window: '7d',
    verdict_window: '30d',
    alert_floor: false,
  }),
  getGridGaps: vi.fn(),
}));

import { getAlerts, getGridGaps, getPreflight, getPreflightDetail, listInvestigations } from '../lib/api';
import { DASHBOARD_TOUR } from '../tours/content';
import { missingAnchors } from '../tours/testing';
import { Dashboard } from './Dashboard';

const GROUP: AlertGroup = {
  id: 'g-1',
  name: 'ET SCAN Example inbound scan',
  kind: 'suricata',
  sev: 'high',
  count: 4,
  verdict: 'false_positive',
  conf: 0.8,
  latest: '2m ago',
  inherited: false,
  events: [],
};

const RUN: InvestigationRow = {
  id: 'run-1',
  name: 'ET SCAN Example inbound scan',
  kind: 'suricata',
  verdict: 'false_positive',
  conf: 0.9,
  host: '192.0.2.10',
  dst: '198.51.100.7',
  status: 'complete',
  when: '1h ago',
  ts: iso(HOUR),
  alertId: 'ev-1',
  isPrimary: true,
  fallback: false,
};

const PAGE: InvestigationList = {
  rows: [RUN],
  total: 1,
  running: 0,
  truePositives: 0,
  totalAll: 1,
  active: false,
  limit: 50,
  offset: 0,
};

describe('the Dashboard page tour', () => {
  it('finds every anchor it names', async () => {
    vi.mocked(getAlerts).mockResolvedValue({ groups: [GROUP], truncated: false, other_docs: 0 });
    vi.mocked(listInvestigations).mockResolvedValue(PAGE);
    vi.mocked(getPreflight).mockResolvedValue({ status: 'green', failing: 0, warned: 0, checked_at: iso(0) });
    vi.mocked(getPreflightDetail).mockResolvedValue({ rows: [], checked_at: iso(0) });
    // A closed gap inside the default 24 hour window.
    const gap: GridGap = {
      id: 1,
      source: 'probe',
      plane: null,
      started_at: iso(6 * HOUR),
      ended_at: iso(2 * HOUR),
      open: false,
      duration_s: 4 * 3_600,
      detail: 'Elasticsearch did not answer the health probe.',
    };
    vi.mocked(getGridGaps).mockImplementation(async () => ({
      since: iso(24 * HOUR),
      until: iso(0),
      gaps: [gap],
    }));

    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <Dashboard />
      </MemoryRouter>,
    );
    await screen.findByTestId('grid-gap-strip');
    await screen.findByTestId('recent-investigation');
    await screen.findByText('All checks pass.');

    expect(missingAnchors(DASHBOARD_TOUR)).toEqual([]);
  });
});
