// The Hunts page tour: every anchor the tour names is on the page with data.
//
// The grid gap strip shows only when a gap falls in the page window, so the
// ledger holds one open gap that started six hours ago.
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { DemoProvider } from '../lib/demo';
import type { GridGap, HuntRow, HuntStat } from '../lib/types';

const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const ROW: HuntRow = {
  id: 'H1',
  objective: 'Hunt for hosts beaconing to rare external IPs',
  kind: 'chat',
  status: 'complete',
  findingCount: 2,
  affectedHosts: 1,
  confidence: 0.7,
  startedBy: 'analyst',
  when: '2h',
  ts: iso(2 * HOUR),
  chatCount: 0,
};

const STATS: HuntStat[] = [
  { label: 'Hunts', value: '1', sub: 'recent', tone: 'accent' },
  { label: 'Findings', value: '2', sub: 'surfaced', tone: 'warn' },
  { label: 'In progress', value: '0', sub: 'running now', tone: 'sigma' },
];

const GAP: GridGap = {
  id: 1,
  source: 'probe',
  plane: null,
  started_at: iso(6 * HOUR),
  ended_at: null,
  open: true,
  duration_s: 6 * 3_600,
  detail: 'Elasticsearch did not answer the health probe.',
};

const LEAD = {
  id: 7,
  status: 'open',
  formed_at: iso(3 * HOUR),
  updated_at: iso(3 * HOUR),
  entities: [['host', '192.0.2.10']],
  kinds: ['novel_destination', 'off_hours'],
  weight_at_formation: 0.9,
  scope_count: 1,
  hunt_id: null,
  shadow: false,
  single_signal: false,
  observations: [],
  hunt_queued: false,
};

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunts: vi.fn(async () => [ROW]),
  getHuntStats: vi.fn(async () => STATS),
  getHuntTemplates: vi.fn().mockResolvedValue([]),
  getHuntSchedules: vi.fn().mockResolvedValue({ schedules: [], masterSwitchEnabled: true }),
  getShadowHits: vi.fn().mockResolvedValue({ hits: [], unread: 0 }),
  getAnalytics: vi.fn().mockResolvedValue({ analytics: [], counts: {} }),
  getAnalyticHits: vi.fn().mockResolvedValue({
    hits: [],
    counts: { all: 0, unread: 0, live: 0, shadow: 0 },
  }),
  getNeedsYou: vi
    .fn()
    .mockResolvedValue({ unread_shadow_hits: 0, leads_needing_decision: 1, total: 1 }),
  getLeads: vi.fn(async () => [LEAD]),
  getLeadCount: vi.fn(async (status = 'needs_decision') => ({ status, entity: null, total: 1 })),
  getGridGaps: vi.fn(async (window: { since: string; until?: string }) => ({
    since: window.since,
    until: window.until ?? new Date().toISOString(),
    gaps: [GAP],
  })),
}));

import { HUNTS_TOUR } from '../tours/content';
import { missingAnchors } from '../tours/testing';
import { ShellProvider } from '../shell/ShellContext';
import { Hunts } from './Hunts';

describe('the Hunts page tour', () => {
  it('finds every anchor it names on the page', async () => {
    render(
      <MemoryRouter initialEntries={['/hunts']}>
        <DemoProvider demo={false}>
          <ShellProvider>
            <Routes>
              <Route path="/hunts" element={<Hunts />} />
            </Routes>
          </ShellProvider>
        </DemoProvider>
      </MemoryRouter>,
    );
    await screen.findByText(ROW.objective);
    await screen.findByTestId('grid-gap-strip');
    expect(await screen.findByTestId('leads-select-all')).toBeTruthy();
    expect(missingAnchors(HUNTS_TOUR)).toEqual([]);
  });
});
