// One tile, three denominators (dogfood 2026-09-07, D4). "True positives · 24h"
// is labelled for a 24-hour window, its number counts DETECTION GROUPS, and its
// subtext counted INVESTIGATION RUNS over thirty days. Read in two tabs at the
// same minute the tile said one and the investigations list said three, and
// nothing on the tile said the two were counting different things.
//
// Every number in the tile now names the unit and the window it answers for.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { AlertGroup, InvestigationList, InvestigationRow, Verdict } from '../lib/types';

const group = (id: string, verdict: Verdict): AlertGroup => ({
  id,
  name: `ET TEST ${id}`,
  kind: 'suricata',
  sev: 'high',
  count: 4,
  verdict,
  conf: verdict === 'untriaged' ? null : 0.8,
  latest: '2m ago',
  inherited: false,
  events: [],
});

// One true positive among three groups: the shape the range was in when the
// tile read "1" beside a 24h investigations list reading "3 true positives".
const GROUPS: [string, Verdict][] = [
  ['g-tp', 'true_positive'],
  ['g-fp', 'false_positive'],
  ['g-nmi', 'needs_more_info'],
];

const listInvestigations = vi.hoisted(() => vi.fn());

const empty = (): InvestigationList => ({
  rows: [] as InvestigationRow[],
  total: 0,
  running: 0,
  truePositives: 0,
  totalAll: 0,
  active: false,
  limit: 100,
  offset: 0,
});

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue({ groups: [], truncated: false, other_docs: 0 }),
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  listInvestigations,
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getHealth: vi.fn().mockResolvedValue(null),
  getDetectionTuningSummary: vi.fn().mockResolvedValue(null),
  getMe: vi.fn().mockResolvedValue({ username: 'ana', role: 'analyst', status: '' }),
  getPreflight: vi.fn().mockResolvedValue({ status: 'green', failing: 0, warned: 0, checked_at: '2026-08-19T00:00:00+00:00' }),
  getPreflightDetail: vi.fn().mockResolvedValue({ rows: [], checked_at: '2026-08-19T00:00:00+00:00' }),
}));

import { queueOf } from '../test/alertQueue';
import { Dashboard } from './Dashboard';
import { getAlerts } from '../lib/api';

const fallback = (id: string): InvestigationRow => ({
  id,
  name: `Run ${id}`,
  kind: 'suricata',
  verdict: 'needs_more_info',
  conf: 0.3,
  host: '192.0.2.10',
  status: 'complete',
  when: '2d ago',
  ts: '2026-08-20T10:00:00+00:00',
  alertId: `ev-${id}`,
  isPrimary: true,
  fallback: true,
});

const mount = async (pipelineErrors: InvestigationRow[] = []) => {
  vi.mocked(getAlerts).mockResolvedValue(queueOf(GROUPS.map(([id, v]) => group(id, v))));
  listInvestigations.mockImplementation(async (q: { verdict?: string[] } = {}) =>
    q.verdict?.length ? { ...empty(), rows: pipelineErrors, total: pipelineErrors.length } : empty(),
  );
  render(
    <MemoryRouter>
      <Dashboard />
    </MemoryRouter>,
  );
  await screen.findByText('Investigation outcomes');
};

/** The whole true-positives tile (the Panel), located from its label. */
const tpTile = async () =>
  (await screen.findByText('True positives · 24h')).closest('.rounded-panel')!;

describe('Dashboard true-positives tile — every number answers one question', () => {
  it('names the unit its number counts, and the set it is one of', async () => {
    await mount();
    const tile = await tpTile();
    // The number is 1. The investigations list over the same window says 3,
    // because it counts runs. Naming the unit is what makes both readable.
    expect(tile.textContent).toContain('of 3 detection groups');
  });

  it('keeps the needs-info clause on the same unit and window', async () => {
    await mount();
    const tile = await tpTile();
    expect(tile.textContent).toContain('1 need more info');
  });

  it('labels the pipeline-error clause with its OWN window and unit', async () => {
    await mount([fallback('fb1'), fallback('fb2')]);
    const tile = await tpTile();
    // It counts investigation runs over thirty days, which is neither the unit
    // nor the window in the tile's heading, so it says so.
    expect(tile.textContent).toMatch(/runs, last 30 days/i);
    expect(await screen.findByRole('button', { name: '2 pipeline errors' })).toBeTruthy();
  });

  it('says nothing about a 30-day window when there is nothing to say', async () => {
    await mount();
    const tile = await tpTile();
    expect(tile.textContent).not.toMatch(/30 days/);
  });
});
