// The recent-investigations rows on the Dashboard read their status from
// lib/statusMeta.ts, which said "Investigating" and "Error". The
// Investigations list reads statusMeta() from lib/labels.ts and says
// "Running" and "Failed". One run read two ways on two screens.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

const ROWS = vi.hoisted(() =>
  (['running', 'error', 'complete'] as const).map((status, i) => ({
    id: `INV-${status}`,
    name: `Rule ${status}`,
    kind: 'suricata',
    verdict: status === 'complete' ? 'false_positive' : 'untriaged',
    conf: status === 'complete' ? 0.9 : null,
    host: `192.0.2.${10 + i}`,
    dst: '198.51.100.7',
    status,
    when: `${i + 1}m ago`,
    ts: '2026-07-14T10:00:00+00:00',
    fallback: false,
  })),
);

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue({ groups: [], truncated: false, other_docs: 0 }),
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  listInvestigations: vi.fn().mockImplementation(async (q: { verdict?: string[] } = {}) => ({
    rows: q.verdict?.length ? [] : ROWS,
    total: q.verdict?.length ? 0 : ROWS.length,
    running: 1,
    truePositives: 0,
    totalAll: ROWS.length,
    active: false,
    limit: 100,
    offset: 0,
  })),
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getHealth: vi.fn().mockResolvedValue(null),
  getMe: vi.fn().mockResolvedValue({ username: 'ana', role: 'analyst', status: '' }),
  getPreflight: vi.fn().mockResolvedValue({
    status: 'green',
    failing: 0,
    warned: 0,
    checked_at: '2026-08-19T00:00:00+00:00',
  }),
  getPreflightDetail: vi.fn().mockResolvedValue({ rows: [], checked_at: '2026-08-19T00:00:00+00:00' }),
  getShadowHits: vi.fn().mockResolvedValue({ hits: [], unread: 0 }),
}));

import { Dashboard } from './Dashboard';

const rowOf = async (status: string): Promise<HTMLElement> =>
  (await screen.findByText(`Rule ${status}`)).closest(
    '[data-testid="recent-investigation"]',
  ) as HTMLElement;

describe('Dashboard recent investigations status words', () => {
  it('reads the status words of lib/labels.ts', async () => {
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    );
    expect((await rowOf('running')).textContent).toContain('Running');
    expect((await rowOf('error')).textContent).toContain('Failed');
    expect((await rowOf('complete')).textContent).toContain('Complete');
    // Negative control: the words of the old map are gone from every row.
    for (const status of ['running', 'error']) {
      expect((await rowOf(status)).textContent ?? '').not.toMatch(/Investigating|\bError\b|Interrupted/);
    }
    // The title names the cause, because "Failed" no longer does.
    expect((await rowOf('error')).querySelector('[title*="An error stopped the run"]')).toBeTruthy();
  });
});
