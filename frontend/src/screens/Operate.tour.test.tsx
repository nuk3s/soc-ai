// The Status page tour points at real elements (tours/content.ts).
//
// The page renders with its four live panels and their reads answered: the
// three dependencies, the scheduled jobs, the analytic sweep and one
// escalation with no answer. Every anchor the tour names must then be on the
// page, so a renamed or removed `data-tour` attribute fails here.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

const MINUTE = 60_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHealth: vi.fn(),
  getQualityTrend: vi.fn(),
  getQualityEvalStatus: vi.fn(),
  getHuntCatalog: vi.fn(),
  getStrandedEscalations: vi.fn(),
  getAnalyticHits: vi.fn().mockResolvedValue({ hits: [], counts: { all: 0, unread: 0, live: 0, shadow: 0 } }),
  getConfig: vi.fn(),
  getAutoTriageStatus: vi.fn(),
  getDossierSweepHealth: vi.fn(),
  getDiscoveryScan: vi.fn(),
  getAuditVerifySchedule: vi.fn(),
  getMaintenance: vi.fn(),
}));

import {
  getAuditVerifySchedule,
  getAutoTriageStatus,
  getConfig,
  getDiscoveryScan,
  getDossierSweepHealth,
  getHealth,
  getHuntCatalog,
  getMaintenance,
  getQualityEvalStatus,
  getQualityTrend,
  getStrandedEscalations,
} from '../lib/api';
import { STATUS_TOUR } from '../tours/content';
import { missingAnchors } from '../tours/testing';
import { Operate } from './Operate';

describe('the Status page tour', () => {
  it('finds every anchor it names', async () => {
    vi.mocked(getHealth).mockResolvedValue({
      es: { ok: true, detail: 'es' },
      llm: { ok: true, detail: 'llm' },
      so: { ok: true, detail: 'so' },
    });
    vi.mocked(getConfig).mockResolvedValue({ groups: [], tokens: [], users: [], dangerHost: '' });
    vi.mocked(getAutoTriageStatus).mockResolvedValue({
      active: false,
      total: 0,
      hunted: 0,
      skipped: 0,
      failed: 0,
      finished_at: null,
      severities: [],
      note: null,
      current: null,
      tool_calls: 0,
    });
    vi.mocked(getDossierSweepHealth).mockResolvedValue({
      running: false,
      degraded: false,
      last_run: null,
      error_count: 0,
    });
    vi.mocked(getDiscoveryScan).mockResolvedValue({
      running: false,
      last_scan: null,
      last_summary: null,
      note: null,
    });
    vi.mocked(getAuditVerifySchedule).mockResolvedValue({
      enabled: true,
      interval_hours: 24,
      window_days: 7,
      last_run: null,
      broken: false,
      broken_since: null,
      detail: null,
    });
    vi.mocked(getQualityTrend).mockResolvedValue({
      points: [],
      freshness: {
        latest_ts: null,
        scheduled: false,
        stale: false,
        last_attempt_at: null,
        last_exit_code: null,
        last_detail: null,
      },
    });
    vi.mocked(getQualityEvalStatus).mockResolvedValue({
      running: false,
      last_run: null,
      last_exit_code: null,
      last_detail: '',
    });
    vi.mocked(getMaintenance).mockResolvedValue({
      backups: [],
      backups_dir: '/data/backups',
      blocklists_dir: '/data/blocklists',
      blocklists_refreshed: null,
      blocklist_files: 0,
    });
    vi.mocked(getHuntCatalog).mockResolvedValue({
      specs: [],
      sweeps_enabled: true,
      sweep_interval_minutes: 60,
      sweep_window_minutes: 1440,
      last_sweep_at: iso(10 * MINUTE),
    });
    vi.mocked(getStrandedEscalations).mockResolvedValue({
      claims: [{ alert_id: 'ev-example', escalated_by: 'analyst', claimed_at: iso(120 * MINUTE) }],
      total: 1,
      settling_minutes: 15,
    });

    render(
      <MemoryRouter initialEntries={['/operate']}>
        <Operate />
      </MemoryRouter>,
    );
    await screen.findAllByTestId('status-dependency');
    await screen.findAllByTestId('status-job');
    await screen.findByText('Check Security Onion now');
    await screen.findByText('Sweeps on');

    expect(missingAnchors(STATUS_TOUR)).toEqual([]);
  });
});
