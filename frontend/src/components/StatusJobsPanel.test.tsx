// The Status page's job list: one row per job that runs with no operator
// (H1-D14, R5-I4). Each row holds the state, the last run, the last result and
// a link to the setting that turns the job on or off.
//
// Before this panel the page listed the analytic sweep and nothing else.
// Continuous Auto-Investigate, the dossier sweep, the discovery scan, the
// audit-chain check, the nightly eval and the backup ran, failed or stopped
// with no trace on the page whose job is to say "is it running?".
//
// The rule the tests below hold hardest: a read that failed, or a read the
// caller may not make, never renders as "on". Every fixture time is relative
// to now.
import { act, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getConfig: vi.fn(),
  getAutoTriageStatus: vi.fn(),
  getDossierSweepHealth: vi.fn(),
  getDiscoveryScan: vi.fn(),
  getAuditVerifySchedule: vi.fn(),
  getQualityTrend: vi.fn(),
  getQualityEvalStatus: vi.fn(),
  getMaintenance: vi.fn(),
}));

import {
  ApiError,
  getAuditVerifySchedule,
  getAutoTriageStatus,
  getConfig,
  getDiscoveryScan,
  getDossierSweepHealth,
  getMaintenance,
  getQualityEvalStatus,
  getQualityTrend,
  type AutoTriageStatus,
  type QualityTrend,
} from '../lib/api';
import type { Config } from '../lib/types';
import { StatusJobsPanel } from './StatusJobsPanel';

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const ON: Record<string, boolean | number> = {
  auto_triage_schedule_enabled: true,
  auto_triage_schedule_interval_minutes: 5,
  dossier_enabled: true,
  dossier_schedule_enabled: true,
  dossier_schedule_interval_hours: 24,
  discovery_enabled: true,
  discovery_schedule_enabled: true,
  discovery_schedule_interval_hours: 24,
  audit_verify_schedule_enabled: true,
  audit_verify_schedule_interval_hours: 24,
  eval_nightly_enabled: true,
  eval_nightly_hour_utc: 3,
};

function config(values: Record<string, boolean | number>): Config {
  return {
    groups: [
      {
        title: 'Everything',
        items: Object.entries(values).map(([key, value]) => ({
          key,
          label: key,
          help: '',
          source: 'env' as const,
          apply: 'hot-apply' as const,
          type: typeof value === 'boolean' ? ('toggle' as const) : ('number' as const),
          value,
          day1: true,
        })),
      },
    ],
    tokens: [],
    users: [],
    dangerHost: '',
  };
}

const TRIAGE: AutoTriageStatus = {
  active: false,
  total: 6,
  hunted: 4,
  skipped: 2,
  failed: 0,
  finished_at: iso(8 * MIN),
  severities: ['critical', 'high'],
  note: null,
  current: null,
  tool_calls: 31,
  degraded: false,
  grid_errors: [],
};

const TREND: QualityTrend = {
  points: [],
  freshness: {
    latest_ts: iso(20 * HOUR),
    scheduled: true,
    stale: false,
    last_attempt_at: iso(20 * HOUR),
    last_exit_code: 0,
    last_detail: null,
  },
};

const NAMES = [
  'Continuous Auto-Investigate',
  'Dossier sweep',
  'Discovery scan',
  'Audit chain check',
  'Nightly quality eval',
  'Nightly backup',
];

beforeEach(() => {
  vi.mocked(getConfig).mockReset().mockResolvedValue(config(ON));
  vi.mocked(getAutoTriageStatus).mockReset().mockResolvedValue(TRIAGE);
  vi.mocked(getDossierSweepHealth).mockReset().mockResolvedValue({
    running: false,
    degraded: false,
    last_run: iso(3 * HOUR),
    error_count: 0,
  });
  vi.mocked(getDiscoveryScan).mockReset().mockResolvedValue({
    running: false,
    last_scan: iso(5 * HOUR),
    last_summary: { hosts_found: 12, errors: [] },
    note: null,
  });
  vi.mocked(getAuditVerifySchedule).mockReset().mockResolvedValue({
    enabled: true,
    interval_hours: 24,
    window_days: 7,
    last_run: iso(2 * HOUR),
    broken: false,
    broken_since: null,
    detail: null,
  });
  vi.mocked(getQualityTrend).mockReset().mockResolvedValue(TREND);
  vi.mocked(getQualityEvalStatus).mockReset().mockResolvedValue({
    running: false,
    last_run: null,
    last_exit_code: null,
    last_detail: '',
  });
  vi.mocked(getMaintenance).mockReset().mockResolvedValue({
    backups: [{ name: 'soc-ai-backup-a.tar.gz', size_bytes: 3 * 1024 * 1024, modified: iso(10 * HOUR) }],
    backups_dir: '/data/backups',
    blocklists_dir: '/data/blocklists',
    blocklists_refreshed: null,
    blocklist_files: 0,
  });
});

const mount = () =>
  render(
    <MemoryRouter>
      <StatusJobsPanel />
    </MemoryRouter>,
  );

function row(name: string): HTMLElement {
  const el = screen
    .getAllByTestId('status-job')
    .find((r) => within(r).queryByText(name, { selector: '[data-part="name"]' }));
  if (!el) throw new Error(`no job row named ${name}`);
  return el;
}
const state = (name: string) => within(row(name)).getByTestId('job-state').textContent;
const result = (name: string) => within(row(name)).getByTestId('job-result');
const lastRun = (name: string) => within(row(name)).getByTestId('job-last-run');

async function loaded() {
  await screen.findAllByTestId('status-job');
}

describe('StatusJobsPanel', () => {
  it('lists one row per unattended job, and no row for the two analytic sweeps', async () => {
    mount();
    await loaded();
    const names = screen
      .getAllByTestId('status-job')
      .map((r) => within(r).getByText(/./, { selector: '[data-part="name"]' }).textContent);
    expect(names).toEqual(NAMES);
    // The Analytics panel owns the analytic sweep and the profile sweep.
    expect(screen.queryByText(/analytic sweep$/i, { selector: '[data-part="name"]' })).toBeNull();
    expect(screen.queryByText(/profile sweep/i, { selector: '[data-part="name"]' })).toBeNull();
  });

  it('a sound install reads on, with a relative last run, an absolute title and a result', async () => {
    mount();
    await loaded();
    for (const name of NAMES) expect(state(name)).toBe('on');
    expect(lastRun('Continuous Auto-Investigate')).toHaveTextContent('8m ago');
    expect(lastRun('Continuous Auto-Investigate').getAttribute('title')).toMatch(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}/);
    expect(result('Continuous Auto-Investigate')).toHaveTextContent('The last run investigated 4 alerts.');
    expect(result('Dossier sweep')).toHaveTextContent('The last sweep finished with no error.');
    expect(result('Discovery scan')).toHaveTextContent('The last scan finished with no error.');
    expect(result('Nightly quality eval')).toHaveTextContent('The last eval wrote a trend point.');
    expect(result('Nightly backup')).toHaveTextContent('The last backup wrote 3.0 MiB.');
    expect(within(row('Continuous Auto-Investigate')).getByText('every 5 minutes')).toBeInTheDocument();
    expect(within(row('Nightly quality eval')).getByText('every day at 03:00 UTC')).toBeInTheDocument();
  });

  it('links each row to the setting that turns the job on or off', async () => {
    mount();
    await loaded();
    const hrefs = NAMES.map((n) => within(row(n)).getByRole('link').getAttribute('href'));
    expect(hrefs).toEqual([
      '/config#triage-automation',
      '/config#host-dossier',
      '/config#discovery',
      '/config#audit-trail',
      '/config#quality',
      '/config#maintenance',
    ]);
    expect(within(row('Dossier sweep')).getByRole('link')).toHaveAccessibleName(
      'Open the Dossier sweep setting',
    );
  });

  it('a job whose setting is off reads off, and the discovery row needs both switches', async () => {
    vi.mocked(getConfig).mockResolvedValue(
      config({ ...ON, auto_triage_schedule_enabled: false, discovery_schedule_enabled: false }),
    );
    mount();
    await loaded();
    expect(state('Continuous Auto-Investigate')).toBe('off');
    expect(state('Discovery scan')).toBe('off');
    // Off, a cadence would claim a schedule that is not running.
    expect(within(row('Continuous Auto-Investigate')).queryByText(/every/)).toBeNull();
    expect(state('Dossier sweep')).toBe('on');
  });

  it('a run that could not read the grid reads failed, with the failed queries in the title', async () => {
    vi.mocked(getAutoTriageStatus).mockResolvedValue({
      ...TRIAGE,
      total: 0,
      hunted: 0,
      degraded: true,
      grid_errors: ['severity critical'],
    });
    mount();
    await loaded();
    expect(state('Continuous Auto-Investigate')).toBe('failed');
    expect(result('Continuous Auto-Investigate')).toHaveTextContent('The last run could not read the grid.');
    expect(result('Continuous Auto-Investigate').getAttribute('title')).toContain('severity critical');
  });

  it('a run with failed investigations reads failed and counts them', async () => {
    vi.mocked(getAutoTriageStatus).mockResolvedValue({ ...TRIAGE, hunted: 3, failed: 2 });
    mount();
    await loaded();
    expect(state('Continuous Auto-Investigate')).toBe('failed');
    expect(result('Continuous Auto-Investigate')).toHaveTextContent(
      'The last run investigated 3 alerts. 2 investigations failed.',
    );
  });

  it('a running job reads running, whatever its last result', async () => {
    vi.mocked(getAutoTriageStatus).mockResolvedValue({ ...TRIAGE, active: true, hunted: 1, total: 5 });
    vi.mocked(getQualityEvalStatus).mockResolvedValue({
      running: true,
      last_run: null,
      last_exit_code: null,
      last_detail: '',
    });
    mount();
    await loaded();
    expect(state('Continuous Auto-Investigate')).toBe('running');
    expect(result('Continuous Auto-Investigate')).toHaveTextContent(
      'A run is in progress. It investigated 1 of 5 alerts.',
    );
    expect(state('Nightly quality eval')).toBe('running');
  });

  it('a sweep or a scan that recorded errors reads failed with the count', async () => {
    vi.mocked(getDossierSweepHealth).mockResolvedValue({
      running: false,
      degraded: true,
      last_run: iso(1 * HOUR),
      error_count: 3,
    });
    vi.mocked(getDiscoveryScan).mockResolvedValue({
      running: false,
      last_scan: iso(1 * HOUR),
      last_summary: { errors: ['the scan failed. See the server logs.'] },
      note: null,
    });
    mount();
    await loaded();
    expect(state('Dossier sweep')).toBe('failed');
    expect(result('Dossier sweep')).toHaveTextContent('The last sweep recorded 3 errors.');
    expect(state('Discovery scan')).toBe('failed');
    expect(result('Discovery scan')).toHaveTextContent('The last scan recorded 1 error.');
    expect(result('Discovery scan').getAttribute('title')).toContain('See the server logs');
  });

  it('an audit break reads failed, and no break reads as no break on record', async () => {
    vi.mocked(getAuditVerifySchedule).mockResolvedValue({
      enabled: true,
      interval_hours: 24,
      window_days: 7,
      last_run: iso(1 * HOUR),
      broken: true,
      broken_since: iso(2 * DAY),
      detail: '2 records claim sequence 503.',
    });
    mount();
    await loaded();
    expect(state('Audit chain check')).toBe('failed');
    expect(result('Audit chain check')).toHaveTextContent('The last check found a break in the chain.');
    expect(result('Audit chain check').getAttribute('title')).toContain('2 records claim sequence 503.');
  });

  it('an audit check that could not read the index reads unknown, and a clean one intact', async () => {
    const base = {
      enabled: true,
      interval_hours: 24,
      window_days: 7,
      last_run: iso(1 * HOUR),
      broken: false,
      broken_since: null,
      detail: null,
    };
    vi.mocked(getAuditVerifySchedule).mockResolvedValue({ ...base, last_outcome: 'not_checked' });
    const { unmount } = mount();
    await loaded();
    expect(state('Audit chain check')).toBe('unknown');
    expect(result('Audit chain check')).toHaveTextContent('The last check could not read the audit index.');
    unmount();

    vi.mocked(getAuditVerifySchedule).mockResolvedValue({ ...base, last_outcome: 'intact' });
    mount();
    await loaded();
    expect(state('Audit chain check')).toBe('on');
    expect(result('Audit chain check')).toHaveTextContent('The last check found the chain intact.');
  });

  it('an audit check with no alarm claims no clean result', async () => {
    mount();
    await loaded();
    // The loop stamps a check that could not read the index like a clean one.
    // "Intact" would be a claim the route cannot back.
    expect(result('Audit chain check')).toHaveTextContent('No break is on record since soc-ai started.');
    expect(result('Audit chain check')).not.toHaveTextContent(/intact|clean/i);
  });

  it('the nightly eval reads its exit code', async () => {
    vi.mocked(getQualityTrend).mockResolvedValue({
      ...TREND,
      freshness: { ...TREND.freshness, last_exit_code: 2, last_detail: 'no eligible alerts' },
    });
    const { unmount } = mount();
    await loaded();
    expect(state('Nightly quality eval')).toBe('on');
    expect(result('Nightly quality eval')).toHaveTextContent('The last eval found no alert to grade.');
    unmount();

    vi.mocked(getQualityTrend).mockResolvedValue({
      ...TREND,
      freshness: { ...TREND.freshness, last_exit_code: 5, last_detail: 'APIConnectionError: refused' },
    });
    mount();
    await loaded();
    expect(state('Nightly quality eval')).toBe('failed');
    expect(result('Nightly quality eval')).toHaveTextContent('The last eval failed.');
    expect(result('Nightly quality eval').getAttribute('title')).toContain('APIConnectionError');
  });

  it('the backup row reads the newest archive: stale is failed, none is unknown', async () => {
    vi.mocked(getMaintenance).mockResolvedValue({
      backups: [{ name: 'soc-ai-backup-b.tar.gz', size_bytes: 1024, modified: iso(3 * DAY) }],
      backups_dir: '/data/backups',
      blocklists_dir: '/data/blocklists',
      blocklists_refreshed: null,
      blocklist_files: 0,
    });
    const { unmount } = mount();
    await loaded();
    expect(state('Nightly backup')).toBe('failed');
    expect(result('Nightly backup')).toHaveTextContent('The newest archive is 3 days old.');
    unmount();

    vi.mocked(getMaintenance).mockResolvedValue({
      backups: [],
      backups_dir: '/data/backups',
      blocklists_dir: '/data/blocklists',
      blocklists_refreshed: null,
      blocklist_files: 0,
    });
    mount();
    await loaded();
    expect(state('Nightly backup')).toBe('unknown');
    expect(result('Nightly backup')).toHaveTextContent('soc-ai finds no archive in /data/backups.');
    expect(lastRun('Nightly backup')).toHaveTextContent('never');
  });

  it('a job on its schedule that missed two intervals reads failed as overdue', async () => {
    vi.mocked(getDossierSweepHealth).mockResolvedValue({
      running: false,
      degraded: false,
      last_run: iso(3 * DAY),
      error_count: 0,
    });
    mount();
    await loaded();
    expect(state('Dossier sweep')).toBe('failed');
    expect(result('Dossier sweep')).toHaveTextContent('The job is overdue. It runs every day.');
  });

  it('a failed status read reads unknown though the setting is on', async () => {
    vi.mocked(getAutoTriageStatus).mockRejectedValue(new Error('502'));
    mount();
    await loaded();
    expect(state('Continuous Auto-Investigate')).toBe('unknown');
    expect(lastRun('Continuous Auto-Investigate')).toHaveTextContent('unknown');
    expect(result('Continuous Auto-Investigate')).toHaveTextContent('soc-ai could not read this job.');
  });

  it('an analyst sees each admin-only job as unknown with the reason, never as on', async () => {
    const forbidden = () => Promise.reject(new ApiError('admin only', 403, 'admin_required'));
    vi.mocked(getConfig).mockImplementation(forbidden);
    vi.mocked(getDiscoveryScan).mockImplementation(forbidden);
    vi.mocked(getQualityTrend).mockImplementation(forbidden);
    vi.mocked(getQualityEvalStatus).mockImplementation(forbidden);
    vi.mocked(getMaintenance).mockImplementation(forbidden);
    mount();
    await loaded();
    for (const name of ['Discovery scan', 'Nightly quality eval', 'Nightly backup']) {
      expect(state(name)).toBe('unknown');
      expect(result(name)).toHaveTextContent('Only an admin can read this job.');
    }
    // The status reads are open to an analyst. The on/off switch is not, so
    // the state stays unknown and the result still says what the run did.
    expect(state('Continuous Auto-Investigate')).toBe('unknown');
    expect(result('Continuous Auto-Investigate')).toHaveTextContent('The last run investigated 4 alerts.');
    expect(state('Dossier sweep')).toBe('unknown');
    // The audit route carries its own switch, so that row can say on.
    expect(state('Audit chain check')).toBe('on');
    expect(screen.queryAllByText('on', { selector: '[data-testid="job-state"]' })).toHaveLength(1);
  });
});

describe('StatusJobsPanel on the public demo', () => {
  it('names the demo as the reason a job is hidden, and never asks for an admin', async () => {
    // The demo refuses every admin read with reason demo_mode. No visitor can
    // sign in there, so "Only an admin can read this job" sent them nowhere.
    const demo = () => Promise.reject(new ApiError('demo', 403, 'demo_mode'));
    vi.mocked(getConfig).mockImplementation(demo);
    vi.mocked(getDiscoveryScan).mockImplementation(demo);
    vi.mocked(getQualityTrend).mockImplementation(demo);
    vi.mocked(getQualityEvalStatus).mockImplementation(demo);
    vi.mocked(getMaintenance).mockImplementation(demo);
    mount();
    await loaded();
    for (const name of ['Discovery scan', 'Nightly quality eval', 'Nightly backup']) {
      expect(state(name)).toBe('unknown');
      expect(result(name)).toHaveTextContent('The demo does not show this job.');
    }
    expect(screen.queryByText('Only an admin can read this job.')).toBeNull();
  });
});

describe('StatusJobsPanel poll', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('reads on the 5-minute tick, and a failed poll turns an on row to unknown', async () => {
    mount();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(getAutoTriageStatus).toHaveBeenCalledTimes(1);
    expect(state('Continuous Auto-Investigate')).toBe('on');

    vi.mocked(getAutoTriageStatus).mockRejectedValue(new Error('timeout'));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(299_000);
    });
    expect(getAutoTriageStatus).toHaveBeenCalledTimes(1);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_000);
    });
    expect(getAutoTriageStatus).toHaveBeenCalledTimes(2);
    expect(state('Continuous Auto-Investigate')).toBe('unknown');
  });
});
