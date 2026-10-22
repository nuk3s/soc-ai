import { CalendarClock } from 'lucide-react';
import { Link } from 'react-router-dom';

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
  type AuditVerifySchedule,
  type AutoTriageStatus,
  type DiscoveryScanStatus,
  type DossierSweepHealth,
  type Maintenance,
  type QualityEvalStatus,
  type QualityTrend,
} from '../lib/api';
import { agoWords, timeLabel } from '../lib/timeRange';
import { tint } from '../lib/tokens';
import type { Config } from '../lib/types';
import { useAsync } from '../lib/useAsync';
import { Panel, PanelHeader } from './Panel';
import { Freshness, LoadingState } from './States';

// ---------------------------------------------------------------------------
// Scheduled jobs on the Status page (H1-D14, R5-I4).
//
// One row per job that runs with no operator: continuous Auto-Investigate, the
// dossier sweep, the discovery scan, the audit-chain check, the nightly eval
// and the backup. The analytic sweep and the profile sweep are NOT here: the
// Analytics panel below owns both, row by row.
//
// Every row reads a route that already exists, except the audit-chain check,
// whose loop kept its state in memory with no route until GET
// /audit/verify-schedule. The on/off switches come from GET /config, which is
// admin-only, as are the discovery, eval and backup reads. An analyst sees
// those rows as "unknown", with the reason. Never as "on".
//
// The loader never rejects. Each read settles to a value, so a failed read
// turns its row "unknown" on the next poll. A rejecting loader would let
// useAsync keep the last-good rows through a failed background poll, and an
// "on" row would stand over a read that failed.
//
// Polls on the page's 5-minute cadence.
// ---------------------------------------------------------------------------

export type JobState = 'on' | 'off' | 'running' | 'failed' | 'unknown';

export interface JobRow {
  id: 'auto-investigate' | 'dossier' | 'discovery' | 'audit' | 'eval' | 'backup';
  name: string;
  /** The cadence, shown only when the job is on. */
  schedule: string | null;
  state: JobState;
  /** ISO time of the last run. Null: no run on record. Undefined: unknown. */
  lastRun: string | null | undefined;
  /** The last result in one short sentence. */
  result: string;
  /** The raw reason behind a failed result, for the title. */
  resultTitle: string | null;
  to: string;
}

type Settled<T> = { ok: true; data: T } | { ok: false; error: unknown };

export interface JobsRead {
  config: Settled<Config>;
  autoTriage: Settled<AutoTriageStatus>;
  dossier: Settled<DossierSweepHealth>;
  discovery: Settled<DiscoveryScanStatus>;
  audit: Settled<AuditVerifySchedule>;
  quality: Settled<QualityTrend>;
  qualityRun: Settled<QualityEvalStatus>;
  maintenance: Settled<Maintenance>;
}

async function settle<T>(p: Promise<T>): Promise<Settled<T>> {
  try {
    return { ok: true, data: await p };
  } catch (error) {
    return { ok: false, error };
  }
}

/** Every read at once. Never rejects: each failure is a value. */
export async function readJobs(): Promise<JobsRead> {
  const [config, autoTriage, dossier, discovery, audit, quality, qualityRun, maintenance] =
    await Promise.all([
      settle(getConfig()),
      settle(getAutoTriageStatus()),
      settle(getDossierSweepHealth()),
      settle(getDiscoveryScan()),
      settle(getAuditVerifySchedule()),
      settle(getQualityTrend()),
      settle(getQualityEvalStatus()),
      settle(getMaintenance()),
    ]);
  return { config, autoTriage, dossier, discovery, audit, quality, qualityRun, maintenance };
}

// ---- helpers ---------------------------------------------------------------

function readFailure(error: unknown): string {
  // The public demo refuses every admin read, and no visitor can sign in there.
  if (error instanceof ApiError && error.reason === 'demo_mode') {
    return 'The demo does not show this job.';
  }
  return error instanceof ApiError && error.status === 403
    ? 'Only an admin can read this job.'
    : 'soc-ai could not read this job.';
}

function setting(read: Settled<Config>, key: string): boolean | number | string | undefined {
  if (!read.ok) return undefined;
  for (const g of read.data.groups) {
    for (const s of g.items) if (s.key === key) return s.value;
  }
  return undefined;
}

/** True when every switch is on, false when one is off, null when unknown. */
function switches(read: Settled<Config>, keys: string[]): boolean | null {
  let all = true;
  for (const key of keys) {
    const v = setting(read, key);
    if (typeof v !== 'boolean') return null;
    if (!v) all = false;
  }
  return all;
}

function numberSetting(read: Settled<Config>, key: string): number | null {
  const v = setting(read, key);
  return typeof v === 'number' && Number.isFinite(v) && v > 0 ? v : null;
}

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;

/** "every 5 minutes", "every hour", "every 6 hours", "every day". */
export function everyWords(minutes: number): string {
  if (minutes % 1440 === 0) {
    const d = minutes / 1440;
    return d === 1 ? 'every day' : `every ${d} days`;
  }
  if (minutes % 60 === 0) {
    const h = minutes / 60;
    return h === 1 ? 'every hour' : `every ${h} hours`;
  }
  return minutes === 1 ? 'every minute' : `every ${minutes} minutes`;
}

/** Two intervals with no run: the earliest moment the time alone proves a
 *  missed run. The Analytics panel uses the same rule for its sweep. */
function overdue(lastRun: string | null | undefined, minutes: number | null, now: number): boolean {
  if (!lastRun || minutes === null) return false;
  const t = Date.parse(lastRun);
  return Number.isFinite(t) && now - t > 2 * minutes * 60_000;
}

type Outcome = 'ok' | 'failed' | 'never' | 'unknown';

function stateOf(enabled: boolean | null, running: boolean, outcome: Outcome): JobState {
  if (running) return 'running';
  if (enabled === false) return 'off';
  if (outcome === 'failed') return 'failed';
  if (outcome === 'unknown' || enabled === null) return 'unknown';
  return 'on';
}

interface Facts {
  enabled: boolean | null;
  intervalMinutes: number | null;
  running: boolean;
  lastRun: string | null | undefined;
  outcome: Outcome;
  result: string;
  resultTitle?: string | null;
  schedule?: string | null;
}

function finish(
  base: Pick<JobRow, 'id' | 'name' | 'to'>,
  f: Facts,
  now: number,
): JobRow {
  let { outcome, result } = f;
  let resultTitle = f.resultTitle ?? null;
  const every = f.intervalMinutes !== null ? everyWords(f.intervalMinutes) : null;
  if (f.enabled === true && !f.running && overdue(f.lastRun, f.intervalMinutes, now)) {
    outcome = 'failed';
    resultTitle = result;
    result = `The job is overdue. It runs ${every}.`;
  }
  return {
    ...base,
    schedule: f.enabled === true ? (f.schedule ?? every) : null,
    state: stateOf(f.enabled, f.running, outcome),
    lastRun: f.lastRun,
    result,
    resultTitle,
  };
}

// ---- one function per job -------------------------------------------------

function autoInvestigate(read: JobsRead, now: number): JobRow {
  const base = { id: 'auto-investigate', name: 'Continuous Auto-Investigate', to: '/config#triage-automation' } as const;
  const enabled = switches(read.config, ['auto_triage_schedule_enabled']);
  const intervalMinutes = numberSetting(read.config, 'auto_triage_schedule_interval_minutes');
  const r = read.autoTriage;
  if (!r.ok) {
    return finish(base, { enabled, intervalMinutes, running: false, lastRun: undefined, outcome: 'unknown', result: readFailure(r.error) }, now);
  }
  const s = r.data;
  const facts = { enabled, intervalMinutes, running: s.active, lastRun: s.finished_at };
  if (s.active) {
    return finish(base, { ...facts, outcome: 'ok', result: `A run is in progress. It investigated ${s.hunted} of ${s.total} alerts.` }, now);
  }
  if (!s.finished_at) {
    return finish(base, { ...facts, outcome: 'never', result: 'No run since soc-ai started.' }, now);
  }
  if (s.degraded) {
    return finish(
      base,
      {
        ...facts,
        outcome: 'failed',
        result: 'The last run could not read the grid.',
        resultTitle: (s.grid_errors ?? []).join('. ') || null,
      },
      now,
    );
  }
  if (s.failed > 0) {
    return finish(
      base,
      {
        ...facts,
        outcome: 'failed',
        result: `The last run investigated ${plural(s.hunted, 'alert')}. ${plural(s.failed, 'investigation')} failed.`,
      },
      now,
    );
  }
  if (s.total === 0 && s.hunted === 0) {
    return finish(base, { ...facts, outcome: 'ok', result: 'The last run found no alert to investigate.' }, now);
  }
  return finish(base, { ...facts, outcome: 'ok', result: `The last run investigated ${plural(s.hunted, 'alert')}.` }, now);
}

function dossier(read: JobsRead, now: number): JobRow {
  const base = { id: 'dossier', name: 'Dossier sweep', to: '/config#host-dossier' } as const;
  const enabled = switches(read.config, ['dossier_enabled', 'dossier_schedule_enabled']);
  const hours = numberSetting(read.config, 'dossier_schedule_interval_hours');
  const intervalMinutes = hours !== null ? hours * 60 : null;
  const r = read.dossier;
  if (!r.ok) {
    return finish(base, { enabled, intervalMinutes, running: false, lastRun: undefined, outcome: 'unknown', result: readFailure(r.error) }, now);
  }
  const s = r.data;
  const facts = { enabled, intervalMinutes, running: s.running, lastRun: s.last_run };
  if (s.running) return finish(base, { ...facts, outcome: 'ok', result: 'A sweep is in progress.' }, now);
  if (!s.last_run) return finish(base, { ...facts, outcome: 'never', result: 'No sweep since soc-ai started.' }, now);
  if (s.degraded) {
    return finish(base, { ...facts, outcome: 'failed', result: `The last sweep recorded ${plural(s.error_count, 'error')}.` }, now);
  }
  return finish(base, { ...facts, outcome: 'ok', result: 'The last sweep finished with no error.' }, now);
}

function discoveryErrors(summary: Record<string, unknown> | null): string[] {
  const errors = summary?.errors;
  return Array.isArray(errors) ? errors.filter((e): e is string => typeof e === 'string') : [];
}

function discovery(read: JobsRead, now: number): JobRow {
  const base = { id: 'discovery', name: 'Discovery scan', to: '/config#discovery' } as const;
  const enabled = switches(read.config, ['discovery_enabled', 'discovery_schedule_enabled']);
  const hours = numberSetting(read.config, 'discovery_schedule_interval_hours');
  const intervalMinutes = hours !== null ? hours * 60 : null;
  const r = read.discovery;
  if (!r.ok) {
    return finish(base, { enabled, intervalMinutes, running: false, lastRun: undefined, outcome: 'unknown', result: readFailure(r.error) }, now);
  }
  const s = r.data;
  const facts = { enabled, intervalMinutes, running: s.running, lastRun: s.last_scan };
  if (s.running) return finish(base, { ...facts, outcome: 'ok', result: 'A scan is in progress.' }, now);
  if (!s.last_scan) return finish(base, { ...facts, outcome: 'never', result: 'No scan since soc-ai started.' }, now);
  const errors = discoveryErrors(s.last_summary);
  if (errors.length > 0) {
    return finish(
      base,
      { ...facts, outcome: 'failed', result: `The last scan recorded ${plural(errors.length, 'error')}.`, resultTitle: errors.join(' ') },
      now,
    );
  }
  return finish(base, { ...facts, outcome: 'ok', result: 'The last scan finished with no error.' }, now);
}

function audit(read: JobsRead, now: number): JobRow {
  const base = { id: 'audit', name: 'Audit chain check', to: '/config#audit-trail' } as const;
  const r = read.audit;
  if (!r.ok) {
    const enabled = switches(read.config, ['audit_verify_schedule_enabled']);
    const hours = numberSetting(read.config, 'audit_verify_schedule_interval_hours');
    return finish(
      base,
      { enabled, intervalMinutes: hours !== null ? hours * 60 : null, running: false, lastRun: undefined, outcome: 'unknown', result: readFailure(r.error) },
      now,
    );
  }
  const s = r.data;
  const facts = { enabled: s.enabled, intervalMinutes: s.interval_hours * 60, running: false, lastRun: s.last_run };
  if (s.broken) {
    return finish(
      base,
      { ...facts, outcome: 'failed', result: 'The last check found a break in the chain.', resultTitle: s.detail },
      now,
    );
  }
  if (!s.last_run) return finish(base, { ...facts, outcome: 'never', result: 'No check since soc-ai started.' }, now);
  if (s.last_outcome === 'not_checked') {
    return finish(
      base,
      { ...facts, outcome: 'unknown', result: 'The last check could not read the audit index.' },
      now,
    );
  }
  if (s.last_outcome === 'intact') {
    return finish(base, { ...facts, outcome: 'ok', result: 'The last check found the chain intact.' }, now);
  }
  // An older server keeps no outcome. It stamps a check that could not read
  // the index like a clean one, so this row says what is on record.
  return finish(
    base,
    {
      ...facts,
      outcome: 'ok',
      result: 'No break is on record since soc-ai started.',
      resultTitle: 'soc-ai keeps no result for a check that could not read the audit index.',
    },
    now,
  );
}

function nightlyEval(read: JobsRead, now: number): JobRow {
  const base = { id: 'eval', name: 'Nightly quality eval', to: '/config#quality' } as const;
  const enabled = switches(read.config, ['eval_nightly_enabled']);
  const hour = setting(read.config, 'eval_nightly_hour_utc');
  const schedule = typeof hour === 'number' ? `every day at ${String(hour).padStart(2, '0')}:00 UTC` : 'every day';
  const running = read.qualityRun.ok && read.qualityRun.data.running;
  const r = read.quality;
  if (!r.ok) {
    return finish(base, { enabled, intervalMinutes: 1440, running, lastRun: undefined, outcome: 'unknown', result: readFailure(r.error), schedule }, now);
  }
  const f = r.data.freshness;
  const facts = { enabled, intervalMinutes: 1440, running, lastRun: f.last_attempt_at, schedule };
  if (running) return finish(base, { ...facts, outcome: 'ok', result: 'An eval is in progress.' }, now);
  if (!f.last_attempt_at) return finish(base, { ...facts, outcome: 'never', result: 'No eval is on record.' }, now);
  if (f.last_exit_code === 0) {
    const newest = r.data.points[r.data.points.length - 1];
    return finish(
      base,
      {
        ...facts,
        outcome: 'ok',
        result: newest?.alarmed ? 'The last eval raised a quality alarm.' : 'The last eval wrote a trend point.',
      },
      now,
    );
  }
  if (f.last_exit_code === 2) {
    return finish(base, { ...facts, outcome: 'ok', result: 'The last eval found no alert to grade.', resultTitle: f.last_detail }, now);
  }
  return finish(base, { ...facts, outcome: 'failed', result: 'The last eval failed.', resultTitle: f.last_detail }, now);
}

function fmtSize(bytes: number): string {
  if (bytes >= 1 << 30) return `${(bytes / (1 << 30)).toFixed(1)} GiB`;
  if (bytes >= 1 << 20) return `${(bytes / (1 << 20)).toFixed(1)} MiB`;
  if (bytes >= 1 << 10) return `${(bytes / (1 << 10)).toFixed(0)} KiB`;
  return `${bytes} B`;
}

// A nightly host cron job writes the archive. 36 hours is one missed night and
// a margin for a slow run.
const BACKUP_STALE_MS = 36 * 3_600_000;

function backup(read: JobsRead, now: number): JobRow {
  const row = (state: JobState, lastRun: string | null | undefined, result: string): JobRow => ({
    id: 'backup',
    name: 'Nightly backup',
    schedule: 'host cron job',
    state,
    lastRun,
    result,
    resultTitle: null,
    to: '/config#maintenance',
  });
  const r = read.maintenance;
  if (!r.ok) return row('unknown', undefined, readFailure(r.error));
  // The backup runs outside soc-ai and has no switch here. No archive is no
  // evidence either way: the cron job can write to another directory.
  const newest = r.data.backups[0];
  if (!newest) return row('unknown', null, `soc-ai finds no archive in ${r.data.backups_dir}.`);
  const age = now - Date.parse(newest.modified);
  if (Number.isFinite(age) && age > BACKUP_STALE_MS) {
    return row('failed', newest.modified, `The newest archive is ${agoWords(newest.modified).replace(/ ago$/, '')} old.`);
  }
  return row('on', newest.modified, `The last backup wrote ${fmtSize(newest.size_bytes)}.`);
}

/** The rows, in a fixed order. */
export function jobRows(read: JobsRead, now = Date.now()): JobRow[] {
  return [
    autoInvestigate(read, now),
    dossier(read, now),
    discovery(read, now),
    audit(read, now),
    nightlyEval(read, now),
    backup(read, now),
  ];
}

// ---- render ----------------------------------------------------------------

export const JOB_COLOR: Record<JobState, string> = {
  on: '#3fb950',
  running: '#4b8bf5',
  off: '#8b949e',
  failed: '#f85149',
  unknown: '#f5a623',
};

function StateChip({ state }: { state: JobState }) {
  const color = JOB_COLOR[state];
  return (
    <span
      className="inline-flex w-fit items-center gap-1.5 rounded-chip border px-1.5 py-px text-[11px] font-semibold"
      style={{ color, borderColor: tint(color, 0.4), background: tint(color, 0.09) }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
      <span data-testid="job-state">{state}</span>
    </span>
  );
}

function LastRun({ iso }: { iso: string | null | undefined }) {
  if (iso === undefined) {
    return (
      <span data-testid="job-last-run" className="text-faint">
        unknown
      </span>
    );
  }
  const { text, title } = timeLabel(iso);
  return (
    <span data-testid="job-last-run" className="text-dim" title={title || undefined}>
      {text}
    </span>
  );
}

const GRID = 'md:grid md:grid-cols-[minmax(170px,220px)_88px_84px_1fr_auto] md:items-baseline md:gap-3';

export function StatusJobsPanel() {
  const read = useAsync(readJobs, [], { refetchInterval: 300_000 });
  const rows = read.data ? jobRows(read.data) : null;
  return (
    <Panel className="md:col-span-2">
      <PanelHeader
        icon={<CalendarClock size={16} />}
        title="Scheduled jobs"
        right={<Freshness at={read.lastUpdated} />}
      />
      {!rows ? (
        <LoadingState label="Reading the scheduled jobs" />
      ) : (
        <>
          <div
            aria-hidden
            className={`hidden border-b border-border px-[15px] py-1.5 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint ${GRID}`}
          >
            <span>Job</span>
            <span>State</span>
            <span>Last run</span>
            <span>Last result</span>
            <span />
          </div>
          <ul className="divide-y divide-border">
            {rows.map((r) => (
              <li
                key={r.id}
                data-testid="status-job"
                className={`flex flex-col gap-1.5 px-[15px] py-2.5 text-[13px] ${GRID}`}
              >
                <div className="min-w-0">
                  <div data-part="name" className="font-semibold text-text-2">
                    {r.name}
                  </div>
                  {r.schedule && <div className="text-[11.5px] text-faint">{r.schedule}</div>}
                </div>
                <StateChip state={r.state} />
                <LastRun iso={r.lastRun} />
                <div
                  data-testid="job-result"
                  className="min-w-0 break-words text-text-2"
                  title={r.resultTitle ?? undefined}
                >
                  {r.result}
                </div>
                <Link
                  to={r.to}
                  aria-label={`Open the ${r.name} setting`}
                  className="w-fit text-[12px] text-accent hover:underline"
                >
                  Setting
                </Link>
              </li>
            ))}
          </ul>
          <div className="border-t border-border px-[15px] py-2.5 text-[11.5px] leading-[1.55] text-faint">
            soc-ai runs these jobs with no operator. The Analytics panel shows the analytic sweep
            and the profile sweep. soc-ai keeps most of these times in memory. A restart clears
            them.
          </div>
        </>
      )}
    </Panel>
  );
}
