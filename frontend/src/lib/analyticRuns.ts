import type { HuntCatalog, HuntCatalogSpec, LoopHealth, PriorCoverage } from './api';
import { ago } from './timeRange';

// ---------------------------------------------------------------------------
// Whether the loop that runs an analytic is on and has run.
//
// Two loops run analytics. The catalog sweep runs the `match` analytics and
// is off by default. The profile sweep runs the `profile` analytics and is on
// by default. A grid with the catalog sweep off showed sixteen analytics with
// a green "live" dot, a legend that said the sweep runs them, and a hits panel
// that said no analytic matched a document the sweeps read. None of them had
// run. One reader here answers the question for the tab, the hits panel and
// the Operate panel, from GET /hunt-catalog.
// ---------------------------------------------------------------------------

/** The evaluators the hourly profile sweep runs. A `profile` analytic reads a
 *  stored baseline. A `model` analytic runs a tier 3 detector in the same
 *  sweep. The backend holds the same set as PRIOR_SWEEP_EVALUATORS. */
export const PROFILE_SWEEP_EVALUATORS: readonly string[] = ['profile', 'model'];

/** True when the profile sweep runs an analytic of this evaluator. */
export function runsInProfileSweep(evaluator: string | undefined): boolean {
  return evaluator !== undefined && PROFILE_SWEEP_EVALUATORS.includes(evaluator);
}

/** True when a hunt can run an analytic of this evaluator. `t_run_analytic`
 *  runs a `match` analytic as a grid query. It returns could_not_run for a
 *  `profile` or a `model` analytic, because the profile sweep answers those.
 *  A hunt started on one spent its first step on that error and then
 *  rebuilt the hypothesis by hand for nine minutes. */
export function huntCanRun(evaluator: string | undefined): boolean {
  return evaluator === 'match';
}

/** Why a live analytic that a hunt cannot run has no hunt control. */
export const NO_HUNT_LINE =
  'A hunt cannot run this analytic. The profile sweep runs it every hour.';

/** True when the loop that runs an analytic of this evaluator is on and has
 *  run at least once. null when the catalog is not read yet. */
export function loopRuns(
  catalog: HuntCatalog | null | undefined,
  evaluator: string | undefined,
): boolean | null {
  if (!catalog) return null;
  if (runsInProfileSweep(evaluator)) {
    // An older backend sends no profile-sweep fields. Unknown, never "not running".
    if (catalog.last_prior_run_at === undefined) return null;
    return (catalog.prior_sweeps_enabled ?? true) && !!catalog.last_prior_run_at;
  }
  return catalog.sweeps_enabled && catalog.last_sweep_at !== null;
}

/** The sentences that say a loop does not run. Empty when both loops run. */
export function sweepsNotice(catalog: HuntCatalog | null | undefined): string[] {
  if (!catalog) return [];
  const out: string[] = [];
  const matchRuns = loopRuns(catalog, 'match');
  const profileRuns = loopRuns(catalog, 'profile');
  if (!matchRuns) {
    if (!catalog.sweeps_enabled) {
      out.push(
        catalog.last_sweep_at
          ? `Sweeps are off. The match analytics do not run. The last sweep ran ${ago(catalog.last_sweep_at)}.`
          : profileRuns === false
            ? 'Sweeps are off. No analytic has run.'
            : 'Sweeps are off. No match analytic has run.',
      );
    } else {
      out.push('Sweeps are on. No sweep has run yet.');
    }
  }
  if (profileRuns === false) {
    out.push(
      catalog.prior_sweeps_enabled === false
        ? 'The profile sweep is off. The profile analytics do not run.'
        : 'The profile sweep has not run yet.',
    );
  }
  return out;
}

/** The run state of an analytic: the loop runs it, the loop is on and has
 *  not run it yet, or the loop is off. `undefined` and `null` are unknown.
 *
 *  Three states come from the analytic's own newest run. `failed`: the run
 *  failed and read no document. `blind`: the run matched nothing that the
 *  analytic reads. `unmeasured`: the profile sweep scored the analytic
 *  against no host. A green "live" over any of the three was a false
 *  all-clear (dogfood 2026-10-19). */
export type RunState =
  | boolean
  | 'waiting'
  | 'failed'
  | 'blind'
  | 'unmeasured'
  | null
  | undefined;

/** True when the loop that runs an analytic of this evaluator is on and has
 *  not run yet. The analytic then waits for the next sweep. */
export function loopWaits(
  catalog: HuntCatalog | null | undefined,
  evaluator: string | undefined,
): boolean {
  if (!catalog) return false;
  if (runsInProfileSweep(evaluator)) {
    return (catalog.prior_sweeps_enabled ?? true) && catalog.last_prior_run_at === null;
  }
  return catalog.sweeps_enabled && catalog.last_sweep_at === null;
}

/** The run state for a list row, from the catalog. */
export function runState(
  catalog: HuntCatalog | null | undefined,
  evaluator: string | undefined,
): RunState {
  const runs = loopRuns(catalog, evaluator);
  return runs === false && loopWaits(catalog, evaluator) ? 'waiting' : runs;
}

/** The entity evaluations of one profile run, every coverage state counted. */
export function evaluations(c: PriorCoverage): number {
  return c.measured + c.learning + c.blind + c.not_applicable;
}

/** The run state of one analytic: the loop's state, then its newest run.
 *
 *  A loop that is off stays off. A failed newest run reads failed even
 *  when the loop has never completed a run: the profile sweep skips a
 *  wake while the grid is down, and that is a failure the record names. */
export function specRunState(
  catalog: HuntCatalog | null | undefined,
  spec: HuntCatalogSpec | null | undefined,
  evaluator: string | undefined = spec?.evaluator,
): RunState {
  const loop = runState(catalog, evaluator);
  if (!spec || loop === false || loop === null || loop === undefined) return loop;
  if (spec.last_error_text || spec.last_error) return 'failed';
  if (loop !== true) return loop;
  if (runsInProfileSweep(spec.evaluator)) {
    return spec.coverage && evaluations(spec.coverage) === 0 ? 'unmeasured' : true;
  }
  return spec.blind ? 'blind' : true;
}

/** The failed run of an analytic in one sentence for its row. Null when the
 *  newest run did not fail. An older backend sends no sentence, and the row
 *  then says that the run failed. */
export function failureLine(spec: HuntCatalogSpec | null | undefined, at: string | null | undefined): string | null {
  if (!spec || !(spec.last_error_text || spec.last_error)) return null;
  const when = at ? ` ${ago(at)}` : '';
  const why = spec.last_error_text ?? 'The application log holds the reason.';
  return `The last run failed${when}. ${why}`;
}

/** The window a loop's counts cover: "in 24 h", or "in the last 3 h" after
 *  a restart cut the record of the profile sweep short. */
function countWindow(countedSince: string | null | undefined, now: number): string {
  if (!countedSince) return 'in 24 h';
  const hours = Math.round((now - Date.parse(countedSince)) / 3_600_000);
  if (!Number.isFinite(hours) || hours >= 24) return 'in 24 h';
  return `in the last ${Math.max(1, hours)} h`;
}

/** One result line for one loop: the newest run, the failed runs of the day
 *  and the first failure of the open streak. Null for a loop with no run on
 *  record. The Status page read a green "Sweeps on" over 25 failed runs, and
 *  after one good sweep the outage left no trace (R5-D3, R5-I3). */
export function loopResultLine(health: LoopHealth | null | undefined, now = Date.now()): string | null {
  if (!health) return null;
  const when = ago(health.last_run_at, now);
  const parts: string[] = [];
  if (health.last_outcome === 'failed') parts.push(`Last sweep failed ${when}.`);
  else if (health.last_outcome === 'skipped') parts.push(`Last sweep did not run ${when}.`);
  else parts.push(`Last sweep completed ${when}.`);
  const failing = health.last_outcome !== 'ok';
  if (failing && health.last_error_text) parts.push(health.last_error_text);
  const runs = health.runs_24h;
  const noun = runs === 1 ? 'run' : 'runs';
  const window = countWindow(health.counted_since, now);
  if (health.failed_24h > 0) {
    const verb = health.last_outcome === 'skipped' ? 'did not complete' : 'failed';
    parts.push(`${health.failed_24h} of ${runs} ${noun} ${verb} ${window}.`);
  } else {
    parts.push(`${runs} of ${runs} ${noun} completed ${window}.`);
  }
  if (failing && health.failing_since) parts.push(`First failure ${ago(health.failing_since, now)}.`);
  return parts.join(' ');
}

// The screen words of the stored analytic fields (dogfood 2026-10-06 C6).
// "tier", "evaluator" and "scope" needed the manual. The stored values do not
// change: the address bar and the API keep them.

/** The status words. A candidate reads "draft": it is written and never ran. */
export const STATUS_WORD: Record<string, string> = {
  candidate: 'draft',
  live: 'live',
  shadow: 'shadow',
  retired: 'retired',
};
/** Where the analytic comes from. The stored field is `tier`. */
export const SOURCE_WORD: Record<string, string> = {
  shipped: 'shipped with soc-ai',
  local: 'written here',
};
/** How the analytic decides. The stored field is `evaluator`. */
export const METHOD_WORD: Record<string, string> = {
  match: 'query',
  profile: 'baseline',
  model: 'learned',
};
/** What one hit is about. The stored field is `scope_kind`. */
export const APPLIES_WORD: Record<string, string> = {
  host: 'host',
  ip: 'address',
  user: 'account',
  cloud_identity: 'cloud account',
  mailbox: 'mailbox',
  decoy: 'decoy',
  rule: 'rule',
  dataset: 'dataset',
};

const word = (map: Record<string, string>, key: string | undefined): string =>
  key ? (map[key] ?? key.replace(/_/g, ' ')) : '';

export const statusWord = (status: string | undefined): string => word(STATUS_WORD, status);
export const sourceWord = (tier: string | undefined): string => word(SOURCE_WORD, tier);
export const methodWord = (evaluator: string | undefined): string => word(METHOD_WORD, evaluator);
export const appliesWord = (scope: string | undefined): string => word(APPLIES_WORD, scope);

/** "every hour", "every 2 h", "every 30 min", "every day". */
export function intervalWords(minutes: number | null | undefined): string {
  if (!minutes || minutes <= 0) return '';
  if (minutes === 60) return 'every hour';
  if (minutes === 1440) return 'every day';
  if (minutes % 60 === 0) return `every ${minutes / 60} h`;
  return `every ${minutes} min`;
}

/** A window in minutes as words: 1440 reads "24 h", 43200 reads "30 days". */
export function windowWords(minutes: number | null | undefined): string {
  if (minutes == null || minutes <= 0) return '';
  if (minutes >= 2880 && minutes % 1440 === 0) return `${minutes / 1440} days`;
  if (minutes >= 60 && minutes % 60 === 0) return `${minutes / 60} h`;
  return `${minutes} min`;
}

/** The status word, with the run state when the loop does not run it. An
 *  analytic the loop has not run yet waits for the next sweep. It read
 *  "shadow, not running" after "Run in shadow", and looked broken. */
export function statusLabel(status: string, running: RunState, every = 'every hour'): string {
  const shown = statusWord(status);
  if (status === 'live' || status === 'shadow') {
    if (running === 'waiting') {
      return `${shown}, waits for the next sweep${every ? `, ${every}` : ''}`;
    }
    if (running === false) return `${shown}, not running`;
    if (running === 'failed') return `${shown}, last run failed`;
    if (running === 'blind') return `${shown}, blind on the last run`;
    if (running === 'unmeasured') return `${shown}, measured no host`;
  }
  return shown;
}

export const NOT_RUNNING_TITLE =
  'The sweep that runs this analytic is off, or it has not run yet. The analytic has read no document.';

export const WAITING_TITLE =
  'The sweep that runs this analytic is on. It has not run this analytic yet. The next sweep runs it.';

export const FAILED_TITLE =
  'The newest run of this analytic failed. It read no document. The line under the status says why.';

export const BLIND_RUN_TITLE =
  'The newest run matched nothing that this analytic reads. The telemetry is absent. A zero here does not show a clean grid.';

export const UNMEASURED_TITLE =
  'The newest profile sweep scored this analytic against no host. A zero here does not show a clean network.';
