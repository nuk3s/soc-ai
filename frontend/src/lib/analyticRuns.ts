import type { HuntCatalog } from './api';
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
 *  not run it yet, or the loop is off. `undefined` and `null` are unknown. */
export type RunState = boolean | 'waiting' | null | undefined;

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
  }
  return shown;
}

export const NOT_RUNNING_TITLE =
  'The sweep that runs this analytic is off, or it has not run yet. The analytic has read no document.';

export const WAITING_TITLE =
  'The sweep that runs this analytic is on. It has not run this analytic yet. The next sweep runs it.';
