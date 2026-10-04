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

/** True when the loop that runs an analytic of this evaluator is on and has
 *  run at least once. null when the catalog is not read yet. */
export function loopRuns(
  catalog: HuntCatalog | null | undefined,
  evaluator: string | undefined,
): boolean | null {
  if (!catalog) return null;
  if (evaluator === 'profile') {
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

/** The status word, with the run state when the loop does not run it. */
export function statusLabel(status: string, running: boolean | null | undefined): string {
  if (running === false && (status === 'live' || status === 'shadow')) {
    return `${status}, not running`;
  }
  return status;
}

export const NOT_RUNNING_TITLE =
  'The sweep that runs this analytic is off, or it has not run yet. The analytic has read no document.';
