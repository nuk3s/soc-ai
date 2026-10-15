import type { AlertGroup, Verdict } from './types';

const SETTLED: ReadonlySet<string> = new Set([
  'true_positive',
  'needs_more_info',
  'inconclusive',
  'false_positive',
]);

/** The verdict a group counts under, and where it comes from. */
export interface GroupOutcome {
  /** null for a pipeline fallback with no settled verdict to count. */
  verdict: Verdict | null;
  conf: number | null;
  /** The run that holds the verdict. */
  invId: string | null;
  /** True when no run in the page window decided the verdict. The group
   *  keeps the older verdict that covers it. */
  inherited: boolean;
  /** The ISO time of the run behind an inherited verdict. */
  at: string | null;
}

/**
 * The verdict a detection group counts under: on the Dashboard breakdown, in
 * the verdict filter and sort of the Alerts list, in the "untriaged" count and
 * the "Needs decision" chip, and on the row pill.
 *
 * Runs made inside the page window decide the verdict (owner rule,
 * 2026-10-14). The server names the worst verdict among those runs as
 * `windowVerdict`. One true positive among later false positives is the alert
 * the analyst has to see (prod 2026-10-13). A group with no run in the window
 * keeps its standing verdict, the verdict of the newest run of the rule, and
 * that verdict is inherited. An untriaged group stays untriaged.
 *
 * A pipeline fallback with no window verdict counts under no verdict. Its
 * stored needs_more_info is not a verdict the pipeline reached.
 *
 * An older server sends no `windowVerdict` key. The group then counts under
 * the worst verdict when that is worse than the standing verdict.
 */
export function outcomeOf(g: AlertGroup): GroupOutcome {
  const none = { inherited: false, at: null };
  if (g.windowVerdict === undefined) {
    if (g.worstVerdict && SETTLED.has(g.worstVerdict)) {
      return { verdict: g.worstVerdict as Verdict, conf: g.worstConf ?? null, invId: g.worstInvId ?? null, ...none };
    }
    if (g.fallback) return { verdict: null, conf: null, invId: g.invId ?? null, ...none };
    return { verdict: g.verdict, conf: g.conf, invId: g.invId ?? null, ...none };
  }
  if (g.windowVerdict && SETTLED.has(g.windowVerdict)) {
    return {
      verdict: g.windowVerdict as Verdict,
      conf: g.windowConf ?? null,
      invId: g.windowInvId ?? null,
      ...none,
    };
  }
  if (g.fallback) return { verdict: null, conf: null, invId: g.invId ?? null, ...none };
  if (g.verdict === 'untriaged') return { verdict: 'untriaged', conf: null, invId: g.invId ?? null, ...none };
  return { verdict: g.verdict, conf: g.conf, invId: g.invId ?? null, inherited: true, at: g.verdictAt ?? null };
}

/** The verdict a group counts under. See {@link outcomeOf}. */
export function groupOutcome(g: AlertGroup): Verdict | null {
  return outcomeOf(g).verdict;
}

/** True when the group has no run in the page window and keeps an older
 *  verdict. See {@link outcomeOf}. */
export function isInheritedOutcome(g: AlertGroup): boolean {
  return outcomeOf(g).inherited;
}

/**
 * Optimistic hide for drawer-initiated group acks. The ES aggregation behind
 * the alerts feed takes seconds-to-minutes to reflect a fresh ack, so a group
 * the analyst just acknowledged would otherwise sit in the queue looking
 * un-acked after a successful "Executed ✓" (dogfood 2026-07-15). `ackedAt`
 * maps rule name → epoch-ms of the session-local ack; a group whose latest
 * event is NEWER than the ack re-surfaces (new events → new decision).
 */
export function hideOptimisticallyAcked(
  groups: AlertGroup[],
  ackedAt: Record<string, number>,
  hideAcked: boolean,
): AlertGroup[] {
  if (!hideAcked) return groups;
  return groups.filter((g) => {
    const at = ackedAt[g.name];
    if (!at) return true;
    const latest = g.latestTs ? Date.parse(g.latestTs) : Number.NaN;
    return Number.isFinite(latest) && latest > at;
  });
}
