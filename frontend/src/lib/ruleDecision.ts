// ---------------------------------------------------------------------------
// The words and the helpers of the rule decisions.
//
// soc-ai gives a false positive verdict, and a guard holds the automatic
// acknowledge. The alert stays open on the grid. A rule decision lets the
// analyst acknowledge the open false positives of one rule at once. Every
// surface of a rule decision reads its words here: the row of Needs you, the
// rule page, the decision bar, the action card and the command palette.
// ---------------------------------------------------------------------------

import {
  getNeedsYouItems,
  getRuleDecisions,
  ruleDecisionHref,
  ruleKeyOf,
  type RuleDecisionDay,
  type RuleDecisionGroup,
  type RuleDecisionGroupName,
  type RuleDecisionListEntry,
  type RuleDecisionPlan,
  type RuleDecisionSample,
} from './api';
import { utcStamp } from './timeRange';

/** One rule that the command palette can open. */
export interface RuleTarget {
  key: string;
  name: string;
  href: string;
  /** The second line of the hit. */
  detail: string;
}

const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

/** "471 open false positives". */
export function openFalsePositivesWords(n: number): string {
  return `${n.toLocaleString()} open false ${plural(n, 'positive', 'positives')}`;
}

/** The key and the name of a list entry. An entry with no key takes the key
 *  of its name. Null when the entry names no rule. */
function entryRule(entry: RuleDecisionListEntry): { key: string; name: string } | null {
  const name = entry.ruleName?.trim() ?? '';
  const key = entry.ruleKey?.trim() || (name ? ruleKeyOf(name) : '');
  if (!key) return null;
  return { key, name: name || key };
}

/** The rules that the command palette finds: each rule with open false
 *  positives in Needs you, then each standing decision in force. One hit for
 *  each rule. A source that does not answer gives no hit. */
export async function paletteRules(): Promise<RuleTarget[]> {
  const [items, decisions] = await Promise.allSettled([
    Promise.resolve().then(() => getNeedsYouItems()),
    Promise.resolve().then(() => getRuleDecisions()),
  ]);
  const out = new Map<string, RuleTarget>();
  if (items.status === 'fulfilled') {
    for (const item of items.value?.items ?? []) {
      if (item.type !== 'rule' || out.has(item.id)) continue;
      out.set(item.id, {
        key: item.id,
        name: item.title,
        href: item.href || ruleDecisionHref(item.id),
        detail: `Rule decision. ${openFalsePositivesWords(item.count ?? 0)}.`,
      });
    }
  }
  if (decisions.status === 'fulfilled') {
    for (const entry of decisions.value?.standing ?? []) {
      const rule = entryRule(entry);
      if (!rule || out.has(rule.key)) continue;
      out.set(rule.key, {
        key: rule.key,
        name: rule.name,
        href: ruleDecisionHref(rule.key),
        detail: entry.endsAt
          ? `Rule decision. A standing decision is in force until ${utcStamp(entry.endsAt)}.`
          : 'Rule decision. A standing decision is in force.',
      });
    }
  }
  return [...out.values()];
}

/** The rules of `rules` whose name or detail holds the query. */
export function matchRules(rules: readonly RuleTarget[], q: string): RuleTarget[] {
  const query = q.trim().toLowerCase();
  if (query.length < 2) return [];
  return rules.filter((r) => r.name.toLowerCase().includes(query) || r.key.toLowerCase() === query);
}

// ── The rule page ───────────────────────────────────────────────────────────

/** The label above the rule name, and the title of a page with no name. */
export const RULE_PAGE_LABEL = 'Rule decision';

/** The heading of each group on the page. */
export const RULE_GROUP_TITLE: Record<RuleDecisionGroupName, string> = {
  confident: 'False positives with checked evidence',
  weak: 'False positives with weak evidence',
};

/** What each group is, in one or two sentences. */
export const RULE_GROUP_ABOUT: Record<RuleDecisionGroupName, string> = {
  confident: 'The evidence guards passed. A guard held the automatic acknowledge for the reasons below.',
  weak: 'soc-ai is not sure of these verdicts. Read the samples before you acknowledge them.',
};

/** A group with no open false positive. */
export const RULE_GROUP_EMPTY: Record<RuleDecisionGroupName, string> = {
  confident: 'No open false positive of this rule has checked evidence.',
  weak: 'No open false positive of this rule has weak evidence.',
};

/** The label of a hold reason when the server sends no label. The server
 *  gives the label of each reason. The console keeps these for a sample whose
 *  reason the group does not list. */
const REASON_WORDS: Record<string, string> = {
  high_stakes: 'The rule is high stakes',
  below_threshold: 'The confidence is under the limit',
  no_investigation: 'The investigation retrieved no evidence',
  uncited: 'The report cites no evidence',
  oracle_dissent: 'The Oracle disagrees with the verdict',
  earlier_true_positive: 'An earlier investigation of the alert is a true positive',
  earlier_runs_unread: 'soc-ai did not read the earlier investigations of the alert',
  auto_ack_failed: 'The automatic acknowledge failed',
  auto_ack_off: 'The automatic acknowledge is off',
};

/** The words of a hold reason: the label of the group, else the label of
 *  the console, else the reason as the server sent it. */
export function reasonLabel(code: string | null | undefined, groups: readonly RuleDecisionGroup[]): string | null {
  if (!code) return null;
  for (const group of groups) {
    const found = group.reasons.find((r) => r.code === code);
    if (found?.label) return found.label;
  }
  return REASON_WORDS[code] ?? code;
}

/** A count of machines: the server sends a number, or the list itself. */
export function machineCount(value: number | readonly unknown[] | null | undefined): number | null {
  if (Array.isArray(value)) return value.length;
  return typeof value === 'number' ? value : null;
}

/** "471 open false positives of this rule: 470 with checked evidence, 1 with weak evidence." */
export function ruleSummaryWords(confident: number, weak: number): string {
  const total = confident + weak;
  if (total === 0) return 'No open false positive of this rule waits on you.';
  const parts = [`${confident.toLocaleString()} with checked evidence`];
  if (weak > 0) parts.push(`${weak.toLocaleString()} with weak evidence`);
  return `${openFalsePositivesWords(total)} of this rule: ${parts.join(', ')}.`;
}

/** The facts of a group in one line: the machines at each end and the span. */
export function groupFactsWords(group: RuleDecisionGroup): string {
  const sources = machineCount(group.sources);
  const destinations = machineCount(group.destinations);
  const out: string[] = [];
  if (sources !== null && destinations !== null) {
    out.push(
      `${sources.toLocaleString()} source ${plural(sources, 'machine', 'machines')} and ` +
        `${destinations.toLocaleString()} destination ${plural(destinations, 'machine', 'machines')}.`,
    );
  }
  if (group.firstEvent && group.lastEvent && group.firstEvent !== group.lastEvent) {
    out.push(`Events from ${utcStamp(group.firstEvent)} to ${utcStamp(group.lastEvent)}.`);
  } else if (group.firstEvent || group.lastEvent) {
    out.push(`Event ${utcStamp(group.firstEvent ?? group.lastEvent)}.`);
  }
  return out.join(' ');
}

/** The read of the grid, when the grid did not answer or soc-ai did not
 *  read it yet. Null when the last read is good. */
export function gridReadWords(gridAnswered: boolean, readAt: string | null): string | null {
  if (!readAt) {
    return 'soc-ai did not read the grid for these alerts yet. Each alert counts as open.';
  }
  if (gridAnswered) return null;
  return `The grid did not answer. The counts are from the read of ${utcStamp(readAt)}.`;
}

/** "The grid holds 1,204 open alerts of this rule in the last 30 days." Null
 *  when not counted. The window comes from the server. */
export function openAlertsWords(n: number | null | undefined, days?: number | null): string | null {
  if (typeof n !== 'number') return null;
  const window = typeof days === 'number' && days > 0 ? ` in the last ${days} ${plural(days, 'day', 'days')}` : '';
  return `The grid holds ${n.toLocaleString()} open ${plural(n, 'alert', 'alerts')} of this rule${window}.`;
}

/** The alarm of a rule that also holds a true positive verdict. */
export function truePositiveAlarmWords(n: number): string {
  return n === 1
    ? 'This rule also holds 1 true positive verdict. Read it before a decision.'
    : `This rule also holds ${n.toLocaleString()} true positive verdicts. Read them before a decision.`;
}

/** The words of one bar of the chart. */
export function dayWords(day: RuleDecisionDay): string {
  const parts = [`${day.confident.toLocaleString()} with checked evidence`];
  if (day.weak > 0) parts.push(`${day.weak.toLocaleString()} with weak evidence`);
  const total = day.confident + day.weak;
  return `${day.day} UTC: ${total.toLocaleString()} ${plural(total, 'investigation', 'investigations')}, ${parts.join(', ')}.`;
}

const DAY_MS = 86_400_000;
/** The most days the chart draws. An older day is outside the chart. */
export const MAX_CHART_DAYS = 400;

/** The days of the chart from the first to the last, with each day that the
 *  server does not send as zero. The axis is then linear in time. */
export function fillDays(days: readonly RuleDecisionDay[]): RuleDecisionDay[] {
  const parsed = days
    .map((d) => ({ d, t: Date.parse(`${d.day}T00:00:00Z`) }))
    .filter((p) => !Number.isNaN(p.t))
    .sort((a, b) => a.t - b.t);
  if (parsed.length === 0) return [];
  const byDay = new Map<number, RuleDecisionDay>();
  for (const p of parsed) {
    const was = byDay.get(p.t);
    byDay.set(
      p.t,
      was ? { day: was.day, confident: was.confident + p.d.confident, weak: was.weak + p.d.weak } : p.d,
    );
  }
  const last = parsed[parsed.length - 1].t;
  const first = Math.max(parsed[0].t, last - (MAX_CHART_DAYS - 1) * DAY_MS);
  const out: RuleDecisionDay[] = [];
  for (let t = first; t <= last; t += DAY_MS) {
    out.push(byDay.get(t) ?? { day: new Date(t).toISOString().slice(0, 10), confident: 0, weak: 0 });
  }
  return out;
}

/** The samples of one group, in the order of the server. */
export function samplesOf(samples: readonly RuleDecisionSample[], group: RuleDecisionGroupName): RuleDecisionSample[] {
  return samples.filter((s) => s.group === group);
}

// ── The decision bar ────────────────────────────────────────────────────────

/** The days of a standing decision. The server reads the setting
 *  `rule_decision_days`, 30 by default. */
export const STANDING_DAYS = 30;

/** The main button: "Acknowledge the 470 false positives with checked evidence". With
 *  the weak ones it names the whole count. A rule with none that has checked
 *  evidence offers the group with weak evidence. */
export function acknowledgeLabel(confident: number, weak: number, includeWeak: boolean): string {
  // Each open false positive is on the machines of a true positive: the
  // button waits for the third choice, and it names no count of 0.
  if (confident + weak === 0) return 'Acknowledge the false positives';
  if (confident === 0 && weak > 0) {
    return weak === 1
      ? 'Acknowledge the 1 false positive with weak evidence'
      : `Acknowledge the ${weak.toLocaleString()} false positives with weak evidence`;
  }
  if (includeWeak && weak > 0) {
    const n = confident + weak;
    return n === 1 ? 'Acknowledge the 1 false positive' : `Acknowledge the ${n.toLocaleString()} false positives`;
  }
  return confident === 1
    ? 'Acknowledge the 1 false positive with checked evidence'
    : `Acknowledge the ${confident.toLocaleString()} false positives with checked evidence`;
}

/** The check box of the weak group. */
export function includeWeakLabel(weak: number): string {
  return `Also the ${weak.toLocaleString()} with weak evidence`;
}

export const INCLUDE_WEAK_HINT = 'soc-ai is not sure of these verdicts. Read the samples first.';

const alertsWords = (n: number) => `${n.toLocaleString()} ${plural(n, 'alert', 'alerts')}`;

/** The plan of the choice that the bar offers, or null. */
export function planFor(
  plans: readonly RuleDecisionPlan[] | null | undefined,
  includeWeak: boolean,
  includeTruePositivePairs = false,
): RuleDecisionPlan | null {
  return (
    (plans ?? []).find(
      (p) => p.includeWeak === includeWeak && (p.includeTruePositivePairs ?? false) === includeTruePositivePairs,
    ) ?? null
  );
}

/** The open false positives on the machines of a true positive, and what the
 *  main button does with them. */
export function truePositivePairsWords(n: number): string {
  return n === 1
    ? '1 of the open false positives is on the machines of a true positive. The main button leaves it out.'
    : `${n.toLocaleString()} of the open false positives are on the machines of a true positive. ` +
        'The main button leaves them out.';
}

/** The third choice: the false positives on the machines of the true positive. */
export function includeTruePositivePairsLabel(n: number): string {
  return `Also the ${n.toLocaleString()} on the machines of the true positive`;
}

export const INCLUDE_TRUE_POSITIVE_PAIRS_HINT =
  'A true positive verdict stands on these machines. Read it before you acknowledge them.';

/** The mark of a day of a true positive on the chart. */
export const TRUE_POSITIVE_DAY_WORDS = 'A true positive of this rule is on this day.';

/** What the main button writes, before the press: the alerts of the
 *  investigations, the alerts that inherit, and the alerts that stay open.
 *  With no plan the count of the alerts is unknown. */
export function acknowledgeWrites(
  n: number,
  plan: RuleDecisionPlan | null = null,
  opts: { known?: boolean; scanMax?: number | null } = {},
): string {
  const tail = 'Each investigation records this decision. No verdict changes.';
  if (!plan) {
    const what = n === 1 ? '1 investigation' : `${n.toLocaleString()} investigations`;
    const unknown = opts.known === false ? ' The grid did not answer, so the count of the alerts is unknown.' : '';
    return (
      `Writes: soc-ai acknowledges the alerts of ${what} and the alerts that inherit their verdict in Security Onion.` +
      `${unknown} ${tail}`
    );
  }
  const parts = [
    `Writes: soc-ai acknowledges ${alertsWords(plan.alerts)} of these investigations and ` +
      `${alertsWords(plan.inherit)} that inherit their verdict in Security Onion.`,
  ];
  if (plan.held > 0) {
    parts.push(
      plan.held === 1
        ? '1 alert of this rule stays open: a verdict of its own holds it.'
        : `${plan.held.toLocaleString()} alerts of this rule stay open: a verdict of their own holds them.`,
    );
  }
  if (plan.capped) {
    const max = typeof opts.scanMax === 'number' ? ` at ${alertsWords(opts.scanMax)}` : '';
    parts.push(`The scan of the grid stopped${max}. More alerts can inherit the verdict.`);
  }
  parts.push(tail);
  return parts.join(' ');
}

/** The second choice. */
export const STANDING_LABEL = `Acknowledge these, and each later false positive of this rule for ${STANDING_DAYS} days`;

/** What the second choice writes, and what stays guarded. */
export function standingWrites(n: number): string {
  const what = n === 1 ? '1 investigation' : `${n.toLocaleString()} investigations`;
  return (
    `Writes: the same acknowledge of ${what} now. For ${STANDING_DAYS} days, soc-ai also acknowledges each later ` +
    'false positive of this rule. A later verdict with weak evidence still waits for you. ' +
    'A true positive verdict on the rule ends the decision.'
  );
}

/** "Held: {reason}." with one period. A label of the server ends with a
 *  period, and the sample read "alert.." (dogfood 2026-11-19, D17). */
export function heldWords(reason: string): string {
  return `Held: ${reason.trim().replace(/\.+$/, '')}.`;
}

/** Why the console offers no standing decision. */
export function standingRefusedWords(why: string | null): string {
  return `soc-ai offers no standing decision for this rule. ${why?.trim() || 'The server gives no reason.'}`;
}

export const NOTE_LABEL = 'Note';
export const NOTE_HINT = 'The note is optional. The record of the decision keeps it.';

/** A standing decision in force. */
export function standingInForceWords(s: { by: string; at: string; endsAt: string; acknowledged: number }): string {
  return (
    `A standing decision is in force until ${utcStamp(s.endsAt)}. ${s.by} made it at ${utcStamp(s.at)}. ` +
    `soc-ai acknowledged ${s.acknowledged.toLocaleString()} later false ${plural(s.acknowledged, 'positive', 'positives')} under it.`
  );
}

export const END_STANDING_LABEL = 'End the standing decision';
export const END_STANDING_WRITES =
  'Writes: soc-ai ends the standing decision. Each later false positive of this rule waits for you again.';

/** The progress of a decision that soc-ai still writes. */
export function progressWords(alerts: number | null): string {
  const so = typeof alerts === 'number' && alerts > 0 ? ` ${alerts.toLocaleString()} acknowledged so far.` : '';
  return `soc-ai acknowledges the alerts in Security Onion.${so}`;
}

/** The result of a decision: "Acknowledged 1,204 alerts. 0 failed." A failed
 *  decision states the failure first. */
export function resultWords(r: { state: string; alerts: number | null; failed: number | null }): string {
  const alerts = r.alerts ?? 0;
  const failed = r.failed ?? 0;
  const counts = `Acknowledged ${alerts.toLocaleString()} ${plural(alerts, 'alert', 'alerts')}. ${failed.toLocaleString()} failed.`;
  return r.state === 'failed' ? `The decision failed. ${counts} Press a button to try again.` : counts;
}

/** Why a standing decision ended, in words. */
export function endCauseWords(cause: string | null | undefined): string | null {
  if (!cause) return null;
  switch (cause) {
    case 'expired':
      return `The ${STANDING_DAYS} days ended.`;
    case 'analyst':
    case 'ended':
    case 'ended_by_analyst':
      return 'An analyst ended it.';
    case 'true_positive':
      return 'A true positive verdict on the rule ended it.';
    default:
      return cause;
  }
}

/** One record of the history of the rule, in words. */
export function historyWords(r: {
  decision: string;
  by: string;
  at: string;
  state: string;
  alerts: number | null;
  failed: number | null;
  endedAt: string | null;
  endCause: string | null;
}): string {
  const what =
    r.decision === 'standing'
      ? `${r.by} made a standing decision at ${utcStamp(r.at)}.`
      : `${r.by} acknowledged the false positives at ${utcStamp(r.at)}.`;
  const result = r.state === 'acknowledging' ? progressWords(r.alerts) : resultWords(r);
  const cause = endCauseWords(r.endCause);
  const ended = r.endedAt ? ` It ended at ${utcStamp(r.endedAt)}.${cause ? ` ${cause}` : ''}` : '';
  return `${what} ${result}${ended}`;
}

// ── The action card of an investigation ─────────────────────────────────────

/** The line beside the open Acknowledge of an open false positive. */
export function ruleOpenWords(n: number): string {
  return `This rule has ${openFalsePositivesWords(n)}.`;
}

/** The link of that line. */
export const DECIDE_ON_RULE = 'Decide on the rule';

/** The head of the actions of an open false positive: "This false positive is
 *  1 of 29 open on its rule." The link names the step. */
export function ruleDecisionHeadWords(n: number): string {
  return `This false positive is 1 of ${n.toLocaleString()} open on its rule.`;
}

/** The receipt of an acknowledge that a rule decision wrote. */
export function ruleReceiptWords(at: string | null | undefined): string {
  return at
    ? `The analyst acknowledged this with the rule decision of ${utcStamp(at)}.`
    : 'The analyst acknowledged this with a rule decision.';
}

/** The link of the receipt. */
export const OPEN_RULE_DECISION = 'Open the rule decision';

// ── The standing decisions on Needs you ─────────────────────────────────────

export const STANDING_FOLD_TITLE = 'Standing rule decisions';

/** One standing decision in force, in words. */
export function standingEntryWords(e: Pick<RuleDecisionListEntry, 'endsAt' | 'acknowledged' | 'by' | 'at'>): string {
  const parts: string[] = [];
  parts.push(e.endsAt ? `In force until ${utcStamp(e.endsAt)}.` : 'In force.');
  if (typeof e.acknowledged === 'number') {
    parts.push(
      `soc-ai acknowledged ${e.acknowledged.toLocaleString()} later false ${plural(e.acknowledged, 'positive', 'positives')} under it.`,
    );
  }
  if (e.by && e.at) parts.push(`${e.by} made it at ${utcStamp(e.at)}.`);
  return parts.join(' ');
}

/** The rule of a list entry for the fold: its name and its page. */
export function standingEntryRule(e: RuleDecisionListEntry): { name: string; href: string } | null {
  const rule = entryRule(e);
  return rule ? { name: rule.name, href: ruleDecisionHref(rule.key) } : null;
}
