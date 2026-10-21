import type { AckGroupResult, EscalateGroupResult } from './api';
import { plural } from './plural';

// ---------------------------------------------------------------------------
// What a group ack or a group escalate is allowed to claim it did.
//
// These live here rather than in Alerts.tsx because they have two callers, and
// for a while only one of them knew that. The Alerts console's strip was
// rewritten as the write path learned to distinguish its outcomes — a case
// withheld from a duplicate, an alert Security Onion had merely acknowledged,
// a claim from an earlier escalate whose outcome is unknown, a case created
// with nothing attached. The investigation drawer's settled-action bar calls
// the SAME two endpoints and kept reporting "Escalated N of M events to a
// case", which is the pre-1.5 story: it read `escalated` and `total` and threw
// the rest away.
//
// So the drawer would call an empty case a successful escalate, and never
// named the case id an operator has to go and close. Alerts.tsx cannot be the
// home for the shared version — it renders the drawer, so importing back the
// other way is a cycle.
//
// The rule every clause below follows: one fact, one source, one sentence, or
// nothing at all. Four outcomes arriving as one number is what produced the
// original defect, where "17 already escalated" counted seventeen alerts that
// had no case while the one alert that really did collect a second case was
// reported as a clean escalate.
// ---------------------------------------------------------------------------

/** The tail both ack surfaces share: what is left, and what will never leave.
 *
 * Two different facts, and conflating them was the defect. `remaining` is work
 * this press did not get to, and another press will do it. `already_acked` is
 * work Security Onion has already recorded that its own index cannot hide from
 * a query, so those rows stay on screen no matter how many times the button is
 * pressed — an operator who is not told that reads a working button as a broken
 * one. */
export function ackTail(r: {
  capped: boolean;
  remaining?: number;
  already_acked?: number;
}): string {
  const parts: string[] = [];
  const remaining = r.remaining ?? 0;
  const already = r.already_acked ?? 0;
  if (already > 0) {
    parts.push(
      `${plural(already, 'alert')} already acknowledged in Security Onion. This index cannot hide them, so they stay listed`,
    );
  }
  if (remaining > 0) {
    parts.push(
      r.capped
        ? `${plural(remaining, 'alert')} left. Press again to continue`
        : `${plural(remaining, 'alert')} left`,
    );
  }
  return parts.length ? ` · ${parts.join(' · ')}` : '';
}

/** True when an ack press wrote to no alert: nothing acknowledged and no
 *  write failed. Such a press must not wear the success check
 *  (dogfood 2026-10-19, R2-D15). */
export function ackWroteNothing(r: Pick<AckGroupResult, 'acked' | 'failed'>): boolean {
  return r.acked === 0 && r.failed === 0;
}

/** True when an escalate press opened no case and no write failed. An empty
 *  case counts in `failed`, so it is a failure here. */
export function escalateWroteNothing(r: Pick<EscalateGroupResult, 'escalated' | 'failed'>): boolean {
  return r.escalated === 0 && r.failed === 0;
}

/** "The alert of X is", "The 3 alerts of X are", or, when the count is not
 *  the whole group, "3 alerts of X are". */
function subject(n: number, groupName: string, whole: boolean): string {
  if (whole) {
    return n === 1
      ? `The alert of ${groupName} is`
      : `The ${n.toLocaleString()} alerts of ${groupName} are`;
  }
  return `${plural(n, 'alert')} of ${groupName} ${n === 1 ? 'is' : 'are'}`;
}

/** The sentence for more alerts than one press reached. */
function leftSentence(remaining: number): string {
  return `${plural(remaining, 'alert')} left. Press again to continue.`;
}

/** What to say after acknowledging ONE group, wherever the button lives.
 *
 *  `unhidable` is the caller's knowledge that the index of the detection
 *  cannot search the acknowledged flag (the group row shows no counts), so an
 *  acknowledged alert stays listed under Hide acknowledged. */
export function ackMessage(
  r: AckGroupResult,
  groupName: string,
  opts: { unhidable?: boolean } = {},
): string {
  if (ackWroteNothing(r)) {
    // A second press. Before 2026-10-19 this read "Acknowledged 0 alerts in X"
    // under a green check, and said nothing of what the group still held.
    const already = r.already_acked ?? 0;
    const remaining = r.remaining ?? 0;
    const sentences =
      already > 0
        ? [`${subject(already, groupName, remaining === 0)} already acknowledged.`]
        : [`No alert of ${groupName} waits for an acknowledgement.`];
    sentences.push('soc-ai wrote nothing.');
    if (already > 0 && opts.unhidable) {
      sentences.push(
        already === 1
          ? 'The index of this detection cannot hide it. It stays listed.'
          : 'The index of this detection cannot hide them. They stay listed.',
      );
    }
    if (remaining > 0) sentences.push(leftSentence(remaining));
    return sentences.join(' ');
  }
  const parts = [`Acknowledged ${plural(r.acked, 'alert')} in ${groupName}`];
  if (r.failed) parts.push(`${plural(r.failed, 'event')} failed`);
  return parts.join(' · ') + ackTail(r);
}

/** What to say after an escalate press that opened no case and had no
 *  failure. Each skip is its own sentence, and the ledger's case ids are
 *  named (dogfood 2026-10-19, R2-D15, R2-I2). */
function escalateNothingMessage(r: EscalateGroupResult, groupName: string): string {
  const onCase = r.already_escalated ?? 0;
  const acked = r.already_acked ?? 0;
  const unresolved = r.unresolved ?? 0;
  const remaining = r.remaining ?? 0;
  const ids = (r.existing_cases ?? []).map((c) => c.id);
  // A count is the whole group only when it is the one skip and no press is
  // left to make.
  const kinds = [onCase, acked, unresolved].filter((n) => n > 0).length;
  const whole = kinds === 1 && remaining === 0;
  const sentences: string[] = [];
  if (onCase > 0) {
    if (onCase === 1 && ids.length === 1) {
      sentences.push(`${subject(1, groupName, whole)} already on case ${ids[0]}.`);
    } else {
      sentences.push(`${subject(onCase, groupName, whole)} already on a case.`);
      if (ids.length === 1) sentences.push(`The soc-ai record names case ${ids[0]}.`);
      if (ids.length > 1) sentences.push(`The soc-ai record names cases ${ids.join(', ')}.`);
    }
  }
  if (acked > 0) sentences.push(`${subject(acked, groupName, whole)} already acknowledged.`);
  if (unresolved > 0) {
    sentences.push(
      `${plural(unresolved, 'alert')} of ${groupName} ${unresolved === 1 ? 'has' : 'have'} an earlier escalate with an unknown outcome. soc-ai left ${unresolved === 1 ? 'it' : 'them'} alone.`,
    );
  }
  if (!sentences.length) sentences.push(`No alert of ${groupName} waits for a case.`);
  sentences.push('soc-ai opened no case.');
  if (remaining > 0) sentences.push(leftSentence(remaining));
  return sentences.join(' ');
}

/** What to say after escalating ONE group, wherever the button lives.
 *
 * Four different outcomes used to arrive as one number. "N events already
 * escalated, not opening a second case" counted every alert the press skipped,
 * including the ones Security Onion had merely acknowledged, so on the group
 * that produced this fix it claimed seventeen duplicate cases prevented where
 * not one of the seventeen had a case, while the single alert that really did
 * collect a second case was reported as a clean escalate.
 *
 * Each clause below is a separate fact with a separate source, so each gets its
 * own sentence or none at all. */
export function escalateMessage(r: EscalateGroupResult, groupName: string): string {
  if (escalateWroteNothing(r)) return escalateNothingMessage(r, groupName);
  const withheld = r.already_escalated ?? 0;
  const acked = r.already_acked ?? 0;
  const unresolved = r.unresolved ?? 0;
  const empty = r.empty_cases ?? [];
  const remaining = r.remaining ?? 0;
  const opened = r.escalated > 0 ? plural(r.escalated, 'case') : 'no cases';
  const ids = (r.cases ?? []).map((c) => c.id);
  const parts = [`Opened ${opened} for ${groupName}${ids.length ? `: ${ids.join(', ')}` : ''}`];
  if (r.failed > 0) parts.push(`${plural(r.failed, 'alert')} failed`);
  if (empty.length > 0) {
    // Security Onion made the case and attached nothing, so the alert is on no
    // case and an empty one is now in the queue. Name it: closing or reusing it
    // is a thing only the operator can do.
    parts.push(
      `${plural(empty.length, 'case')} created with nothing attached, left empty in Security Onion: ${empty.join(', ')}`,
    );
  }
  if (withheld > 0) {
    parts.push(`${plural(withheld, 'alert')} already on a case, no second case opened`);
    const existing = (r.existing_cases ?? []).map((c) => c.id);
    if (existing.length) {
      parts.push(`Existing ${existing.length === 1 ? 'case' : 'cases'}: ${existing.join(', ')}`);
    }
  }
  if (acked > 0) {
    parts.push(`${plural(acked, 'alert')} already acknowledged in Security Onion, skipped`);
  }
  if (unresolved > 0) {
    parts.push(
      `${plural(unresolved, 'alert')} from an earlier escalate whose outcome is unknown, left alone`,
    );
  }
  if (remaining > 0) {
    parts.push(`${plural(remaining, 'alert')} left${r.capped ? '. Press again to continue' : ''}`);
  }
  return parts.join(' · ');
}

/** The toast links for the cases an escalate opened, then for the cases its
 *  skipped alerts are already on. A case with no console URL is named in the
 *  message and gets no link. */
export function escalateLinks(r: EscalateGroupResult): Array<{ label: string; href: string }> {
  const seen = new Set<string>();
  return [...(r.cases ?? []), ...(r.existing_cases ?? [])]
    .filter((c): c is { id: string; url: string } => !!c.url)
    .filter((c) => !seen.has(c.id) && !!seen.add(c.id))
    .map((c) => ({ label: `Open case ${c.id}`, href: c.url }));
}

/** True when the escalate answer names a case id. The toast then stays until
 *  it is dismissed: a case id is something to copy. */
export function escalateNamesCase(r: EscalateGroupResult): boolean {
  return (r.cases?.length ?? 0) > 0 || (r.existing_cases?.length ?? 0) > 0;
}
