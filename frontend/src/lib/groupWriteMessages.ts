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

/** What to say after acknowledging ONE group, wherever the button lives. */
export function ackMessage(r: AckGroupResult, groupName: string): string {
  const parts = [`Acknowledged ${plural(r.acked, 'alert')} in ${groupName}`];
  if (r.failed) parts.push(`${plural(r.failed, 'event')} failed`);
  return parts.join(' · ') + ackTail(r);
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
  const withheld = r.already_escalated ?? 0;
  const acked = r.already_acked ?? 0;
  const unresolved = r.unresolved ?? 0;
  const empty = r.empty_cases ?? [];
  const remaining = r.remaining ?? 0;
  const opened = r.escalated > 0 ? plural(r.escalated, 'case') : 'no cases';
  const parts = [`Opened ${opened} for ${groupName}`];
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
