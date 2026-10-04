// ---------------------------------------------------------------------------
// The decisions on one lead, oldest first.
//
// The lead kept one decision row. A dismiss after a reopen wrote over the
// first dismissal, a reopened lead read its old dismissal as current, and a
// promotion was on no timeline. The server now returns every decision in
// `decisions`, and the page states each one in order.
//
// The fields ride beside the LeadDetail type and not inside it, so this file
// is the one place that reads them.
// ---------------------------------------------------------------------------

/** One decision as the server states it. */
export interface LeadDecision {
  action: 'dismissed' | 'reopened' | 'promoted' | 'closed_by_hunt' | 'held' | string;
  at: string | null;
  by: string | null;
  reason: string | null;
  note: string | null;
  hunt_id: string | null;
  investigation_id: string | null;
}

/** The lead fields this file reads. An older server sends none of them. */
export interface LeadDecisionFields {
  decisions?: LeadDecision[];
  hold_reason?: string | null;
  hold_sentence?: string | null;
}

/** The hand the settle rule and the loop sign with on the server. */
export const AUTO_HUNT_ACTOR = 'auto-hunt';

/** Why the settle rule left a clean hunt's lead open. The server sends the
 *  sentence too. These are the words for a server that sends the code only. */
export const HOLD_SENTENCE: Record<string, string> = {
  partial_read: 'The hunt could not read all evidence.',
  earlier_threat: 'An earlier hunt found a threat.',
};

/** The chip word for each decision. */
export const DECISION_WORD: Record<string, string> = {
  dismissed: 'dismissed',
  reopened: 'reopened',
  promoted: 'promoted',
  closed_by_hunt: 'closed',
  held: 'needs a decision',
};

export function decisionsOf(lead: LeadDecisionFields): LeadDecision[] | null {
  return Array.isArray(lead.decisions) ? lead.decisions : null;
}

/** The sentence that says why a finished hunt did not close the lead, or null. */
export function holdSentence(lead: LeadDecisionFields): string | null {
  if (lead.hold_sentence) return lead.hold_sentence;
  if (lead.hold_reason) return HOLD_SENTENCE[lead.hold_reason] ?? null;
  return null;
}

/** The hand that took a decision, in the words the page uses for it. */
export function actorOf(by: string | null, socAi: string): string {
  if (!by) return '';
  return by === AUTO_HUNT_ACTOR || by === socAi ? socAi : by;
}
