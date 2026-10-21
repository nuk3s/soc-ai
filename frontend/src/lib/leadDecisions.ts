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

/** The chip word for each decision. The store keeps the word `promoted`.
 *  The console names the act by its control, so the chip reads "investigation
 *  opened" (owner, 2026-10-07). */
export const DECISION_WORD: Record<string, string> = {
  dismissed: 'dismissed',
  reopened: 'reopened',
  promoted: 'investigation opened',
  closed_by_hunt: 'closed',
  held: 'needs a decision',
  kept_open: 'kept open',
  formed_from_backtest: 'backtest replay',
};

/** The rule soc-ai closes a lead by when its hunt investigated its findings
 *  (soc_ai.store.leads.settle_after_hunt), as a clause after "when". The hunt
 *  investigates a threat finding that names a host, an address, a user or a
 *  domain. An observation has no verdict. The pages said "every finding" in
 *  one place and "every threat finding" in another (dogfood 2026-10-19,
 *  V1-H3). One wording, here. */
export const CLOSE_RULE_CLAUSE = 'every threat finding of the hunt that names an entity has a verdict';

/** The reason the store records on a close by the verdict of a hunt finding
 *  (soc_ai.store.leads.PROMOTED_FINDING_REASON). */
export const FINDING_VERDICT_REASON = 'finding_verdict';

/** The chip word of one decision. A close on the verdicts of a hunt is stored
 *  as `promoted`, and the chip read "investigation opened" beside the words
 *  "soc-ai closed the lead" (dogfood 2026-10-19, V1-H2). */
export function decisionWord(d: { action: string; reason?: string | null }): string {
  if (d.action === 'promoted' && d.reason === FINDING_VERDICT_REASON) return DECISION_WORD.closed_by_hunt;
  return DECISION_WORD[d.action] ?? d.action;
}

/** The decision the server records on a lead that formed from backtest
 *  replays only (soc_ai.store.leads.BACKTEST_DECISION). */
export const BACKTEST_DECISION = 'formed_from_backtest';

/** True when the lead formed from backtest replays only. The list sends the
 *  flag. The lead page also reads the decision, for an older list. */
export function formedFromBacktest(lead: {
  formed_from_backtest?: boolean;
  decisions?: { action: string }[];
}): boolean {
  return (
    lead.formed_from_backtest === true ||
    (lead.decisions ?? []).some((d) => d.action === BACKTEST_DECISION)
  );
}

export function decisionsOf(lead: LeadDecisionFields): LeadDecision[] | null {
  return Array.isArray(lead.decisions) ? lead.decisions : null;
}

/** The sentence that says why a finished hunt did not close the lead, or null. */
export function holdSentence(lead: LeadDecisionFields): string | null {
  if (lead.hold_sentence) return lead.hold_sentence;
  if (lead.hold_reason) return HOLD_SENTENCE[lead.hold_reason] ?? null;
  return null;
}

/** True for a hand the product signs with: auto-hunt, the catalog sweep, or
 *  any `system:` actor (system:hunt, system:self-heal, system:catalog). */
export function isSystemActor(by: string | null | undefined): boolean {
  if (!by) return false;
  return by === AUTO_HUNT_ACTOR || by === CATALOG_SWEEP_ACTOR || by.startsWith('system:');
}

/** The hand the catalog sweep signs its hunts with. */
export const CATALOG_SWEEP_ACTOR = 'hunt-catalog';

/** The hand that took a decision, in the words the page uses for it. A system
 *  actor reads as the product: the timeline printed "system:hunt" (R3-D5). */
export function actorOf(by: string | null, socAi: string): string {
  if (!by) return '';
  return by === socAi || isSystemActor(by) ? socAi : by;
}
