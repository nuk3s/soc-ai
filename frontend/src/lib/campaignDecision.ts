// ---------------------------------------------------------------------------
// The decision of a campaign, read off the payload the same way on each page.
//
// A campaign has no decision, or one of closed, authorized and case. Only an
// active campaign (open or ended) waits on one. A merged campaign passes no
// decision on, and a withdrawn one has nothing to decide. A server of an
// earlier release sends no decision field: the console then states no
// decision, so it never claims that a campaign waits.
// ---------------------------------------------------------------------------

import type {
  CampaignChange,
  CampaignDecision,
  CampaignDecisionType,
  CampaignStatus,
} from './api';

/** The decision state a page draws. `unknown`: the server sends no decision,
 *  or the campaign is not active. */
export type DecisionState = 'unknown' | 'waits' | CampaignDecisionType;

/** True for a campaign the store holds as active: open or ended. */
export function isActiveCampaign(status: CampaignStatus): boolean {
  return status === 'open' || status === 'ended';
}

/** The decision state of a campaign payload, a list row or a link. `decision`
 *  is the decision object of the detail or the type of a row. */
export function decisionState(c: {
  status: CampaignStatus;
  decision?: CampaignDecision | CampaignDecisionType | null;
}): DecisionState {
  if (!isActiveCampaign(c.status) || c.decision === undefined) return 'unknown';
  if (c.decision === null) return 'waits';
  return typeof c.decision === 'string' ? c.decision : c.decision.type;
}

/** The newest acknowledgement that followed the decision that stands. An
 *  acknowledgement of an earlier close, before the campaign opened again,
 *  does not count. */
export function acknowledgementOf(
  changes: readonly CampaignChange[] | undefined,
  decision: Pick<CampaignDecision, 'at'>,
): CampaignChange | null {
  const since = Date.parse(decision.at);
  let best: CampaignChange | null = null;
  for (const c of changes ?? []) {
    if (c.type !== 'acknowledged') continue;
    const at = Date.parse(c.at);
    if (Number.isNaN(at) || (!Number.isNaN(since) && at < since)) continue;
    if (!best || at > Date.parse(best.at)) best = c;
  }
  return best;
}

/** True when a closed campaign has alerts left to acknowledge. The
 *  acknowledgement of a close runs after the close, and a restart in that
 *  minute loses the rest. Three cases: the close asked for the
 *  acknowledgement and no acknowledgement followed it, the acknowledgement
 *  that followed it failed for some alerts, or the close scope still counts
 *  alerts. `scopeAlerts` is null when the grid did not answer. */
export function remainsToAcknowledge(
  changes: readonly CampaignChange[] | undefined,
  decision: Pick<CampaignDecision, 'at'>,
  scopeAlerts: number | null | undefined,
): boolean {
  const ack = acknowledgementOf(changes, decision);
  // The newest close is the one that stands.
  let decided: CampaignChange | null = null;
  for (const c of changes ?? []) {
    if (c.type !== 'decided' || c.detail.decision !== 'closed') continue;
    if (!decided || Date.parse(c.at) > Date.parse(decided.at)) decided = c;
  }
  const asked = decided?.detail.acknowledge === true;
  return (asked && !ack) || (ack?.detail.failed ?? 0) > 0 || (scopeAlerts ?? 0) > 0;
}

/** True when a campaign holds the investigation of this link: the campaign is
 *  active and the verdict of the investigation does not differ. The analyst
 *  then decides once, on the campaign, and no action of the investigation
 *  waits. The server applies the same rule to the needs-you count. A link of
 *  an earlier server carries no decision field, and that server counts the
 *  actions, so the console then counts them too.
 *
 *  An authorized campaign holds no investigation through the link: the mark
 *  of the authorization holds each investigation inside, and an investigation
 *  outside keeps normal handling. Its actions wait, and it is a Needs you
 *  item of its own. */
export function campaignHolds(
  link: { status: CampaignStatus; differs: boolean; decision?: CampaignDecisionType | null } | null | undefined,
): boolean {
  return (
    !!link &&
    link.decision !== undefined &&
    link.decision !== 'authorized' &&
    isActiveCampaign(link.status) &&
    !link.differs
  );
}
