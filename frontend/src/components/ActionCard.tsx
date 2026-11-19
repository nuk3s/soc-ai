import { AlertTriangle, ArrowUpRight, Check, Loader2, MessageSquare, Network, RotateCcw, Triangle, X, type LucideIcon } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { getActionScope, type ActionScope, type InvestigationCampaign } from '../lib/api';
import { campaignHolds } from '../lib/campaignDecision';
import { ACTION_CAMPAIGN_NOTE, OPEN_CAMPAIGN, campaignDecidedNoWait } from '../lib/campaignWords';
import { utcStamp } from '../lib/timeRange';
import type { ActionTag, CaseLink, RecommendedAction } from '../lib/types';
import type { InvestigationRuleDecision } from '../lib/api';
import { DECIDE_ON_RULE, OPEN_RULE_DECISION, ruleOpenWords, ruleReceiptWords } from '../lib/ruleDecision';
import { RULE_ICON } from './rule/RuleRowFacts';

// ---------------------------------------------------------------------------
// One recommended action, from the recommendation to the record.
//
// Dogfood 2026-10-06 found four faults on this card:
//
// - "Acknowledge alert" acknowledged every alert of the rule from the last 7
//   days on one click (first hour S2). The card now states the scope before
//   the click, asks for a confirm, and offers "Acknowledge this alert only".
// - Escalate and Dismiss acted on the first click (investigation S2). Every
//   write and every dismissal now has the confirm step Override verdict has.
// - Dismiss changed one tab and nothing else (first hour S4). The server
//   stores it with the actor and the time, and the card offers an undo.
// - "Executed · anonymous" had no time and could not tell an auto-ack from a
//   colleague (investigation S3). The record names who and when.
// ---------------------------------------------------------------------------

const ACTION_ICON: Record<ActionTag, LucideIcon> = {
  ack: Check,
  escalate: Triangle,
  comment: MessageSquare,
};
const ACTION_ICON_COLOR: Record<ActionTag, string> = {
  ack: '#7ba893',
  escalate: '#f04438',
  comment: '#4b8bf5',
};
const ACTION_TAG_COLOR: Record<ActionTag, { color: string; bg: string }> = {
  ack: { color: '#8b94a3', bg: '#161c25' },
  escalate: { color: '#f04438', bg: 'rgba(240,68,56,.12)' },
  comment: { color: '#4b8bf5', bg: 'rgba(75,139,245,.12)' },
};

/** The word on the button that starts each write. "Execute" named nothing. */
export const ACTION_VERB: Record<ActionTag, string> = {
  ack: 'Acknowledge',
  escalate: 'Escalate to case',
  comment: 'Add comment',
};

/** What a write does, when the server did not say. Escalate and comment have
 *  one target each, so the card can state it without a round trip. */
const DEFAULT_SCOPE: Record<ActionTag, string> = {
  ack: 'Acknowledge this alert in Security Onion.',
  escalate: 'Open one Security Onion case for this alert.',
  comment: 'Add a comment to the Security Onion case this investigation opened.',
};

/** What the escalate of a promoted finding does, while the server counts the
 *  alerts that the case attaches. The server then states the whole effect. */
export const FINDING_CASE_SCOPE = 'Open one Security Onion case for this finding.';
export const FINDING_CASE_COUNTING =
  'Open one Security Onion case for this finding. soc-ai is counting the alerts that the case attaches.';
export const FINDING_CASE_COUNT_FAILED =
  'Open one Security Onion case for this finding. soc-ai could not count the alerts that the case attaches.';

/** The dismiss confirm. The row of the pending-action list asks the same. */
export const DISMISS_CONFIRM_TEXT =
  'Dismiss this recommended action. soc-ai records your name and the time. You can undo it.';
/** What an escalate does when the alert is already on a case. The execute
 *  route opens no second case and records the action as done. */
export const NO_SECOND_CASE =
  'soc-ai opens no second case. The press records this action as done.';

/** "The alert is already on cases A, B." A list the grid did not confirm
 *  names its cases as a finding, like the Alerts escalate confirm. */
export function casesHead(count: number, complete: boolean): string {
  const noun = count === 1 ? 'case' : 'cases';
  return complete ? `The alert is already on ${noun}` : `soc-ai found the alert on ${noun}`;
}

/** The case sentence as plain text, for a confirm. */
export function casesSentence(cases: readonly CaseLink[], complete: boolean): string {
  return `${casesHead(cases.length, complete)} ${cases.map((c) => c.id).join(', ')}.`;
}

/** The case sentence with each case a link to its page in the Security Onion
 *  console. A case with no page reads as its id. */
export function CasesLine({
  cases,
  complete,
  className,
}: {
  cases: readonly CaseLink[];
  complete: boolean;
  className?: string;
}) {
  return (
    <div data-testid="action-cases" className={className}>
      {casesHead(cases.length, complete)}{' '}
      {cases.map((c, i) => (
        <span key={c.id}>
          {i > 0 && ', '}
          {c.url ? (
            <a
              href={c.url}
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-accent hover:underline"
            >
              {c.id}
            </a>
          ) : (
            <span className="font-mono">{c.id}</span>
          )}
        </span>
      ))}
      .
    </div>
  );
}
/** The ack scope while the server counts, and when it could not count. */
export const ACK_COUNTING = 'soc-ai is counting the alerts this ack covers.';
export const ACK_COUNT_FAILED =
  'soc-ai could not count the alerts. The ack covers the unacknowledged alerts of this rule from the last 7 days.';

/** "2026-10-19 03:12 UTC": the date, clock time and zone of an ISO instant,
 *  or null when it does not parse. A bare "03:12" named no day and no zone
 *  (dogfood 2026-10-19, R2-D17). The form is the one of the investigation
 *  page (utcStamp): the page showed one event in three forms (AA5). */
export function clockTime(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return utcStamp(d.toISOString());
}

/** "Executed by auto-ack at 03:12": who or what wrote, and when. A record
 *  with no time names the actor alone. */
export function executedLine(by: string, at?: string | null): string {
  const when = clockTime(at);
  return when ? `Executed by ${by} at ${when}` : `Executed by ${by}`;
}

/** "Dismissed by alice at 11:09". */
export function dismissedLine(by: string, at?: string | null): string {
  const when = clockTime(at);
  return when ? `Dismissed by ${by} at ${when}` : `Dismissed by ${by}`;
}

/** The label of the confirm button: the write, with its count. An escalate
 *  of an alert already on a case writes nothing, and the press records the
 *  action as done. */
export function confirmLabel(tag: ActionTag, scope: ActionScope | null, onCase = false): string {
  if (tag === 'ack') {
    if (scope?.scope === 'group' && scope.count != null) {
      return scope.count === 1 ? 'Acknowledge 1 alert' : `Acknowledge ${scope.count} alerts`;
    }
    return 'Acknowledge this alert';
  }
  if (tag === 'escalate') {
    if (onCase) return 'Record as done';
    // The case of a finding also attaches and marks the alerts it cites.
    if (scope?.scope === 'finding' && scope.count) {
      return scope.count === 1
        ? 'Open the case and attach 1 alert'
        : `Open the case and attach ${scope.count} alerts`;
    }
    return 'Open the case';
  }
  return 'Add the comment';
}

export type ActionDecision = 'approved' | 'executing' | 'failed' | 'dismissing';

export interface ActionDismissalState {
  by: string;
  at: string | null;
}

export function ActionCard({
  action,
  index,
  invId,
  decision,
  message,
  executedBy,
  dismissal,
  dismissError,
  onExecute,
  onDismiss,
  onUndoDismiss,
  disabledReason,
  lockedReason,
  confirmRequest,
  cases,
  casesComplete = false,
  findingCase = false,
  campaign = null,
  ruleDecision = null,
}: {
  action: RecommendedAction;
  /** The position of the action in the report. The server keys on it. */
  index: number;
  invId: string;
  decision?: ActionDecision;
  message?: string;
  /** The current user name, for the record of a write made from this tab. */
  executedBy?: string;
  /** The standing dismissal: the server's, or the one this tab just made. */
  dismissal?: ActionDismissalState | null;
  /** Why the last dismissal or undo did not land. */
  dismissError?: string | null;
  onExecute: (scope: 'group' | 'alert', opts?: { retry?: boolean }) => void;
  onDismiss: () => void;
  onUndoDismiss: () => void;
  /** Set when the action has no Security Onion target (a promoted finding).
   *  The write button is off with this as its tooltip. Dismiss still works. */
  disabledReason?: string;
  /** Set when a newer run replaced this one. Every button is off. */
  lockedReason?: string;
  /** A new value opens the write confirm: the chat asked for this action. */
  confirmRequest?: number;
  /** The cases the alert is already on. An escalate names and links each
   *  one, and a press then opens no second case (V3-N2). */
  cases?: readonly CaseLink[];
  /** False when the grid did not confirm the case list. */
  casesComplete?: boolean;
  /** The run is a promoted finding. Its escalate opens a case from the
   *  finding, and the card says so. */
  findingCase?: boolean;
  /** The campaign of the investigation. When the campaign holds it, the card
   *  names the campaign and sends the analyst there. The write stays. */
  campaign?: InvestigationCampaign | null;
  /** Set when the investigation is an open false positive. The open
   *  Acknowledge states the open false positives of its rule and links the
   *  rule page. */
  ruleDecision?: InvestigationRuleDecision | null;
}) {
  const Icon = ACTION_ICON[action.tag];
  const tagStyle = ACTION_TAG_COLOR[action.tag];
  const [confirm, setConfirm] = useState<'write' | 'dismiss' | null>(null);
  const [scope, setScope] = useState<ActionScope | null>(null);
  const [scopeState, setScopeState] = useState<'idle' | 'loading' | 'error'>('idle');

  // The system already carried this out (e.g. auto-ack). Render it done — never
  // offer the analyst an Approve/Execute button for an already-applied action.
  const applied = action.applied === true && !decision;
  // A closed action: the server closed it with a note and nobody executed it.
  // A backtest replay closes every action this way ("Not executable. This run
  // is a backtest replay."). It reads grey, never as a green write.
  const closedNote =
    applied && action.appliedNote && action.appliedNote !== 'Already acknowledged' && !action.appliedBy
      ? action.appliedNote
      : null;
  const dismissed = !!dismissal && !applied && decision !== 'approved';
  const eff = applied ? 'approved' : decision;
  const pending =
    !applied &&
    !dismissed &&
    (!decision || decision === 'failed' || decision === 'dismissing');
  // The card builds the campaign sentence, with its link, from the campaign
  // of the investigation. The server sends the same sentence as `note` with
  // the code `campaign`, so the card states it once.
  const ownCampaignNote = !!campaign && campaignHolds(campaign);
  // A campaign with a decision in force asks for nothing (OW4): the card
  // states the decision in place of "Open the case on the campaign."
  const decidedNoWait = ownCampaignNote ? campaignDecidedNoWait(campaign) : null;
  // The server states why a write can act against an analyst verdict. The
  // row of the pending-action list reads the same rule (R1-I1 follow-up).
  const blockedReason = action.blockedReason || undefined;
  // The Escalate of an investigation that a campaign holds: the one case of
  // the activity opens on the campaign. The server blocks the write, and the
  // card states the block with the link of the campaign. It is no button.
  const campaignCase =
    action.tag === 'escalate' && !!blockedReason && (action.noteCode === 'campaign' || ownCampaignNote);
  const campaignHref = action.noteHref?.trim() || (campaign ? `/campaigns/${campaign.id}` : null);
  const serverNote =
    action.note && action.note.trim() && !(action.noteCode === 'campaign' && (ownCampaignNote || campaignCase))
      ? action.note.trim()
      : null;
  const writeOffReason = lockedReason ?? disabledReason ?? blockedReason;
  const canWrite = pending && !writeOffReason;

  useEffect(() => {
    if (confirmRequest != null && canWrite) setConfirm('write');
    // canWrite is read at the time of the request.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [confirmRequest]);

  // State the scope before the click. Only an ack needs the server: its plan
  // depends on the grid. The other two have one target each.
  useEffect(() => {
    // An ack and the case of a finding write to more than one alert. The
    // server states how many before the click.
    const counted = action.tag === 'ack' || (action.tag === 'escalate' && findingCase);
    if (!canWrite || !counted) return;
    let live = true;
    setScopeState('loading');
    getActionScope(invId, index)
      .then((s) => {
        if (!live) return;
        setScope(s ?? null);
        setScopeState('idle');
      })
      .catch(() => live && setScopeState('error'));
    return () => {
      live = false;
    };
    // A failed press can leave the finding with no recorded result. The
    // server then answers the blocked state, so the read runs again.
  }, [canWrite, action.tag, findingCase, invId, index, decision]);

  // The alert is already on a case. The escalate states it and links each
  // case. The execute route opens no second case.
  const onCases = action.tag === 'escalate' && cases && cases.length > 0 ? cases : null;
  const scopeSentence = onCases
    ? NO_SECOND_CASE
    : action.tag === 'ack'
      ? scope?.sentence ??
        (scopeState === 'loading'
          ? ACK_COUNTING
          : scopeState === 'error'
            ? ACK_COUNT_FAILED
            : DEFAULT_SCOPE.ack)
      : action.tag === 'escalate' && findingCase
        ? scope?.sentence ??
          (scopeState === 'loading'
            ? FINDING_CASE_COUNTING
            : scopeState === 'error'
              ? FINDING_CASE_COUNT_FAILED
              : FINDING_CASE_SCOPE)
        : DEFAULT_SCOPE[action.tag];
  const groupAck = action.tag === 'ack' && scope?.scope === 'group';
  // An earlier press on this finding recorded no result. A press opens no
  // case, so the one control is "Try again", behind its own confirm.
  const retryCase = action.tag === 'escalate' && findingCase && scope?.retry === true;

  const base = dismissed || closedNote
    ? { border: '#2a3645', bg: '#0c0f15' }
    : eff === 'failed'
      ? { border: 'rgba(240,68,56,.35)', bg: 'rgba(240,68,56,.05)' }
      : eff === 'approved'
        ? { border: 'rgba(63,185,80,.32)', bg: 'rgba(63,185,80,.05)' }
        : { border: '#1c232e', bg: '#0b0e13' };

  const btn =
    'flex items-center gap-1.5 rounded-control border px-4 py-2 text-[13px] font-semibold disabled:cursor-not-allowed disabled:opacity-50';

  return (
    <div
      data-testid={`action-card-${index}`}
      className="rounded-panel border p-[14px_15px] transition-opacity"
      style={{ borderColor: base.border, background: base.bg, opacity: dismissed ? 0.7 : 1 }}
    >
      <div className="flex items-start gap-[11px]">
        <span className="mt-px flex" style={{ color: ACTION_ICON_COLOR[action.tag] }}>
          <Icon size={16} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-[14px] font-semibold">{action.title}</span>
            <span
              className="rounded-chip px-1.5 py-[1.5px] font-mono text-[10px] uppercase"
              style={{ color: tagStyle.color, background: tagStyle.bg }}
            >
              {action.tag}
            </span>
          </div>
          <div className="mt-1 text-[12.5px] leading-[1.5] text-dim">{action.rationale}</div>
        </div>
      </div>

      {decision === 'failed' && message && (
        <div className="mt-[10px] pl-[31px] font-mono text-[11.5px] leading-[1.5] text-danger">
          {message}
        </div>
      )}

      {dismissError && (
        <div role="alert" className="mt-[10px] pl-[31px] text-[12px] leading-[1.5] text-danger">
          {dismissError}
        </div>
      )}

      {dismissed ? (
        <div data-testid="action-dismissed" className="mt-[11px] flex flex-wrap items-center gap-2 pl-[31px] text-[12.5px]">
          <span className="font-semibold text-dim">
            {`✕ ${dismissedLine(dismissal!.by, dismissal!.at)}.`}
          </span>
          <button
            onClick={onUndoDismiss}
            disabled={decision === 'dismissing' || !!lockedReason}
            title={lockedReason}
            className="flex items-center gap-1 font-semibold text-accent hover:underline disabled:opacity-50"
          >
            <RotateCcw size={12} /> Undo
          </button>
        </div>
      ) : pending ? (
        <>
          {onCases && (
            <CasesLine
              cases={onCases}
              complete={casesComplete}
              className="mt-[10px] pl-[31px] text-[12px] leading-[1.5] text-text-2"
            />
          )}
          {/* The scope of a write the card offers. The case of a held
              investigation opens on the campaign, so the card states no scope. */}
          {!campaignCase && (
            <div
              data-testid="action-scope"
              className={`${onCases ? 'mt-1' : 'mt-[10px]'} pl-[31px] text-[12px] leading-[1.5] text-text-2`}
            >
              {scopeSentence}
            </div>
          )}
          {action.pendingNote && (
            <div className="mt-1 pl-[31px] text-[12px] leading-[1.5] text-faint">
              {action.pendingNote}
            </div>
          )}
          {/* An open false positive: one decision for the whole rule. */}
          {action.tag === 'ack' && ruleDecision && ruleDecision.count > 0 && (
            <div
              data-testid="action-rule-decision"
              className="mt-1 flex flex-wrap items-baseline gap-x-2 gap-y-0.5 pl-[31px] text-[12px] leading-[1.5] text-text-2"
            >
              <span className="min-w-0 break-words">
                <RULE_ICON size={11} aria-hidden className="mr-1 inline-block align-[-1px] text-dim" />
                {ruleOpenWords(ruleDecision.count)}
              </span>
              <Link
                to={ruleDecision.href}
                className="inline-flex flex-none items-center gap-0.5 font-semibold text-accent hover:underline"
              >
                {DECIDE_ON_RULE}
                <ArrowUpRight size={12} aria-hidden />
              </Link>
            </div>
          )}
          {/* An ack the record calls done and the grid does not show. The
              card offers it again and names the earlier write. */}
          {action.appliedBy && (
            <div data-testid="action-earlier-write" className="mt-1 pl-[31px] text-[12px] leading-[1.5] text-faint">
              Earlier write: {executedLine(action.appliedBy, action.appliedAt).replace(/^Executed /, '')}.
            </div>
          )}
          {lockedReason && (
            <div className="mt-1 pl-[31px] text-[12px] leading-[1.5] text-warn">{lockedReason}</div>
          )}
          {campaignCase && (
            <div
              data-testid="action-campaign-case"
              className="mt-1 flex flex-wrap items-baseline gap-x-2 gap-y-0.5 pl-[31px] text-[12px] leading-[1.5] text-text-2"
            >
              <span className="min-w-0 break-words">
                <Network size={11} aria-hidden className="mr-1 inline-block align-[-1px] text-dim" />
                {ownCampaignNote && campaign && (
                  <>
                    {ACTION_CAMPAIGN_NOTE.before}
                    <span className="font-semibold">{campaign.title.trim()}</span>
                    {'. '}
                  </>
                )}
                {decidedNoWait ?? blockedReason}
              </span>
              {campaignHref && (
                <Link
                  to={campaignHref}
                  className="inline-flex flex-none items-center gap-0.5 font-semibold text-accent hover:underline"
                >
                  {OPEN_CAMPAIGN}
                  <ArrowUpRight size={12} aria-hidden />
                </Link>
              )}
            </div>
          )}
          {ownCampaignNote && campaign && !campaignCase && (
            <div
              data-testid="action-campaign"
              className="mt-1 flex flex-wrap items-baseline gap-x-2 gap-y-0.5 pl-[31px] text-[12px] leading-[1.5] text-text-2"
            >
              <span className="min-w-0 break-words">
                <Network size={11} aria-hidden className="mr-1 inline-block align-[-1px] text-dim" />
                {ACTION_CAMPAIGN_NOTE.before}
                <span className="font-semibold">{campaign.title.trim()}</span>
                {decidedNoWait ? `. ${decidedNoWait}` : ACTION_CAMPAIGN_NOTE.after}
              </span>
              <Link
                to={`/campaigns/${campaign.id}`}
                className="inline-flex flex-none items-center gap-0.5 font-semibold text-accent hover:underline"
              >
                {OPEN_CAMPAIGN}
                <ArrowUpRight size={12} aria-hidden />
              </Link>
            </div>
          )}
          {/* A note of the server that the card builds no sentence for: a
              code the console does not know, or a campaign note with no
              campaign link. The card states it as plain text. */}
          {serverNote && (
            <div data-testid="action-note" className="mt-1 break-words pl-[31px] text-[12px] leading-[1.5] text-text-2">
              {serverNote}
            </div>
          )}
          {!lockedReason && blockedReason && !campaignCase && (
            <div data-testid="action-blocked" className="mt-1 pl-[31px] text-[12px] leading-[1.5] text-warn">
              {blockedReason}
            </div>
          )}
          {confirm === 'write' ? (
            <div data-testid="action-confirm" className="ml-[31px] mt-[11px] rounded-[7px] border px-3 py-2.5" style={{ borderColor: 'rgba(245,166,35,.35)', background: 'rgba(245,166,35,.07)' }}>
              <div className="mb-2.5 flex items-start gap-2 text-[12.5px] leading-[1.5] text-warn">
                <AlertTriangle size={13} className="mt-px flex-none" />
                <span>
                  {retryCase
                    ? scope?.retrySentence ?? scopeSentence
                    : onCases
                      ? `${casesSentence(onCases, casesComplete)} ${scopeSentence}`
                      : `This writes to Security Onion. ${scopeSentence}`}
                </span>
              </div>
              <div className="flex flex-wrap gap-2">
                <button
                  onClick={() => {
                    setConfirm(null);
                    if (retryCase) onExecute('group', { retry: true });
                    else onExecute('group');
                  }}
                  className={`${btn} border-success-btn-border bg-success-btn text-[#eafff2] hover:bg-[#22824c]`}
                >
                  <Check size={15} /> {retryCase ? 'Try again' : confirmLabel(action.tag, scope, !!onCases)}
                </button>
                {groupAck && (
                  <button
                    onClick={() => {
                      setConfirm(null);
                      onExecute('alert');
                    }}
                    className={`${btn} border-border-strong bg-surface-3 text-text-2 hover:text-text`}
                  >
                    Acknowledge this alert only
                  </button>
                )}
                <button
                  onClick={() => setConfirm(null)}
                  className={`${btn} border-border-strong bg-surface-3 text-text-2 hover:text-text`}
                >
                  Cancel
                </button>
              </div>
            </div>
          ) : confirm === 'dismiss' ? (
            <div data-testid="dismiss-confirm" className="ml-[31px] mt-[11px] rounded-[7px] border px-3 py-2.5" style={{ borderColor: 'rgba(245,166,35,.35)', background: 'rgba(245,166,35,.07)' }}>
              <div className="mb-2.5 flex items-start gap-2 text-[12.5px] leading-[1.5] text-warn">
                <AlertTriangle size={13} className="mt-px flex-none" />
                <span>{DISMISS_CONFIRM_TEXT}</span>
              </div>
              <div className="flex flex-wrap gap-2">
                <button
                  onClick={() => {
                    setConfirm(null);
                    onDismiss();
                  }}
                  className={`${btn} border-danger bg-[rgba(240,68,56,.1)] text-[#fca5a5] hover:bg-[rgba(240,68,56,.18)]`}
                >
                  <X size={15} /> Confirm dismiss
                </button>
                <button
                  onClick={() => setConfirm(null)}
                  className={`${btn} border-border-strong bg-surface-3 text-text-2 hover:text-text`}
                >
                  Cancel
                </button>
              </div>
            </div>
          ) : (
            <div className="mt-[13px] flex gap-[9px] pl-[31px]">
              {!campaignCase && (
                <button
                  onClick={() => setConfirm('write')}
                  disabled={!canWrite}
                  title={writeOffReason}
                  className={`${btn} border-success-btn-border bg-success-btn text-[#eafff2] hover:bg-[#22824c] disabled:hover:bg-success-btn`}
                >
                  <Check size={15} />{' '}
                  {retryCase ? 'Try again' : decision === 'failed' ? 'Retry' : ACTION_VERB[action.tag]}
                </button>
              )}
              <button
                onClick={() => setConfirm('dismiss')}
                disabled={!!lockedReason || decision === 'dismissing'}
                title={lockedReason}
                className={`${btn} border-border-strong bg-surface-3 text-text-2 hover:border-danger hover:text-danger disabled:hover:border-border-strong disabled:hover:text-text-2`}
              >
                <X size={15} /> Dismiss
              </button>
            </div>
          )}
        </>
      ) : closedNote ? (
        <div data-testid="action-closed" className="mt-[11px] pl-[31px] text-[12.5px] font-semibold text-dim">
          {closedNote}
        </div>
      ) : decision === 'executing' ? (
        <div
          className="mt-[11px] flex items-center gap-2 pl-[31px] text-[12.5px] font-semibold"
          style={{ color: '#d29922' }}
        >
          <Loader2 size={14} className="animate-spin" /> Writing to Security Onion
        </div>
      ) : (
        <div className="mt-[11px] pl-[31px]">
          <div
            data-testid="action-record"
            className="flex items-center gap-2 text-[12.5px] font-semibold"
            style={{ color: '#3fb950' }}
          >
            {applied && action.ruleDecisionReceipt
              ? `✓ ${ruleReceiptWords(action.ruleDecisionReceipt.at ?? action.appliedAt)}`
              : applied
                ? action.appliedNote === 'Already acknowledged'
                  ? '✓ Already acknowledged in Security Onion'
                  : `✓ ${executedLine(action.appliedBy ?? 'auto-ack', action.appliedAt)}`
                : `✓ ${executedLine(executedBy ?? 'you', new Date().toISOString())}`}
          </div>
          {/* The receipt of a rule decision links the decision. */}
          {applied && action.ruleDecisionReceipt?.href && (
            <Link
              to={action.ruleDecisionReceipt.href}
              data-testid="action-rule-receipt-link"
              className="mt-0.5 inline-flex items-center gap-0.5 text-[12px] font-semibold text-accent hover:underline"
            >
              {OPEN_RULE_DECISION}
              <ArrowUpRight size={12} aria-hidden />
            </Link>
          )}
          {(message || (applied && action.appliedDetail)) && (
            <div data-testid="action-result" className="mt-1 text-[12px] leading-[1.5] text-dim">
              {message || action.appliedDetail}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
