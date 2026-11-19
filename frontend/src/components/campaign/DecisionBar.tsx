import { useEffect, useState } from 'react';
import { Briefcase, CheckCircle2, Clock, ExternalLink, HelpCircle, ShieldCheck } from 'lucide-react';
import {
  acknowledgeCampaign,
  getCampaignCloseScope,
  reopenCampaign,
  retryCampaignCase,
  revokeCampaignAuthorization,
  type CampaignDetail,
} from '../../lib/api';
import { acknowledgementOf, decisionState, remainsToAcknowledge } from '../../lib/campaignDecision';
import {
  ACKNOWLEDGE_REST_ACTION,
  AUTHORIZE_ACTION,
  CASE_ACTION,
  CASE_FAILED,
  CASE_LINK,
  CASE_PENDING,
  CASE_PENDING_DETAIL,
  CASE_REOPEN_CONFIRM,
  CASE_RETRY_ACTION,
  CASE_RETRY_FAILED,
  CLOSE_ACTION,
  DECISION_FAILED,
  REASON_REQUIRED,
  REOPEN_ACTION,
  REOPEN_CONFIRM,
  REVOKE_ACTION,
  REVOKE_CONFIRM,
  acknowledgedSentence,
  authorizedSentence,
  caseAttachedWords,
  caseCommentsWords,
  caseFailureWords,
  caseOpenSentence,
  casePendingSince,
  caseRetryConfirm,
  decisionNote,
  decisionSentence,
  insideWords,
  waitsSentence,
} from '../../lib/campaignWords';
import { demoBlocked, useDemo } from '../../lib/demo';
import { SinceDecisionLines } from './SinceDecision';

const PRIMARY =
  'flex-none whitespace-nowrap rounded-control border border-accent bg-[rgba(75,139,245,.14)] px-3 py-1.5 text-[12.5px] font-semibold text-accent hover:bg-[rgba(75,139,245,.22)] disabled:opacity-60';
const SECONDARY =
  'flex-none whitespace-nowrap rounded-control border border-border-strong bg-surface-3 px-3 py-1.5 text-[12.5px] font-semibold text-text-2 hover:text-text disabled:opacity-60';
/** The three decisions of a campaign that waits: one visual weight, so none
 *  of them reads as the default. */
/** A fact of the case: a count beside the state line. */
const FACT =
  'inline-flex items-center rounded-chip border border-border-strong bg-surface-3 px-2 py-0.5 font-mono text-[11.5px] text-text-2';
const DECISION =
  'flex-none whitespace-nowrap rounded-control border border-border-strong bg-surface-3 px-3 py-1.5 text-[12.5px] font-semibold text-text hover:border-accent hover:text-accent disabled:opacity-60';

function errorText(err: unknown): string {
  return err instanceof Error && err.message ? err.message : DECISION_FAILED;
}

/** The decision of the campaign: the first line under its title, because the
 *  decision is why the analyst opens the page. One line of state and one
 *  button. A campaign that waits reads as work in the warning tone, with the
 *  three decisions side by side in one visual weight: "Open one case", for
 *  an admin "Record authorized activity", and "Close with a reason". A case
 *  that Security Onion refused states the reason in that bar. A request for
 *  a case with no readable answer reads calm, with the one button "Try
 *  again". A campaign with a case states since when, who, the link to the
 *  case, the alerts attached, the comments of soc-ai and "Open again". A closed campaign reads calm: who closed
 *  it, when, the reason, the note, the alerts that soc-ai acknowledged, and
 *  the button "Open again". When alerts of the close are left to acknowledge,
 *  the button "Acknowledge the remaining alerts" with the count of the close
 *  scope stands beside it. An authorized campaign reads calm too: the label,
 *  who, when, the expiry, the investigations inside, and the button "Revoke"
 *  while the authorization is in force. Open again and Revoke state what they
 *  write before the press. Revoke asks for a reason.
 *
 *  A decision with no form here states itself with no button. A campaign
 *  that is not active, or a server that sends no decision, shows no bar. */
/** True when the bar states what is new since the earlier decision. The
 *  banner then holds the newest hunt answer beside the hunt of the reopen
 *  (W1), and the header does not state the answer a second time. */
export function sinceInBar(c: CampaignDetail): boolean {
  return Boolean(c.sinceDecision) && decisionState(c) === 'waits' && c.case?.state !== 'pending';
}

export function DecisionBar({
  campaign: c,
  onCloseRequest,
  onDecided,
  onAuthorizeRequest,
  onCaseRequest,
  canAuthorize = false,
  onShowNew,
}: {
  campaign: CampaignDetail;
  onCloseRequest: () => void;
  onDecided: (next: CampaignDetail) => void;
  /** Opens the dialog "Record authorized activity". */
  onAuthorizeRequest?: () => void;
  /** Opens the dialog "Open one case". A server with no case field offers no case. */
  onCaseRequest?: () => void;
  /** True for an admin, or for a session the console cannot read. */
  canAuthorize?: boolean;
  /** Opens the investigations of the campaign with only the new ones (SD3). */
  onShowNew?: () => void;
}) {
  const demo = useDemo();
  const [confirming, setConfirming] = useState(false);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The alerts that the close scope still counts: undefined before the read,
  // null when the grid did not answer.
  const [scopeAlerts, setScopeAlerts] = useState<number | null | undefined>(undefined);
  const [reads, setReads] = useState(0);
  const state = decisionState(c);
  const closedId = state === 'closed' ? c.id : null;
  useEffect(() => {
    if (closedId === null) return;
    let live = true;
    Promise.resolve()
      .then(() => getCampaignCloseScope(closedId))
      .then((scope) => {
        if (live) setScopeAlerts(scope?.alerts ?? null);
      })
      .catch(() => {
        if (live) setScopeAlerts(null);
      });
    return () => {
      live = false;
    };
  }, [closedId, reads]);
  if (state === 'unknown') return null;

  if (state === 'waits' && c.case?.state === 'pending') {
    return <PendingCaseBar campaign={c} onDecided={onDecided} />;
  }

  if (state === 'waits') {
    const failure = c.case?.state === 'failed' ? caseFailureWords(c.case.failure) : null;
    return (
      <div
        data-testid="campaign-decision"
        data-state="waits"
        className="mt-2.5 rounded-card border border-warn/40 bg-warn/10 px-3 py-2"
      >
        {/* A campaign that opened again states the earlier decision and
            what is new since it, above the line of the wait. */}
        {c.sinceDecision && (
          <SinceDecisionLines since={c.sinceDecision} onShowNew={onShowNew} answer={c.answers?.[0] ?? null} />
        )}
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          <Clock size={15} aria-hidden className="flex-none text-warn" />
          <span data-testid="campaign-decision-state" className="min-w-0 flex-[1_1_20rem] break-words text-[13px] text-text">
            {waitsSentence(c.waitsSince)}
          </span>
          {/* The decisions wrap as one group, so no button stands alone on a line. */}
          <div data-testid="campaign-decisions" className="ml-auto flex max-w-full flex-wrap justify-end gap-2">
            {onCaseRequest && c.case !== undefined && (
              <button type="button" data-testid="campaign-case" onClick={onCaseRequest} className={DECISION}>
                {CASE_ACTION}
              </button>
            )}
            {canAuthorize && onAuthorizeRequest && (
              <button type="button" data-testid="campaign-authorize" onClick={onAuthorizeRequest} className={DECISION}>
                {AUTHORIZE_ACTION}
              </button>
            )}
            <button type="button" data-testid="campaign-close" onClick={onCloseRequest} className={DECISION}>
              {CLOSE_ACTION}
            </button>
          </div>
        </div>
        {failure !== null && (
          <div
            data-testid="campaign-case-failed"
            className="mt-1 break-words pl-[27px] text-[12.5px] leading-snug text-text-2"
          >
            {failure ? `${CASE_FAILED} ${failure}` : CASE_FAILED}
          </div>
        )}
      </div>
    );
  }

  const decision = c.decision;
  if (!decision) return null;
  if (state === 'authorized' && c.authorization) {
    return <AuthorizedBar campaign={c} onDecided={onDecided} />;
  }
  const closed = state === 'closed';
  const onCase = state === 'case';
  // A close and a case clear the same way.
  const reopenable = closed || onCase;
  const ack = closed ? acknowledgementOf(c.changes, decision) : null;
  const rest = closed && remainsToAcknowledge(c.changes, decision, scopeAlerts);
  const noteText = decisionNote(decision.note);
  const Icon = closed ? CheckCircle2 : onCase ? Briefcase : ShieldCheck;
  const soCase = onCase ? c.case : null;

  const reopen = () => {
    const blocked = demoBlocked(demo);
    if (blocked) {
      setError(blocked);
      return;
    }
    setBusy(true);
    setError(null);
    reopenCampaign(c.id, { note: note.trim() })
      .then((next) => {
        setConfirming(false);
        setNote('');
        onDecided(next);
      })
      .catch((err: unknown) => setError(errorText(err)))
      .finally(() => setBusy(false));
  };

  const acknowledgeRest = () => {
    const blocked = demoBlocked(demo);
    if (blocked) {
      setError(blocked);
      return;
    }
    setBusy(true);
    setError(null);
    acknowledgeCampaign(c.id)
      .then((next) => {
        onDecided(next);
        setReads((n) => n + 1);
      })
      .catch((err: unknown) => setError(errorText(err)))
      .finally(() => setBusy(false));
  };

  return (
    <div
      data-testid="campaign-decision"
      data-state={state}
      className="mt-2.5 rounded-card border border-border bg-surface-2 px-3 py-2"
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <Icon size={15} aria-hidden className="flex-none text-dim" />
        <span data-testid="campaign-decision-state" className="min-w-0 flex-[1_1_20rem] break-words text-[13px] text-text-2">
          {onCase ? caseOpenSentence(soCase, decision) : decisionSentence(decision)}
        </span>
        {soCase?.url && (
          <a
            data-testid="campaign-case-link"
            href={soCase.url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex flex-none items-center gap-1 whitespace-nowrap text-[12.5px] font-semibold text-accent hover:underline"
          >
            {CASE_LINK}
            <ExternalLink size={12} aria-hidden />
          </a>
        )}
        {rest && !confirming && (
          <button
            type="button"
            data-testid="campaign-acknowledge-rest"
            disabled={busy}
            onClick={acknowledgeRest}
            className={SECONDARY}
          >
            {ACKNOWLEDGE_REST_ACTION}
            {scopeAlerts != null && scopeAlerts > 0 && (
              <span data-testid="campaign-acknowledge-count" className="ml-1.5 font-mono text-dim">
                {scopeAlerts.toLocaleString('en-US')}
              </span>
            )}
          </button>
        )}
        {reopenable && !confirming && (
          <button
            type="button"
            data-testid="campaign-reopen"
            onClick={() => {
              setError(null);
              setConfirming(true);
            }}
            className={SECONDARY}
          >
            {REOPEN_ACTION}
          </button>
        )}
      </div>
      {soCase && (typeof soCase.alerts === 'number' || typeof soCase.comments === 'number') && (
        <div className="mt-1.5 flex flex-wrap gap-1.5 pl-[27px]">
          {typeof soCase.alerts === 'number' && (
            <span data-testid="campaign-case-alerts" className={FACT}>
              {caseAttachedWords(soCase.alerts)}
            </span>
          )}
          {typeof soCase.comments === 'number' && (
            <span data-testid="campaign-case-comments" className={FACT}>
              {caseCommentsWords(soCase.comments)}
            </span>
          )}
        </div>
      )}
      {(noteText || ack) && (
        <div className="mt-1 flex flex-col gap-0.5 pl-[27px] text-[12.5px] leading-snug text-dim">
          {noteText && (
            <span data-testid="campaign-decision-note" className="break-words">
              {noteText}
            </span>
          )}
          {ack && (
            <span data-testid="campaign-decision-ack" className="break-words">
              {acknowledgedSentence(ack.detail)}
            </span>
          )}
        </div>
      )}
      {confirming && (
        <div data-testid="campaign-reopen-confirm" className="mt-2 border-t border-border pl-[27px] pt-2">
          <p className="break-words text-[12.5px] leading-snug text-text-2">
            {onCase ? CASE_REOPEN_CONFIRM : REOPEN_CONFIRM}
          </p>
          <label htmlFor={`reopen-note-${c.id}`} className="mt-2 block text-[12px] font-semibold text-dim">
            Note
          </label>
          <input
            id={`reopen-note-${c.id}`}
            data-testid="campaign-reopen-note"
            value={note}
            maxLength={2000}
            onChange={(e) => setNote(e.target.value)}
            className="mt-1 w-full rounded-control border border-border-input bg-bg px-2.5 py-1.5 text-[12.5px] text-text outline-none focus:border-accent"
          />
          <div className="mt-2 flex flex-wrap gap-2">
            <button type="button" data-testid="campaign-reopen-submit" disabled={busy} onClick={reopen} className={PRIMARY}>
              {REOPEN_ACTION}
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() => {
                setConfirming(false);
                setError(null);
              }}
              className={SECONDARY}
            >
              Cancel
            </button>
          </div>
        </div>
      )}
      {error && (
        <div role="alert" className="mt-1.5 pl-[27px] text-[12.5px] text-danger">
          {error}
        </div>
      )}
    </div>
  );
}

/** The bar of an authorized campaign. Revoke shows while the authorization is
 *  in force: an expired one still covers the past and holds no mark to clear
 *  for a later event. */
function AuthorizedBar({
  campaign: c,
  onDecided,
}: {
  campaign: CampaignDetail;
  onDecided: (next: CampaignDetail) => void;
}) {
  const demo = useDemo();
  const [confirming, setConfirming] = useState(false);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const a = c.authorization;
  if (!a) return null;
  const inForce = a.state === 'active' && Date.parse(a.expiresAt) > Date.now();
  const noteText = decisionNote(a.note ?? c.decision?.note);

  const revoke = () => {
    if (!reason.trim()) {
      setError(REASON_REQUIRED);
      return;
    }
    const blocked = demoBlocked(demo);
    if (blocked) {
      setError(blocked);
      return;
    }
    setBusy(true);
    setError(null);
    revokeCampaignAuthorization(c.id, { reason: reason.trim() })
      .then((next) => {
        setConfirming(false);
        setReason('');
        onDecided(next);
      })
      .catch((err: unknown) => setError(errorText(err)))
      .finally(() => setBusy(false));
  };

  return (
    <div
      data-testid="campaign-decision"
      data-state="authorized"
      className="mt-2.5 rounded-card border border-border bg-surface-2 px-3 py-2"
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <ShieldCheck size={15} aria-hidden className="flex-none text-text-2" />
        <span data-testid="campaign-decision-state" className="min-w-0 flex-[1_1_20rem] break-words text-[13px] text-text-2">
          {authorizedSentence(a, c.decision)}
        </span>
        {inForce && !confirming && (
          <button
            type="button"
            data-testid="campaign-revoke"
            onClick={() => {
              setError(null);
              setConfirming(true);
            }}
            className={SECONDARY}
          >
            {REVOKE_ACTION}
          </button>
        )}
      </div>
      <div className="mt-1 flex flex-col gap-0.5 pl-[27px] text-[12.5px] leading-snug text-dim">
        <span data-testid="campaign-decision-inside" className="break-words">
          {`${insideWords(a.inside)}.`}
        </span>
        {noteText && (
          <span data-testid="campaign-decision-note" className="break-words">
            {noteText}
          </span>
        )}
      </div>
      {confirming && (
        <div data-testid="campaign-revoke-confirm" className="mt-2 border-t border-border pl-[27px] pt-2">
          <p className="break-words text-[12.5px] leading-snug text-text-2">{REVOKE_CONFIRM}</p>
          <label htmlFor={`revoke-reason-${c.id}`} className="mt-2 block text-[12px] font-semibold text-dim">
            Reason
          </label>
          <input
            id={`revoke-reason-${c.id}`}
            data-testid="campaign-revoke-reason"
            value={reason}
            maxLength={2000}
            onChange={(e) => setReason(e.target.value)}
            className="mt-1 w-full rounded-control border border-border-input bg-bg px-2.5 py-1.5 text-[12.5px] text-text outline-none focus:border-accent"
          />
          <div className="mt-2 flex flex-wrap gap-2">
            <button
              type="button"
              data-testid="campaign-revoke-submit"
              disabled={busy || !reason.trim()}
              onClick={revoke}
              className={PRIMARY}
            >
              {REVOKE_ACTION}
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() => {
                setConfirming(false);
                setError(null);
              }}
              className={SECONDARY}
            >
              Cancel
            </button>
          </div>
        </div>
      )}
      {error && (
        <div role="alert" className="mt-1.5 pl-[27px] text-[12.5px] text-danger">
          {error}
        </div>
      )}
    </div>
  );
}

/** The bar of a request for a case whose answer soc-ai could not read. It
 *  reads calm: what soc-ai knows, and the one button "Try again". The press
 *  states what it writes before it sends: an audit record, and the request
 *  clears. Security Onion can hold the case, so the analyst looks first. */
function PendingCaseBar({
  campaign: c,
  onDecided,
}: {
  campaign: CampaignDetail;
  onDecided: (next: CampaignDetail) => void;
}) {
  const demo = useDemo();
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const since = c.case ? casePendingSince(c.case) : '';

  const retry = () => {
    const blocked = demoBlocked(demo);
    if (blocked) {
      setError(blocked);
      return;
    }
    setBusy(true);
    setError(null);
    retryCampaignCase(c.id)
      .then((next) => {
        setConfirming(false);
        onDecided(next);
      })
      .catch((err: unknown) => setError(err instanceof Error && err.message ? err.message : CASE_RETRY_FAILED))
      .finally(() => setBusy(false));
  };

  return (
    <div
      data-testid="campaign-decision"
      data-state="case_pending"
      className="mt-2.5 rounded-card border border-border bg-surface-2 px-3 py-2"
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <HelpCircle size={15} aria-hidden className="flex-none text-text-2" />
        <span data-testid="campaign-decision-state" className="min-w-0 flex-[1_1_20rem] break-words text-[13px] text-text">
          {CASE_PENDING}
        </span>
        {!confirming && (
          <button
            type="button"
            data-testid="campaign-case-retry"
            onClick={() => {
              setError(null);
              setConfirming(true);
            }}
            className={SECONDARY}
          >
            {CASE_RETRY_ACTION}
          </button>
        )}
      </div>
      <div className="mt-1 flex flex-col gap-0.5 pl-[27px] text-[12.5px] leading-snug text-dim">
        {since && <span className="break-words">{since}</span>}
        <span className="break-words">{CASE_PENDING_DETAIL}</span>
      </div>
      {confirming && (
        <div data-testid="campaign-case-retry-confirm" className="mt-2 border-t border-border pl-[27px] pt-2">
          <p className="break-words text-[12.5px] leading-snug text-text-2">{caseRetryConfirm(c.title)}</p>
          <div className="mt-2 flex flex-wrap gap-2">
            <button type="button" disabled={busy} onClick={retry} className={PRIMARY}>
              {CASE_RETRY_ACTION}
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() => {
                setConfirming(false);
                setError(null);
              }}
              className={SECONDARY}
            >
              Cancel
            </button>
          </div>
        </div>
      )}
      {error && (
        <div role="alert" className="mt-1.5 pl-[27px] text-[12.5px] text-danger">
          {error}
        </div>
      )}
    </div>
  );
}
