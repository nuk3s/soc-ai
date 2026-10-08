import { AlertTriangle, Check, Loader2, MessageSquare, RotateCcw, Triangle, X, type LucideIcon } from 'lucide-react';
import { useEffect, useState } from 'react';
import { getActionScope, type ActionScope } from '../lib/api';
import type { ActionTag, RecommendedAction } from '../lib/types';

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

/** "03:12": the local clock time of an ISO instant, or null when it does not parse. */
export function clockTime(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
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

/** The label of the confirm button: the write, with its count. */
export function confirmLabel(tag: ActionTag, scope: ActionScope | null): string {
  if (tag === 'ack') {
    if (scope?.scope === 'group' && scope.count != null) {
      return scope.count === 1 ? 'Acknowledge 1 alert' : `Acknowledge ${scope.count} alerts`;
    }
    return 'Acknowledge this alert';
  }
  if (tag === 'escalate') return 'Open the case';
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
  onExecute: (scope: 'group' | 'alert') => void;
  onDismiss: () => void;
  onUndoDismiss: () => void;
  /** Set when the action has no Security Onion target (a promoted finding).
   *  The write button is off with this as its tooltip. Dismiss still works. */
  disabledReason?: string;
  /** Set when a newer run replaced this one. Every button is off. */
  lockedReason?: string;
  /** A new value opens the write confirm: the chat asked for this action. */
  confirmRequest?: number;
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
  const canWrite = pending && !disabledReason && !lockedReason;

  useEffect(() => {
    if (confirmRequest != null && canWrite) setConfirm('write');
    // canWrite is read at the time of the request.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [confirmRequest]);

  // State the scope before the click. Only an ack needs the server: its plan
  // depends on the grid. The other two have one target each.
  useEffect(() => {
    if (!canWrite || action.tag !== 'ack') return;
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
  }, [canWrite, action.tag, invId, index]);

  const scopeSentence =
    action.tag === 'ack'
      ? scope?.sentence ??
        (scopeState === 'loading'
          ? 'soc-ai is counting the alerts this ack covers.'
          : scopeState === 'error'
            ? 'soc-ai could not count the alerts. The ack covers the unacknowledged alerts of this rule from the last 7 days.'
            : DEFAULT_SCOPE.ack)
      : DEFAULT_SCOPE[action.tag];
  const groupAck = action.tag === 'ack' && scope?.scope === 'group';

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
          <div data-testid="action-scope" className="mt-[10px] pl-[31px] text-[12px] leading-[1.5] text-text-2">
            {scopeSentence}
          </div>
          {action.pendingNote && (
            <div className="mt-1 pl-[31px] text-[12px] leading-[1.5] text-faint">
              {action.pendingNote}
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
          {confirm === 'write' ? (
            <div data-testid="action-confirm" className="ml-[31px] mt-[11px] rounded-[7px] border px-3 py-2.5" style={{ borderColor: 'rgba(245,166,35,.35)', background: 'rgba(245,166,35,.07)' }}>
              <div className="mb-2.5 flex items-start gap-2 text-[12.5px] leading-[1.5] text-warn">
                <AlertTriangle size={13} className="mt-px flex-none" />
                <span>This writes to Security Onion. {scopeSentence}</span>
              </div>
              <div className="flex flex-wrap gap-2">
                <button
                  onClick={() => {
                    setConfirm(null);
                    onExecute('group');
                  }}
                  className={`${btn} border-success-btn-border bg-success-btn text-[#eafff2] hover:bg-[#22824c]`}
                >
                  <Check size={15} /> {confirmLabel(action.tag, scope)}
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
                <span>Dismiss this recommendation. soc-ai records your name and the time. You can undo it.</span>
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
              <button
                onClick={() => setConfirm('write')}
                disabled={!canWrite}
                title={lockedReason ?? disabledReason}
                className={`${btn} border-success-btn-border bg-success-btn text-[#eafff2] hover:bg-[#22824c] disabled:hover:bg-success-btn`}
              >
                <Check size={15} /> {decision === 'failed' ? 'Retry' : ACTION_VERB[action.tag]}
              </button>
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
            {applied
              ? action.appliedNote === 'Already acknowledged'
                ? '✓ Already acknowledged in Security Onion'
                : `✓ ${executedLine(action.appliedBy ?? 'auto-ack', action.appliedAt)}`
              : `✓ ${executedLine(executedBy ?? 'you', new Date().toISOString())}`}
          </div>
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
