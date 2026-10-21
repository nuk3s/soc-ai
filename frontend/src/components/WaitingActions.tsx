import { AlertTriangle, Check, Loader2, X } from 'lucide-react';
import { useEffect, useId, useRef, useState } from 'react';
import {
  dismissAction,
  executeAction,
  getActionScope,
  restoreAction,
  type ActionScope,
} from '../lib/api';
import { demoBlocked, useDemo } from '../lib/demo';
import { plural } from '../lib/plural';
import { useToast } from '../lib/toast';
import type { InvestigationRow, WaitingAction } from '../lib/types';
import {
  ACK_COUNTING,
  ACK_COUNT_FAILED,
  ACTION_VERB,
  CasesLine,
  DISMISS_CONFIRM_TEXT,
  NO_SECOND_CASE,
  confirmLabel,
} from './ActionCard';
import { isBacktestReplay } from './BacktestReplayChip';

// ---------------------------------------------------------------------------
// The waiting actions of one row of the pending-action list.
//
// The needs-you line "N recommended actions wait for you" opens the
// Investigations list filtered to the runs with a waiting action. To act, the
// analyst opened each run and came back: two page changes per run, 32 for 16
// runs (dogfood 2026-10-19, R1-I1). The row now offers the write and Dismiss
// in place. The write button names the write with the word of the action
// card: "Escalate to case", "Acknowledge", "Add comment".
//
// The controls call the client functions of the action card, so the writes go
// through the same routes, the same SO write timeout and the same needs-you
// refresh. The row follows the rules of the card: a backtest replay offers
// no button, an action the server marks not executable keeps its write button
// off with the reason, the demo blocks
// every write, a write and a dismissal ask for a confirm, and a dismissal
// offers an undo. The server refuses a run that a newer run replaced.
// ---------------------------------------------------------------------------

/** The note on a replay row. The words of the server and the action card. */
export const REPLAY_ACTION_NOTE = 'Not executable. This run is a backtest replay.';

/** "The alert of ET X" / "Security Onion case 42" / "The finding X": what
 *  the action acts on. The row called a finding or a lead "The alert of ..."
 *  (verify 2026-10-20, V3-N4). The server names the type of the target. */
export function actionTargetText(a: WaitingAction, rule: string): string {
  if (a.targetType === 'case') {
    return a.target ? `Security Onion case ${a.target}` : 'No Security Onion case';
  }
  const name = a.target || rule;
  if (a.targetType === 'finding') return `The finding ${name}`;
  if (a.targetType === 'lead') return /^lead\b/i.test(name) ? name : `The lead ${name}`;
  return a.type === 'ack' ? `The alerts of ${name}` : `The alert of ${name}`;
}

/** "the escalation of ET X": the action as a noun, for a toast. */
export function actionNoun(a: WaitingAction, rule: string): string {
  const name = a.target || rule;
  if (a.type === 'escalate') return `the escalation of ${name}`;
  if (a.type === 'ack') return `the acknowledgement of ${name}`;
  return a.target ? `the comment on Security Onion case ${a.target}` : 'the comment';
}

/** The consequence of the write, in one sentence, stated in the confirm. An
 *  ack reads its count from the server first, like the action card. */
export function actionConfirmText(
  a: WaitingAction,
  rule: string,
  scope: ActionScope | null,
  scopeState: 'idle' | 'loading' | 'error',
): string {
  const name = a.target || rule;
  if (a.type === 'escalate') return `Open a Security Onion case for the alert of ${name}.`;
  if (a.type === 'comment') {
    return a.target
      ? `Add a comment to Security Onion case ${a.target}.`
      : 'Add a comment to the Security Onion case this investigation opened.';
  }
  if (scopeState === 'loading') return ACK_COUNTING;
  if (scopeState === 'error') return ACK_COUNT_FAILED;
  if (scope?.scope === 'group' && scope.count != null) {
    if (scope.count === 0) return scope.sentence;
    const head = `Acknowledge ${plural(scope.count, 'alert')} of ${name} in Security Onion.`;
    return scope.held > 0
      ? `${head} soc-ai leaves ${plural(scope.held, 'alert')} with a true positive or needs more info verdict open.`
      : head;
  }
  return `Acknowledge the alert of ${name} in Security Onion.`;
}

/** The key of one action across the list: the run and the report position. */
export const waitingKey = (runId: string, index: number): string => `${runId}:${index}`;

export function WaitingActions({
  row,
  onDone,
  onRestored,
}: {
  row: InvestigationRow;
  /** The action left the pending set: executed or dismissed. */
  onDone: (key: string) => void;
  /** An undo put a dismissed action back. */
  onRestored: (key: string) => void;
}) {
  const actions = row.waitingActions ?? [];
  if (actions.length === 0) return null;
  return (
    <div data-testid={`waiting-actions-${row.id}`} data-waiting-row={row.id} className="flex flex-col gap-2">
      {actions.map((a) => (
        <WaitingActionLine
          key={a.id}
          row={row}
          action={a}
          onDone={onDone}
          onRestored={onRestored}
        />
      ))}
    </div>
  );
}

const btn =
  'flex items-center gap-1.5 rounded-control border px-3 py-1 text-[12.5px] font-semibold disabled:cursor-not-allowed disabled:opacity-50';

function WaitingActionLine({
  row,
  action: a,
  onDone,
  onRestored,
}: {
  row: InvestigationRow;
  action: WaitingAction;
  onDone: (key: string) => void;
  onRestored: (key: string) => void;
}) {
  const demo = useDemo();
  const { toast } = useToast();
  const [confirm, setConfirm] = useState<'write' | 'dismiss' | null>(null);
  const [busy, setBusy] = useState<'executing' | 'dismissing' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scope, setScope] = useState<ActionScope | null>(null);
  const [scopeState, setScopeState] = useState<'idle' | 'loading' | 'error'>('idle');
  const executeRef = useRef<HTMLButtonElement>(null);
  const dismissRef = useRef<HTMLButtonElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  // The button that opened the confirm. The focus goes back to it on close.
  const openerRef = useRef<HTMLButtonElement | null>(null);

  const key = waitingKey(row.id, a.index);
  // The alert of an escalate is already on a case: the scope route says so.
  const onCases =
    confirm === 'write' && a.type === 'escalate' && scope?.cases && scope.cases.length > 0
      ? scope.cases
      : null;
  const rule = row.name;
  // A replay offers no action at all. The server closes every action of a
  // replay and refuses each write, the dismissal too. The client keeps the
  // rule, so an older server or a stale flag cannot offer the button.
  const replay = isBacktestReplay(row.ranBy);
  const canExecute = a.executable && !replay;
  const reason = replay ? REPLAY_ACTION_NOTE : a.executable ? null : a.reason;
  // The word of the action card names the write. "Execute" named nothing.
  const verb = ACTION_VERB[a.type] ?? a.label;
  const what = `${verb} for ${rule}`;
  // The action as a noun, for the toasts: "the escalation of ET X".
  const noun = actionNoun(a, rule);
  // Each button reads the target as its description, so a screen reader
  // tells two rows apart.
  const targetId = useId();

  // An ack states its count before the write, and an escalate names the
  // cases the alert is already on. The read happens when the confirm opens:
  // one read per press, never one per row on the list. Until the escalate
  // read answers, the confirm states the default write. The execute route
  // opens no second case whatever the confirm said.
  useEffect(() => {
    if (confirm !== 'write' || (a.type !== 'ack' && a.type !== 'escalate')) return;
    let live = true;
    setScopeState('loading');
    Promise.resolve()
      .then(() => getActionScope(row.id, a.index))
      .then((s) => {
        if (!live) return;
        setScope(s ?? null);
        setScopeState('idle');
      })
      .catch(() => live && setScopeState('error'));
    return () => {
      live = false;
    };
  }, [confirm, a.type, a.index, row.id]);

  // The focus moves into the confirm, onto Cancel: the button that writes
  // nothing. Enter on the write button then never writes by accident.
  useEffect(() => {
    if (confirm) cancelRef.current?.focus();
  }, [confirm]);

  // Escape closes the open confirm wherever the focus is on the row, and
  // when the focus is on no control at all. The confirm closed only while
  // the focus was inside it (verify 2026-10-20, V3-N9). A key on a control
  // outside the row belongs to that control.
  const lineRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!confirm) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape' || e.defaultPrevented) return;
      const target = e.target instanceof Node ? e.target : null;
      const rowEl = lineRef.current?.closest('[data-waiting-row]') ?? lineRef.current;
      const onRow = !!target && !!rowEl && rowEl.contains(target);
      const nowhere = target === document.body || target === document.documentElement;
      if (!onRow && !nowhere) return;
      e.preventDefault();
      setConfirm(null);
      openerRef.current?.focus();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [confirm]);

  const open = (which: 'write' | 'dismiss', opener: HTMLButtonElement | null) => {
    openerRef.current = opener;
    setError(null);
    setConfirm(which);
  };
  const close = () => {
    setConfirm(null);
    openerRef.current?.focus();
  };

  const execute = (writeScope: 'group' | 'alert') => {
    setConfirm(null);
    const blocked = demoBlocked(demo);
    if (blocked) {
      setError(blocked);
      return;
    }
    setBusy('executing');
    setError(null);
    executeAction(row.id, a.index, a.type === 'ack' ? writeScope : undefined)
      .then((res) => {
        if (res.status !== 'executed') {
          setError(res.error || 'The write to Security Onion failed.');
          return;
        }
        // A press that wrote nothing reads in the info tone. The list asks
        // the server again, and the server decides whether the action waits.
        const wroteNothing = res.count === 0;
        toast({
          tone: wroteNothing ? 'info' : 'success',
          message: res.detail || `soc-ai executed ${noun}.`,
        });
        onDone(key);
      })
      .catch((e: unknown) => setError(e instanceof Error ? e.message : 'The request failed.'))
      .finally(() => setBusy(null));
  };

  const restore = () => {
    const blocked = demoBlocked(demo);
    if (blocked) {
      toast({ tone: 'info', message: blocked });
      return;
    }
    restoreAction(row.id, a.index)
      .then(() => onRestored(key))
      .catch((e: unknown) =>
        toast({
          tone: 'danger',
          message: e instanceof Error ? e.message : 'soc-ai did not store the change. Try again.',
        }),
      );
  };

  const dismiss = () => {
    setConfirm(null);
    const blocked = demoBlocked(demo);
    if (blocked) {
      setError(blocked);
      return;
    }
    setBusy('dismissing');
    setError(null);
    dismissAction(row.id, a.index)
      .then(() => {
        toast({
          tone: 'info',
          message: `You dismissed ${noun}.`,
          action: { label: 'Undo', onClick: restore },
        });
        onDone(key);
      })
      .catch((e: unknown) =>
        setError(e instanceof Error ? e.message : 'soc-ai did not store the change. Try again.'),
      )
      .finally(() => setBusy(null));
  };

  return (
    <div ref={lineRef} data-testid={`waiting-action-${row.id}-${a.index}`} className="flex flex-col gap-1">
      <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-[12.5px]">
        {replay && (
          <>
            <span className="font-semibold text-text">{verb}</span>
            <span className="text-faint">·</span>
          </>
        )}
        <span id={targetId} className="min-w-0 break-words text-text-2">
          {actionTargetText(a, rule)}
        </span>
        {!replay && (
          <span className="ml-auto flex flex-none items-center gap-2">
            {busy && (
              <span className="flex items-center gap-1 text-[12px] font-semibold text-warn">
                <Loader2 size={12} className="animate-spin" />
                {busy === 'executing' ? 'Writing to Security Onion' : 'Storing the dismissal'}
              </span>
            )}
            <button
              ref={executeRef}
              type="button"
              aria-describedby={targetId}
              aria-expanded={confirm === 'write'}
              disabled={busy !== null || !canExecute}
              title={reason ?? undefined}
              onClick={() => (confirm === 'write' ? close() : open('write', executeRef.current))}
              className={`${btn} border-success-btn-border bg-success-btn text-[#eafff2] hover:bg-[#22824c] disabled:hover:bg-success-btn`}
            >
              <Check size={13} />
              {verb}
            </button>
            <button
              ref={dismissRef}
              type="button"
              aria-describedby={targetId}
              aria-expanded={confirm === 'dismiss'}
              disabled={busy !== null}
              onClick={() => (confirm === 'dismiss' ? close() : open('dismiss', dismissRef.current))}
              className={`${btn} border-border-strong bg-surface-3 text-text-2 hover:border-danger hover:text-danger`}
            >
              <X size={13} />
              Dismiss
            </button>
          </span>
        )}
      </div>
      {a.rationale && <div className="text-[12px] leading-[1.5] text-dim">{a.rationale}</div>}
      {reason && (
        <div data-testid="waiting-action-reason" className="text-[12px] leading-[1.5] text-faint">
          {reason}
        </div>
      )}
      {error && (
        <div role="alert" className="text-[12px] leading-[1.5] text-danger">
          {error}
        </div>
      )}
      {confirm && (
        <div
          data-testid="waiting-action-confirm"
          role="group"
          aria-label={confirm === 'write' ? `Confirm: ${what}` : `Confirm dismiss: ${what}`}
          onKeyDown={(e) => {
            if (e.key === 'Escape') {
              e.stopPropagation();
              e.preventDefault();
              close();
            }
          }}
          className="mt-1 rounded-[7px] border px-3 py-2.5"
          style={{ borderColor: 'rgba(245,166,35,.35)', background: 'rgba(245,166,35,.07)' }}
        >
          <div className="mb-2.5 flex items-start gap-2 text-[12.5px] leading-[1.5] text-warn">
            <AlertTriangle size={13} className="mt-px flex-none" />
            {onCases ? (
              <span>
                <CasesLine cases={onCases} complete={scope?.casesComplete ?? false} />
                {NO_SECOND_CASE}
              </span>
            ) : (
              <span>
                {confirm === 'write'
                  ? actionConfirmText(a, rule, scope, a.type === 'ack' ? scopeState : 'idle')
                  : DISMISS_CONFIRM_TEXT}
              </span>
            )}
          </div>
          <div className="flex flex-wrap gap-2">
            {confirm === 'write' ? (
              <>
                <button
                  type="button"
                  onClick={() => execute('group')}
                  className={`${btn} border-success-btn-border bg-success-btn text-[#eafff2] hover:bg-[#22824c]`}
                >
                  <Check size={13} /> {confirmLabel(a.type, scope, !!onCases)}
                </button>
                {a.type === 'ack' && scope?.scope === 'group' && (
                  <button
                    type="button"
                    onClick={() => execute('alert')}
                    className={`${btn} border-border-strong bg-surface-3 text-text-2 hover:text-text`}
                  >
                    Acknowledge this alert only
                  </button>
                )}
              </>
            ) : (
              <button
                type="button"
                onClick={dismiss}
                className={`${btn} border-danger bg-[rgba(240,68,56,.1)] text-[#fca5a5] hover:bg-[rgba(240,68,56,.18)]`}
              >
                <X size={13} /> Confirm dismiss
              </button>
            )}
            <button
              ref={cancelRef}
              type="button"
              onClick={close}
              className={`${btn} border-border-strong bg-surface-3 text-text-2 hover:text-text`}
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
