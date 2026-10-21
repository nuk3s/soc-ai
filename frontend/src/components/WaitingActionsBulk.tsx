import { AlertTriangle, Check, Loader2, RotateCcw, X } from 'lucide-react';
import { useEffect, useRef } from 'react';
import { dismissAction, restoreAction } from '../lib/api';
import { plural } from '../lib/plural';
import type { InvestigationRow, WaitingAction } from '../lib/types';
import { waitingKey } from './WaitingActions';

// ---------------------------------------------------------------------------
// Dismiss for the selection on the pending-action list (dogfood 2026-10-20).
//
// The analyst dismissed each waiting action on its own row: two presses and a
// confirm per action. The rows take a selection, like the leads on the Hunts
// page, and one Dismiss with one confirm dismisses the waiting actions of the
// selected rows. Each dismissal goes through the route of the row, so the
// server stores the actor and the time of each one. The press states a result
// per row, and the Undo of the press restores each dismissal it made.
// ---------------------------------------------------------------------------

/** The waiting actions of one selected row. */
export interface BulkDismissTarget {
  runId: string;
  name: string;
  actions: WaitingAction[];
}

/** What a press or its Undo did on one row. ``done`` and ``failed`` hold the
 *  report positions of the actions. */
export interface BulkDismissRowResult {
  runId: string;
  name: string;
  done: number[];
  failed: { index: number; error: string }[];
}

/** The result line of a press or of its Undo. */
export interface BulkDismissEntry {
  rows: BulkDismissRowResult[];
  /** The dismissals the Undo restores. Null once the Undo ran. */
  undo: { runId: string; name: string; index: number }[] | null;
  /** Set on the answer of an Undo. */
  undoOf?: boolean;
  /** A refusal of the whole press. */
  error?: string;
}

/** The waiting actions of the selected rows that this tab has not acted on.
 *  A selected row the list does not show is not a target. */
export function bulkDismissTargets(
  rows: readonly InvestigationRow[],
  ids: readonly string[],
  done: ReadonlySet<string>,
): BulkDismissTarget[] {
  const chosen = new Set(ids);
  return rows
    .filter((r) => chosen.has(r.id))
    .map((r) => ({
      runId: r.id,
      name: r.name,
      actions: (r.waitingActions ?? []).filter((a) => !done.has(waitingKey(r.id, a.index))),
    }))
    .filter((t) => t.actions.length > 0);
}

export const actionCount = (targets: readonly BulkDismissTarget[]): number =>
  targets.reduce((n, t) => n + t.actions.length, 0);

/** The sentences of the confirm. */
export function bulkDismissConfirmText(targets: readonly BulkDismissTarget[], offList: number): string[] {
  const out = [
    `Dismiss ${plural(actionCount(targets), 'recommended action')} on ${plural(targets.length, 'investigation')}.`,
    'Dismiss writes nothing to Security Onion. soc-ai records your name and the time.',
  ];
  if (offList > 0) {
    out.push(
      offList === 1
        ? '1 selected investigation is not on this list. The press skips it.'
        : `${offList.toLocaleString()} selected investigations are not on this list. The press skips them.`,
    );
  }
  out.push('You can undo the dismissal from the result line.');
  return out;
}

/** The sentence of the result line. */
export function bulkDismissResultText(entry: BulkDismissEntry): string {
  if (entry.error) return entry.error;
  const done = entry.rows.reduce((n, r) => n + r.done.length, 0);
  const failed = entry.rows.reduce((n, r) => n + r.failed.length, 0);
  const total = done + failed;
  const runs = entry.rows.filter((r) => r.done.length > 0).length;
  const failedRuns = entry.rows.filter((r) => r.failed.length > 0).length;
  if (entry.undoOf) {
    if (failed === 0) return `Undid the dismissal of ${plural(done, 'recommended action')}.`;
    return (
      `Undid the dismissal of ${done.toLocaleString()} of ${plural(total, 'recommended action')}. ` +
      `The undo did not complete for ${plural(failed, 'action')}.`
    );
  }
  if (failed === 0) {
    return `Dismissed ${plural(done, 'recommended action')} on ${plural(runs, 'investigation')}.`;
  }
  const stays =
    failedRuns === 1
      ? 'Its investigation stays selected. Try it again.'
      : 'Their investigations stay selected. Try them again.';
  return `Dismissed ${done.toLocaleString()} of ${plural(total, 'recommended action')}. ${failed.toLocaleString()} failed. ${stays}`;
}

/** The words for one row of the result line. */
function rowWords(r: BulkDismissRowResult, undoOf: boolean): string {
  const parts: string[] = [];
  if (r.done.length) {
    parts.push(`${undoOf ? 'Restored' : 'Dismissed'} ${plural(r.done.length, 'action')}.`);
  }
  for (const f of r.failed) parts.push(f.error);
  return parts.join(' ');
}

const errorText = (e: unknown): string =>
  e instanceof Error && e.message ? e.message : 'soc-ai did not store the change. Try again.';

/** Dismiss each action of each target through the route of the row, one at
 *  a time. A failure stops nothing: each action has its own answer. */
export async function dismissEach(targets: readonly BulkDismissTarget[]): Promise<BulkDismissRowResult[]> {
  const out: BulkDismissRowResult[] = [];
  for (const t of targets) {
    const row: BulkDismissRowResult = { runId: t.runId, name: t.name, done: [], failed: [] };
    for (const a of t.actions) {
      try {
        await dismissAction(t.runId, a.index);
        row.done.push(a.index);
      } catch (e) {
        row.failed.push({ index: a.index, error: errorText(e) });
      }
    }
    out.push(row);
  }
  return out;
}

/** Restore each dismissal of a press, one at a time. */
export async function restoreEach(
  undo: readonly { runId: string; name: string; index: number }[],
): Promise<BulkDismissRowResult[]> {
  const byRun = new Map<string, BulkDismissRowResult>();
  for (const u of undo) {
    let row = byRun.get(u.runId);
    if (!row) {
      row = { runId: u.runId, name: u.name, done: [], failed: [] };
      byRun.set(u.runId, row);
    }
    try {
      await restoreAction(u.runId, u.index);
      row.done.push(u.index);
    } catch (e) {
      row.failed.push({ index: u.index, error: errorText(e) });
    }
  }
  return [...byRun.values()];
}

const btn =
  'flex items-center gap-1.5 rounded-control border px-3 py-1 text-[12.5px] font-semibold disabled:cursor-not-allowed disabled:opacity-50';

/** The confirm of the press. The focus goes to Cancel, and Escape closes it. */
export function BulkDismissConfirm({
  targets,
  offList,
  busy,
  onCancel,
  onConfirm,
}: {
  targets: readonly BulkDismissTarget[];
  offList: number;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    cancelRef.current?.focus();
  }, []);
  return (
    <div
      data-testid="bulk-dismiss-confirm"
      role="group"
      aria-label="Confirm dismiss of the selected actions"
      onKeyDown={(e) => {
        if (e.key === 'Escape') {
          e.stopPropagation();
          onCancel();
        }
      }}
      className="mb-3.5 rounded-[7px] border px-3 py-2.5"
      style={{ borderColor: 'rgba(245,166,35,.35)', background: 'rgba(245,166,35,.07)' }}
    >
      <div className="mb-2.5 flex items-start gap-2 text-[12.5px] leading-[1.5] text-warn">
        <AlertTriangle size={13} className="mt-px flex-none" />
        <span>{bulkDismissConfirmText(targets, offList).join(' ')}</span>
      </div>
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          disabled={busy}
          onClick={onConfirm}
          className={`${btn} border-danger bg-[rgba(240,68,56,.1)] text-[#fca5a5] hover:bg-[rgba(240,68,56,.18)]`}
        >
          {busy ? <Loader2 size={13} className="animate-spin" /> : <X size={13} />} Confirm dismiss
        </button>
        <button
          ref={cancelRef}
          type="button"
          onClick={onCancel}
          className={`${btn} border-border-strong bg-surface-3 text-text-2 hover:text-text`}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

/** The result line of a press: the sentence, one line per row, and the Undo. */
export function BulkDismissResultLine({
  entry,
  busy,
  onUndo,
  onClose,
}: {
  entry: BulkDismissEntry;
  busy: boolean;
  onUndo: () => void;
  onClose: () => void;
}) {
  const failed = entry.rows.some((r) => r.failed.length > 0) || !!entry.error;
  return (
    <div
      data-testid="bulk-dismiss-result"
      role="status"
      className="mb-3.5 overflow-hidden rounded-card border"
      style={{ borderColor: 'rgba(75,139,245,.30)', background: 'rgba(75,139,245,.06)' }}
    >
      <div className="flex items-center gap-2.5 px-3.5 py-2.5 text-[13px]">
        {failed ? (
          <AlertTriangle size={13} className="flex-none text-warn" />
        ) : (
          <Check size={13} className="flex-none text-accent" />
        )}
        <span className="min-w-0 flex-1 break-words font-semibold text-text-2">
          {bulkDismissResultText(entry)}
        </span>
        {entry.undo && entry.undo.length > 0 && (
          <button
            type="button"
            disabled={busy}
            onClick={onUndo}
            className="flex flex-none items-center gap-1 text-[12.5px] font-semibold text-accent hover:underline disabled:opacity-50"
          >
            {busy ? <Loader2 size={12} className="animate-spin" /> : <RotateCcw size={12} />} Undo
          </button>
        )}
        <button
          type="button"
          onClick={onClose}
          className="flex flex-none text-dim hover:text-text"
          aria-label="Close the result"
        >
          <X size={14} />
        </button>
      </div>
      {entry.rows.length > 0 && (
        <div className="border-t border-border-faint px-3.5 py-2 text-[12.5px]">
          {entry.rows.map((r) => (
            <div key={r.runId} data-testid={`bulk-dismiss-row-${r.runId}`} className="flex items-start gap-2 py-[3px]">
              {r.failed.length ? (
                <X size={12} className="mt-[3px] flex-none text-danger" />
              ) : (
                <Check size={12} className="mt-[3px] flex-none text-success" />
              )}
              <span className="min-w-0 break-words text-text-2">{r.name}</span>
              <span className={r.failed.length ? 'text-danger' : 'text-faint'}>
                {rowWords(r, !!entry.undoOf)}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
