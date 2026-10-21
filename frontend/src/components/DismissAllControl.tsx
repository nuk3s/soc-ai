import { useState } from 'react';

import { ApiError } from '../lib/api';
import type { NeedsYouState } from '../lib/needsYou';
import {
  decisionsThatStay,
  dismissAll,
  dismissAllPrompt,
  dismissAllUndoNote,
  restoreDismissals,
  snapshotDismissals,
} from '../lib/notifications';
import { useToast } from '../lib/toast';
import type { Notification } from '../lib/types';

/** The toast after a Dismiss all: what it hid and what the server read. */
function dismissAllDone(events: number, read: number | null): string {
  const parts: string[] = [];
  if (events > 0) parts.push(`Dismiss all hid ${events} notification${events === 1 ? '' : 's'}.`);
  if (read !== null && read > 0) {
    parts.push(`${read} shadow hit${read === 1 ? ' is' : 's are'} read.`);
  }
  return parts.length > 0 ? parts.join(' ') : 'Dismiss all hid every older notification.';
}

/**
 * "Dismiss all" and its confirm step, for the bell panel and the Notifications
 * screen. The work is lib/notifications.ts::dismissAll, so the two surfaces
 * cannot do two different things under one name.
 *
 * The confirm step states what happens: how many events it hides, how many
 * shadow hits it marks read on the server, and which decisions stay. One
 * stray click must not empty the list (D8). A toast then offers Undo for the
 * local hide. The shadow hits stay read, and the confirm says so (dogfood
 * 2026-10-19, R1-I6).
 *
 * `rows` are the event rows on screen. `loadedAt` is when they loaded, in
 * epoch ms. The moment of the Dismiss all is the earlier of that and the load
 * of the count, so nothing that arrived after either read is hidden or read.
 */
export function DismissAllControl({
  rows,
  more,
  needsYou,
  loadedAt,
  onDone,
  compact = false,
}: {
  rows: ReadonlyArray<Notification>;
  more: boolean;
  needsYou: NeedsYouState;
  loadedAt: number | null;
  onDone?: () => void;
  compact?: boolean;
}) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { toast } = useToast();

  const data = needsYou.data;
  const shadowHits = data ? data.unread_shadow_hits : null;
  const dismissible = rows.filter((n) => n.dismissible !== false);
  const fixed = rows.length - dismissible.length;
  const canAct = loadedAt !== null && (dismissible.length > 0 || more || shadowHits !== 0);

  const moment = (): number => {
    const own = loadedAt ?? Date.now();
    const count = data ? needsYou.loadedAt : null;
    return typeof count === 'number' ? Math.min(own, count) : own;
  };

  const confirm = async () => {
    setBusy(true);
    setError(null);
    const before = snapshotDismissals();
    try {
      const read = await dismissAll({ rows: dismissible, loadedAt: moment(), shadowHits });
      setConfirming(false);
      onDone?.();
      toast({
        message: dismissAllDone(dismissible.length, read),
        tone: 'success',
        duration: 10_000,
        action: { label: 'Undo', onClick: () => restoreDismissals(before) },
      });
    } catch (e) {
      setConfirming(false);
      setError(
        e instanceof ApiError && e.reason === 'shadow_hits_changed'
          ? 'New shadow hits arrived after the count. Dismiss all hid the notifications and marked no hit read. Check the new count and try again.'
          : 'Dismiss all hid the notifications. It could not mark the shadow hits read. Try again.',
      );
    } finally {
      setBusy(false);
    }
  };

  const small = compact ? 'px-2 py-1 text-[11.5px]' : 'px-3 py-1.5 text-[12px]';

  if (confirming) {
    return (
      <div
        role="group"
        aria-label="Confirm dismiss all"
        className={`flex flex-wrap items-center gap-2 ${compact ? 'w-full pt-2' : 'mt-1 max-w-[440px] justify-end'}`}
      >
        <span className="text-[12px] leading-[1.45] text-dim">
          {dismissAllPrompt({
            events: dismissible.length,
            more,
            shadowHits,
            stay: decisionsThatStay(data),
            fixed,
          })}{' '}
          {dismissAllUndoNote({ events: dismissible.length, shadowHits })}
        </span>
        <button
          onClick={() => void confirm()}
          disabled={busy}
          autoFocus
          className={`rounded-control border border-danger bg-surface-3 font-semibold text-danger hover:bg-[rgba(240,68,56,.08)] disabled:opacity-60 ${small}`}
        >
          Dismiss all
        </button>
        <button
          onClick={() => setConfirming(false)}
          disabled={busy}
          className={`rounded-control border border-border-strong font-semibold text-dim hover:border-accent hover:text-text ${small}`}
        >
          Cancel
        </button>
      </div>
    );
  }

  return (
    <>
      {canAct && (
        <button
          onClick={() => {
            setError(null);
            setConfirming(true);
          }}
          title="Hide every event up to now and mark every unread shadow hit read. Leads and other decisions stay."
          className={`flex-none rounded-control border border-border-strong bg-surface-3 font-semibold text-dim hover:border-accent hover:text-text ${compact ? 'px-2 py-0.5 text-[11px]' : 'mt-1 px-3 py-1.5 text-[12px]'}`}
        >
          Dismiss all
        </button>
      )}
      {error && (
        <span role="alert" className={`text-[11.5px] text-warn ${compact ? 'w-full pt-1' : 'mt-1'}`}>
          {error}
        </span>
      )}
    </>
  );
}
