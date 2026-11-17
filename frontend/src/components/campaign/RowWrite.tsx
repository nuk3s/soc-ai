import { useState } from 'react';
import { type CampaignDetail } from '../../lib/api';
import { OVERRIDE_FAILED, REASON_REQUIRED } from '../../lib/campaignWords';
import { demoBlocked, useDemo } from '../../lib/demo';

export const ROW_BUTTON =
  'flex-none whitespace-nowrap rounded-control border border-border-strong bg-surface-3 px-2.5 py-1 text-[11.5px] font-semibold text-text-2 hover:border-accent hover:text-text disabled:opacity-60';
const PRIMARY =
  'flex-none whitespace-nowrap rounded-control border border-accent bg-[rgba(75,139,245,.14)] px-3 py-1 text-[12px] font-semibold text-accent hover:bg-[rgba(75,139,245,.22)] disabled:opacity-60';

/** The confirm of a write on one row of a fold: the sentence of what the
 *  press writes, a reason when the write needs one, the press and Cancel.
 *  The press sends `write` and hands the campaign of the answer up. */
export function RowConfirm({
  testId,
  sentence,
  action,
  needsReason,
  write,
  onDone,
  onCancel,
}: {
  testId: string;
  sentence: string;
  action: string;
  needsReason: boolean;
  write: (reason: string) => Promise<CampaignDetail>;
  onDone: (next: CampaignDetail) => void;
  onCancel: () => void;
}) {
  const demo = useDemo();
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const id = `${testId}-reason`;
  const ready = !busy && (!needsReason || reason.trim().length > 0);

  const send = () => {
    if (needsReason && !reason.trim()) {
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
    write(reason.trim())
      .then(onDone)
      .catch((err: unknown) => setError(err instanceof Error && err.message ? err.message : OVERRIDE_FAILED))
      .finally(() => setBusy(false));
  };

  return (
    <div data-testid={testId} className="rounded-card border border-border bg-surface-2 px-3 py-2">
      <p className="break-words text-[12.5px] leading-snug text-text-2">{sentence}</p>
      {needsReason && (
        <>
          <label htmlFor={id} className="mt-2 block text-[12px] font-semibold text-dim">
            Reason
          </label>
          <input
            id={id}
            value={reason}
            maxLength={2000}
            onChange={(e) => setReason(e.target.value)}
            className="mt-1 w-full rounded-control border border-border-input bg-bg px-2.5 py-1.5 text-[12.5px] text-text outline-none focus:border-accent"
          />
        </>
      )}
      <div className="mt-2 flex flex-wrap gap-2">
        <button type="button" disabled={!ready} onClick={send} className={PRIMARY}>
          {action}
        </button>
        <button type="button" disabled={busy} onClick={onCancel} className={ROW_BUTTON}>
          Cancel
        </button>
      </div>
      {error && (
        <div role="alert" className="mt-1.5 break-words text-[12.5px] text-danger">
          {error}
        </div>
      )}
    </div>
  );
}
