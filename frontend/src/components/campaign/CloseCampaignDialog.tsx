import { useEffect, useId, useState } from 'react';
import { AlertTriangle, X } from 'lucide-react';
import {
  closeCampaign,
  getCampaignCloseScope,
  type CampaignCloseReason,
  type CampaignCloseScope,
  type CampaignDetail,
} from '../../lib/api';
import {
  CLOSE_REASONS,
  CLOSE_SUBMIT,
  CLOSE_TITLE,
  DECISION_FAILED,
  NOTE_OPTIONAL,
  NO_VERDICT_CHANGE,
  REOPENS_SENTENCE,
  SCOPE_COUNTING,
  SCOPE_NONE,
  SCOPE_UNREAD,
  acknowledgeLabel,
  closeReasonLabel,
  closeWritesSentence,
  scopeCappedSentence,
} from '../../lib/campaignWords';
import { demoBlocked, useDemo } from '../../lib/demo';
import { Spinner } from '../States';

const LABEL = 'mb-1.5 block text-[12px] font-semibold text-dim';
/** The scope of a failed read: an unknown count, never a zero. */
const UNREAD: CampaignCloseScope = { alerts: null, rules: null, capped: false };

/**
 * The dialog of "Close with a reason". The analyst picks one of three
 * reasons, can add a note, and decides whether soc-ai acknowledges the alerts
 * of the campaign in Security Onion. The server counts those alerts before
 * the press: the alerts of the confirmed rules between the machines of the
 * campaign, in its period, that no analyst acknowledged. A count that soc-ai
 * cannot read is no zero: the box stays, it starts clear, and the dialog says
 * that soc-ai cannot read the count.
 *
 * The dialog states what the press writes, and that new activity opens the
 * campaign again. The press waits for a reason and for the count.
 */
export function CloseCampaignDialog({
  campaign,
  open,
  onClose,
  onClosed,
}: {
  campaign: Pick<CampaignDetail, 'id' | 'title'>;
  open: boolean;
  onClose: () => void;
  onClosed: (next: CampaignDetail) => void;
}) {
  const demo = useDemo();
  const titleId = useId();
  const noteId = useId();
  const [scope, setScope] = useState<CampaignCloseScope | null>(null);
  const [reason, setReason] = useState<CampaignCloseReason | null>(null);
  const [note, setNote] = useState('');
  const [acknowledge, setAcknowledge] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // A fresh dialog and a fresh count for each open.
  useEffect(() => {
    if (!open) return;
    let alive = true;
    setScope(null);
    setReason(null);
    setNote('');
    setAcknowledge(false);
    setError(null);
    getCampaignCloseScope(campaign.id)
      .then((answer) => {
        if (!alive) return;
        setScope(answer);
        setAcknowledge(typeof answer.alerts === 'number' && answer.alerts > 0);
      })
      .catch(() => {
        if (alive) setScope(UNREAD);
      });
    return () => {
      alive = false;
    };
  }, [open, campaign.id]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  // A count of zero offers no acknowledgement. An unknown count keeps the box.
  const offered = scope !== null && scope.alerts !== 0;
  const willAcknowledge = offered && acknowledge;
  const canSave = reason !== null && scope !== null && !saving;

  const save = () => {
    if (!reason || !scope) return;
    const blocked = demoBlocked(demo);
    if (blocked) {
      setError(blocked);
      return;
    }
    setSaving(true);
    setError(null);
    closeCampaign(campaign.id, { reason, note: note.trim(), acknowledge: willAcknowledge })
      .then((next) => {
        onClosed(next);
        onClose();
      })
      .catch((err: unknown) => setError(err instanceof Error && err.message ? err.message : DECISION_FAILED))
      .finally(() => setSaving(false));
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: 'rgba(0,0,0,.65)' }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        data-testid="close-campaign-dialog"
        className="relative max-h-[calc(100vh-48px)] w-[540px] max-w-[calc(100vw-32px)] overflow-y-auto rounded-panel-lg border p-6"
        style={{ background: '#0e1117', borderColor: '#1c232e' }}
      >
        <button onClick={onClose} className="absolute right-4 top-4 text-ghost hover:text-text" aria-label="Close">
          <X size={16} />
        </button>
        <div id={titleId} className="mb-1 pr-6 text-[14px] font-semibold">
          {CLOSE_TITLE}
        </div>
        <p className="mb-4 break-words pr-6 text-[12.5px] leading-[1.5] text-dim">{campaign.title}</p>

        <fieldset className="mb-4">
          <legend className={LABEL}>Reason</legend>
          <div className="flex flex-col gap-1.5">
            {CLOSE_REASONS.map((r) => (
              <label key={r} className="flex cursor-pointer items-center gap-2 text-[13px] text-text">
                <input
                  type="radio"
                  name={`close-reason-${campaign.id}`}
                  value={r}
                  checked={reason === r}
                  onChange={() => setReason(r)}
                />
                {closeReasonLabel(r)}
              </label>
            ))}
          </div>
        </fieldset>

        <div className="mb-4">
          <label htmlFor={noteId} className={LABEL}>
            Note
          </label>
          <textarea
            id={noteId}
            value={note}
            maxLength={2000}
            rows={3}
            onChange={(e) => setNote(e.target.value)}
            className="w-full rounded-control border border-border-input bg-bg px-3 py-2 text-[13px] text-text outline-none focus:border-accent"
          />
          <div className="mt-1 text-[11.5px] text-faint">{NOTE_OPTIONAL}</div>
        </div>

        <div className="mb-4 text-[12.5px] leading-[1.5]">
          {scope === null ? (
            <div className="flex items-center gap-2 text-dim">
              <Spinner size={13} /> {SCOPE_COUNTING}
            </div>
          ) : !offered ? (
            <div data-testid="close-scope-none" className="text-dim">
              {SCOPE_NONE}
            </div>
          ) : (
            <>
              <label className="flex cursor-pointer items-start gap-2 text-text">
                <input
                  type="checkbox"
                  className="mt-[3px]"
                  checked={acknowledge}
                  onChange={(e) => setAcknowledge(e.target.checked)}
                />
                <span className="min-w-0 break-words">{acknowledgeLabel(scope)}</span>
              </label>
              {scope.alerts === null && (
                <div data-testid="close-scope-unread" className="mt-1 pl-[22px] text-warn">
                  {SCOPE_UNREAD}
                </div>
              )}
              {scope.capped && typeof scope.alerts === 'number' && (
                <div data-testid="close-scope-capped" className="mt-1 pl-[22px] text-dim">
                  {scopeCappedSentence(scope.alerts)}
                </div>
              )}
            </>
          )}
        </div>

        <div className="mb-4 rounded-[7px] border border-warn/35 bg-warn/[.07] px-3 py-2.5 text-[12.5px] leading-[1.5] text-text-2">
          <div className="flex items-start gap-2">
            <AlertTriangle size={13} aria-hidden className="mt-[3px] flex-none text-warn" />
            <div className="min-w-0 break-words">
              <div data-testid="close-writes">{closeWritesSentence(willAcknowledge, scope?.alerts ?? null)}</div>
              <div>{REOPENS_SENTENCE}</div>
              <div>{NO_VERDICT_CHANGE}</div>
            </div>
          </div>
        </div>

        {error && (
          <div role="alert" className="mb-3 break-words text-[12.5px] text-danger">
            {error}
          </div>
        )}

        <div className="flex flex-wrap justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-control border border-border-strong bg-surface-3 px-4 py-2 text-[13px] font-semibold text-text-2 hover:text-text"
          >
            Cancel
          </button>
          <button
            disabled={!canSave}
            onClick={save}
            className="flex items-center gap-1.5 rounded-control border border-accent bg-[rgba(75,139,245,.14)] px-4 py-2 text-[13px] font-semibold text-accent hover:bg-[rgba(75,139,245,.22)] disabled:opacity-60"
          >
            {saving && <Spinner size={13} />}
            {CLOSE_SUBMIT}
          </button>
        </div>
      </div>
    </div>
  );
}
