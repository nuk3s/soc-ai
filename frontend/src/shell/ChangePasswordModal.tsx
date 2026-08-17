import { KeyRound, X } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import type { RefObject } from 'react';
import type { ApiError } from '../lib/api';
import { changePassword } from '../lib/api';
import { useToast } from '../lib/toast';
import { useModalSurface } from '../lib/useModalSurface';

/**
 * Mirror of ``soc_ai.store.auth.MIN_PASSWORD_LENGTH``. Client-side it only buys
 * a fast, local "too short" instead of a round trip — the server holds the real
 * floor and re-checks, so a drift here weakens nothing: a server that raised its
 * minimum answers `password_too_short` with ITS number, and the mapping below
 * files that message under the same field this local check would have used.
 */
export const MIN_PASSWORD_LENGTH = 8;

/** Which field the current error belongs under; 'form' = not attributable. */
type ErrField = 'current' | 'new' | 'confirm' | 'form';

/**
 * Backend `detail.reason` → the field its message belongs under. Keyed off the
 * machine-readable code, never the prose: matching on the sentence broke the
 * moment anyone edited it, and filed every rejection but one under the
 * form-level slot instead of beneath the input that caused it.
 */
const REASON_FIELD: Record<string, ErrField> = {
  bad_credentials: 'current',
  password_too_short: 'new',
  password_too_long: 'new',
};

interface Props {
  open: boolean;
  onClose: () => void;
  /**
   * Where focus goes when the dialog closes. The menu item that opens this
   * dialog unmounts in the same commit (it closes its own menu), so there is no
   * live opener to restore to — the account menu passes its avatar trigger.
   */
  returnFocusRef?: RefObject<HTMLElement | null>;
}

/**
 * Self-service password change. Deliberately a small centered dialog (the
 * keyboard-cheatsheet overlay's shape) rather than the right-side Drawer: three
 * fields and two buttons is a decision, not a reading surface.
 *
 * Succeeding here does NOT sign the analyst out — the backend keeps this
 * session and drops the account's others — so the confirmation is a toast, not
 * a bounce to the login screen.
 */
export function ChangePasswordModal({ open, onClose, returnFocusRef }: Props) {
  const { toast } = useToast();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [err, setErr] = useState<{ field: ErrField; message: string } | null>(null);
  const [saving, setSaving] = useState(false);
  const dialogRef = useRef<HTMLDivElement>(null);
  const firstRef = useRef<HTMLInputElement>(null);
  // Bumped on every open and every submit. A request that settles after the
  // analyst has closed (or reopened) the dialog belongs to a generation that no
  // longer exists, so it must not write state — otherwise a cancelled attempt's
  // rejection paints an error onto the next opening, and a late success closes
  // and toasts over a form the analyst has started retyping.
  const gen = useRef(0);

  useModalSurface({
    open,
    onClose,
    containerRef: dialogRef,
    initialFocusRef: firstRef,
    returnFocusRef,
  });

  // Clear on EVERY open/close transition, not just close. Clearing only on close
  // meant an in-flight rejection landing after the dialog closed wrote its error
  // back with nothing left to clear it — reopening then showed a red "Current
  // password is incorrect." above an empty Current field.
  useEffect(() => {
    gen.current += 1;
    setCurrent('');
    setNext('');
    setConfirm('');
    setErr(null);
    setSaving(false);
  }, [open]);

  if (!open) return null;

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (saving) return;
    if (next.length < MIN_PASSWORD_LENGTH) {
      setErr({
        field: 'new',
        message: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`,
      });
      return;
    }
    if (next !== confirm) {
      setErr({ field: 'confirm', message: 'The new passwords do not match.' });
      return;
    }
    setErr(null);
    setSaving(true);
    const mine = (gen.current += 1);
    changePassword(current, next)
      .then(() => {
        if (mine !== gen.current) return;
        toast({ tone: 'success', message: 'Password changed. You are still signed in.' });
        onClose();
      })
      .catch((e: ApiError) => {
        if (mine !== gen.current) return;
        // File the message under the field its `reason` names; anything without
        // a known reason (network, timeout, an unmapped code) is form-level.
        setErr({
          field: REASON_FIELD[e.reason ?? ''] ?? 'form',
          message: e.message || 'Could not change the password.',
        });
        setSaving(false);
      });
  }

  const fieldErr = (f: ErrField) => (err?.field === f ? err.message : null);

  return (
    <>
      <div
        onClick={onClose}
        className="fixed inset-0 z-[60] bg-[rgba(4,6,9,.55)] backdrop-blur-[2px]"
      />
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label="Change password"
        tabIndex={-1}
        className="fixed left-1/2 top-1/2 z-[61] -translate-x-1/2 -translate-y-1/2 animate-fadeUp overflow-hidden rounded-panel-lg border border-border-input bg-surface-card shadow-palette outline-none"
        style={{ width: 'min(400px,92vw)' }}
      >
        <div className="flex items-center justify-between border-b border-border-2 px-4 py-[13px]">
          <span className="flex items-center gap-2 text-[14px] font-semibold text-text">
            <KeyRound size={15} className="text-faint" />
            Change password
          </span>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="flex rounded-control text-faint hover:text-text outline-none focus-visible:ring-1 focus-visible:ring-accent"
          >
            <X size={15} />
          </button>
        </div>

        <form onSubmit={submit} className="flex flex-col gap-3.5 px-4 py-4">
          <Field
            id="cp-current"
            label="Current password"
            value={current}
            autoComplete="current-password"
            inputRef={firstRef}
            onChange={setCurrent}
            error={fieldErr('current')}
          />
          <Field
            id="cp-new"
            label="New password"
            value={next}
            autoComplete="new-password"
            hint={`At least ${MIN_PASSWORD_LENGTH} characters.`}
            onChange={setNext}
            error={fieldErr('new')}
          />
          <Field
            id="cp-confirm"
            label="Confirm new password"
            value={confirm}
            autoComplete="new-password"
            onChange={setConfirm}
            error={fieldErr('confirm')}
          />

          {fieldErr('form') && (
            <div role="alert" className="text-[11.5px] leading-[1.5] text-danger">
              {fieldErr('form')}
            </div>
          )}

          <div className="mt-0.5 flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-control border border-border-input px-3 py-[7px] text-[12.5px] font-semibold text-dim hover:border-border-strong hover:text-text outline-none focus-visible:ring-1 focus-visible:ring-accent"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="rounded-control bg-accent px-3 py-[7px] text-[12.5px] font-semibold text-white outline-none hover:bg-accent-deep disabled:cursor-not-allowed disabled:opacity-60 focus-visible:ring-1 focus-visible:ring-accent"
            >
              {saving ? 'Changing…' : 'Change password'}
            </button>
          </div>
        </form>
      </div>
    </>
  );
}

function Field({
  id,
  label,
  value,
  onChange,
  error,
  hint,
  autoComplete,
  inputRef,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  error: string | null;
  hint?: string;
  autoComplete: string;
  inputRef?: React.RefObject<HTMLInputElement>;
}) {
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-[11.5px] font-semibold text-dim">
        {label}
      </label>
      <input
        id={id}
        ref={inputRef}
        type="password"
        value={value}
        autoComplete={autoComplete}
        aria-invalid={error ? true : undefined}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-control border border-border-input bg-bg px-3 py-2 text-[13px] text-text outline-none focus:border-accent"
        style={error ? { borderColor: '#f04438' } : undefined}
      />
      {error ? (
        <div role="alert" className="mt-1 text-[11.5px] leading-[1.45] text-danger">
          {error}
        </div>
      ) : hint ? (
        <div className="mt-1 text-[11px] leading-[1.45] text-faint">{hint}</div>
      ) : null}
    </div>
  );
}
