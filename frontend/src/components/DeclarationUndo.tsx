import { RotateCcw, X } from 'lucide-react';
import { useState } from 'react';
import { clearDossierOverride, setDossierOverride } from '../lib/api';
import { fieldLabel, valueText } from '../lib/hostDossier';
import type { Dossier, DossierField, DossierFieldName } from '../lib/types';
import { Spinner } from './States';

// ---------------------------------------------------------------------------
// Undo for one declaration on the host page.
//
// The way back from a declaration was two clicks into a long Remove button
// inside the Edit form (dogfood 2026-10-19, R4-I4). After a declaration
// saves, the page states what changed and offers Undo until the operator
// closes the note or makes the next change.
// ---------------------------------------------------------------------------

/** One field a write changed: its state before and after. */
export interface DeclarationChange {
  ip: string;
  field: DossierFieldName;
  before: DossierField;
  after: DossierField;
}

function sameDeclaration(a: DossierField, b: DossierField): boolean {
  if (a.overridden !== b.overridden) return false;
  if (!a.overridden) return true;
  return (
    (a.value ?? null) === (b.value ?? null) &&
    JSON.stringify(a.value_json ?? null) === JSON.stringify(b.value_json ?? null) &&
    (a.operator_note ?? null) === (b.operator_note ?? null)
  );
}

/** The one declaration a write changed, or null when it changed none or
 *  more than one. A write on another address changes no field here. */
export function declarationChange(before: Dossier | null, after: Dossier): DeclarationChange | null {
  if (!before || before.ip !== after.ip) return null;
  const changed: DeclarationChange[] = [];
  for (const next of after.fields) {
    const prior = before.fields.find((f) => f.field === next.field);
    if (prior && !sameDeclaration(prior, next)) {
      changed.push({ ip: after.ip, field: next.field, before: prior, after: next });
    }
  }
  return changed.length === 1 ? changed[0] : null;
}

/** "Role declared: domain controller." or "Role declaration removed." */
export function declarationNote(change: DeclarationChange): string {
  const label = fieldLabel(change.field);
  if (!change.after.overridden) return `${label} declaration removed.`;
  const value = valueText(change.field, change.after.value, change.after.value_json);
  return value ? `${label} declared: ${value}.` : `${label} declared.`;
}

/** The write that puts the field back the way it was. */
export function undoDeclaration(change: DeclarationChange): Promise<Dossier> {
  const prior = change.before;
  if (!prior.overridden) return clearDossierOverride(change.ip, change.field);
  return setDossierOverride(change.ip, {
    field: change.field,
    ...(prior.value != null && prior.value.trim() !== '' ? { value: prior.value } : {}),
    ...(prior.value_json != null ? { value_json: prior.value_json } : {}),
    ...(prior.operator_note ? { note: prior.operator_note } : {}),
  });
}

export function DeclarationUndo({
  change,
  onUndone,
  onClose,
}: {
  change: DeclarationChange;
  /** The host after the Undo write. */
  onUndone: (next: Dossier) => void;
  onClose: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const undo = () => {
    setBusy(true);
    setErr(null);
    undoDeclaration(change)
      .then(onUndone)
      .catch((e: unknown) => {
        const msg = e instanceof Error ? e.message : 'The Undo did not save. Try again.';
        setErr(/^403\b/.test(msg) ? 'Only an admin can change this.' : msg);
      })
      .finally(() => setBusy(false));
  };
  return (
    <div
      data-testid="declaration-undo"
      role="status"
      className="mb-3 flex flex-wrap items-center gap-x-3 gap-y-1.5 rounded-card border border-accent/30 bg-accent/[0.06] px-3.5 py-2 text-[12.5px] text-text-2"
    >
      <span className="min-w-0 flex-1">{declarationNote(change)}</span>
      {err && <span className="basis-full text-[12px] text-danger">{err}</span>}
      <button
        type="button"
        onClick={undo}
        disabled={busy}
        className="flex flex-none items-center gap-1.5 rounded-control border border-accent/40 px-2.5 py-1 text-[11.5px] font-semibold text-accent hover:bg-accent/15 disabled:opacity-60"
      >
        {busy ? <Spinner size={11} /> : <RotateCcw size={11} />}
        Undo
      </button>
      <button
        type="button"
        onClick={onClose}
        aria-label="Close the Undo note"
        className="flex flex-none items-center rounded-control p-1 text-faint hover:text-text"
      >
        <X size={13} />
      </button>
    </div>
  );
}
