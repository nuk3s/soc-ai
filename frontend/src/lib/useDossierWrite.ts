import { useState } from 'react';
import type { Dossier } from './types';

/**
 * One dossier mutation, from click to re-render.
 *
 * Every dossier write answers with the WHOLE re-resolved host (setting `role`
 * can close a conflict), so the response replaces the page rather than patching
 * one field — `onApplied` is the parent's "here is the new page" callback. The
 * hook exists because three surfaces mutate (fact rows, the why-care strip's
 * conflict cards, the unknown line's declare forms) and the busy/error/response
 * plumbing must not be three slightly different copies.
 */
export function useDossierWrite(onApplied: (next: Dossier) => void) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const run = (op: () => Promise<Dossier>, after?: () => void) => {
    setBusy(true);
    setErr(null);
    op()
      .then((next) => {
        onApplied(next);
        after?.();
      })
      .catch((e: unknown) => {
        const msg = e instanceof Error ? e.message : 'That did not go through.';
        // require_admin_api's 403 carries a `reason` and no `hint`, so request()
        // hands back the bare status line. Say what it means instead.
        setErr(/^403\b/.test(msg) ? 'Only an admin can change this.' : msg);
      })
      .finally(() => setBusy(false));
  };

  return { busy, err, setErr, run };
}
