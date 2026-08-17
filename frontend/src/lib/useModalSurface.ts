import { useEffect } from 'react';
import type { RefObject } from 'react';
import { useShell } from '../shell/ShellContext';

// Focusable descendants for the initial focus + Tab focus-trap. Excludes
// tabindex="-1" (programmatic-only) targets.
const FOCUSABLE =
  'a[href],button:not([disabled]),textarea:not([disabled]),input:not([disabled]),select:not([disabled]),[tabindex]:not([tabindex="-1"])';

interface ModalSurfaceOptions {
  open: boolean;
  onClose: () => void;
  /** The dialog element. Focus is trapped inside it while open. */
  containerRef: RefObject<HTMLElement | null>;
  /** Focus this on open instead of the first focusable descendant. */
  initialFocusRef?: RefObject<HTMLElement | null>;
  /**
   * Restore focus here on close, instead of whatever held focus when the dialog
   * opened. Needed whenever the opener unmounts in the same commit that opens
   * the dialog (a menu item that closes its own menu): by the time the open
   * effect runs, `document.activeElement` is already BODY, so the captured
   * "opener" is nothing. Point this at a surface that outlives the dialog.
   */
  returnFocusRef?: RefObject<HTMLElement | null>;
}

/**
 * The behaviour `aria-modal="true"` promises, in one place.
 *
 * A dialog that declares the rest of the page inert has to make that true:
 * count into the shared modal stack (so keyboard layers disarm), lock body
 * scroll, move focus in, keep Tab inside, close on Escape, and hand focus back
 * on the way out. Written three times across this app before it was extracted —
 * and the third copy shipped without the trap or the scroll lock, so four Tabs
 * from inside the change-password dialog landed in the sidebar nav BEHIND the
 * scrim, where a keyboard user could type a password into a field they cannot
 * see.
 *
 * Callers still own the markup (`role`, `aria-modal`, the scrim) and the
 * open/close state; this owns only the focus and keyboard contract.
 */
export function useModalSurface({
  open,
  onClose,
  containerRef,
  initialFocusRef,
  returnFocusRef,
}: ModalSurfaceOptions): void {
  const { paletteOpen, pushModal, popModal } = useShell();

  useEffect(() => {
    if (!open) return;
    pushModal();
    const opener = document.activeElement as HTMLElement | null;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const t = window.setTimeout(() => {
      const node = containerRef.current;
      if (!node) return;
      const target =
        initialFocusRef?.current ?? node.querySelector<HTMLElement>(FOCUSABLE) ?? node;
      target.focus();
    }, 0);
    return () => {
      window.clearTimeout(t);
      document.body.style.overflow = prevOverflow;
      popModal();
      (returnFocusRef?.current ?? opener)?.focus?.();
    };
  }, [open, pushModal, popModal, containerRef, initialFocusRef, returnFocusRef]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      // The command palette layers ABOVE any dialog and owns Escape while it is
      // open — closing the palette must not also tear down the dialog beneath it
      // (which would discard the analyst's open report, or their half-typed
      // credential). Same shared precondition the Alerts key layer uses.
      if (e.key === 'Escape' && !paletteOpen) {
        onClose();
        return;
      }
      if (e.key === 'Tab') {
        const node = containerRef.current;
        if (!node) return;
        const items = Array.from(node.querySelectorAll<HTMLElement>(FOCUSABLE));
        if (items.length === 0) {
          e.preventDefault();
          node.focus();
          return;
        }
        const first = items[0];
        const last = items[items.length - 1];
        const active = document.activeElement;
        if (e.shiftKey && (active === first || !node.contains(active))) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && (active === last || !node.contains(active))) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose, paletteOpen, containerRef]);
}
