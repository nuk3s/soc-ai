import { useEffect, useRef } from 'react';
import type { ReactNode } from 'react';
import { useShell } from '../shell/ShellContext';

// Focusable descendants for the initial focus + Tab focus-trap. Excludes
// tabindex="-1" (programmatic-only) targets.
const FOCUSABLE =
  'a[href],button:not([disabled]),textarea:not([disabled]),input:not([disabled]),select:not([disabled]),[tabindex]:not([tabindex="-1"])';

interface DrawerProps {
  open: boolean;
  onClose: () => void;
  /** content rendered in the fixed header bar */
  header?: ReactNode;
  children: ReactNode;
}

/** Right-side drawer with a blurred scrim. Slides in from the right. */
export function Drawer({ open, onClose, header, children }: DrawerProps) {
  const { paletteOpen, pushModal, popModal } = useShell();
  const asideRef = useRef<HTMLElement>(null);

  // Modal-focus contract: while open, count into the shared modal stack,
  // scroll-lock the body, and move focus into the dialog — restoring it to the
  // opener (and unlocking) on close.
  useEffect(() => {
    if (!open) return;
    pushModal();
    const opener = document.activeElement as HTMLElement | null;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const t = window.setTimeout(() => {
      const node = asideRef.current;
      if (!node) return;
      const first = node.querySelector<HTMLElement>(FOCUSABLE);
      (first ?? node).focus();
    }, 0);
    return () => {
      window.clearTimeout(t);
      document.body.style.overflow = prevOverflow;
      popModal();
      opener?.focus?.();
    };
  }, [open, pushModal, popModal]);

  // Escape closes (unless the palette layers above and owns Escape); Tab is
  // trapped within the dialog so focus can't fall to the list behind the scrim.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      // The command palette layers ABOVE the drawer and owns Escape while it's
      // open — closing the palette must not also tear down the drawer beneath it
      // (which would delete the analyst's open report). Same shared precondition
      // the Alerts key layer uses (resolveTriageKey short-circuits on paletteOpen).
      if (e.key === 'Escape' && !paletteOpen) {
        onClose();
        return;
      }
      if (e.key === 'Tab') {
        const node = asideRef.current;
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
  }, [open, onClose, paletteOpen]);

  if (!open) return null;

  return (
    <>
      <div
        onClick={onClose}
        className="fixed inset-0 z-40 bg-[rgba(4,6,9,.62)] backdrop-blur-[2px]"
      />
      <aside
        ref={asideRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={header ? 'drawer-title' : undefined}
        aria-label={header ? undefined : 'Detail panel'}
        tabIndex={-1}
        className="fixed bottom-0 right-0 top-0 z-[41] flex w-[620px] max-w-[94vw] animate-slideIn flex-col border-l border-border-2 bg-surface-1 shadow-drawer outline-none"
      >
        {header && (
          <div
            id="drawer-title"
            className="flex flex-none items-center gap-2.5 border-b border-border px-4 py-[13px]"
          >
            {header}
          </div>
        )}
        <div className="flex-1 overflow-y-auto">{children}</div>
      </aside>
    </>
  );
}
