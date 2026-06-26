import { useEffect } from 'react';
import type { ReactNode } from 'react';

interface DrawerProps {
  open: boolean;
  onClose: () => void;
  /** content rendered in the fixed header bar */
  header?: ReactNode;
  children: ReactNode;
}

/** Right-side drawer with a blurred scrim. Slides in from the right. */
export function Drawer({ open, onClose, header, children }: DrawerProps) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <>
      <div
        onClick={onClose}
        className="fixed inset-0 z-40 bg-[rgba(4,6,9,.62)] backdrop-blur-[2px]"
      />
      <aside
        role="dialog"
        aria-modal="true"
        className="fixed bottom-0 right-0 top-0 z-[41] flex w-[620px] max-w-[94vw] animate-slideIn flex-col border-l border-border-2 bg-surface-1 shadow-drawer"
      >
        {header && (
          <div className="flex flex-none items-center gap-2.5 border-b border-border px-4 py-[13px]">
            {header}
          </div>
        )}
        <div className="flex-1 overflow-y-auto">{children}</div>
      </aside>
    </>
  );
}
