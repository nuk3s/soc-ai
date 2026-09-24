import { useRef } from 'react';
import type { ReactNode } from 'react';
import { useModalSurface } from '../lib/useModalSurface';

interface DrawerProps {
  open: boolean;
  onClose: () => void;
  /** content rendered in the fixed header bar */
  header?: ReactNode;
  /** The width. A detail drawer is 620px. `wide` is for content that cannot
   *  fit there: the hunting flow chart is 1600px across. */
  size?: 'default' | 'wide';
  children: ReactNode;
}

const WIDTH: Record<'default' | 'wide', string> = {
  default: 'w-[620px] max-w-[94vw]',
  wide: 'w-[1480px] max-w-[96vw]',
};

/** Right-side drawer with a blurred scrim. Slides in from the right. */
export function Drawer({ open, onClose, header, size = 'default', children }: DrawerProps) {
  const asideRef = useRef<HTMLElement>(null);

  // Modal-focus contract (stack count, scroll lock, initial focus, Tab trap,
  // Escape-yields-to-palette, focus restore) — shared with every other
  // aria-modal surface via useModalSurface.
  useModalSurface({ open, onClose, containerRef: asideRef });

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
        className={`fixed bottom-0 right-0 top-0 z-[41] flex ${WIDTH[size]} animate-slideIn flex-col border-l border-border-2 bg-surface-1 shadow-drawer outline-none`}
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
