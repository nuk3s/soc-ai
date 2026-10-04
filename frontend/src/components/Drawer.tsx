import { useRef } from 'react';
import type { ReactNode, RefObject } from 'react';
import { useModalSurface } from '../lib/useModalSurface';

interface DrawerProps {
  open: boolean;
  onClose: () => void;
  /** content rendered in the fixed header bar */
  header?: ReactNode;
  /** The width. A detail drawer is 620px. `wide` is for content that cannot
   *  fit there: the hunting flow chart is 1600px across. */
  size?: 'default' | 'wide';
  /** The dialog's accessible name. Without it the name is the whole header,
   *  buttons included ("… Permalink Close", fleet P13). */
  ariaLabel?: string;
  /** Where focus goes on close when the opener was not focusable, such as a
   *  list row opened by a keyboard shortcut. */
  returnFocusRef?: RefObject<HTMLElement | null>;
  children: ReactNode;
}

const WIDTH: Record<'default' | 'wide', string> = {
  default: 'w-[620px] max-w-[94vw]',
  wide: 'w-[1480px] max-w-[96vw]',
};

/** Right-side drawer with a blurred scrim. Slides in from the right. */
export function Drawer({
  open,
  onClose,
  header,
  size = 'default',
  ariaLabel,
  returnFocusRef,
  children,
}: DrawerProps) {
  const asideRef = useRef<HTMLElement>(null);

  // Modal-focus contract (stack count, scroll lock, initial focus, Tab trap,
  // Escape-yields-to-palette, focus restore) — shared with every other
  // aria-modal surface via useModalSurface.
  useModalSurface({ open, onClose, containerRef: asideRef, returnFocusRef });

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
        aria-labelledby={header && !ariaLabel ? 'drawer-title' : undefined}
        aria-label={ariaLabel ?? (header ? undefined : 'Detail panel')}
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
