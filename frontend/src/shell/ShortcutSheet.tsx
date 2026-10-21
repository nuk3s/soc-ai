import { useEffect, useRef } from 'react';
import { KeyHelpOverlay, onAlertsPage } from '../components/KeyHelpOverlay';
import { isEditableTarget } from '../lib/triageKeys';
import { useModalSurface } from '../lib/useModalSurface';
import { returnFocusTarget } from './platform';
import { useShell } from './ShellContext';

/** The keyboard shortcut sheet, on any page. The command palette opens it,
 *  and so does the "?" key. It was reachable only with the "?" key on Alerts,
 *  and the help button opened the palette (dogfood 2026-10-06). Then "?" did
 *  nothing outside Alerts while the sheet listed it as a global key (dogfood
 *  2026-10-19, R1-D16). */
export function ShortcutSheet() {
  const { shortcutsOpen, openShortcuts, closeShortcuts, modalOpen } = useShell();
  const panelRef = useRef<HTMLDivElement>(null);
  // Where the focus goes on close. A sheet opened from the keyboard with
  // nothing focused gave the focus back to BODY (H1-D19). Set before the
  // modal surface below moves the focus into the sheet.
  const returnRef = useRef<HTMLElement | null>(null);
  useEffect(() => {
    if (shortcutsOpen) returnRef.current = returnFocusTarget(document.activeElement);
  }, [shortcutsOpen]);
  useModalSurface({
    open: shortcutsOpen,
    onClose: closeShortcuts,
    containerRef: panelRef,
    returnFocusRef: returnRef,
  });

  // "?" opens the sheet, unless a page layer handled the key first. Alerts
  // has its own key layer and its own copy of the sheet, and it calls
  // preventDefault on the keys it handles. The check waits one task, so the
  // order of the two listeners does not matter.
  useEffect(() => {
    if (shortcutsOpen || modalOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== '?' || e.metaKey || e.ctrlKey || e.altKey) return;
      if (isEditableTarget(e.target as HTMLElement | null)) return;
      if (window.location.pathname.includes('login')) return;
      window.setTimeout(() => {
        if (e.defaultPrevented) return;
        // A page copy of the sheet is already open.
        if (document.querySelector('[role="dialog"][aria-label="Keyboard shortcuts"]')) return;
        openShortcuts();
      }, 0);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [shortcutsOpen, modalOpen, openShortcuts]);

  if (!shortcutsOpen) return null;
  return <KeyHelpOverlay onClose={closeShortcuts} panelRef={panelRef} rowKeys={onAlertsPage()} />;
}
