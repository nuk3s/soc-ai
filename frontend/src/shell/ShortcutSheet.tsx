import { useRef } from 'react';
import { KeyHelpOverlay } from '../components/KeyHelpOverlay';
import { useModalSurface } from '../lib/useModalSurface';
import { useShell } from './ShellContext';

/** The keyboard shortcut sheet, opened from the command palette on any page.
 *  It was reachable only with the "?" key on Alerts, and the help button
 *  opened the palette (dogfood 2026-10-06). */
export function ShortcutSheet() {
  const { shortcutsOpen, closeShortcuts } = useShell();
  const panelRef = useRef<HTMLDivElement>(null);
  useModalSurface({ open: shortcutsOpen, onClose: closeShortcuts, containerRef: panelRef });
  if (!shortcutsOpen) return null;
  return <KeyHelpOverlay onClose={closeShortcuts} panelRef={panelRef} />;
}
