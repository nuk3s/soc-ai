import { X } from 'lucide-react';
import type { RefObject } from 'react';
import { paletteKeyLabel } from '../shell/platform';

// ── keyboard cheatsheet overlay (E2.5) ──────────────────────────────────────
// A small centered card + backdrop reusing the command-palette overlay styling.
// Lists the global shortcuts (`/`, Cmd+K, `?`, `c`) on every page. The
// Alerts row shortcuts show on Alerts only: the help listed them on every
// page, where they do nothing (dogfood 2026-10-19, V1-S4). `?` opens it on
// every page, and the command palette opens it too.
/** A placeholder for the palette key. The overlay prints "⌘K" on a Mac and
 *  "Ctrl K" elsewhere. The list said "⌘K" on Linux (dogfood 2026-10-19). */
const PALETTE_KEY = 'mod+K';

/** The row keys of the Alerts page. They act on the highlighted row. */
export const ROW_KEY_HELP: Array<{ keys: string; label: string }> = [
  { keys: 'j / k', label: 'Move focus down / up' },
  { keys: '↓ / ↑', label: 'Move focus down / up' },
  { keys: 'o  ↵', label: 'Open the focused detection' },
  { keys: 'a', label: 'Acknowledge the focused group' },
  { keys: 'e', label: 'Escalate the focused group to a case' },
  { keys: 'i', label: 'Investigate the focused group' },
  { keys: 'x', label: 'Select / deselect the focused group' },
];

/** The keys that work on every page. */
export const GLOBAL_KEY_HELP: Array<{ keys: string; label: string }> = [
  { keys: '/', label: 'Open the command palette to search' },
  // The key name is the platform's, at render time (PALETTE_KEY below).
  { keys: PALETTE_KEY, label: 'Toggle the command palette' },
  { keys: '?', label: 'Show this shortcut help' },
  { keys: 'c', label: 'Open Ask soc-ai, the chat about this page' },
  { keys: 'esc', label: 'Close help / palette / drawer / Ask soc-ai' },
];

/** Every key the console knows, the row keys first. */
export const KEY_HELP: Array<{ keys: string; label: string }> = [...ROW_KEY_HELP, ...GLOBAL_KEY_HELP];

/** True on the Alerts page, the one page with row keys. The router mounts
 *  the console under a base path, so the check reads the last segment. */
export function onAlertsPage(pathname: string = window.location.pathname): boolean {
  return /\/alerts\/?$/.test(pathname);
}

export function KeyHelpOverlay({
  onClose,
  panelRef,
  rowKeys = false,
}: {
  onClose: () => void;
  /** The dialog, for a caller that traps the focus inside it. */
  panelRef?: RefObject<HTMLDivElement>;
  /** List the Alerts row keys. Only the Alerts page has them. */
  rowKeys?: boolean;
}) {
  const keys = rowKeys ? KEY_HELP : GLOBAL_KEY_HELP;
  return (
    <>
      <div onClick={onClose} className="fixed inset-0 z-[60] bg-[rgba(4,6,9,.55)] backdrop-blur-[2px]" />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label="Keyboard shortcuts"
        className="fixed left-1/2 top-1/2 z-[61] flex max-h-[calc(100vh-32px)] -translate-x-1/2 -translate-y-1/2 animate-fadeUp flex-col overflow-hidden rounded-panel-lg border border-border-input bg-surface-card shadow-palette"
        style={{ width: 'min(440px,92vw)' }}
      >
        <div className="flex items-center justify-between border-b border-border-2 px-4 py-[13px]">
          <span className="text-[14px] font-semibold text-text">Keyboard shortcuts</span>
          <button onClick={onClose} aria-label="Close" className="flex text-faint hover:text-text">
            <X size={15} />
          </button>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto p-2">
          {keys.map((k) => (
            <div key={k.keys + k.label} className="flex items-center gap-3 rounded-control px-2.5 py-[7px]">
              <kbd className="min-w-[42px] rounded-[4px] border border-border-input bg-surface-3 px-1.5 py-px text-center font-mono text-[11px] text-text-2">
                {k.keys === PALETTE_KEY ? paletteKeyLabel() : k.keys}
              </kbd>
              <span className="text-[13px] text-dim">{k.label}</span>
            </div>
          ))}
        </div>
        <div className="border-t border-border-2 px-4 py-[9px] font-mono text-[10.5px] text-faint">
          {rowKeys
            ? 'Row shortcuts act on the highlighted detection. The shortcuts do not fire while you type in a filter.'
            : 'The Alerts page adds row shortcuts. The shortcuts do not fire while you type in a field.'}
        </div>
      </div>
    </>
  );
}
