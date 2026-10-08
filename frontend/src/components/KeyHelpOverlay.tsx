import { X } from 'lucide-react';
import type { RefObject } from 'react';

// ── keyboard cheatsheet overlay (E2.5) ──────────────────────────────────────
// A small centered card + backdrop reusing the command-palette overlay styling.
// Lists the Alerts-only row shortcuts AND the global ones (`/`, Cmd+K, `?`, `c`) so
// one panel maps the whole keyboard surface. Alerts opens it with `?`, and the
// command palette opens it from any page.
export const KEY_HELP: Array<{ keys: string; label: string }> = [
  { keys: 'j / k', label: 'Move focus down / up' },
  { keys: '↓ / ↑', label: 'Move focus down / up' },
  { keys: 'o  ↵', label: 'Open the focused detection' },
  { keys: 'a', label: 'Acknowledge the focused group' },
  { keys: 'e', label: 'Escalate the focused group to a case' },
  { keys: 'i', label: 'Investigate the focused group' },
  { keys: 'x', label: 'Select / deselect the focused group' },
  { keys: '/', label: 'Open the command palette to search' },
  { keys: '⌘K', label: 'Toggle the command palette' },
  { keys: '?', label: 'Show this shortcut help' },
  { keys: 'c', label: 'Open Ask soc-ai, the chat about this page' },
  { keys: 'esc', label: 'Close help / palette / drawer / Ask soc-ai' },
];

export function KeyHelpOverlay({
  onClose,
  panelRef,
}: {
  onClose: () => void;
  /** The dialog, for a caller that traps the focus inside it. */
  panelRef?: RefObject<HTMLDivElement>;
}) {
  return (
    <>
      <div onClick={onClose} className="fixed inset-0 z-[60] bg-[rgba(4,6,9,.55)] backdrop-blur-[2px]" />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label="Keyboard shortcuts"
        className="fixed left-1/2 top-1/2 z-[61] -translate-x-1/2 -translate-y-1/2 animate-fadeUp overflow-hidden rounded-panel-lg border border-border-input bg-surface-card shadow-palette"
        style={{ width: 'min(440px,92vw)' }}
      >
        <div className="flex items-center justify-between border-b border-border-2 px-4 py-[13px]">
          <span className="text-[14px] font-semibold text-text">Keyboard shortcuts</span>
          <button onClick={onClose} aria-label="Close" className="flex text-faint hover:text-text">
            <X size={15} />
          </button>
        </div>
        <div className="max-h-[60vh] overflow-y-auto p-2">
          {KEY_HELP.map((k) => (
            <div key={k.keys + k.label} className="flex items-center gap-3 rounded-control px-2.5 py-[7px]">
              <kbd className="min-w-[42px] rounded-[4px] border border-border-input bg-surface-3 px-1.5 py-px text-center font-mono text-[11px] text-text-2">
                {k.keys}
              </kbd>
              <span className="text-[13px] text-dim">{k.label}</span>
            </div>
          ))}
        </div>
        <div className="border-t border-border-2 px-4 py-[9px] font-mono text-[10.5px] text-faint">
          Row shortcuts act on the highlighted detection. The shortcuts do not fire while you type in a filter.
        </div>
      </div>
    </>
  );
}
