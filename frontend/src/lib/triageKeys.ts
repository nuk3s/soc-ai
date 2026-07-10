// Pure key → action mapping for the Alerts keyboard-first triage (E2.5).
//
// Extracted verbatim from the Alerts.tsx keydown effect so the guard ORDER,
// the key table, and the clamp semantics are unit-testable without mounting
// the whole screen. The effect in Alerts.tsx stays a thin adapter: it builds
// a TriageKeyContext from component state, calls preventDefault() on any
// non-null action, and dispatches to its local handlers. Behavior contract
// (do not reorder — each guard shadows the ones below it):
//
//   1. palette open            → nothing (the palette owns `/` and Cmd+K)
//   2. focus in an editable    → nothing (typing must never triage)
//   3. help overlay open       → Escape closes it; every other key is inert
//   4. Cmd/Ctrl/Alt held       → nothing (browser shortcuts stay the browser's;
//                                 Shift is allowed — `?` needs it)
//   5. `?`                     → open the cheatsheet
//   6. empty list              → nothing to navigate or act on
//   7. j/↓ k/↑                 → move focus (clamp, no wrap)
//   8. o/Enter a e i x         → row actions, only with a focused row

export interface TriageKeyEvent {
  key: string;
  metaKey: boolean;
  ctrlKey: boolean;
  altKey: boolean;
}

export interface TriageKeyContext {
  /** Command palette open (shared shell signal — no DOM sniffing). */
  paletteOpen: boolean;
  /** The `?` shortcut cheatsheet overlay open. */
  keyHelpOpen: boolean;
  /** Event target is an input/textarea/select/[contenteditable]. */
  targetIsEditable: boolean;
  /** Number of visible (filtered + sorted) alert groups. */
  rowCount: number;
  /** A focused row exists (focusedIndex valid AND the row still rendered). */
  hasFocusedRow: boolean;
}

export type TriageAction =
  | { kind: 'close-help' } // Escape while the cheatsheet is open
  | { kind: 'open-help' } // ?
  | { kind: 'move'; delta: 1 | -1 } // j/ArrowDown, k/ArrowUp
  | { kind: 'open' } // o / Enter — open existing report or investigate
  | { kind: 'ack' } // a
  | { kind: 'escalate' } // e
  | { kind: 'investigate' } // i — same handler as 'open' by design
  | { kind: 'toggle-select' }; // x

/** True when the keydown target is a form control or contenteditable —
 * triage shortcuts must never fire while the user is typing. */
export function isEditableTarget(
  el: { tagName?: string; isContentEditable?: boolean } | null,
): boolean {
  const tag = el?.tagName ?? '';
  return /INPUT|TEXTAREA|SELECT/.test(tag) || el?.isContentEditable === true;
}

/** Map one keydown to a triage action, or null for "not ours — don't
 * preventDefault". See the guard-order contract at the top of the file. */
export function resolveTriageKey(
  e: TriageKeyEvent,
  ctx: TriageKeyContext,
): TriageAction | null {
  if (ctx.paletteOpen) return null;
  if (ctx.targetIsEditable) return null;

  // The cheatsheet overlay owns Esc while it's open (any modifier state).
  if (ctx.keyHelpOpen) {
    return e.key === 'Escape' ? { kind: 'close-help' } : null;
  }

  // Shift is allowed (needed for `?`); Cmd/Ctrl/Alt are not.
  if (e.metaKey || e.ctrlKey || e.altKey) return null;

  if (e.key === '?') return { kind: 'open-help' };

  if (ctx.rowCount === 0) return null;

  switch (e.key) {
    case 'j':
    case 'ArrowDown':
      return { kind: 'move', delta: 1 };
    case 'k':
    case 'ArrowUp':
      return { kind: 'move', delta: -1 };
  }

  // Row actions no-op gracefully when nothing is focused or the row vanished
  // under a refresh.
  if (!ctx.hasFocusedRow) return null;

  switch (e.key) {
    case 'o':
    case 'Enter':
      return { kind: 'open' };
    case 'a':
      return { kind: 'ack' };
    case 'e':
      return { kind: 'escalate' };
    case 'i':
      return { kind: 'investigate' };
    case 'x':
      return { kind: 'toggle-select' };
  }
  return null;
}

/** Next focused index for a move: clamp at the ends (no wrap); entering from
 * "unfocused" (-1) lands on the first row going down, the last going up.
 * Assumes rowCount > 0 (resolveTriageKey never emits 'move' on an empty list). */
export function nextFocusIndex(current: number, delta: 1 | -1, rowCount: number): number {
  if (current < 0) return delta > 0 ? 0 : rowCount - 1;
  return Math.min(rowCount - 1, Math.max(0, current + delta));
}
