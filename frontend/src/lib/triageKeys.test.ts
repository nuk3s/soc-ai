// Pins the keyboard-triage contract (E2.5) extracted from Alerts.tsx: the
// guard ORDER (palette > editable target > help overlay > modifiers), the
// key → action table, and the clamp-no-wrap focus movement. A regression here
// means triage keys firing while the analyst types, or dead shortcuts.
import { describe, expect, it } from 'vitest';
import {
  isEditableTarget,
  nextFocusIndex,
  resolveTriageKey,
  type TriageKeyContext,
  type TriageKeyEvent,
} from './triageKeys';

const key = (k: string, mods: Partial<TriageKeyEvent> = {}): TriageKeyEvent => ({
  key: k,
  metaKey: false,
  ctrlKey: false,
  altKey: false,
  ...mods,
});

const ctx = (over: Partial<TriageKeyContext> = {}): TriageKeyContext => ({
  paletteOpen: false,
  keyHelpOpen: false,
  targetIsEditable: false,
  rowCount: 5,
  hasFocusedRow: true,
  ...over,
});

describe('resolveTriageKey', () => {
  it('maps the full key table when a row is focused', () => {
    expect(resolveTriageKey(key('j'), ctx())).toEqual({ kind: 'move', delta: 1 });
    expect(resolveTriageKey(key('ArrowDown'), ctx())).toEqual({ kind: 'move', delta: 1 });
    expect(resolveTriageKey(key('k'), ctx())).toEqual({ kind: 'move', delta: -1 });
    expect(resolveTriageKey(key('ArrowUp'), ctx())).toEqual({ kind: 'move', delta: -1 });
    expect(resolveTriageKey(key('o'), ctx())).toEqual({ kind: 'open' });
    expect(resolveTriageKey(key('Enter'), ctx())).toEqual({ kind: 'open' });
    expect(resolveTriageKey(key('a'), ctx())).toEqual({ kind: 'ack' });
    expect(resolveTriageKey(key('e'), ctx())).toEqual({ kind: 'escalate' });
    expect(resolveTriageKey(key('i'), ctx())).toEqual({ kind: 'investigate' });
    expect(resolveTriageKey(key('x'), ctx())).toEqual({ kind: 'toggle-select' });
    expect(resolveTriageKey(key('?'), ctx())).toEqual({ kind: 'open-help' });
    expect(resolveTriageKey(key('z'), ctx())).toBeNull(); // unbound key → browser's
  });

  it('hard guards swallow everything: palette open, typing in a field, Cmd/Ctrl/Alt held', () => {
    expect(resolveTriageKey(key('j'), ctx({ paletteOpen: true }))).toBeNull();
    expect(resolveTriageKey(key('j'), ctx({ targetIsEditable: true }))).toBeNull();
    // Editable target outranks even the help overlay's Escape (guard order).
    expect(
      resolveTriageKey(key('Escape'), ctx({ keyHelpOpen: true, targetIsEditable: true })),
    ).toBeNull();
    for (const mod of ['metaKey', 'ctrlKey', 'altKey'] as const) {
      expect(resolveTriageKey(key('a', { [mod]: true }), ctx())).toBeNull();
    }
  });

  it('help overlay owns Escape (any modifiers); every other key is inert while open', () => {
    expect(resolveTriageKey(key('Escape'), ctx({ keyHelpOpen: true }))).toEqual({
      kind: 'close-help',
    });
    // Modifier gate sits BELOW the help-overlay branch — Ctrl+Esc still closes.
    expect(
      resolveTriageKey(key('Escape', { ctrlKey: true }), ctx({ keyHelpOpen: true })),
    ).toEqual({ kind: 'close-help' });
    expect(resolveTriageKey(key('j'), ctx({ keyHelpOpen: true }))).toBeNull();
    expect(resolveTriageKey(key('?'), ctx({ keyHelpOpen: true }))).toBeNull();
  });

  it('empty list mutes nav+actions (help still opens); no focused row mutes actions only', () => {
    expect(resolveTriageKey(key('j'), ctx({ rowCount: 0 }))).toBeNull();
    expect(resolveTriageKey(key('a'), ctx({ rowCount: 0 }))).toBeNull();
    expect(resolveTriageKey(key('?'), ctx({ rowCount: 0 }))).toEqual({ kind: 'open-help' });
    // j/k can ENTER focus from the unfocused state; row actions cannot fire there.
    expect(resolveTriageKey(key('j'), ctx({ hasFocusedRow: false }))).toEqual({
      kind: 'move',
      delta: 1,
    });
    expect(resolveTriageKey(key('a'), ctx({ hasFocusedRow: false }))).toBeNull();
  });
});

describe('nextFocusIndex', () => {
  it('clamps at both ends (no wrap) and enters from unfocused at the correct end', () => {
    expect(nextFocusIndex(2, 1, 5)).toBe(3); // plain step
    expect(nextFocusIndex(4, 1, 5)).toBe(4); // bottom: clamp, no wrap to 0
    expect(nextFocusIndex(0, -1, 5)).toBe(0); // top: clamp, no wrap to end
    expect(nextFocusIndex(-1, 1, 5)).toBe(0); // unfocused + down → first row
    expect(nextFocusIndex(-1, -1, 5)).toBe(4); // unfocused + up → last row
  });
});

describe('isEditableTarget', () => {
  it('flags form controls and contenteditable, not plain elements or null', () => {
    expect(isEditableTarget({ tagName: 'INPUT' })).toBe(true);
    expect(isEditableTarget({ tagName: 'TEXTAREA' })).toBe(true);
    expect(isEditableTarget({ tagName: 'SELECT' })).toBe(true);
    expect(isEditableTarget({ tagName: 'DIV', isContentEditable: true })).toBe(true);
    expect(isEditableTarget({ tagName: 'DIV' })).toBe(false);
    expect(isEditableTarget(null)).toBe(false);
  });
});
