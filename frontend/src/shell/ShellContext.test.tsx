// Pins the shared modal-focus contract (DESIGN Q10): ShellContext exposes a
// modal stack so ANY open surface (drawer OR palette) reads as `modalOpen`,
// which the Alerts triage key layer keys off to disarm destructive shortcuts.
import { act, renderHook } from '@testing-library/react';
import type { ReactNode } from 'react';
import { describe, expect, it } from 'vitest';
import { ShellProvider, useShell } from './ShellContext';

const wrapper = ({ children }: { children: ReactNode }) => <ShellProvider>{children}</ShellProvider>;

describe('ShellContext modal stack', () => {
  it('modalOpen tracks push/pop and never resurrects from a negative count', () => {
    const { result } = renderHook(() => useShell(), { wrapper });
    expect(result.current.modalOpen).toBe(false);

    act(() => result.current.pushModal());
    expect(result.current.modalOpen).toBe(true);

    // two open, one closed → still a modal open (nested surfaces)
    act(() => result.current.pushModal());
    act(() => result.current.popModal());
    expect(result.current.modalOpen).toBe(true);

    act(() => result.current.popModal());
    expect(result.current.modalOpen).toBe(false);

    // popping past zero is clamped — no negative count flipping back to "open"
    act(() => result.current.popModal());
    act(() => result.current.pushModal());
    expect(result.current.modalOpen).toBe(true);
  });

  it('an open palette reads as a modal even with an empty modal count', () => {
    const { result } = renderHook(() => useShell(), { wrapper });
    expect(result.current.modalOpen).toBe(false);

    act(() => result.current.openPalette());
    expect(result.current.paletteOpen).toBe(true);
    expect(result.current.modalOpen).toBe(true);

    act(() => result.current.closePalette());
    expect(result.current.modalOpen).toBe(false);
  });
});
