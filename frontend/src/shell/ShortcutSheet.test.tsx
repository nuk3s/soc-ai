// Dogfood 2026-10-19. R1-D16: "?" did nothing outside Alerts while the help
// listed it as a global key. H1-D19: after Escape the focus fell to BODY.
import { act, fireEvent, render, screen } from '@testing-library/react';
import { useEffect } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { KEY_HELP } from '../components/KeyHelpOverlay';
import { PALETTE_TRIGGER_ATTR } from './platform';
import { ShellProvider } from './ShellContext';
import { ShortcutSheet } from './ShortcutSheet';

const flush = () => act(async () => { await vi.advanceTimersByTimeAsync(0); });

/** A page key layer that owns "?", the way Alerts does: it calls
 *  preventDefault on its own keys. */
function OwnsQuestionMark() {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === '?') e.preventDefault();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);
  return null;
}

const mount = (extra: React.ReactNode = null) =>
  render(
    <ShellProvider>
      <button type="button" {...{ [PALETTE_TRIGGER_ATTR]: '' }}>
        Search or jump to
      </button>
      <input aria-label="Filter" />
      {extra}
      <ShortcutSheet />
    </ShellProvider>,
  );

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('the "?" key', () => {
  it('opens the shortcut help on any page', async () => {
    mount();
    fireEvent.keyDown(document.body, { key: '?', shiftKey: true });
    await flush();
    expect(screen.getByRole('dialog', { name: 'Keyboard shortcuts' })).toBeTruthy();
  });

  it('does nothing while the analyst types in a field', async () => {
    mount();
    fireEvent.keyDown(screen.getByLabelText('Filter'), { key: '?', shiftKey: true });
    await flush();
    expect(screen.queryByRole('dialog', { name: 'Keyboard shortcuts' })).toBeNull();
  });

  it('leaves the key to a page layer that handled it', async () => {
    mount(<OwnsQuestionMark />);
    fireEvent.keyDown(document.body, { key: '?', shiftKey: true });
    await flush();
    expect(screen.queryByRole('dialog', { name: 'Keyboard shortcuts' })).toBeNull();
  });

  it('gives the focus to the palette trigger after Escape when nothing held it', async () => {
    mount();
    (document.activeElement as HTMLElement | null)?.blur?.();
    fireEvent.keyDown(document.body, { key: '?', shiftKey: true });
    await flush();
    fireEvent.keyDown(document, { key: 'Escape' });
    await flush();
    expect(screen.queryByRole('dialog', { name: 'Keyboard shortcuts' })).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Search or jump to' }));
  });
});

// H1-D24. The help listed "⌘K" on Linux.
describe('the shortcut list', () => {
  it('names the palette key of the platform', async () => {
    vi.stubGlobal('navigator', { ...navigator, platform: 'Linux x86_64', userAgent: 'Mozilla/5.0 (X11; Linux x86_64)' });
    mount();
    fireEvent.keyDown(document.body, { key: '?', shiftKey: true });
    await flush();
    const dialog = screen.getByRole('dialog', { name: 'Keyboard shortcuts' });
    expect(dialog.textContent).toContain('Ctrl K');
    expect(dialog.textContent).not.toContain('⌘K');
  });

  it('lists "?" as a key that works on every page', () => {
    expect(KEY_HELP.find((k) => k.keys === '?')?.label).toBe('Show this shortcut help');
  });
});

// V1-S4: the help listed the Alerts row keys on every page.
describe('the page keys', () => {
  afterEach(() => {
    window.history.pushState({}, '', '/');
  });

  it('lists no Alerts row key on another page, and says where they are', async () => {
    window.history.pushState({}, '', '/app/hunts');
    mount();
    fireEvent.keyDown(document.body, { key: '?', shiftKey: true });
    await flush();
    const dialog = screen.getByRole('dialog', { name: 'Keyboard shortcuts' });
    expect(dialog.textContent).not.toContain('Acknowledge the focused group');
    expect(dialog.textContent).not.toContain('Move focus down / up');
    expect(dialog.textContent).toContain('Show this shortcut help');
    expect(dialog.textContent).toContain(
      'The Alerts page adds row shortcuts. The shortcuts do not fire while you type in a field.',
    );
  });

  it('lists the row keys on Alerts', async () => {
    window.history.pushState({}, '', '/app/alerts');
    mount();
    fireEvent.keyDown(document.body, { key: '?', shiftKey: true });
    await flush();
    const dialog = screen.getByRole('dialog', { name: 'Keyboard shortcuts' });
    expect(dialog.textContent).toContain('Acknowledge the focused group');
    expect(dialog.textContent).toContain('Row shortcuts act on the highlighted detection.');
  });
});
