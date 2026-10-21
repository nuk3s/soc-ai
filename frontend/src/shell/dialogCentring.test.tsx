import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
// @ts-expect-error The Tailwind config is plain JS with no type declaration.
import tailwindConfig from '../../tailwind.config.js';
import { KeyHelpOverlay } from '../components/KeyHelpOverlay';
import { ChangePasswordModal } from './ChangePasswordModal';
import { ToastProvider } from '../lib/toast';
import { ShellProvider } from './ShellContext';

// Dogfood 2026-10-19 R1-D13. The fadeUp keyframes set `transform`. An
// animation with fill-mode `both` keeps its last frame, so `translateY(0)`
// replaced the `-translate-x-1/2 -translate-y-1/2` that centres a dialog. The
// shortcut help sat with its top edge at the middle of the screen and its
// footer below the fold, and the palette sat right of centre.
describe('dialog centring (R1-D13)', () => {
  const keyframes = (tailwindConfig as { theme: { extend: { keyframes: Record<string, unknown> } } })
    .theme.extend.keyframes;

  it('the fadeUp keyframes do not set transform, so a centring translate survives', () => {
    const frames = keyframes.fadeUp as Record<string, Record<string, string>>;
    for (const frame of Object.values(frames)) {
      expect(Object.keys(frame)).not.toContain('transform');
    }
  });

  it('the shortcut help fits the viewport and scrolls inside', () => {
    render(<KeyHelpOverlay onClose={() => {}} />);
    const dialog = screen.getByRole('dialog', { name: 'Keyboard shortcuts' });
    expect(dialog.className).toMatch(/max-h-\[calc\(100vh/);
    expect(dialog.className).toContain('-translate-y-1/2');
  });

  it('the change password dialog fits the viewport and scrolls inside', () => {
    render(
      <ShellProvider>
        <ToastProvider>
          <ChangePasswordModal open onClose={() => {}} />
        </ToastProvider>
      </ShellProvider>,
    );
    const dialog = screen.getByRole('dialog', { name: 'Change password' });
    expect(dialog.className).toMatch(/max-h-\[calc\(100vh/);
    expect(dialog.className).toContain('overflow-y-auto');
  });
});
