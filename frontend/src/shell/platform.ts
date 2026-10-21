// Small shell facts that depend on the browser: the modifier key name, and
// where the focus goes when a dialog closes with no opener to return to.

/** True on macOS and iOS, where the palette shortcut is the command key. */
export function isMacPlatform(): boolean {
  if (typeof navigator === 'undefined') return false;
  const platform = navigator.platform ?? '';
  const agent = navigator.userAgent ?? '';
  return /Mac|iPhone|iPad|iPod/i.test(platform) || /Macintosh|Mac OS X|iPhone|iPad/i.test(agent);
}

/** The palette shortcut as the keyboard prints it: "⌘K" on a Mac, "Ctrl K"
 *  elsewhere. The search box showed "⌘K" on Linux (dogfood 2026-10-19,
 *  H1-D24). Both keys open the palette on every platform. */
export function paletteKeyLabel(): string {
  return isMacPlatform() ? '⌘K' : 'Ctrl K';
}

/** The attribute on the top bar's "Search or jump to" button. A dialog that
 *  opened from the keyboard with nothing focused returns the focus here. */
export const PALETTE_TRIGGER_ATTR = 'data-palette-trigger';

/** Where the focus goes when a dialog closes: the element that held it when
 *  the dialog opened, or the palette trigger when that was the page body or
 *  is gone. After Escape the focus fell to BODY (dogfood 2026-10-19, H1-D19),
 *  and the next Tab started again at the top of the page. */
export function returnFocusTarget(opener: Element | null): HTMLElement | null {
  if (
    opener instanceof HTMLElement &&
    opener !== document.body &&
    opener !== document.documentElement &&
    opener.isConnected
  ) {
    return opener;
  }
  return document.querySelector<HTMLElement>(`[${PALETTE_TRIGGER_ATTR}]`);
}
