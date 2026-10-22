// ---------------------------------------------------------------------------
// Test helpers for the tours. Imported by vitest files only.
// ---------------------------------------------------------------------------
import { SESSION_OFF_KEY, setAutoStartAllowedInTests } from './autoStart';
import type { Tour } from './types';

/**
 * The anchors of a tour that have no element under `root`.
 *
 * A smoke test renders a screen with data and asserts this is empty, so a
 * renamed or removed `data-tour` attribute fails a test. The check is on the
 * attribute only: happy-dom lays nothing out, so visibility is a browser
 * question.
 */
export function missingAnchors(tour: Tour, root: ParentNode = document): string[] {
  const missing: string[] = [];
  for (const step of tour.steps) {
    if (!root.querySelector(`[data-tour="${CSS.escape(step.anchor)}"]`)) missing.push(step.anchor);
  }
  return [...new Set(missing)];
}

/**
 * Let a tour start by itself in this test.
 *
 * Under vitest no tour starts by itself (autoStart.ts), and happy-dom also
 * reports navigator.webdriver as true. This helper lifts both, so a trigger
 * test sees the console the way an operator sees it. Call
 * resetTourAutoStartForTests() in afterEach.
 */
export function allowTourAutoStartInTests(): void {
  setAutoStartAllowedInTests(true);
  Object.defineProperty(navigator, 'webdriver', { configurable: true, get: () => false });
}

/** Undo allowTourAutoStartInTests(), and clear the ?tour=off switch of the tab. */
export function resetTourAutoStartForTests(): void {
  setAutoStartAllowedInTests(false);
  // The own property shadows the prototype getter. Deleting it restores the
  // happy-dom value.
  delete (navigator as unknown as Record<string, unknown>).webdriver;
  try {
    sessionStorage.removeItem(SESSION_OFF_KEY);
  } catch {
    /* no storage */
  }
}
