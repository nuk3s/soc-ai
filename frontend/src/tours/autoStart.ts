// ---------------------------------------------------------------------------
// When a tour may start by itself.
//
// An automated browser must see the console as it is, with no card over the
// page. A tour never starts by itself when:
//
// - navigator.webdriver is true. Playwright, Selenium and the dogfood scripts
//   set it, so tests/browser and the scripts stay unaffected;
// - the URL has ?tour=off. The tab keeps the switch in sessionStorage, so a
//   script that loads one URL with it and then clicks on is covered too;
// - localStorage "soc-ai.tours.off" is "1";
// - the code runs under vitest, until a test calls
//   allowTourAutoStartInTests() from tours/testing.ts. (happy-dom also reports
//   navigator.webdriver as true; the helper overrides that as well.)
//
// The "?" menu still opens a tour in every one of these cases, so an automated
// check can open a tour on purpose. docs/WEBUI_GUIDE.md "Tours" states the rule.
// ---------------------------------------------------------------------------
import { OFF_KEY } from './state';

export type AutoStartBlock = 'test' | 'webdriver' | 'url' | 'switch';

/** The sessionStorage key that keeps ?tour=off for the tab. */
export const SESSION_OFF_KEY = 'soc-ai.tours.off.session';

let testAllowed = false;

/** For tours/testing.ts only. */
export function setAutoStartAllowedInTests(on: boolean): void {
  testAllowed = on;
}

function urlSaysOff(): boolean {
  try {
    if (new URLSearchParams(window.location.search).get('tour') === 'off') {
      sessionStorage.setItem(SESSION_OFF_KEY, '1');
      return true;
    }
    return sessionStorage.getItem(SESSION_OFF_KEY) === '1';
  } catch {
    return false;
  }
}

/** Why a tour may not start by itself now, or null when it may. */
export function autoStartBlock(): AutoStartBlock | null {
  if (import.meta.env.MODE === 'test' && !testAllowed) return 'test';
  if (typeof navigator !== 'undefined' && navigator.webdriver === true) return 'webdriver';
  if (urlSaysOff()) return 'url';
  try {
    if (localStorage.getItem(OFF_KEY) === '1') return 'switch';
  } catch {
    /* no storage: nothing set the switch */
  }
  return null;
}
