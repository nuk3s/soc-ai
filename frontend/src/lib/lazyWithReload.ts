import { lazy } from 'react';
import type { ComponentType, LazyExoticComponent } from 'react';

// One-shot reload marker. Present = this tab already tried a reload to recover
// from a failed chunk import, so a second failure is NOT staleness (server
// down, genuinely missing file) and must surface instead of reload-looping.
const RELOAD_FLAG = 'socai-chunk-reload';

// sessionStorage can throw (storage disabled / exotic embed contexts). Treat
// an unreadable flag as "already reloaded": without the marker we cannot rule
// out a reload loop, so fail toward the error boundary, never toward looping.
function flagSet(): boolean {
  try {
    return sessionStorage.getItem(RELOAD_FLAG) !== null;
  } catch {
    return true;
  }
}

function setFlag(): void {
  try {
    sessionStorage.setItem(RELOAD_FLAG, '1');
  } catch {
    // ignore — flagSet() already fails safe when storage is unavailable
  }
}

function clearFlag(): void {
  try {
    sessionStorage.removeItem(RELOAD_FLAG);
  } catch {
    // ignore
  }
}

/**
 * `React.lazy` with self-healing for stale deploys. A deploy replaces the
 * content-hashed chunk files, so an already-open tab that lazily navigates to
 * a not-yet-loaded screen dynamic-imports a dead filename and gets a 404. One
 * full reload fixes that (the fresh index.html points at live chunks) — so on
 * the first import failure we reload in place of rendering anything, and only
 * a repeat failure (flag already set) reaches the error boundary.
 *
 * Drop-in for `lazy()`: keep the named-export `.then` shim in the importer.
 */
export function lazyWithReload<T extends ComponentType<unknown>>(
  importer: () => Promise<{ default: T }>,
): LazyExoticComponent<T> {
  return lazy(() =>
    importer().then(
      (mod) => {
        clearFlag(); // healthy import → re-arm auto-heal for the next deploy
        return mod;
      },
      (err: unknown) => {
        if (flagSet()) throw err; // second strike → let the error boundary show
        setFlag();
        window.location.reload();
        // The reload is in flight; never resolve so React keeps showing the
        // Suspense fallback (a spinner) instead of flashing anything stale.
        return new Promise<never>(() => {});
      },
    ),
  );
}
