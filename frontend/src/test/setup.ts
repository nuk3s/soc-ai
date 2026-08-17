// Shared vitest setup (wired via `test.setupFiles` in vite.config.ts).
//
// - jest-dom's /vitest entry registers the DOM matchers on vitest's `expect`
//   AND module-augments vitest's Assertion type, so `toBeInTheDocument()` etc.
//   typecheck everywhere (this file is inside tsconfig.app.json's `src`
//   include, which is what makes the augmentation program-wide).
// - Explicit RTL cleanup: we run with `globals: false` (explicit imports keep
//   test files honest), and RTL only auto-registers its afterEach cleanup when
//   test globals exist — so without this, mounted trees leak across tests.
import '@testing-library/jest-dom/vitest';
import { cleanup, configure } from '@testing-library/react';
import { afterEach, beforeEach, vi } from 'vitest';

// findBy*/waitFor default to 1000ms, which a loaded run can miss on a single
// state hop. 5s is the working bound; it MUST stay below vite.config.ts's
// testTimeout (15s) with margin. When the two were equal the runner killed the
// test at the instant the wait expired, so every failure read as a bare "Test
// timed out" with no assertion — the gap is what turns a miss into a readable
// "unable to find element", which is how the flake below was finally diagnosed
// instead of guessed at. Raising this further does NOT help: the real cause was
// worker starvation, fixed by `fileParallelism: false` in vite.config.ts.
configure({ asyncUtilTimeout: 5000 });

// Default fetch for every test: reject, loudly and instantly. Spread-
// importOriginal api mock factories keep the REAL implementation for any
// function they omit, so a screen that calls an omitted function fetches
// against ::1:3000 for real — a latency race that only fails under load
// (the Dashboard.generalChat flake, da26d74). This guard turns that class
// of gap into a deterministic, named failure. Registered here (setupFiles
// hooks run first), so a test file's own `vi.stubGlobal('fetch', ...)` in
// its beforeEach still wins.
beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    (input: RequestInfo | URL, init?: RequestInit) =>
      Promise.reject(
        new Error(
          `Unmocked network call in test: ${init?.method ?? 'GET'} ${String(input)} — ` +
            'add the api function to your vi.mock("../lib/api") factory ' +
            'or vi.stubGlobal("fetch", ...) in this suite.',
        ),
      ),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
