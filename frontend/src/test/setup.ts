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
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

afterEach(() => {
  cleanup();
});
