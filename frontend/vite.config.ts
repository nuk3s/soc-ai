// vitest/config re-exports Vite's defineConfig with the `test` key typed, so
// one file configures both the build and the unit-test runner (Vite 5 idiom).
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// The SPA is served under /app by FastAPI (parallel to the legacy /ui during
// migration), so `base` makes built asset URLs absolute under /app/. The dev
// server also serves under /app/.
//
// The dev proxy lets `npm run dev` talk to a real backend: set VITE_API_PROXY to
// your soc-ai origin (e.g. https://soc-ai.example:8443). If the backend has
// API_AUTH_REQUIRED on, also set VITE_API_TOKEN so api.ts sends a bearer.
// Defaults to same-origin (no cross-origin proxy) so no host is baked in.
const apiTarget = process.env.VITE_API_PROXY || 'https://127.0.0.1:8443'

// https://vite.dev/config/
export default defineConfig({
  base: '/app/',
  plugins: [react()],
  server: {
    proxy: {
      '/api': { target: apiTarget, changeOrigin: true, secure: false },
    },
  },
  test: {
    // happy-dom over jsdom, deliberately: jsdom implements the WHATWG
    // LegacyUnforgeable Location (window.location and location.reload are
    // non-configurable — verified on jsdom 26), so the reload-on-stale-chunk
    // path in lazyWithReload/ErrorBoundary cannot be stubbed under jsdom at
    // all. happy-dom's location is configurable (mockable) and the runner is
    // faster; none of our components need jsdom-only APIs.
    environment: 'happy-dom',
    environmentOptions: {
      happyDOM: {
        // Script/CSS file loading is (rightly) off in tests, but happy-dom
        // reports each refused load as a console error. useUpdateCheck's tests
        // must insert a real `<script type=module src=/app/assets/…>` (the
        // hook reads it from the DOM), so treat refused loads as silent
        // successes instead of stderr noise.
        settings: { handleDisabledFileLoadingAsSuccess: true },
      },
    },
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
  },
})
