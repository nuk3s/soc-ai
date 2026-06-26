import { defineConfig } from 'vite'
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
})
