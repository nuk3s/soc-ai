import { Suspense } from 'react';
import { RefreshCw, X } from 'lucide-react';
import { Outlet, useLocation } from 'react-router-dom';
import { ErrorBoundary } from '../components/ErrorBoundary';
import { RouteFallback } from '../components/States';
import { useUpdateCheck } from '../lib/useUpdateCheck';
import { CommandPalette } from './CommandPalette';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';

/** The global authenticated shell: sidebar + topbar + scrolling content. */
export function AppShell() {
  const update = useUpdateCheck();
  const location = useLocation();
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar />
        <div className="relative flex-1 overflow-y-auto">
          {/* Boundary inside the shell so lazily-loaded screens don't unmount
              the sidebar/topbar while their chunk loads; the ErrorBoundary
              keeps a crashing screen (render error, dead chunk after a deploy)
              from unmounting the shell — the card renders in the content pane.
              Keyed by pathname so navigating away from a crashed route remounts
              a clean boundary (the crash doesn't wedge every other screen). */}
          <Suspense fallback={<RouteFallback />}>
            <ErrorBoundary key={location.pathname}>
              <Outlet />
            </ErrorBoundary>
          </Suspense>
        </div>
      </div>
      <CommandPalette />
      {/* Deploy-under-open-tab notice (useUpdateCheck): persistent but
          non-blocking, styled after the Dashboard connection banner. */}
      {update.stale && (
        <div
          role="status"
          className="fixed bottom-4 right-4 z-50 flex max-w-[360px] items-start gap-2.5 rounded-card border px-3.5 py-2.5 text-[13px] shadow-drawer"
          style={{ borderColor: 'rgba(75,139,245,.4)', background: '#0e1117' }}
        >
          <span className="mt-px flex flex-shrink-0 text-accent">
            <RefreshCw size={15} />
          </span>
          <div className="min-w-0 flex-1">
            <div className="font-semibold text-text-2">soc-ai was updated</div>
            <div className="mt-0.5 text-[12px] leading-[1.5] text-dim">
              Reload for the latest version.
            </div>
            <button
              onClick={() => window.location.reload()}
              className="mt-2 rounded-control border border-border-strong bg-surface-3 px-3 py-1.5 text-[12px] font-semibold text-text hover:border-accent"
            >
              Reload
            </button>
          </div>
          <button
            onClick={update.dismiss}
            className="mt-px flex text-dim hover:text-text"
            aria-label="Dismiss"
          >
            <X size={14} />
          </button>
        </div>
      )}
    </div>
  );
}
