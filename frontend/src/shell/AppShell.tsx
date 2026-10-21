import { Suspense, type ReactNode } from 'react';
import { RefreshCw, X } from 'lucide-react';
import { Outlet, useLocation } from 'react-router-dom';
import { AskPanel } from '../components/AskPanel';
import { ErrorBoundary } from '../components/ErrorBoundary';
import { RouteFallback } from '../components/States';
import { ChatProvider } from '../lib/chatScope';
import { DEMO_BANNER_H, DemoBanner, DemoProvider, useDemoStatus } from '../lib/demo';
import { NeedsYouProvider } from '../lib/needsYou';
import { ToastProvider } from '../lib/toast';
import { useUpdateCheck } from '../lib/useUpdateCheck';
import { CommandPalette } from './CommandPalette';
import { GeneratedPasswordBanner } from './GeneratedPasswordBanner';
import { PreviousPageTracker } from './PreviousPageTracker';
import { ShortcutSheet } from './ShortcutSheet';
import { SessionProvider, useSession } from './Session';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';

/** The routed screen, held back until /me answers. A screen's own reads are
 *  protected endpoints too, so an unauthenticated visit must not mount it. */
function GatedOutlet() {
  const { status } = useSession();
  if (status === 'pending') return <RouteFallback />;
  return <Outlet />;
}

/** One read of the needs-you count for the sidebar, the bell and the
 *  Dashboard, held until /me answers like every other protected read. */
function SessionNeedsYou({ children }: { children: ReactNode }) {
  const ready = useSession().status === 'ready';
  return <NeedsYouProvider enabled={ready}>{children}</NeedsYouProvider>;
}

/** The one chat panel's state. Its /about read waits for /me like every
 *  other protected read. */
function SessionChat({ children }: { children: ReactNode }) {
  const ready = useSession().status === 'ready';
  return <ChatProvider aboutReady={ready}>{children}</ChatProvider>;
}

/** The global authenticated shell: sidebar + topbar + scrolling content. */
export function AppShell() {
  const update = useUpdateCheck();
  const demo = useDemoStatus();
  const location = useLocation();
  return (
    <DemoProvider demo={demo}>
      <ToastProvider>
      <SessionProvider>
      <SessionNeedsYou>
      <SessionChat>
      {/* Demo honesty banner: pinned above the shell on EVERY screen, never
          dismissible. Absent (and the DOM untouched) outside demo mode. */}
      {demo && <DemoBanner />}
      <div
        className="flex h-screen overflow-hidden"
        style={demo ? { height: `calc(100vh - ${DEMO_BANNER_H}px)` } : undefined}
      >
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <Topbar />
          {/* The generated admin password is still in use (H1-D5). Shown on
              every page until the password changes. */}
          <GeneratedPasswordBanner />
          {/* Bottom padding keeps the last row of a screen clear of the
              update notice, which floats at the bottom right. */}
          <div className="relative flex-1 overflow-y-auto pb-20">
            {/* Boundary inside the shell so lazily-loaded screens don't unmount
                the sidebar/topbar while their chunk loads; the ErrorBoundary
                keeps a crashing screen (render error, dead chunk after a deploy)
                from unmounting the shell — the card renders in the content pane.
                Keyed by pathname so navigating away from a crashed route remounts
                a clean boundary (the crash doesn't wedge every other screen). */}
            <Suspense fallback={<RouteFallback />}>
              <ErrorBoundary key={location.pathname}>
                <GatedOutlet />
              </ErrorBoundary>
            </Suspense>
          </div>
        </div>
        {/* The one chat. Every page opens it from the top bar. */}
        <AskPanel />
        <CommandPalette />
        <ShortcutSheet />
        <PreviousPageTracker />
        {/* Deploy-under-open-tab notice (useUpdateCheck): persistent but
            non-blocking, styled after the Dashboard connection banner. It
            sits under the Ask soc-ai panel (z-45), which would otherwise
            lose its Send button under the notice. */}
        {update.stale && (
          <div
            role="status"
            className="fixed bottom-4 right-4 z-[44] flex max-w-[360px] items-start gap-2.5 rounded-card border px-3.5 py-2.5 text-[13px] shadow-drawer"
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
      </SessionChat>
      </SessionNeedsYou>
      </SessionProvider>
      </ToastProvider>
    </DemoProvider>
  );
}
