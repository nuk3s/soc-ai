import { Suspense } from 'react';
import { Outlet } from 'react-router-dom';
import { RouteFallback } from '../components/States';
import { CommandPalette } from './CommandPalette';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';

/** The global authenticated shell: sidebar + topbar + scrolling content. */
export function AppShell() {
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar />
        <div className="relative flex-1 overflow-y-auto">
          {/* Boundary inside the shell so lazily-loaded screens don't unmount
              the sidebar/topbar while their chunk loads. */}
          <Suspense fallback={<RouteFallback />}>
            <Outlet />
          </Suspense>
        </div>
      </div>
      <CommandPalette />
    </div>
  );
}
