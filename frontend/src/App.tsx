import { Suspense } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { ErrorBoundary } from './components/ErrorBoundary';
import { RouteFallback } from './components/States';
import { lazyWithReload } from './lib/lazyWithReload';
import { AppShell } from './shell/AppShell';

// Route screens are code-split: each loads on first navigation (chunked by
// Vite), keeping the entry bundle to the shell + router. Screens use named
// exports, hence the `.then` shims. The shared Suspense fallback lives in
// AppShell (around the Outlet) so the shell stays mounted during loads; the
// boundary here covers the routes outside the shell (login).
// lazyWithReload (not bare lazy): a deploy replaces the hashed chunks, so an
// open tab's first navigation to a stale filename 404s — the wrapper reloads
// once to pick up the fresh build, and only a repeat failure surfaces the
// ErrorBoundary card.
const Alerts = lazyWithReload(() => import('./screens/Alerts').then((m) => ({ default: m.Alerts })));
const Backtest = lazyWithReload(() => import('./screens/Backtest').then((m) => ({ default: m.Backtest })));
const Config = lazyWithReload(() => import('./screens/Config').then((m) => ({ default: m.Config })));
const Dashboard = lazyWithReload(() => import('./screens/Dashboard').then((m) => ({ default: m.Dashboard })));
const Entity = lazyWithReload(() => import('./screens/Entity').then((m) => ({ default: m.Entity })));
const HuntDetail = lazyWithReload(() => import('./screens/HuntDetail').then((m) => ({ default: m.HuntDetail })));
const Hunts = lazyWithReload(() => import('./screens/Hunts').then((m) => ({ default: m.Hunts })));
const Investigations = lazyWithReload(() => import('./screens/Investigations').then((m) => ({ default: m.Investigations })));
const InvestigationPage = lazyWithReload(() => import('./screens/InvestigationPage').then((m) => ({ default: m.InvestigationPage })));
const Login = lazyWithReload(() => import('./screens/Login').then((m) => ({ default: m.Login })));
const Notifications = lazyWithReload(() => import('./screens/Notifications').then((m) => ({ default: m.Notifications })));
const Runbooks = lazyWithReload(() => import('./screens/Runbooks').then((m) => ({ default: m.Runbooks })));

export function App() {
  return (
    <Suspense fallback={<RouteFallback />}>
      {/* Boundary above the routes: a crash in Login (or any route render)
          shows the error card instead of unmounting the whole tree. In-shell
          routes are additionally covered by the boundary around the Outlet in
          AppShell, which catches first and keeps the shell mounted. */}
      <ErrorBoundary>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route element={<AppShell />}>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/investigations" element={<Investigations />} />
            <Route path="/investigation/:id" element={<InvestigationPage />} />
            <Route path="/notifications" element={<Notifications />} />
            <Route path="/hunts" element={<Hunts />} />
            <Route path="/hunts/:id" element={<HuntDetail />} />
            <Route path="/entity/:value" element={<Entity />} />
            <Route path="/backtest" element={<Backtest />} />
            <Route path="/runbooks" element={<Runbooks />} />
            <Route path="/config" element={<Config />} />
          </Route>
          <Route path="/" element={<Navigate to="/login" replace />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </ErrorBoundary>
    </Suspense>
  );
}
