import { Suspense, lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { RouteFallback } from './components/States';
import { AppShell } from './shell/AppShell';

// Route screens are code-split: each loads on first navigation (chunked by
// Vite), keeping the entry bundle to the shell + router. Screens use named
// exports, hence the `.then` shims. The shared Suspense fallback lives in
// AppShell (around the Outlet) so the shell stays mounted during loads; the
// boundary here covers the routes outside the shell (login).
const Alerts = lazy(() => import('./screens/Alerts').then((m) => ({ default: m.Alerts })));
const Backtest = lazy(() => import('./screens/Backtest').then((m) => ({ default: m.Backtest })));
const Config = lazy(() => import('./screens/Config').then((m) => ({ default: m.Config })));
const Dashboard = lazy(() => import('./screens/Dashboard').then((m) => ({ default: m.Dashboard })));
const Entity = lazy(() => import('./screens/Entity').then((m) => ({ default: m.Entity })));
const HuntDetail = lazy(() => import('./screens/HuntDetail').then((m) => ({ default: m.HuntDetail })));
const Hunts = lazy(() => import('./screens/Hunts').then((m) => ({ default: m.Hunts })));
const Investigations = lazy(() => import('./screens/Investigations').then((m) => ({ default: m.Investigations })));
const InvestigationPage = lazy(() => import('./screens/InvestigationPage').then((m) => ({ default: m.InvestigationPage })));
const Login = lazy(() => import('./screens/Login').then((m) => ({ default: m.Login })));
const Notifications = lazy(() => import('./screens/Notifications').then((m) => ({ default: m.Notifications })));
const Runbooks = lazy(() => import('./screens/Runbooks').then((m) => ({ default: m.Runbooks })));

export function App() {
  return (
    <Suspense fallback={<RouteFallback />}>
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
    </Suspense>
  );
}
