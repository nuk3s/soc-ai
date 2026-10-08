import { Suspense, useEffect, useState } from 'react';
import { Link, Navigate, Route, Routes, useLocation, useParams } from 'react-router-dom';
import { ErrorBoundary } from './components/ErrorBoundary';
import { RouteFallback } from './components/States';
import { getMe } from './lib/api';
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
const HostDetail = lazyWithReload(() => import('./screens/HostDetail').then((m) => ({ default: m.HostDetail })));
const Hosts = lazyWithReload(() => import('./screens/Hosts').then((m) => ({ default: m.Hosts })));
const HuntDetail = lazyWithReload(() => import('./screens/HuntDetail').then((m) => ({ default: m.HuntDetail })));
const Hunts = lazyWithReload(() => import('./screens/Hunts').then((m) => ({ default: m.Hunts })));
const Investigations = lazyWithReload(() => import('./screens/Investigations').then((m) => ({ default: m.Investigations })));
const InvestigationPage = lazyWithReload(() => import('./screens/InvestigationPage').then((m) => ({ default: m.InvestigationPage })));
const LeadDetail = lazyWithReload(() => import('./screens/LeadDetail').then((m) => ({ default: m.LeadDetail })));
const Login = lazyWithReload(() => import('./screens/Login').then((m) => ({ default: m.Login })));
const Notifications = lazyWithReload(() => import('./screens/Notifications').then((m) => ({ default: m.Notifications })));
const Operate = lazyWithReload(() => import('./screens/Operate').then((m) => ({ default: m.Operate })));
const Runbooks = lazyWithReload(() => import('./screens/Runbooks').then((m) => ({ default: m.Runbooks })));

/**
 * The /entity/:value route.
 *
 * The route used to send every private address to the host page before
 * anything was read. An address an investigation named that no machine holds
 * then opened "the network sweep has never seen this address", and the
 * investigations that named it were one more click away (dogfood 2026-10-06,
 * S2). The entity page now asks which machine holds the value: a machine
 * opens its page, and any other value stays on the entity page.
 *
 * The key is keyed on the value, so a link to a second entity remounts the
 * page with no state left over from the first.
 */
function EntityRoute() {
  const { value = '' } = useParams();
  return <Entity key={value} />;
}

/**
 * An address that is no page. It redirected to the Dashboard and said
 * nothing, so a mistyped or stale link read as a link to the Dashboard
 * (dogfood 2026-10-06). The page says so, names the address and offers the
 * Dashboard. It renders inside the shell, so the sidebar and the search stay.
 */
function UnknownRoute() {
  const { pathname } = useLocation();
  return (
    <div className="px-[22px] pb-[60px] pt-5">
      <div
        data-testid="unknown-route"
        className="mx-auto flex max-w-[560px] flex-col items-center gap-2 rounded-card border border-border bg-surface-1 px-4 py-8 text-center"
      >
        <div className="text-[13.5px] font-semibold text-text-2">No page at this address.</div>
        <div className="text-[12.5px] leading-[1.6] text-faint">
          The console has no page at <span className="font-mono text-dim">{pathname}</span>. The link
          is wrong or out of date.
        </div>
        <Link
          to="/dashboard"
          className="mt-1 rounded-control border border-border-strong bg-surface-3 px-3 py-1.5 text-[12px] font-semibold text-text-2 hover:border-accent hover:text-text"
        >
          Open the Dashboard
        </Link>
      </div>
    </div>
  );
}

/**
 * The bare root. With auth on, `/me` is a 401 and the login screen is the
 * right place to land. With auth off (the lab default) `/me` answers with
 * the anonymous admin, and sending that reader to a login form they cannot
 * use is a dead end: the first thing the range tester saw was a password
 * prompt on an instance that has no passwords.
 */
function RootRoute() {
  const [to, setTo] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    getMe().then(
      () => live && setTo('/dashboard'),
      () => live && setTo('/login'),
    );
    return () => {
      live = false;
    };
  }, []);
  if (to === null) return <RouteFallback />;
  return <Navigate to={to} replace />;
}

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
            <Route path="/leads/:id" element={<LeadDetail />} />
            <Route path="/entity/:value" element={<EntityRoute />} />
            <Route path="/hosts" element={<Hosts />} />
            <Route path="/hosts/:key" element={<HostDetail />} />
            <Route path="/operate" element={<Operate />} />
            <Route path="/backtest" element={<Backtest />} />
            <Route path="/runbooks" element={<Runbooks />} />
            <Route path="/config" element={<Config />} />
            <Route path="*" element={<UnknownRoute />} />
          </Route>
          <Route path="/" element={<RootRoute />} />
        </Routes>
      </ErrorBoundary>
    </Suspense>
  );
}
