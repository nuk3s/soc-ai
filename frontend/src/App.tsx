import { Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from './shell/AppShell';
import { Alerts } from './screens/Alerts';
import { Backtest } from './screens/Backtest';
import { Config } from './screens/Config';
import { Dashboard } from './screens/Dashboard';
import { HuntDetail } from './screens/HuntDetail';
import { Hunts } from './screens/Hunts';
import { Investigations } from './screens/Investigations';
import { InvestigationPage } from './screens/InvestigationPage';
import { Login } from './screens/Login';
import { Notifications } from './screens/Notifications';

export function App() {
  return (
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
        <Route path="/backtest" element={<Backtest />} />
        <Route path="/config" element={<Config />} />
      </Route>
      <Route path="/" element={<Navigate to="/login" replace />} />
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  );
}
