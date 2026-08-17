import { Bell, BookOpen, ChevronsLeft, ChevronsRight, Crosshair, History, Info, LayoutDashboard, Search, Server, Settings, Triangle } from 'lucide-react';
import { NavLink, useLocation } from 'react-router-dom';
import { type ReactNode, useEffect, useState } from 'react';
import { getAbout, getMe } from '../lib/api';
import type { AboutInfo, Me } from '../lib/types';
import { ScopeMark, Wordmark } from '../components/Logo';
import { AccountMenu } from './AccountMenu';
import { useShell } from './ShellContext';

interface NavItem {
  to: string;
  label: string;
  icon: ReactNode;
  /** mark a not-yet-shipped surface so it reads as in-development */
  dev?: boolean;
  /** also active for these path prefixes */
  match?: string[];
}

const NAV: NavItem[] = [
  { to: '/dashboard', label: 'Dashboard', icon: <LayoutDashboard size={16} /> },
  { to: '/alerts', label: 'Alerts', icon: <Triangle size={16} /> },
  { to: '/investigations', label: 'Investigations', icon: <Search size={16} />, match: ['/investigations', '/investigation', '/entity'] },
  // Sits beside Investigations rather than under Config: the dossier is a
  // network view an analyst pivots INTO from an alert, not a settings panel.
  { to: '/hosts', label: 'Hosts', icon: <Server size={16} />, match: ['/hosts'] },
  { to: '/notifications', label: 'Notifications', icon: <Bell size={16} /> },
  { to: '/hunts', label: 'Hunts', icon: <Crosshair size={16} />, match: ['/hunts'] },
  { to: '/backtest', label: 'Backtest', icon: <History size={16} /> },
  { to: '/runbooks', label: 'Runbooks', icon: <BookOpen size={16} /> },
  { to: '/config', label: 'Config', icon: <Settings size={16} /> },
];

export function Sidebar() {
  const { collapsed, toggleNav } = useShell();
  const location = useLocation();

  const [me, setMe] = useState<Me>({ username: 'analyst', role: 'analyst', status: '' });
  const [about, setAbout] = useState<AboutInfo | null>(null);

  useEffect(() => {
    getMe().then(setMe).catch(() => {/* keep placeholder */});
    getAbout().then(setAbout).catch(() => {/* version line just stays hidden */});
  }, []);

  return (
    <div
      className="flex flex-none flex-col overflow-hidden border-r border-border bg-surface-1 px-3 py-3.5 transition-[width] duration-[180ms] ease-in-out"
      style={{ width: collapsed ? 64 : 212 }}
    >
      {/* logo */}
      <div
        className="flex items-center gap-2.5 px-1.5 pb-4 pt-1.5"
        style={{ justifyContent: collapsed ? 'center' : 'flex-start' }}
      >
        <ScopeMark size={28} />
        {!collapsed && <Wordmark />}
      </div>

      {!collapsed ? (
        <div className="px-2 pb-1.5 pt-2 text-[10.5px] font-semibold uppercase tracking-[.07em] text-faint">
          Investigate
        </div>
      ) : (
        <div className="h-3.5" />
      )}

      <nav>
        {NAV.map((n) => {
          const active =
            location.pathname === n.to || (n.match ?? []).some((m) => location.pathname.startsWith(m));
          return (
            <NavLink
              key={n.to}
              to={n.to}
              title={n.label}
              className="mb-0.5 flex items-center gap-2.5 rounded-control px-[9px] py-2 text-[13.5px] font-medium hover:bg-surface-3"
              style={{
                justifyContent: collapsed ? 'center' : 'flex-start',
                background: active ? '#11161e' : 'transparent',
              }}
            >
              <span className="flex w-[17px] flex-none" style={{ color: active ? '#4b8bf5' : '#7d8896' }}>
                {n.icon}
              </span>
              {!collapsed && (
                <span className="flex-1 whitespace-nowrap" style={{ color: active ? '#e6e9ef' : '#8b94a3' }}>
                  {n.label}
                </span>
              )}
              {!collapsed && n.dev && (
                <span
                  className="rounded-chip border px-1.5 py-px text-[9.5px] font-semibold uppercase tracking-[.04em]"
                  style={{ color: '#f5a623', borderColor: 'rgba(245,166,35,.35)', background: 'rgba(245,166,35,.08)' }}
                >
                  dev
                </span>
              )}
            </NavLink>
          );
        })}
      </nav>

      <div className="flex-1" />

      {/* collapse toggle */}
      <button
        onClick={toggleNav}
        title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        className="mb-1.5 flex items-center gap-2.5 rounded-control px-[9px] py-[7px] text-faint hover:bg-surface-3 hover:text-text"
        style={{ justifyContent: collapsed ? 'center' : 'flex-start' }}
      >
        <span className="flex w-[17px] flex-none">
          {collapsed ? <ChevronsRight size={16} /> : <ChevronsLeft size={16} />}
        </span>
        {!collapsed && <span className="flex-1 whitespace-nowrap text-[12.5px] font-medium">Collapse</span>}
      </button>

      {/* version line — quiet, always-visible, deep-links to the About panel */}
      {about && (
        <NavLink
          to="/config#about"
          title={`soc-ai v${about.version} — About`}
          aria-label={`About soc-ai, version ${about.version}`}
          className="mb-1.5 flex items-center gap-2.5 rounded-control px-[9px] py-[6px] text-faint hover:bg-surface-3 hover:text-text"
          style={{ justifyContent: collapsed ? 'center' : 'flex-start' }}
        >
          <span className="flex w-[17px] flex-none justify-center">
            <Info size={15} />
          </span>
          {!collapsed && (
            <span className="flex-1 whitespace-nowrap text-[12px]">
              soc-ai <span className="font-mono text-faint">v{about.version}</span>
            </span>
          )}
        </NavLink>
      )}

      {/* account — one menu, reachable in BOTH sidebar states */}
      <AccountMenu me={me} onMe={setMe} />
    </div>
  );
}
