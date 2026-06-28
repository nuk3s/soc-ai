import { Bell, ChevronsLeft, ChevronsRight, Crosshair, LayoutDashboard, LogOut, Search, Settings, Triangle } from 'lucide-react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import { type ReactNode, useEffect, useRef, useState } from 'react';
import { getMe, setMyStatus, signOut } from '../lib/api';
import type { Me } from '../lib/types';
import { ScopeMark, Wordmark } from '../components/Logo';
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
  { to: '/investigations', label: 'Investigations', icon: <Search size={16} /> },
  { to: '/notifications', label: 'Notifications', icon: <Bell size={16} /> },
  { to: '/hunts', label: 'Hunts', icon: <Crosshair size={16} />, dev: true, match: ['/hunts'] },
  { to: '/config', label: 'Config', icon: <Settings size={16} /> },
];

function initials(username: string): string {
  const parts = username.trim().split(/[\s._-]+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  return username.slice(0, 2).toUpperCase();
}

export function Sidebar() {
  const { collapsed, toggleNav } = useShell();
  const navigate = useNavigate();
  const location = useLocation();

  const [me, setMe] = useState<Me>({ username: 'analyst', role: 'analyst', status: '' });
  const [editingStatus, setEditingStatus] = useState(false);
  const [statusDraft, setStatusDraft] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    getMe().then(setMe).catch(() => {/* keep placeholder */});
  }, []);

  function startEdit() {
    setStatusDraft(me.status);
    setEditingStatus(true);
    // Focus after render
    setTimeout(() => inputRef.current?.focus(), 0);
  }

  function commitEdit() {
    const trimmed = statusDraft.trim().slice(0, 64);
    setEditingStatus(false);
    setMyStatus(trimmed)
      .then((r) => setMe((prev) => ({ ...prev, status: r.status })))
      .catch(() => {/* silently leave old value */});
  }

  function cancelEdit() {
    setEditingStatus(false);
    setStatusDraft('');
  }

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
          Triage
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
              <span className="flex w-[17px] flex-none" style={{ color: active ? '#4b8bf5' : '#5b6473' }}>
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
        className="mb-1.5 flex items-center gap-2.5 rounded-control px-[9px] py-[7px] text-faint hover:bg-surface-3 hover:text-text"
        style={{ justifyContent: collapsed ? 'center' : 'flex-start' }}
      >
        <span className="flex w-[17px] flex-none">
          {collapsed ? <ChevronsRight size={16} /> : <ChevronsLeft size={16} />}
        </span>
        {!collapsed && <span className="flex-1 whitespace-nowrap text-[12.5px] font-medium">Collapse</span>}
      </button>

      {/* user row */}
      <div
        className="flex items-center gap-[9px] border-t border-border pt-2.5"
        style={{ justifyContent: collapsed ? 'center' : 'flex-start' }}
      >
        <div
          title={`${me.username} · ${me.role}`}
          className="flex h-7 w-7 flex-none items-center justify-center rounded-full border border-border-input text-[11px] font-semibold text-[#b9c2cf]"
          style={{ background: 'linear-gradient(135deg,#2c3340,#1a1f28)' }}
        >
          {initials(me.username)}
        </div>
        {!collapsed && (
          <>
            <div className="min-w-0 flex-1">
              <div className="truncate text-[12.5px] font-semibold">{me.username}</div>
              {editingStatus ? (
                <input
                  ref={inputRef}
                  value={statusDraft}
                  maxLength={64}
                  onChange={(e) => setStatusDraft(e.target.value)}
                  onBlur={commitEdit}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') commitEdit();
                    if (e.key === 'Escape') cancelEdit();
                  }}
                  className="w-full rounded bg-bg px-1 py-px text-[10.5px] text-text outline-none focus:ring-1 focus:ring-accent"
                  placeholder="Set status…"
                />
              ) : (
                <div
                  onClick={startEdit}
                  title="Click to set status"
                  className="cursor-text truncate text-[10.5px] text-faint hover:text-text"
                >
                  {me.status || <span className="italic opacity-50">Set status…</span>}
                </div>
              )}
            </div>
            <button
              onClick={() => signOut(navigate)}
              title="Sign out"
              className="flex text-faint hover:text-text"
            >
              <LogOut size={15} />
            </button>
          </>
        )}
      </div>
    </div>
  );
}
