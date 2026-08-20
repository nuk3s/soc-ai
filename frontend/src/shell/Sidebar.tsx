import {
  Bell,
  BookOpen,
  ChevronDown,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Crosshair,
  History,
  Info,
  LayoutDashboard,
  Search,
  Server,
  Settings,
  Triangle,
  Wrench,
} from 'lucide-react';
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

interface NavGroup {
  label: string;
  /** Collapsible groups persist their open/closed state under localStorage
   * (see OPERATE_NAV_KEY). Investigate omits this — the analyst loop is
   * always fully shown. */
  collapsible?: boolean;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Investigate',
    items: [
      { to: '/dashboard', label: 'Dashboard', icon: <LayoutDashboard size={16} /> },
      { to: '/alerts', label: 'Alerts', icon: <Triangle size={16} /> },
      { to: '/investigations', label: 'Investigations', icon: <Search size={16} />, match: ['/investigations', '/investigation', '/entity'] },
      // Sits beside Investigations rather than under Config: the dossier is a
      // network view an analyst pivots INTO from an alert, not a settings panel.
      { to: '/hosts', label: 'Hosts', icon: <Server size={16} />, match: ['/hosts'] },
      { to: '/notifications', label: 'Notifications', icon: <Bell size={16} /> },
      { to: '/hunts', label: 'Hunts', icon: <Crosshair size={16} />, match: ['/hunts'] },
    ],
  },
  {
    // The operator's loop rather than the analyst's: prove the model/audit
    // chain are trustworthy, replay history, configure. Collapsed by default
    // (see OPERATE_NAV_KEY) so a first-run session reads as an analyst tool,
    // not a cockpit — Wave-2 progressive disclosure.
    label: 'Operate',
    collapsible: true,
    items: [
      // The hub entry leads the group (route lives in App.tsx).
      { to: '/operate', label: 'Operate', icon: <Wrench size={16} /> },
      { to: '/runbooks', label: 'Runbooks', icon: <BookOpen size={16} /> },
      { to: '/backtest', label: 'Backtest', icon: <History size={16} /> },
      { to: '/config', label: 'Config', icon: <Settings size={16} /> },
    ],
  },
];

/** Per-item active check, shared by row styling and the group-level
 * force-expand test below (same rule: exact path or a `match` prefix). */
function isItemActive(item: NavItem, pathname: string): boolean {
  return pathname === item.to || (item.match ?? []).some((m) => pathname.startsWith(m));
}

const OPERATE_NAV_KEY = 'soc-ai:navOperateCollapsed';

function readStoredOperateCollapsed(): boolean {
  try {
    // DEFAULT COLLAPSED — the inverse default of whole-sidebar `navCollapsed`
    // (which defaults to expanded). Only an explicit prior expand (stored
    // '0') opts back in; absent/garbage both read as collapsed.
    return localStorage.getItem(OPERATE_NAV_KEY) !== '0';
  } catch {
    return true;
  }
}

export function Sidebar() {
  const { collapsed, toggleNav } = useShell();
  const location = useLocation();

  const [me, setMe] = useState<Me>({ username: 'analyst', role: 'analyst', status: '' });
  const [about, setAbout] = useState<AboutInfo | null>(null);
  // Lazy initializer: read the persisted preference once on mount, same
  // "localStorage read once" idiom as ShellContext's navCollapsed (there it's
  // hydrated via an effect; here a lazy initializer avoids a post-mount flash
  // since there's no SSR concern for this value).
  const [operateStoredCollapsed, setOperateStoredCollapsed] = useState<boolean>(readStoredOperateCollapsed);

  useEffect(() => {
    getMe().then(setMe).catch(() => {/* keep placeholder */});
    getAbout().then(setAbout).catch(() => {/* version line just stays hidden */});
  }, []);

  // Force-expand: while the active route lives inside the Operate group, it
  // always renders expanded, regardless of the stored preference — the
  // user's current location must never be hidden. This OVERRIDES the stored
  // value for display only; it does not write through. A click on the
  // heading while force-expanded still flips + persists the stored flag (see
  // toggleOperateCollapsed) — it just has no visible effect until the route
  // moves elsewhere, at which point the stored preference resumes. Simplest
  // rule that satisfies "never hide the current location" without adding a
  // second persisted state.
  const operateGroup = NAV_GROUPS.find((g) => g.collapsible);
  const operateForceExpanded =
    !!operateGroup && operateGroup.items.some((item) => isItemActive(item, location.pathname));

  const toggleOperateCollapsed = () => {
    setOperateStoredCollapsed((c) => {
      const next = !c;
      try {
        localStorage.setItem(OPERATE_NAV_KEY, next ? '1' : '0');
      } catch {
        /* ignore */
      }
      return next;
    });
  };

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

      {/* Rail mode never shows headings (or hides items — see below), so this
          spacer just preserves the original vertical rhythm above the icons. */}
      {collapsed && <div className="h-3.5" />}

      <nav>
        {NAV_GROUPS.map((group) => {
          // Only a collapsible group (Operate) ever folds its items; a plain
          // group (Investigate) always shows everything, matching pre-groups
          // behavior exactly.
          const groupCollapsed = group.collapsible ? (operateForceExpanded ? false : operateStoredCollapsed) : false;
          return (
            <div key={group.label}>
              {!collapsed &&
                (group.collapsible ? (
                  <button
                    type="button"
                    onClick={toggleOperateCollapsed}
                    aria-expanded={!groupCollapsed}
                    className="mb-0.5 flex w-full items-center gap-1 rounded-control px-2 pb-1.5 pt-2 text-[10.5px] font-semibold uppercase tracking-[.07em] text-faint hover:text-text"
                  >
                    {groupCollapsed ? <ChevronRight size={12} /> : <ChevronDown size={12} />}
                    {group.label}
                  </button>
                ) : (
                  <div className="px-2 pb-1.5 pt-2 text-[10.5px] font-semibold uppercase tracking-[.07em] text-faint">
                    {group.label}
                  </div>
                ))}
              {(collapsed || !groupCollapsed) &&
                group.items.map((n) => {
                  const active = isItemActive(n, location.pathname);
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
            </div>
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
