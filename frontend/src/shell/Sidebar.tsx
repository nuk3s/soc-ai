import {
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
import { needsYouPart, useNeedsYouCount } from '../lib/needsYou';
import type { AboutInfo, Me } from '../lib/types';
import { ScopeMark, Wordmark } from '../components/Logo';
import { AccountMenu } from './AccountMenu';
import { entityNavSection } from './pages';
import { useSession } from './Session';
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
    // The analyst's loop. Always open.
    label: 'Analyst',
    items: [
      { to: '/dashboard', label: 'Dashboard', icon: <LayoutDashboard size={16} /> },
      { to: '/alerts', label: 'Alerts', icon: <Triangle size={16} /> },
      { to: '/investigations', label: 'Investigations', icon: <Search size={16} />, match: ['/investigations', '/investigation'] },
      // Sits beside Investigations rather than under Config: the dossier is a
      // network view an analyst pivots INTO from an alert, not a settings panel.
      { to: '/hosts', label: 'Hosts', icon: <Server size={16} />, match: ['/hosts'] },
      // A lead lives on the Hunts page, so a lead page keeps Hunts lit.
      // Notifications left the sidebar: the bell opens the same list, and
      // its "View all notifications" link opens the page.
      { to: '/hunts', label: 'Hunts', icon: <Crosshair size={16} />, match: ['/hunts', '/leads'] },
    ],
  },
  {
    // The operator's loop rather than the analyst's: prove the model/audit
    // chain are trustworthy, replay history, configure. Collapsed by default
    // (see OPERATE_NAV_KEY) so a first-run session reads as an analyst tool,
    // not a cockpit — Wave-2 progressive disclosure.
    label: 'Operator',
    collapsible: true,
    items: [
      // The hub entry leads the group (route lives in App.tsx). The group and
      // its first page both read "Operate", so the page is "Status" now.
      { to: '/operate', label: 'Status', icon: <Wrench size={16} /> },
      { to: '/runbooks', label: 'Runbooks', icon: <BookOpen size={16} /> },
      { to: '/backtest', label: 'Backtest', icon: <History size={16} /> },
      { to: '/config', label: 'Settings', icon: <Settings size={16} /> },
    ],
  },
];

/** Per-item active check, shared by row styling and the group-level
 * force-expand test below (same rule: exact path or a `match` prefix). */
function isItemActive(item: NavItem, pathname: string, search = ''): boolean {
  // An entity page lights Hosts for an address or a host name, and no entry
  // for a user or a domain (dogfood 2026-10-19, R4-D23).
  const entity = entityNavSection(pathname, search);
  if (entity !== undefined) return entity === item.to;
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

/** One badge on a nav entry: a part of the needs-you count. */
interface NavBadge {
  testId: string;
  /** The count, or null when the server could not read it. */
  value: number | null;
  title: string;
}

/** "7d" as "7 days", "24h" as "24 hours", for a badge tooltip. */
function windowWords(range: string): string {
  const m = range.match(/^(\d+)([mhd])$/);
  if (!m) return range;
  const n = Number(m[1]);
  const unit = m[2] === 'm' ? 'minute' : m[2] === 'h' ? 'hour' : 'day';
  return `${n} ${unit}${n === 1 ? '' : 's'}`;
}

/** What a badge shows: null for nothing, "?" for an unknown part, else the
 *  count. Unknown reads as "?", grey. Zero reads as nothing, because a
 *  standing "0" teaches the eye to skip the badge. Nothing shows before the
 *  first read. */
function badgeState(badge: NavBadge, failed: boolean, loaded: boolean): 'none' | 'unknown' | 'count' {
  if (!loaded && !failed) return 'none';
  if (failed || badge.value === null) return 'unknown';
  return badge.value ? 'count' : 'none';
}

/** The name of a nav link on the collapsed rail, where the label is not on
 *  screen. It carries the badge in words. */
function railLinkName(label: string, badge: NavBadge | undefined, failed: boolean, loaded: boolean): string {
  if (!badge) return label;
  const st = badgeState(badge, failed, loaded);
  if (st === 'unknown') return `${label}, could not count what needs you`;
  if (st === 'count') return `${label}, ${badge.value} need${badge.value === 1 ? 's' : ''} you`;
  return label;
}

function NeedsYouBadge({
  badge,
  failed,
  loaded,
  compact = false,
}: {
  badge: NavBadge;
  failed: boolean;
  loaded: boolean;
  /** The collapsed rail: a small count on the corner of the icon. The rail
   *  hid every badge (dogfood 2026-10-19, R1-D17). */
  compact?: boolean;
}) {
  const st = badgeState(badge, failed, loaded);
  if (st === 'none') return null;
  const unknown = st === 'unknown';
  const value = badge.value ?? 0;
  return (
    <span
      data-testid={badge.testId}
      className={
        compact
          ? 'absolute right-0.5 top-0 rounded-chip border px-1 text-[9px] font-semibold leading-[14px] tabular-nums'
          : 'rounded-chip border px-1.5 py-px text-[10px] font-semibold tabular-nums'
      }
      style={
        unknown
          ? { color: '#8b949e', borderColor: 'rgba(139,148,158,.45)', background: 'rgba(139,148,158,.1)' }
          : { color: '#d29922', borderColor: 'rgba(210,153,34,.45)', background: 'rgba(210,153,34,.1)' }
      }
      title={unknown ? 'Could not read what needs you. Open the page to try again.' : badge.title}
    >
      {unknown ? '?' : compact && value > 99 ? '99+' : badge.value}
    </span>
  );
}

export function Sidebar() {
  const { collapsed, toggleNav } = useShell();
  const location = useLocation();
  // Hold every read until /me answers (see Session.tsx, D14).
  const ready = useSession().status === 'ready';

  const [me, setMe] = useState<Me>({ username: 'analyst', role: 'analyst', status: '' });
  const [about, setAbout] = useState<AboutInfo | null>(null);
  // Lazy initializer: read the persisted preference once on mount, same
  // "localStorage read once" idiom as ShellContext's navCollapsed (there it's
  // hydrated via an effect; here a lazy initializer avoids a post-mount flash
  // since there's no SSR concern for this value).
  const [operateStoredCollapsed, setOperateStoredCollapsed] = useState<boolean>(readStoredOperateCollapsed);

  // What waits on the analyst, as badges on the three entries that hold it.
  // Every badge is a part of the one needs-you count, which the Dashboard tile
  // and the bell read from the same provider, so the badges add up to the
  // number those two surfaces state. A failed read is not a zero. The badge
  // went away on a 503, and the nav then read exactly like a quiet day.
  const needsYou = useNeedsYouCount();
  const badges: Record<string, NavBadge> = {
    '/alerts': {
      testId: 'sidebar-needs-you-alerts',
      value: needsYouPart(needsYou.data, 'untriaged_groups'),
      title: `Alert groups with no verdict in the last ${windowWords(needsYou.data?.alert_window ?? '7d')}. The count hides acknowledged groups.`,
    },
    '/investigations': {
      testId: 'sidebar-needs-you-investigations',
      value: needsYouPart(needsYou.data, 'needs_more_info', 'pending_actions'),
      title: `Verdicts that need more info, plus recommended actions that wait for you, in the last ${windowWords(needsYou.data?.verdict_window ?? '30d')}.`,
    },
    '/hunts': {
      testId: 'sidebar-needs-you',
      value: needsYouPart(needsYou.data, 'unread_shadow_hits', 'leads_needing_decision'),
      title: 'Unread shadow hits, plus leads that wait on a decision. Open Hunts to read them.',
    },
  };

  useEffect(() => {
    if (!ready) return;
    getMe().then(setMe).catch(() => {/* keep placeholder */});
    getAbout().then(setAbout).catch(() => {/* version line just stays hidden */});
  }, [ready]);

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
    !!operateGroup && operateGroup.items.some((item) => isItemActive(item, location.pathname, location.search));

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
                  const active = isItemActive(n, location.pathname, location.search);
                  const badgeFailed = needsYou.failed && !needsYou.data;
                  const badgeLoaded = needsYou.data !== null;
                  const railName = collapsed
                    ? railLinkName(n.label, badges[n.to], badgeFailed, badgeLoaded)
                    : undefined;
                  return (
                    <NavLink
                      key={n.to}
                      to={n.to}
                      title={railName ?? n.label}
                      aria-label={railName}
                      className="relative mb-0.5 flex items-center gap-2.5 rounded-control px-[9px] py-2 text-[13.5px] font-medium hover:bg-surface-3"
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
                      {badges[n.to] && (
                        <NeedsYouBadge
                          badge={badges[n.to]}
                          failed={badgeFailed}
                          loaded={badgeLoaded}
                          compact={collapsed}
                        />
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
          title={`About soc-ai v${about.version}`}
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
