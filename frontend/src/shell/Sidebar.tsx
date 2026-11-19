import {
  BookOpen,
  ChevronDown,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Crosshair,
  History,
  Inbox,
  Info,
  LayoutDashboard,
  Network,
  Search,
  Server,
  Settings,
  Triangle,
  Wrench,
} from 'lucide-react';
import { Link, NavLink, useLocation } from 'react-router-dom';
import { type ReactNode, useEffect, useState } from 'react';
import { getAbout, getMe } from '../lib/api';
import {
  NEEDS_YOU_PAGE,
  campaignsWaiting,
  decisionCount,
  decisionFloor,
  investigationsWaiting,
  needsYouLinks,
  needsYouPart,
  reviewCount,
  scopeOfWindow,
  ANY_AGE,
  useNeedsYouCount,
} from '../lib/needsYou';
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
      // The one list of every decision that waits, with the count of the top
      // bar and the Dashboard tile. The analyst found the page through the
      // tile and the bell only (dogfood 2026-11-17).
      { to: NEEDS_YOU_PAGE, label: 'Needs you', icon: <Inbox size={16} /> },
      { to: '/dashboard', label: 'Dashboard', icon: <LayoutDashboard size={16} /> },
      // The campaign is the unit of work of the analyst (owner, 2026-11-14),
      // so Campaigns sits directly after Dashboard. Its item lights on the
      // list and on each campaign page.
      { to: '/campaigns', label: 'Campaigns', icon: <Network size={16} />, match: ['/campaigns'] },
      { to: '/alerts', label: 'Alerts', icon: <Triangle size={16} /> },
      { to: '/investigations', label: 'Investigations', icon: <Search size={16} />, match: ['/investigations', '/investigation'] },
      // Sits beside Investigations rather than under Config: the dossier is a
      // network view an analyst pivots INTO from an alert, not a settings panel.
      { to: '/hosts', label: 'Hosts', icon: <Server size={16} />, match: ['/hosts'] },
      // A lead lives on the Hunts page, so a lead page keeps Hunts lit. The
      // campaign pages light their own item above.
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
  /** The list the badge counts. The badge is a link to it, so the number on
   *  the badge is the list it opens. */
  to: string;
  /** A decision badge is amber. A review badge is grey: the unread shadow
   *  hits are review work, and only a decision takes the color. */
  tone: 'decision' | 'review';
  /** The words after the count in the accessible name: "need you". */
  noun: (n: number) => string;
  /** True when a part of the count could not be read: the count is a floor
   *  and shows "+", as the bell badge does. */
  floor?: boolean;
}

const needYou = (n: number) => `need${n === 1 ? 's' : ''} you`;

/** The scope of a badge tooltip in words: "in the last 7 days", or "at any
 *  age" for the window "all". The Investigations badge read "in the last
 *  all" (round 3 part 2, P3). */
function scopeWords(range: string): string {
  return range === 'all' ? ANY_AGE : `in the ${scopeOfWindow(range)}`;
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

/** One badge in words: "2 need you", "236 shadow hits to review". */
function badgeWords(badge: NavBadge, failed: boolean, loaded: boolean): string | null {
  const st = badgeState(badge, failed, loaded);
  if (st === 'unknown') return badge.tone === 'review' ? null : 'could not count what needs you';
  if (st === 'count') return `${badge.value} ${badge.noun(badge.value ?? 0)}`;
  return null;
}

/** The name of a nav link on the collapsed rail, where the label is not on
 *  screen. It carries the badges in words. */
function railLinkName(label: string, badges: NavBadge[] | undefined, failed: boolean, loaded: boolean): string {
  const words = (badges ?? []).map((b) => badgeWords(b, failed, loaded)).filter((w): w is string => !!w);
  return [label, ...words].join(', ');
}

const BADGE_STYLE = {
  decision: { color: '#d29922', borderColor: 'rgba(210,153,34,.45)', background: 'rgba(210,153,34,.1)' },
  neutral: { color: '#8b949e', borderColor: 'rgba(139,148,158,.45)', background: 'rgba(139,148,158,.1)' },
};

function NeedsYouBadge({
  badge,
  label,
  failed,
  loaded,
  compact = false,
}: {
  badge: NavBadge;
  /** The label of the nav entry, for the accessible name of the badge. */
  label: string;
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
  // The badge is a link of its own, beside the nav link. The badge on
  // Investigations said 39 and the entry opened 64 other rows (production
  // review 2026-11-12, ui-core 7). Each badge opens the list it counts.
  return (
    <Link
      to={badge.to}
      data-testid={badge.testId}
      aria-label={`${badgeWords(badge, failed, loaded) ?? 'could not count what needs you'} in ${label}`}
      className={
        compact
          ? 'rounded-chip border px-1 text-[9px] font-semibold leading-[14px] tabular-nums hover:brightness-125'
          : 'rounded-chip border px-1.5 py-px text-[10px] font-semibold tabular-nums hover:brightness-125'
      }
      style={unknown || badge.tone === 'review' ? BADGE_STYLE.neutral : BADGE_STYLE.decision}
      title={unknown ? 'Could not read what needs you. Open the page to try again.' : badge.title}
    >
      {unknown ? '?' : compact && value > 99 ? '99+' : `${value}${badge.floor ? '+' : ''}`}
    </Link>
  );
}

/** The badges of one nav entry, beside its link. The rail shows the first
 *  badge that has something to say. */
function NavBadges({
  badges,
  label,
  failed,
  loaded,
  compact,
}: {
  badges: NavBadge[];
  label: string;
  failed: boolean;
  loaded: boolean;
  compact: boolean;
}) {
  const shown = badges.filter((b) => badgeState(b, failed, loaded) !== 'none');
  if (shown.length === 0) return null;
  const list = compact ? shown.slice(0, 1) : shown;
  return (
    <span
      className={
        compact
          ? 'absolute right-0.5 top-0 flex'
          : 'absolute right-[9px] top-1/2 flex -translate-y-1/2 items-center gap-1'
      }
    >
      {list.map((b) => (
        <NeedsYouBadge key={b.testId} badge={b} label={label} failed={failed} loaded={loaded} compact={compact} />
      ))}
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

  // What waits on the analyst, as badges on the four entries that hold it.
  // Every badge is a part of the one needs-you count, which the Dashboard tile
  // and the bell read from the same provider. A failed read is not a zero. The
  // badge went away on a 503, and the nav then read exactly like a quiet day.
  //
  // The amber badges count decisions. The unread shadow hits are review work,
  // and their badge on Hunts is grey (production review 2026-11-12, ui-core
  // 4). The Investigations badge counts the runs of the list's Needs you view,
  // with the same query, so the badge and the view state one number (ui-core 7).
  const needsYou = useNeedsYouCount();
  const links = needsYouLinks(needsYou.data);
  const verdictScope = scopeWords(needsYou.data?.verdict_window ?? '30d');
  const badges: Record<string, NavBadge[]> = {
    [NEEDS_YOU_PAGE]: [
      {
        testId: 'sidebar-needs-you-total',
        value: needsYou.data ? decisionCount(needsYou.data) : null,
        floor: needsYou.data ? decisionFloor(needsYou.data) : false,
        title:
          'Decisions that wait on you: the number of the top bar and the Dashboard. Select the badge to open the list.',
        to: NEEDS_YOU_PAGE,
        tone: 'decision',
        noun: (n) => `${n === 1 ? 'decision waits' : 'decisions wait'} on you`,
      },
    ],
    '/campaigns': [
      {
        testId: 'sidebar-needs-you-campaigns',
        value: campaignsWaiting(needsYou.data),
        title: 'Campaigns that wait on your decision, at any age. Select the badge to open them.',
        to: links.campaigns,
        tone: 'decision',
        noun: needYou,
      },
    ],
    '/alerts': [
      {
        testId: 'sidebar-needs-you-alerts',
        value: needsYouPart(needsYou.data, 'untriaged_groups'),
        title: `Alert groups with no verdict ${scopeWords(needsYou.data?.alert_window ?? '7d')}. The count hides acknowledged groups.`,
        to: links.untriaged,
        tone: 'decision',
        noun: needYou,
      },
    ],
    '/investigations': [
      {
        testId: 'sidebar-needs-you-investigations',
        value: investigationsWaiting(needsYou.data),
        title: `Investigations that need more info or have a recommended action that waits for you, ${verdictScope}. An investigation of a campaign waits on the campaign. Select the badge to open the Needs you view.`,
        to: links.investigations,
        tone: 'decision',
        noun: needYou,
      },
    ],
    '/hunts': [
      {
        testId: 'sidebar-needs-you',
        value: needsYouPart(needsYou.data, 'leads_needing_decision'),
        title: 'Leads that wait on a decision. Select the badge to open them.',
        to: links.leads,
        tone: 'decision',
        noun: needYou,
      },
      {
        testId: 'sidebar-review-hits',
        value: needsYou.data ? reviewCount(needsYou.data) : null,
        title: 'Unread shadow hits to review. A shadow hit is not a decision. Select the badge to open the hits.',
        to: links.shadowHits,
        tone: 'review',
        noun: (n) => `shadow ${n === 1 ? 'hit' : 'hits'} to review`,
      },
    ],
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

      <nav data-tour="nav">
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
                    <div key={n.to} className="relative">
                      <NavLink
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
                        {!collapsed && n.dev && (
                          <span
                            className="rounded-chip border px-1.5 py-px text-[9.5px] font-semibold uppercase tracking-[.04em]"
                            style={{ color: '#f5a623', borderColor: 'rgba(245,166,35,.35)', background: 'rgba(245,166,35,.08)' }}
                          >
                            dev
                          </span>
                        )}
                      </NavLink>
                      {badges[n.to] && (
                        <NavBadges
                          badges={badges[n.to]}
                          label={n.label}
                          failed={badgeFailed}
                          loaded={badgeLoaded}
                          compact={collapsed}
                        />
                      )}
                    </div>
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
