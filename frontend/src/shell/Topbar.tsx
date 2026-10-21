import { Bell, Check, ChevronDown, HelpCircle, Network, Search, Settings, X } from 'lucide-react';
import { type RefObject, useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { AskSocAiButton } from '../components/AskPanel';
import { DevBadge, SyntheticEvalBadge } from '../components/Badges';
import { DismissAllControl } from '../components/DismissAllControl';
import { HuntOutcomeChip } from '../components/HuntOutcomeChip';
import { NeedsYouBlock } from '../components/NeedsYouBlock';
import { LoadingInline } from '../components/States';
import {
  type Health,
  getHealth,
  getNotifications,
  getWorkspaces,
  onNeedsYouChanged,
} from '../lib/api';
import {
  NOTIFICATIONS_CAP,
  NOTIFICATIONS_DISMISSED_EVENT,
  NO_NOTIFICATIONS,
  dismissNotification,
  formatNotificationTitle,
  formatNotificationWhen,
  getClearedAt,
  hasMoreNotifications,
  isNeedsYouRow,
  nextNotificationLimit,
  visibleNotifications,
} from '../lib/notifications';
import type { Notification, Workspace } from '../lib/types';
import { needsYouLines, useNeedsYouCount } from '../lib/needsYou';
import { type Crumb, GUIDE_URL, crumbFor } from './pages';
import { PALETTE_TRIGGER_ATTR, paletteKeyLabel } from './platform';
import { UPSTREAM_COLOR, type UpstreamState, upstreamState } from './upstream';
import { useSession } from './Session';
import { useShell } from './ShellContext';
import { isMachineKey } from '../lib/hostDossier';

const TONE: Record<Notification['tone'], string> = {
  danger: '#f04438',
  warn: '#f5a623',
  accent: '#4b8bf5',
};

// An IPv4 or IPv6 literal. A workspace named for its grid address used to show
// the first digit as its avatar ("1"), which reads as a count (RD15).
const IP_NAME = /^(\d{1,3}(\.\d{1,3}){3}(:\d+)?|\[?[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,7}\]?(:\d+)?)$/i;

/** The avatar glyph for a workspace: its first letter, or a network glyph when
 *  the name is an address. */
export function WorkspaceGlyph({ name, size = 11 }: { name: string; size?: number }) {
  if (!name) return <>?</>;
  if (IP_NAME.test(name.trim())) {
    return (
      <span aria-hidden="true" data-testid="ws-glyph-ip" className="flex">
        <Network size={size} />
      </span>
    );
  }
  return <>{name[0].toUpperCase()}</>;
}

/** The panel header line for the bell: "11 need you · 8 notifications".
 *
 *  The first number is the needs-you count, the one the Dashboard tile and the
 *  sidebar badges state. The bell counted its own rows and said "None need
 *  attention" while 10 leads waited. `need` is null when the count could not
 *  be read, and `floor` marks a count that misses a part the server could not
 *  read. `undefined` is a count still being read. The second number counts
 *  the other rows on the list. One row has one name: a notification. The
 *  bell said "events", the screen said "items" (dogfood 2026-10-19, V1-S7). */
export function notificationSummary(need: number | null | undefined, events: number, floor = false): string {
  const head =
    need === undefined
      ? 'Reading what needs you'
      : need === null
        ? 'Could not read what needs you'
        : need === 0
          ? // A zero over a part the server could not read is no answer. The
            // header said "Nothing needs you" beside a Dashboard tile reading
            // "0+" (dogfood 2026-10-19, H1-D10).
            floor
            ? 'Could not count what needs you'
            : 'Nothing needs you'
          : `${need}${floor ? '+' : ''} need${need === 1 && !floor ? 's' : ''} you`;
  return events > 0 ? `${head} · ${events} notification${events === 1 ? '' : 's'}` : head;
}

function isInside(target: EventTarget | null, refs: RefObject<HTMLElement | null>[]): boolean {
  if (!(target instanceof Node)) return false;
  return refs.some((r) => r.current?.contains(target));
}

function useBreadcrumb(): Crumb {
  const { pathname, search } = useLocation();
  return crumbFor(pathname, search);
}

export function Topbar() {
  const { openPalette, ws, setWs, crumbName } = useShell();
  // Every read below is a protected endpoint. Hold them until /me answers, so
  // a signed-out visit does not fire a burst of 401s before the redirect (D14).
  const ready = useSession().status === 'ready';
  const { crumb, crumb2 } = useBreadcrumb();
  // A machine page names its machine. The raw key "agent:<uuid>" rides in the
  // tooltip only.
  const crumb2Name = crumb2 && crumbName?.key === crumb2 ? crumbName.name : null;
  const crumb2Key = !!crumb2 && crumb.startsWith('Hosts') && isMachineKey(crumb2);
  const navigate = useNavigate();
  const [wsOpen, setWsOpen] = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);
  const [healthOpen, setHealthOpen] = useState(false);
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [notifs, setNotifs] = useState<Notification[]>([]);
  // The rows the panel asks for. "Show more" adds 20. The poll keeps the
  // limit while the panel is open, and a closed panel goes back to 12.
  const [limit, setLimit] = useState(NOTIFICATIONS_CAP);
  const limitRef = useRef(NOTIFICATIONS_CAP);
  // How many rows the last answer held, before the hidden ones left, and when
  // it landed. A full answer can have more behind it. Dismiss all hides up to
  // the moment of the answer the analyst read.
  const [received, setReceived] = useState(0);
  const [loadedAt, setLoadedAt] = useState<number | null>(null);
  const loadRef = useRef<() => void>(() => {});
  const [health, setHealth] = useState<Health | null>(null);
  const [healthFailed, setHealthFailed] = useState(false);

  useEffect(() => {
    if (!ready) return;
    let alive = true;
    getWorkspaces()
      .then((list) => {
        if (!alive) return;
        setWorkspaces(list);
        if (list.length > 0) setWs(list[0].name);
      })
      .catch(() => {});
    // The events only: the Needs-you block states the leads and the shadow
    // hits as counts. With 300 unread hits the first 12 rows were all hits,
    // and every event behind them was off the panel (production 2026-10-14).
    // `after` is the last Dismiss all, so hidden rows take no place in the
    // limit.
    const load = () =>
      getNotifications({ limit: limitRef.current, eventsOnly: true, after: getClearedAt() })
        .then((list) => {
          if (!alive) return;
          setReceived(list.length);
          setLoadedAt(Date.now());
          setNotifs(visibleNotifications(list));
        })
        .catch(() => {});
    loadRef.current = load;
    load();
    // Topbar mounts on every in-shell route, so this poll runs for the whole
    // session. Skip a backgrounded tab (the house guard, lib/useAsync.ts:118) —
    // /notifications is the app's hottest endpoint and nobody is watching the
    // bell in a parked tab — and re-read once on return to visible so the badge
    // is current the moment the analyst looks again.
    const t = setInterval(() => {
      if (document.hidden) return;
      load();
    }, 15000); // keep the bell live without a reload
    const onVisible = () => {
      if (!document.hidden) load();
    };
    document.addEventListener('visibilitychange', onVisible);
    // A dismiss from anywhere (this bell, the Notifications pane, "Clear all")
    // re-reads immediately so the badge count can't lag its 15s poll.
    window.addEventListener(NOTIFICATIONS_DISMISSED_EVENT, load);
    // The bell holds a notice per unread shadow hit. An analyst who reads a hit
    // on the Hunts page watched the strip and the sidebar move while the bell
    // stood still for up to 15 s, so one number read two ways on one screen.
    const stopNeedsYou = onNeedsYouChanged(load);
    return () => {
      alive = false;
      clearInterval(t);
      document.removeEventListener('visibilitychange', onVisible);
      window.removeEventListener(NOTIFICATIONS_DISMISSED_EVENT, load);
      stopNeedsYou();
    };
  }, [ready]);

  const handleDismiss = (id: string) => {
    dismissNotification(id);
    setNotifs((ns) => ns.filter((n) => n.id !== id));
  };
  const showMore = () => {
    const next = nextNotificationLimit(limitRef.current);
    limitRef.current = next;
    setLimit(next);
    loadRef.current();
  };
  // A closed panel polls the default list again. The longer list is for the
  // analyst who asked for it, while the panel is open.
  useEffect(() => {
    if (notifOpen || limitRef.current === NOTIFICATIONS_CAP) return;
    limitRef.current = NOTIFICATIONS_CAP;
    setLimit(NOTIFICATIONS_CAP);
  }, [notifOpen]);
  const openNotif = (n: Notification) => {
    if (n.href) {
      navigate(n.href);
      setNotifOpen(false);
    }
  };

  // Poll upstream health (ES / model gateway / Security Onion API / PCAP) for
  // the status indicator.
  useEffect(() => {
    if (!ready) return;
    let alive = true;
    const tick = () =>
      getHealth()
        .then((h) => {
          if (!alive) return;
          setHealth(h);
          setHealthFailed(false);
        })
        .catch(() => {
          if (!alive) return;
          setHealth(null);
          setHealthFailed(true);
        });
    tick();
    // Same hidden-tab guard as the notifications poll above: don't probe
    // upstream health for a parked tab, and refresh once on return to visible.
    const t = setInterval(() => {
      if (document.hidden) return;
      tick();
    }, 60_000);
    const onVisible = () => {
      if (!document.hidden) tick();
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      alive = false;
      clearInterval(t);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [ready]);

  // Every component the pill's one word speaks for. `so` covers the Security
  // Onion web API, the path every acknowledge, escalate and case write takes.
  // Leaving it out is what let the pill read "connected" beside a setup-health
  // card reporting a Security Onion timeout (dogfood 2026-09-07, D1). It is
  // read defensively so a page served by an older build shows "connected" for
  // what it CAN see rather than crashing on an absent field.
  const healthList = health
    ? [health.es, health.llm, ...(health.so ? [health.so] : []), ...(health.pcap ? [health.pcap] : [])]
    : [];
  const healthDown = healthList.filter((c) => upstreamState(c) === 'down').length;
  const healthDegraded = healthList.filter((c) => upstreamState(c) === 'degraded').length;
  const healthOk = health !== null && !healthFailed && healthDown === 0 && healthDegraded === 0;
  const healthState: UpstreamState | null = healthOk
    ? 'ok'
    : health === null || healthFailed
      ? null
      : healthDown > 0
        ? 'down'
        : 'degraded';
  const healthLabel = healthFailed
    ? 'unreachable'
    : health === null
      ? 'checking'
      : healthOk
        ? 'connected'
        : [healthDown > 0 ? `${healthDown} down` : '', healthDegraded > 0 ? `${healthDegraded} degraded` : '']
            .filter(Boolean)
            .join(', ');
  // grey = initial load; amber = fetch failed or a dependency degraded;
  // red = a dependency down; green = all ok
  const healthColor = healthFailed ? '#f5a623' : healthState === null ? '#6b7484' : UPSTREAM_COLOR[healthState];

  const menusOpen = wsOpen || notifOpen || healthOpen;

  const wsBtnRef = useRef<HTMLButtonElement>(null);
  const wsPanelRef = useRef<HTMLDivElement>(null);
  const notifBtnRef = useRef<HTMLButtonElement>(null);
  const notifPanelRef = useRef<HTMLDivElement>(null);
  const healthBtnRef = useRef<HTMLButtonElement>(null);
  const healthPanelRef = useRef<HTMLDivElement>(null);

  // Outside click and Escape close the open dropdown. This used to be a
  // `fixed inset-0` click-catcher inside this bar, and the bar's backdrop blur
  // makes it the containing block for fixed children, so the catcher covered
  // the 52 px strip only. A click on the page did nothing, and the open panel
  // sat over "Clear all" and "Test LLM" (D5, RC9, RD6). A document listener
  // has no layer to clip and covers nothing.
  useEffect(() => {
    if (!menusOpen) return;
    const keep = [wsBtnRef, wsPanelRef, notifBtnRef, notifPanelRef, healthBtnRef, healthPanelRef];
    const close = () => {
      setWsOpen(false);
      setNotifOpen(false);
      setHealthOpen(false);
    };
    const onDown = (e: MouseEvent) => {
      if (!isInside(e.target, keep)) close();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      const opener = notifOpen ? notifBtnRef : healthOpen ? healthBtnRef : wsBtnRef;
      close();
      opener.current?.focus();
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [menusOpen, notifOpen, healthOpen]);

  // The badge states the needs-you count, the number the Dashboard tile and
  // the sidebar badges state. The bell used to count its own danger and warn
  // rows, with a 24 h window on leads and only shadow leads in warn, so it said
  // "None need attention" while 10 leads waited (dogfood 2026-10-06).
  // Two fallbacks keep the bell honest. With no count to read, the badge counts
  // the danger and warn rows, the old rule. With nothing needing the analyst
  // and a danger row on the list, such as a dependency down or a failed
  // triage, the badge shows "!" so a fault still lights the bell.
  const needsYou = useNeedsYouCount();
  const events = notifs.filter((n) => !isNeedsYouRow(n));
  const faults = events.filter((n) => n.tone === 'danger').length;
  const need = needsYou.data ? needsYou.data.total : null;
  const floor = (needsYou.data?.unknown.length ?? 0) > 0;
  const fallback = notifs.filter((n) => n.tone !== 'accent').length;
  const badge: string | null =
    need === null
      ? fallback > 0
        ? String(fallback)
        : null
      : need > 0
        ? `${need}${floor ? '+' : ''}`
        : faults > 0
          ? '!'
          : null;
  // The name states the floor the badge marks with "+". It read "34 need you"
  // under a badge of "34+" (dogfood 2026-10-19, R1-D18).
  const bellName =
    need !== null && need > 0
      ? floor
        ? `Notifications, ${need} or more need you`
        : `Notifications, ${need} need${need === 1 ? 's' : ''} you`
      : need === 0 && floor
        ? 'Notifications, could not count what needs you'
        : badge === '!'
        ? `Notifications, ${faults} urgent`
        : need === null && fallback > 0
          ? `Notifications, ${fallback} need${fallback === 1 ? 's' : ''} attention`
          : 'Notifications';
  const showSummary = notifs.length > 0 || (need ?? 0) > 0 || needsYou.failed;
  // The parts of the badge, shown above the events. They add up to the badge.
  const needsYouParts = needsYouLines(needsYou.data);
  const more = hasMoreNotifications(received, limit);

  return (
    <div className="relative z-30 flex h-[52px] flex-none items-center gap-[11px] border-b border-border bg-[rgba(11,14,19,.7)] py-0 pl-4 pr-3.5 backdrop-blur-[8px]">
      {/* Workspace switcher, only when more than one workspace exists. One
          workspace has nothing to switch to, and the chip showed a bare grid
          address that read as a page name (dogfood 2026-10-06). */}
      {workspaces.length > 1 && (
        <button
          ref={wsBtnRef}
          aria-haspopup="dialog"
          aria-expanded={wsOpen}
          onClick={() => {
            setWsOpen((o) => !o);
            setNotifOpen(false);
            setHealthOpen(false);
          }}
          title="Switch workspace"
          className="flex flex-none items-center gap-2 rounded-control border border-border-2 bg-surface-1 px-[9px] py-[5px] hover:border-border-strong"
        >
          <div
            className="flex h-5 w-5 items-center justify-center rounded-[5px] text-[10px] font-bold text-white"
            style={{ background: 'linear-gradient(135deg,#4b8bf5,#2c5fd0)' }}
          >
            <WorkspaceGlyph name={ws} />
          </div>
          <span className="whitespace-nowrap text-[12.5px] font-semibold">{ws || 'Workspace'}</span>
          <span className="flex text-faint">
            <ChevronDown size={12} />
          </span>
        </button>
      )}

      {/* workspace dropdown — only shown when multiple workspaces exist */}
      {wsOpen && workspaces.length > 1 && (
        <div ref={wsPanelRef} role="dialog" aria-label="Workspaces" className="absolute left-3.5 top-12 z-[33] w-64 animate-fadeUp rounded-panel border border-border-input bg-surface-card p-1.5 shadow-dropdown">
          <div className="px-[9px] pb-1.5 pt-[7px] text-[10px] font-semibold uppercase tracking-[.06em] text-faint">
            Workspaces
          </div>
          {workspaces.map((w) => (
            <button
              key={w.name}
              onClick={() => {
                setWs(w.name);
                setWsOpen(false);
              }}
              className="flex w-full items-center gap-[9px] rounded-control px-[9px] py-2 hover:bg-[#141b25]"
            >
              <div
                className="flex h-[23px] w-[23px] items-center justify-center rounded-badge border border-border-strong text-[10.5px] font-bold text-text-2"
                style={{ background: 'linear-gradient(135deg,#3a4250,#22272f)' }}
              >
                <WorkspaceGlyph name={w.name} size={12} />
              </div>
              <div className="min-w-0 flex-1 break-words text-left text-[12.5px] font-semibold">{w.name}</div>
              <span
                className="h-[7px] w-[7px] rounded-full"
                title={w.env}
                style={{ background: w.env === 'prod' ? '#3fb950' : '#f5a623' }}
              />
              {w.name === ws && (
                <span className="flex text-accent">
                  <Check size={14} />
                </span>
              )}
            </button>
          ))}
          <div className="mt-[5px] border-t border-border-2 pt-[5px]">
            <div className="flex w-full cursor-default items-center gap-[9px] rounded-control px-[9px] py-2 text-[12.5px] text-faint">
              <span className="flex w-[23px] justify-center">
                <Settings size={14} />
              </span>
              <span className="flex-1 text-left">Manage workspaces</span>
              <DevBadge />
            </div>
          </div>
        </div>
      )}

      {workspaces.length > 1 && <div className="h-[18px] w-px flex-none bg-border-2" />}

      {/* breadcrumb */}
      <div className="flex min-w-0 items-center gap-[7px] text-[13px] text-dim">
        <span data-testid="topbar-crumb" className="whitespace-nowrap font-semibold text-text">
          {crumb}
        </span>
        {crumb2 && (
          <>
            <span className="text-ghost">/</span>
            <span
              data-testid="topbar-crumb2"
              className={`min-w-0 break-words text-dim ${crumb2Name ? 'text-[12.5px]' : 'font-mono text-[12px]'}`}
              title={crumb2Name || crumb2Key ? crumb2 : undefined}
            >
              {crumb2Name ?? (crumb2Key ? 'machine' : crumb2)}
            </span>
          </>
        )}
      </div>

      <div className="flex-1" />

      {/* command palette trigger */}
      <button
        onClick={openPalette}
        {...{ [PALETTE_TRIGGER_ATTR]: '' }}
        title={`Search or jump to. The shortcut is ${paletteKeyLabel()}.`}
        className="flex flex-none cursor-text items-center gap-2 rounded-control border border-border-2 bg-surface-1 px-2.5 py-1.5 text-faint hover:border-border-strong"
        style={{ width: 'clamp(170px,22vw,300px)' }}
      >
        <span className="flex">
          <Search size={14} />
        </span>
        <span className="flex-1 break-words text-left text-[12.5px]">Search or jump to</span>
        <kbd className="rounded-[4px] border border-border-input px-[5px] py-px font-mono text-[10px] text-dim">{paletteKeyLabel()}</kbd>
      </button>

      {/* upstream health (ES / LLM / PCAP) */}
      <button
        ref={healthBtnRef}
        aria-haspopup="dialog"
        aria-expanded={healthOpen}
        onClick={() => {
          setHealthOpen((o) => !o);
          setWsOpen(false);
          setNotifOpen(false);
        }}
        title="Upstream health"
        data-state={healthState ?? undefined}
        className="flex flex-none items-center gap-1.5 rounded-control border border-border-2 px-[9px] py-1.5 font-mono text-[11.5px] text-dim hover:border-border-strong hover:text-text"
      >
        <span
          className="h-1.5 w-1.5 rounded-full"
          style={{ background: healthColor, boxShadow: `0 0 8px ${healthColor}` }}
        />
        {healthLabel}
      </button>
      {/* health dropdown: ES / LLM / Security Onion / PCAP, with the PCAP hint */}
      {healthOpen && (
        <div
          ref={healthPanelRef}
          role="dialog"
          aria-label="Upstream health"
          className="absolute right-[150px] top-12 z-[33] w-[360px] animate-fadeUp overflow-hidden rounded-panel border border-border-input bg-surface-card shadow-dropdown">
          <div className="border-b border-border-2 px-3.5 py-3 text-[13px] font-semibold">
            Upstream health
          </div>
          {healthFailed && (
            <div className="px-3.5 py-6 text-center text-[12px] text-warn">The API is unreachable. The console tries again.</div>
          )}
          {!healthFailed && health === null && (
            <div className="px-3.5 py-6 text-center text-[12px] text-faint"><LoadingInline>Checking</LoadingInline></div>
          )}
          {/* One term per thing: "the grid" is Security Onion and its
              Elasticsearch, and "the model gateway" serves the model. */}
          {([
            ['Grid: Elasticsearch', health?.es],
            ['Model gateway', health?.llm],
            ['Grid: Security Onion API', health?.so],
            ['Sensor PCAP', health?.pcap],
          ] as const).map(([label, c]) => {
            if (c == null) return null;
            const st = upstreamState(c);
            const color = UPSTREAM_COLOR[st];
            return (
              <div key={label} className="flex gap-2.5 border-b border-border-faint px-3.5 py-[11px] last:border-0">
                <span
                  className="mt-[5px] h-[7px] w-[7px] flex-none rounded-full"
                  style={{ background: color, boxShadow: `0 0 7px ${color}` }}
                />
                <div className="min-w-0 flex-1">
                  <div className="text-[12.5px] font-semibold">
                    {label} <span style={{ color }}>{st}</span>
                  </div>
                  <div className="mt-0.5 break-words font-mono text-[10.5px] leading-[1.5] text-faint">
                    {c.detail}
                  </div>
                </div>
              </div>
            );
          })}
          {health?.pcap == null && health !== null && (
            <div className="px-3.5 py-2.5 font-mono text-[10.5px] text-faint">
              PCAP fetch is off. The setting pcap_enabled is false.
            </div>
          )}
        </div>
      )}

      {/* notifications */}
      <button
        ref={notifBtnRef}
        aria-haspopup="dialog"
        aria-expanded={notifOpen}
        onClick={() => {
          setNotifOpen((o) => !o);
          setWsOpen(false);
          setHealthOpen(false);
        }}
        title={bellName}
        aria-label={bellName}
        className="relative flex h-[34px] w-[34px] flex-none items-center justify-center rounded-control border border-border-2 text-dim hover:border-border-strong hover:text-text"
      >
        <Bell size={16} />
        {badge !== null && (
          <span
            data-testid="notif-badge"
            className="absolute -right-[5px] -top-[5px] flex h-4 min-w-[16px] items-center justify-center rounded-lg border-2 border-surface-1 bg-danger px-[3px] font-mono text-[9px] font-bold text-white"
          >
            {badge}
          </span>
        )}
      </button>

      {/* The panel follows the bell in the DOM so Tab reaches its rows before
          the Help button (D6, RD8). It is absolute, so the order does not move
          it on screen. */}
      {/* notifications dropdown */}
      {notifOpen && (
        <div
          ref={notifPanelRef}
          role="dialog"
          aria-label="Notifications"
          className="absolute right-[46px] top-12 z-[33] w-[332px] animate-fadeUp overflow-hidden rounded-panel border border-border-input bg-surface-card shadow-dropdown">
          <div className="flex flex-wrap items-baseline gap-2 border-b border-border-2 px-3.5 py-3">
            <span className="text-[13px] font-semibold">Notifications</span>
            {showSummary && (
              <span data-testid="notif-summary" className="ml-auto text-[11.5px] text-faint">
                {notificationSummary(needsYou.data ? need : needsYou.failed ? null : undefined, events.length, floor)}
              </span>
            )}
            <DismissAllControl
              compact
              rows={events}
              more={more}
              needsYou={needsYou}
              loadedAt={loadedAt}
            />
          </div>
          {/* Every unit of the badge, part by part, with its scope. The panel
              listed 12 shadow hits under a badge of 309 (production
              2026-10-14). */}
          {needsYouParts.length > 0 && (
            <NeedsYouBlock
              state={needsYou}
              onFollow={() => setNotifOpen(false)}
              className="border-b border-border-2 px-3.5 py-2.5"
            />
          )}
          {/* The events scroll inside the panel, so "Show more" cannot push the
              panel past the bottom of the window. */}
          <div className="max-h-[min(60vh,560px)] overflow-y-auto">
          {events.length === 0 && (
            <div className="px-3.5 py-6 text-center text-[12px] text-faint">
              {needsYouParts.length > 0 ? 'No other notifications.' : NO_NOTIFICATIONS}
            </div>
          )}
          {events.map((nt) => {
            const body = (
              <>
                <div className="text-[12.5px] leading-[1.45]">
                  {/* The notice names a hunt by its whole head line. The
                      dropdown is narrow, so the browser clamps the title to
                      three lines and the hover holds the whole text. The
                      server cut the objective at 80 characters, mid-word. */}
                  <span
                    data-testid="bell-title"
                    className="break-words"
                    title={formatNotificationTitle(nt.title)}
                  >
                    {formatNotificationTitle(nt.title)}
                  </span>
                  {/* How a hunt ended, from its outcome field. */}
                  {nt.outcome && (
                    <>
                      {' '}
                      <HuntOutcomeChip outcome={nt.outcome} />
                    </>
                  )}
                  {/* A run against planted synthetic scenarios must never read
                      as a real one — badge it wherever the row appears. */}
                  {nt.isSynthEval && (
                    <>
                      {' '}
                      <SyntheticEvalBadge />
                    </>
                  )}
                </div>
                {formatNotificationWhen(nt.when) && (
                  <div className="mt-[3px] font-mono text-[10.5px] text-faint">
                    {formatNotificationWhen(nt.when)}
                  </div>
                )}
              </>
            );
            return (
              <div
                key={nt.id}
                className={`flex gap-2.5 border-b border-border-faint px-3.5 py-[11px] hover:bg-[#141b25]${nt.href ? ' cursor-pointer' : ''}`}
                /* A click anywhere on the row opens it, the way the old block
                   did; the body button below carries the keyboard path and
                   its click bubbles here. Dismiss stops the bubble. */
                onClick={nt.href ? () => openNotif(nt) : undefined}
              >
                <span
                  className="mt-[5px] h-[7px] w-[7px] flex-none rounded-full"
                  style={{ background: TONE[nt.tone], boxShadow: `0 0 7px ${TONE[nt.tone]}` }}
                />
                {/* The body is a real button when the row leads somewhere, so it
                    sits in the Tab order beside Dismiss. As a div with an
                    onClick, Tab skipped it, and the only thing the keyboard
                    could do to a notification was make it disappear. */}
                {nt.href ? (
                  <button type="button" className="min-w-0 flex-1 text-left">
                    {body}
                  </button>
                ) : (
                  <div className="min-w-0 flex-1">{body}</div>
                )}
                {/* No dismiss control on a finding the server says must not be
                    silenceable from local storage: an audit record whose content no
                    longer matches its own hash. */}
                {nt.dismissible !== false && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleDismiss(nt.id);
                    }}
                    aria-label="Dismiss"
                    className="flex flex-none self-start p-0.5 text-faint hover:text-text"
                  >
                    <X size={13} />
                  </button>
                )}
              </div>
            );
          })}
          {/* The API cut the list at the limit. A full answer can have more
              behind it, so the control loads 20 more rows. */}
          {more && (
            <button
              onClick={showMore}
              className="w-full px-3.5 py-2 text-left text-[12px] font-semibold text-dim hover:bg-[#141b25] hover:text-text"
            >
              Show more
            </button>
          )}
          </div>
          <button
            onClick={() => {
              navigate('/notifications');
              setNotifOpen(false);
            }}
            className="w-full border-t border-border-2 px-3.5 py-2.5 text-left text-[12px] font-semibold text-accent hover:bg-[#141b25]"
          >
            View all notifications
          </button>
        </div>
      )}

      {/* The guide. The button opened the command palette, and the guide had
          no link in the console (dogfood 2026-10-06). The palette holds the
          keyboard shortcuts. */}
      <a
        href={GUIDE_URL}
        target="_blank"
        rel="noopener noreferrer"
        title="Open the guide in a new tab"
        aria-label="Open the guide"
        className="flex h-[34px] w-[34px] flex-none items-center justify-center rounded-control border border-border-2 text-dim hover:border-border-strong hover:text-text"
      >
        <HelpCircle size={16} />
      </a>

      {/* The one chat, at the right end on every page. The label names the
          object the page shows. */}
      <AskSocAiButton />
    </div>
  );
}
