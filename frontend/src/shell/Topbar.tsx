import { Bell, Check, ChevronDown, HelpCircle, Network, Search, Settings, X } from 'lucide-react';
import { type RefObject, useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import { DevBadge, SyntheticEvalBadge } from '../components/Badges';
import {
  type Health,
  getHealth,
  getNotifications,
  getWorkspaces,
  onNeedsYouChanged,
} from '../lib/api';
import {
  NOTIFICATIONS_DISMISSED_EVENT,
  NO_NOTIFICATIONS,
  dismissNotification,
  formatNotificationTitle,
  formatNotificationWhen,
  getDismissed,
} from '../lib/notifications';
import type { Notification, Workspace } from '../lib/types';
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

/** The panel header line for the bell: the badge counts only the rows that ask
 *  for action, so the header says how the two numbers relate (D4, RD8). */
export function notificationSummary(total: number, actionable: number): string {
  const rest = total - actionable;
  const head = actionable > 0 ? `${actionable} need${actionable === 1 ? 's' : ''} attention` : 'None need attention';
  return rest > 0 ? `${head} · ${rest} more` : head;
}

function isInside(target: EventTarget | null, refs: RefObject<HTMLElement | null>[]): boolean {
  if (!(target instanceof Node)) return false;
  return refs.some((r) => r.current?.contains(target));
}

function useBreadcrumb(): { crumb: string; crumb2?: string } {
  const { pathname } = useLocation();
  const params = useParams();
  if (pathname.startsWith('/dashboard')) return { crumb: 'Dashboard' };
  if (pathname.startsWith('/alerts')) return { crumb: 'Alerts' };
  if (pathname.startsWith('/investigations')) return { crumb: 'Investigations' };
  if (pathname.startsWith('/investigation')) return { crumb: 'Investigation', crumb2: params.id };
  if (pathname.startsWith('/hunts') && params.id) return { crumb: 'Hunts', crumb2: params.id };
  if (pathname.startsWith('/hunts')) return { crumb: 'Hunts' };
  if (pathname.startsWith('/hosts') && params.key) return { crumb: 'Hosts', crumb2: params.key };
  if (pathname.startsWith('/hosts')) return { crumb: 'Hosts' };
  if (pathname.startsWith('/notifications')) return { crumb: 'Notifications' };
  if (pathname.startsWith('/backtest')) return { crumb: 'Backtest' };
  if (pathname.startsWith('/runbooks')) return { crumb: 'Runbooks' };
  if (pathname.startsWith('/config')) return { crumb: 'Config' };
  return { crumb: '' };
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
    const load = () =>
      getNotifications()
        .then((list) => {
          if (!alive) return;
          const dismissed = getDismissed();
          setNotifs(list.filter((n) => !dismissed.has(n.id)));
        })
        .catch(() => {});
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
  const healthDown = healthList.filter((c) => !c.ok).length;
  const healthOk = health !== null && !healthFailed && healthDown === 0;
  // grey = initial load; amber = fetch failed or components down; green = all ok
  const healthColor = healthFailed ? '#f5a623' : health === null ? '#6b7484' : healthOk ? '#3fb950' : '#f5a623';

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

  // The badge is a call to action, so it counts only items that ARE one:
  // danger (true positives) and warn (needs-info, hunts with findings,
  // dependency-down). `accent` completions — the "FP closed itself" firehose —
  // stay in the dropdown and on /notifications but never light the badge.
  const actionable = notifs.filter((n) => n.tone !== 'accent');
  const bellName =
    actionable.length > 0 ? `Notifications, ${actionable.length} need${actionable.length === 1 ? 's' : ''} attention` : 'Notifications';

  return (
    <div className="relative z-30 flex h-[52px] flex-none items-center gap-[11px] border-b border-border bg-[rgba(11,14,19,.7)] py-0 pl-4 pr-3.5 backdrop-blur-[8px]">
      {/* workspace switcher — dropdown only when >1 workspace exists */}
      {workspaces.length > 1 ? (
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
          <span className="whitespace-nowrap text-[12.5px] font-semibold">{ws || '…'}</span>
          <span className="flex text-faint">
            <ChevronDown size={12} />
          </span>
        </button>
      ) : (
        <div
          title="Current workspace"
          className="flex flex-none items-center gap-2 rounded-control border border-border-2 bg-surface-1 px-[9px] py-[5px]"
        >
          <div
            className="flex h-5 w-5 items-center justify-center rounded-[5px] text-[10px] font-bold text-white"
            style={{ background: 'linear-gradient(135deg,#4b8bf5,#2c5fd0)' }}
          >
            <WorkspaceGlyph name={ws} />
          </div>
          <span className="whitespace-nowrap text-[12.5px] font-semibold">{ws || '…'}</span>
        </div>
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
              <div className="min-w-0 flex-1 truncate text-left text-[12.5px] font-semibold">{w.name}</div>
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

      <div className="h-[18px] w-px flex-none bg-border-2" />

      {/* breadcrumb */}
      <div className="flex min-w-0 items-center gap-[7px] text-[13px] text-dim">
        <span className="whitespace-nowrap font-semibold text-text">{crumb}</span>
        {crumb2 && (
          <>
            <span className="text-ghost">/</span>
            <span
              data-testid="topbar-crumb2"
              className={`truncate whitespace-nowrap text-dim ${crumb2Name ? 'text-[12.5px]' : 'font-mono text-[12px]'}`}
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
        title="Search or jump to. The shortcut is ⌘K."
        className="flex flex-none cursor-text items-center gap-2 rounded-control border border-border-2 bg-surface-1 px-2.5 py-1.5 text-faint hover:border-border-strong"
        style={{ width: 'clamp(170px,22vw,300px)' }}
      >
        <span className="flex">
          <Search size={14} />
        </span>
        <span className="flex-1 truncate whitespace-nowrap text-left text-[12.5px]">Search or jump to…</span>
        <kbd className="rounded-[4px] border border-border-input px-[5px] py-px font-mono text-[10px] text-dim">⌘K</kbd>
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
        className="flex flex-none items-center gap-1.5 rounded-control border border-border-2 px-[9px] py-1.5 font-mono text-[11.5px] text-dim hover:border-border-strong hover:text-text"
      >
        <span
          className="h-1.5 w-1.5 rounded-full"
          style={{ background: healthColor, boxShadow: `0 0 8px ${healthColor}` }}
        />
        {healthFailed ? 'unreachable' : health === null ? 'checking…' : healthOk ? 'connected' : `${healthDown} degraded`}
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
            <div className="px-3.5 py-6 text-center text-[12px] text-warn">The API is unreachable. Retrying…</div>
          )}
          {!healthFailed && health === null && (
            <div className="px-3.5 py-6 text-center text-[12px] text-faint">Checking…</div>
          )}
          {([
            ['Elasticsearch', health?.es],
            ['LLM gateway', health?.llm],
            ['Security Onion API', health?.so],
            ['PCAP (sensor)', health?.pcap],
          ] as const).map(([label, c]) =>
            c == null ? null : (
              <div key={label} className="flex gap-2.5 border-b border-border-faint px-3.5 py-[11px] last:border-0">
                <span
                  className="mt-[5px] h-[7px] w-[7px] flex-none rounded-full"
                  style={{ background: c.ok ? '#3fb950' : '#f5a623', boxShadow: `0 0 7px ${c.ok ? '#3fb950' : '#f5a623'}` }}
                />
                <div className="min-w-0 flex-1">
                  <div className="text-[12.5px] font-semibold">
                    {label} <span className={c.ok ? 'text-success' : 'text-warn'}>{c.ok ? 'ok' : 'down'}</span>
                  </div>
                  <div className="mt-0.5 break-words font-mono text-[10.5px] leading-[1.5] text-faint">
                    {c.detail}
                  </div>
                </div>
              </div>
            )
          )}
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
        {actionable.length > 0 && (
          <span
            data-testid="notif-badge"
            className="absolute -right-[5px] -top-[5px] flex h-4 min-w-[16px] items-center justify-center rounded-lg border-2 border-surface-1 bg-danger px-[3px] font-mono text-[9px] font-bold text-white"
          >
            {actionable.length}
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
          <div className="flex items-baseline gap-2 border-b border-border-2 px-3.5 py-3">
            <span className="text-[13px] font-semibold">Notifications</span>
            {notifs.length > 0 && (
              <span data-testid="notif-summary" className="ml-auto text-[11.5px] text-faint">
                {notificationSummary(notifs.length, actionable.length)}
              </span>
            )}
          </div>
          {notifs.length === 0 && (
            <div className="px-3.5 py-6 text-center text-[12px] text-faint">{NO_NOTIFICATIONS}</div>
          )}
          {notifs.map((nt) => {
            const body = (
              <>
                <div className="text-[12.5px] leading-[1.45]">
                  {formatNotificationTitle(nt.title)}
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

      {/* help */}
      <button
        onClick={openPalette}
        title="Help & shortcuts"
        aria-label="Help and shortcuts"
        className="flex h-[34px] w-[34px] flex-none items-center justify-center rounded-control border border-border-2 text-dim hover:border-border-strong hover:text-text"
      >
        <HelpCircle size={16} />
      </button>

    </div>
  );
}
