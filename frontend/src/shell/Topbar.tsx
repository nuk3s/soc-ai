import { Bell, Check, ChevronDown, HelpCircle, Search, Settings } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useLocation, useParams } from 'react-router-dom';
import { DevBadge } from '../components/Badges';
import { type Health, getHealth, getNotifications, getWorkspaces } from '../lib/api';
import type { Notification, Workspace } from '../lib/types';
import { useShell } from './ShellContext';

const TONE: Record<Notification['tone'], string> = {
  danger: '#f04438',
  warn: '#f5a623',
  accent: '#4b8bf5',
};

function useBreadcrumb(): { crumb: string; crumb2?: string } {
  const { pathname } = useLocation();
  const params = useParams();
  if (pathname.startsWith('/alerts')) return { crumb: 'Alerts' };
  if (pathname.startsWith('/investigations')) return { crumb: 'Investigations' };
  if (pathname.startsWith('/investigation')) return { crumb: 'Investigation', crumb2: params.id };
  if (pathname.startsWith('/hunts') && params.id) return { crumb: 'Hunts', crumb2: params.id };
  if (pathname.startsWith('/hunts')) return { crumb: 'Hunts' };
  if (pathname.startsWith('/config')) return { crumb: 'Config' };
  return { crumb: '' };
}

export function Topbar() {
  const { openPalette, ws, setWs } = useShell();
  const { crumb, crumb2 } = useBreadcrumb();
  const [wsOpen, setWsOpen] = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);
  const [healthOpen, setHealthOpen] = useState(false);
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [notifs, setNotifs] = useState<Notification[]>([]);
  const [health, setHealth] = useState<Health | null>(null);
  const [healthFailed, setHealthFailed] = useState(false);

  useEffect(() => {
    getWorkspaces().then((list) => {
      setWorkspaces(list);
      if (list.length > 0) setWs(list[0].name);
    });
    getNotifications().then(setNotifs);
  }, []);

  // Poll upstream health (ES / LLM / PCAP) for the status indicator.
  useEffect(() => {
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
    const t = setInterval(tick, 60_000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  const healthList = health ? [health.es, health.llm, ...(health.pcap ? [health.pcap] : [])] : [];
  const healthDown = healthList.filter((c) => !c.ok).length;
  const healthOk = health !== null && !healthFailed && healthDown === 0;
  // grey = initial load; amber = fetch failed or components down; green = all ok
  const healthColor = healthFailed ? '#f5a623' : health === null ? '#6b7484' : healthOk ? '#3fb950' : '#f5a623';

  const menusOpen = wsOpen || notifOpen || healthOpen;
  const closeMenus = () => {
    setWsOpen(false);
    setNotifOpen(false);
    setHealthOpen(false);
  };

  return (
    <div className="relative z-30 flex h-[52px] flex-none items-center gap-[11px] border-b border-border bg-[rgba(11,14,19,.7)] py-0 pl-4 pr-3.5 backdrop-blur-[8px]">
      {/* workspace switcher — dropdown only when >1 workspace exists */}
      {workspaces.length > 1 ? (
        <button
          onClick={() => {
            setWsOpen((o) => !o);
            setNotifOpen(false);
          }}
          title="Switch workspace"
          className="flex flex-none items-center gap-2 rounded-control border border-border-2 bg-surface-1 px-[9px] py-[5px] hover:border-border-strong"
        >
          <div
            className="flex h-5 w-5 items-center justify-center rounded-[5px] text-[10px] font-bold text-white"
            style={{ background: 'linear-gradient(135deg,#4b8bf5,#2c5fd0)' }}
          >
            {ws ? ws[0] : '?'}
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
            {ws ? ws[0] : '?'}
          </div>
          <span className="whitespace-nowrap text-[12.5px] font-semibold">{ws || '…'}</span>
        </div>
      )}

      <div className="h-[18px] w-px flex-none bg-border-2" />

      {/* breadcrumb */}
      <div className="flex min-w-0 items-center gap-[7px] text-[13px] text-dim">
        <span className="whitespace-nowrap font-semibold text-text">{crumb}</span>
        {crumb2 && (
          <>
            <span className="text-ghost">/</span>
            <span className="truncate whitespace-nowrap font-mono text-[12px] text-dim">{crumb2}</span>
          </>
        )}
      </div>

      <div className="flex-1" />

      {/* command palette trigger */}
      <button
        onClick={openPalette}
        title="Search — ⌘K"
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

      {/* notifications */}
      <button
        onClick={() => {
          setNotifOpen((o) => !o);
          setWsOpen(false);
        }}
        title="Notifications"
        className="relative flex h-[34px] w-[34px] flex-none items-center justify-center rounded-control border border-border-2 text-dim hover:border-border-strong hover:text-text"
      >
        <Bell size={16} />
        {notifs.length > 0 && (
          <span className="absolute -right-[5px] -top-[5px] flex h-4 min-w-[16px] items-center justify-center rounded-lg border-2 border-surface-1 bg-danger px-[3px] font-mono text-[9px] font-bold text-white">
            {notifs.length}
          </span>
        )}
      </button>

      {/* help */}
      <button
        onClick={openPalette}
        title="Help & shortcuts"
        className="flex h-[34px] w-[34px] flex-none items-center justify-center rounded-control border border-border-2 text-dim hover:border-border-strong hover:text-text"
      >
        <HelpCircle size={16} />
      </button>

      {/* click-catcher */}
      {menusOpen && <div onClick={closeMenus} className="fixed inset-0 z-[31]" />}

      {/* workspace dropdown — only shown when multiple workspaces exist */}
      {wsOpen && workspaces.length > 1 && (
        <div className="absolute left-3.5 top-12 z-[33] w-64 animate-fadeUp rounded-panel border border-border-input bg-surface-card p-1.5 shadow-dropdown">
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
                {w.name[0]}
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

      {/* notifications dropdown */}
      {notifOpen && (
        <div className="absolute right-[46px] top-12 z-[33] w-[332px] animate-fadeUp overflow-hidden rounded-panel border border-border-input bg-surface-card shadow-dropdown">
          <div className="border-b border-border-2 px-3.5 py-3 text-[13px] font-semibold">Notifications</div>
          {notifs.length === 0 && (
            <div className="px-3.5 py-6 text-center text-[12px] text-faint">No notifications.</div>
          )}
          {notifs.map((nt, i) => (
            <div key={i} className="flex cursor-pointer gap-2.5 border-b border-border-faint px-3.5 py-[11px] hover:bg-[#141b25]">
              <span
                className="mt-[5px] h-[7px] w-[7px] flex-none rounded-full"
                style={{ background: TONE[nt.tone], boxShadow: `0 0 7px ${TONE[nt.tone]}` }}
              />
              <div className="min-w-0 flex-1">
                <div className="text-[12.5px] leading-[1.45]">{nt.title}</div>
                {nt.when && <div className="mt-[3px] font-mono text-[10.5px] text-faint">{nt.when} ago</div>}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* health dropdown — ES / LLM / PCAP, with the PCAP re-creation hint */}
      {healthOpen && (
        <div className="absolute right-[150px] top-12 z-[33] w-[360px] animate-fadeUp overflow-hidden rounded-panel border border-border-input bg-surface-card shadow-dropdown">
          <div className="border-b border-border-2 px-3.5 py-3 text-[13px] font-semibold">
            Upstream health
          </div>
          {healthFailed && (
            <div className="px-3.5 py-6 text-center text-[12px] text-warn">API unreachable — retrying…</div>
          )}
          {!healthFailed && health === null && (
            <div className="px-3.5 py-6 text-center text-[12px] text-faint">Checking…</div>
          )}
          {([
            ['Elasticsearch', health?.es],
            ['LLM gateway', health?.llm],
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
              PCAP fetch is disabled (pcap_enabled=false).
            </div>
          )}
        </div>
      )}
    </div>
  );
}
