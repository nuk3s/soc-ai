import { BookOpen, ChevronsLeft, Crosshair, Search, Settings, Triangle, Zap } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { getAlerts, getInvestigations, signOut } from '../lib/api';
import { searchEntities } from '../lib/paletteSearch';
import type { AlertGroup, InvestigationRow } from '../lib/types';
import { useShell } from './ShellContext';

interface Command {
  group: 'Go to' | 'Action' | 'View' | 'Account' | 'Investigations' | 'Alerts';
  label: string;
  icon: ReactNode;
  run: () => void;
}

export function CommandPalette() {
  const { paletteOpen, openPalette, closePalette, togglePalette, collapsed, toggleNav, requestTriage } =
    useShell();
  const navigate = useNavigate();
  const [q, setQ] = useState('');
  const [idx, setIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const commands = useMemo<Command[]>(() => {
    const go = (to: string) => () => {
      closePalette();
      navigate(to);
    };
    return [
      { group: 'Go to', label: 'Alerts', icon: <Triangle size={15} />, run: go('/alerts') },
      { group: 'Go to', label: 'Investigations', icon: <Search size={15} />, run: go('/investigations') },
      { group: 'Go to', label: 'Hunts', icon: <Crosshair size={15} />, run: go('/hunts') },
      { group: 'Go to', label: 'Runbooks', icon: <BookOpen size={15} />, run: go('/runbooks') },
      { group: 'Go to', label: 'Config', icon: <Settings size={15} />, run: go('/config') },
      {
        group: 'Action',
        label: 'Bulk investigate all untriaged',
        icon: <Zap size={15} />,
        run: () => {
          closePalette();
          navigate('/alerts');
          requestTriage();
        },
      },
      {
        group: 'Action',
        label: (collapsed ? 'Expand' : 'Collapse') + ' sidebar',
        icon: <ChevronsLeft size={15} />,
        run: () => {
          closePalette();
          toggleNav();
        },
      },
      { group: 'View', label: 'My queue', icon: <Triangle size={15} />, run: go('/alerts?view=myqueue') },
      { group: 'View', label: 'Critical alerts', icon: <Triangle size={15} />, run: go('/alerts?view=critical') },
      { group: 'View', label: 'Needs decision', icon: <Triangle size={15} />, run: go('/alerts?view=decision') },
      {
        group: 'Account',
        label: 'Sign out',
        icon: <Triangle size={15} />,
        // Destroy the server session — not just a client-side route change
        // (which would leave the session cookie alive). Shared with the sidebar.
        run: () => {
          closePalette();
          void signOut(navigate);
        },
      },
    ];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [collapsed, navigate, closePalette, toggleNav, requestTriage]);

  // Entity corpus for the search half of "Search or jump to": fetched once per
  // palette open (fail-soft — a fetch error just means command-only results).
  const [invs, setInvs] = useState<InvestigationRow[]>([]);
  const [groups, setGroups] = useState<AlertGroup[]>([]);

  const filtered = useMemo(() => {
    const query = q.toLowerCase();
    const base = query
      ? commands.filter((c) => c.label.toLowerCase().includes(query) || c.group.toLowerCase().includes(query))
      : commands;
    const entities = searchEntities(q, invs, groups).map<Command>((h) => ({
      group: h.group,
      label: h.label,
      icon: h.group === 'Investigations' ? <Search size={15} /> : <Triangle size={15} />,
      run: () => {
        closePalette();
        navigate(h.to);
      },
    }));
    return [...base, ...entities];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, commands, invs, groups]);

  // reset query + selection on open; focus the input; refresh the entity corpus
  useEffect(() => {
    if (paletteOpen) {
      setQ('');
      setIdx(0);
      getInvestigations().then(setInvs).catch(() => {});
      getAlerts({ range: '7d' }).then(setGroups).catch(() => {});
      // focus after paint
      const t = setTimeout(() => inputRef.current?.focus(), 0);
      return () => clearTimeout(t);
    }
  }, [paletteOpen]);

  // global keyboard: ⌘K/Ctrl-K toggle, `/` open, arrows + enter when open
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.metaKey || e.ctrlKey;
      if (mod && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault();
        togglePalette();
        return;
      }
      if (paletteOpen) {
        if (e.key === 'Escape') closePalette();
        else if (e.key === 'ArrowDown') {
          e.preventDefault();
          setIdx((i) => {
            const n = filtered.length;
            return n ? (i + 1) % n : 0;
          });
        } else if (e.key === 'ArrowUp') {
          e.preventDefault();
          setIdx((i) => {
            const n = filtered.length;
            return n ? (i - 1 + n) % n : 0;
          });
        } else if (e.key === 'Enter') {
          e.preventDefault();
          filtered[idx]?.run();
        }
        return;
      }
      const tag = (e.target as HTMLElement)?.tagName ?? '';
      const onLogin = window.location.hash.includes('login') || window.location.pathname.includes('login');
      if (e.key === '/' && !/INPUT|TEXTAREA/.test(tag) && !onLogin) {
        e.preventDefault();
        openPalette();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [paletteOpen, filtered, idx, togglePalette, openPalette, closePalette]);

  if (!paletteOpen) return null;

  return (
    <>
      <div onClick={closePalette} className="fixed inset-0 z-[60] bg-[rgba(4,6,9,.55)] backdrop-blur-[2px]" />
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        className="fixed left-1/2 top-[84px] z-[61] -translate-x-1/2 animate-fadeUp overflow-hidden rounded-panel-lg border border-border-input bg-surface-card shadow-palette"
        style={{ width: 'min(560px,92vw)' }}
      >
        <div className="flex items-center gap-2.5 border-b border-border-2 px-4 py-[13px]">
          <span className="flex text-faint">
            <Search size={15} />
          </span>
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setIdx(0);
            }}
            placeholder="Search commands, screens, hosts…"
            className="flex-1 border-none bg-transparent text-[15px] text-text outline-none"
          />
          <kbd className="rounded-[4px] border border-border-input px-1.5 py-px font-mono text-[10px] text-faint">esc</kbd>
        </div>
        <div className="max-h-[344px] overflow-y-auto p-1.5">
          {filtered.map((c, i) => (
            <button
              key={c.group + c.label}
              onClick={c.run}
              onMouseMove={() => setIdx(i)}
              className="flex w-full items-center gap-[11px] rounded-control px-[11px] py-[9px] text-left"
              style={{ background: i === idx ? '#141b25' : 'transparent' }}
            >
              <span className="flex w-4 justify-center text-dim">{c.icon}</span>
              <span className="flex-1 text-[13.5px] text-text">{c.label}</span>
              <span className="rounded-chip border border-border-2 bg-surface-3 px-[7px] py-px font-mono text-[10px] text-faint">
                {c.group}
              </span>
            </button>
          ))}
          {filtered.length === 0 && <div className="p-[26px] text-center text-[13px] text-faint">No matches</div>}
        </div>
        <div className="flex items-center gap-4 border-t border-border-2 px-3.5 py-[9px] font-mono text-[10.5px] text-faint">
          <span>↑↓ navigate</span>
          <span>↵ select</span>
          <span>esc close</span>
        </div>
      </div>
    </>
  );
}
