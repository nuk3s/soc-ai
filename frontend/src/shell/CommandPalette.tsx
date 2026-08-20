import { Bell, BookOpen, ChevronsLeft, Crosshair, History, Info, LayoutDashboard, Search, Server, Settings, SlidersHorizontal, Triangle, Wrench, Zap } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { getAlerts, getConfig, getInvestigations, signOut } from '../lib/api';
import { buildConfigLayout, keyToSectionId } from '../lib/configLayout';
import type { ConfigParent } from '../lib/configLayout';
import { searchEntities } from '../lib/paletteSearch';
import type { AlertGroup, InvestigationRow } from '../lib/types';
import { useShell } from './ShellContext';

interface Command {
  group: 'Go to' | 'Action' | 'View' | 'Account' | 'Investigations' | 'Alerts' | 'Settings';
  label: string;
  icon: ReactNode;
  run: () => void;
}

/** One Config-page hit: a single setting (carries `key`, so the Config page can
 * flash the exact row) or a whole section (no key — just the anchor). */
interface SettingHit {
  label: string;
  to: string;
  key?: string;
}

const SETTINGS_CAP = 10;
// Below this the settings corpus (~275 rows) would swamp the command list, and
// an empty query must still show the plain command menu.
const SETTINGS_MIN_QUERY = 2;

/**
 * Case-insensitive search over every setting the Config page renders, plus the
 * sections themselves. The palette indexed only screens and entities, so any
 * settings concept ("inherit", "egress") returned "No matches" while the Config
 * page held the answer behind 31 collapsed sections (dogfood 2026-08-01).
 *
 * Ranked: setting labels, then sections, then key matches, then help-text-only
 * matches — the analyst's words are usually the label, and a help-text match is
 * the weakest signal. Section ids come from buildConfigLayout/keyToSectionId, so
 * `/config#<id>` always agrees with the id the page actually renders.
 */
function searchSettings(q: string, layout: ConfigParent[] | null): SettingHit[] {
  const query = q.trim().toLowerCase();
  if (!layout || query.length < SETTINGS_MIN_QUERY) return [];
  const sectionOf = keyToSectionId(layout);
  // 0 = setting label, 1 = section, 2 = setting key, 3 = help text only.
  const tiers: SettingHit[][] = [[], [], [], []];
  for (const parent of layout) {
    for (const child of parent.children) {
      if (child.label.toLowerCase().includes(query)) {
        tiers[1].push({ label: `${child.label} · section`, to: `/config#${child.id}` });
      }
      if (child.kind !== 'group') continue;
      for (const item of child.group.items) {
        const label = item.label || item.key;
        const tier = label.toLowerCase().includes(query)
          ? 0
          : item.key.toLowerCase().includes(query)
            ? 2
            : (item.help || '').toLowerCase().includes(query)
              ? 3
              : -1;
        if (tier < 0) continue;
        tiers[tier].push({
          label: `${label} · ${child.label}`,
          to: `/config#${sectionOf[item.key] ?? child.id}`,
          key: item.key,
        });
      }
    }
  }
  return tiers.flat().slice(0, SETTINGS_CAP);
}

// Focusable descendants for the Tab focus-trap while the palette is open.
const FOCUSABLE =
  'a[href],button:not([disabled]),textarea:not([disabled]),input:not([disabled]),select:not([disabled]),[tabindex]:not([tabindex="-1"])';

export function CommandPalette() {
  const { paletteOpen, openPalette, closePalette, togglePalette, collapsed, toggleNav, pushModal, popModal } =
    useShell();
  const navigate = useNavigate();
  const [q, setQ] = useState('');
  const [idx, setIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);

  const commands = useMemo<Command[]>(() => {
    const go = (to: string) => () => {
      closePalette();
      navigate(to);
    };
    return [
      { group: 'Go to', label: 'Dashboard', icon: <LayoutDashboard size={15} />, run: go('/dashboard') },
      { group: 'Go to', label: 'Alerts', icon: <Triangle size={15} />, run: go('/alerts') },
      { group: 'Go to', label: 'Investigations', icon: <Search size={15} />, run: go('/investigations') },
      // Screens do not self-register here; the Go-to list is hand-kept in the
      // sidebar's order, so a new nav entry has to be added in both places.
      { group: 'Go to', label: 'Hosts', icon: <Server size={15} />, run: go('/hosts') },
      { group: 'Go to', label: 'Notifications', icon: <Bell size={15} />, run: go('/notifications') },
      { group: 'Go to', label: 'Hunts', icon: <Crosshair size={15} />, run: go('/hunts') },
      // Operate group, sidebar order: the hub first, then its three items.
      { group: 'Go to', label: 'Operate', icon: <Wrench size={15} />, run: go('/operate') },
      { group: 'Go to', label: 'Runbooks', icon: <BookOpen size={15} />, run: go('/runbooks') },
      { group: 'Go to', label: 'Backtest', icon: <History size={15} />, run: go('/backtest') },
      { group: 'Go to', label: 'Config', icon: <Settings size={15} />, run: go('/config') },
      { group: 'Go to', label: 'About soc-ai', icon: <Info size={15} />, run: go('/config#about') },
      {
        group: 'Action',
        label: 'Bulk investigate all untriaged',
        icon: <Zap size={15} />,
        // Carry the intent in the navigation STATE, not a shell nonce: Alerts is
        // code-split, so from another screen it mounts AFTER this click commits —
        // a nonce bumped pre-mount is seeded away and never seen, and the batch
        // silently never starts. Alerts consumes-and-clears location.state on the
        // arriving navigation (and on a repeat while already there).
        run: () => {
          closePalette();
          navigate('/alerts', { state: { autoTriage: true } });
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
  }, [collapsed, navigate, closePalette, toggleNav]);

  // Entity corpus for the search half of "Search or jump to": fetched once per
  // palette open (fail-soft — a fetch error just means command-only results).
  const [invs, setInvs] = useState<InvestigationRow[]>([]);
  const [groups, setGroups] = useState<AlertGroup[]>([]);

  // Config corpus for the Settings group. Unlike the entity corpus this is
  // fetched ONCE per mount, not per open: it's large, near-static, and
  // admin-only — an analyst's 403 (or any failure) is cached as "no settings
  // results" so the palette behaves exactly as it did before, with no error UI
  // and no retry on every ⌘K.
  const [layout, setLayout] = useState<ConfigParent[] | null>(null);
  const configRequested = useRef(false);

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
    // Pre-filtered against the query (like the entity hits), so the generic
    // label/group filter above must not run over them a second time.
    const settings = searchSettings(q, layout).map<Command>((h) => ({
      group: 'Settings',
      label: h.label,
      icon: <SlidersHorizontal size={15} />,
      run: () => {
        closePalette();
        // `state.highlightKey` is the contract the Config page reads to flash
        // the exact row; section hits carry no key, so they navigate bare.
        if (h.key) navigate(h.to, { state: { highlightKey: h.key } });
        else navigate(h.to);
      },
    }));
    return [...base, ...entities, ...settings];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, commands, invs, groups, layout]);

  // reset query + selection on open; focus the input; refresh the entity corpus;
  // count into the shared modal stack and restore focus to the opener on close.
  useEffect(() => {
    if (!paletteOpen) return;
    setQ('');
    setIdx(0);
    getInvestigations().then(setInvs).catch(() => {});
    getAlerts({ range: '7d' }).then(setGroups).catch(() => {});
    if (!configRequested.current) {
      configRequested.current = true;
      getConfig()
        .then((c) => setLayout(buildConfigLayout(c.groups)))
        .catch(() => {});
    }
    pushModal();
    const opener = document.activeElement as HTMLElement | null;
    // focus after paint
    const t = setTimeout(() => inputRef.current?.focus(), 0);
    return () => {
      clearTimeout(t);
      popModal();
      opener?.focus?.();
    };
  }, [paletteOpen, pushModal, popModal]);

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
        else if (e.key === 'Tab') {
          const node = panelRef.current;
          if (!node) return;
          const items = Array.from(node.querySelectorAll<HTMLElement>(FOCUSABLE));
          if (items.length === 0) return;
          const first = items[0];
          const last = items[items.length - 1];
          const active = document.activeElement;
          if (e.shiftKey && (active === first || !node.contains(active))) {
            e.preventDefault();
            last.focus();
          } else if (!e.shiftKey && (active === last || !node.contains(active))) {
            e.preventDefault();
            first.focus();
          }
        } else if (e.key === 'ArrowDown') {
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
        ref={panelRef}
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
            role="combobox"
            aria-autocomplete="list"
            aria-controls="palette-listbox"
            aria-expanded={filtered.length > 0}
            aria-activedescendant={filtered[idx] ? `palette-opt-${idx}` : undefined}
          />
          <kbd className="rounded-[4px] border border-border-input px-1.5 py-px font-mono text-[10px] text-faint">esc</kbd>
        </div>
        <div className="max-h-[344px] overflow-y-auto p-1.5" role="listbox" id="palette-listbox" aria-label="Results">
          {filtered.map((c, i) => (
            <button
              key={c.group + c.label}
              id={`palette-opt-${i}`}
              role="option"
              aria-selected={i === idx}
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
