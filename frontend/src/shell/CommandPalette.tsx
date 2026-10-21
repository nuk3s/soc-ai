import { AtSign, Bell, BookOpen, ChevronsLeft, Crosshair, Globe, History, Info, Keyboard, LayoutDashboard, Search, Server, Settings, SlidersHorizontal, Triangle, User, Wrench, Zap } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { getAlerts, getConfig, getHealth, getInvestigations, listMachines, searchEntityIndex, signOut } from '../lib/api';
import { buildConfigLayout, keyToSectionId } from '../lib/configLayout';
import type { ConfigParent } from '../lib/configLayout';
import { machineHref } from '../lib/hostsList';
import {
  SERVER_HIT_GROUP,
  machineHitDetail,
  machineHitLabel,
  rowsFor,
  searchEntities,
  type QueryResult,
} from '../lib/paletteSearch';
import type { AlertGroup, EntitySearchHit, InvestigationRow, MachineRow } from '../lib/types';
import { isSignedOut, useSession } from './Session';
import { useShell } from './ShellContext';
import { GUIDE_URL } from './pages';
import { returnFocusTarget } from './platform';
import { upstreamState } from './upstream';

interface Command {
  group:
    | 'Go to'
    | 'Help'
    | 'Action'
    | 'View'
    | 'Account'
    | 'Investigations'
    | 'Alerts'
    | 'Settings'
    | 'Hosts'
    | 'Users'
    | 'Domains'
    | 'Addresses'
    | 'Hunts';
  label: string;
  /** The second line. Two results with the same label read apart on it. */
  detail?: string;
  icon: ReactNode;
  run: () => void;
}

const NO_RESULT: QueryResult<never> = { q: '', rows: [] };

const SERVER_HIT_ICON: Record<EntitySearchHit['type'], ReactNode> = {
  user: <User size={15} />,
  domain: <AtSign size={15} />,
  address: <Server size={15} />,
  external_address: <Globe size={15} />,
  hunt: <Crosshair size={15} />,
};

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

/** The sweep the palette starts. Alerts runs it with the header sweep window
 *  and its default floor, "High and up", which also takes the alerts that
 *  carry no severity (lib/api.ts severitiesAtOrAbove). */
const SWEEP_RANGE = '24h';
const SWEEP_SEVERITIES = new Set(['critical', 'high', 'unknown']);

/** What the confirm step knows before the analyst starts the sweep. */
interface BulkCheck {
  /** Untriaged alert groups in the sweep band, or null while unknown. */
  groups: number | null;
  /** The count read failed. */
  countFailed: boolean;
  /** Why the sweep cannot run now, one sentence each. */
  blocked: string[];
  checking: boolean;
}

/** Why the confirm offers no Investigate when the count is zero. */
const BULK_NOTHING = 'No alert group of these severities waits for a verdict.';

/** The count line of the confirm step. */
function bulkCountLine(check: BulkCheck): string {
  if (check.groups !== null) {
    const n = check.groups;
    return `${n.toLocaleString()} alert group${n === 1 ? '' : 's'} of these severities ${n === 1 ? 'has' : 'have'} no verdict.`;
  }
  return check.countFailed ? 'soc-ai could not count the alert groups.' : 'Counting the alert groups.';
}

// Focusable descendants for the Tab focus-trap while the palette is open.
const FOCUSABLE =
  'a[href],button:not([disabled]),textarea:not([disabled]),input:not([disabled]),select:not([disabled]),[tabindex]:not([tabindex="-1"])';

export function CommandPalette() {
  const {
    paletteOpen,
    openPalette,
    closePalette,
    togglePalette,
    collapsed,
    toggleNav,
    pushModal,
    popModal,
    openShortcuts,
  } = useShell();
  // With sign-in off there is no session to end. Sign out stranded the analyst
  // on a login page with no credentials to use (RD2).
  const signedOut = isSignedOut(useSession().me);
  const navigate = useNavigate();
  const [q, setQ] = useState('');
  const [idx, setIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  // The confirm step of the bulk sweep. The entry started a sweep at once,
  // with no word on the window, the severities or the model cost (dogfood
  // 2026-10-19, R1-D14).
  const [bulk, setBulk] = useState<BulkCheck | null>(null);
  const confirmRef = useRef<HTMLButtonElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);

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
      // Operator group, sidebar order: the hub first, then its three items.
      { group: 'Go to', label: 'Status', icon: <Wrench size={15} />, run: go('/operate') },
      { group: 'Go to', label: 'Runbooks', icon: <BookOpen size={15} />, run: go('/runbooks') },
      { group: 'Go to', label: 'Backtest', icon: <History size={15} />, run: go('/backtest') },
      { group: 'Go to', label: 'Settings', icon: <Settings size={15} />, run: go('/config') },
      { group: 'Go to', label: 'About soc-ai', icon: <Info size={15} />, run: go('/config#about') },
      {
        group: 'Action',
        label: 'Investigate untriaged alerts of the last 24 hours',
        detail: 'The Bulk Investigate sweep of the Alerts page',
        icon: <Zap size={15} />,
        // The entry opens a confirm step. The sweep starts from its button.
        run: () => setBulk({ groups: null, countFailed: false, blocked: [], checking: true }),
      },
      {
        group: 'Help',
        label: 'Keyboard shortcuts',
        icon: <Keyboard size={15} />,
        run: () => {
          closePalette();
          openShortcuts();
        },
      },
      {
        group: 'Help',
        label: 'Open the guide',
        icon: <BookOpen size={15} />,
        run: () => {
          closePalette();
          window.open(GUIDE_URL, '_blank', 'noopener');
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
      { group: 'View', label: 'My queue', icon: <Triangle size={15} />, run: go('/alerts?view=mine') },
      { group: 'View', label: 'Critical alerts', icon: <Triangle size={15} />, run: go('/alerts?view=critical') },
      { group: 'View', label: 'Needs decision', icon: <Triangle size={15} />, run: go('/alerts?view=decision') },
      ...(signedOut
        ? []
        : ([
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
          ] satisfies Command[])),
    ];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [collapsed, navigate, closePalette, toggleNav, signedOut, openShortcuts]);

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

  // Hosts are searched SERVER-side per keystroke, through the same machine
  // search the Hosts list uses, so the palette and the list give one answer
  // (dogfood 2026-10-02, U7). The search reads every machine, quiet ones too.
  // 150ms debounce, fail-soft like the other corpora.
  //
  // Each result set carries the query it answers, and the list shows a set
  // only while the box still holds that query. A set from the previous query
  // stayed on screen above "No matches" until the next answer landed
  // (dogfood 2026-10-06, 7.5).
  const [hostResult, setHostResult] = useState<QueryResult<MachineRow>>(NO_RESULT);
  // Users, domains, addresses no machine holds and hunts: the server's index
  // (dogfood 2026-10-06, 7.2 and 7.4). Same debounce, same rule.
  const [indexResult, setIndexResult] = useState<QueryResult<EntitySearchHit>>(NO_RESULT);
  useEffect(() => {
    const term = q.trim();
    if (!paletteOpen || term.length < 2) {
      setHostResult(NO_RESULT);
      setIndexResult(NO_RESULT);
      return;
    }
    let alive = true;
    const t = setTimeout(() => {
      listMachines({ q: term, limit: 8 })
        .then((res) => {
          if (alive) setHostResult({ q: term, rows: res.rows });
        })
        // Unlike the client-filtered corpora, a kept-on-error page here would
        // show hits for a query the user is no longer typing — clear instead.
        .catch(() => {
          if (alive) setHostResult({ q: term, rows: [] });
        });
      searchEntityIndex(term)
        .then((res) => {
          if (alive) setIndexResult({ q: term, rows: res.hits });
        })
        .catch(() => {
          if (alive) setIndexResult({ q: term, rows: [] });
        });
    }, 150);
    return () => {
      alive = false;
      clearTimeout(t);
    };
  }, [paletteOpen, q]);
  const hostRows = rowsFor(hostResult, q);
  const indexHits = rowsFor(indexResult, q);

  const filtered = useMemo(() => {
    const query = q.toLowerCase();
    const base = query
      ? commands.filter(
          (c) =>
            c.label.toLowerCase().includes(query) ||
            c.group.toLowerCase().includes(query) ||
            (c.detail ?? '').toLowerCase().includes(query),
        )
      : commands;
    // IP → host page is the analyst's primary pivot, so host hits sit ahead of
    // investigation/alert entity hits.
    const hostCmds = hostRows.map<Command>((h) => ({
      group: 'Hosts',
      label: machineHitLabel(h),
      detail: machineHitDetail(h),
      icon: <Server size={15} />,
      run: () => {
        closePalette();
        navigate(machineHref(h.key));
      },
    }));
    const indexCmds = indexHits.map<Command>((h) => ({
      group: SERVER_HIT_GROUP[h.type],
      label: h.label,
      detail: h.detail,
      icon: SERVER_HIT_ICON[h.type],
      run: () => {
        closePalette();
        navigate(h.href);
      },
    }));
    const entities = searchEntities(q, invs, groups).map<Command>((h) => ({
      group: h.group,
      label: h.label,
      detail: h.detail,
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
    return [...base, ...hostCmds, ...indexCmds, ...entities, ...settings];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, commands, hostResult, indexResult, invs, groups, layout]);

  // reset query + selection on open; focus the input; refresh the entity corpus;
  // count into the shared modal stack and restore focus to the opener on close.
  useEffect(() => {
    if (!paletteOpen) return;
    setQ('');
    setIdx(0);
    setBulk(null);
    getInvestigations().then(setInvs).catch(() => {});
    getAlerts({ range: '7d' }).then((q) => setGroups(q.groups)).catch(() => {});
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
      // A palette opened from the keyboard with nothing focused gave the
      // focus back to BODY (dogfood 2026-10-19, H1-D19). The trigger takes it.
      returnFocusTarget(opener)?.focus?.();
    };
  }, [paletteOpen, pushModal, popModal]);

  // The confirm step reads what it states: the untriaged groups in the sweep
  // band, and whether the grid and the model gateway answer.
  const bulkOpen = bulk !== null;
  useEffect(() => {
    if (!bulkOpen) return;
    let alive = true;
    Promise.allSettled([getAlerts({ range: SWEEP_RANGE }), getHealth()]).then(([alerts, health]) => {
      if (!alive) return;
      const rows = alerts.status === 'fulfilled' ? alerts.value?.groups : undefined;
      const groups = Array.isArray(rows)
        ? rows.filter((g) => SWEEP_SEVERITIES.has(g.sev) && g.verdict === 'untriaged' && !g.triaging).length
        : null;
      // An unread health answer blocks nothing. The sweep reports its own
      // failure on Alerts.
      const h = health.status === 'fulfilled' ? health.value : null;
      const blocked: string[] = [];
      if (h?.es && upstreamState(h.es) === 'down') {
        blocked.push('The grid does not answer. The sweep cannot read the alerts.');
      }
      if (h?.llm && upstreamState(h.llm) === 'down') {
        blocked.push('The model gateway does not answer. The investigations cannot run.');
      }
      setBulk({ groups, countFailed: groups === null, blocked, checking: false });
    });
    return () => {
      alive = false;
    };
  }, [bulkOpen]);
  // The focus goes to the button that acts, or to Cancel when the sweep
  // cannot run. A sweep with no group to investigate starts nothing, so its
  // button is off too. At 0 groups the button stayed on and took the focus
  // (dogfood 2026-10-19, V1-S3).
  const bulkBlocked = (bulk?.blocked.length ?? 0) > 0;
  const bulkChecking = bulk?.checking ?? false;
  const bulkEmpty = bulk?.groups === 0;
  useEffect(() => {
    if (!bulkOpen) return;
    (bulkBlocked || bulkChecking || bulkEmpty ? cancelRef : confirmRef).current?.focus();
  }, [bulkOpen, bulkBlocked, bulkChecking, bulkEmpty]);
  const startBulk = () => {
    setBulk(null);
    closePalette();
    // Carry the intent in the navigation STATE, not a shell nonce: Alerts is
    // code-split, so from another screen it mounts AFTER this click commits —
    // a nonce bumped pre-mount is seeded away and never seen, and the batch
    // silently never starts. Alerts consumes-and-clears location.state on the
    // arriving navigation (and on a repeat while already there).
    navigate('/alerts', { state: { autoTriage: true } });
  };
  const cancelBulk = () => {
    setBulk(null);
    window.setTimeout(() => inputRef.current?.focus(), 0);
  };

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
        } else if (bulkOpen) {
          // The confirm step has its own buttons. The list keys do nothing.
          return;
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
  }, [paletteOpen, filtered, idx, togglePalette, openPalette, closePalette, bulkOpen]);

  if (!paletteOpen) return null;

  return (
    <>
      <div onClick={closePalette} className="fixed inset-0 z-[60] bg-[rgba(4,6,9,.55)] backdrop-blur-[2px]" />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        className="fixed left-1/2 top-[84px] z-[61] flex max-h-[calc(100vh-100px)] -translate-x-1/2 animate-fadeUp flex-col overflow-hidden rounded-panel-lg border border-border-input bg-surface-card shadow-palette"
        style={{ width: 'min(560px,92vw)' }}
      >
        {bulk ? (
          <div data-testid="palette-bulk-confirm" className="flex min-h-0 flex-col overflow-y-auto">
            <div className="flex items-center gap-2.5 border-b border-border-2 px-4 py-[13px]">
              <span className="flex text-faint">
                <Zap size={15} />
              </span>
              <span className="text-[14px] font-semibold text-text">Investigate untriaged alerts</span>
            </div>
            <div className="flex flex-col gap-2 px-4 py-3.5 text-[13px] leading-[1.5] text-dim">
              <p>
                soc-ai sweeps the alerts of the last 24 hours. The sweep covers the critical and high
                alerts and the alerts with no severity.
              </p>
              <p data-testid="palette-bulk-count" className="text-text-2">
                {bulkCountLine(bulk)}
              </p>
              <p>soc-ai investigates each untriaged alert. Each investigation uses the model.</p>
              {bulk.blocked.map((line) => (
                <p key={line} className="font-semibold text-danger">
                  {line}
                </p>
              ))}
            </div>
            <div className="flex items-center justify-end gap-2 border-t border-border-2 px-3.5 py-2.5">
              <button
                ref={cancelRef}
                type="button"
                onClick={cancelBulk}
                className="rounded-control border border-border-2 px-3 py-1.5 text-[12.5px] font-semibold text-dim hover:border-border-strong hover:text-text"
              >
                Cancel
              </button>
              <button
                ref={confirmRef}
                type="button"
                onClick={startBulk}
                disabled={bulk.checking || bulk.blocked.length > 0 || bulk.groups === 0}
                title={bulk.groups === 0 ? BULK_NOTHING : undefined}
                className="rounded-control border border-accent bg-accent px-3 py-1.5 text-[12.5px] font-semibold text-white disabled:cursor-not-allowed disabled:opacity-50"
              >
                Investigate
              </button>
            </div>
          </div>
        ) : (
        <>
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
            placeholder="Search commands, screens, hosts"
            className="flex-1 border-none bg-transparent text-[15px] text-text outline-none"
            role="combobox"
            aria-autocomplete="list"
            aria-controls="palette-listbox"
            aria-expanded={filtered.length > 0}
            aria-activedescendant={filtered[idx] ? `palette-opt-${idx}` : undefined}
          />
          <kbd className="rounded-[4px] border border-border-input px-1.5 py-px font-mono text-[10px] text-faint">esc</kbd>
        </div>
        <div className="max-h-[344px] min-h-0 flex-1 overflow-y-auto p-1.5" role="listbox" id="palette-listbox" aria-label="Results">
          {filtered.map((c, i) => (
            <button
              key={`${c.group}:${c.label}:${c.detail ?? ''}:${i}`}
              id={`palette-opt-${i}`}
              role="option"
              aria-selected={i === idx}
              onClick={c.run}
              onMouseMove={() => setIdx(i)}
              className="flex w-full items-center gap-[11px] rounded-control px-[11px] py-[9px] text-left"
              style={{ background: i === idx ? '#141b25' : 'transparent' }}
            >
              <span className="flex w-4 justify-center text-dim">{c.icon}</span>
              <span className="min-w-0 flex-1">
                <span className="block break-words text-[13.5px] text-text">{c.label}</span>
                {c.detail && (
                  <span
                    data-testid="palette-detail"
                    className="block break-all font-mono text-[11px] text-faint"
                  >
                    {c.detail}
                  </span>
                )}
              </span>
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
        </>
        )}
      </div>
    </>
  );
}
