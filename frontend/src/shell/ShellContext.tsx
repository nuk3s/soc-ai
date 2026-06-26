import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

const NAV_KEY = 'soc-ai:navCollapsed';

interface ShellState {
  collapsed: boolean;
  toggleNav: () => void;
  paletteOpen: boolean;
  openPalette: () => void;
  closePalette: () => void;
  togglePalette: () => void;
  ws: string;
  setWs: (w: string) => void;
  /** triggered by command palette / bulk bar to kick the alerts auto-triage strip */
  triageNonce: number;
  requestTriage: () => void;
}

const Ctx = createContext<ShellState | null>(null);

export function ShellProvider({ children }: { children: ReactNode }) {
  const [collapsed, setCollapsed] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [ws, setWs] = useState('');
  const [triageNonce, setTriageNonce] = useState(0);

  // hydrate persisted sidebar state
  useEffect(() => {
    try {
      if (localStorage.getItem(NAV_KEY) === '1') setCollapsed(true);
    } catch {
      /* ignore */
    }
  }, []);

  const toggleNav = useCallback(() => {
    setCollapsed((c) => {
      const next = !c;
      try {
        localStorage.setItem(NAV_KEY, next ? '1' : '0');
      } catch {
        /* ignore */
      }
      return next;
    });
  }, []);

  const openPalette = useCallback(() => setPaletteOpen(true), []);
  const closePalette = useCallback(() => setPaletteOpen(false), []);
  const togglePalette = useCallback(() => setPaletteOpen((o) => !o), []);
  const requestTriage = useCallback(() => setTriageNonce((n) => n + 1), []);

  const value = useMemo<ShellState>(
    () => ({
      collapsed,
      toggleNav,
      paletteOpen,
      openPalette,
      closePalette,
      togglePalette,
      ws,
      setWs,
      triageNonce,
      requestTriage,
    }),
    [collapsed, toggleNav, paletteOpen, openPalette, closePalette, togglePalette, ws, triageNonce, requestTriage]
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useShell(): ShellState {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error('useShell must be used within ShellProvider');
  return ctx;
}
