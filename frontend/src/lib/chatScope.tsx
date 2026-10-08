import {
  createContext,
  type MutableRefObject,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { getAbout } from './api';
import { isEditableTarget } from './triageKeys';
import type { ChatMessage, Investigation } from './types';
import { useOptionalShell } from '../shell/ShellContext';

// ---------------------------------------------------------------------------
// The scope of the one chat panel.
//
// The console had four chat surfaces: a floating bubble on the investigation,
// host and hunt pages, and a panel on the Dashboard (owner, 2026-10-07: "Sometimes
// it is a collapsible bubble, sometimes it is a panel."). Now there is one panel,
// mounted once in the shell. A page says what it shows with useChatScope, and
// the panel opens on that scope. A page that says nothing is on the general
// scope, the one rolling thread per analyst.
//
// The threads themselves live on the server, one per scope, so a reload or a
// second tab reads the same conversation. The draft lives in sessionStorage
// under the scope key (lib/chatDraft.ts), so it survives a close and a reload.
// ---------------------------------------------------------------------------

export type ChatScopeKind = 'general' | 'investigation' | 'host' | 'lead' | 'hunt';

/** The object a thread is about. */
export interface ChatScope {
  kind: ChatScopeKind;
  /** The id the chat routes take: the investigation id, the host address, the
   *  lead id or the hunt id. Empty for the general scope. */
  id: string;
  /** The name the scope line shows: the rule, the host name, "Lead 18", the
   *  hunt objective. */
  name?: string | null;
}

export const GENERAL_SCOPE: ChatScope = { kind: 'general', id: '' };

/** One key per thread. It keys the draft, the stale-reply guard and the panel
 *  body, so a scope switch starts the next thread clean. */
export function scopeKey(s: ChatScope): string {
  return s.kind === 'general' ? 'general' : `${s.kind}:${s.id}`;
}

/** The words on the button that opens the panel on `kind`. */
export function askLabel(kind: ChatScopeKind): string {
  return kind === 'general' ? 'Ask soc-ai' : `Ask soc-ai about this ${kind}`;
}

/** What an investigation page lends the panel. The verdict and the cited ids
 *  change what the panel draws. The callbacks act on the page. */
export interface InvestigationChatHooks {
  /** The verdict on the page. A proposal of the same verdict offers no Apply. */
  verdict?: Investigation['verdict'];
  /** Document ids the investigation cites. An answer that names one links it. */
  linkIds?: string[];
  /** The messages the page already holds, shown until the thread read lands. */
  seed?: ChatMessage[];
  /** Called after the panel applied a proposed verdict. */
  onVerdictApplied?: () => void;
  /** Open the escalate confirm on the page. Absent when the page has none. */
  onEscalate?: () => void;
}

/** One page's claim on the panel. */
export interface PageChatScope {
  scope: ChatScope;
  investigation?: InvestigationChatHooks;
}

/** A registration as the provider holds it. */
export interface ChatRegistration {
  token: number;
  scope: ChatScope;
  verdict?: Investigation['verdict'];
  linkIds: string[];
  canEscalate: boolean;
  /** The page's latest callbacks and seed. Read at event time, never drawn. */
  hooks: MutableRefObject<InvestigationChatHooks | undefined>;
}

/** A question to send once the panel is on `key` and its thread read settled. */
export interface PendingAsk {
  text: string;
  key: string;
  n: number;
}

export interface ChatState {
  open: boolean;
  /** The page's registration, or null on a page with no object. */
  page: ChatRegistration | null;
  /** The scope the page offers: its object, or general. */
  pageScope: ChatScope;
  /** The scope the panel shows. */
  activeScope: ChatScope;
  /** The general scope is on. `general_chat_enabled` in /about turns it off. */
  generalEnabled: boolean;
  /** Whether `scope` can open. Only the general scope has a switch. */
  available: (scope: ChatScope) => boolean;
  /** Open the panel on the page scope, or on the general scope. `ask` sends
   *  one question once the thread is ready. */
  openChat: (opts?: { general?: boolean; ask?: string }) => void;
  closeChat: () => void;
  /** Show the general thread. The page keeps its scope for the way back. */
  showGeneral: () => void;
  /** Show the page's own thread again. */
  showPage: () => void;
  pendingAsk: PendingAsk | null;
  consumeAsk: (n: number) => void;
  register: (reg: Omit<ChatRegistration, 'token'>) => number;
  unregister: (token: number) => void;
}

const ChatCtx = createContext<ChatState | null>(null);

/** The open button carries this attribute. Focus falls back to it on close. */
export const ASK_BUTTON_ATTR = 'data-ask-soc-ai';

/** The shortcut that opens the panel. The shortcut sheet lists it. */
export const ASK_SHORTCUT = 'c';

/**
 * Holds the panel's state for the whole shell.
 *
 * `generalEnabled` overrides the /about read. The shell leaves it out and
 * passes `aboutReady` once the session is known, because /about is a
 * protected read. A test passes the flag.
 */
export function ChatProvider({
  children,
  aboutReady = false,
  generalEnabled: generalOverride,
}: {
  children: ReactNode;
  aboutReady?: boolean;
  generalEnabled?: boolean;
}) {
  const shell = useOptionalShell();
  const [open, setOpen] = useState(false);
  const [regs, setRegs] = useState<ChatRegistration[]>([]);
  const [onGeneral, setOnGeneral] = useState(false);
  const [pendingAsk, setPendingAsk] = useState<PendingAsk | null>(null);
  const [aboutFlag, setAboutFlag] = useState<boolean | null>(null);
  const tokenRef = useRef(0);
  const askRef = useRef(0);
  // Where the focus goes back to on close: the control that opened the panel.
  const returnFocusRef = useRef<HTMLElement | null>(null);

  // The general scope's switch, read the way the Dashboard read it: one GET,
  // and a failed read fails open, because the setting defaults on.
  useEffect(() => {
    if (generalOverride !== undefined || !aboutReady) return;
    let alive = true;
    getAbout()
      .then((a) => alive && setAboutFlag(a.general_chat_enabled !== false))
      .catch(() => alive && setAboutFlag(true));
    return () => {
      alive = false;
    };
  }, [aboutReady, generalOverride]);
  const generalEnabled = generalOverride ?? aboutFlag === true;

  const register = useCallback((reg: Omit<ChatRegistration, 'token'>) => {
    tokenRef.current += 1;
    const token = tokenRef.current;
    setRegs((rs) => [...rs, { ...reg, token }]);
    return token;
  }, []);
  const unregister = useCallback((token: number) => {
    setRegs((rs) => rs.filter((r) => r.token !== token));
  }, []);

  // The newest registration wins: a drawer over a page claims the panel while
  // it is open, and the page has it back when the drawer closes.
  const page = regs.length > 0 ? regs[regs.length - 1] : null;
  const pageScope = page?.scope ?? GENERAL_SCOPE;
  const pageKey = scopeKey(pageScope);
  const activeScope = onGeneral ? GENERAL_SCOPE : pageScope;

  const available = useCallback(
    (scope: ChatScope) => scope.kind !== 'general' || generalEnabled,
    [generalEnabled],
  );

  // The panel shows the object on screen. A move to another page puts it on
  // that page's scope, and the general switch starts over.
  useEffect(() => {
    setOnGeneral(false);
  }, [pageKey]);

  // Nothing to show: a page with no object while the general scope is off.
  useEffect(() => {
    if (open && !available(activeScope)) setOpen(false);
  }, [open, activeScope, available]);

  const openChat = useCallback(
    (opts?: { general?: boolean; ask?: string }) => {
      const target = opts?.general ? GENERAL_SCOPE : pageScope;
      if (!available(target)) return;
      const active = document.activeElement;
      if (active instanceof HTMLElement && !active.closest('[data-ask-panel]')) {
        returnFocusRef.current = active;
      }
      setOnGeneral(!!opts?.general && pageScope.kind !== 'general');
      setOpen(true);
      if (opts?.ask) {
        askRef.current += 1;
        setPendingAsk({ text: opts.ask, key: scopeKey(target), n: askRef.current });
      }
    },
    [pageScope, available],
  );

  const closeChat = useCallback(() => {
    setOpen(false);
    setPendingAsk(null);
    const back = returnFocusRef.current;
    returnFocusRef.current = null;
    if (back && back.isConnected) {
      back.focus();
      return;
    }
    const buttons = document.querySelectorAll<HTMLElement>(`[${ASK_BUTTON_ATTR}]`);
    buttons[buttons.length - 1]?.focus();
  }, []);

  const showGeneral = useCallback(() => {
    if (generalEnabled) setOnGeneral(true);
  }, [generalEnabled]);
  const showPage = useCallback(() => setOnGeneral(false), []);
  const consumeAsk = useCallback(
    (n: number) => setPendingAsk((p) => (p && p.n === n ? null : p)),
    [],
  );

  // The shortcut. It opens the panel from any page, and on an open panel it
  // moves the focus into the input. It never fires while the analyst types.
  const paletteOpen = shell?.paletteOpen ?? false;
  const shortcutsOpen = shell?.shortcutsOpen ?? false;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== ASK_SHORTCUT || e.metaKey || e.ctrlKey || e.altKey) return;
      if (paletteOpen || shortcutsOpen) return;
      if (isEditableTarget(e.target as HTMLElement | null)) return;
      if (open) {
        e.preventDefault();
        document.querySelector<HTMLElement>('[data-ask-panel] textarea')?.focus();
        return;
      }
      if (!available(pageScope)) return;
      e.preventDefault();
      openChat();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, paletteOpen, shortcutsOpen, pageScope, available, openChat]);

  const value = useMemo<ChatState>(
    () => ({
      open,
      page,
      pageScope,
      activeScope,
      generalEnabled,
      available,
      openChat,
      closeChat,
      showGeneral,
      showPage,
      pendingAsk,
      consumeAsk,
      register,
      unregister,
    }),
    [
      open,
      page,
      pageScope,
      activeScope,
      generalEnabled,
      available,
      openChat,
      closeChat,
      showGeneral,
      showPage,
      pendingAsk,
      consumeAsk,
      register,
      unregister,
    ],
  );

  return <ChatCtx.Provider value={value}>{children}</ChatCtx.Provider>;
}

/** The panel's state, or null outside the shell (a screen rendered alone). */
export function useChat(): ChatState | null {
  return useContext(ChatCtx);
}

/**
 * Claim the panel for the object this page shows, while the page is mounted.
 *
 * Pass null until the object is known. A screen rendered outside the shell has
 * no provider, and the call does nothing there.
 */
export function useChatScope(reg: PageChatScope | null): void {
  const ctx = useContext(ChatCtx);
  const register = ctx?.register;
  const unregister = ctx?.unregister;
  const hooks = useRef<InvestigationChatHooks | undefined>(reg?.investigation);
  // Declared first, so the registration below always holds this commit's
  // callbacks. The panel reads them at event time.
  useEffect(() => {
    hooks.current = reg?.investigation;
  });
  const kind = reg?.scope.kind;
  const id = reg?.scope.id;
  const name = reg?.scope.name ?? null;
  const verdict = reg?.investigation?.verdict;
  const links = (reg?.investigation?.linkIds ?? []).join(' ');
  const canEscalate = !!reg?.investigation?.onEscalate;
  useEffect(() => {
    if (!register || !unregister || !kind || id === undefined) return;
    const token = register({
      scope: { kind, id, name },
      verdict,
      linkIds: links ? links.split(' ') : [],
      canEscalate,
      hooks,
    });
    return () => unregister(token);
  }, [register, unregister, kind, id, name, verdict, links, canEscalate]);
}
