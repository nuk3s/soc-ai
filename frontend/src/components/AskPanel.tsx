import { MessageSquare, Triangle, X } from 'lucide-react';
import { type ReactNode, useEffect, useRef, useState } from 'react';
import { VerdictPill } from './Badges';
import { ChatThreadView } from './ChatDock';
import { huntProposalRow, useHuntLaunch } from './HuntProposalCard';
import { Panel, PanelHeader } from './Panel';
import { Spinner } from './States';
import {
  type ChatThread,
  type HuntChatThread,
  clearGeneralChat,
  clearHostChat,
  clearLeadChat,
  getChatThread,
  getGeneralChat,
  getHostChat,
  getHuntChat,
  getLeadChat,
  postChat,
  postGeneralChat,
  postHostChat,
  postHuntChat,
  postLeadChat,
  resolveInvestigation,
} from '../lib/api';
import {
  ASK_BUTTON_ATTR,
  ASK_SHORTCUT,
  type ChatRegistration,
  type ChatScope,
  type ChatScopeKind,
  type PendingAsk,
  askLabel,
  scopeKey,
  useChat,
} from '../lib/chatScope';
import { useChatReadiness } from '../lib/chatReadiness';
import type { ChatMessage, Investigation } from '../lib/types';
import { useChatThread } from '../lib/useChatThread';
import { useOptionalShell } from '../shell/ShellContext';

// ---------------------------------------------------------------------------
// Ask soc-ai: the console's one chat.
//
// A right-side panel that slides in over the page. It has one width and one
// header on every page, and one button in the top bar opens it. The panel is
// on the scope of the object the page shows (an investigation, a host, a lead
// or a hunt) and offers a switch to the general thread. Each scope keeps its
// own thread on the server, and its draft in the tab.
//
// The panel is not modal. The page under it stays live, because the inline
// Escalate opens the confirm on the page. A drawer can sit under the panel:
// the Alerts drawer opens it from its own header, because the drawer covers
// the top bar.
// ---------------------------------------------------------------------------

/** The width of the panel on every page. */
export const ASK_PANEL_WIDTH = 'w-[440px]';

/** The general scope's openers. The Dashboard card shows the same three. */
export const GENERAL_STARTERS = [
  'What datasets do I have?',
  'What is my noisiest rule this week?',
  'What did overnight look like?',
];

const HOST_STARTERS = [
  'What is this host?',
  'Who has it talked to today?',
  'Any alerts involving it this week?',
];

const LEAD_STARTERS = [
  'Why did this lead form?',
  'What else did these entities do this week?',
  'Is this pattern normal here?',
];

const HUNT_STARTERS = [
  'Which host was worst?',
  'What did this hunt not check?',
  'What should I check next?',
];

/** Starter questions that fit the verdict. "Why not a false positive?" on a
 *  false positive verdict asks the chat to argue against itself (P16). */
export function investigationStarters(verdict: Investigation['verdict'] | undefined): string[] {
  const first =
    verdict === 'false_positive'
      ? 'Why not a true positive?'
      : verdict === 'true_positive'
        ? 'Why not a false positive?'
        : 'What evidence would settle this verdict?';
  return [first, 'What evidence supports this verdict?', 'What should I check next?'];
}

/** The scope line's words for each kind. */
const SCOPE_TITLE: Record<ChatScopeKind, string> = {
  general: 'General',
  investigation: 'This investigation',
  host: 'This host',
  lead: 'This lead',
  hunt: 'This hunt',
};

// Normalise the hunt thread's wire shape to the shared hook's ChatThread. The
// only difference is HuntChatMessage.tools is `string | null` where
// ChatMessage.tools is `string | undefined`, so drop the null.
function toChatThread(t: HuntChatThread): ChatThread {
  return {
    messages: t.messages.map((m) => ({ role: m.role, text: m.text, tools: m.tools ?? undefined })),
    pending: t.pending,
    progress_tools: t.progress_tools,
  };
}

/** How one scope talks to the server, and what its empty thread says. */
interface ScopeAdapter {
  fetch: () => Promise<ChatThread>;
  send: (text: string) => Promise<ChatThread>;
  /** The scopes with a stored per-scope thread to discard. */
  clear?: () => Promise<ChatThread>;
  placeholder: string;
  hint: string;
  starters: string[];
}

function adapterFor(scope: ChatScope, verdict: Investigation['verdict'] | undefined): ScopeAdapter {
  const id = scope.id;
  switch (scope.kind) {
    case 'investigation': {
      const starters = investigationStarters(verdict);
      return {
        fetch: () => getChatThread(id),
        send: (text) => postChat(id, text),
        placeholder: `Ask a follow-up. Example: ${starters[0].toLowerCase()}`,
        hint: 'No messages yet. Ask a follow-up about this investigation.',
        starters,
      };
    }
    case 'host':
      return {
        fetch: () => getHostChat(id),
        send: (text) => postHostChat(id, text),
        clear: () => clearHostChat(id),
        placeholder: 'Ask about this host. Example: who has it talked to today?',
        hint:
          'Ask about this host. soc-ai answers from its dossier and its live telemetry. ' +
          'A question that needs a sweep comes back as a hunt for you to confirm.',
        starters: HOST_STARTERS,
      };
    case 'lead':
      return {
        fetch: () => getLeadChat(id),
        send: (text) => postLeadChat(id, text),
        clear: () => clearLeadChat(id),
        placeholder: 'Ask about this lead. Example: why did this lead form?',
        hint:
          'Ask about this lead. soc-ai answers from its observations and the live telemetry. ' +
          'A question that needs a sweep comes back as a hunt for you to confirm.',
        starters: LEAD_STARTERS,
      };
    case 'hunt':
      return {
        fetch: () => getHuntChat(id).then(toChatThread),
        send: (text) => postHuntChat(id, text).then(toChatThread),
        placeholder: 'Ask a follow-up question. Example: which host was worst?',
        hint:
          'Ask a follow-up question about this hunt. soc-ai answers from the evidence of this hunt. ' +
          'The chat cannot change the result.',
        starters: HUNT_STARTERS,
      };
    default:
      return {
        fetch: () => getGeneralChat(),
        send: (text) => postGeneralChat(text),
        clear: () => clearGeneralChat(),
        placeholder: 'Ask about your grid. Example: what datasets do I have?',
        hint:
          'Ask about your grid. soc-ai answers here. ' +
          'A question that needs a sweep comes back as a hunt for you to confirm.',
        starters: GENERAL_STARTERS,
      };
  }
}

/**
 * The one button that opens the panel. The top bar holds it on every page. A
 * drawer that covers the top bar holds a second copy in its header.
 */
export function AskSocAiButton() {
  const chat = useChat();
  if (!chat || !chat.available(chat.pageScope)) return null;
  const label = askLabel(chat.pageScope.kind);
  const onPage = scopeKey(chat.activeScope) === scopeKey(chat.pageScope);
  return (
    <button
      type="button"
      {...{ [ASK_BUTTON_ATTR]: '' }}
      aria-expanded={chat.open && onPage}
      aria-keyshortcuts={ASK_SHORTCUT}
      title={`${label}. The shortcut is ${ASK_SHORTCUT.toUpperCase()}.`}
      onClick={() => (chat.open && onPage ? chat.closeChat() : chat.openChat())}
      className="flex flex-none items-center gap-1.5 rounded-control border border-accent-deep bg-[rgba(75,139,245,.14)] px-[11px] py-1.5 text-[12.5px] font-semibold text-[#cfe0ff] hover:border-accent hover:bg-[rgba(75,139,245,.22)]"
    >
      <MessageSquare size={14} />
      <span className="whitespace-nowrap">{label}</span>
    </button>
  );
}

const FOCUSABLE =
  'a[href],button:not([disabled]),textarea:not([disabled]),input:not([disabled]),select:not([disabled]),[tabindex]:not([tabindex="-1"])';

/**
 * The panel itself, mounted once in the shell. Nothing renders while it is
 * closed, so a closed panel costs no request.
 */
export function AskPanel() {
  const chat = useChat();
  if (!chat || !chat.open) return null;
  return <OpenPanel />;
}

function OpenPanel() {
  const chat = useChat()!;
  const shell = useOptionalShell();
  const panelRef = useRef<HTMLElement>(null);
  // The modal count when the panel opened. A modal opened after the panel is
  // the newer layer, and Escape is its key.
  const baseModals = useRef(shell?.modalCount ?? 0);
  const modalCount = shell?.modalCount ?? 0;
  const paletteOpen = shell?.paletteOpen ?? false;
  const shortcutsOpen = shell?.shortcutsOpen ?? false;
  const { closeChat } = chat;

  // Capture phase, so a drawer under the panel does not also take the key.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const node = panelRef.current;
      if (!node) return;
      const active = document.activeElement;
      const inside = node.contains(active);
      if (e.key === 'Escape') {
        if (paletteOpen || shortcutsOpen || modalCount > baseModals.current) return;
        // Focus on the page belongs to the page: an open menu there takes
        // its own Escape. Focus in the panel, or nowhere, closes the panel.
        if (!inside && active && active !== document.body) return;
        e.stopPropagation();
        closeChat();
        return;
      }
      if (e.key === 'Tab' && inside && modalCount > 0) {
        // A modal drawer under the panel pulls Tab back into itself. Keep
        // the focus in the panel while it is there.
        const items = Array.from(node.querySelectorAll<HTMLElement>(FOCUSABLE));
        if (items.length === 0) return;
        e.stopPropagation();
        const first = items[0];
        const last = items[items.length - 1];
        if (e.shiftKey && active === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && active === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [closeChat, modalCount, paletteOpen, shortcutsOpen]);

  const scope = chat.activeScope;
  const reg = scope.kind !== 'general' ? chat.page : null;
  return (
    <aside
      ref={panelRef}
      data-ask-panel
      role="dialog"
      aria-modal="false"
      aria-labelledby="ask-panel-title"
      // `backwards`, not `both`: a transform kept after the slide-in would make
      // the panel the containing block of every fixed child, and the document
      // drawer a cited event opens would then draw inside the panel.
      className={`fixed bottom-0 right-0 top-0 z-[45] flex ${ASK_PANEL_WIDTH} max-w-[100vw] animate-[slideIn_.26s_cubic-bezier(.2,.8,.2,1)_backwards] flex-col border-l border-border-2 bg-surface-1 shadow-drawer`}
    >
      <ScopedChat
        key={scopeKey(scope)}
        scope={scope}
        reg={reg && scopeKey(reg.scope) === scopeKey(scope) ? reg : null}
        pendingAsk={chat.pendingAsk}
      />
    </aside>
  );
}

/** Header, scope line and thread for one scope. Keyed on the scope, so a
 *  switch starts the next thread clean and moves the focus to its input. */
function ScopedChat({
  scope,
  reg,
  pendingAsk,
}: {
  scope: ChatScope;
  reg: ChatRegistration | null;
  pendingAsk: PendingAsk | null;
}) {
  const ctx = useChat()!;
  const verdict = reg?.verdict;
  const adapter = adapterFor(scope, verdict);
  const key = scopeKey(scope);
  const chat = useChatThread({
    subject: key,
    // The scope's id rides in the adapter. The key is the hook's identity.
    fetchThread: () => adapter.fetch(),
    sendMessage: (_subject, text) => adapter.send(text),
    seed: reg?.hooks.current?.seed,
  });
  const launch = useHuntLaunch();
  const [clearError, setClearError] = useState<string | null>(null);
  // A dead model gateway blocks the send, and the panel says why. A dead or
  // slow grid gets a note (H1-D13).
  const readiness = useChatReadiness();
  const blocked = readiness.blocked;

  // A question asked from outside the panel: "Resolve in chat", a Dashboard
  // starter. It waits for the thread read, so a turn already running gets the
  // text in the box and no 409.
  const { consumeAsk } = ctx;
  useEffect(() => {
    if (!pendingAsk || pendingAsk.key !== key || !chat.synced) return;
    consumeAsk(pendingAsk.n);
    if (chat.pending || blocked) chat.setDraft(pendingAsk.text);
    else chat.send(pendingAsk.text);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pendingAsk, key, chat.synced]);

  const ask = (q: string) => (chat.pending || blocked ? chat.setDraft(q) : chat.send(q));

  const clear = adapter.clear;
  const clearThread = () => {
    if (!clear) return;
    setClearError(null);
    clear()
      // The DELETE returns the emptied thread, but the hook owns the thread
      // state and exposes only a re-read.
      .then(() => chat.refresh())
      .catch(() => setClearError('Could not clear the conversation. Try again.'));
  };

  const count = chat.messages.length;
  const pageKind = ctx.pageScope.kind;
  const renderSpecial =
    scope.kind === 'investigation'
      ? (m: ChatMessage, i: number) =>
          m.role === 'user' || m.kind !== 'verdict_proposal' ? null : (
          <VerdictProposalRow
            key={i}
            m={m}
            i={i}
            invId={scope.id}
            verdict={verdict}
            canEscalate={!!reg?.canEscalate}
            onEscalate={() => reg?.hooks.current?.onEscalate?.()}
            onResolved={() =>
              chat
                .refresh()
                .catch(() => {})
                .finally(() => reg?.hooks.current?.onVerdictApplied?.())
            }
          />
        )
      : scope.kind === 'hunt'
        ? undefined
        : (m: ChatMessage, i: number) => huntProposalRow(m, i, launch);

  return (
    <>
      <div className="flex flex-none items-center gap-2.5 border-b border-border px-4 py-[13px]">
        <span className="flex text-accent">
          <MessageSquare size={15} />
        </span>
        <h2 id="ask-panel-title" className="text-[14px] font-semibold text-text">
          Ask soc-ai
        </h2>
        {count > 0 && (
          <span className="font-mono text-[11px] text-accent">
            {count} msg{count !== 1 ? 's' : ''}
          </span>
        )}
        <div className="flex-1" />
        {clear && count > 0 && (
          <button
            type="button"
            onClick={clearThread}
            className="text-[11px] text-faint transition-colors hover:text-dim"
          >
            Clear conversation
          </button>
        )}
        <button
          type="button"
          onClick={ctx.closeChat}
          aria-label="Close Ask soc-ai"
          title="Close. The shortcut is Esc."
          className="flex text-dim hover:text-text"
        >
          <X size={16} />
        </button>
      </div>
      <div
        data-testid="ask-scope"
        className="flex flex-none items-center gap-2 border-b border-border-2 bg-surface-2 px-4 py-2 text-[12px]"
      >
        <span className="text-faint">Scope</span>
        <span data-testid="ask-scope-title" className="flex-none font-semibold text-text-2">
          {SCOPE_TITLE[scope.kind]}
        </span>
        {scope.kind !== 'general' && scope.name && (
          <span
            data-testid="ask-scope-name"
            className="min-w-0 break-words font-mono text-[11.5px] text-dim"
            title={scope.name}
          >
            {scope.name}
          </span>
        )}
        <div className="flex-1" />
        {scope.kind !== 'general' && ctx.generalEnabled && (
          <button
            type="button"
            onClick={ctx.showGeneral}
            className="flex-none text-[11.5px] font-semibold text-accent hover:underline"
          >
            Switch to general
          </button>
        )}
        {scope.kind === 'general' && pageKind !== 'general' && (
          <button
            type="button"
            onClick={ctx.showPage}
            className="flex-none text-[11.5px] font-semibold text-accent hover:underline"
          >
            Back to this {pageKind}
          </button>
        )}
      </div>
      <ChatThreadView
        label={`Ask soc-ai, ${SCOPE_TITLE[scope.kind].toLowerCase()}`}
        placeholder={adapter.placeholder}
        autoFocus
        emptyHint={
          <div className="flex flex-col gap-2.5 py-1 text-[12.5px]">
            <div className="flex items-start gap-1.5 text-faint">
              <span className="mt-[3px] flex flex-none">
                <MessageSquare size={13} />
              </span>
              <span>{adapter.hint}</span>
            </div>
            <StarterChips questions={adapter.starters} onAsk={ask} disabledReason={blocked} />
          </div>
        }
        messages={chat.messages}
        pending={chat.pending}
        progressTools={chat.progressTools}
        draft={chat.draft}
        onDraft={chat.setDraft}
        onSend={chat.send}
        linkIds={scope.kind === 'investigation' ? (reg?.linkIds ?? []) : undefined}
        linkEntities
        blockedReason={blocked}
        stateNote={readiness.note}
        renderSpecial={renderSpecial}
      />
      {clearError && (
        <div className="flex-none px-4 pb-2 text-right text-[11px] text-danger">{clearError}</div>
      )}
    </>
  );
}

/** The question chips. A click asks the question outright. With a
 *  `disabledReason` the chips are off, and the reason is their title. */
function StarterChips({
  questions,
  onAsk,
  disabledReason = null,
}: {
  questions: string[];
  onAsk: (q: string) => void;
  disabledReason?: string | null;
}) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {questions.map((q) => (
        <button
          key={q}
          type="button"
          onClick={() => onAsk(q)}
          disabled={!!disabledReason}
          title={disabledReason ?? undefined}
          className="rounded-pill border border-border-input bg-surface-3 px-2.5 py-1 text-left text-[12px] text-text-2 hover:border-accent hover:text-text disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:border-border-input disabled:hover:text-text-2"
        >
          {q}
        </button>
      ))}
    </div>
  );
}

/**
 * A verdict the chat proposed for this investigation, with its Apply control.
 *
 * The card REPLACES its row: the proposal's rationale is the model's answer
 * restated, so the prose as well would say it twice. The hunt card composes
 * the bubble instead. There the answer and the proposed sweep are two halves
 * of one reply.
 */
function VerdictProposalRow({
  m,
  i,
  invId,
  verdict,
  canEscalate,
  onEscalate,
  onResolved,
}: {
  m: ChatMessage;
  i: number;
  invId: string;
  verdict: Investigation['verdict'] | undefined;
  canEscalate: boolean;
  onEscalate: () => void;
  onResolved: () => void;
}): ReactNode {
  const [applying, setApplying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The caller passes a verdict proposal only. The check narrows the type.
  if (m.kind !== 'verdict_proposal' || !m.proposal) return null;
  const p = m.proposal;

  const apply = () => {
    if (m.messageId == null || !m.token || applying) return;
    setApplying(true);
    setError(null);
    resolveInvestigation(invId, m.messageId, m.token)
      .then(onResolved)
      .catch((err: unknown) =>
        setError(err instanceof Error ? err.message : 'soc-ai could not apply the verdict. Try again.'),
      )
      .finally(() => setApplying(false));
  };

  return (
    <div
      key={i}
      data-testid="chat-verdict-proposal"
      className="max-w-[88%] min-w-0 self-start break-words rounded-card border px-3 py-2.5"
      style={{ borderColor: 'rgba(75,139,245,.35)', background: 'rgba(75,139,245,.06)' }}
    >
      <div className="mb-1 flex items-center gap-2 text-[12px] font-semibold text-text-2">
        Proposed verdict
        <VerdictPill verdict={p.verdict} conf={p.confidence} />
      </div>
      <div className="mb-2 text-[13px] text-text-2">{p.rationale}</div>
      {p.verdict === verdict && !m.applied ? (
        // The proposal is the verdict the page already has (K4).
        <div data-testid="proposal-current" className="text-[12px] text-dim">
          This is the current verdict.
        </div>
      ) : m.validation === 'pass' && !m.applied ? (
        <>
          <button
            type="button"
            disabled={applying}
            onClick={apply}
            className="flex items-center gap-1.5 rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold text-[#cfe0ff] disabled:opacity-60"
            style={{ background: 'rgba(75,139,245,.14)', borderColor: 'rgba(75,139,245,.4)' }}
          >
            {applying && <Spinner size={12} />}
            {applying ? 'Applying' : 'Apply verdict'}
          </button>
          {error && <div className="mt-1.5 text-[11.5px] text-danger">{error}</div>}
        </>
      ) : m.applied ? (
        <div className="text-[12px] font-semibold text-success">✓ Applied</div>
      ) : (
        <div className="text-[12px] text-warn">Not evidence-backed{m.objection ? `. ${m.objection}` : ''}</div>
      )}
      {/* The action the answer points at, inline (C4). A true positive goes to
          a case. The button opens the confirm on the page. */}
      {canEscalate &&
        (p.verdict === 'true_positive' ||
          (p.recommended_actions ?? []).some((a) => a.tool_name === 'escalate_to_case')) && (
          <button
            type="button"
            onClick={onEscalate}
            data-testid="chat-escalate"
            className="mt-2 flex items-center gap-1.5 rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold"
            style={{ borderColor: 'rgba(240,68,56,.4)', background: 'rgba(240,68,56,.10)', color: '#fca5a5' }}
          >
            <Triangle size={13} /> Escalate to case
          </button>
        )}
    </div>
  );
}

/**
 * The Dashboard's Ask soc-ai card. It holds the panel's place in a saved
 * layout (`assistant`) and opens the panel on the general scope. A starter
 * asks its question on click.
 */
export function AskSocAiCard() {
  const chat = useChat();
  const readiness = useChatReadiness();
  if (!chat || !chat.generalEnabled) return null;
  return (
    <div data-testid="ask-card">
      <Panel>
        <PanelHeader
          icon={<MessageSquare size={15} />}
          title="Ask soc-ai"
          right={
            <button
              type="button"
              onClick={() => chat.openChat({ general: true })}
              className="text-[12px] font-semibold text-accent hover:underline"
            >
              Open
            </button>
          }
          className="py-[11px]"
        />
        <div className="flex flex-col gap-2.5 px-[15px] pb-[14px] pt-1 text-[12.5px]">
          <div className="text-faint">
            Ask about your grid. The answer opens in the Ask soc-ai panel.
          </div>
          {(readiness.blocked || readiness.note) && (
            <div
              data-testid="ask-card-state"
              role="status"
              className={`leading-[1.45] ${readiness.blocked ? 'text-warn' : 'text-faint'}`}
            >
              {[readiness.blocked, readiness.note].filter(Boolean).join(' ')}
            </div>
          )}
          <StarterChips
            questions={GENERAL_STARTERS}
            onAsk={(q) => chat.openChat({ general: true, ask: q })}
            disabledReason={readiness.blocked}
          />
        </div>
      </Panel>
    </div>
  );
}
