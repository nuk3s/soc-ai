import { MessageSquare, Send, Wrench, X } from 'lucide-react';
import { type ReactNode, useEffect, useRef, useState } from 'react';
import { Markdown } from './Markdown';
import { Panel, PanelHeader } from './Panel';

// ---------------------------------------------------------------------------
// Shared chat rendering, used by the investigation chat (Investigation.tsx),
// the hunt chat (HuntDetail.tsx) and the Dashboard assistant
// (GeneralChatPanel.tsx) so the surfaces can't drift visually. The THREAD state
// (loading, polling while the assistant works, posting a turn) lives in
// useChatThread or, for the hunt chat, still in the screen.
// ---------------------------------------------------------------------------

/** The message shape the shared renderer needs; screens may carry richer types. */
export interface ChatDockMessage {
  role: 'user' | 'assistant';
  text?: string | null;
  tools?: string | null;
}

interface ChatPanelShellProps<M extends ChatDockMessage> {
  title: string;
  /** Small mono label in the header, e.g. "scoped to this investigation". */
  scopeLabel: string;
  placeholder: string;
  messages: M[];
  pending: boolean;
  /** Tools the in-flight turn has called so far (oldest first). */
  progressTools?: string[];
  draft: string;
  onDraft: (v: string) => void;
  onSend: () => void;
  /** Stretch to the parent's height (dock mode) instead of a fixed band. */
  fill?: boolean;
  onClose?: () => void;
  /** Screen-specific size classes for the scrolling message list. */
  listSizeClass: string;
  /** Optional hint rendered when the thread is empty and idle. */
  emptyHint?: ReactNode;
  /** Screen-specific header action (e.g. "Clear conversation"), placed with the
   *  msg count and scope label rather than orphaned below the panel. */
  headerRight?: ReactNode;
  /**
   * Screen-specific message kinds (e.g. the investigation chat's verdict
   * proposals): return a node (carrying its own key) to replace the default
   * bubble for that message, or null to fall through to it.
   *
   * It replaces the WHOLE row, so a card that should appear ALONGSIDE the
   * agent's prose composes {@link AssistantBubble} itself rather than
   * re-implementing it — the Dashboard chat's hunt proposal rides on the same
   * row as the answer, and dropping that prose would throw away the half of the
   * reply the analyst judges the proposal by.
   */
  renderSpecial?: (m: M, i: number) => ReactNode | null;
}

/**
 * Chat panel chrome: header, scrolling bubble list (with autoscroll and a
 * fade-in on messages that arrive after mount), typing indicator, input row.
 */
// Tool name -> what the analyst would call it. Unknown tools fall back to a
// de-prefixed, de-underscored form so a new tool still reads sensibly.
const TOOL_LABELS: Record<string, string> = {
  t_query_events_oql: 'Querying events',
  t_query_zeek_logs: 'Reading Zeek logs',
  t_enrich_ip: 'Enriching IP',
  t_enrich_domain: 'Enriching domain',
  t_enrich_hash: 'Enriching hash',
  t_host_summary: 'Profiling host',
  t_origin_chain: 'Checking who was driving the host',
  t_prevalence: 'Checking prevalence',
  t_rule_prevalence: 'Checking rule prevalence',
  t_get_pcap: 'Fetching PCAP',
  t_decode_payload: 'Decoding payload',
  t_get_rule_content: 'Reading the rule',
  t_query_cases: 'Searching cases',
  t_query_detections: 'Searching detections',
  t_lookup_runbook: 'Consulting runbooks',
  t_get_playbooks: 'Reading the playbook',
  t_web_search: 'Searching the web',
  t_crawl_page: 'Reading a page',
  propose_verdict: 'Drafting a verdict',
};

export function toolLabel(name: string): string {
  return (
    TOOL_LABELS[name] ??
    name.replace(/^t_/, '').replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase())
  );
}

/**
 * What the agent said: the markdown bubble plus the tools footer under it.
 *
 * Exported because a caller that decorates a row (a proposal card) still has to
 * render the prose, and a private copy is exactly how this project's chat
 * surfaces drift — the hunt chat forked its manager and missed every feature
 * shipped after. Emits a fragment, so the CALLER owns the row wrapper (width,
 * self-alignment, fade-in) and supplies the vertical rhythm as `gap-1.5`.
 *
 * Renders nothing for an empty turn rather than an empty bubble: a proposal row
 * whose agent proposed without prose should show the card alone.
 */
export function AssistantBubble({ text, tools }: { text?: string | null; tools?: string | null }) {
  return (
    <>
      {text ? (
        <div
          className="overflow-hidden break-words rounded-[12px_12px_12px_3px] border border-border-2 bg-surface-3 px-[13px] py-2.5 text-[13px] leading-[1.55] text-text-2 [&_pre]:max-w-full [&_pre]:overflow-x-auto"
          style={{ textWrap: 'pretty' }}
        >
          <Markdown>{text}</Markdown>
        </div>
      ) : null}
      {tools ? (
        <div className="flex items-center gap-1.5 font-mono text-[10.5px] text-faint">
          <span className="text-accent">
            <Wrench size={11} />
          </span>
          tools · {tools}
        </div>
      ) : null}
    </>
  );
}

export function ChatPanelShell<M extends ChatDockMessage>({
  title,
  scopeLabel,
  placeholder,
  messages,
  pending,
  progressTools,
  draft,
  onDraft,
  onSend,
  fill,
  onClose,
  listSizeClass,
  emptyHint,
  headerRight,
  renderSpecial,
}: ChatPanelShellProps<M>) {
  const listRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const didMountRef = useRef(false);
  // Tracks the highest message index seen at mount-time so subsequent new
  // messages (added while the panel is open) can receive a fade-in.
  const seedLengthRef = useRef(-1);

  // autoscroll on new messages / typing indicator (skip the initial mount)
  useEffect(() => {
    if (!didMountRef.current) {
      didMountRef.current = true;
      seedLengthRef.current = messages.length;
      return;
    }
    const el = listRef.current;
    if (el) el.scrollTo({ top: el.scrollHeight, behavior: 'smooth' });
  }, [messages.length, pending]);

  // Grow the draft box with its content (up to a cap) so a long question stays
  // fully visible instead of scrolling off a single line.
  useEffect(() => {
    const el = inputRef.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${Math.min(el.scrollHeight, 120)}px`;
  }, [draft]);

  return (
    <Panel className={`flex min-h-0 flex-col${fill ? ' h-full' : ''}`}>
      <PanelHeader
        icon={<MessageSquare size={15} />}
        title={title}
        right={
          <div className="flex items-center gap-2.5">
            {messages.length > 0 && (
              <span className="font-mono text-[11px] text-accent">
                {messages.length} msg{messages.length !== 1 ? 's' : ''}
              </span>
            )}
            <div className="font-mono text-[11px] text-faint">{scopeLabel}</div>
            {headerRight}
            {onClose && (
              <button
                onClick={onClose}
                aria-label="Close chat"
                className="flex text-dim hover:text-text"
              >
                <X size={15} />
              </button>
            )}
          </div>
        }
        className="py-[11px]"
      />
      <div ref={listRef} className={`flex flex-col gap-3 overflow-y-auto p-[15px] ${listSizeClass}`}>
        {emptyHint != null && messages.length === 0 && !pending && emptyHint}
        {messages.map((m, i) => {
          // Messages that arrived after the panel mounted get a subtle fade-in.
          // History / seed messages (present at mount) render immediately.
          const isNew = i >= seedLengthRef.current;

          const special = renderSpecial?.(m, i);
          if (special != null) return special;

          return m.role === 'user' ? (
            <div
              key={i}
              className="max-w-[82%] min-w-0 self-end break-words rounded-[12px_12px_3px_12px] border border-accent-deep bg-[#1d3a6b] px-[13px] py-[9px] text-[13px] leading-[1.5]"
            >
              {m.text}
            </div>
          ) : (
            <div
              key={i}
              className={`flex min-w-0 max-w-[88%] flex-col gap-1.5 self-start${isNew ? ' animate-fadeUp' : ''}`}
            >
              <AssistantBubble text={m.text} tools={m.tools} />
            </div>
          );
        })}
        {pending && (
          <div className="flex flex-col items-start gap-1 self-start">
            <div className="flex items-center gap-1 rounded-[12px_12px_12px_3px] border border-border-2 bg-surface-3 px-3.5 py-[11px]">
              <span className="h-1.5 w-1.5 animate-blink rounded-full bg-faint" />
              <span className="h-1.5 w-1.5 animate-blink rounded-full bg-faint" style={{ animationDelay: '.2s' }} />
              <span className="h-1.5 w-1.5 animate-blink rounded-full bg-faint" style={{ animationDelay: '.4s' }} />
            </div>
            {/* What the agent is actually DOING. A long multi-tool turn used to
                look identical to a hung one (dogfood 2026-08-06). */}
            {progressTools != null && progressTools.length > 0 && (
              <span className="pl-1 text-[11px] text-faint">
                {toolLabel(progressTools[progressTools.length - 1])}
                {progressTools.length > 1 && ` · ${progressTools.length} steps`}
              </span>
            )}
          </div>
        )}
      </div>
      <div className="flex items-end gap-[9px] border-t border-border px-[13px] py-[11px]">
        <textarea
          ref={inputRef}
          rows={1}
          value={draft}
          onChange={(e) => onDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              onSend();
            }
          }}
          placeholder={placeholder}
          className="max-h-[120px] flex-1 resize-none overflow-y-auto rounded-control border border-border-input bg-bg px-3 py-[9px] text-[13px] leading-[1.45] text-text outline-none focus:border-accent"
        />
        <button
          onClick={onSend}
          aria-label="Send"
          className="flex h-9 w-[38px] flex-none items-center justify-center rounded-control bg-accent text-white hover:bg-accent-deep"
        >
          <Send size={16} />
        </button>
      </div>
    </Panel>
  );
}

/**
 * Floating "Chat about this" dock: a launcher pinned bottom-right of the
 * viewport that opens the chat as a docked overlay panel. Costs no layout
 * space and stays reachable however far the evidence has been scrolled.
 * `children` renders the opened panel and receives a close callback.
 */
export function ChatDockShell({
  label,
  children,
}: {
  label: ReactNode;
  children: (close: () => void) => ReactNode;
}) {
  const [open, setOpen] = useState(false);
  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="fixed bottom-6 right-6 z-40 flex items-center gap-2 rounded-pill border border-accent-deep bg-accent px-[18px] py-3 text-[13px] font-semibold text-white shadow-[0_12px_34px_rgba(75,139,245,.42)] transition-transform hover:-translate-y-0.5 hover:bg-accent-deep"
      >
        <MessageSquare size={16} />
        {label}
      </button>
    );
  }
  return (
    <div className="fixed bottom-6 right-6 z-40 h-[560px] max-h-[calc(100vh-96px)] w-[400px] max-w-[calc(100vw-32px)] animate-fadeUp drop-shadow-[0_24px_70px_rgba(0,0,0,.6)]">
      {children(() => setOpen(false))}
    </div>
  );
}
