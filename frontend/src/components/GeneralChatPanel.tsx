import { MessageSquare } from 'lucide-react';
import { useState } from 'react';
import { ChatPanelShell } from './ChatDock';
import { huntProposalRow, useHuntLaunch } from './HuntProposalCard';
import { clearGeneralChat, getGeneralChat, postGeneralChat } from '../lib/api';
import { useChatThread } from '../lib/useChatThread';

// ---------------------------------------------------------------------------
// The Dashboard assistant.
//
// The slot used to hold an Ask box that prefilled the Hunt Console's objective
// and navigated — so "what datasets do I have?" became a multi-minute
// background job producing a formal report. Most questions asked at a launcher
// screen deserve an ANSWER at investigation-chat latency; a sweep is the
// exception, and the agent PROPOSES it rather than starting it.
//
// Transport comes from useChatThread and chrome from ChatPanelShell +
// AssistantBubble, all shared with the investigation chat. That is not
// tidiness: the hunt chat forked both and consequently missed live tool
// progress and the grounding loop. What is genuinely local to this surface is
// below — the thread has no subject id, and the proposal card starts a hunt
// instead of applying a verdict.
// ---------------------------------------------------------------------------

/**
 * The hook's subject: identity for the stale-response guard and key for the
 * persisted draft. A constant, because the thread is keyed on the CALLER
 * server-side — there is one rolling thread per analyst and it never swaps
 * under the panel.
 */
const THREAD_SUBJECT = 'dashboard-general';

/** Openers that show the surface's range; clicking one fills the box, so the
 *  analyst edits a question rather than facing a blank prompt. */
const STARTERS = [
  'What datasets do I have?',
  'What is my noisiest rule this week?',
  'What did overnight look like?',
];

/**
 * Ask soc-ai — the Dashboard's persistent, per-analyst chat.
 *
 * Renders nothing of its own when the thread is empty beyond a hint: idle cost
 * is one GET on mount, because the poll inside useChatThread re-arms only while
 * a turn is pending.
 */
export function GeneralChatPanel() {
  const chat = useChatThread({
    subject: THREAD_SUBJECT,
    // These endpoints take no id — the backend derives the thread from the
    // caller — so they ignore the subject the hook passes them.
    fetchThread: getGeneralChat,
    sendMessage: (_subject, text) => postGeneralChat(text),
  });

  // The proposal-card launch flow (which card is mid-start, per-card errors)
  // is shared with the host page chat — see HuntProposalCard.
  const launch = useHuntLaunch();
  const [clearError, setClearError] = useState<string | null>(null);

  /**
   * Start over. One rolling thread per analyst means it is otherwise permanent
   * — and its history is what the NEXT turn's prompt carries, so a stale
   * conversation is a cost and a context problem, not just clutter.
   */
  const clearThread = () => {
    setClearError(null);
    clearGeneralChat()
      // The DELETE already returns the emptied thread, but the hook owns the
      // thread state and exposes only a re-read. One extra GET on a rare,
      // deliberate action beats a second path that can write that state.
      .then(() => chat.refresh())
      .catch(() => setClearError('Could not clear the conversation — please try again.'));
  };

  return (
    <div>
      <ChatPanelShell
        title="Ask soc-ai"
        scopeLabel="your environment"
        placeholder="Ask about your environment… e.g. what datasets do I have?"
        // No min-height: an untouched assistant must not take a screenful of the
        // landing page before it has said anything.
        listSizeClass="max-h-[360px]"
        emptyHint={
          <div className="flex flex-col gap-2.5 py-1 text-[12.5px]">
            <div className="flex items-center gap-1.5 text-faint">
              <MessageSquare size={13} />
              Ask about your grid — answered here. Questions that need a sweep come back as a hunt to
              confirm.
            </div>
            <div className="flex flex-wrap gap-1.5">
              {STARTERS.map((q) => (
                <button
                  key={q}
                  type="button"
                  onClick={() => chat.setDraft(q)}
                  className="rounded-pill border border-border-input bg-surface-3 px-2.5 py-1 text-[12px] text-text-2 hover:border-accent hover:text-text"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        }
        messages={chat.messages}
        pending={chat.pending}
        progressTools={chat.progressTools}
        draft={chat.draft}
        onDraft={chat.setDraft}
        onSend={chat.send}
        // Starting over. Deliberately understated: this is a reset, not a thread
        // list — the Dashboard is a launcher screen, and chat history IA is the
        // scope trap this design named. Only once there IS a conversation.
        headerRight={
          chat.messages.length > 0 ? (
            <button
              type="button"
              onClick={clearThread}
              className="text-[11px] text-faint transition-colors hover:text-dim"
            >
              Clear conversation
            </button>
          ) : null
        }
        renderSpecial={(m, i) => huntProposalRow(m, i, launch)}
      />
      {/* A failed clear stays under the panel: the header has room for the
          control, not for a sentence explaining why it didn't work. */}
      {clearError && (
        <div className="mt-1.5 flex justify-end text-[11px] text-danger">{clearError}</div>
      )}
    </div>
  );
}
