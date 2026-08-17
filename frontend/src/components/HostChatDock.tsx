import { MessageSquare } from 'lucide-react';
import { useState } from 'react';
import { ChatDockShell, ChatPanelShell } from './ChatDock';
import { huntProposalRow, useHuntLaunch } from './HuntProposalCard';
import { clearHostChat, getHostChat, postHostChat } from '../lib/api';
import { useChatThread } from '../lib/useChatThread';

// ---------------------------------------------------------------------------
// "Chat about this host": the floating bubble on /hosts/:ip, mounted exactly
// the way Investigation.tsx mounts its dock — a bottom-right launcher that
// costs no layout space, opening the scoped chat as a docked overlay.
//
// Transport comes from useChatThread, chrome from ChatPanelShell, and the
// hunt-proposal card from HuntProposalCard — all shared. What is genuinely
// local to this surface: the subject is the host's address (the thread is
// SHARED per host server-side, so a colleague's conversation about this box is
// this conversation), and the scope label prefers the resolved hostname.
// ---------------------------------------------------------------------------

/** Openers that show the surface's range; clicking one fills the box. */
const STARTERS = [
  'What is this host?',
  'Who has it talked to today?',
  'Any alerts involving it this week?',
];

export function HostChatDock({ ip, hostname }: { ip: string; hostname: string | null }) {
  const chat = useChatThread({
    // The address is the subject: it keys the persisted draft and the
    // stale-response guard, and the endpoints are scoped to it.
    subject: ip,
    fetchThread: getHostChat,
    sendMessage: postHostChat,
  });
  const launch = useHuntLaunch();
  const [clearError, setClearError] = useState<string | null>(null);

  /** Start over. The thread is shared per HOST and otherwise permanent — and
   *  its history is what the next turn's prompt carries. */
  const clearThread = () => {
    setClearError(null);
    clearHostChat(ip)
      // The DELETE already returns the emptied thread, but the hook owns the
      // thread state and exposes only a re-read (same trade as the Dashboard).
      .then(() => chat.refresh())
      .catch(() => setClearError('Could not clear the conversation — please try again.'));
  };

  const msgCount = chat.messages.length;
  return (
    <ChatDockShell label={msgCount > 0 ? `Chat · ${msgCount}` : 'Chat about this host'}>
      {(close) => (
        <div className="flex h-full min-h-0 flex-col">
          <div className="min-h-0 flex-1">
            <ChatPanelShell
              title="Chat about this host"
              // The name a human uses when the sweep (or an operator) has one;
              // the address is the honest fallback.
              scopeLabel={hostname ?? ip}
              placeholder="Ask about this host… e.g. who has it talked to today?"
              listSizeClass="min-h-0 flex-1"
              fill
              onClose={close}
              emptyHint={
                <div className="flex flex-col gap-2.5 py-1 text-[12.5px]">
                  <div className="flex items-center gap-1.5 text-faint">
                    <MessageSquare size={13} />
                    Ask about this host — answered here from its dossier and live telemetry.
                    Questions that need a sweep come back as a hunt to confirm.
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
              // A reset, not a thread list — and only once there IS a
              // conversation (the Dashboard panel's exact trade).
              headerRight={
                msgCount > 0 ? (
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
          </div>
          {/* A failed clear reports under the panel — the header holds the
              control, not a sentence about why it didn't work. */}
          {clearError && (
            <div className="mt-1.5 flex justify-end text-[11px] text-danger">{clearError}</div>
          )}
        </div>
      )}
    </ChatDockShell>
  );
}
