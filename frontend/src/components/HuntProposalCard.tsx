import { Crosshair } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { AssistantBubble } from './ChatDock';
import { Spinner } from './States';
import { MAX_OBJECTIVE_CHARS, startHuntConsole } from '../lib/api';
import type { ChatMessage } from '../lib/types';

// ---------------------------------------------------------------------------
// The "Proposed hunt" card: how a chat surface renders the agent's proposal
// and hands the DECISION to the analyst. Shared by the Dashboard assistant
// (GeneralChatPanel) and the host page chat (HostChatDock) — a private copy per
// panel is exactly how this project's chat surfaces drift (the hunt chat forked
// its manager and missed every feature shipped after), so the card, the launch
// flow and its failure handling live here once.
// ---------------------------------------------------------------------------

export interface HuntLaunch {
  /** Index of the card mid-launch, or null when idle. */
  starting: number | null;
  /** Per-card failure text, keyed by message index. */
  startError: Record<number, string>;
  /** Confirm card `idx`: start `objective` and navigate to the live hunt. */
  start: (idx: number, objective: string) => void;
}

/**
 * The launch half of the card: which proposal is mid-start, per-card errors,
 * and the confirm action. One instance per PANEL (not per card) so "one launch
 * at a time" holds across a thread that carries several proposals; errors are
 * keyed by message index so a second card's failure can't appear under the
 * first.
 */
export function useHuntLaunch(): HuntLaunch {
  const navigate = useNavigate();
  const [starting, setStarting] = useState<number | null>(null);
  const [startError, setStartError] = useState<Record<number, string>>({});

  /**
   * Confirm a proposed hunt: the analyst's click is the ONLY thing that starts
   * one. Optimistically navigates to the live hunt, the same as the Hunt
   * Console's own box, so the analyst watches it run instead of guessing.
   */
  const start = (idx: number, objective: string) => {
    if (starting !== null) return; // one launch at a time — a double click is one hunt
    setStarting(idx);
    setStartError(({ [idx]: _drop, ...rest }) => rest);
    // The agent's brief can run long; the endpoint rejects an over-long body,
    // and a card that 422s on click is worse than one that was trimmed.
    startHuntConsole(objective.slice(0, MAX_OBJECTIVE_CHARS))
      .then((r) => navigate(`/hunts/${r.hunt_id}`))
      .catch((e: unknown) => {
        setStartError((s) => ({
          ...s,
          [idx]: e instanceof Error ? e.message : 'Could not start the hunt — please try again.',
        }));
        setStarting(null); // stays on the page; the card is still confirmable
      });
  };

  return { starting, startError, start };
}

/**
 * `renderSpecial` body for hunt-proposal rows, shared verbatim by both panels.
 * Returns null for anything that is not a confirmable proposal so the shell
 * falls through to the ordinary bubble — the manager stores whatever
 * `propose_hunt` returned and "" is a legal objective, and prose beats a Start
 * button with nothing behind it.
 */
export function huntProposalRow(m: ChatMessage, i: number, launch: HuntLaunch): ReactNode | null {
  if (m.kind !== 'hunt_proposal') return null;
  const objective = m.proposal.objective.trim();
  if (!objective) return null;
  const why = m.proposal.why.trim();
  return (
    <div key={i} className="flex min-w-0 max-w-[88%] flex-col gap-1.5 self-start">
      {/* The proposal rides on the SAME row as the answer ("say what you
          already found, then propose the sweep"), so the row renders the
          shared bubble AND the card — dropping the prose would throw away the
          half of the reply the analyst judges the proposal by. */}
      <AssistantBubble text={m.text} tools={m.tools} />
      <div
        className="rounded-card border px-3 py-2.5"
        style={{ borderColor: 'rgba(75,139,245,.35)', background: 'rgba(75,139,245,.06)' }}
      >
        <div className="mb-1.5 flex items-center gap-1.5 text-[12px] font-semibold text-text-2">
          <span className="flex text-accent">
            <Crosshair size={13} />
          </span>
          Proposed hunt
        </div>
        {/* The agent has already looked at the grid, so its objective is
            sharper than the analyst's raw sentence — but the analyst is the
            one who decides a multi-minute sweep is worth running. */}
        <div className="break-words text-[13px] leading-[1.5] text-text-2">{objective}</div>
        {why && <div className="mt-1 break-words text-[12px] leading-[1.45] text-dim">{why}</div>}
        <button
          type="button"
          disabled={launch.starting !== null}
          onClick={() => launch.start(i, objective)}
          className="mt-2 flex items-center gap-1.5 rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold text-[#cfe0ff] disabled:opacity-60"
          style={{ background: 'rgba(75,139,245,.14)', borderColor: 'rgba(75,139,245,.4)' }}
        >
          {launch.starting === i && <Spinner size={12} />}
          {launch.starting === i ? 'Starting…' : 'Start this hunt'}
        </button>
        {launch.startError[i] && (
          <div className="mt-1.5 break-words text-[11.5px] text-danger">{launch.startError[i]}</div>
        )}
      </div>
    </div>
  );
}
