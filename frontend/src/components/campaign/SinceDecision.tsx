import { Radar, RotateCcw } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { CampaignHuntAnswer, CampaignSinceDecision } from '../../lib/api';
import {
  SHOW_NEW_ACTION,
  SINCE_CHIP,
  SINCE_CHIP_TITLE,
  sinceEarlierSentence,
  sinceLaterSentence,
  sinceMachinesSentence,
  sinceNewSentence,
  sinceNoteSentence,
  sinceReopenHuntSentence,
  sinceReopenSentence,
  sinceStageSentence,
} from '../../lib/campaignWords';
import { HuntAnswerLine } from './HuntAnswerLine';

/** What is new since the earlier decision, at the top of the bar of a
 *  campaign that waits (SD3). A chip leads. Then the reopen and the earlier
 *  decision, the new facts, the stage, and each machine that the decision
 *  did not hold. One control shows only the new investigations.
 *
 *  Production, 2026-11-18: campaign 2 opened again three days after a close,
 *  and the page read only "This campaign waits on your decision since ...".
 *  The analyst had to find the new events by hand.
 *
 *  Round 3 part 2 (W1): the last line links the hunt that the reopen started
 *  with its outcome, beside the newest answer of a hunt that read the
 *  campaign. The analyst read "found no activity" of a scheduled hunt, and
 *  the hunt of the reopen had confirmed a true positive. */
export function SinceDecisionLines({
  since,
  onShowNew,
  answer,
}: {
  since: CampaignSinceDecision;
  /** Opens the investigations of the campaign with only the new ones. */
  onShowNew?: () => void;
  /** The newest answer of a hunt that read the campaign. */
  answer?: CampaignHuntAnswer | null;
}) {
  const hunt = since.reopenHunt ?? null;
  const note = sinceNoteSentence(since);
  const machines = sinceMachinesSentence(since);
  const later = sinceLaterSentence(since);
  return (
    <div data-testid="campaign-since" className="mb-2 border-b border-warn/25 pb-2">
      <div className="flex flex-wrap items-start gap-x-2.5 gap-y-1">
        <span
          data-testid="campaign-since-chip"
          title={SINCE_CHIP_TITLE}
          className="inline-flex flex-none items-center gap-1 whitespace-nowrap rounded-pill border border-warn/50 bg-warn/15 px-2 py-px text-[11.5px] font-semibold text-warn"
        >
          <RotateCcw size={12} aria-hidden />
          {SINCE_CHIP}
        </span>
        <span data-testid="campaign-since-earlier" className="min-w-0 flex-[1_1_20rem] break-words text-[13px] text-text">
          {sinceReopenSentence(since)} {sinceEarlierSentence(since)}
          {note && <span className="text-text-2"> {note}</span>}
        </span>
      </div>
      <div className="mt-1 flex flex-wrap items-start gap-x-3 gap-y-1.5 pl-[2px]">
        <span className="min-w-0 flex-[1_1_20rem] break-words text-[12.5px] leading-snug text-text-2">
          <span data-testid="campaign-since-new">{sinceNewSentence(since)}</span>{' '}
          <span data-testid="campaign-since-stage">{sinceStageSentence(since)}</span>
          {machines && (
            <>
              {' '}
              <span data-testid="campaign-since-machines">{machines}</span>
            </>
          )}
          {later && (
            <>
              {' '}
              <span data-testid="campaign-since-later">{later}</span>
            </>
          )}
        </span>
        {onShowNew && since.investigations > 0 && (
          <button
            type="button"
            data-testid="campaign-show-new"
            onClick={onShowNew}
            className="flex-none rounded-control border border-border-strong bg-surface-2 px-2.5 py-1 text-[12px] font-semibold text-text-2 hover:border-accent hover:text-accent"
          >
            {SHOW_NEW_ACTION}
          </button>
        )}
      </div>
      {(hunt || answer) && (
        <div data-testid="campaign-since-hunts" className="mt-1 flex flex-col gap-1 pl-[2px]">
          {hunt && (
            <div data-testid="campaign-since-reopen-hunt" className="flex items-start gap-2 text-[12.5px] leading-snug text-text-2">
              <Radar size={14} aria-hidden className="mt-px flex-none text-dim" />
              <span className="min-w-0 break-words">
                {sinceReopenHuntSentence(hunt)}{' '}
                <Link to={`/hunts/${encodeURIComponent(hunt.id)}`} className="text-accent hover:underline">
                  Open the hunt
                </Link>
              </span>
            </div>
          )}
          {answer && answer.huntId !== hunt?.id && (
            <HuntAnswerLine subject="campaign" answer={answer} testId="campaign-hunt-answer" />
          )}
        </div>
      )}
    </div>
  );
}
