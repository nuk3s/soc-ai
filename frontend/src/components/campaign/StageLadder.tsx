import { Link } from 'react-router-dom';
import type { CampaignLadderStep } from '../../lib/api';
import {
  NOT_SEEN,
  NO_OWN_PROOF,
  STAGE_ORDER,
  VIEW_EVIDENCE,
  heldByWords,
  ownProofWords,
  stageLabel,
} from '../../lib/campaignWords';
import { STAGE_COLOR, stageRank } from '../../lib/campaignViz';
import { utcStamp } from '../../lib/timeRange';
import { Panel } from '../Panel';
import { runHref } from './shared';
import { UtcTime } from '../UtcTime';

/** The five stages as one row of steps, lowest first. A reached step wears
 *  the color of its stage and states what happened, its first time, the
 *  record that proves it and a link to the investigation that holds that
 *  record. A stage the server did not send reads as not seen, so the row
 *  always has five steps. The two charts below use the same colors.
 *
 *  A later stage can prove a stage earlier than its own first proof: an
 *  action on a target needs access to it. The step then states "by" and that
 *  earlier time, so the times never run backward along the ladder. A stage
 *  with no proof of its own that a later stage needs wears a ring in its
 *  color, and says that no investigation proves the stage itself.
 *
 *  A server of an earlier release sends no headline and no evidence: the step
 *  then states its time and the link. */
export function StageLadder({ ladder }: { ladder: CampaignLadderStep[] }) {
  const byStage = new Map(ladder.map((s) => [s.stage, s]));
  return (
    <Panel>
      <div className="px-[15px] pb-3 pt-2.5">
        <div className="mb-2 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">Stage ladder</div>
        <ol data-testid="stage-ladder" className="relative grid grid-cols-5 gap-x-3">
          {/* The rail behind the five steps. */}
          <span aria-hidden className="absolute left-[9px] right-[9px] top-[9px] h-px bg-border-strong" />
          {STAGE_ORDER.map((stage, i) => {
            const step = byStage.get(stage);
            const reached = Boolean(step?.reached);
            const held = step?.heldBy ?? null;
            // A later stage needs this one, and no investigation proves it.
            const implied = !reached && held !== null;
            return (
              <li
                key={stage}
                data-testid={`ladder-${stage}`}
                data-reached={reached}
                data-implied={implied}
                className="relative min-w-0"
              >
                <span
                  aria-hidden
                  className={`flex h-[19px] w-[19px] items-center justify-center rounded-full font-mono text-[10px] font-semibold ${
                    reached ? '' : implied ? 'border-2 bg-surface-1 text-text-2' : 'border border-ghost bg-surface-1 text-faint'
                  }`}
                  style={
                    reached
                      ? {
                          background: STAGE_COLOR[stage],
                          color: stageRank(stage) >= 2 ? '#0b0e13' : '#e6e9ef',
                          boxShadow: '0 0 0 3px rgb(var(--surface-1))',
                        }
                      : implied
                        ? { borderColor: STAGE_COLOR[stage], boxShadow: '0 0 0 3px rgb(var(--surface-1))' }
                        : { boxShadow: '0 0 0 3px rgb(var(--surface-1))' }
                  }
                >
                  {i + 1}
                </span>
                <div
                  className={`mt-1.5 break-words text-[12.5px] leading-tight ${
                    reached ? 'font-semibold text-text' : implied ? 'text-text-2' : 'text-dim'
                  }`}
                >
                  {stageLabel(stage)}
                </div>
                {reached && step ? (
                  <div className="mt-1 text-[11px] leading-snug text-dim">
                    {step.headline?.trim() && (
                      <p data-testid="ladder-headline" className="break-words text-[12px] leading-snug text-text-2">
                        {step.headline.trim()}
                      </p>
                    )}
                    {held ? (
                      <>
                        <div data-testid="ladder-time" className="mt-0.5 font-mono text-[10.5px] text-text-2">
                          by <UtcTime iso={held.at} />
                        </div>
                        <p data-testid="ladder-held" className="mt-0.5 break-words text-[10.5px] leading-snug text-faint">
                          {heldByWords(held.stage)} {ownProofWords(utcStamp(step.firstAt, { seconds: true }))}
                        </p>
                      </>
                    ) : (
                      <div data-testid="ladder-time" className="mt-0.5 font-mono text-[10.5px] text-text-2">
                        <UtcTime iso={step.firstAt} />
                      </div>
                    )}
                    {step.evidence?.label?.trim() && (
                      <div
                        data-testid="ladder-evidence"
                        className="mt-0.5 break-words font-mono text-[10.5px] leading-snug text-faint"
                      >
                        {step.evidence.label.trim()}
                      </div>
                    )}
                    {step.proofRunId && (
                      <Link
                        to={runHref(step.proofRunId)}
                        className="mt-0.5 inline-block font-semibold text-accent hover:underline"
                      >
                        {VIEW_EVIDENCE}
                      </Link>
                    )}
                  </div>
                ) : held ? (
                  <div className="mt-1 text-[11px] leading-snug text-dim">
                    <div data-testid="ladder-time" className="font-mono text-[10.5px] text-text-2">
                      by <UtcTime iso={held.at} />
                    </div>
                    <p data-testid="ladder-held" className="mt-0.5 break-words text-[10.5px] leading-snug text-faint">
                      {NO_OWN_PROOF} {heldByWords(held.stage)}
                    </p>
                  </div>
                ) : (
                  <div className="mt-1 text-[11px] text-faint">{NOT_SEEN}</div>
                )}
              </li>
            );
          })}
        </ol>
      </div>
    </Panel>
  );
}
