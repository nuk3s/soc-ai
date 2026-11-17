import { Link } from 'react-router-dom';
import type { CampaignLadderStep } from '../../lib/api';
import { NOT_SEEN, STAGE_ORDER, VIEW_EVIDENCE, stageLabel } from '../../lib/campaignWords';
import { STAGE_COLOR, stageRank } from '../../lib/campaignViz';
import { utcStamp } from '../../lib/timeRange';
import { Panel } from '../Panel';
import { runHref } from './shared';

/** The five stages as one row of steps, lowest first. A reached step wears
 *  the color of its stage and states what happened, its first time, the
 *  record that proves it and a link to the investigation that holds that
 *  record. A stage the server did not send reads as not seen, so the row
 *  always has five steps. The two charts below use the same colors.
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
            return (
              <li key={stage} data-testid={`ladder-${stage}`} data-reached={reached} className="relative min-w-0">
                <span
                  aria-hidden
                  className={`flex h-[19px] w-[19px] items-center justify-center rounded-full font-mono text-[10px] font-semibold ${
                    reached ? '' : 'border border-ghost bg-surface-1 text-faint'
                  }`}
                  style={
                    reached
                      ? {
                          background: STAGE_COLOR[stage],
                          color: stageRank(stage) >= 2 ? '#0b0e13' : '#e6e9ef',
                          boxShadow: '0 0 0 3px rgb(var(--surface-1))',
                        }
                      : { boxShadow: '0 0 0 3px rgb(var(--surface-1))' }
                  }
                >
                  {i + 1}
                </span>
                <div
                  className={`mt-1.5 break-words text-[12.5px] leading-tight ${
                    reached ? 'font-semibold text-text' : 'text-dim'
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
                    <div className="mt-0.5 font-mono text-[10.5px] text-text-2">
                      {utcStamp(step.firstAt, { seconds: true })}
                    </div>
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
