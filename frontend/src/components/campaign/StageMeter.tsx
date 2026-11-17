import type { CampaignStage } from '../../lib/api';
import { STAGE_COLOR, STAGE_SEQUENCE, stageRank } from '../../lib/campaignViz';
import { stageMeterWords } from '../../lib/campaignWords';

const SEGMENT = {
  sm: 'h-[6px] w-[10px]',
  md: 'h-[8px] w-[14px]',
} as const;

/** The stage a campaign reached, as five small segments, lowest stage first.
 *  The segments up to the reached stage wear the colors of their stages, the
 *  ramp of the stage ladder and the two charts. The others wear the muted
 *  surface. A campaign with no proven stage fills none. The meter is one
 *  image: its accessible name and its hover text state the stage in words. */
export function StageMeter({
  stage,
  size = 'sm',
  testId = 'stage-meter',
  className = '',
}: {
  stage: CampaignStage | null | undefined;
  size?: keyof typeof SEGMENT;
  testId?: string;
  className?: string;
}) {
  const reached = stageRank(stage);
  const words = stageMeterWords(stage);
  return (
    <span
      role="img"
      aria-label={words}
      title={words}
      data-testid={testId}
      data-stage={stage ?? ''}
      className={`inline-flex flex-none items-center gap-[2px] ${className}`}
    >
      {STAGE_SEQUENCE.map((s, i) => {
        const filled = i <= reached;
        return (
          <span
            key={s}
            aria-hidden
            data-filled={filled}
            className={`${SEGMENT[size]} rounded-[2px] ${filled ? '' : 'bg-border-strong'}`}
            style={filled ? { background: STAGE_COLOR[s] } : undefined}
          />
        );
      })}
    </span>
  );
}
