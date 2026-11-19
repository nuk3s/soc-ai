import { Network } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { InvestigationCampaign } from '../../lib/api';
import { campaignState, stateWaits } from '../../lib/campaignDecision';
import { campaignChipLabel, campaignChipWords } from '../../lib/campaignWords';
import { stageColor } from '../../lib/campaignViz';

/** The link from a row to the campaign of its investigation: the network
 *  icon, "Campaign 2", a dot in the color of the stage that the campaign
 *  reached, and the one state of the campaign: "· Closed" (round "decide
 *  once", DC4). A row of a decided campaign so states the decision, and no
 *  mark of the row says that it waits. A campaign that waits states Open or
 *  Ended in the warning tone. The accessible name and the hover text state
 *  the same words, the title and the stage, and the differs sentence when the
 *  verdict of the row differs. A dashed border marks a verdict that differs.
 *  The state can take a second line inside the chip, so no word is cut.
 *
 *  The rows that hold the chip open on a click and on Enter, so the chip keeps
 *  both events to itself. No campaign renders nothing. */
export function CampaignChip({
  campaign,
  testId = 'campaign-chip',
}: {
  campaign: InvestigationCampaign | null | undefined;
  testId?: string;
}) {
  if (!campaign) return null;
  const words = campaignChipWords(campaign);
  const label = campaignChipLabel(campaign);
  const waits = stateWaits(campaign);
  return (
    <Link
      to={`/campaigns/${campaign.id}`}
      aria-label={words}
      title={words}
      data-testid={testId}
      data-differs={campaign.differs}
      onClick={(e) => e.stopPropagation()}
      onKeyDown={(e) => e.stopPropagation()}
      className={`inline-flex max-w-full flex-none flex-wrap items-center gap-x-[4px] rounded-badge border bg-surface-2 px-[6px] py-[2px] text-[10.5px] font-semibold text-text-2 hover:border-accent hover:text-accent ${
        campaign.differs ? 'border-dashed border-ghost' : 'border-border-strong'
      }`}
    >
      <Network size={10} aria-hidden className="flex-none" />
      <span className="whitespace-nowrap">{label.head}</span>
      <span
        aria-hidden
        data-testid={`${testId}-dot`}
        className="h-[6px] w-[6px] flex-none rounded-full"
        style={{ background: stageColor(campaign.stage) }}
      />{' '}
      <span
        data-testid={`${testId}-state`}
        data-state={campaignState(campaign)}
        className={`whitespace-nowrap ${waits ? 'text-warn' : ''}`}
      >
        {label.state}
      </span>
    </Link>
  );
}
