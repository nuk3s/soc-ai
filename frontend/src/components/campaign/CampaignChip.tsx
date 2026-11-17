import { Network } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { InvestigationCampaign } from '../../lib/api';
import { CAMPAIGN_CHIP_WORD, campaignChipWords } from '../../lib/campaignWords';
import { stageColor } from '../../lib/campaignViz';

/** The link from a row to the campaign of its investigation: the network
 *  icon, the word "Campaign" and a dot in the color of the stage that the
 *  campaign reached. The accessible name and the hover text state the title
 *  and the stage, and the differs sentence when the verdict of the row differs.
 *  A dashed border marks a verdict that differs.
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
  return (
    <Link
      to={`/campaigns/${campaign.id}`}
      aria-label={words}
      title={words}
      data-testid={testId}
      data-differs={campaign.differs}
      onClick={(e) => e.stopPropagation()}
      onKeyDown={(e) => e.stopPropagation()}
      className={`inline-flex flex-none items-center gap-[4px] whitespace-nowrap rounded-badge border bg-surface-2 px-[6px] py-[2px] text-[10.5px] font-semibold text-text-2 hover:border-accent hover:text-accent ${
        campaign.differs ? 'border-dashed border-ghost' : 'border-border-strong'
      }`}
    >
      <Network size={10} aria-hidden className="flex-none" />
      {CAMPAIGN_CHIP_WORD}
      <span
        aria-hidden
        data-testid={`${testId}-dot`}
        className="h-[6px] w-[6px] flex-none rounded-full"
        style={{ background: stageColor(campaign.stage) }}
      />
    </Link>
  );
}
