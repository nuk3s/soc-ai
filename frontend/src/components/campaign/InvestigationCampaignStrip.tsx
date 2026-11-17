import { ArrowUpRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { InvestigationCampaign } from '../../lib/api';
import { decisionState } from '../../lib/campaignDecision';
import { OPEN_CAMPAIGN, STRIP_CLOSED, campaignStripWords, stageReachedWords } from '../../lib/campaignWords';
import { stageColor } from '../../lib/campaignViz';
import { CampaignDecisionChip } from './shared';
import { StageMeter } from './StageMeter';

/** The strip under the header of an investigation page that is part of a
 *  campaign. The campaign is the unit of work of the analyst, and the page of
 *  one investigation is support for it, so the strip leads the page: the
 *  stage meter, the sentence with the title, the stage in words and the link
 *  to the campaign. The left edge wears the color of the stage. The chip
 *  states the decision of the campaign, and the sentence states a closed
 *  campaign. No campaign renders nothing. */
export function InvestigationCampaignStrip({
  campaign,
  className = '',
}: {
  campaign: InvestigationCampaign | null | undefined;
  className?: string;
}) {
  if (!campaign) return null;
  const words = campaignStripWords(campaign.differs);
  return (
    <section
      data-testid="investigation-campaign"
      data-differs={campaign.differs}
      aria-label="Campaign"
      className={`flex flex-wrap items-center gap-x-3 gap-y-1.5 rounded-card border border-l-[3px] border-border bg-surface-1 px-3.5 py-2.5 ${className}`}
      style={{ borderLeftColor: stageColor(campaign.stage) }}
    >
      <StageMeter stage={campaign.stage} size="md" />
      <span
        data-testid="investigation-campaign-sentence"
        className="min-w-0 flex-[1_1_20rem] break-words text-[13px] text-text"
      >
        {words.before}
        <span className="font-semibold">{campaign.title.trim()}</span>
        {words.after}
        {decisionState(campaign) === 'closed' && STRIP_CLOSED}
      </span>
      <CampaignDecisionChip campaign={campaign} />
      <span data-testid="investigation-campaign-stage" className="flex-none text-[11.5px] text-dim">
        {stageReachedWords(campaign.stage)}
      </span>
      <Link
        to={`/campaigns/${campaign.id}`}
        className="flex flex-none items-center gap-1 text-[12px] font-semibold text-accent hover:underline"
      >
        {OPEN_CAMPAIGN}
        <ArrowUpRight size={13} aria-hidden />
      </Link>
    </section>
  );
}
