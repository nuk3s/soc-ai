import { Fragment } from 'react';
import { AlertTriangle, Network } from 'lucide-react';
import { Link } from 'react-router-dom';
import type {
  CampaignAuthorizationRecord,
  CampaignCase,
  CampaignDecision,
  CampaignDecisionType,
  CampaignPartyBrief,
  CampaignStage,
  CampaignState,
  CampaignStatus,
} from '../../lib/api';
import { campaignState, stateWaits } from '../../lib/campaignDecision';
import {
  beyondCountTitle,
  beyondCountWords,
  partyName,
  stageLabel,
  stateChipTitle,
  stateLabel,
} from '../../lib/campaignWords';
import { stageColor } from '../../lib/campaignViz';
import { machineHref } from '../../lib/hostsList';

// The small parts the list page and the campaign page share: the state chip,
// the stage chip and the name of a machine as a link to its host page.

const CHIP =
  'inline-flex flex-none items-center whitespace-nowrap rounded-chip border px-1.5 py-px text-[10.5px]';

/** The one state of a campaign (DC1, round "decide once"): Open, Ended,
 *  Closed, Authorized, Case, Merged or Withdrawn, with a one-sentence hover
 *  text. The state is the decision in force, else the activity status, so
 *  no page shows "Open" beside "Closed". A campaign that waits on a decision
 *  wears the warning tone, because it is work. A decision and a campaign
 *  that is not active read neutral. */
export function CampaignStateChip({
  campaign,
}: {
  campaign: {
    status: CampaignStatus;
    state?: CampaignState | '' | null;
    decision?: CampaignDecision | CampaignDecisionType | null;
    /** The authorization of the campaign: the hover text states its expiry. */
    authorization?: Pick<CampaignAuthorizationRecord, 'expiresAt' | 'state'> | null;
    /** The case of the campaign: the hover text states its time. */
    case?: Pick<CampaignCase, 'openedAt'> | null;
  };
}) {
  const state = campaignState(campaign);
  const waits = stateWaits(campaign);
  const tone = waits ? 'border-warn/40 bg-warn/10 font-semibold text-warn' : 'border-border-strong bg-surface-2 text-text-2';
  const title = stateChipTitle({
    state,
    waits,
    authorization: campaign.authorization,
    caseOpenedAt: campaign.case?.openedAt,
    ended: campaign.status === 'ended',
  });
  return (
    <span
      data-testid="campaign-state"
      data-state={state}
      data-waits={waits}
      title={title || undefined}
      className={`${CHIP} ${tone}`}
    >
      {stateLabel(state)}
    </span>
  );
}

/** The alarm of a list row: the investigations beyond the authorization, in
 *  the danger tone. A count of 0, or a server that sends none, renders nothing. */
export function CampaignBeyondChip({ beyond }: { beyond?: number | null }) {
  if (!beyond || beyond <= 0) return null;
  return (
    <span
      data-testid="campaign-beyond-chip"
      title={beyondCountTitle(beyond)}
      className={`${CHIP} gap-1 border-danger/50 bg-danger/10 font-semibold text-danger`}
    >
      <AlertTriangle size={11} aria-hidden className="flex-none" />
      {beyondCountWords(beyond)}
    </span>
  );
}

/** The mark of a notification about a campaign: the network icon and the
 *  word "Campaign". The row title is the link, so the mark is no link.
 *
 *  `stage` is the stage the server sends on the row. The border and the icon
 *  wear the color of the stage on the graphics of the campaign page, so the
 *  bell states how far the campaign went. A null stage wears the color of no
 *  stage. An older server sends no stage, and the mark stays neutral. */
export function CampaignNoticeMark({ stage }: { stage?: CampaignStage | null } = {}) {
  const known = stage !== undefined;
  const color = known ? stageColor(stage) : undefined;
  return (
    <span
      data-testid="notification-campaign"
      data-stage={known ? (stage ?? 'none') : undefined}
      title={known ? (stage ? `Stage reached: ${stageLabel(stage)}` : 'No proven stage') : undefined}
      className="inline-flex flex-none items-center gap-[4px] whitespace-nowrap rounded-badge border border-border-strong bg-surface-2 px-[6px] py-[1px] align-[1px] text-[10.5px] font-semibold text-text-2"
      style={color ? { borderColor: color } : undefined}
    >
      <Network size={10} aria-hidden className="flex-none" style={color ? { color } : undefined} />
      Campaign
    </span>
  );
}

/** The stage a campaign or a member reached. No stage renders nothing. The
 *  dot wears the color of the stage on the graphics of the campaign page. */
export function CampaignStageChip({ stage }: { stage: CampaignStage | null }) {
  if (!stage) return null;
  return (
    <span
      data-testid="campaign-stage"
      data-stage={stage}
      className={`${CHIP} gap-1.5 border-border-strong bg-surface-2 text-text-2`}
    >
      <span
        aria-hidden
        data-testid="campaign-stage-dot"
        className="h-2 w-2 flex-none rounded-full"
        style={{ background: stageColor(stage) }}
      />
      {stageLabel(stage)}
    </span>
  );
}

/** The name of a machine, linked to its host page. */
export function PartyLink({
  party,
  className = '',
}: {
  party: Pick<CampaignPartyBrief, 'machineKey' | 'name'> & {
    address?: string | null;
    addresses?: string[];
  };
  className?: string;
}) {
  return (
    <Link
      to={machineHref(party.machineKey)}
      className={`break-words text-accent hover:underline ${className}`}
      title={party.address ?? party.addresses?.[0] ?? party.machineKey}
    >
      {partyName(party)}
    </Link>
  );
}

/** Machine names as links, one comma between two. */
export function PartyLinks({ parties }: { parties: CampaignPartyBrief[] }) {
  return (
    <>
      {parties.map((p, i) => (
        <Fragment key={p.machineKey}>
          {i > 0 && ', '}
          <PartyLink party={p} />
        </Fragment>
      ))}
    </>
  );
}

/** The address of the page of an investigation. */
export function runHref(runId: string): string {
  return `/investigation/${encodeURIComponent(runId)}`;
}
