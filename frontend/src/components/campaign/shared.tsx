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
  CampaignStatus,
} from '../../lib/api';
import { decisionState } from '../../lib/campaignDecision';
import {
  DECISION_CHIP_LABEL,
  DECISION_CHIP_TITLE,
  authorizedChipLabel,
  authorizedChipTitle,
  beyondCountTitle,
  caseChipLabel,
  caseChipTitle,
  beyondCountWords,
  partyName,
  stageLabel,
  statusLabel,
} from '../../lib/campaignWords';
import { stageColor } from '../../lib/campaignViz';
import { machineHref } from '../../lib/hostsList';

// The small parts the list page and the campaign page share: the two chips
// and the name of a machine as a link to its host page.

const CHIP =
  'inline-flex flex-none items-center whitespace-nowrap rounded-chip border px-1.5 py-px text-[10.5px]';

/** The status of a campaign. Open wears the accent; the rest read neutral. */
export function CampaignStatusChip({ status }: { status: CampaignStatus }) {
  const tone =
    status === 'open'
      ? 'border-accent/40 bg-accent/10 text-accent'
      : 'border-border-strong bg-surface-2 text-text-2';
  return (
    <span data-testid="campaign-status" className={`${CHIP} ${tone}`}>
      {statusLabel(status)}
    </span>
  );
}

/** The decision state of a campaign on a list row: "Waits on you" in the
 *  warning tone, because it is work, or the decision in a neutral tone. An
 *  authorized chip states its expiry. A case chip states the day of the case
 *  when the payload carries the case: the detail does, and a list row of
 *  this release does not. A campaign that is not active, or a server with no
 *  decision field, renders nothing. */
export function CampaignDecisionChip({
  campaign,
}: {
  campaign: {
    status: CampaignStatus;
    decision?: CampaignDecision | CampaignDecisionType | null;
    /** The authorization of the campaign: an authorized chip states its expiry. */
    authorization?: Pick<CampaignAuthorizationRecord, 'expiresAt' | 'state'> | null;
    /** The case of the campaign: a case chip states its day. */
    case?: Pick<CampaignCase, 'openedAt'> | null;
  };
}) {
  const state = decisionState(campaign);
  if (state === 'unknown') return null;
  const tone =
    state === 'waits' ? 'border-warn/40 bg-warn/10 text-warn' : 'border-border-strong bg-surface-2 text-text-2';
  const a = state === 'authorized' ? campaign.authorization : null;
  const openedAt = state === 'case' ? campaign.case?.openedAt : null;
  const title = a
    ? authorizedChipTitle(a)
    : state === 'case'
      ? caseChipTitle(openedAt)
      : (DECISION_CHIP_TITLE[state] ?? '');
  const word = a
    ? authorizedChipLabel(a)
    : state === 'case'
      ? caseChipLabel(openedAt)
      : (DECISION_CHIP_LABEL[state] ?? String(state));
  return (
    <span
      data-testid="campaign-decision-chip"
      data-state={state}
      title={title}
      className={`${CHIP} ${tone} ${state === 'waits' ? 'font-semibold' : ''}`}
    >
      {word}
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
