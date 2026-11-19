import { ShieldCheck } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { CampaignDetail } from '../../lib/api';
import {
  authorizationSentence,
  campaignLaterSentence,
  eventsFacts,
  heldInvestigations,
  lastActivityOf,
} from '../../lib/campaignWords';

import { Panel } from '../Panel';
import { BeyondBanner } from './CampaignBeyond';
import { DecisionBar, sinceInBar } from './DecisionBar';
import { HuntAnswerLine } from './HuntAnswerLine';
import { CampaignStageChip, CampaignStateChip } from './shared';
import { UtcTime } from '../UtcTime';

const LINK = 'text-accent hover:underline';

/** The title, the state, the stage and the period, then the decision bar,
 *  the alarm of the investigations beyond the authorization, the bottom line, one line of facts about the events of the campaign, and
 *  one line for each authorization that covers investigations of the
 *  campaign. A merged campaign names the campaign that holds it. */
export function CampaignHeader({
  campaign: c,
  onCloseRequest = () => {},
  onDecided = () => {},
  onAuthorizeRequest,
  onCaseRequest,
  canAuthorize = false,
  onShowBeyond,
  onShowNew,
}: {
  campaign: CampaignDetail;
  onCloseRequest?: () => void;
  onDecided?: (next: CampaignDetail) => void;
  onAuthorizeRequest?: () => void;
  /** Opens the dialog "Open one case". */
  onCaseRequest?: () => void;
  canAuthorize?: boolean;
  /** Opens the fold of the investigations beyond the authorization. */
  onShowBeyond?: () => void;
  /** Opens the investigations of the campaign with only the new ones. */
  onShowNew?: () => void;
}) {
  const facts = eventsFacts(c.events);
  // The decision bar states the authorization on the campaign. The lines
  // below it state the stored records with a rule list.
  const older = c.authorizations.filter((a) => a.id !== c.authorization?.id);
  return (
    <Panel>
      <div data-testid="campaign-header" className="px-[15px] py-3">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
          <h1 className="break-words text-[19px] font-semibold">{c.title}</h1>
          <CampaignStateChip campaign={c} />
          <CampaignStageChip stage={c.stage} />
          <span data-testid="campaign-period" className="font-mono text-[11.5px] text-dim">
            <UtcTime iso={c.firstEvent} to={lastActivityOf(c)} seconds={false} />
          </span>
        </div>
        <DecisionBar
          campaign={c}
          onCloseRequest={onCloseRequest}
          onDecided={onDecided}
          onAuthorizeRequest={onAuthorizeRequest}
          onCaseRequest={onCaseRequest}
          canAuthorize={canAuthorize}
          onShowNew={onShowNew}
        />
        <BeyondBanner beyond={c.beyond} onShow={onShowBeyond} />
        {c.status === 'merged' && c.mergedInto != null && (
          <div data-testid="campaign-merged" className="mt-2 text-[13px] text-text-2">
            This campaign is part of{' '}
            <Link to={`/campaigns/${c.mergedInto}`} className={LINK}>
              campaign {c.mergedInto}
            </Link>
            .
          </div>
        )}
        {c.bottomLine && (
          <p data-testid="campaign-bottom-line" className="mt-2 break-words text-[14px] leading-[1.55] text-text">
            {c.bottomLine}
          </p>
        )}
        {/* The newest hunt that read the campaign, and what it found. A
            reopened campaign states it in the bar, beside the hunt of the reopen.
            The banner of a reopened campaign states the later alert events
            already. Else the answer line states them (G6). */}
        {!sinceInBar(c) && (
          <HuntAnswerLine
            subject="campaign"
            answer={c.answers?.[0]}
            testId="campaign-hunt-answer"
            className="mt-1.5"
            later={(c.sinceDecision?.laterAlerts ?? 0) > 0 ? null : campaignLaterSentence(c.events)}
          />
        )}
        {facts && (
          <p data-testid="campaign-facts" className="mt-1.5 break-words text-[12.5px] leading-snug text-text-2">
            {facts}
          </p>
        )}
        {older.length > 0 && (
          <ul data-testid="campaign-authorizations" className="mt-2 space-y-1">
            {older.map((a) => (
              <li key={a.id} className="flex items-start gap-2 text-[12.5px] leading-snug text-text-2">
                <ShieldCheck size={14} aria-hidden className="mt-px flex-none text-dim" />
                <span className="min-w-0 break-words">{authorizationSentence(a, heldInvestigations(c.members), c.authorization)}</span>
              </li>
            ))}
          </ul>
        )}
        {c.earlierCampaign && (
          <div data-testid="campaign-earlier" className="mt-1.5 text-[12.5px] text-dim">
            The same machines formed an earlier campaign:{' '}
            <Link to={`/campaigns/${c.earlierCampaign.id}`} className={`break-words ${LINK}`}>
              {c.earlierCampaign.title}
            </Link>
            .
          </div>
        )}
      </div>
    </Panel>
  );
}
