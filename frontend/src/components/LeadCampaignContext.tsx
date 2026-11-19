import { Network, ShieldCheck } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { LeadDetail, LeadHuntAnswer } from '../lib/api';
import {
  HUNT_ANSWER_TITLE,
  huntAnswerWord,
  authorizedPartSentence,
  closedWithCampaignSentence,
  huntStarterLabel,
  leadCampaignDecisionSentence,
  leadCampaignParts,
} from '../lib/campaignWords';
import { HuntAnswerLine, huntAnswerTone } from './campaign/HuntAnswerLine';
import { Panel, PanelHeader } from './Panel';
import { UtcTime } from './UtcTime';

const LINE = 'flex items-start gap-2 text-[12.5px] leading-snug text-text-2';

/** The answer of one hunt in the shape of the answer line. */
function answerOf(a: LeadHuntAnswer) {
  return { huntId: a.hunt_id, outcome: a.outcome, huntAt: a.hunt_at, findingTitle: a.finding_title };
}

/** The context of a lead at the top of its page: the campaign that it is
 *  part of and the decision on that campaign, a close with the campaign, the
 *  observations that are authorized activity, and the newest answer of a
 *  hunt that read the lead. An older server sends none of it, and the block
 *  is then empty. */
export function LeadCampaignContext({ lead }: { lead: Pick<LeadDetail, 'campaign_context' | 'authorized' | 'answers'> }) {
  const c = lead.campaign_context ?? null;
  const authorized = lead.authorized ?? [];
  const newest = lead.answers?.[0];
  if (!c && authorized.length === 0 && !newest) return null;
  const parts = c ? leadCampaignParts(c) : null;
  return (
    <div data-testid="lead-context" className="mt-2 flex flex-col gap-1">
      {c && parts && (
        <div data-testid="lead-context-campaign" className={LINE}>
          <Network size={14} aria-hidden className="mt-px flex-none text-dim" />
          <span className="min-w-0 break-words">
            {parts.before}
            <Link to={`/campaigns/${c.id}`} className="text-accent hover:underline">
              {parts.link}
            </Link>
            {`${parts.after} ${leadCampaignDecisionSentence(c)}`}
            {c.closed_with_campaign && (
              <span data-testid="lead-context-closed-with"> {closedWithCampaignSentence(c)}</span>
            )}
          </span>
        </div>
      )}
      {authorized.map((p) => (
        <div key={p.label} data-testid="lead-context-authorized" className={LINE}>
          <ShieldCheck size={14} aria-hidden className="mt-px flex-none text-dim" />
          <span className="min-w-0 break-words">{authorizedPartSentence(p)}</span>
        </div>
      ))}
      <HuntAnswerLine subject="lead" answer={newest ? answerOf(newest) : null} testId="lead-hunt-answer" />
    </div>
  );
}

/** The other hunts that read the lead, newest first, each with its answer.
 *  The hunts of the lead itself are in the panel "Hunts on this lead". */
export function LeadOtherHunts({ answers }: { answers: readonly LeadHuntAnswer[] | undefined }) {
  if (!answers || answers.length === 0) return null;
  return (
    <Panel className="mt-4">
      <PanelHeader title={`Other hunts that read this lead · ${answers.length}`} />
      <ul data-testid="lead-other-hunts" className="divide-y divide-border-faint">
        {answers.map((a) => (
          <li key={a.hunt_id} data-testid={`lead-other-hunt-${a.hunt_id}`} className="px-[15px] py-2.5 text-[12.5px]">
            <div className="flex flex-wrap items-center gap-2.5">
              <span
                title={HUNT_ANSWER_TITLE}
                className="inline-flex items-center gap-1 font-semibold"
                style={{ color: huntAnswerTone(a.outcome) }}
              >
                {huntAnswerWord('lead', a.outcome)}
              </span>
              <Link to={`/hunts/${encodeURIComponent(a.hunt_id)}`} className="text-accent hover:underline">
                {huntStarterLabel(a.starter)}
              </Link>
              <UtcTime className="font-mono text-[11.5px] text-faint" iso={a.hunt_at} seconds={false} />
              {a.outcome === 'new_activity' && a.finding_title && (
                <span className="min-w-0 break-words text-text">{a.finding_title}</span>
              )}
            </div>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
