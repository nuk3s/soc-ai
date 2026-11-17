import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  includeInCampaign,
  type CampaignDetail,
  type CampaignLead,
  type CampaignRelated as CampaignRelatedT,
  type CampaignRelatedRun,
} from '../../lib/api';
import {
  INCLUDE_ACTION,
  INCLUDE_CONFIRM,
  OPEN_LEAD,
  RELATED_EMPTY,
  RELATED_LEAD_NOTE,
  falsePositiveSentence,
  namedSentence,
  sessionTail,
} from '../../lib/campaignWords';
import { utcStamp } from '../../lib/timeRange';
import { VerdictPill } from '../Badges';
import { UNKNOWN } from '../Kpi';
import { Panel, PanelHeader } from '../Panel';
import { LEAD_STATUS_LABEL, leadStatusLabel } from '../LeadsStrip';
import { ROW_BUTTON, RowConfirm } from './RowWrite';
import { PartyLink, runHref } from './shared';

const ROW = 'px-[15px] py-2.5 text-[12.5px]';

/** The candidates the engine does not include: the investigations on a pair
 *  of machines that need more info, the leads on a machine of the campaign
 *  with an observation that the campaign does not hold, the sessions between
 *  machines, the hosts that documents of the campaign name, and the alerts
 *  from a target that soc-ai judged false positive. `embedded` drops the
 *  panel and the title: a fold of the page holds them. */
export function CampaignRelated({
  related,
  leads = [],
  embedded = false,
  writes,
}: {
  related: CampaignRelatedT;
  /** The related leads. A lead of the campaign is in the fold of the leads and the hunts. */
  leads?: readonly CampaignLead[];
  embedded?: boolean;
  /** Include on each investigation that needs more info. */
  writes?: { campaignId: number; onChanged: (next: CampaignDetail) => void };
}) {
  const { needsMoreInfo, sessions, named, falsePositiveFromTargets } = related;
  const falsePositives = falsePositiveSentence(falsePositiveFromTargets);
  const relatedLeads = leads.filter((l) => l.related);
  const empty =
    needsMoreInfo.length === 0 &&
    relatedLeads.length === 0 &&
    sessions.length === 0 &&
    named.length === 0 &&
    !falsePositives;
  const body = (
    <>
      {empty ? (
        <div data-testid="related-empty" className={`${ROW} text-dim`}>
          {RELATED_EMPTY}
        </div>
      ) : (
        <ul data-testid="campaign-related" className="divide-y divide-border-faint">
          {needsMoreInfo.map((r) => (
            <RelatedRunRow key={r.runId} r={r} writes={writes} />
          ))}
          {relatedLeads.map((l) => (
            <li key={`lead-${l.id}`} data-testid={`related-lead-${l.id}`} className={ROW}>
              <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
                <span className="min-w-0 break-words text-text-2">{l.title}</span>
                <span className="text-dim">
                  {l.state === 'dismissed' || l.state === 'promoted' ? LEAD_STATUS_LABEL[l.state] : leadStatusLabel(l.state)}
                </span>
                <span className="text-dim">{RELATED_LEAD_NOTE}</span>
                <Link to={`/leads/${l.id}`} className="ml-auto font-semibold text-accent hover:underline">
                  {OPEN_LEAD}
                </Link>
              </div>
            </li>
          ))}
          {sessions.map((s, i) => (
            <li
              key={`${s.source.machineKey}-${s.target.machineKey}-${s.port}-${i}`}
              data-testid="related-session"
              className={`break-words text-text-2 ${ROW}`}
              title={s.dataset || undefined}
            >
              <PartyLink party={s.source} /> to <PartyLink party={s.target} />
              {sessionTail(s)}
            </li>
          ))}
          {named.map((n) => (
            <li key={n.value} data-testid="related-named" className={`break-words text-text-2 ${ROW}`}>
              {namedSentence(n)}
            </li>
          ))}
          {falsePositives && (
            <li data-testid="related-false-positives" className={`text-text-2 ${ROW}`}>
              {falsePositives}
            </li>
          )}
        </ul>
      )}
    </>
  );
  if (embedded) return body;
  return (
    <Panel>
      <PanelHeader title="Related, not proven" />
      {body}
    </Panel>
  );
}

function RelatedRunRow({
  r,
  writes,
}: {
  r: CampaignRelatedRun;
  writes?: { campaignId: number; onChanged: (next: CampaignDetail) => void };
}) {
  const [confirming, setConfirming] = useState(false);
  return (
    <li data-testid={`related-run-${r.runId}`} className={ROW}>
      <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
        <VerdictPill verdict="needs_more_info" showConf={false} />
        <Link to={runHref(r.runId)} className="break-words text-accent hover:underline">
          {r.label}
        </Link>
        {(r.sourceAddress || r.targetAddress) && (
          <span className="font-mono text-[11.5px] text-dim">
            {`${r.sourceAddress ?? UNKNOWN} to ${r.targetAddress ?? UNKNOWN}`}
          </span>
        )}
        {r.finishedAt && <span className="font-mono text-[11.5px] text-faint">{utcStamp(r.finishedAt)}</span>}
        {writes && !confirming && (
          <button
            type="button"
            data-testid="related-include"
            onClick={() => setConfirming(true)}
            aria-label={`${INCLUDE_ACTION}: ${r.label}`}
            className={`ml-auto ${ROW_BUTTON}`}
          >
            {INCLUDE_ACTION}
          </button>
        )}
      </div>
      {writes && confirming && (
        <div className="mt-2">
          <RowConfirm
            testId="related-include-confirm"
            sentence={INCLUDE_CONFIRM}
            action={INCLUDE_ACTION}
            needsReason
            write={(reason) => includeInCampaign(writes.campaignId, { runId: r.runId, reason })}
            onDone={(next) => {
              setConfirming(false);
              writes.onChanged(next);
            }}
            onCancel={() => setConfirming(false)}
          />
        </div>
      )}
    </li>
  );
}
