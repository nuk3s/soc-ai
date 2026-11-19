import { Network } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { HostCampaign, ThreatCampaign } from '../../lib/api';
import { alertsWords, gridReadWords, hostRoleLabel, lastActivityOf } from '../../lib/campaignWords';

import { THREAT_CAMPAIGN_AUTHORIZED } from '../../lib/tooltips';
import { CampaignStateChip } from './shared';
import { StageMeter } from './StageMeter';
import { UtcTime } from '../UtcTime';

/** The campaigns of a machine on its host page, newest last event first. One
 *  line for each: the stage meter, the title as the link, the one state
 *  chip, the role of the machine in words, the period and the alerts.
 *
 *  The campaign waits on a decision, and its investigations do not: the
 *  state chip states the decision, or Open or Ended in the warning tone while
 *  the campaign waits. A count of the
 *  investigations that wait can no longer show, because the server counts
 *  none for an investigation that a campaign holds.
 *
 *  `threats` holds the campaigns of the confirmed threats of the host. A
 *  campaign there adds the investigations that an authorization holds, so
 *  the host page names each campaign once. No campaign renders nothing. */
export function HostCampaigns({
  campaigns,
  threats = [],
  className = 'mb-3',
}: {
  campaigns: HostCampaign[] | undefined;
  threats?: ThreatCampaign[];
  className?: string;
}) {
  if (!campaigns?.length) return null;
  const counts = new Map(threats.map((t) => [t.id, t]));
  return (
    <section
      data-testid="host-campaigns"
      aria-labelledby="host-campaigns-title"
      className={`rounded-card border border-border bg-surface-1 px-3.5 py-2.5 ${className}`}
    >
      <h2
        id="host-campaigns-title"
        className="mb-1.5 flex items-center gap-1.5 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint"
      >
        <Network size={12} aria-hidden />
        Campaigns
      </h2>
      <ul className="flex flex-col gap-1.5">
        {campaigns.map((c) => {
          const threat = counts.get(c.id);
          return (
            <li
              key={c.id}
              data-testid="host-campaign"
              className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px]"
            >
              <StageMeter stage={c.stage} />
              <Link
                to={`/campaigns/${c.id}`}
                className="min-w-0 break-words text-[13px] font-semibold text-text hover:text-accent hover:underline"
              >
                {c.title}
              </Link>
              <CampaignStateChip campaign={c} />
              <span data-testid="host-campaign-role" className="text-text-2">
                {hostRoleLabel(c.role)}
              </span>
              <span data-testid="host-campaign-period" className="font-mono text-[11.5px] text-dim">
                <UtcTime iso={c.firstEvent} to={lastActivityOf(c)} seconds={false} />
              </span>
              {typeof c.alerts === 'number' && (
                <span data-testid="host-campaign-alerts" className="text-dim">
                  {`${alertsWords(c.alerts)}${gridReadWords(c)}`}
                </span>
              )}
              {threat && threat.authorized > 0 && (
                <span data-testid="host-campaign-authorized" title={THREAT_CAMPAIGN_AUTHORIZED} className="text-faint">
                  {threat.authorized.toLocaleString()} authorized
                </span>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
