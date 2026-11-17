import { Link } from 'react-router-dom';
import type { CampaignMember } from '../../lib/api';
import { VERDICT_STANDS } from '../../lib/campaignWords';
import { VerdictPill } from '../Badges';
import { Panel, PanelHeader } from '../Panel';
import { runHref } from './shared';

/** The investigations on a session of the campaign with another verdict.
 *  The engine changes no verdict, so each row states that its verdict stands.
 *  No such investigation renders nothing. `embedded` drops the panel and the
 *  title: a fold of the page holds them. */
export function CampaignVerdictsDiffer({ members, embedded = false }: { members: CampaignMember[]; embedded?: boolean }) {
  const rows = members.filter((m) => m.verdictDiffers);
  if (rows.length === 0) return null;
  const body = (
    <ul data-testid="campaign-verdicts-differ" className="divide-y divide-border-faint">
      {rows.map((m) => (
        <li
          key={m.runId}
          data-testid={`differs-${m.runId}`}
          className="flex flex-wrap items-center gap-x-2.5 gap-y-1 px-[15px] py-2.5 text-[12.5px]"
        >
          <VerdictPill verdict={m.verdict} showConf={false} />
          <Link to={runHref(m.runId)} className="break-words text-accent hover:underline">
            {m.label}
          </Link>
          <span className="text-dim">{VERDICT_STANDS}</span>
        </li>
      ))}
    </ul>
  );
  if (embedded) return body;
  return (
    <Panel>
      <PanelHeader title="Verdicts that differ" />
      {body}
    </Panel>
  );
}
