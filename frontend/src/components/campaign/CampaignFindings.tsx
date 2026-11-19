import { Link } from 'react-router-dom';
import type { CampaignMember } from '../../lib/api';
import { VIEW_HUNT, stageLabel } from '../../lib/campaignWords';
import { utcStamp } from '../../lib/timeRange';
import { ImpactChip } from '../ConfirmedThreats';
import { FindingNameNote } from '../FindingNameNote';
import { UNKNOWN, UNKNOWN_TONE } from '../Kpi';
import { runHref } from './shared';

const TH = 'px-2.5 py-2 text-left font-semibold';

/** The true positive findings and leads of the campaign, oldest first. A
 *  finding with no time comes last. */
export function findingRows(members: readonly CampaignMember[]): CampaignMember[] {
  const at = (m: CampaignMember) => (m.eventAt ? Date.parse(m.eventAt) : Number.POSITIVE_INFINITY);
  return members
    .filter(
      (m) => !m.verdictDiffers && m.verdict === 'true_positive' && (m.kind === 'finding' || m.kind === 'lead'),
    )
    .sort((a, b) => at(a) - at(b) || a.runId.localeCompare(b.runId));
}

/** The hunt findings that prove the campaign: the time, the title as a link to
 *  its investigation and to its hunt, the impact and the stage. */
export function CampaignFindings({ members }: { members: CampaignMember[] }) {
  const rows = findingRows(members);
  if (rows.length === 0) return null;
  return (
    <div className="overflow-x-auto">
      <table data-testid="campaign-findings" className="w-full text-[12.5px]">
        <thead className="border-b border-border bg-surface-2 text-[10.5px] uppercase tracking-[.06em] text-faint">
          <tr>
            <th scope="col" className="px-[15px] py-2 text-left font-semibold">
              Time
            </th>
            <th scope="col" className={TH}>
              Finding
            </th>
            <th scope="col" className={TH}>
              Impact
            </th>
            <th scope="col" className="px-[15px] py-2 text-left font-semibold">
              Stage
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((m) => (
            <tr
              key={m.runId}
              data-testid={`finding-${m.runId}`}
              className="border-b border-border-faint align-top last:border-b-0"
            >
              <td className="whitespace-nowrap px-[15px] py-2.5 font-mono text-[11.5px] text-text-2">
                {m.eventAt ? utcStamp(m.eventAt, { seconds: true }) : <span className={UNKNOWN_TONE}>{UNKNOWN}</span>}
              </td>
              <td className="min-w-[14rem] px-2.5 py-2.5">
                <Link to={runHref(m.runId)} className="break-words text-accent hover:underline">
                  {m.label}
                </Link>
                <FindingNameNote note={m.nameNote} className="mt-1" />
                {m.huntId && (
                  <div className="mt-0.5">
                    <Link
                      to={`/hunts/${encodeURIComponent(m.huntId)}`}
                      className="text-[11.5px] font-semibold text-accent hover:underline"
                    >
                      {VIEW_HUNT}
                    </Link>
                  </div>
                )}
              </td>
              <td className="px-2.5 py-2.5">{m.impact && <ImpactChip impact={m.impact} />}</td>
              <td data-testid="finding-stage" className="px-[15px] py-2.5 text-text-2">
                {m.stage && stageLabel(m.stage)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
