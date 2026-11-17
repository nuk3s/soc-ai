import type { CampaignDetection } from '../../lib/api';
import { STAGE_ORDER, detectionSentence, stageLabel } from '../../lib/campaignWords';
import { Panel, PanelHeader } from '../Panel';

/** For each reached stage: the tier that saw it first, and the time from the
 *  event to the verdict. Lowest stage first. No row renders nothing.
 *  `embedded` drops the panel and the title: a fold of the page holds them. */
export function DetectionRecord({ detection, embedded = false }: { detection: CampaignDetection[]; embedded?: boolean }) {
  if (detection.length === 0) return null;
  const rank = (r: CampaignDetection) => {
    const i = STAGE_ORDER.indexOf(r.stage);
    return i < 0 ? STAGE_ORDER.length : i;
  };
  const rows = [...detection].sort((a, b) => rank(a) - rank(b));
  const body = (
    <ul data-testid="detection-record" className="divide-y divide-border-faint">
      {rows.map((r) => (
        <li
          key={r.stage}
          data-testid={`detection-${r.stage}`}
          className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-[15px] py-2.5 text-[12.5px]"
        >
          <span className="font-semibold text-text">{stageLabel(r.stage)}</span>
          <span className="text-text-2">{detectionSentence(r)}</span>
        </li>
      ))}
    </ul>
  );
  if (embedded) return body;
  return (
    <Panel>
      <PanelHeader title="Detection record" />
      {body}
    </Panel>
  );
}
