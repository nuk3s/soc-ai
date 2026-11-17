import type { CampaignChange } from '../../lib/api';
import { changeSentence } from '../../lib/campaignWords';
import { stageColor } from '../../lib/campaignViz';
import { utcStamp } from '../../lib/timeRange';

/** The dot of a change: the stage color for a new stage, the warning tone
 *  for a reopen and a refused case, the danger tone for an investigation
 *  beyond the authorization, the accent for a new machine, an include and a
 *  case, and a neutral tone for the rest. A close reads calm. */
function dotColor(c: CampaignChange): string {
  switch (c.type) {
    case 'stage':
      return stageColor(c.detail?.to ?? null);
    case 'reopened':
      return 'rgb(var(--warn))';
    case 'beyond':
      return 'rgb(var(--danger))';
    case 'party':
    case 'included':
    case 'case':
      return 'rgb(var(--accent))';
    case 'case_failed':
      return 'rgb(var(--warn))';
    default:
      return 'rgb(var(--dim))';
  }
}

/** Every change of the campaign in words, newest first: the time, a dot in
 *  the tone of the change and one sentence. The list sits in the Changes
 *  fold of the campaign page. */
export function CampaignChanges({
  changes,
  labels = {},
}: {
  changes: readonly CampaignChange[];
  /** The label of each investigation, by its id, for the changes that name one. */
  labels?: Readonly<Record<string, string>>;
}) {
  return (
    <ol data-testid="campaign-changes" className="flex flex-col px-[15px] py-2">
      {changes.map((c) => (
        <li
          key={c.id}
          data-testid="campaign-change"
          data-type={c.type}
          className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 border-b border-border-faint py-1.5 last:border-b-0"
        >
          <span
            data-testid="campaign-change-at"
            className="w-[150px] flex-none whitespace-nowrap font-mono text-[11.5px] text-faint"
          >
            {utcStamp(c.at)}
          </span>
          <span className="flex min-w-0 flex-[1_1_18rem] items-baseline gap-2">
            <span
              aria-hidden
              data-testid="campaign-change-dot"
              className="h-[7px] w-[7px] flex-none translate-y-[-1px] rounded-full"
              style={{ background: dotColor(c) }}
            />
            <span data-testid="campaign-change-words" className="min-w-0 break-words text-[12.5px] text-text-2">
              {changeSentence(c, labels)}
            </span>
          </span>
        </li>
      ))}
    </ol>
  );
}
