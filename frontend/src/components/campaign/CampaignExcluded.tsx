import { useState } from 'react';
import { Link } from 'react-router-dom';
import { undoCampaignOverride, type CampaignDetail, type CampaignExcludedRun } from '../../lib/api';
import { UNDO_ACTION, UNDO_EXCLUDE_CONFIRM, excludedSentence } from '../../lib/campaignWords';
import { ROW_BUTTON, RowConfirm } from './RowWrite';
import { runHref } from './shared';

/** The investigations that an analyst excluded from the campaign, newest
 *  first: the investigation, who excluded it, when, the reason, and Undo. */
export function CampaignExcluded({
  excluded,
  campaignId,
  onChanged,
}: {
  excluded: readonly CampaignExcludedRun[];
  campaignId: number;
  onChanged: (next: CampaignDetail) => void;
}) {
  const rows = [...excluded].sort((a, b) => b.at.localeCompare(a.at));
  return (
    <ul data-testid="campaign-excluded" className="divide-y divide-border-faint">
      {rows.map((e) => (
        <ExcludedRow key={e.runId} e={e} campaignId={campaignId} onChanged={onChanged} />
      ))}
    </ul>
  );
}

function ExcludedRow({
  e,
  campaignId,
  onChanged,
}: {
  e: CampaignExcludedRun;
  campaignId: number;
  onChanged: (next: CampaignDetail) => void;
}) {
  const [confirming, setConfirming] = useState(false);
  return (
    <li data-testid={`excluded-${e.runId}`} className="px-[15px] py-2.5 text-[12.5px]">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <span className="min-w-0 flex-[1_1_22rem]">
          <Link to={runHref(e.runId)} className="break-words font-semibold text-accent hover:underline">
            {e.label}
          </Link>
          <span data-testid="excluded-words" className="mt-0.5 block break-words text-text-2">
            {excludedSentence(e)}
          </span>
        </span>
        {!confirming && (
          <button
            type="button"
            data-testid="excluded-undo"
            onClick={() => setConfirming(true)}
            aria-label={`${UNDO_ACTION}: ${e.label}`}
            className={ROW_BUTTON}
          >
            {UNDO_ACTION}
          </button>
        )}
      </div>
      {confirming && (
        <div className="mt-2">
          <RowConfirm
            testId="excluded-undo-confirm"
            sentence={UNDO_EXCLUDE_CONFIRM}
            action={UNDO_ACTION}
            needsReason={false}
            write={() => undoCampaignOverride(campaignId, e.runId)}
            onDone={(next) => {
              setConfirming(false);
              onChanged(next);
            }}
            onCancel={() => setConfirming(false)}
          />
        </div>
      )}
    </li>
  );
}
