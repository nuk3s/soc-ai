import { AlertTriangle } from 'lucide-react';
import { Link } from 'react-router-dom';
import type { CampaignBeyondRun, CampaignParty } from '../../lib/api';
import { BEYOND_SHOW, BEYOND_TAIL, beyondSentence, beyondWhyWords, partyName } from '../../lib/campaignWords';
import { utcStamp } from '../../lib/timeRange';
import { UNKNOWN, UNKNOWN_TONE } from '../Kpi';
import { runHref } from './shared';

/** The one alarm of an authorized campaign, under the decision bar: the count
 *  of the investigations outside the authorization, in the danger tone, and
 *  a button that opens their fold. No investigation outside, no banner. */
export function BeyondBanner({
  beyond,
  onShow,
}: {
  beyond: readonly CampaignBeyondRun[] | undefined;
  onShow?: () => void;
}) {
  const n = beyond?.length ?? 0;
  if (n === 0) return null;
  return (
    <div
      data-testid="campaign-beyond-banner"
      className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-2 rounded-card border border-danger/55 bg-danger/[.10] px-3 py-2"
    >
      <AlertTriangle size={16} aria-hidden className="flex-none text-danger" />
      <span className="min-w-0 flex-[1_1_20rem] break-words text-[13px] leading-snug">
        <span data-testid="campaign-beyond-count" className="font-semibold text-danger">
          {beyondSentence(n)}
        </span>{' '}
        <span className="text-text-2">{BEYOND_TAIL}</span>
      </span>
      {onShow && (
        <button
          type="button"
          data-testid="campaign-beyond-show"
          onClick={onShow}
          className="flex-none whitespace-nowrap rounded-control border border-danger/60 bg-danger/[.12] px-3 py-1.5 text-[12.5px] font-semibold text-danger hover:bg-danger/[.2]"
        >
          {BEYOND_SHOW}
        </button>
      )}
    </div>
  );
}

/** The investigations outside the authorization, oldest event first: the
 *  event time, the investigation, the two machines and why it is outside. */
export function CampaignBeyond({
  beyond,
  parties,
}: {
  beyond: readonly CampaignBeyondRun[];
  parties: readonly CampaignParty[];
}) {
  const names = new Map(parties.map((p) => [p.machineKey, partyName(p)]));
  const name = (key: string | null) => (key ? (names.get(key) ?? key) : UNKNOWN);
  const rows = [...beyond].sort((a, b) => (a.eventAt ?? '').localeCompare(b.eventAt ?? ''));
  return (
    <ul data-testid="campaign-beyond" className="divide-y divide-border-faint">
      {rows.map((r) => (
        <li
          key={r.runId}
          data-testid={`beyond-${r.runId}`}
          data-why={r.why}
          className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-[15px] py-2.5 text-[12.5px]"
        >
          <span className="w-[150px] flex-none whitespace-nowrap font-mono text-[11.5px] text-text-2">
            {r.eventAt ? utcStamp(r.eventAt) : <span className={UNKNOWN_TONE}>{UNKNOWN}</span>}
          </span>
          <span className="min-w-0 flex-[1_1_22rem]">
            <Link to={runHref(r.runId)} className="break-words font-semibold text-accent hover:underline">
              {r.label}
            </Link>
            <span className="ml-2 break-words text-text-2">
              {name(r.sourceKey)} to {name(r.targetKey)}
            </span>
            <span data-testid="beyond-why" className="mt-0.5 block break-words font-semibold text-danger">
              {beyondWhyWords(r.why)}
            </span>
          </span>
        </li>
      ))}
    </ul>
  );
}
