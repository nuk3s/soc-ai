import { Link, useSearchParams } from 'react-router-dom';
import {
  CampaignBeyondChip,
  CampaignDecisionChip,
  CampaignStageChip,
  CampaignStatusChip,
  PartyLinks,
} from '../components/campaign/shared';
import { StageMeter } from '../components/campaign/StageMeter';
import { UNKNOWN, UNKNOWN_TONE } from '../components/Kpi';
import { Panel } from '../components/Panel';
import { EmptyState, ErrorState, LoadingState, StaleNotice } from '../components/States';
import { getCampaigns, type CampaignList, type CampaignRow } from '../lib/api';
import { decisionState } from '../lib/campaignDecision';
import { CAMPAIGNS_EMPTY, CAMPAIGNS_NONE_WAIT, FILTER_ALL, FILTER_WAITS, moreWords } from '../lib/campaignWords';
import { utcWindow } from '../lib/timeRange';
import { useAsync } from '../lib/useAsync';
import { useTabTitle } from '../lib/useTabTitle';

// ---------------------------------------------------------------------------
// Campaigns: one row for each active campaign, newest last event first. The
// last column counts the alert events of the campaign. A campaign with no
// stored events, or a server of an earlier release, shows the unknown mark there.
//
// The page is read-only. The engine builds the campaigns from the stored runs
// when the route is read, so the list polls once a minute and a rebuild that
// failed reads as a stale notice over the rows of the last build.
//
// Each row states its decision: "Waits on you" or the decision. The filter
// "Waits on you" (`?decision=waits`) holds the campaigns with no decision,
// the ones the Campaigns badge counts. A server with no decision field shows
// no filter and no chip.
// ---------------------------------------------------------------------------

const REFETCH_MS = 60_000;

const TH = 'px-2.5 py-2 text-left font-semibold';

const FILTER_BUTTON =
  'flex items-center gap-1.5 rounded-control border px-2.5 py-1 text-[12px] font-semibold';
const FILTER_ON = 'border-accent bg-accent/10 text-accent';
const FILTER_OFF = 'border-border-strong bg-surface-2 text-text-2 hover:text-text';

export function Campaigns() {
  useTabTitle('Campaigns');
  const list = useAsync<CampaignList>(() => getCampaigns(), [], { refetchInterval: REFETCH_MS });
  const [params, setParams] = useSearchParams();
  const waitsOnly = params.get('decision') === 'waits';
  const setWaitsOnly = (on: boolean) =>
    setParams(
      (p) => {
        const next = new URLSearchParams(p);
        if (on) next.set('decision', 'waits');
        else next.delete('decision');
        return next;
      },
      { replace: true },
    );

  if (list.loading && !list.data) return <LoadingState label="Reading the campaigns" />;
  if (list.error && !list.data) {
    return <ErrorState error={list.error} onRetry={list.refetch} label="the campaigns" />;
  }
  if (!list.data) return null;
  const { rows: all, stale } = list.data;
  // An older server sends no decision on any row: no filter then.
  const decided = all.some((r) => r.decision !== undefined);
  const waiting = all.filter((r) => decisionState(r) === 'waits');
  const filtered = decided && waitsOnly;
  const rows = filtered ? waiting : all;

  return (
    <div className="p-5">
      {list.error ? (
        <StaleNotice
          since={list.lastUpdated}
          reason="refresh-failed"
          retrying
          onRefresh={list.refetch}
          className="mb-3"
        />
      ) : (
        // The rebuild failed and the rows are the rows of the last build.
        // The list carries no build time, so the notice states none.
        stale && <StaleNotice since={null} onRefresh={list.refetch} className="mb-3" />
      )}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <h1 className="text-[19px] font-semibold">Campaigns</h1>
        {decided && (
          <div data-testid="campaigns-filter" role="group" aria-label="Filter" className="flex flex-wrap gap-1.5">
            <button
              type="button"
              aria-pressed={!filtered}
              onClick={() => setWaitsOnly(false)}
              className={`${FILTER_BUTTON} ${filtered ? FILTER_OFF : FILTER_ON}`}
            >
              {FILTER_ALL}
              <span className="font-mono tabular-nums">{all.length.toLocaleString()}</span>
            </button>
            <button
              type="button"
              aria-pressed={filtered}
              onClick={() => setWaitsOnly(true)}
              className={`${FILTER_BUTTON} ${filtered ? FILTER_ON : FILTER_OFF}`}
            >
              {FILTER_WAITS}
              <span className="font-mono tabular-nums">{waiting.length.toLocaleString()}</span>
            </button>
          </div>
        )}
      </div>
      <Panel className="mt-3">
        {rows.length === 0 ? (
          <div data-testid="campaigns-empty">
            <EmptyState>{filtered && all.length > 0 ? CAMPAIGNS_NONE_WAIT : CAMPAIGNS_EMPTY}</EmptyState>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table data-testid="campaigns-table" className="w-full text-[12.5px]">
              <thead className="border-b border-border bg-surface-2 text-[10.5px] uppercase tracking-[.06em] text-faint">
                <tr>
                  <th scope="col" className="px-[15px] py-2 text-left font-semibold">
                    Campaign
                  </th>
                  <th scope="col" className={TH}>
                    Status
                  </th>
                  <th scope="col" className={TH}>
                    Stage
                  </th>
                  <th scope="col" className={TH}>
                    Actors
                  </th>
                  <th scope="col" className={TH}>
                    Targets
                  </th>
                  <th scope="col" className={TH}>
                    Period
                  </th>
                  <th scope="col" className="px-[15px] py-2 text-right font-semibold">
                    Alerts
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <CampaignListRow key={row.id} row={row} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}

function CampaignListRow({ row }: { row: CampaignRow }) {
  const more = moreWords(row.targetsMore);
  return (
    <tr data-testid={`campaign-row-${row.id}`} className="border-b border-border-faint align-top last:border-b-0">
      <td className="px-[15px] py-2.5">
        <Link
          to={`/campaigns/${row.id}`}
          className="break-words font-semibold text-accent hover:underline"
        >
          {row.title}
        </Link>
      </td>
      <td className="px-2.5 py-2.5">
        <span className="flex flex-wrap items-center gap-1.5">
          <CampaignStatusChip status={row.status} />
          <CampaignDecisionChip campaign={row} />
          <CampaignBeyondChip beyond={row.beyond} />
        </span>
      </td>
      <td data-testid="campaign-row-stage" className="px-2.5 py-2.5">
        <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <StageMeter stage={row.stage} />
          <CampaignStageChip stage={row.stage} />
        </span>
      </td>
      <td data-testid="campaign-actors" className="break-words px-2.5 py-2.5">
        <PartyLinks parties={row.actors} />
      </td>
      <td data-testid="campaign-targets" className="break-words px-2.5 py-2.5">
        <PartyLinks parties={row.targets} />
        {more && <span className="text-dim">{` ${more}`}</span>}
      </td>
      <td className="px-2.5 py-2.5 font-mono text-[11.5px] text-text-2">
        {utcWindow(row.firstEvent, row.lastEvent)}
      </td>
      <td data-testid="campaign-row-alerts" className="px-[15px] py-2.5 text-right font-mono">
        {typeof row.alerts === 'number' ? (
          row.alerts.toLocaleString()
        ) : (
          <span className={UNKNOWN_TONE}>{UNKNOWN}</span>
        )}
      </td>
    </tr>
  );
}
