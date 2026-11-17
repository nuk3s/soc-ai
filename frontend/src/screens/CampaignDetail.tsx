import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { CampaignView } from '../components/campaign/CampaignView';
import { ErrorState, LoadingState, NotFoundState, StaleNotice } from '../components/States';
import { ApiError, getCampaign, isNotFound, type CampaignDetail as CampaignDetailT } from '../lib/api';
import { useAsync } from '../lib/useAsync';
import { useTabTitle } from '../lib/useTabTitle';
import { useOptionalShell } from '../shell/ShellContext';

// ---------------------------------------------------------------------------
// One campaign. The page loads it and gates the states. CampaignView draws
// the campaign: the graphics first, then the folds that hold the tables. Each
// part is one file under components/campaign/.
//
// The engine rebuilds the campaign when the route is read and the store
// changed, so the page reads again once a minute. A merged or a withdrawn
// campaign has empty lists, and the page shows its header only. The one write
// is the decision: a close or an Open again answers with the campaign after
// it, and the page shows that answer until the next read lands.
// ---------------------------------------------------------------------------

const REFETCH_MS = 60_000;

export function CampaignDetail() {
  const { id = '' } = useParams();
  // A campaign id is a positive integer. Anything else is a wrong link: the
  // page answers it as not found and sends no request.
  const validId = /^\d+$/.test(id) && Number(id) > 0;
  const campaignId = Number(id);
  const campaign = useAsync<CampaignDetailT>(
    () =>
      validId
        ? getCampaign(campaignId)
        : Promise.reject(new ApiError(`Campaign ${id} not found`, 404, 'campaign_not_found')),
    [id],
    { refetchInterval: validId ? REFETCH_MS : 0 },
  );
  // The answer of the last decision, and the moment it landed. A read that
  // lands after it is newer and wins.
  const [decided, setDecided] = useState<{ data: CampaignDetailT; at: number } | null>(null);
  const fresh =
    decided && decided.data.id === campaignId && decided.at > (campaign.lastUpdated ?? 0) ? decided.data : null;
  const d = fresh ?? campaign.data;
  useTabTitle(d ? `Campaign ${d.id}` : validId ? `Campaign ${campaignId}` : null);
  // The top bar names the campaign by its number. The title holds the names
  // of the parties and is long: the top bar broke it inside a word at 900 px.
  // The header of the page states the title.
  const setCrumbName = useOptionalShell()?.setCrumbName;
  const crumb = d ? `Campaign ${d.id}` : null;
  useEffect(() => {
    if (!setCrumbName || !crumb) return;
    setCrumbName({ key: id, name: crumb });
    return () => setCrumbName(null);
  }, [setCrumbName, id, crumb]);

  if (campaign.loading && !d) return <LoadingState label="Reading the campaign" />;
  // A 404 is an answer, and a Retry of it fails again. Any other failure keeps
  // the error card and its Retry.
  if (campaign.error && !d) {
    return isNotFound(campaign.error) ? (
      <NotFoundState what="campaign" id={id} backTo="/campaigns" backLabel="Back to campaigns" />
    ) : (
      <ErrorState error={campaign.error} onRetry={campaign.refetch} label="this campaign" />
    );
  }
  if (!d) return null;
  const builtAt = Date.parse(d.builtAt);

  return (
    <div className="p-5">
      {campaign.error ? (
        // The re-read failed. The page keeps the campaign it read before.
        <StaleNotice
          since={campaign.lastUpdated}
          reason="refresh-failed"
          retrying
          onRefresh={campaign.refetch}
          className="mb-3"
        />
      ) : (
        // The rebuild failed. The campaign is the campaign of the last build.
        d.stale && (
          <StaleNotice
            since={Number.isNaN(builtAt) ? null : builtAt}
            onRefresh={campaign.refetch}
            className="mb-3"
          />
        )
      )}
      {/* The key resets the selection, the folds and the member filter when
          a link opens another campaign. */}
      <CampaignView key={d.id} campaign={d} onDecided={(next) => setDecided({ data: next, at: Date.now() })} />
    </div>
  );
}
