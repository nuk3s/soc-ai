import { useState } from 'react';
import { Link } from 'react-router-dom';

import { getGridGapHits, markGridGapHitsBenign, setAnalyticStatus } from '../lib/api';
import { entityPath } from '../lib/entityPath';
import { utcStamp, utcWindow } from '../lib/leadWords';
import { plural } from '../lib/plural';
import type { GridGapBenignResult, GridGapHit, GridGapHits, GridGapHold } from '../lib/types';
import { useAsync } from '../lib/useAsync';
import { Drawer } from './Drawer';
import { LoadingInline } from './States';

// ---------------------------------------------------------------------------
// The review of one grid gap.
//
// The range grid was down from Oct 15 13:36 UTC to Oct 19 10:15 UTC. The first
// sweep after it wrote five "connection rate collapsed" hits and three "plane
// falls silent" hits for hours inside the outage. One joined a lead, and the
// daily hit limit held a live analytic in shadow. The operator opened every
// hit and marked it benign, 24 actions, and found the cause of the hold alone
// (dogfood 2026-10-19, R1-I5, R3-I1, R3-I2, R4-I3).
//
// The drawer lists the hits the gap wrote, marks them benign in one write
// after a confirm that states the counts, and names each analytic that the
// gap hits held. Return to live is a separate click on the approve route.
// soc-ai never moves the analytic by itself. The observation mark has no
// undo, so the result offers none.
//
// Round 2 (G-1): the range review listed 12 hits, and one confirm marked all
// of them, two rate spikes and a collapse that ran on after the recovery among
// them. Each hit now has a check box. The server selects a hit whose events
// lie inside the gap and that is not a spike, and states the reason for each hit
// it leaves out. The mark writes only the checked hits.
// ---------------------------------------------------------------------------

/** The reason Return to live records on the version row. */
export const RETURN_TO_LIVE_WHY =
  'The hits that broke the daily hit limit fall inside a grid gap.';

/** "5 of the 5 hits that broke the daily hit limit fall inside a grid gap." */
export function gapHoldLine(hold: GridGapHold): string {
  const verb = hold.gap_hits === 1 ? 'falls' : 'fall';
  return (
    `${hold.gap_hits} of the ${plural(hold.hits, 'hit')} that broke the daily hit limit ` +
    `${verb} inside a grid gap.`
  );
}

/** What the gap hits mean for the hold, in one sentence. */
export function gapHoldOffer(hold: GridGapHold): string {
  const others = Math.max(0, hold.hits - hold.gap_hits);
  if (hold.return_offered) {
    return `Without them, the analytic stays inside its limit of ${plural(hold.budget, 'hit')} a day.`;
  }
  // A gap does not explain a spike, so the server counts a spike inside the
  // gap against the limit. Say that, before the other reasons.
  const spikes = hold.spike_hits ?? 0;
  if (spikes > 0 && others <= hold.budget) {
    return (
      `A gap does not explain the ${plural(spikes, 'spike')}. ` +
      'Check for a back-fill burst before you approve the analytic.'
    );
  }
  if (others <= hold.budget) {
    return 'The hold names another breach too. Read it under Versions.';
  }
  return `The other ${plural(others, 'hit')} alone break the limit of ${plural(hold.budget, 'hit')} a day.`;
}

/** Return to live for one held analytic. One explicit click on the approve
 *  route, with a reason on record. Nothing calls it for the operator. */
export function ReturnToLive({ hold, onDone }: { hold: GridGapHold; onDone?: () => void }) {
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);
  const go = async () => {
    setBusy(true);
    setFailed(null);
    try {
      await setAnalyticStatus(hold.analytic_id, 'live', RETURN_TO_LIVE_WHY);
      setDone(true);
      onDone?.();
    } catch (e) {
      setFailed(e instanceof Error && e.message ? e.message : 'The analytic did not move.');
    } finally {
      setBusy(false);
    }
  };
  if (done) {
    return (
      <div data-testid="return-to-live-done" className="text-[11.5px] text-text-2">
        The analytic is live again.
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-1">
      <button
        type="button"
        disabled={busy}
        onClick={() => void go()}
        data-testid={`return-to-live-${hold.analytic_id}`}
        title="Approve the analytic to live. soc-ai does not do this for you."
        className="self-start whitespace-nowrap rounded-control border border-border-strong px-2.5 py-1 text-[11.5px] font-semibold hover:bg-surface-2 disabled:opacity-50"
      >
        Return to live
      </button>
      {failed && <div className="text-[11.5px] text-warn">{failed}</div>}
    </div>
  );
}

function HoldRow({ hold, onChanged }: { hold: GridGapHold; onChanged: () => void }) {
  return (
    <li data-testid={`gap-hold-${hold.analytic_id}`} className="flex flex-col gap-1 py-2 text-[12px]">
      <span className="font-semibold">{hold.title}</span>
      <span className="text-text-2">{gapHoldLine(hold)}</span>
      <span className="text-dim">{gapHoldOffer(hold)}</span>
      {hold.return_offered && <ReturnToLive hold={hold} onDone={onChanged} />}
    </li>
  );
}

function gapWords(review: GridGapHits): string {
  const { gap } = review;
  if (gap.open || !gap.ended_at) {
    return `The grid has held no data since ${utcStamp(gap.started_at)}.`;
  }
  return `The grid held no data from ${utcWindow(gap.started_at, gap.ended_at)}.`;
}

/** The review selects a hit by default. An older server sends no selection
 *  and marked every hit, so its hits read as selected. */
export function selectedByDefault(hit: GridGapHit): boolean {
  return hit.selected_by_default ?? true;
}

/** "Mark 3 hits benign", or "Mark 3 of 5 hits benign" when some stay out. */
export function markLabel(selected: number, count: number): string {
  if (selected === count) return `Mark ${plural(count, 'hit')} benign`;
  return `Mark ${selected} of ${plural(count, 'hit')} benign`;
}

function MarkControl({
  review,
  ids,
  onMarked,
}: {
  review: GridGapHits;
  ids: number[];
  onMarked: (result: GridGapBenignResult) => void;
}) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);
  const picked = new Set(ids);
  const leads = new Set(
    review.hits
      .filter((hit) => picked.has(hit.id) && hit.lead_id !== null)
      .map((hit) => hit.lead_id),
  ).size;
  const rest = Math.max(0, review.count - ids.length);
  const confirm = async () => {
    setBusy(true);
    setFailed(null);
    try {
      onMarked(await markGridGapHitsBenign(review.gap.id, ids, ids.length));
      setConfirming(false);
    } catch (e) {
      setFailed(e instanceof Error && e.message ? e.message : 'soc-ai marked no hit.');
    } finally {
      setBusy(false);
    }
  };
  if (!confirming || ids.length === 0) {
    return (
      <button
        type="button"
        disabled={ids.length === 0}
        onClick={() => setConfirming(true)}
        data-testid="gap-mark-benign"
        title={ids.length === 0 ? 'Select a hit to mark it benign.' : undefined}
        className="self-start rounded-control bg-accent px-3 py-1 text-[12px] font-semibold text-white disabled:opacity-50"
      >
        {markLabel(ids.length, review.count)}
      </button>
    );
  }
  return (
    <div
      data-testid="gap-mark-confirm"
      className="flex flex-col gap-1.5 rounded-panel border border-border-strong px-3 py-2 text-[12px]"
    >
      <div>{`soc-ai marks ${plural(ids.length, 'hit')} benign with the note "${review.note}".`}</div>
      {rest > 0 && (
        <div className="text-text-2">{`${plural(rest, 'hit')} ${rest === 1 ? 'stays' : 'stay'} unmarked.`}</div>
      )}
      {leads > 0 && (
        <div className="text-text-2">
          {`${plural(leads, 'lead')} ${leads === 1 ? 'holds' : 'hold'} some of these hits. ` +
            'The hits stay on their leads. Each lead weighs only the observations that remain.'}
        </div>
      )}
      <div className="text-text-2">No analytic changes status. You cannot undo the marks.</div>
      <div className="flex items-center gap-2">
        <button
          type="button"
          disabled={busy}
          onClick={() => void confirm()}
          className="rounded-control bg-accent px-3 py-1 font-semibold text-white disabled:opacity-50"
        >
          Confirm
        </button>
        <button type="button" onClick={() => setConfirming(false)} className="text-dim">
          Cancel
        </button>
      </div>
      {failed && <div className="text-[11.5px] text-warn">{failed}</div>}
    </div>
  );
}

function ReviewBody({
  review,
  onChanged,
}: {
  review: GridGapHits;
  onChanged: () => void;
}) {
  const [result, setResult] = useState<GridGapBenignResult | null>(null);
  // The analytics the operator returned to live here. The next read lists
  // them no more, so the drawer keeps the answer on screen.
  const [returned, setReturned] = useState<string[]>([]);
  // The operator's own choices by hit id. A hit with no choice keeps the
  // selection of the server, so a second read keeps what the operator set.
  const [chosen, setChosen] = useState<Record<number, boolean>>({});
  const closed = !review.gap.open && !!review.gap.ended_at;
  const isSelected = (hit: GridGapHit) => chosen[hit.id] ?? selectedByDefault(hit);
  // The hits a mark wrote leave the list at once. The read after the mark
  // drops them too, and the hits the operator left out stay for a second mark.
  const marked = new Set(result?.ids ?? []);
  const hits = review.hits.filter((hit) => !marked.has(hit.id));
  const left = Math.max(0, review.count - (review.hits.length - hits.length));
  const shown: GridGapHits = { ...review, count: left, hits };
  const ids = hits.filter(isSelected).map((hit) => hit.id);
  return (
    <div className="flex flex-col gap-4 p-4 text-[12.5px]">
      <div className="flex flex-col gap-1">
        <div className="font-semibold">{gapWords(review)}</div>
        <div className="text-text-2">
          {'The list holds the hits that measure a count or a silence. Their events overlap the ' +
            `gap or the ${plural(review.settle_minutes, 'minute')} after it.`}
        </div>
        <div className="text-text-2">
          soc-ai selects each hit whose events lie inside that time. It does not select a spike.
        </div>
        <div className="text-dim">A hit on matched documents is not on the list. Its documents exist.</div>
      </div>

      <div>
        <div className="mb-1.5 text-[13px] font-semibold">{`Hits · ${left}`}</div>
        {left === 0 ? (
          <div data-testid="gap-no-hits" className="text-dim">
            No hit of this gap waits for a review.
          </div>
        ) : (
          <ul data-testid="gap-hits" className="divide-y divide-border-faint">
            {hits.map((hit) => (
              <li key={hit.id} className="flex flex-wrap items-center gap-x-2 gap-y-0.5 py-1.5">
                {closed && (
                  <input
                    type="checkbox"
                    checked={isSelected(hit)}
                    onChange={(e) => {
                      const on = e.target.checked;
                      setChosen((now) => ({ ...now, [hit.id]: on }));
                    }}
                    aria-label={`Select the ${hit.kind_label} hit on ${hit.entity_key}`}
                    data-testid={`gap-hit-select-${hit.id}`}
                  />
                )}
                <span className="font-semibold">{hit.analytic_title}</span>
                <Link
                  to={entityPath(hit.entity_kind, hit.entity_key)}
                  className="font-mono text-[12px] text-accent hover:underline"
                >
                  {hit.entity_key}
                </Link>
                <span className="text-dim">{hit.kind_label}</span>
                {hit.recorded_in_shadow && <span className="text-[11px] text-warn">shadow</span>}
                {hit.lead_id !== null && (
                  <Link to={`/leads/${hit.lead_id}`} className="text-[11.5px] text-accent hover:underline">
                    {`in lead ${hit.lead_id}`}
                  </Link>
                )}
                <span className="basis-full text-[11.5px] text-dim">
                  {`Events ${utcWindow(hit.event_start, hit.event_end)}.`}
                </span>
                {(hit.reasons ?? []).map((reason) => (
                  <span key={reason} className="basis-full text-[11.5px] text-warn">
                    {reason}
                  </span>
                ))}
              </li>
            ))}
          </ul>
        )}
        {left > hits.length && (
          <div className="mt-1 text-[11.5px] text-dim">
            {`The list shows the first ${hits.length} hits. ` +
              'Open the review again after the mark to read the rest.'}
          </div>
        )}
      </div>

      {result && (
        <div data-testid="gap-mark-result" role="status" className="text-text-2">
          {`soc-ai marked ${plural(result.marked, 'hit')} benign.`}
        </div>
      )}
      {left > 0 &&
        (closed ? (
          <MarkControl
            review={shown}
            ids={ids}
            onMarked={(r) => {
              setResult(r);
              onChanged();
            }}
          />
        ) : (
          <div className="text-dim">The gap is open. Review its hits after the grid comes back.</div>
        ))}

      {(review.held.length > 0 || returned.length > 0) && (
        <div>
          <div className="mb-1 text-[13px] font-semibold">Analytics soc-ai held</div>
          {returned.map((title) => (
            <div key={title} data-testid="gap-returned" role="status" className="text-text-2">
              {`The analytic "${title}" is live again.`}
            </div>
          ))}
          <ul data-testid="gap-holds" className="divide-y divide-border-faint">
            {review.held.map((hold) => (
              <HoldRow
                key={hold.analytic_id}
                hold={hold}
                onChanged={() => {
                  setReturned((now) => (now.includes(hold.title) ? now : [...now, hold.title]));
                  onChanged();
                }}
              />
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

/** The review drawer of one gap. `gapId` null keeps it closed. `onChanged`
 *  runs after a mark or a Return to live, so the opener can read again. */
export function GridGapReviewDrawer({
  gapId,
  onClose,
  onChanged,
}: {
  gapId: number | null;
  onClose: () => void;
  onChanged?: () => void;
}) {
  const review = useAsync(
    () => (gapId !== null ? getGridGapHits(gapId) : Promise.resolve(null)),
    [gapId],
  );
  const changed = () => {
    review.refetch();
    onChanged?.();
  };
  return (
    <Drawer
      open={gapId !== null}
      onClose={onClose}
      ariaLabel="Hits in a grid gap"
      header={<span className="text-[13.5px] font-semibold">Hits in a grid gap</span>}
    >
      {review.data ? (
        <ReviewBody key={review.data.gap.id} review={review.data} onChanged={changed} />
      ) : (
        <div className="p-4 text-[12.5px] text-dim">
          {review.error ? 'Could not read the gap.' : <LoadingInline>Reading the gap</LoadingInline>}
        </div>
      )}
    </Drawer>
  );
}

/** The grid-gap lines of a hold card in the Analytics drawer: how many of the
 *  hits that broke the limit fall inside a grid gap, Return to live when the
 *  gap hits alone broke it, and the review of the gap. The hold card said why
 *  soc-ai held the analytic and never said the hits came from an outage. */
export function GapHoldNote({ hold, onChanged }: { hold: GridGapHold; onChanged?: () => void }) {
  const [reviewing, setReviewing] = useState<number | null>(null);
  // A hold whose hits span two gaps names the oldest. One review clears it,
  // and the strip on the pages names the other.
  const gapId = hold.gap_ids[0] ?? null;
  return (
    <div data-testid="analytic-held-gap" className="mt-1.5 flex flex-col gap-1">
      <div className="text-text-2">{gapHoldLine(hold)}</div>
      <div className="text-dim">{gapHoldOffer(hold)}</div>
      <div className="flex flex-wrap items-center gap-2">
        {hold.return_offered && <ReturnToLive hold={hold} onDone={onChanged} />}
        {gapId !== null && (
          <button
            type="button"
            onClick={() => setReviewing(gapId)}
            data-testid="analytic-held-gap-review"
            className="self-start text-[11.5px] font-semibold text-accent hover:underline"
          >
            Review the hits in this grid gap
          </button>
        )}
      </div>
      {reviewing !== null && (
        <GridGapReviewDrawer
          gapId={reviewing}
          onClose={() => setReviewing(null)}
          onChanged={onChanged}
        />
      )}
    </div>
  );
}
