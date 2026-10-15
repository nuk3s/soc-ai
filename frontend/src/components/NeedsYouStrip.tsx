import { useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';

import { getNeedsYou, onNeedsYouChanged } from '../lib/api';
import { plural } from '../lib/plural';
import { useAsync } from '../lib/useAsync';
import { LoadingInline, StaleNotice } from './States';

// ---------------------------------------------------------------------------
// Needs you — the first line of the Hunts page.
//
// The page reads top to bottom as the pipeline. This line states how much of it
// waits on the analyst, and each link jumps to the block that holds the work
// with its filter already set.
//
// Two rules hold the line honest. It never hides: a page that shows the strip
// only when something waits teaches the eye to skip it. And a failed read
// states the failure, because "nothing needs you" over a dead API is the false
// all-clear the whole surface exists to prevent.
// ---------------------------------------------------------------------------

/** The two blocks a link jumps to. The ids live on the blocks themselves. */
const HITS_ANCHOR = '#analytic-hits';
const LEADS_ANCHOR = '#leads';

export function NeedsYouStrip() {
  const [params] = useSearchParams();
  const needs = useAsync(getNeedsYou, [], { refetchInterval: 60_000 });
  // A hit read on this page, a hunt started from a lead and a dismissal all
  // move the count. The API emits the change, so the strip never holds a stale
  // number beside the block that changed it.
  useEffect(() => onNeedsYouChanged(needs.refetch), [needs.refetch]);

  /** The address of one block, with the filter set and the rest kept. */
  const to = (key: 'hits' | 'leads', value: string, hash: string) => {
    const next = new URLSearchParams(params);
    next.set(key, value);
    return { search: `?${next.toString()}`, hash };
  };

  const data = needs.data;
  // A failed first read states the failure. A poll failing after a good read
  // kept the last number with nothing to date it, so a dead API read as a fresh
  // count. Two consecutive failures is the house threshold: one missed poll is
  // a blip, and a marker on every hiccup is one an analyst stops reading.
  const stale = needs.failCount >= 2;

  return (
    <>
    <div
      data-testid="needs-you"
      className={`${stale ? 'mb-2' : 'mb-4'} flex flex-wrap items-center gap-x-2.5 gap-y-1 rounded-panel border border-border bg-surface-1 px-[15px] py-2.5`}
    >
      <span className="text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
        Needs you
      </span>
      {!data ? (
        <span className="text-[12.5px] text-dim">
          {needs.error ? 'Could not read what needs you.' : <LoadingInline>Reading what needs you</LoadingInline>}
        </span>
      ) : data.total === 0 ? (
        <>
          <span className="text-[13px] font-semibold text-text">Nothing needs you.</span>
          <span className="text-[11.5px] text-dim">
            No unread shadow hit. No lead waits on a decision.
          </span>
          <span data-testid="needs-you-scope" className="text-[11.5px] text-faint">
            The count covers all unread shadow hits and all open leads.
          </span>
        </>
      ) : (
        <>
          <span
            data-testid="needs-you-count"
            className="rounded-chip border border-accent/40 bg-accent/10 px-1.5 py-px text-[11px] font-semibold tabular-nums text-accent"
            title="Unread shadow hits, plus leads that wait on a decision."
          >
            {data.total}
          </span>
          {/* The strip does not read the page window, so each line states
              its scope in visible words. The hit count holds every unread
              hit, and the hits block lists the last 7 days, so the link
              names the 7 days it opens. */}
          {data.unread_shadow_hits > 0 && (
            <span data-testid="needs-you-hits" className="text-[12.5px]">
              <span className="text-text-2">
                {plural(data.unread_shadow_hits, 'shadow hit')}{' '}
                {data.unread_shadow_hits === 1 ? 'is' : 'are'} unread
              </span>
              <span className="text-faint"> · all unread · </span>
              <Link to={to('hits', 'unread', HITS_ANCHOR)} className="text-accent hover:underline">
                Read the last 7 days
              </Link>
            </span>
          )}
          {data.unread_shadow_hits > 0 && data.leads_needing_decision > 0 && (
            <span className="text-faint">·</span>
          )}
          {data.leads_needing_decision > 0 && (
            <span data-testid="needs-you-leads" className="text-[12.5px]">
              <Link
                to={to('leads', 'needs_decision', LEADS_ANCHOR)}
                className="text-accent hover:underline"
              >
                {plural(data.leads_needing_decision, 'lead')}{' '}
                {data.leads_needing_decision === 1 ? 'waits' : 'wait'} on a decision
              </Link>
              <span className="text-faint"> · all open</span>
            </span>
          )}
          <span className="text-[11.5px] text-faint">Each link jumps to the block below.</span>
        </>
      )}
    </div>
    {stale && (
      <StaleNotice
        since={needs.lastUpdated}
        onRefresh={needs.refetch}
        reason={needs.error ? 'refresh-failed' : 'stale'}
        retrying
        className="mb-4"
      />
    )}
    </>
  );
}
