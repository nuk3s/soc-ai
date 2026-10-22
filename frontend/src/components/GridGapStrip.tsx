import { AlertTriangle } from 'lucide-react';
import { useState } from 'react';

import { getGridGaps } from '../lib/api';
import { cn } from '../lib/cn';
import { plural } from '../lib/plural';
import { absoluteTime, rangeToSinceUntil } from '../lib/timeRange';
import type { GridGap } from '../lib/types';
import { useAsync } from '../lib/useAsync';
import { GridGapReviewDrawer } from './GridGapReview';
import type { CustomRange } from './TimeRangeFilter';

// ---------------------------------------------------------------------------
// The grid gap strip.
//
// The range grid was down from Oct 15 13:36 UTC to Oct 19 10:15 UTC. After it
// came back, every windowed page counted the hole as a quiet grid: zero alerts,
// zero hunts and flat host charts, with nothing on the page to say the grid
// had sent no data. The backend keeps a ledger of grid gaps. This strip names
// each gap that overlaps the page window, one line per gap.
//
// The strip states only a gap the server recorded. It shows nothing while the
// read loads, when the read fails, and when the window holds no gap. The grid
// health banner reports a failed read, and the strip does not repeat it.
//
// A closed gap that wrote hits offers "Review N hits in this gap". The link
// opens the review drawer (GridGapReview.tsx), where one confirm marks them
// benign. The first sweep after the range outage wrote eight false hits, and
// the operator marked them one by one (dogfood 2026-10-19, R3-I2, R4-I3).
// ---------------------------------------------------------------------------

/** The strip re-reads the ledger on this cadence, so an open gap closes on
 *  screen within a few minutes of the grid coming back. */
const REFETCH_MS = 300_000;

/** A gap edge in the console's one absolute format, with its zone:
 *  "2026-10-15 09:36 EDT". The strip said "Oct 18 14:00 UTC" above a
 *  Dashboard panel that said "2026-10-19 09:15 EDT" (dogfood 2026-10-19,
 *  V1-S5). */
export function gapTime(iso: string): string {
  return absoluteTime(iso);
}

/** The plane of a sweep gap as the console writes it. The server holds the
 *  same words (soc_ai.store.grid_gaps.plane_words). */
const PLANE_WORDS: Record<string, string> = { connection_rate: 'network flow' };

function planeWords(plane: string | null): string {
  if (!plane) return 'grid';
  return PLANE_WORDS[plane] ?? plane.replace(/_/g, ' ');
}

/** The note of an operator gap, with one stop at the end. */
function noteSentence(detail: string | null | undefined): string {
  const text = (detail ?? '').trim();
  if (!text) return '';
  return ` Note: ${/[.!?]$/.test(text) ? text : `${text}.`}`;
}

/** The length of a gap: whole hours from one hour up ("93 h"), else whole
 *  minutes ("45 min"). A gap the ledger recorded is never "0 min". */
export function gapDuration(seconds: number): string {
  if (seconds >= 3_600) return `${Math.round(seconds / 3_600)} h`;
  return `${Math.max(1, Math.round(seconds / 60))} min`;
}

/** The seconds of a gap. The server value is the source. The edges are the
 *  fallback for a row that does not carry it. */
function gapSeconds(gap: GridGap, now: number): number {
  if (Number.isFinite(gap.duration_s)) return gap.duration_s;
  const start = new Date(gap.started_at).getTime();
  const end = gap.ended_at ? new Date(gap.ended_at).getTime() : now;
  return Math.max(0, (end - start) / 1_000);
}

/** The line for one gap. It names the type of the gap, the way the bell and
 *  the hints do. The strip said "No grid data" over a sweep gap that the
 *  bell named "no network flow documents" (dogfood 2026-10-19, V1-S6).
 *
 *  probe: "The grid was unreadable from A to B (93 h)."
 *  sweep: "Most hosts sent no network flow documents from A to B (20 h)."
 *  operator: "An operator recorded a grid gap from A to B (93 h). Note: ..."
 *  Each line ends "Counts in this window are incomplete." An open gap reads
 *  "since A (93 h so far)". A source this build does not know reads "No
 *  grid data from A to B". */
export function gapSentence(gap: GridGap, now: number = Date.now()): string {
  const length = gapDuration(gapSeconds(gap, now));
  const open = gap.open || gap.ended_at == null;
  const span = open
    ? `since ${gapTime(gap.started_at)} (${length} so far)`
    : `from ${gapTime(gap.started_at)} to ${gapTime(gap.ended_at as string)} (${length})`;
  const tail = ' Counts in this window are incomplete.';
  switch (gap.source) {
    case 'probe':
      return `The grid ${open ? 'is' : 'was'} unreadable ${span}.${tail}`;
    case 'sweep':
      return `Most hosts ${open ? 'send' : 'sent'} no ${planeWords(gap.plane)} documents ${span}.${tail}`;
    case 'operator':
      return `An operator recorded a grid gap ${span}.${noteSentence(gap.detail)}${tail}`;
    default:
      return `No grid data ${span}.${tail}`;
  }
}

interface Props {
  /** The page window: a preset such as "24h", or "custom". */
  range: string;
  custom?: CustomRange | null;
  className?: string;
}

export function GridGapStrip({ range, custom, className }: Props) {
  // The window converts INSIDE the loader. A preset then keeps the same deps
  // on every render, and each poll re-anchors "now".
  const ledger = useAsync(
    () => getGridGaps(rangeToSinceUntil(range, custom)),
    [range, custom?.from, custom?.to],
    { refetchInterval: REFETCH_MS },
  );
  // The gap whose review drawer is open. The drawer sits outside the strip, so
  // a read of the ledger after a mark does not close it.
  const [reviewing, setReviewing] = useState<number | null>(null);
  // A test double or an older server can answer with another shape.
  const served = ledger.data?.gaps;
  const gaps = Array.isArray(served) ? served : [];
  const hidden = ledger.loading || ledger.error || gaps.length === 0;

  return (
    <>
      {!hidden && (
        <div
          role="status"
          data-testid="grid-gap-strip"
          data-tour="grid-gap"
          className={cn(
            'flex items-start gap-2 rounded-card border border-warn/30 bg-warn/[0.06] px-3.5 py-2.5 text-[12.5px] leading-[1.5] text-text-2',
            className,
          )}
        >
          <AlertTriangle size={14} className="mt-[3px] flex-none text-warn" />
          <div className="min-w-0 flex-1">
            {gaps.map((gap) => {
              const toReview = gap.open ? 0 : (gap.hits_to_review ?? 0);
              return (
                <div key={gap.id} data-testid="grid-gap" title={gap.detail}>
                  {gapSentence(gap)}
                  {toReview > 0 && (
                    <>
                      {' '}
                      <button
                        type="button"
                        data-testid="grid-gap-review"
                        onClick={() => setReviewing(gap.id)}
                        className="font-semibold text-accent hover:underline"
                      >
                        {`Review ${plural(toReview, 'hit')} in this gap`}
                      </button>
                    </>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
      {/* Mounted only while open: the drawer needs the shell, and a page
          with no gap to review needs nothing. */}
      {reviewing !== null && (
        <GridGapReviewDrawer
          gapId={reviewing}
          onClose={() => setReviewing(null)}
          onChanged={ledger.refetch}
        />
      )}
    </>
  );
}
