import { cn } from '../lib/cn';
import {
  DEFINE_ANALYTIC,
  DEFINE_HIT,
  DEFINE_HUNT,
  DEFINE_LEAD,
  DEFINE_SCHEDULE,
} from '../lib/tooltips';
import { FlowLink } from './HowThisFlows';

// ---------------------------------------------------------------------------
// One dim line that states what a thing is.
//
// The Hunts page names five things: a hit, a lead, a hunt, a schedule and an
// analytic. It named all five and said what none of them was, so the owner read
// the page and could not tell one from another.
//
// The line sits under the section header, before the content, and under the
// title of the page or the drawer that holds one of those things. One component
// renders it everywhere, so a thing reads the same wherever an analyst meets
// it.
//
// The line ends in the link to the chart: one sentence states what a thing is,
// and the chart states where it sits in the flow.
// ---------------------------------------------------------------------------

/** The sentence per thing. The sentences themselves live with the other
 *  tooltip copy, because the chips and the pills read them too. */
const SENTENCE = {
  hit: DEFINE_HIT,
  lead: DEFINE_LEAD,
  hunt: DEFINE_HUNT,
  schedule: DEFINE_SCHEDULE,
  analytic: DEFINE_ANALYTIC,
} as const;

/** The things this app defines on screen. */
export type DefinedThing = keyof typeof SENTENCE;

export function Definition({ of, className }: { of: DefinedThing; className?: string }) {
  return (
    <p
      data-testid={`define-${of}`}
      className={cn('text-[11.5px] leading-[1.6] text-dim', className)}
    >
      {SENTENCE[of]} <FlowLink />
    </p>
  );
}
