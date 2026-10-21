import { Link, useLocation, useSearchParams } from 'react-router-dom';

import flowUrl from '../assets/hunting-flow.svg';
import { cn } from '../lib/cn';
import {
  DEFINE_ANALYTIC,
  DEFINE_HIT,
  DEFINE_HUNT,
  DEFINE_LEAD,
  DEFINE_SCHEDULE,
  OVERVIEW_FLOW,
} from '../lib/tooltips';
import { Drawer } from './Drawer';

// ---------------------------------------------------------------------------
// How this flows: the chart behind every definition line.
//
// The Hunts page reads as the pipeline and never drew it: an analytic finds a
// hit, hits on one entity form a lead, a lead starts a hunt, and the hunt
// investigates what it finds. The chart draws the alert path beside the sweep
// path, because both end in an investigation, a verdict and an action in
// Security Onion (owner, 2026-10-07). The chart states each step and names
// the screen that holds it. Its words are the words of the controls: "Hunt
// this lead", "Open an investigation", "hit".
//
// The drawer carries the address parameter `?flow=1`, the way the composer
// carries `?new=1`: a reload keeps it open, closing takes the parameter out,
// and a tab change clears it. The chart is 1600px across, so this drawer is the
// wide one.
// ---------------------------------------------------------------------------

/** The address parameter that opens the drawer. */
export const FLOW_PARAM = 'flow';

/** The words on the link. One phrase, so the link reads the same in the header
 *  and at the end of every definition line. */
export const FLOW_LINK_LABEL = 'How this flows';

/** The chart for a reader who cannot see it. A chart of boxes and their
 *  arrows says nothing as "hunting-flow.svg". */
export const FLOW_ALT =
  'The flow, left to right and then down. Two inputs enter on the left. On the sweep path an ' +
  'analytic runs on every hourly sweep and finds a hit. Hits on one entity form a lead. The ' +
  'lead starts its own hunt, or you press Hunt this lead. A hunt returns findings. soc-ai ' +
  'investigates each threat finding. On the alert path soc-ai triages an alert. Both paths end in an ' +
  'investigation, which ends in a verdict. In Needs you, you agree with the verdict or ' +
  'override it. Your action goes to Security Onion. The chart also defines the two verbs.';

/** The sentences under the chart: the flow in one line, then the five
 *  definitions in the order the chart reads. */
const SENTENCES = [
  OVERVIEW_FLOW,
  DEFINE_ANALYTIC,
  DEFINE_HIT,
  DEFINE_LEAD,
  DEFINE_HUNT,
  DEFINE_SCHEDULE,
] as const;

/** The address of the Hunt Console. The chart lives on that page, so a link
 *  from anywhere else goes there first. */
const HUNTS_PATH = '/hunts';

/**
 * The link that opens the chart.
 *
 * On the Hunt Console the link keeps the address the analyst is reading and
 * adds the parameter, so the filters on screen survive the drawer. On any other
 * page it is a plain link to the Hunt Console with the drawer open.
 */
export function FlowLink({ className }: { className?: string }) {
  const [params] = useSearchParams();
  const { pathname } = useLocation();
  const next = new URLSearchParams(params);
  next.set(FLOW_PARAM, '1');
  const to =
    pathname === HUNTS_PATH ? { search: `?${next.toString()}` } : `${HUNTS_PATH}?${FLOW_PARAM}=1`;
  return (
    <Link to={to} className={cn('text-accent hover:underline', className)}>
      {FLOW_LINK_LABEL}
    </Link>
  );
}

export function HowThisFlowsDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <Drawer
      open={open}
      onClose={onClose}
      size="wide"
      header={
        <div className="flex min-w-0 flex-1 items-center justify-between gap-2.5">
          <span className="text-[13.5px] font-semibold">{FLOW_LINK_LABEL}</span>
          <button
            type="button"
            onClick={onClose}
            className="rounded-control border border-border-strong px-2.5 py-1 text-[12px] font-semibold text-dim hover:text-text"
          >
            Close
          </button>
        </div>
      }
    >
      <div className="p-4">
        <img
          data-testid="hunting-flow-chart"
          src={flowUrl}
          alt={FLOW_ALT}
          className="w-full rounded-panel border border-border"
          style={{ maxWidth: '100%' }}
        />
        {/* The flow line and the five sentences the page carries. A reader
            who cannot see the chart still gets the words, and a reader who can
            gets them twice, which is how a definition is learned. */}
        <ul
          data-testid="flow-definitions"
          className="mt-4 flex flex-col gap-2 text-[12.5px] leading-[1.6] text-text-2"
        >
          {SENTENCES.map((sentence) => (
            <li key={sentence}>{sentence}</li>
          ))}
        </ul>
      </div>
    </Drawer>
  );
}
