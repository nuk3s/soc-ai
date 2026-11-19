import { Link, useLocation, useSearchParams } from 'react-router-dom';

import flowUrl from '../assets/hunting-flow.svg';
import { cn } from '../lib/cn';
import {
  DEFINE_ALERT,
  DEFINE_ANALYTIC,
  DEFINE_CAMPAIGN,
  DEFINE_CAMPAIGN_DECISION,
  DEFINE_HIT,
  DEFINE_HUNT,
  DEFINE_INVESTIGATION,
  DEFINE_LEAD,
  DEFINE_NEEDS_YOU,
  DEFINE_TWO_VERBS,
  DEFINE_VERDICT,
  OVERVIEW_FLOW,
} from '../lib/tooltips';
import { Drawer } from './Drawer';

// ---------------------------------------------------------------------------
// How this flows: the chart behind every definition line.
//
// The Hunts page reads as the pipeline and never drew it: an analytic finds a
// hit, hits on one entity form a lead, soc-ai hunts the lead, and the hunt
// investigates its threat findings. The chart draws the alert path under the
// sweep path, because both end in an investigation and a verdict (owner,
// 2026-10-07). A confirmed attack starts or joins a campaign, and the analyst
// decides once on the campaign in Needs you (owner, 2026-11-16: "Update the
// flow chart with our new update."). Each box states one thing and names the
// screen that holds it. The longer sentences live under the chart.
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
  'The flow from the grid to your decision, in three rows. On the sweep path an analytic ' +
  'finds a hit, and hits on one entity form a lead. soc-ai hunts the lead, and the hunt ' +
  'returns findings. A clean lead hunt closes the lead. Another hunt that reads a lead or a ' +
  'campaign closes nothing: it writes its answer on the lead or the campaign. ' +
  'soc-ai investigates each threat finding that names an entity. On the ' +
  'alert path soc-ai investigates one alert of each group. The investigation ends in a ' +
  'verdict. A confirmed attack starts or joins a campaign. A true positive or needs more info ' +
  'verdict of an alert writes an observation that can form a lead. Needs you lists the work ' +
  'that waits on you. A rule with open false positives waits there for one decision. You ' +
  'decide once on a campaign, and soc-ai writes the action to Security Onion.';

/** The sentences under the chart: the flow in one line, then one definition
 *  for each box in the order the chart reads, then the two verbs. */
export const FLOW_SENTENCES = [
  OVERVIEW_FLOW,
  DEFINE_ANALYTIC,
  DEFINE_HIT,
  DEFINE_LEAD,
  DEFINE_HUNT,
  DEFINE_ALERT,
  DEFINE_INVESTIGATION,
  DEFINE_VERDICT,
  DEFINE_CAMPAIGN,
  DEFINE_CAMPAIGN_DECISION,
  DEFINE_NEEDS_YOU,
  DEFINE_TWO_VERBS,
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
        {/* The flow line and the definition of each box. A reader
            who cannot see the chart still gets the words, and a reader who can
            gets them twice, which is how a definition is learned. */}
        <ul
          data-testid="flow-definitions"
          className="mt-4 flex flex-col gap-2 text-[12.5px] leading-[1.6] text-text-2"
        >
          {FLOW_SENTENCES.map((sentence) => (
            <li key={sentence}>{sentence}</li>
          ))}
        </ul>
      </div>
    </Drawer>
  );
}
