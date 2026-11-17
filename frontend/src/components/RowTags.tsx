import type { ReactNode } from 'react';
import { MessageSquare } from 'lucide-react';

import { AUTHORIZED_MARK, markHolds } from '../lib/authorizedActivity';
import { CHIP_AUTHORIZED_ACTIVITY, CHIP_SUBJECT_HUNT } from '../lib/tooltips';
import type { InvestigationCampaign } from '../lib/api';
import type { AuthorizationRef, DetectionKind, HuntKind } from '../lib/types';
import { HuntKindBadge, KindBadge, RunClassChip, SyntheticEvalBadge } from './Badges';
import { BacktestReplayChip } from './BacktestReplayChip';
import { CampaignChip } from './campaign/CampaignChip';

// ---------------------------------------------------------------------------
// The tags column.
//
// The chips of a row sat inline with its title: the type, the depth, the
// synthetic mark, the replay mark. Each row carried a different set, so each
// title started at a different x and the list read jagged (owner, 2026-10-07).
// The chips now sit in one fixed-width column at the end of the row, in one
// order, on every list: Investigations, Alerts, Hunts and the Dashboard. The
// title cell holds the title and nothing else, so every title starts at the
// same x and wraps in its own cell.
// ---------------------------------------------------------------------------

/** The width of the tags column. The widest chip, "Synthetic evaluation
 *  data", is 154px and fits on one line. More chips wrap onto the next line
 *  in the cell. The Investigations list and the Alerts list fit a 1280px
 *  window with this width. */
export const TAGS_COLUMN = '160px';

/** The tooltip on the column header. */
export const TAGS_HEADER_TITLE =
  'The tags of the row. A tag states the type, the campaign, the depth of the investigation or a mark on the row. ' +
  'The order is the same on every list.';

/** The header of the tags column. */
export function TagsHeader({ className = '' }: { className?: string }) {
  return (
    <div data-testid="tags-header" title={TAGS_HEADER_TITLE} className={className}>
      Tags
    </div>
  );
}

const CHIP =
  'flex-none rounded-badge border border-border-2 bg-surface-2 px-[6px] py-[2px] font-mono text-[10.5px]';

export interface RowTagsProps {
  /** The test id of the cell. */
  testId?: string;
  /** The detection type. */
  kind?: DetectionKind;
  /** The campaign of the investigation of the row. The chip links to it. */
  campaign?: InvestigationCampaign | null;
  campaignTestId?: string;
  /** The run read a hunt. */
  subjectHunt?: boolean;
  subjectTestId?: string;
  /** How the hunt came to exist. */
  huntKind?: HuntKind;
  /** The depth of the run. Leave it out on a list that shows no depth. */
  depth?: { runClass?: string | null; placeholder?: boolean; running?: boolean; testId?: string };
  /** The run used planted synthetic scenarios. */
  synthetic?: boolean;
  /** The run is a backtest replay. */
  replay?: boolean;
  replayTestId?: string;
  /** The authorized activity the run matched. A revoked one shows no chip. */
  authorized?: AuthorizationRef | null;
  /** The handled counts of an alert group. */
  counts?: ReactNode;
  /** An operator dismissed the failure. */
  dismissed?: boolean;
  /** A newer run replaced this run. The value is the tooltip. */
  superseded?: string | null;
  /** The controls that open a related run. */
  links?: ReactNode;
  /** The count of chat messages. */
  chatCount?: number | null;
}

/**
 * The tags of one row, in the one order: type, campaign, hunt subject, hunt kind,
 * depth, synthetic mark, replay mark, authorized activity, handled counts,
 * dismissed, superseded, related runs, chat count. The cell renders on a row with no tag too, so
 * the column holds its width on every row.
 */
export function RowTags({
  testId = 'row-tags',
  kind,
  campaign,
  campaignTestId,
  subjectHunt,
  subjectTestId,
  huntKind,
  depth,
  synthetic,
  replay,
  replayTestId,
  authorized,
  counts,
  dismissed,
  superseded,
  links,
  chatCount,
}: RowTagsProps) {
  return (
    <div data-testid={testId} className="flex min-w-0 flex-wrap items-center gap-1">
      {kind && <KindBadge kind={kind} />}
      <CampaignChip campaign={campaign} testId={campaignTestId} />
      {subjectHunt && (
        <span data-testid={subjectTestId} title={CHIP_SUBJECT_HUNT} className={`${CHIP} text-dim`}>
          hunt
        </span>
      )}
      {huntKind && <HuntKindBadge kind={huntKind} />}
      {depth && (
        <RunClassChip
          runClass={depth.runClass}
          testId={depth.testId}
          placeholder={depth.placeholder}
          running={depth.running}
        />
      )}
      {synthetic && <SyntheticEvalBadge />}
      {replay && <BacktestReplayChip testId={replayTestId} />}
      {markHolds(authorized) && (
        <span
          data-testid="authorized-chip"
          title={`${CHIP_AUTHORIZED_ACTIVITY} The label is "${authorized.label}".`}
          className={`${CHIP} border-accent text-accent`}
        >
          {AUTHORIZED_MARK}
        </span>
      )}
      {counts}
      {dismissed && (
        <span
          title="An operator dismissed this failure. The Dashboard does not count it."
          className={`${CHIP} text-faint`}
        >
          Dismissed
        </span>
      )}
      {superseded && (
        <span title={superseded} className={`${CHIP} text-faint`}>
          Superseded
        </span>
      )}
      {links}
      {(chatCount ?? 0) > 0 && (
        <span
          className={`${CHIP} flex items-center gap-[4px] text-accent`}
          title={`${chatCount} chat message${chatCount === 1 ? '' : 's'}`}
        >
          <MessageSquare size={10} />
          {chatCount}
        </span>
      )}
    </div>
  );
}
