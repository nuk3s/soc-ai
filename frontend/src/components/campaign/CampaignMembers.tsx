import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  excludeFromCampaign,
  undoCampaignOverride,
  type CampaignDetail,
  type CampaignLink,
  type CampaignMember,
  type CampaignParty,
} from '../../lib/api';
import {
  AUTHORIZED_CHIP,
  AUTHORIZED_CHIP_TITLE,
  NEW_CHIP,
  NEW_CHIP_TITLE,
  EXCLUDE_ACTION,
  EXCLUDE_CONFIRM,
  INCLUDED_CHIP,
  INCLUDED_CHIP_TITLE,
  LINK_ORDER,
  OUTSIDE_MARK,
  UNDO_ACTION,
  UNDO_INCLUDE_CONFIRM,
  VIEW_HUNT,
  linkLabel,
  linkPieces,
  memberTypeLabel,
  partyName,
  stageLabel,
} from '../../lib/campaignWords';
import { plural } from '../../lib/plural';
import { utcStamp } from '../../lib/timeRange';
import { VerdictPill } from '../Badges';
import { ImpactChip } from '../ConfirmedThreats';
import { UNKNOWN, UNKNOWN_TONE } from '../Kpi';
import { Panel, PanelHeader } from '../Panel';
import { ROW_BUTTON, RowConfirm } from './RowWrite';
import { selectionHolds, type CampaignSelection } from './selection';
import { runHref } from './shared';

const CHIP = 'inline-flex flex-none items-center whitespace-nowrap rounded-chip border px-1.5 py-px text-[10.5px]';

/** The writes of the rows: the campaign, the answer of a write, and the
 *  investigations beyond the authorization. With none, the table has no
 *  column of actions. */
export interface MemberWrites {
  campaignId: number;
  onChanged: (next: CampaignDetail) => void;
  /** The investigations outside the authorization. */
  outside?: ReadonlySet<string>;
}

const TH = 'px-2.5 py-2 text-left font-semibold';

type LinkFilter = CampaignLink | 'all';

/** The investigations of the campaign, with the link that made each one
 *  part of it and why. A campaign can hold sixty investigations and more, so
 *  a row of buttons filters the table by link. The investigations whose
 *  verdict differs have their own section.
 *
 *  A selection on a graphic shows only its investigations, under a line that
 *  names it and a button that clears it. The link buttons then count those
 *  investigations. `embedded` drops the panel and the title: a fold of the
 *  page holds them. */
export function CampaignMembers({
  members,
  parties,
  selection = null,
  onClearSelection,
  embedded = false,
  writes,
  fresh,
  newOnly = false,
  newWords,
  onShowAll,
}: {
  members: CampaignMember[];
  parties: CampaignParty[];
  selection?: CampaignSelection | null;
  onClearSelection?: () => void;
  embedded?: boolean;
  /** Exclude and Undo on each row. */
  writes?: MemberWrites;
  /** The investigations that are new since the earlier decision. Each row
   *  of one carries the chip "New". */
  fresh?: ReadonlySet<string>;
  /** Show only the new investigations, with any verdict. */
  newOnly?: boolean;
  /** The line over the table while it shows only the new investigations. */
  newWords?: string;
  onShowAll?: () => void;
}) {
  const [filter, setFilter] = useState<LinkFilter>('all');
  // The new investigations are the rows of the control "Show the new
  // investigations": a new one whose verdict differs is one of them too, so
  // the count of the server and the rows are the same list.
  const rows = newOnly && fresh ? members.filter((m) => fresh.has(m.runId)) : members.filter((m) => !m.verdictDiffers);
  if (rows.length === 0) return null;
  const picked = selection ? rows.filter((m) => selectionHolds(selection, m)) : rows;

  const counts = new Map<CampaignLink, number>();
  for (const m of picked) counts.set(m.link, (counts.get(m.link) ?? 0) + 1);
  // The links in the engine's order, then a link a newer server sends.
  const links = [
    ...LINK_ORDER.filter((l) => counts.has(l)),
    ...[...counts.keys()].filter((l) => !LINK_ORDER.includes(l)),
  ];
  // A filter whose link left the campaign on a re-read shows every row.
  const active: LinkFilter = filter !== 'all' && !counts.has(filter) ? 'all' : filter;
  const shown = active === 'all' ? picked : picked.filter((m) => m.link === active);
  const names = Object.fromEntries(parties.map((p) => [p.machineKey, partyName(p)]));
  // A link sentence names the other investigation by its label, never by its id.
  const labels = Object.fromEntries(rows.map((m) => [m.runId, m.label]));

  const button = (value: LinkFilter, label: string, count: number) => (
    <button
      key={value}
      type="button"
      aria-pressed={active === value}
      onClick={() => setFilter(value)}
      className={`rounded-chip border px-2 py-px text-[11px] ${
        active === value ? 'border-accent text-accent' : 'border-border-faint text-dim hover:text-text-2'
      }`}
    >
      {label}{' '}
      <span className="font-mono tabular-nums text-faint">{count.toLocaleString()}</span>
    </button>
  );

  const body = (
    <>
      {newOnly && (
        <div
          data-testid="members-new-only"
          className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-border-faint bg-warn/5 px-[15px] py-2 text-[12.5px] text-text-2"
        >
          <span className="break-words">{newWords ?? `Showing ${plural(rows.length, 'new investigation')}.`}</span>
          {onShowAll && (
            <button
              type="button"
              onClick={onShowAll}
              className="rounded-control border border-border-strong bg-surface-2 px-2 py-0.5 text-[11.5px] text-text-2 hover:border-accent"
            >
              Show all investigations
            </button>
          )}
        </div>
      )}
      {selection && (
        <div
          data-testid="members-selection"
          className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-border-faint bg-accent/5 px-[15px] py-2 text-[12.5px] text-text-2"
        >
          <span className="break-words">
            {`Showing ${picked.length.toLocaleString()} of ${plural(rows.length, 'investigation')}: ${selection.label}.`}
          </span>
          {onClearSelection && (
            <button
              type="button"
              onClick={onClearSelection}
              className="rounded-control border border-border-strong bg-surface-2 px-2 py-0.5 text-[11.5px] text-text-2 hover:border-accent"
            >
              Show all investigations
            </button>
          )}
        </div>
      )}
      <div
        role="group"
        aria-label="Filter by link"
        data-testid="members-filter"
        className="flex flex-wrap items-center gap-1.5 border-b border-border-faint px-[15px] py-2"
      >
        {button('all', 'All', picked.length)}
        {links.map((l) => button(l, linkLabel(l), counts.get(l) ?? 0))}
      </div>
      <div className="overflow-x-auto">
        <table data-testid="campaign-members" className="w-full text-[12.5px]">
          <thead className="border-b border-border bg-surface-2 text-[10.5px] uppercase tracking-[.06em] text-faint">
            <tr>
              <th scope="col" className="px-[15px] py-2 text-left font-semibold">
                Event time
              </th>
              <th scope="col" className={TH}>
                Type
              </th>
              <th scope="col" className={TH}>
                Investigation
              </th>
              <th scope="col" className={TH}>
                Verdict
              </th>
              <th scope="col" className={TH}>
                Impact
              </th>
              <th scope="col" className={TH}>
                Stage
              </th>
              <th scope="col" className="px-[15px] py-2 text-left font-semibold">
                Link
              </th>
            </tr>
          </thead>
          <tbody>
            {shown.map((m) => (
              <MemberRow
                key={m.runId}
                m={m}
                names={names}
                labels={labels}
                writes={writes}
                isNew={fresh?.has(m.runId) ?? false}
              />
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
  if (embedded) return body;
  return (
    <Panel>
      <PanelHeader title="Investigations" />
      {body}
    </Panel>
  );
}

function MemberRow({
  m,
  names,
  labels,
  writes,
  isNew = false,
}: {
  m: CampaignMember;
  names: Record<string, string>;
  labels: Record<string, string>;
  writes?: MemberWrites;
  /** The event of the investigation is after the earlier decision. */
  isNew?: boolean;
}) {
  const [confirming, setConfirming] = useState(false);
  const outside = writes?.outside?.has(m.runId) ?? false;
  const included = m.included === true || m.link === 'included';
  return (
    <>
    <tr
      data-testid={`member-${m.runId}`}
      data-link={m.link}
      className={`align-top ${confirming ? '' : 'border-b border-border-faint last:border-b-0'}`}
    >
      <td className="whitespace-nowrap px-[15px] py-2.5 font-mono text-[11.5px] text-text-2">
        {m.eventAt ? utcStamp(m.eventAt, { seconds: true }) : <span className={UNKNOWN_TONE}>{UNKNOWN}</span>}
      </td>
      <td className="px-2.5 py-2.5 text-text-2">{memberTypeLabel(m.kind)}</td>
      <td className="min-w-[12rem] px-2.5 py-2.5">
        <Link to={runHref(m.runId)} className="break-words text-accent hover:underline">
          {m.label}
        </Link>
        {(m.authorized || included || outside || isNew) && (
          <div className="mt-1 flex flex-wrap gap-1.5">
            {isNew && (
              <span
                data-testid="member-new"
                title={NEW_CHIP_TITLE}
                className={`${CHIP} border-warn/50 bg-warn/10 font-semibold text-warn`}
              >
                {NEW_CHIP}
              </span>
            )}
            {m.authorized && (
              <span
                data-testid="member-authorized"
                title={AUTHORIZED_CHIP_TITLE}
                className={`${CHIP} border-border-strong bg-surface-2 text-text-2`}
              >
                {AUTHORIZED_CHIP}
              </span>
            )}
            {included && (
              <span
                data-testid="member-included"
                title={INCLUDED_CHIP_TITLE}
                className={`${CHIP} border-accent/40 bg-accent/10 text-accent`}
              >
                {INCLUDED_CHIP}
              </span>
            )}
            {outside && (
              <span data-testid="member-outside" className={`${CHIP} border-danger/50 bg-danger/10 font-semibold text-danger`}>
                {OUTSIDE_MARK}
              </span>
            )}
          </div>
        )}
        {writes && !confirming && (
          <div className="mt-1.5">
            <button
              type="button"
              data-testid={included ? 'member-undo' : 'member-exclude'}
              onClick={() => setConfirming(true)}
              className={ROW_BUTTON}
              aria-label={`${included ? UNDO_ACTION : EXCLUDE_ACTION}: ${m.label}`}
            >
              {included ? UNDO_ACTION : EXCLUDE_ACTION}
            </button>
          </div>
        )}
        {m.kind === 'finding' && m.huntId && (
          <div className="mt-0.5">
            <Link
              to={`/hunts/${encodeURIComponent(m.huntId)}`}
              className="text-[11.5px] font-semibold text-accent hover:underline"
            >
              {VIEW_HUNT}
            </Link>
          </div>
        )}
      </td>
      <td className="px-2.5 py-2.5">
        <VerdictPill verdict={m.verdict} showConf={false} />
      </td>
      <td className="px-2.5 py-2.5">{m.impact && <ImpactChip impact={m.impact} />}</td>
      <td data-testid="member-stage" className="px-2.5 py-2.5 text-text-2">
        {m.stage && stageLabel(m.stage)}
      </td>
      <td className="min-w-[16rem] px-[15px] py-2.5">
        <div className="font-semibold text-text-2">{linkLabel(m.link)}</div>
        <LinkSentence m={m} names={names} labels={labels} />
      </td>
    </tr>
    {writes && confirming && (
      <tr className="border-b border-border-faint last:border-b-0">
        <td colSpan={7} className="px-[15px] pb-2.5">
          {/* The table can be wider than the panel. The confirm holds to the
              left edge of the view, so no part of it scrolls out of sight. */}
          <div className="sticky left-[15px] max-w-[40rem]">
          <RowConfirm
            testId={included ? 'member-undo-confirm' : 'member-exclude-confirm'}
            sentence={included ? UNDO_INCLUDE_CONFIRM : EXCLUDE_CONFIRM}
            action={included ? UNDO_ACTION : EXCLUDE_ACTION}
            needsReason={!included}
            write={(reason) =>
              included
                ? undoCampaignOverride(writes.campaignId, m.runId)
                : excludeFromCampaign(writes.campaignId, { runId: m.runId, reason })
            }
            onDone={(next) => {
              setConfirming(false);
              writes.onChanged(next);
            }}
            onCancel={() => setConfirming(false)}
          />
          </div>
        </td>
      </tr>
    )}
    </>
  );
}

/** The link sentence of a row (W5). The id of the other investigation is
 *  behind its link, and the id of a shared connection is in the hover of the
 *  sentence. */
function LinkSentence({
  m,
  names,
  labels,
}: {
  m: CampaignMember;
  names: Record<string, string>;
  labels: Record<string, string>;
}) {
  const p = linkPieces(m, names, labels);
  return (
    <div data-testid="member-link-sentence" title={p.title} className="mt-0.5 text-dim [overflow-wrap:anywhere]">
      {p.before}
      {p.other &&
        (p.other.runId ? (
          <Link
            data-testid="member-link-other"
            to={runHref(p.other.runId)}
            className="text-text-2 hover:text-accent hover:underline"
          >
            {p.other.words}
          </Link>
        ) : (
          p.other.words
        ))}
      {p.after}
    </div>
  );
}
