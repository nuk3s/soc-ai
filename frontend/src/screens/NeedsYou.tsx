import { Fragment, useEffect } from 'react';
import { ArrowRight, ArrowUpRight, Crosshair, FileSearch, Network, Server, Siren } from 'lucide-react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { SeverityTag, VerdictPill } from '../components/Badges';
import { ImpactChip } from '../components/ConfirmedThreats';
import { StageMeter } from '../components/campaign/StageMeter';
import { Panel } from '../components/Panel';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { getNeedsYouItems, onNeedsYouChanged, type NeedsYouItem, type NeedsYouItems } from '../lib/api';
import {
  campaignsWaiting,
  investigationsWaiting,
  needsYouPart,
  needsYouTypeLink,
  useNeedsYouCount,
  type NeedsYouFilter,
  rulesWaiting,
} from '../lib/needsYou';
import {
  NEEDS_YOU_EMPTY,
  NEEDS_YOU_GROUP_LABEL,
  NO_MACHINE,
  needsYouEventWords,
  needsYouGroupHeading,
  needsYouGroups,
  needsYouShowsImpact,
  type NeedsYouGroup,
  machineTitle,
  NEEDS_YOU_EMPTY_FLOOR,
  NEEDS_YOU_FILTERS,
  NEEDS_YOU_LIMIT,
  needsYouFilterEmpty,
  needsYouFilterOf,
  NEEDS_YOU_SCOPE,
  needsYouOpenLabel,
  needsYouTotalWords,
  needsYouTypeLabel,
  needsYouUnreadWords,
  waitAge,
} from '../lib/needsYouItems';
import { timeTitle } from '../lib/timeRange';
import type { Severity, Verdict } from '../lib/types';
import { useAsync } from '../lib/useAsync';
import { useTabTitle } from '../lib/useTabTitle';
import { RULE_ICON, RuleRowFacts } from '../components/rule/RuleRowFacts';
import { StandingRuleDecisions } from '../components/rule/StandingRuleDecisions';

// ---------------------------------------------------------------------------
// Needs you: every decision that waits, as one list the analyst works from
// top to bottom. The server sends the most important first, and the page
// keeps that order (lib/needsYouItems.ts). Each row states what it is, a small graphic where one exists,
// the title, why it waits, how long it waits and one link to the place where
// the analyst decides it. The alert groups with no verdict are one row.
//
// The row is prepared for the decision (dogfood 2026-11-17, a09 and a11): a
// verdict badge and an impact mark lead, then the title, the machines as
// chips, the action that waits in words and "Waits for {duration}". The row
// opens the item. No row writes.
//
// The page reads the list once a minute, and again after any write in the
// console that moves the needs-you count.
// ---------------------------------------------------------------------------

const REFETCH_MS = 60_000;

const ICON = {
  campaign: Network,
  investigation: FileSearch,
  lead: Crosshair,
  alerts: Siren,
  rule: RULE_ICON,
} as const;

export function NeedsYou() {
  useTabTitle('Needs you');
  const list = useAsync<NeedsYouItems>(() => getNeedsYouItems(), [], { refetchInterval: REFETCH_MS });
  const { refetch } = list;
  useEffect(() => onNeedsYouChanged(() => refetch()), [refetch]);
  // The type filter of a line of the Dashboard tile or of the bell. An
  // unknown value shows every item.
  const [params] = useSearchParams();
  const filter = needsYouFilterOf(params.get('type'));
  // The counts of the chips are the parts of the one count: the numbers of
  // the lines that open each filter.
  const count = useNeedsYouCount();

  if (list.loading && !list.data) return <LoadingState label="Reading what needs you" />;
  if (list.error && !list.data) {
    return <ErrorState error={list.error} onRetry={list.refetch} label="what needs you" />;
  }
  if (!list.data) return null;
  // The order of the server: the most important first.
  const items = filter ? list.data.items.filter((item) => item.type === filter) : list.data.items;
  const now = Date.now();
  // A type that the server could not read leaves the total a floor. The top
  // bar marks the same number with "+".
  const unread = needsYouUnreadWords(list.data.unknown);

  return (
    <div className="p-5">
      <h1 className="text-[19px] font-semibold">Needs you</h1>
      <p data-testid="needs-you-total" className="mt-1 text-[14px] text-text">
        {needsYouTotalWords(list.data.total, unread !== null)}
      </p>
      {unread && (
        <p data-testid="needs-you-unread" className="mt-0.5 text-[12px] text-warn">
          {unread}
        </p>
      )}
      <p data-testid="needs-you-scope" className="mt-0.5 text-[12px] text-faint">
        {NEEDS_YOU_SCOPE}
        {list.data.items.length >= NEEDS_YOU_LIMIT && ` The list shows the first ${NEEDS_YOU_LIMIT} items.`}
      </p>
      <FilterChips filter={filter} counts={partCounts(count.data)} />
      <Panel className="mt-3">
        {items.length === 0 ? (
          <EmptyState>
            {unread && (!filter || (list.data.unknown ?? []).includes(filter))
              ? NEEDS_YOU_EMPTY_FLOOR
              : filter
                ? needsYouFilterEmpty(filter)
                : NEEDS_YOU_EMPTY}
          </EmptyState>
        ) : (
          // One heading for each group with its count, in the order of the
          // server (OW5): the eye finds where the campaigns end.
          <div data-testid="needs-you-list">
            {needsYouGroups(items).map(({ group, items: grouped }, g) => (
              <section key={group} aria-label={NEEDS_YOU_GROUP_LABEL[group]} data-group={group}>
                <h2
                  data-testid="needs-you-group-heading"
                  className={`px-[15px] pb-1 pt-3 text-[11px] font-semibold uppercase tracking-[.06em] text-dim ${
                    g > 0 ? 'border-t border-border-strong' : ''
                  }`}
                >
                  {needsYouGroupHeading(group, groupCount(group, grouped.length, count.data))}
                </h2>
                <ol>
                  {grouped.map((item) => (
                    <NeedsYouRow key={`${item.type}:${item.id}`} item={item} now={now} />
                  ))}
                </ol>
              </section>
            ))}
          </div>
        )}
      </Panel>
      <StandingRuleDecisions />
    </div>
  );
}

/** The count of a group heading. The one item of the alert groups counts
 *  its groups, from the one needs-you count; null when that is not read.
 *  Each other group counts its items. */
function groupCount(
  group: NeedsYouGroup,
  items: number,
  data: ReturnType<typeof useNeedsYouCount>['data'],
): number | null {
  return group === 'alerts' ? needsYouPart(data, 'untriaged_groups') : items;
}

/** The count of each type, from the one needs-you count. Null when the count
 *  is not read or a part is unknown. */
function partCounts(data: ReturnType<typeof useNeedsYouCount>['data']): Record<NeedsYouFilter, number | null> {
  return {
    campaign: campaignsWaiting(data),
    investigation: investigationsWaiting(data),
    lead: needsYouPart(data, 'leads_needing_decision'),
    alerts: needsYouPart(data, 'untriaged_groups'),
    rule: rulesWaiting(data),
  };
}

/** One chip for each type and one for every item. Each chip is a link to
 *  the page with its filter, and the chip of the filter in force is lit. */
function FilterChips({
  filter,
  counts,
}: {
  filter: NeedsYouFilter | null;
  counts: Record<NeedsYouFilter, number | null>;
}) {
  const chip = (active: boolean) =>
    `inline-flex items-center gap-1.5 rounded-pill border px-2.5 py-[3px] text-[12px] font-semibold ${
      active ? 'border-accent bg-accent/10 text-accent' : 'border-border-strong text-text-2 hover:text-text'
    }`;
  return (
    <nav aria-label="Filter the list by type" data-testid="needs-you-filters" className="mt-3 flex flex-wrap gap-1.5">
      <Link to="/needs-you" aria-current={filter === null ? 'page' : undefined} className={chip(filter === null)}>
        Every type
      </Link>
      {NEEDS_YOU_FILTERS.map(({ type, label }) => {
        const n = counts[type];
        return (
          <Link
            key={type}
            to={needsYouTypeLink(type)}
            data-testid={`needs-you-filter-${type}`}
            aria-current={filter === type ? 'page' : undefined}
            className={chip(filter === type)}
          >
            {label}
            {typeof n === 'number' && <span className="font-mono tabular-nums">{n.toLocaleString()}</span>}
          </Link>
        );
      })}
    </nav>
  );
}

function NeedsYouRow({ item, now }: { item: NeedsYouItem; now: number }) {
  const navigate = useNavigate();
  const Icon = ICON[item.type] ?? FileSearch;
  const age = waitAge(item.since, now);
  // An older server sends no `why`: its `detail` states why the item waits.
  const why = item.why || item.detail;
  // The detail adds a fact that `why` does not hold: the stage and the alert
  // events of a campaign, and the observation types of a lead.
  const extra = item.why && (item.type === 'campaign' || item.type === 'lead') ? item.detail : null;
  return (
    <li
      data-testid="needs-you-item"
      data-type={item.type}
      // The row opens the item. The link at its end is the same target for
      // the keyboard. No row writes.
      onClick={(e) => {
        if ((e.target as HTMLElement).closest('a')) return;
        navigate(item.href);
      }}
      className="flex cursor-pointer flex-wrap items-start gap-x-4 gap-y-1.5 border-t border-border-faint px-[15px] py-3 first:border-t-0 hover:bg-surface-2"
    >
      {/* The marks lead: the verdict, the impact and the severity. */}
      <span data-testid="needs-you-item-marks" className="flex w-[168px] flex-none flex-col items-start gap-1.5">
        <span className="flex flex-wrap items-center gap-1.5">
          <VerdictPill verdict={(item.verdict ?? null) as Verdict} conf={item.confidence ?? null} />
          {needsYouShowsImpact(item) && <ImpactChip impact={item.impact ?? 'unknown'} />}
        </span>
        <span className="flex flex-wrap items-center gap-2">
          {/* A severity that soc-ai does not hold reads unknown. */}
          <SeverityTag sev={(item.severity ?? 'unknown') as Severity} />
          <span className="flex items-center gap-1.5">
            <Icon size={13} aria-hidden className="flex-none text-dim" />
            <span data-testid="needs-you-item-type" className="text-[11px] font-semibold uppercase tracking-[.05em] text-dim">
              {needsYouTypeLabel(item.type)}
            </span>
          </span>
        </span>
      </span>
      <span className="flex min-w-0 flex-[1_1_22rem] items-start gap-3">
        {item.type === 'campaign' && <StageMeter stage={item.stage ?? null} size="md" className="mt-[5px]" />}
        <span className="flex min-w-0 flex-col gap-1">
          <span data-testid="needs-you-item-title" className="block break-words text-[13px] font-semibold text-text">
            {item.title}
          </span>
          {why && (
            <span data-testid="needs-you-item-detail" className="block break-words text-[12.5px] text-text-2">
              {why}
            </span>
          )}
          {/* A campaign that opened again: what is new since the earlier decision. */}
          {item.newFacts && (
            <span data-testid="needs-you-item-new" className="block break-words text-[12.5px] font-semibold text-warn">
              {item.newFacts}
            </span>
          )}
          {extra && (
            <span data-testid="needs-you-item-extra" className="block break-words text-[12px] text-dim">
              {extra}
            </span>
          )}
          <MachineChips item={item} />
          {item.type === 'rule' && <RuleRowFacts item={item} />}
          {item.action && (
            <span data-testid="needs-you-item-action" className="block break-words text-[12px] text-text-2">
              <span className="font-semibold text-text">{item.action.label}</span>
              <span className="text-dim">. {item.action.writes}</span>
            </span>
          )}
        </span>
      </span>
      <span className="flex flex-none flex-col items-end gap-0.5">
        {age && (
          <span
            data-testid="needs-you-item-age"
            data-old={age.old}
            title={timeTitle(item.since)}
            className={`whitespace-nowrap text-[12px] ${age.old ? 'font-semibold text-warn' : 'text-dim'}`}
          >
            {age.text}
          </span>
        )}
        {/* The time of the event that the order reads. The one item of the
            alert groups reads no group, so it has none. */}
        {item.type !== 'alerts' && (
          <span data-testid="needs-you-item-event" className="whitespace-nowrap text-[11.5px] text-faint">
            {needsYouEventWords(item.eventAt)}
          </span>
        )}
      </span>
      <Link
        to={item.href}
        className="flex flex-none items-center gap-1 whitespace-nowrap text-[12px] font-semibold text-accent hover:underline"
      >
        {needsYouOpenLabel(item.type)}
        <ArrowUpRight size={13} aria-hidden />
      </Link>
    </li>
  );
}

/** The machines of an item as chips: the name, then the address. The alert
 *  groups name no machine. Another item with no machine says so. */
function MachineChips({ item }: { item: NeedsYouItem }) {
  if (item.machines === undefined || item.type === 'alerts') return null;
  const machines = item.machines ?? [];
  const more = item.machinesMore ?? 0;
  if (machines.length === 0 && more === 0) {
    return (
      <span data-testid="needs-you-item-machines" className="text-[12px] text-faint">
        {NO_MACHINE}
      </span>
    );
  }
  // A direction only when the record holds a source and a target (OW5).
  const directed = item.machinesDirected === true && machines.length === 2;
  return (
    <span
      data-testid="needs-you-item-machines"
      data-directed={directed}
      className="flex flex-wrap items-center gap-1.5"
    >
      {machines.map((m, i) => (
        <Fragment key={`${m.name ?? ''}|${m.address ?? ''}`}>
          {directed && i === 1 && (
            <ArrowRight
              size={12}
              data-testid="needs-you-machines-arrow"
              aria-label="to"
              className="flex-none text-dim"
            />
          )}
          <span
            data-testid="needs-you-machine"
            title={`${directed ? (i === 0 ? 'Source. ' : 'Target. ') : ''}${machineTitle(m)}`}
            className="inline-flex items-center gap-1 rounded-chip border border-border-strong bg-surface-3 px-1.5 py-px text-[11.5px] text-text-2"
          >
            <Server size={11} aria-hidden className="flex-none text-dim" />
            {m.name && <span className="font-semibold text-text">{m.name}</span>}
            {m.address && <span className="font-mono">{m.address}</span>}
          </span>
        </Fragment>
      ))}
      {more > 0 && (
        <span data-testid="needs-you-machines-more" className="text-[11.5px] text-dim">
          {more === 1 ? '1 more machine' : `${more} more machines`}
        </span>
      )}
    </span>
  );
}
