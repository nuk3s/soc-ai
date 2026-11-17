import { useEffect } from 'react';
import { ArrowUpRight, Crosshair, FileSearch, Network, Siren } from 'lucide-react';
import { Link } from 'react-router-dom';
import { StageMeter } from '../components/campaign/StageMeter';
import { Panel } from '../components/Panel';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { getNeedsYouItems, onNeedsYouChanged, type NeedsYouItem, type NeedsYouItems } from '../lib/api';
import {
  NEEDS_YOU_EMPTY,
  NEEDS_YOU_EMPTY_FLOOR,
  NEEDS_YOU_LIMIT,
  NEEDS_YOU_SCOPE,
  needsYouOpenLabel,
  needsYouTotalWords,
  needsYouTypeLabel,
  needsYouUnreadWords,
  sortNeedsYou,
  waitAge,
} from '../lib/needsYouItems';
import { utcStamp } from '../lib/timeRange';
import { useAsync } from '../lib/useAsync';
import { useTabTitle } from '../lib/useTabTitle';

// ---------------------------------------------------------------------------
// Needs you: every decision that waits, as one list the analyst works from
// top to bottom. The campaigns come first. Inside each type the oldest item
// comes first. Each row states what it is, a small graphic where one exists,
// the title, why it waits, how long it waits and one link to the place where
// the analyst decides it. The alert groups with no verdict are one row.
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
} as const;

export function NeedsYou() {
  useTabTitle('Needs you');
  const list = useAsync<NeedsYouItems>(() => getNeedsYouItems(), [], { refetchInterval: REFETCH_MS });
  const { refetch } = list;
  useEffect(() => onNeedsYouChanged(() => refetch()), [refetch]);

  if (list.loading && !list.data) return <LoadingState label="Reading what needs you" />;
  if (list.error && !list.data) {
    return <ErrorState error={list.error} onRetry={list.refetch} label="what needs you" />;
  }
  if (!list.data) return null;
  const items = sortNeedsYou(list.data.items);
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
        {list.data.items.length >= NEEDS_YOU_LIMIT && ` The list shows the oldest ${NEEDS_YOU_LIMIT} items.`}
      </p>
      <Panel className="mt-3">
        {items.length === 0 ? (
          <EmptyState>{unread ? NEEDS_YOU_EMPTY_FLOOR : NEEDS_YOU_EMPTY}</EmptyState>
        ) : (
          <ol data-testid="needs-you-list">
            {items.map((item, i) => (
              <NeedsYouRow
                key={`${item.type}:${item.id}`}
                item={item}
                now={now}
                // A thin rule between two types, so the eye finds where the campaigns end.
                newType={i > 0 && items[i - 1].type !== item.type}
              />
            ))}
          </ol>
        )}
      </Panel>
    </div>
  );
}

function NeedsYouRow({ item, now, newType }: { item: NeedsYouItem; now: number; newType: boolean }) {
  const Icon = ICON[item.type] ?? FileSearch;
  const age = waitAge(item.since, now);
  return (
    <li
      data-testid="needs-you-item"
      data-type={item.type}
      className={`flex flex-wrap items-center gap-x-4 gap-y-1.5 px-[15px] py-3 ${
        newType ? 'border-t border-border-strong' : 'border-t border-border-faint first:border-t-0'
      }`}
    >
      <span className="flex w-[148px] flex-none items-center gap-2">
        <Icon size={15} aria-hidden className="flex-none text-dim" />
        <span data-testid="needs-you-item-type" className="text-[11.5px] font-semibold uppercase tracking-[.05em] text-dim">
          {needsYouTypeLabel(item.type)}
        </span>
      </span>
      <span className="flex min-w-0 flex-[1_1_22rem] items-start gap-3">
        {item.type === 'campaign' && <StageMeter stage={item.stage ?? null} size="md" className="mt-[5px]" />}
        <span className="min-w-0">
          <span data-testid="needs-you-item-title" className="block break-words text-[13px] font-semibold text-text">
            {item.title}
          </span>
          {item.detail && (
            <span data-testid="needs-you-item-detail" className="mt-0.5 block break-words text-[12.5px] text-text-2">
              {item.detail}
            </span>
          )}
        </span>
      </span>
      {age && (
        <span
          data-testid="needs-you-item-age"
          data-old={age.old}
          title={utcStamp(item.since)}
          className={`flex-none whitespace-nowrap text-[12px] ${age.old ? 'font-semibold text-warn' : 'text-dim'}`}
        >
          {age.text}
        </span>
      )}
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
