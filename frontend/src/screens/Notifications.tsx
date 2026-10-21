import { Bell, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { SyntheticEvalBadge } from '../components/Badges';
import { DismissAllControl } from '../components/DismissAllControl';
import { HuntOutcomeChip } from '../components/HuntOutcomeChip';
import { ListToolbar } from '../components/ListToolbar';
import { MultiSelect } from '../components/MultiSelect';
import { NeedsYouBlock } from '../components/NeedsYouBlock';
import { ErrorState, Freshness, LoadingState, StaleNotice } from '../components/States';
import { getNotifications } from '../lib/api';
import { useNeedsYouCount } from '../lib/needsYou';
import {
  NOTIFICATIONS_CAP,
  NOTIFICATIONS_DISMISSED_EVENT,
  NOTIFICATION_KINDS,
  NO_NOTIFICATIONS,
  describeNotifications,
  dismissNotification,
  formatNotificationTitle,
  formatNotificationWhen,
  getClearedAt,
  hasMoreNotifications,
  isNeedsYouRow,
  nextNotificationLimit,
  notificationKind,
  visibleNotifications,
  type NotificationKind,
} from '../lib/notifications';
import {
  GROUP_HUNTING,
  TONE_ATTENTION,
  TONE_INFORMATIONAL,
  TONE_URGENT,
} from '../lib/tooltips';
import type { Notification } from '../lib/types';
import { useAsync } from '../lib/useAsync';

const TONE: Record<Notification['tone'], string> = {
  danger: '#f04438',
  warn: '#f5a623',
  accent: '#4b8bf5',
};

/**
 * The row dot's colour, named.
 *
 * `tone` is the one axis that cuts ACROSS kinds — a finished investigation is
 * red, amber or blue depending on its verdict, a finished hunt amber or blue
 * depending on whether it found anything — so it is the honest second facet.
 * These labels are what the dot has always meant; putting them in a filter is
 * also the first time the screen says it out loud.
 */
const URGENCY: ReadonlyArray<{ value: Notification['tone']; label: string }> = [
  { value: 'danger', label: 'Urgent' },
  { value: 'warn', label: 'Attention' },
  { value: 'accent', label: 'Informational' },
];

/** What the dot says, in one sentence. The colour was the only statement. */
const TONE_TITLE: Record<Notification['tone'], string> = {
  danger: TONE_URGENT,
  warn: TONE_ATTENTION,
  accent: TONE_INFORMATIONAL,
};

/** What a group holds, in one sentence. */
const GROUP_TITLE: Partial<Record<NotificationKind, string>> = { hunting: GROUP_HUNTING };

/**
 * Notifications: the Needs-you block, then the events under the same list
 * toolbar its neighbours wear.
 *
 * The Needs-you block states every part of the count the bell badge shows,
 * with its scope, as the bell panel does. The events are the rows the API
 * returns with `events_only`: the leads and the shadow hits are in the block,
 * so one unit never shows twice. "Show more" loads 20 more rows, and "Dismiss
 * all" is the bell's own (lib/notifications.ts::dismissAll).
 *
 * The list round gave Alerts, Investigations, Hunts and Hosts one shared
 * toolbar and skipped this screen, which sits in the same nav group and is just
 * as list-shaped; the result read as forgotten rather than deliberately left
 * alone (dogfood B2). It adopts ListToolbar here, with two facets that each
 * filter real rows:
 *
 *   • KIND, as preset chips — what raised the item, off the id prefix the API
 *     mints. This is the "status vs investigation" split an earlier dogfood
 *     asked for, and the chip counts double as the summary a flat list lacked.
 *   • URGENCY, as the facet row's multi-select — the row dot's own axis.
 *
 * No search box: a notification title is a sentence this app generated from a
 * rule name or an objective, over a list the API cuts at 12 rows until "Show
 * more" asks for more, so a third control would filter nothing the two chips
 * cannot already reach.
 *
 * No saved views either, and that is a judgement rather than an omission. A
 * saved view is a durable name for a query worth re-running; this list is
 * derived fresh from live state on every poll and holds a rolling 24 hours of
 * runs. There is no query here to be worth naming. One chip and one
 * multi-select IS the whole filter state, and it resets every shift. The
 * preset chips give the chip row its content, so the screen still opens with the
 * two-row toolbar its siblings do.
 */
export function Notifications() {
  // The rows the screen asks for. "Show more" adds 20, up to the API maximum.
  const [limit, setLimit] = useState(NOTIFICATIONS_CAP);
  // `after` is read at each call, so the poll sends the moment of the last
  // Dismiss all, and hidden rows take no place in the limit.
  const { data, loading, error, lastUpdated, failCount, refetch } = useAsync(
    () => getNotifications({ limit, eventsOnly: true, after: getClearedAt() }),
    [limit],
    { refetchInterval: 15000 },
  );
  const needsYou = useNeedsYouCount();
  // Bump to re-read localStorage after a dismissal. The hidden rows are read
  // again on every render (not snapshotted at mount) so this screen and the
  // Topbar bell, which reads the same store, can never disagree about what is
  // hidden (the badge/panel mismatch from dogfood 2026-07-15).
  const [dismissTick, setDismissTick] = useState(0);
  void dismissTick;
  // A dismiss from another view (the Topbar bell) also fires this event; re-read
  // so the pane never diverges from the bell between refetches.
  useEffect(() => {
    const bump = () => setDismissTick((t) => t + 1);
    window.addEventListener(NOTIFICATIONS_DISMISSED_EVENT, bump);
    return () => window.removeEventListener(NOTIFICATIONS_DISMISSED_EVENT, bump);
  }, []);
  const [kind, setKind] = useState<NotificationKind | 'all'>('all');
  const [urgency, setUrgency] = useState<string[]>([]);

  // Every event the analyst has not hidden. The header count and "Dismiss all"
  // read THIS: a filter narrows what is shown, never what is active. The leads
  // and the shadow hits are in the Needs-you block, so an older server that
  // sends them anyway does not show one unit twice.
  const items = visibleNotifications(data ?? []).filter((n) => !isNeedsYouRow(n));
  // A full answer can have more rows behind it.
  const more = hasMoreNotifications(data?.length ?? 0, limit);

  const matchesUrgency = (n: Notification) => urgency.length === 0 || urgency.includes(n.tone);

  const visible = items.filter(
    (n) => (kind === 'all' || notificationKind(n) === kind) && matchesUrgency(n),
  );
  const filtered = visible.length !== items.length;

  // Two counts per kind, and they answer different questions. `underUrgency` is
  // what a chip promises — press it and you get exactly that many rows — so it
  // has to respect the facet beside it. `ever` decides whether the chip is worth
  // rendering AT ALL: a deployment with the host dossier switched off would
  // otherwise carry a permanent "Hosts 0" that filters nothing. Splitting them
  // keeps the chip row stable while a facet moves (the kind is still there, its
  // count just went to zero — which is itself the answer) and still drops a kind
  // this install never produces.
  //
  // No memo on any of this, deliberately: the list holds at most 200 rows, and
  // every input here is an array rebuilt on each render, so a useMemo would
  // recompute anyway while implying it does not.
  const byKind = new Map<NotificationKind, { ever: number; underUrgency: number }>();
  for (const n of items) {
    const k = notificationKind(n);
    const c = byKind.get(k) ?? { ever: 0, underUrgency: 0 };
    c.ever += 1;
    if (matchesUrgency(n)) c.underUrgency += 1;
    byKind.set(k, c);
  }

  // Group headers earn their place only while the rows actually span groups:
  // under a kind chip they would just repeat the chip that is already pressed.
  // Headings and chips read the one notificationKind, so a row sits under the
  // heading its chip names. A lead sat under HUNTING and counted on "System"
  // when the two read different fields (D7, RD7).
  const groups = NOTIFICATION_KINDS.map((k) => ({
    ...k,
    rows: visible.filter((n) => notificationKind(n) === k.id),
  })).filter((g) => g.rows.length > 0);
  const grouped = groups.length > 1;

  const dismiss = (id: string) => {
    dismissNotification(id);
    setDismissTick((t) => t + 1);
  };

  const resetFilters = () => {
    setKind('all');
    setUrgency([]);
  };

  // "All", then every kind this install actually produces — plus whichever kind
  // is pressed, so the last row of a kind draining away cannot strand the
  // operator inside a chip that has vanished from under them.
  const presets = [
    {
      id: 'all',
      label: 'All',
      count: items.filter(matchesUrgency).length,
      active: kind === 'all',
    },
    ...NOTIFICATION_KINDS.filter((k) => (byKind.get(k.id)?.ever ?? 0) > 0 || kind === k.id).map(
      (k) => ({
        id: k.id,
        label: k.label,
        count: byKind.get(k.id)?.underUrgency ?? 0,
        active: kind === k.id,
      }),
    ),
  ];

  // No row is clickable as a whole. The title is the link when the row has a
  // destination, so the address can be read, copied and opened in a tab. The
  // row itself is a row.
  const row = (nt: Notification) => (
    <div
      key={nt.id}
      data-testid="notification-row"
      className="flex items-center gap-3 border-b border-border-faint px-4 py-3 hover:bg-surface-hover"
    >
      <span
        data-testid="notification-tone"
        title={TONE_TITLE[nt.tone]}
        className="h-2 w-2 flex-none rounded-full"
        style={{ background: TONE[nt.tone], boxShadow: `0 0 7px ${TONE[nt.tone]}` }}
      />
      <div className="min-w-0 flex-1">
        <div data-testid="notification-title" className="flex flex-wrap items-center gap-1.5 text-[13px]">
          {nt.href ? (
            <Link to={nt.href} className="text-accent hover:underline">
              {formatNotificationTitle(nt.title)}
            </Link>
          ) : (
            formatNotificationTitle(nt.title)
          )}
          {/* How a hunt ended, from its outcome field. */}
          <HuntOutcomeChip outcome={nt.outcome} />
          {/* A run against planted synthetic scenarios must never read as a
              real one — badge it wherever the row appears. */}
          {nt.isSynthEval && <SyntheticEvalBadge />}
        </div>
        {formatNotificationWhen(nt.when) && (
          <div className="mt-0.5 font-mono text-[11px] text-faint">
            {formatNotificationWhen(nt.when)}
          </div>
        )}
      </div>
      {nt.dismissible !== false && (
        <button
          onClick={() => dismiss(nt.id)}
          aria-label="Dismiss"
          title="Take this notification off the list. It does not change the work it names."
          className="flex flex-none p-1 text-faint hover:text-danger"
        >
          <X size={15} />
        </button>
      )}
    </div>
  );

  return (
    <div className="px-[22px] pb-[60px] pt-5">
      <div className="mb-4 flex items-start justify-between gap-3">
        <div>
          <div className="flex items-baseline gap-3">
            <div className="text-title">Notifications</div>
            <Freshness at={lastUpdated} />
          </div>
          <div className="mt-0.5 text-[13px] text-dim">
            {/* The count stays UNFILTERED, like the sibling screens' header
                counts — it is what the bell badge shows, and the two disagreeing
                is the phantom-badge bug all over again. When a filter is on, say
                how much of it is on screen instead of quietly restating it. */}
            {filtered && `${visible.length} of ${items.length} shown. `}
            {/* Names only the row types on the list, the loaded count, and
                whether more exist (D3). */}
            {describeNotifications(items, more)}
          </div>
        </div>
        {/* Dismiss all covers every event, whatever the filter shows, and
            the unread shadow hits. It steps over a row the server marks
            undismissible: one click that sweeps away a tamper finding is not
            a tamper alarm. */}
        <div className="flex max-w-[460px] flex-none flex-col items-end">
          <DismissAllControl
            rows={items}
            more={more}
            needsYou={needsYou}
            loadedAt={lastUpdated}
            onDone={refetch}
          />
        </div>
      </div>
      {failCount >= 2 && <StaleNotice since={lastUpdated} onRefresh={refetch} className="mb-3" />}

      {/* Every part of the count the bell badge shows, with its scope. */}
      <NeedsYouBlock
        state={needsYou}
        className="mb-4 rounded-card border border-border bg-surface-1 px-4 py-3"
      />

      {/* The shared list toolbar, in its sibling placement: directly above the
          list, chip row over facet row, so the four screens in this nav group
          line up on the same left edge and the same top edge. */}
      <ListToolbar
        presets={presets}
        presetsLabel="Types"
        onPreset={(id) => setKind(id as NotificationKind | 'all')}
      >
        <MultiSelect
          label="Urgency"
          options={URGENCY.map((u) => ({ value: u.value, label: u.label }))}
          value={urgency}
          onChange={setUrgency}
        />
      </ListToolbar>

      <div className="overflow-hidden rounded-card border border-border bg-surface-1">
        {loading && <LoadingState />}
        {error && (
          <div className="p-3">
            <ErrorState error={error} onRetry={refetch} label="notifications" />
          </div>
        )}
        {!loading && !error && items.length === 0 && (
          <div className="px-4 py-12 text-center text-[13px] text-faint">
            <Bell size={20} className="mx-auto mb-2 opacity-40" />
            {NO_NOTIFICATIONS}
          </div>
        )}
        {/* Filtered-to-nothing is a different fact from having nothing, and it
            has a different way out. Saying "No active notifications." over a
            live queue would be a lie the operator can act on. */}
        {!loading && !error && items.length > 0 && visible.length === 0 && (
          <div className="px-4 py-12 text-center text-[13px] text-faint">
            <Bell size={20} className="mx-auto mb-2 opacity-40" />
            No notifications match these filters.
            <div className="mt-2.5">
              <button
                onClick={resetFilters}
                className="rounded-control border border-border-strong px-3 py-1.5 text-[12px] font-semibold text-dim hover:border-accent hover:text-text"
              >
                Show all notifications ({items.length})
              </button>
            </div>
          </div>
        )}
        {grouped
          ? groups.map((g) => (
              <div key={g.id}>
                <div
                  data-testid="notification-group"
                  title={GROUP_TITLE[g.id]}
                  className="border-b border-border-faint bg-surface-2 px-4 py-1.5 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint"
                >
                  {g.label}
                </div>
                {g.rows.map(row)}
              </div>
            ))
          : visible.map(row)}
      </div>
      {/* The API cut the list at the limit. A full answer can have more
          behind it, so the control loads 20 more rows. */}
      {more && !error && (
        <button
          onClick={() => setLimit((l) => nextNotificationLimit(l))}
          className="mt-3 rounded-control border border-border-strong px-3 py-1.5 text-[12px] font-semibold text-dim hover:border-accent hover:text-text"
        >
          Show more
        </button>
      )}
    </div>
  );
}
