import { Bell, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ListToolbar } from '../components/ListToolbar';
import { MultiSelect } from '../components/MultiSelect';
import { ErrorState, Freshness, LoadingState, StaleNotice } from '../components/States';
import { getNotifications } from '../lib/api';
import {
  NOTIFICATIONS_DISMISSED_EVENT,
  NOTIFICATION_KINDS,
  dismissMany,
  dismissNotification,
  formatNotificationTitle,
  formatNotificationWhen,
  getDismissed,
  notificationKind,
  type NotificationKind,
} from '../lib/notifications';
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

/**
 * Notifications — the same list toolbar its neighbours wear.
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
 * rule name or an objective, over a list the API caps at 12 rows, so a third
 * control would filter nothing the two chips cannot already reach.
 *
 * No saved views either, and that is a judgement rather than an omission. A
 * saved view is a durable name for a query worth re-running; this list is
 * derived fresh from live state on every poll, holds a rolling 24 hours, and is
 * capped at 12 rows. There is no query here to be worth naming — one chip and
 * one multi-select IS the whole filter state, and it resets every shift. The
 * preset chips give the chip row its content, so the screen still opens with the
 * two-row toolbar its siblings do.
 */
export function Notifications() {
  const navigate = useNavigate();
  const { data, loading, error, lastUpdated, failCount, refetch } = useAsync(getNotifications, [], {
    refetchInterval: 15000,
  });
  // Bump to re-read localStorage after a dismissal. The dismissed set is
  // re-read on every render (not snapshotted at mount) so this screen and the
  // Topbar bell — which polls the same store — can never disagree about what
  // is dismissed (the badge/panel mismatch from dogfood 2026-07-15).
  const [dismissTick, setDismissTick] = useState(0);
  void dismissTick;
  // A dismiss from another view (the Topbar bell) also fires this event; re-read
  // so the pane never diverges from the bell between refetches.
  useEffect(() => {
    const bump = () => setDismissTick((t) => t + 1);
    window.addEventListener(NOTIFICATIONS_DISMISSED_EVENT, bump);
    return () => window.removeEventListener(NOTIFICATIONS_DISMISSED_EVENT, bump);
  }, []);
  const dismissed = getDismissed();

  const [kind, setKind] = useState<NotificationKind | 'all'>('all');
  const [urgency, setUrgency] = useState<string[]>([]);

  // Every undismissed notification. The header count, "Clear all" and the bell
  // badge all read THIS — a filter narrows what is shown, never what is active.
  const items = (data ?? []).filter((n) => !dismissed.has(n.id));

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
  // No memo on any of this, deliberately: the API caps the list at 12 rows, and
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

  // Group headers earn their place only while the rows actually span kinds:
  // under a kind chip they would just repeat the chip that is already pressed.
  const groups = NOTIFICATION_KINDS.map((k) => ({
    ...k,
    rows: visible.filter((n) => notificationKind(n) === k.id),
  })).filter((g) => g.rows.length > 0);
  const grouped = groups.length > 1;

  const dismiss = (id: string) => {
    dismissNotification(id);
    setDismissTick((t) => t + 1);
  };

  const clearAll = () => {
    dismissMany(items.map((n) => n.id));
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

  const row = (nt: Notification) => (
    <div
      key={nt.id}
      data-testid="notification-row"
      onClick={() => {
        if (nt.href) navigate(nt.href);
      }}
      className={
        'flex items-center gap-3 border-b border-border-faint px-4 py-3 ' +
        (nt.href ? 'cursor-pointer hover:bg-surface-hover' : '')
      }
    >
      <span
        className="h-2 w-2 flex-none rounded-full"
        style={{ background: TONE[nt.tone], boxShadow: `0 0 7px ${TONE[nt.tone]}` }}
      />
      <div className="min-w-0 flex-1">
        <div data-testid="notification-title" className="text-[13px]">
          {formatNotificationTitle(nt.title)}
        </div>
        {formatNotificationWhen(nt.when) && (
          <div className="mt-0.5 font-mono text-[11px] text-faint">
            {formatNotificationWhen(nt.when)}
          </div>
        )}
      </div>
      <button
        onClick={(e) => {
          e.stopPropagation();
          dismiss(nt.id);
        }}
        aria-label="Dismiss"
        className="flex flex-none p-1 text-faint hover:text-danger"
      >
        <X size={15} />
      </button>
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
            {filtered ? `${visible.length} of ${items.length} shown` : `${items.length} active`} ·
            in-flight investigations and last-24h completions
          </div>
        </div>
        {items.length > 0 && (
          <button
            onClick={clearAll}
            title="Dismiss every active notification, including any the current filter is hiding"
            className="mt-1 flex-none rounded-control border border-border-strong bg-surface-3 px-3 py-1.5 text-[12px] font-semibold text-dim hover:border-accent hover:text-text"
          >
            Clear all
          </button>
        )}
      </div>
      {failCount >= 2 && <StaleNotice since={lastUpdated} onRefresh={refetch} className="mb-3" />}

      {/* The shared list toolbar, in its sibling placement: directly above the
          list, chip row over facet row, so the four screens in this nav group
          line up on the same left edge and the same top edge. */}
      <ListToolbar
        presets={presets}
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
            No active notifications.
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
                  className="border-b border-border-faint bg-surface-2 px-4 py-1.5 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint"
                >
                  {g.label}
                </div>
                {g.rows.map(row)}
              </div>
            ))
          : visible.map(row)}
      </div>
    </div>
  );
}
