import { Bell, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ErrorState, Freshness, LoadingState, StaleNotice } from '../components/States';
import { getNotifications } from '../lib/api';
import {
  NOTIFICATIONS_DISMISSED_EVENT,
  dismissMany,
  dismissNotification,
  formatNotificationTitle,
  getDismissed,
} from '../lib/notifications';
import type { Notification } from '../lib/types';
import { useAsync } from '../lib/useAsync';

const TONE: Record<Notification['tone'], string> = {
  danger: '#f04438',
  warn: '#f5a623',
  accent: '#4b8bf5',
};

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

  const items = (data ?? []).filter((n) => !dismissed.has(n.id));

  const dismiss = (id: string) => {
    dismissNotification(id);
    setDismissTick((t) => t + 1);
  };

  const clearAll = () => {
    dismissMany(items.map((n) => n.id));
    setDismissTick((t) => t + 1);
  };

  return (
    <div className="px-[22px] pb-[60px] pt-5">
      <div className="mb-4 flex items-start justify-between gap-3">
        <div>
          <div className="flex items-baseline gap-3">
            <div className="text-title">Notifications</div>
            <Freshness at={lastUpdated} />
          </div>
          <div className="mt-0.5 text-[13px] text-dim">
            {items.length} active · in-flight investigations and last-24h completions
          </div>
        </div>
        {items.length > 0 && (
          <button
            onClick={clearAll}
            className="mt-1 flex-none rounded-control border border-border-strong bg-surface-3 px-3 py-1.5 text-[12px] font-semibold text-dim hover:border-accent hover:text-text"
          >
            Clear all
          </button>
        )}
      </div>
      {failCount >= 2 && <StaleNotice since={lastUpdated} onRefresh={refetch} className="mb-3" />}
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
        {items.map((nt) => (
          <div
            key={nt.id}
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
              <div className="text-[13px]">{formatNotificationTitle(nt.title)}</div>
              {nt.when && <div className="mt-0.5 font-mono text-[11px] text-faint">{nt.when} ago</div>}
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
        ))}
      </div>
    </div>
  );
}
