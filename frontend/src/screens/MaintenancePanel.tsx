import { type Maintenance, getMaintenance } from '../lib/api';
import { CollapseChevron } from '../components/Panel';
import { ErrorState, LoadingState } from '../components/States';
import { absTime } from '../lib/timeRange';
import { useAsync } from '../lib/useAsync';

function fmtSize(bytes: number): string {
  if (bytes >= 1 << 30) return `${(bytes / (1 << 30)).toFixed(1)} GiB`;
  if (bytes >= 1 << 20) return `${(bytes / (1 << 20)).toFixed(1)} MiB`;
  if (bytes >= 1 << 10) return `${(bytes / (1 << 10)).toFixed(0)} KiB`;
  return `${bytes} B`;
}

/**
 * Scheduled maintenance — the in-product window onto the host cron jobs
 * (nightly backup, daily blocklist refresh). The panel shows OBSERVED facts
 * only (archives on disk, feed freshness): automation the user can't see in
 * the UI doesn't exist (user requirement, 2026-07-16).
 */
export function MaintenancePanel({
  collapsed = false,
  onToggleCollapse,
}: {
  collapsed?: boolean;
  onToggleCollapse?: () => void;
} = {}) {
  const { data, loading, error } = useAsync<Maintenance>(getMaintenance, [], {
    refetchInterval: 300_000,
  });
  const backups = data?.backups ?? [];

  return (
    <div id="maintenance" className="mb-[22px] scroll-mt-6">
      <div className="mb-1 flex items-center gap-2">
        <div className="text-[15px] font-semibold">Scheduled maintenance</div>
        {onToggleCollapse && (
          <CollapseChevron
            collapsed={collapsed}
            onToggle={onToggleCollapse}
            label="Toggle Scheduled maintenance"
          />
        )}
      </div>
      {!collapsed && (
        <>
          <div className="mb-3 text-[12.5px] leading-[1.5] text-dim">
            What the host cron jobs actually did — nightly database backups (kept 14 days,
            plus a copy outside the container) and the daily blocklist-feed refresh. Stale
            rows here mean a cron is not running.
          </div>

          {loading && !data && <LoadingState />}
          {error && (
            <div className="mb-3">
              <ErrorState error={error} />
            </div>
          )}

          {data && (
            <>
              <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-[.06em] text-faint">
                Blocklist feeds
              </div>
              <div className="mb-4 rounded-card border border-border bg-surface-1 px-3.5 py-2.5 text-[12.5px] text-text-2">
                {data.blocklists_refreshed ? (
                  <>
                    <span className="font-semibold">{data.blocklist_files}</span> feed file
                    {data.blocklist_files === 1 ? '' : 's'} · last refreshed{' '}
                    <span className="font-semibold">{absTime(data.blocklists_refreshed)}</span>
                  </>
                ) : (
                  <span className="text-faint">
                    No blocklist files yet — the refresh cron has not run.
                  </span>
                )}
              </div>

              <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-[.06em] text-faint">
                Backups
              </div>
              <div className="overflow-hidden rounded-card border border-border bg-surface-1">
                {backups.length === 0 && (
                  <div className="px-3.5 py-4 text-[12.5px] text-faint">
                    No backup archives yet — the backup cron has not run.
                  </div>
                )}
                {backups.map((b) => (
                  <div
                    key={b.name}
                    className="flex items-center gap-3 border-b border-border-faint px-3.5 py-2 text-[12px] last:border-0"
                  >
                    <span className="min-w-0 flex-1 truncate font-mono">{b.name}</span>
                    <span className="flex-none text-faint">{fmtSize(b.size_bytes)}</span>
                    <span className="flex-none text-faint">{absTime(b.modified)}</span>
                  </div>
                ))}
              </div>
              <div className="mt-1.5 font-mono text-[10.5px] text-faint">
                archives in {data.backups_dir}
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
