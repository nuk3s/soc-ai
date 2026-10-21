import { type DataSource, getDataSources } from '../lib/api';
import { HelpText } from '../components/HelpText';
import { CollapseChevron } from '../components/Panel';
import { ErrorState, LoadingState } from '../components/States';
import { useAsync } from '../lib/useAsync';

function freshness(iso: string | null): string {
  if (!iso) return '—';
  const days = Math.floor((Date.now() - new Date(iso).getTime()) / 86_400_000);
  if (days <= 0) return 'today';
  if (days === 1) return 'yesterday';
  return `${days} d ago`;
}

/** A data source row. `state` is the status the backend judged: for a local
 * feed it applies the doctor's freshness rule, so a stale feed is never
 * "Active" (dogfood 2026-10-19, H1-D11). */
type SourceRow = DataSource & { state?: string };

const GREEN = '#3fb950';
const AMBER = '#f5a623';
const GREY = '#8b949e';
const RED = '#f85149';

const STATE_STYLE: Record<string, { color: string; label: string }> = {
  active: { color: GREEN, label: 'Active' },
  stale: { color: AMBER, label: 'Stale' },
  partial: { color: AMBER, label: 'Partial' },
  missing: { color: AMBER, label: 'Missing' },
  needs_key: { color: AMBER, label: 'Needs key' },
  off: { color: GREY, label: 'Off' },
  // The grid row reads the health probe (dogfood 2026-10-19, R5-D30).
  down: { color: RED, label: 'Down' },
  slow: { color: AMBER, label: 'Slow' },
  unknown: { color: GREY, label: 'Unknown' },
};

function status(s: SourceRow): { color: string; label: string } {
  const judged = s.state ? STATE_STYLE[s.state] : undefined;
  if (judged) return judged;
  // A backend that sends no state: the presence rule this panel used before.
  if (s.enabled && (s.present || s.category !== 'Local feed')) return STATE_STYLE.active;
  if (s.needs_key && !s.key_configured) return STATE_STYLE.needs_key;
  if (s.category === 'Local feed' && !s.present) return STATE_STYLE.missing;
  return STATE_STYLE.off;
}

export function DataSourcesPanel({
  collapsed = false,
  onToggleCollapse,
}: {
  collapsed?: boolean;
  onToggleCollapse?: () => void;
} = {}) {
  const { data, loading, error } = useAsync(getDataSources, [], { refetchInterval: 30_000 });
  const sources: SourceRow[] = data?.sources ?? [];

  return (
    <div id="data-sources" className="mb-[22px] scroll-mt-6">
      <div className="mb-1 flex items-center gap-2">
        <div className="text-[15px] font-semibold">Data sources</div>
        {onToggleCollapse && (
          <CollapseChevron collapsed={collapsed} onToggle={onToggleCollapse} label="Toggle Data sources" />
        )}
      </div>
      {!collapsed && (
      <>
      <div className="mb-3 text-[12.5px] leading-[1.5] text-dim">
        The first row is the grid. soc-ai reads every alert and event from it. The agent uses
        two types of source for enrichment. A local feed sends nothing out of this network. An
        online lookup is opt-in.{' '}
        <HelpText text="Set the provider keys in Settings > API keys. Turn on the online lookups in Settings > Online enrichment." />
      </div>
      <div className="overflow-hidden rounded-card border border-border bg-surface-1">
        <div className="grid grid-cols-[1fr_120px_90px_80px_100px] gap-2 border-b border-border bg-surface-2 px-3.5 py-2 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
          <div>Source</div>
          <div>Type</div>
          <div>Freshness</div>
          <div>Key</div>
          <div>Status</div>
        </div>
        {loading && <LoadingState />}
        {error && (
          <div className="p-3">
            <ErrorState error={error} />
          </div>
        )}
        {!loading &&
          !error &&
          sources.map((s) => {
            const st = status(s);
            return (
              <div
                key={s.id}
                data-setting-key={`source:${s.id}`}
                className="grid grid-cols-[1fr_120px_90px_80px_100px] items-center gap-2 border-b border-border-faint px-3.5 py-3 last:border-b-0"
              >
                <div className="min-w-0">
                  <div className="text-[13px] font-medium">{s.name}</div>
                  <div className="mt-0.5 text-[11px] leading-[1.4] text-faint">
                    <HelpText text={s.note} />
                  </div>
                </div>
                <div className="text-[11.5px] text-dim">
                  {s.category}
                  <div className="text-[10px] text-faint">
                    {s.egress === 'none' ? 'zero-egress' : 'sends data out'}
                  </div>
                </div>
                <div className="font-mono text-[11.5px] text-dim">
                  {s.category === 'Local feed' ? freshness(s.last_refreshed) : '—'}
                </div>
                <div className="text-[11.5px] text-dim">
                  {s.needs_key ? (s.key_configured ? 'set ✓' : 'missing') : '—'}
                </div>
                <div>
                  <span
                    className="inline-flex items-center gap-1.5 text-[11.5px]"
                    style={{ color: st.color }}
                  >
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: st.color }} />
                    {st.label}
                  </span>
                </div>
              </div>
            );
          })}
      </div>
      </>
      )}
    </div>
  );
}
