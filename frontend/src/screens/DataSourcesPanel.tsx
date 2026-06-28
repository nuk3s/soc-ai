import { type DataSource, getDataSources } from '../lib/api';
import { ErrorState, LoadingState } from '../components/States';
import { useAsync } from '../lib/useAsync';

function freshness(iso: string | null): string {
  if (!iso) return '—';
  const days = Math.floor((Date.now() - new Date(iso).getTime()) / 86_400_000);
  if (days <= 0) return 'today';
  if (days === 1) return 'yesterday';
  return `${days}d ago`;
}

function status(s: DataSource): { color: string; label: string } {
  if (s.enabled && (s.present || s.category !== 'Local feed')) {
    return { color: '#3fb950', label: 'Active' };
  }
  if (s.needs_key && !s.key_configured) return { color: '#f5a623', label: 'Needs key' };
  if (s.category === 'Local feed' && !s.present) return { color: '#f5a623', label: 'Not refreshed' };
  return { color: '#8b949e', label: 'Off' };
}

export function DataSourcesPanel() {
  const { data, loading, error } = useAsync(getDataSources, [], { refetchInterval: 30_000 });
  const sources = data?.sources ?? [];

  return (
    <div id="data-sources" className="mb-[22px] scroll-mt-6">
      <div className="mb-1 text-[15px] font-semibold">Data sources</div>
      <div className="mb-3 text-[12.5px] leading-[1.5] text-dim">
        What the agent draws on for enrichment — local-mirror feeds (zero-egress, refreshed
        out-of-band) and opt-in online lookups. API keys live in <code>.env</code>; the master
        switch for online lookups is under "Online enrichment".
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
                className="grid grid-cols-[1fr_120px_90px_80px_100px] items-center gap-2 border-b border-border-faint px-3.5 py-3 last:border-b-0"
              >
                <div className="min-w-0">
                  <div className="text-[13px] font-medium">{s.name}</div>
                  <div className="mt-0.5 text-[11px] leading-[1.4] text-faint">{s.note}</div>
                </div>
                <div className="text-[11.5px] text-dim">
                  {s.category}
                  <div className="text-[10px] text-faint">
                    {s.egress === 'none' ? 'zero-egress' : 'reaches out'}
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
    </div>
  );
}
