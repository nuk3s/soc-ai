import { CollapseChevron } from '../components/Panel';
import { ErrorState, LoadingState } from '../components/States';
import { type AgentTool, getAgentTools } from '../lib/api';
import { useAsync } from '../lib/useAsync';

const CATEGORY_ORDER = ['Query', 'Enrichment', 'Web research', 'PCAP', 'Action'];

/**
 * Agent tools — every capability the triage & chat agent can call, with a short
 * description and the config/resources each depends on (ES, an API key, PCAP,
 * the online-enrichment switch). Unavailable tools are greyed with their unmet
 * requirement flagged. Read-only against /config/agent-tools.
 */
export function AgentToolsPanel({
  collapsed = false,
  onToggleCollapse,
}: {
  collapsed?: boolean;
  onToggleCollapse?: () => void;
} = {}) {
  const { data, loading, error } = useAsync(getAgentTools, []);
  const tools: AgentTool[] = data?.tools ?? [];
  const groups = CATEGORY_ORDER.map((cat) => ({
    cat,
    items: tools.filter((t) => t.category === cat),
  })).filter((g) => g.items.length > 0);

  return (
    <div id="agent-tools" className="mb-[22px] scroll-mt-6">
      <div className="mb-1 flex items-center gap-2">
        <div className="text-[15px] font-semibold">Agent tools</div>
        {onToggleCollapse && (
          <CollapseChevron collapsed={collapsed} onToggle={onToggleCollapse} label="Toggle Agent tools" />
        )}
      </div>
      {!collapsed && (
      <>
      <div className="mb-3 text-[12.5px] leading-[1.5] text-dim">
        Every tool the triage & chat agent can call, and what each needs turned on. Greyed tools are
        unavailable until their requirement (○) is met.
      </div>
      <div className="overflow-hidden rounded-card border border-border bg-surface-1">
        {loading && !data && <LoadingState />}
        {error && (
          <div className="p-3">
            <ErrorState error={error} />
          </div>
        )}
        {groups.map((g) => (
          <div key={g.cat}>
            <div className="border-b border-border-faint bg-surface-2 px-[15px] py-1.5 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
              {g.cat}
            </div>
            {g.items.map((t) => (
              <div
                key={t.name}
                className="flex items-start gap-3 border-b border-border-faint px-[15px] py-2.5 last:border-0"
                style={{ opacity: t.available ? 1 : 0.55 }}
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[12.5px] font-semibold text-text-2">{t.name}</span>
                    {!t.read_only && (
                      <span
                        className="rounded-chip border px-1.5 py-px text-[9.5px] font-semibold uppercase tracking-[.04em]"
                        style={{ color: '#f5a623', borderColor: 'rgba(245,166,35,.35)', background: 'rgba(245,166,35,.08)' }}
                      >
                        write
                      </span>
                    )}
                  </div>
                  <div className="mt-0.5 text-[12px] leading-[1.4] text-dim">{t.description}</div>
                  {t.requires.length > 0 && (
                    <div className="mt-1.5 flex flex-wrap gap-1.5">
                      {t.requires.map((r) => {
                        const ok = !t.missing.includes(r);
                        return (
                          <span
                            key={r}
                            className="rounded-chip border px-1.5 py-px text-[10px] font-medium"
                            style={
                              ok
                                ? { color: '#3fb950', borderColor: 'rgba(63,185,80,.3)', background: 'rgba(63,185,80,.07)' }
                                : { color: '#f5a623', borderColor: 'rgba(245,166,35,.3)', background: 'rgba(245,166,35,.07)' }
                            }
                          >
                            {ok ? '✓' : '○'} {r}
                          </span>
                        );
                      })}
                    </div>
                  )}
                </div>
                <span
                  className="flex-none text-[11px] font-semibold"
                  style={{ color: t.available ? '#3fb950' : '#8b94a3' }}
                >
                  {t.available ? 'Available' : 'Unavailable'}
                </span>
              </div>
            ))}
          </div>
        ))}
      </div>
      </>
      )}
    </div>
  );
}
