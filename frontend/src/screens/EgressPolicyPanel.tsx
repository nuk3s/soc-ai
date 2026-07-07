import { Radio, ShieldCheck } from 'lucide-react';
import { getEgressPolicy } from '../lib/api';
import { CollapseChevron, SectionTitle } from '../components/Panel';
import { ErrorState, LoadingState } from '../components/States';
import { useAsync } from '../lib/useAsync';

// One page listing EVERY possible egress destination, its enable state, its
// redaction posture, and a best-effort 7-day audit count — so "zero egress" is
// inspectable, not asserted. Read-only over settings + the audit index. A
// prominent banner confirms zero egress when nothing can leave the network.
export function EgressPolicyPanel({
  collapsed = false,
  onToggleCollapse,
}: {
  collapsed?: boolean;
  onToggleCollapse?: () => void;
} = {}) {
  const { data, loading, error } = useAsync(getEgressPolicy, []);

  return (
    <div id="egress-policy" className="mb-[22px] scroll-mt-6">
      <SectionTitle
        right={
          <span className="flex items-center gap-2 text-faint">
            <Radio size={14} />
            {onToggleCollapse && (
              <CollapseChevron collapsed={collapsed} onToggle={onToggleCollapse} label="Toggle Egress policy" />
            )}
          </span>
        }
      >
        Egress policy
      </SectionTitle>
      {!collapsed && (
        <div className="overflow-hidden rounded-card border border-border bg-surface-1 p-[15px]">
          {loading && <LoadingState label="Loading egress policy…" />}
          {error && <ErrorState error={error} />}
          {data && (
            <>
              <div className="mb-3 text-[12.5px] leading-[1.55] text-dim">
                Every path by which data can leave this network — with its enable state, what
                redaction it applies, and how many times it actually fired in the last 7 days (from
                the audit trail). Counts are best-effort: <span className="font-mono">—</span> means
                the destination has no dedicated audit kind, or the audit index was unreachable.
              </div>

              {data.zero_egress ? (
                <div className="mb-3 flex items-start gap-2 rounded-control border border-[rgba(63,185,80,.3)] bg-[rgba(63,185,80,.06)] px-3 py-2.5 text-[12.5px] leading-[1.5] text-success">
                  <span className="mt-0.5 flex-none">
                    <ShieldCheck size={15} />
                  </span>
                  <span>
                    <strong>Zero egress.</strong> Every destination below is disabled — nothing
                    leaves this network.
                  </span>
                </div>
              ) : (
                <div className="mb-3 flex items-start gap-2 rounded-control border border-[rgba(245,166,35,.3)] bg-[rgba(245,166,35,.06)] px-3 py-2.5 text-[12.5px] leading-[1.5] text-warn">
                  <span className="mt-0.5 flex-none">⚠</span>
                  <span>
                    <strong>
                      {data.destinations.filter((d) => d.enabled).length} of {data.destinations.length}
                    </strong>{' '}
                    egress destinations are enabled — data can leave this network. Review the posture
                    of each enabled row below.
                  </span>
                </div>
              )}

              <div className="overflow-hidden rounded-card border border-border bg-bg">
                {data.destinations.map((d) => (
                  <div
                    key={d.id}
                    className="flex items-start gap-3 border-b border-border-faint px-[15px] py-3 last:border-0"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-[13px] font-semibold text-text">{d.label}</span>
                        <span className="font-mono text-[11px] text-faint">{d.id}</span>
                        <span
                          className="rounded px-1.5 py-0.5 text-[10.5px] font-semibold"
                          style={
                            d.enabled
                              ? { background: 'rgba(240,68,56,.1)', color: '#f04438' }
                              : { background: 'rgba(34,197,94,.1)', color: '#22c55e' }
                          }
                        >
                          {d.enabled ? 'egress on' : 'off'}
                        </span>
                      </div>
                      <div className="mt-1 text-[12px] text-dim">{d.detail}</div>
                      <div className="mt-1 flex items-center gap-1.5 text-[11.5px] text-faint">
                        <ShieldCheck size={12} className="flex-none" />
                        <span>
                          redaction: <span className="text-text-2">{d.redaction}</span>
                        </span>
                      </div>
                    </div>
                    <div className="flex-none text-right">
                      <div className="font-mono text-[15px] font-semibold text-text">
                        {d.count_7d == null ? '—' : d.count_7d}
                      </div>
                      <div className="text-[10.5px] uppercase tracking-[.05em] text-faint">7-day</div>
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
