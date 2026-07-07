import { useState } from 'react';
import {
  type DetectionNomination,
  type DetectionOverride,
  getDetectionTuning,
  muteRule,
  unmuteRule,
} from '../lib/api';
import { CollapseChevron } from '../components/Panel';
import { ErrorState, LoadingState } from '../components/States';
import { useAsync } from '../lib/useAsync';

/** Color + label for a tuning recommendation. */
function recBadge(rec: DetectionNomination['recommendation']): { color: string; label: string } {
  if (rec === 'mute') return { color: '#f04438', label: 'Mute' };
  if (rec === 'monitor') return { color: '#f5a623', label: 'Monitor' };
  return { color: '#8b949e', label: '—' };
}

/**
 * The analyst-feedback signal for a nomination — the human corrections that drove
 * (or strengthened) it. Returns '' when the analyst has not touched the rule, so
 * the caller can skip rendering the line entirely.
 */
function analystSignal(n: DetectionNomination): string {
  const parts: string[] = [];
  if (n.override_fp > 0) {
    parts.push(`${n.override_fp} analyst FP-override${n.override_fp === 1 ? '' : 's'}`);
  }
  const resolved = n.chat_resolved + n.manual_resolved;
  if (resolved > 0) {
    const detail: string[] = [];
    if (n.chat_resolved > 0) detail.push(`${n.chat_resolved} chat`);
    if (n.manual_resolved > 0) detail.push(`${n.manual_resolved} manual`);
    parts.push(`${resolved} analyst-resolved (${detail.join(' · ')})`);
  }
  return parts.join(' · ');
}

export function DetectionTuningPanel({
  collapsed = false,
  onToggleCollapse,
}: {
  collapsed?: boolean;
  onToggleCollapse?: () => void;
} = {}) {
  // A nonce drives an optimistic refetch after every mute / un-mute.
  const [nonce, setNonce] = useState(0);
  const { data, loading, error } = useAsync(getDetectionTuning, [nonce]);
  const [actionError, setActionError] = useState('');
  const [busy, setBusy] = useState(false);

  const nominations = data?.nominations ?? [];
  const overrides = data?.overrides ?? [];

  // Wrap a mutation so any error surfaces inline and the lists refetch on success.
  const mutate = (p: Promise<unknown>) => {
    setActionError('');
    setBusy(true);
    p.then(() => setNonce((n) => n + 1))
      .catch((e: unknown) =>
        setActionError(e instanceof Error ? e.message : 'Action failed'),
      )
      .finally(() => setBusy(false));
  };

  return (
    <div id="detection-tuning" className="mb-[22px] scroll-mt-6">
      <div className="mb-1 flex items-center gap-2">
        <div className="text-[15px] font-semibold">Detection tuning</div>
        {onToggleCollapse && (
          <CollapseChevron collapsed={collapsed} onToggle={onToggleCollapse} label="Toggle Detection tuning" />
        )}
      </div>
      {!collapsed && (
      <>
      <div className="mb-3 text-[12.5px] leading-[1.5] text-dim">
        Rules that fire a lot and keep coming back false-positive are nominated here. Muting a
        rule hides its alerts from the default feed — a soft, reversible suppression that{' '}
        <strong>never changes Security Onion</strong>. A rule that has ever caught a true
        positive is never nominated.
      </div>

      {actionError && (
        <div className="mb-2 text-[12px] text-danger">{actionError}</div>
      )}

      {/* ── Nominations ──────────────────────────────────────────────────── */}
      <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-[.06em] text-faint">
        Nominated rules
      </div>
      <div className="mb-4 overflow-hidden rounded-card border border-border bg-surface-1">
        <div className="grid grid-cols-[1fr_80px_120px_110px_90px] gap-2 border-b border-border bg-surface-2 px-3.5 py-2 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
          <div>Rule</div>
          <div>Alerts</div>
          <div>FP / TP / NMI</div>
          <div>Recommend</div>
          <div />
        </div>
        {loading && <LoadingState />}
        {error && (
          <div className="p-3">
            <ErrorState error={error} />
          </div>
        )}
        {!loading && !error && nominations.length === 0 && (
          <div className="px-3.5 py-4 text-[12.5px] text-faint">
            No noisy rules nominated — the feed looks healthy.
          </div>
        )}
        {!loading &&
          !error &&
          nominations.map((n) => {
            const rb = recBadge(n.recommendation);
            return (
              <div
                key={n.rule_name}
                className="grid grid-cols-[1fr_80px_120px_110px_90px] items-center gap-2 border-b border-border-faint px-3.5 py-3 last:border-b-0"
              >
                <div className="min-w-0">
                  <div className="truncate text-[13px] font-medium" title={n.rule_name}>
                    {n.rule_name}
                  </div>
                  <div className="mt-0.5 text-[11px] leading-[1.4] text-faint">{n.reason}</div>
                  {analystSignal(n) && (
                    <div className="mt-0.5 text-[11px] leading-[1.4] text-accent" title="Analyst feedback on this rule">
                      {analystSignal(n)}
                    </div>
                  )}
                </div>
                <div className="font-mono text-[12px] text-dim">{n.alert_count}</div>
                <div className="font-mono text-[11.5px] text-dim">
                  {n.fp} / {n.tp} / {n.nmi}
                </div>
                <div>
                  <span
                    className="inline-flex items-center gap-1.5 text-[11.5px]"
                    style={{ color: rb.color }}
                  >
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: rb.color }} />
                    {rb.label}
                  </span>
                </div>
                <div className="text-right">
                  {n.already_muted ? (
                    <span className="text-[11px] text-faint">muted</span>
                  ) : (
                    <button
                      onClick={() => mutate(muteRule(n.rule_name, n.reason))}
                      disabled={busy}
                      className="flex-none rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-[5px] text-[11.5px] font-semibold text-text hover:border-accent disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      Mute
                    </button>
                  )}
                </div>
              </div>
            );
          })}
      </div>

      {/* ── Active overrides ─────────────────────────────────────────────── */}
      <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-[.06em] text-faint">
        Muted rules ({overrides.length})
      </div>
      <div className="overflow-hidden rounded-card border border-border bg-surface-1">
        <div className="grid grid-cols-[1fr_140px_90px] gap-2 border-b border-border bg-surface-2 px-3.5 py-2 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
          <div>Rule</div>
          <div>Muted by</div>
          <div />
        </div>
        {!loading && !error && overrides.length === 0 && (
          <div className="px-3.5 py-4 text-[12.5px] text-faint">
            No muted rules. Mute a nominated rule above to suppress it from the default feed.
          </div>
        )}
        {overrides.map((o: DetectionOverride) => (
          <div
            key={o.id}
            className="grid grid-cols-[1fr_140px_90px] items-center gap-2 border-b border-border-faint px-3.5 py-3 last:border-b-0"
          >
            <div className="min-w-0">
              <div className="truncate text-[13px] font-medium" title={o.rule_name}>
                {o.rule_name}
              </div>
              {o.reason && (
                <div className="mt-0.5 text-[11px] leading-[1.4] text-faint">{o.reason}</div>
              )}
            </div>
            <div className="truncate text-[11.5px] text-dim" title={o.created_by}>
              {o.created_by}
            </div>
            <div className="text-right">
              <button
                onClick={() => mutate(unmuteRule(o.id))}
                disabled={busy}
                className="flex-none rounded-[7px] border px-[11px] py-[5px] text-[11.5px] font-semibold text-danger hover:bg-[rgba(240,68,56,.12)] disabled:cursor-not-allowed disabled:opacity-40"
                style={{ borderColor: 'rgba(240,68,56,.3)' }}
              >
                Un-mute
              </button>
            </div>
          </div>
        ))}
      </div>
      </>
      )}
    </div>
  );
}
