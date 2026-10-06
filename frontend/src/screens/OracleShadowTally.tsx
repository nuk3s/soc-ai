import { getOracleShadowTally, type OracleShadowReason } from '../lib/api';
import { ORACLE_REASON, ORACLE_SHADOW_CAPTION } from '../lib/tooltips';
import { useAsync } from '../lib/useAsync';

const COLS = 'grid-cols-[110px_1fr_70px_110px]';

function ruleLabel(rule: string): string {
  return rule === 'uncertainty' ? 'Uncertainty' : rule === 'classic' ? 'Classic' : rule;
}

/**
 * The Oracle rule shadow tally: what the uncertainty rule would send beside
 * what the classic rule sent, from the `oracle_shadow` events of the last week.
 * One small table. A failed load says so; it never reads as "the rules agree".
 */
export function OracleShadowTally() {
  const { data, loading, error } = useAsync(() => getOracleShadowTally(7), []);
  const rows: OracleShadowReason[] = data?.by_reason ?? [];

  return (
    <div data-testid="oracle-shadow-tally" className="mt-4">
      <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-[.06em] text-faint">
        Oracle rule shadow, last 7 days
      </div>
      {data && data.mode === 'shadow' && (
        <div className="mb-2 text-[12px] leading-[1.5] text-dim">{ORACLE_SHADOW_CAPTION}</div>
      )}
      {data && (
        <div data-testid="oracle-shadow-summary" className="mb-2 text-[12px] text-dim">
          The uncertainty rule would send {data.would_escalate}. The classic rule sent{' '}
          {data.classic}. Both rules send {data.both}.
        </div>
      )}
      <div className="overflow-hidden rounded-card border border-border bg-surface-1">
        <div
          className={`grid ${COLS} gap-2 border-b border-border bg-surface-2 px-3.5 py-2 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint`}
        >
          <div>Rule</div>
          <div>Reason</div>
          <div>Runs</div>
          <div>Other rule too</div>
        </div>
        {loading && !data && (
          <div className="px-3.5 py-3 text-[12.5px] text-faint">Loading the shadow tally.</div>
        )}
        {error && !data && (
          <div className="px-3.5 py-3 text-[12.5px] text-faint">
            soc-ai could not load the shadow tally. This is not a claim that the rules agree.
          </div>
        )}
        {data && rows.length === 0 && (
          <div className="px-3.5 py-3 text-[12.5px] text-faint">
            {data.mode === 'shadow'
              ? `No run in the last ${data.days} days reached either Oracle rule.`
              : `The Oracle rule mode is ${data.mode}. No shadow row is recorded in this mode.`}
          </div>
        )}
        {rows.map((r) => (
          <div
            key={`${r.rule}:${r.reason}`}
            className={`grid ${COLS} items-center gap-2 border-b border-border-faint px-3.5 py-2 last:border-b-0`}
          >
            <div className="text-[12px] text-dim">{ruleLabel(r.rule)}</div>
            <div className="truncate font-mono text-[11.5px]" title={ORACLE_REASON[r.reason] ?? r.reason}>
              {r.reason}
            </div>
            <div className="font-mono text-[12px] text-dim">{r.count}</div>
            <div className="font-mono text-[12px] text-dim">{r.overlap}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
