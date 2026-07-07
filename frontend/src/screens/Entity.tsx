import { ChevronLeft, Crosshair, Server, ShieldAlert } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { SeverityTag, VerdictPill } from '../components/Badges';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { getEntity } from '../lib/api';
import { absTime } from '../lib/timeRange';
import type { EntityTimelineItem, Severity, Verdict } from '../lib/types';
import { useAsync } from '../lib/useAsync';

// The narrow frontend severity union the pill understands; a hunt finding can
// carry "info" (or an odd value) — coerce so the chip never sees an off-union sev.
const FE_SEV: Severity[] = ['critical', 'high', 'medium', 'low'];
function feSev(sev?: string | null): Severity {
  const v = (sev ?? '').toLowerCase() as Severity;
  return FE_SEV.includes(v) ? v : 'low';
}

/** One card in the entity timeline — an investigation or a hunt finding — a link
 *  to its source run, with the verdict / severity chip for its kind. */
function TimelineCard({ item }: { item: EntityTimelineItem }) {
  const isInv = item.kind === 'investigation';
  return (
    <Link
      to={item.link.replace(/^\/app/, '')}
      className="group flex items-start gap-3 rounded-card border border-border bg-surface-2 px-3.5 py-3 transition-colors hover:border-accent"
    >
      <span
        className="mt-0.5 flex-none"
        style={{ color: isInv ? '#4b8bf5' : '#f0883e' }}
        title={isInv ? 'Investigation' : 'Hunt finding'}
      >
        {isInv ? <ShieldAlert size={15} /> : <Crosshair size={15} />}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="rounded-chip border border-border-input bg-surface-3 px-1.5 py-px font-mono text-[9.5px] font-semibold uppercase tracking-[.04em] text-dim">
            {isInv ? 'Investigation' : 'Hunt finding'}
          </span>
          <span className="font-mono text-[10.5px] text-faint">{absTime(item.ts)}</span>
        </div>
        <div className="mt-1 truncate text-[13px] font-medium text-text group-hover:text-white">
          {item.title || (isInv ? 'Investigation' : 'Hunt finding')}
        </div>
      </div>
      <div className="flex-none self-center">
        {isInv ? (
          <VerdictPill verdict={(item.verdict ?? 'untriaged') as Verdict} conf={item.confidence} />
        ) : (
          <SeverityTag sev={feSev(item.severity)} />
        )}
      </div>
    </Link>
  );
}

/** Entity pivot page (E3.5): "what do we know about <host-or-ip>" — its
 *  investigations + hunt findings on one newest-first timeline. Reached from
 *  every host chip. Read-only. */
export function Entity() {
  const { value = '' } = useParams();
  const { data, loading, error } = useAsync(() => getEntity(value), [value]);

  return (
    <div className="px-[22px] pb-[60px] pt-[18px] font-sans text-text">
      <div className="mb-3.5 flex flex-wrap items-center gap-3">
        <Link
          to="/alerts"
          className="flex items-center gap-1.5 text-[12.5px] text-dim hover:text-text"
        >
          <ChevronLeft size={13} /> Alerts
        </Link>
        <span className="text-ghost">/</span>
        <div className="text-[15px] font-semibold">Entity</div>
      </div>

      <div className="mx-auto max-w-workstation">
        {loading && !data ? (
          <LoadingState label="Loading entity…" />
        ) : error ? (
          <ErrorState error={error} />
        ) : !data ? (
          <ErrorState error={new Error('Entity not found')} />
        ) : (
          <>
            {/* Header: the entity value + kind + summary counts. */}
            <div className="mb-4 rounded-panel-lg border border-border bg-surface-2 px-5 py-4">
              <div className="flex flex-wrap items-center gap-3">
                <span className="text-dim">
                  <Server size={18} />
                </span>
                <span className="font-mono text-[17px] font-semibold text-white">{data.value}</span>
                <span className="rounded-chip border border-border-input bg-surface-3 px-1.5 py-0.5 font-mono text-[9.5px] font-semibold uppercase tracking-[.04em] text-dim">
                  {data.kind}
                </span>
              </div>
              <div className="mt-2.5 flex flex-wrap items-center gap-4 text-[12px] text-dim">
                <span>
                  <span className="font-semibold text-text">{data.summary.investigationCount}</span>{' '}
                  investigation{data.summary.investigationCount === 1 ? '' : 's'}
                </span>
                <span>
                  <span className="font-semibold text-text">{data.summary.huntFindingCount}</span>{' '}
                  hunt finding{data.summary.huntFindingCount === 1 ? '' : 's'}
                </span>
                {data.summary.latestVerdict && (
                  <span className="flex items-center gap-1.5">
                    latest verdict
                    <VerdictPill verdict={data.summary.latestVerdict as Verdict} showConf={false} />
                  </span>
                )}
              </div>
            </div>

            {/* Timeline: merged investigations + hunt findings, newest first. */}
            {data.timeline.length === 0 ? (
              <EmptyState>
                Nothing recorded for <span className="font-mono text-dim">{data.value}</span> yet — no
                investigations or hunt findings name this entity.
              </EmptyState>
            ) : (
              <div className="flex flex-col gap-2">
                {data.timeline.map((item, i) => (
                  <TimelineCard key={`${item.kind}-${item.link}-${i}`} item={item} />
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
