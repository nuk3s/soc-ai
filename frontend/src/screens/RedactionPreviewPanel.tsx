import { Eye, ShieldCheck } from 'lucide-react';
import { getRedactionPreview } from '../lib/api';
import { CollapseChevron, SectionTitle } from '../components/Panel';
import { ErrorState, LoadingState } from '../components/States';
import { useAsync } from '../lib/useAsync';

// Shows EXACTLY what the Oracle pre-egress sanitizer would send: a sample built
// from this deployment's own internal identifiers, before → after. Trust surface
// for the opt-in cloud Oracle — the operator can confirm every internal
// identifier is pseudonymized and public addresses pass through, before enabling.
export function RedactionPreviewPanel({
  collapsed = false,
  onToggleCollapse,
}: {
  collapsed?: boolean;
  onToggleCollapse?: () => void;
} = {}) {
  const { data, loading, error } = useAsync(getRedactionPreview, []);

  return (
    <div id="redaction-preview" className="mb-[22px] scroll-mt-6">
      <SectionTitle
        right={
          <span className="flex items-center gap-2 text-faint">
            <Eye size={14} />
            {onToggleCollapse && (
              <CollapseChevron collapsed={collapsed} onToggle={onToggleCollapse} label="Toggle Redaction preview" />
            )}
          </span>
        }
      >
        Pre-egress redaction preview
      </SectionTitle>
      {!collapsed && (
      <div className="overflow-hidden rounded-card border border-border bg-surface-1 p-[15px]">
        {loading && <LoadingState label="Loading preview…" />}
        {error && <ErrorState error={error} />}
        {data && (
          <>
            <div className="mb-3 flex items-start gap-2 text-[12.5px] leading-[1.55] text-dim">
              <span className="mt-0.5 flex-none text-success"><ShieldCheck size={15} /></span>
              <span>{data.note}</span>
            </div>

            <div className="mb-3 flex flex-wrap gap-1.5">
              {Object.entries(data.summary).map(([cat, n]) => (
                <span
                  key={cat}
                  className="rounded-chip border border-border-2 bg-surface-2 px-2 py-[2px] font-mono text-[11px] text-text-2"
                >
                  {cat} × {n}
                </span>
              ))}
              {Object.keys(data.summary).length === 0 && (
                <span className="text-[12px] text-faint">nothing to redact in the sample</span>
              )}
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <div>
                <div className="mb-1 text-[11px] font-semibold uppercase tracking-[.05em] text-faint">
                  On your grid
                </div>
                <pre className="overflow-x-auto rounded-control border border-border-faint bg-bg p-2.5 font-mono text-[11.5px] leading-[1.5] text-text-2">
                  {JSON.stringify(data.original, null, 2)}
                </pre>
              </div>
              <div>
                <div className="mb-1 text-[11px] font-semibold uppercase tracking-[.05em] text-success">
                  Sent to the Oracle
                </div>
                <pre className="overflow-x-auto rounded-control border border-[rgba(63,185,80,.25)] bg-[rgba(63,185,80,.04)] p-2.5 font-mono text-[11.5px] leading-[1.5] text-text-2">
                  {JSON.stringify(data.sanitized, null, 2)}
                </pre>
              </div>
            </div>
          </>
        )}
      </div>
      )}
    </div>
  );
}
