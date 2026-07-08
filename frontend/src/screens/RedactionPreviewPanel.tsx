import { useState } from 'react';
import { Eye, ShieldAlert, ShieldCheck } from 'lucide-react';
import {
  getAnalystRedactionPreview,
  getInvestigations,
  getRedactionPreview,
  type AnalystRedactionPreviewResult,
} from '../lib/api';
import { CollapseChevron, SectionTitle } from '../components/Panel';
import { ErrorState, LoadingState } from '../components/States';
import { useAsync } from '../lib/useAsync';

// Trust surface for the two cloud egress paths, in two tabs:
//
// - "Oracle sample": EXACTLY what the Oracle pre-egress sanitizer would send —
//   a canned sample built from this deployment's own internal identifiers,
//   before → after (unchanged pre-E5.2 behavior).
// - "Analyst path" (E5.2): pick a PAST completed investigation and see the
//   round-1 analyst prompt rebuilt from its stored events, original vs
//   sanitized under the CURRENT identifier config — read-only simulation, so
//   the operator can inspect the analyst-model redaction before (or after)
//   enabling analyst_cloud_redaction.
type Mode = 'oracle' | 'analyst';

/** Shared summary chips: per-category redaction counts (never the values). */
function SummaryChips({ summary }: { summary: Record<string, number> }) {
  return (
    <div className="mb-3 flex flex-wrap gap-1.5">
      {Object.entries(summary).map(([cat, n]) => (
        <span
          key={cat}
          className="rounded-chip border border-border-2 bg-surface-2 px-2 py-[2px] font-mono text-[11px] text-text-2"
        >
          {cat} × {n}
        </span>
      ))}
      {Object.keys(summary).length === 0 && (
        <span className="text-[12px] text-faint">nothing to redact</span>
      )}
    </div>
  );
}

/** Shared before/after panes; `right` labels the egress destination. */
function BeforeAfter({
  original,
  sanitized,
  right,
}: {
  original: string;
  sanitized: string;
  right: string;
}) {
  return (
    <div className="grid gap-3 md:grid-cols-2">
      <div>
        <div className="mb-1 text-[11px] font-semibold uppercase tracking-[.05em] text-faint">
          On your grid
        </div>
        <pre className="max-h-[420px] overflow-auto whitespace-pre-wrap break-words rounded-control border border-border-faint bg-bg p-2.5 font-mono text-[11.5px] leading-[1.5] text-text-2">
          {original}
        </pre>
      </div>
      <div>
        <div className="mb-1 text-[11px] font-semibold uppercase tracking-[.05em] text-success">
          {right}
        </div>
        <pre className="max-h-[420px] overflow-auto whitespace-pre-wrap break-words rounded-control border border-[rgba(63,185,80,.25)] bg-[rgba(63,185,80,.04)] p-2.5 font-mono text-[11.5px] leading-[1.5] text-text-2">
          {sanitized}
        </pre>
      </div>
    </div>
  );
}

function OracleSample() {
  const { data, loading, error } = useAsync(getRedactionPreview, []);
  return (
    <>
      {loading && <LoadingState label="Loading preview…" />}
      {error && <ErrorState error={error} />}
      {data && (
        <>
          <div className="mb-3 flex items-start gap-2 text-[12.5px] leading-[1.55] text-dim">
            <span className="mt-0.5 flex-none text-success"><ShieldCheck size={15} /></span>
            <span>{data.note}</span>
          </div>
          <SummaryChips summary={data.summary} />
          <BeforeAfter
            original={JSON.stringify(data.original, null, 2)}
            sanitized={JSON.stringify(data.sanitized, null, 2)}
            right="Sent to the Oracle"
          />
        </>
      )}
    </>
  );
}

function AnalystPath() {
  const [invId, setInvId] = useState('');
  // The picker reuses the app's existing investigations list API; fetched when
  // this tab mounts (the tab is unmounted while "Oracle sample" is active).
  const invs = useAsync(getInvestigations, []);
  const preview = useAsync<AnalystRedactionPreviewResult | null>(
    () => (invId ? getAnalystRedactionPreview(invId) : Promise.resolve(null)),
    [invId],
  );

  const complete = (invs.data ?? []).filter((r) => r.status === 'complete');
  const data = preview.data?.kind === 'ok' ? preview.data.preview : null;

  return (
    <>
      <div className="mb-3">
        {invs.loading && <LoadingState label="Loading investigations…" />}
        {invs.error && <ErrorState error={invs.error} />}
        {invs.data && (
          <select
            value={invId}
            onChange={(e) => setInvId(e.target.value)}
            className="w-full max-w-[560px] rounded-control border border-border-input bg-bg px-3 py-2 text-[13px] text-text outline-none focus:border-accent"
            aria-label="Investigation to preview"
          >
            <option value="">
              {complete.length === 0
                ? 'No completed investigations yet'
                : 'Pick a completed investigation…'}
            </option>
            {complete.map((r) => (
              <option key={r.id} value={r.id}>
                {r.id} · {r.name} · {r.verdict} · {r.when}
              </option>
            ))}
          </select>
        )}
      </div>

      {invId && preview.loading && <LoadingState label="Rebuilding analyst prompt…" />}
      {invId && preview.error && <ErrorState error={preview.error} />}

      {preview.data?.kind === 'events_missing' && (
        <div className="flex items-start gap-2 rounded-control border border-border-faint bg-surface-2 px-3 py-2 text-[12.5px] leading-[1.55] text-dim">
          <span className="mt-0.5 flex-none"><Eye size={15} /></span>
          <span>
            This investigation predates the stored events needed to rebuild the analyst
            prompt — only newer runs can be previewed.
          </span>
        </div>
      )}

      {data && (
        <>
          {!data.redaction_enabled && (
            <div className="mb-3 flex items-start gap-2 rounded-control border border-[rgba(245,166,35,.3)] bg-[rgba(245,166,35,.06)] px-3 py-2 text-[12.5px] leading-[1.55] text-[#f5a623]">
              <span className="mt-0.5 flex-none"><ShieldAlert size={15} /></span>
              <span>
                Analyst-path redaction is currently OFF — this is a simulation of what
                WOULD be redacted if you enable it. A real analyst call today sends the
                original text unredacted.
              </span>
            </div>
          )}
          <div className="mb-3 flex items-start gap-2 text-[12.5px] leading-[1.55] text-dim">
            <span className="mt-0.5 flex-none text-success"><ShieldCheck size={15} /></span>
            <span>{data.note}</span>
          </div>
          <SummaryChips summary={data.summary} />
          <BeforeAfter
            original={data.original}
            sanitized={data.sanitized}
            right="Sent to the analyst model"
          />
        </>
      )}
    </>
  );
}

export function RedactionPreviewPanel({
  collapsed = false,
  onToggleCollapse,
}: {
  collapsed?: boolean;
  onToggleCollapse?: () => void;
} = {}) {
  const [mode, setMode] = useState<Mode>('oracle');

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
        <div className="mb-3 flex gap-1.5" role="tablist" aria-label="Redaction preview mode">
          {(
            [
              ['oracle', 'Oracle sample'],
              ['analyst', 'Analyst path'],
            ] as const
          ).map(([m, label]) => (
            <button
              key={m}
              role="tab"
              aria-selected={mode === m}
              onClick={() => setMode(m)}
              className={`rounded-control border px-3 py-1.5 text-[12px] font-semibold transition-colors ${
                mode === m
                  ? 'border-accent bg-surface-2 text-text'
                  : 'border-border-2 text-dim hover:text-text'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
        {mode === 'oracle' ? <OracleSample /> : <AnalystPath />}
      </div>
      )}
    </div>
  );
}
