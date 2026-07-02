import {
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Crosshair,
  Loader2,
  ShieldAlert,
  Target,
} from 'lucide-react';
import { useRef, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Markdown } from '../components/Markdown';
import { Panel, PanelHeader, SectionTitle } from '../components/Panel';
import { ErrorState, LoadingState } from '../components/States';
import { cancelHuntConsole, getHunt } from '../lib/api';
import { useAsync } from '../lib/useAsync';
import type { HuntDetailData, HuntFinding, HuntStatus, TimelineStep } from '../lib/types';

const STATUS_META: Record<HuntStatus, { label: string; color: string; pulse?: boolean }> = {
  running: { label: 'Running', color: '#4b8bf5', pulse: true },
  complete: { label: 'Complete', color: '#3fb950' },
  error: { label: 'Error', color: '#f85149' },
  cancelled: { label: 'Cancelled', color: '#8b949e' },
  interrupted: { label: 'Interrupted', color: '#d29922' },
};

const SEV_COLOR: Record<string, string> = {
  critical: '#f85149',
  high: '#f0883e',
  medium: '#d29922',
  low: '#3fb950',
  info: '#8b949e',
};

function StatusPill({ status }: { status: HuntStatus }) {
  const m = STATUS_META[status] ?? STATUS_META.error;
  return (
    <span
      className="flex items-center gap-1.5 rounded-chip border px-2 py-0.5 text-[11.5px] font-semibold"
      style={{ color: m.color, borderColor: `${m.color}55`, background: `${m.color}14` }}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full${m.pulse ? ' animate-pulse' : ''}`}
        style={{ background: m.color }}
      />
      {m.label}
    </span>
  );
}

function FindingCard({ f }: { f: HuntFinding }) {
  const color = SEV_COLOR[f.severity] ?? SEV_COLOR.info;
  return (
    <div className="rounded-card border border-border bg-surface-2 p-3">
      <div className="mb-1 flex items-center gap-2">
        <span
          className="rounded-chip border px-1.5 py-px text-[10px] font-semibold uppercase tracking-[.04em]"
          style={{ color, borderColor: `${color}55`, background: `${color}14` }}
        >
          {f.severity}
        </span>
        <span className="text-[13px] font-semibold text-text">{f.title}</span>
      </div>
      <div className="text-[12.5px] leading-[1.55] text-text-2">{f.detail}</div>
      {(f.hosts.length > 0 || f.citations.length > 0) && (
        <div className="mt-1.5 flex flex-wrap gap-1.5 font-mono text-[10.5px] text-faint">
          {f.hosts.map((h) => (
            <span key={h} className="rounded-chip bg-surface-3 px-1.5 py-px">
              {h}
            </span>
          ))}
          {f.citations.map((c) => (
            <span key={c} className="rounded-chip bg-surface-3 px-1.5 py-px text-accent">
              {c}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function TimelineRow({ step }: { step: TimelineStep }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border-b border-border last:border-0">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-surface-2"
      >
        {step.detail ? (
          open ? (
            <ChevronDown size={13} className="flex-none text-faint" />
          ) : (
            <ChevronRight size={13} className="flex-none text-faint" />
          )
        ) : (
          <span className="w-[13px] flex-none" />
        )}
        <span className="w-[92px] flex-none text-[10.5px] uppercase tracking-[.03em] text-faint">
          {step.group}
        </span>
        <span className="truncate text-[12.5px] text-text-2">{step.title}</span>
      </button>
      {open && step.detail && (
        <pre className="max-w-full overflow-x-auto whitespace-pre-wrap break-words border-t border-border bg-bg px-3 py-2 font-mono text-[11px] leading-[1.5] text-dim">
          {step.detail}
        </pre>
      )}
    </div>
  );
}

export function HuntDetail() {
  const { id = '' } = useParams();
  const [reloadKey, setReloadKey] = useState(0);
  const [cancelling, setCancelling] = useState(false);

  // useAsync captures pauseWhen at setup and can't see `data` there, so track
  // the current status in a ref and let pauseWhen consult it: stop polling once
  // the hunt reaches a terminal state.
  const statusRef = useRef<HuntStatus | undefined>(undefined);
  const { data, loading, error } = useAsync<HuntDetailData>(() => getHunt(id), [id, reloadKey], {
    refetchInterval: 3000,
    pauseWhen: () => {
      const s = statusRef.current;
      return s === 'complete' || s === 'error' || s === 'cancelled';
    },
  });
  statusRef.current = data?.status;

  const doCancel = () => {
    if (cancelling) return;
    setCancelling(true);
    cancelHuntConsole(id)
      .then(() => setReloadKey((k) => k + 1))
      .catch(() => undefined)
      .finally(() => setCancelling(false));
  };

  return (
    <div className="px-[22px] pb-[60px] pt-[18px]">
      {/* breadcrumb row */}
      <div className="mb-3.5 flex flex-wrap items-center gap-3">
        <Link
          to="/hunts"
          className="flex items-center gap-1.5 text-[12.5px] text-dim hover:text-text"
        >
          <ChevronLeft size={13} /> Hunt Console
        </Link>
        <span className="text-ghost">/</span>
        <div className="text-[15px] font-semibold">Hunt detail</div>
      </div>

      {loading && !data ? (
        <LoadingState label="Loading hunt…" />
      ) : error ? (
        <ErrorState error={error} onRetry={() => setReloadKey((k) => k + 1)} />
      ) : !data ? (
        <ErrorState error={new Error('Hunt not found')} />
      ) : (
        <div className="grid grid-cols-[1fr_360px] gap-4 max-[1100px]:grid-cols-1">
          {/* left: objective, narrative, findings */}
          <div className="flex flex-col gap-4">
            <Panel className="p-4">
              <div className="mb-2 flex items-start gap-2">
                <Crosshair size={18} className="mt-0.5 flex-none text-accent" />
                <div className="flex-1">
                  <div className="text-[15px] font-semibold leading-[1.4] text-text">
                    {data.objective}
                  </div>
                  <div className="mt-1.5 flex items-center gap-2.5 text-[11.5px] text-dim">
                    <StatusPill status={data.status} />
                    <span>by {data.startedBy}</span>
                    <span>· {data.elapsedLabel}</span>
                    {data.status === 'complete' && (
                      <span>· confidence {(data.confidence * 100).toFixed(0)}%</span>
                    )}
                  </div>
                </div>
                {data.status === 'running' && (
                  <button
                    onClick={doCancel}
                    disabled={cancelling}
                    className="flex items-center gap-1.5 rounded-control border border-border px-2.5 py-1.5 text-[12px] text-dim hover:text-text disabled:opacity-50"
                  >
                    {cancelling ? <Loader2 size={13} className="animate-spin" /> : null}
                    Cancel
                  </button>
                )}
              </div>
            </Panel>

            {data.status === 'running' && (
              <Panel className="flex items-center gap-2 px-4 py-3 text-[13px] text-dim">
                <Loader2 size={15} className="animate-spin text-accent" />
                Hunting… correlating events, enriching indicators, mapping to MITRE. This view
                updates live.
              </Panel>
            )}

            {data.narrative && (
              <Panel>
                <PanelHeader icon={<Target size={15} />} title="Narrative" />
                <div className="p-4 text-[13px] leading-[1.6] text-text-2">
                  <Markdown>{data.narrative}</Markdown>
                </div>
              </Panel>
            )}

            <Panel>
              <PanelHeader
                icon={<ShieldAlert size={15} />}
                title="Findings"
                right={
                  <span className="font-mono text-[11px] text-accent">
                    {data.findings.length}
                  </span>
                }
              />
              <div className="flex flex-col gap-2.5 p-4">
                {data.findings.length === 0 ? (
                  <div className="text-[13px] text-dim">
                    {data.status === 'complete'
                      ? 'No findings — a clean hunt. Nothing notable surfaced for this objective.'
                      : 'No findings yet.'}
                  </div>
                ) : (
                  data.findings.map((f, i) => <FindingCard key={i} f={f} />)
                )}
              </div>
            </Panel>
          </div>

          {/* right: hosts / MITRE / actions / trace */}
          <div className="flex flex-col gap-4">
            {data.affectedHosts.length > 0 && (
              <Panel className="p-4">
                <SectionTitle>Affected hosts</SectionTitle>
                <div className="flex flex-wrap gap-1.5">
                  {data.affectedHosts.map((h) => (
                    <span
                      key={h}
                      className="rounded-chip bg-surface-3 px-2 py-0.5 font-mono text-[11.5px] text-text-2"
                    >
                      {h}
                    </span>
                  ))}
                </div>
              </Panel>
            )}

            {data.mitreTechniques.length > 0 && (
              <Panel className="p-4">
                <SectionTitle>MITRE ATT&amp;CK</SectionTitle>
                <div className="flex flex-wrap gap-1.5">
                  {data.mitreTechniques.map((m) => (
                    <span
                      key={m}
                      className="rounded-chip border border-accent/40 bg-accent/10 px-2 py-0.5 font-mono text-[11.5px] text-accent"
                    >
                      {m}
                    </span>
                  ))}
                </div>
              </Panel>
            )}

            {data.recommendedActions.length > 0 && (
              <Panel className="p-4">
                <SectionTitle>Recommended actions</SectionTitle>
                <div className="flex flex-col gap-2">
                  {data.recommendedActions.map((a, i) => (
                    <div key={i}>
                      <div className="text-[12.5px] font-semibold text-text">{a.title}</div>
                      <div className="text-[11.5px] text-dim">{a.rationale}</div>
                    </div>
                  ))}
                </div>
              </Panel>
            )}

            <Panel>
              <PanelHeader title="Agent trace" />
              <div className="max-h-[520px] overflow-y-auto">
                {data.timeline.length === 0 ? (
                  <div className="px-3 py-3 text-[12.5px] text-dim">No steps yet.</div>
                ) : (
                  data.timeline.map((step) => <TimelineRow key={step.id} step={step} />)
                )}
              </div>
            </Panel>
          </div>
        </div>
      )}
    </div>
  );
}
