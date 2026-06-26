import { Activity, AlertTriangle, ArrowUpRight, ChevronLeft, Crosshair, FlaskConical, Play } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import { EntityGraph } from '../components/EntityGraph';
import { HostActivityTimeline } from '../components/HostActivityTimeline';
import { Panel, PanelHeader } from '../components/Panel';
import { RiskRing } from '../components/ConfidenceRing';
import { ErrorState, LoadingState } from '../components/States';
import { getHuntDetail } from '../lib/api';
import { useAsync } from '../lib/useAsync';
import { SEVERITY } from '../lib/tokens';
import type { HuntRow } from '../lib/types';

const TYPE_META: Record<HuntRow['type'], { c: string; bg: string; b: string }> = {
  scheduled: { c: '#4b8bf5', bg: 'rgba(75,139,245,.1)', b: 'rgba(75,139,245,.3)' },
  'ad-hoc': { c: '#a472f0', bg: 'rgba(164,114,240,.1)', b: 'rgba(164,114,240,.3)' },
};
const STATUS_META: Record<HuntRow['status'], { c: string; label: string; pulse: boolean }> = {
  active: { c: '#3fb950', label: 'Active', pulse: false },
  running: { c: '#4b8bf5', label: 'Running', pulse: true },
  complete: { c: '#6b7484', label: 'Complete', pulse: false },
};

export function HuntDetail() {
  const { id = 'h1' } = useParams();
  const { data, loading, error } = useAsync(() => getHuntDetail(id), [id]);

  if (loading) return <div className="p-6"><LoadingState label="Loading hunt…" /></div>;
  if (error) return <div className="p-6"><ErrorState error={error} /></div>;
  if (!data) return null;

  const { hunt } = data;
  const tm = TYPE_META[hunt.type];
  const sm = STATUS_META[hunt.status];

  return (
    <div className="px-[22px] pb-[60px] pt-[18px]">
      {/* breadcrumb row */}
      <div className="mb-3.5 flex flex-wrap items-center gap-3">
        <Link to="/hunts" className="flex items-center gap-1.5 text-[12.5px] text-dim hover:text-text">
          <ChevronLeft size={13} /> Hunts
        </Link>
        <span className="text-ghost">/</span>
        <div className="text-[15px] font-semibold">{hunt.name}</div>
        <span className="rounded-chip border px-[7px] py-0.5 font-mono text-[9.5px] font-semibold uppercase tracking-[.04em]" style={{ color: tm.c, background: tm.bg, borderColor: tm.b }}>
          {hunt.type}
        </span>
        <div className="flex-1" />
        <div className="flex items-center gap-1.5 rounded-[7px] border border-border-2 bg-surface-1 px-2.5 py-1 font-mono text-[11.5px]" style={{ color: sm.c }}>
          <span className={'h-1.5 w-1.5 rounded-full ' + (sm.pulse ? 'animate-pulseDot' : '')} style={{ background: sm.c }} />
          {sm.label}
        </div>
        <button
          disabled
          title="Hunting agent not yet available"
          className="flex cursor-not-allowed items-center gap-1.5 rounded-control border border-border bg-surface-2 px-[13px] py-[7px] text-[12.5px] font-semibold text-dim opacity-50"
        >
          <Play size={12} /> Run now
        </button>
      </div>

      {/* ---- IN-DEVELOPMENT banner ---- */}
      <div
        className="mb-3.5 flex items-start gap-3 rounded-card border px-4 py-3.5"
        style={{
          background: 'rgba(245,166,35,.07)',
          borderColor: 'rgba(245,166,35,.35)',
        }}
      >
        <span className="mt-px flex-none" style={{ color: '#f5a623' }}>
          <FlaskConical size={17} />
        </span>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[13px] font-semibold" style={{ color: '#f5a623' }}>
              In Development
            </span>
            <span
              className="rounded-chip border px-1.5 py-px font-mono text-[9px] font-semibold uppercase tracking-[.05em]"
              style={{
                color: '#f5a623',
                borderColor: 'rgba(245,166,35,.4)',
                background: 'rgba(245,166,35,.12)',
              }}
            >
              Hunting Agent · Phase 2
            </span>
          </div>
          <div className="mt-0.5 text-[12.5px] leading-[1.55] text-dim">
            This is a preview of the upcoming Hunting Agent. All content shown is{' '}
            <span className="font-semibold text-text-2">illustrative mock data</span> — no live
            queries are running. Run and hand-off controls are disabled until the hunting agent
            ships.
          </div>
        </div>
        <span className="mt-px flex-none" style={{ color: 'rgba(245,166,35,.4)' }}>
          <AlertTriangle size={14} />
        </span>
      </div>

      {/* query bar */}
      <div className="mb-3.5 flex items-center gap-2.5 rounded-card border border-border bg-surface-1 px-[13px] py-2.5">
        <span className="flex-none font-mono text-[9.5px] uppercase text-faint">query</span>
        <span className="min-w-0 flex-1 truncate font-mono text-[12.5px] text-text-2">{hunt.query}</span>
        <span className="flex-none font-mono text-[11.5px] text-faint">{hunt.schedule} · last {hunt.last}</span>
      </div>

      {/* graph + host risk */}
      <div className="mb-3.5 grid gap-3.5" style={{ gridTemplateColumns: '1.5fr 1fr' }}>
        <Panel>
          <PanelHeader
            icon={<Crosshair size={15} />}
            title="Entity graph — lateral movement"
            right={<div className="font-mono text-[11px] text-faint">{hunt.host}</div>}
          />
          <EntityGraph nodes={data.nodes} edges={data.edges} highlight={hunt.host} height={320} />
        </Panel>

        <Panel className="flex flex-col">
          <PanelHeader title="Host risk" right={<span className="font-mono text-[12px] text-mono-amber">{hunt.host}</span>} />
          <div className="flex-1 p-[15px]">
            <div className="mb-[15px] flex items-center gap-[13px]">
              <RiskRing score={data.riskScore} color="#f04438" />
              <div>
                <div className="text-[13px] font-semibold text-danger">{data.riskLabel}</div>
                <div className="mt-0.5 text-[12px] leading-[1.5] text-dim">{data.riskDesc}</div>
              </div>
            </div>
            <div className="mb-[9px] text-[10.5px] font-semibold uppercase tracking-[.05em] text-faint">Recent threat signals</div>
            <div className="flex flex-col gap-[9px]">
              {data.hostSignals.map((s, i) => {
                const color = SEVERITY[s.tone].color;
                return (
                  <div key={i} className="flex items-center gap-2.5">
                    <div className="w-[42px] flex-none font-mono text-[11px] text-faint">{s.time}</div>
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-[12.5px]">{s.label}</div>
                      <div
                        className="mt-1 h-1 origin-left animate-barGrow rounded-[2px]"
                        style={{ background: color, width: `${s.w}%` }}
                      />
                    </div>
                    <span className="flex-none font-mono text-[11px] font-semibold" style={{ color }}>{s.sev}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </Panel>
      </div>

      {/* host activity timeline */}
      <Panel>
        <PanelHeader
          icon={<Activity size={14} />}
          title={`Host activity timeline — ${hunt.name} · ${hunt.host}`}
          right={
            <div className="rounded-badge border border-border-input bg-surface-3 px-2 py-0.5 font-mono text-[11.5px] text-dim">
              flows + events · last 45m
            </div>
          }
        />
        {/* detected shapes chips */}
        <div className="flex flex-wrap items-center gap-2 px-[15px] pb-1 pt-3">
          <span className="mr-0.5 text-[10.5px] font-semibold uppercase tracking-[.05em] text-faint">Detected shapes</span>
          {data.patterns.map((p) => (
            <div key={p.label} className="flex items-center gap-1.5 rounded-[7px] border border-border-2 bg-surface-2 px-2.5 py-[5px]">
              <span className="h-2 w-2 rounded-[2px]" style={{ background: p.tone, boxShadow: `0 0 7px ${p.tone}` }} />
              <span className="text-[12px] font-semibold">{p.label}</span>
              <span className="font-mono text-[10.5px] text-faint">{p.detail}</span>
            </div>
          ))}
        </div>
        <div className="px-[15px] pb-1 pt-1.5">
          <HostActivityTimeline />
        </div>
        {/* reconstructed attack sequence ribbon */}
        <div className="mt-1 border-t border-border-faint px-[15px] pb-4 pt-2">
          <div className="mb-2.5 text-[10.5px] font-semibold uppercase tracking-[.05em] text-faint">Reconstructed attack sequence</div>
          <div className="flex flex-wrap items-center gap-2">
            {data.sequence.map((s, i) => (
              <div key={s.name} className="flex items-center gap-2">
                <div className="flex items-center gap-1.5 rounded-control border border-border-2 bg-surface-2 px-[11px] py-1.5">
                  <span className="h-[7px] w-[7px] rounded-[2px]" style={{ background: s.tone, boxShadow: `0 0 7px ${s.tone}` }} />
                  <span className="text-[12px] font-semibold">{s.name}</span>
                  <span className="font-mono text-[10.5px] text-faint">{s.time}</span>
                </div>
                {i < data.sequence.length - 1 && <span className="text-[13px] text-ghost">→</span>}
              </div>
            ))}
          </div>
        </div>
      </Panel>

      {/* findings */}
      <div className="mt-3.5">
        <div className="mb-[11px] flex items-center gap-2">
          <div className="text-[13px] font-semibold uppercase tracking-[.05em] text-text-2">Findings</div>
          <div className="font-mono text-[11.5px] text-faint">{data.findings.length} · promote to investigation</div>
        </div>
        <div className="flex flex-col gap-2.5">
          {data.findings.map((f, i) => {
            const color = SEVERITY[f.tone].color;
            return (
              <div key={i} className="flex items-center gap-[13px] rounded-card border border-border-2 bg-surface-1 px-[15px] py-[13px] hover:border-border-strong">
                <span className="h-2 w-2 flex-none rounded-full" style={{ background: color, boxShadow: `0 0 8px ${color}` }} />
                <div className="min-w-0 flex-1">
                  <div className="text-[13.5px] font-medium" style={{ textWrap: 'pretty' }}>{f.title}</div>
                  <div className="mt-0.5 font-mono text-[11.5px] text-faint">{f.host} · {f.when}</div>
                </div>
                <button
                  disabled
                  title="Available when the hunting agent ships"
                  className="flex flex-none cursor-not-allowed items-center gap-1.5 whitespace-nowrap rounded-control border px-3 py-[7px] text-[12px] font-semibold opacity-40"
                  style={{ borderColor: 'rgba(75,139,245,.3)', background: 'rgba(75,139,245,.08)', color: '#4b8bf5' }}
                >
                  <ArrowUpRight size={13} /> Hand off to investigation
                </button>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
