import {
  AlertTriangle,
  Calendar,
  ChevronRight,
  Crosshair,
  Flag,
  FlaskConical,
  Triangle,
  type LucideIcon,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { SEVERITY } from '../lib/tokens';
import type { HuntRow, HuntStat } from '../lib/types';

const GRID = '1.7fr 92px 1.3fr 104px 88px 96px 28px';

const TONE: Record<HuntStat['tone'], string> = {
  accent: '#4b8bf5',
  sigma: '#a472f0',
  warn: '#f5a623',
  danger: '#f04438',
};
const STAT_ICON: Record<HuntStat['tone'], LucideIcon> = {
  accent: Crosshair,
  sigma: Calendar,
  warn: Flag,
  danger: Triangle,
};

const TYPE_META: Record<HuntRow['type'], { c: string; bg: string; b: string }> = {
  scheduled: { c: '#4b8bf5', bg: 'rgba(75,139,245,.1)', b: 'rgba(75,139,245,.3)' },
  'ad-hoc': { c: '#a472f0', bg: 'rgba(164,114,240,.1)', b: 'rgba(164,114,240,.3)' },
};
const STATUS_META: Record<HuntRow['status'], { c: string; label: string; pulse: boolean }> = {
  active: { c: '#3fb950', label: 'Active', pulse: false },
  running: { c: '#4b8bf5', label: 'Running', pulse: true },
  complete: { c: '#6b7484', label: 'Complete', pulse: false },
};

// ---------------------------------------------------------------------------
// Illustrative mock data — reflects the design vision; not from a live API.
// Replace with real API calls when the hunting agent ships.
// ---------------------------------------------------------------------------

const MOCK_STATS: HuntStat[] = [
  {
    label: 'Total hunts',
    value: '7',
    sub: '5 scheduled · 2 ad-hoc',
    tone: 'accent',
  },
  {
    label: 'Findings (7d)',
    value: '23',
    sub: '3 promoted to investigation',
    tone: 'sigma',
  },
  {
    label: 'In progress',
    value: '1',
    sub: 'beaconing-over-zeek.conn running',
    tone: 'warn',
  },
  {
    label: 'High/Critical',
    value: '4',
    sub: 'findings awaiting review',
    tone: 'danger',
  },
];

const MOCK_HUNTS: HuntRow[] = [
  {
    id: 'h-zerologon',
    name: 'Zerologon DCE/RPC pattern',
    type: 'scheduled',
    query: 'event.dataset:zeek.dce_rpc AND zeek.dce_rpc.operation:(NetrServerAuthenticate3 OR NetrServerReqChallenge) | groupby source.ip | sortby count',
    schedule: 'every 4h',
    last: '2h ago',
    findings: 2,
    maxSev: 'critical',
    status: 'active',
    host: '192.0.2.1',
  },
  {
    id: 'h-dcsync',
    name: 'DCSync / DRSCrackNames activity',
    type: 'scheduled',
    query: 'event.dataset:zeek.dce_rpc AND zeek.dce_rpc.endpoint:drsuapi AND zeek.dce_rpc.operation:(DRSCrackNames OR DRSGetNCChanges) | groupby source.ip',
    schedule: 'every 4h',
    last: '2h ago',
    findings: 1,
    maxSev: 'high',
    status: 'active',
    host: '192.0.2.10',
  },
  {
    id: 'h-ad-enum',
    name: 'AD enumeration — SAMR/LSAR',
    type: 'scheduled',
    query: 'event.dataset:zeek.dce_rpc AND zeek.dce_rpc.endpoint:(samr OR lsarpc) AND zeek.dce_rpc.operation:(SamrEnumerateUsersInDomain OR LsarEnumerateAccounts) | groupby source.ip',
    schedule: 'every 6h',
    last: '4h ago',
    findings: 7,
    maxSev: 'high',
    status: 'active',
    host: '192.0.2.88',
  },
  {
    id: 'h-beacon',
    name: 'Beaconing over zeek.conn (CV)',
    type: 'scheduled',
    query: 'event.dataset:zeek.conn | groupby source.ip,destination.ip | sortby count desc | head 500',
    schedule: 'every 1h',
    last: 'running',
    findings: 5,
    maxSev: 'medium',
    status: 'running',
    host: '192.0.2.15',
  },
  {
    id: 'h-dns-dga',
    name: 'DNS tunneling / DGA entropy',
    type: 'scheduled',
    query: 'event.dataset:zeek.dns AND dns.query.type_name:A | groupby dns.question.registered_domain | sortby count desc',
    schedule: 'every 2h',
    last: '1h ago',
    findings: 4,
    maxSev: 'medium',
    status: 'active',
    host: '192.0.2.22',
  },
  {
    id: 'h-adhoc-notice',
    name: 'ATTACK::Discovery notices sweep',
    type: 'ad-hoc',
    query: 'event.dataset:zeek.notice AND zeek.notice.note:ATTACK::* | groupby zeek.notice.note,source.ip | sortby count',
    schedule: 'on demand',
    last: '3d ago',
    findings: 11,
    maxSev: 'high',
    status: 'complete',
    host: '192.0.2.88',
  },
  {
    id: 'h-adhoc-sigma-draft',
    name: 'Sigma rule candidate — Zerologon',
    type: 'ad-hoc',
    query: 'event.dataset:zeek.dce_rpc AND zeek.dce_rpc.operation:NetrServerAuthenticate3',
    schedule: 'on demand',
    last: '5d ago',
    findings: 3,
    maxSev: 'critical',
    status: 'complete',
    host: '192.0.2.1',
  },
];

// ---------------------------------------------------------------------------

export function Hunts() {
  const navigate = useNavigate();

  return (
    <div className="px-[22px] pb-[60px] pt-5">
      {/* page header */}
      <div className="mb-4 flex items-end gap-3">
        <div>
          <div className="flex items-center gap-2">
            <div className="text-[20px] font-semibold tracking-[-.015em]">Hunts</div>
          </div>
          <div className="mt-0.5 text-[13px] text-dim">
            Scheduled &amp; ad-hoc threat hunts — arriving with the hunting agent.
          </div>
        </div>
        <div className="flex-1" />
        <button
          disabled
          title="Saved hunts arrive with the hunting agent"
          className="flex cursor-not-allowed items-center gap-1.5 rounded-control bg-accent/40 px-[13px] py-2 text-[13px] font-semibold text-white/70"
        >
          + New hunt
        </button>
      </div>

      {/* ---- IN-DEVELOPMENT banner ---- */}
      <div
        className="mb-5 flex items-start gap-3 rounded-card border px-4 py-3.5"
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
            This is a preview of the upcoming Hunting Agent. The content below is{' '}
            <span className="font-semibold text-text-2">illustrative mock data</span> — no live
            queries are running. When the hunting agent ships, this page will show real scheduled
            and ad-hoc hunts, findings, and promote-to-investigation controls.
          </div>
        </div>
        <span className="mt-px flex-none" style={{ color: 'rgba(245,166,35,.4)' }}>
          <AlertTriangle size={14} />
        </span>
      </div>

      {/* stat cards */}
      <div className="mb-[18px] grid grid-cols-4 gap-3">
        {MOCK_STATS.map((h) => {
          const Icon = STAT_ICON[h.tone];
          return (
            <div key={h.label} className="rounded-card border border-border bg-surface-1 p-3.5">
              <div className="flex items-center gap-1.5 text-[12px] text-dim">
                <span className="flex" style={{ color: TONE[h.tone] }}>
                  <Icon size={14} />
                </span>
                {h.label}
              </div>
              <div
                className="mt-2 font-mono text-[26px] font-bold"
                style={{ color: TONE[h.tone] }}
              >
                {h.value}
              </div>
              <div className="mt-0.5 text-[11.5px] text-faint">{h.sub}</div>
            </div>
          );
        })}
      </div>

      {/* hunts table */}
      <div className="overflow-hidden rounded-card border border-border bg-surface-1">
        {/* table header */}
        <div
          className="grid gap-2.5 border-b border-border bg-surface-2 px-3.5 py-[9px] text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint"
          style={{ gridTemplateColumns: GRID }}
        >
          <div>Hunt</div>
          <div>Type</div>
          <div>Query</div>
          <div>Last run</div>
          <div className="text-center">Findings</div>
          <div>Status</div>
          <div />
        </div>

        {MOCK_HUNTS.map((h) => {
          const tm = TYPE_META[h.type];
          const sm = STATUS_META[h.status];
          const findColor = h.findings === 0 ? '#6b7484' : SEVERITY[h.maxSev].color;
          return (
            <div
              key={h.id}
              onClick={() => navigate(`/hunts/${h.id}`)}
              className="grid cursor-pointer items-center gap-2.5 border-b border-border-faint px-3.5 py-[11px] hover:bg-surface-hover"
              style={{ gridTemplateColumns: GRID }}
            >
              <div className="min-w-0">
                <div className="truncate text-[13.5px] font-medium">{h.name}</div>
                <div className="mt-0.5 font-mono text-[11px] text-faint">{h.schedule}</div>
              </div>
              <div>
                <span
                  className="rounded-chip border px-[7px] py-0.5 font-mono text-[9.5px] font-semibold uppercase tracking-[.04em]"
                  style={{ color: tm.c, background: tm.bg, borderColor: tm.b }}
                >
                  {h.type}
                </span>
              </div>
              <div className="truncate font-mono text-[11.5px] text-dim">{h.query}</div>
              <div className="font-mono text-[12px] text-dim">{h.last}</div>
              <div className="text-center">
                <span
                  className="inline-flex items-center gap-1.5 font-mono text-[12.5px] font-semibold"
                  style={{ color: findColor }}
                >
                  <span
                    className="h-[7px] w-[7px] rounded-full"
                    style={{ background: findColor }}
                  />
                  {h.findings}
                </span>
              </div>
              <div>
                <span
                  className="inline-flex items-center gap-1.5 text-[11.5px]"
                  style={{ color: sm.c }}
                >
                  <span
                    className={
                      'h-1.5 w-1.5 rounded-full ' + (sm.pulse ? 'animate-pulseDot' : '')
                    }
                    style={{ background: sm.c }}
                  />
                  {sm.label}
                </span>
              </div>
              <div className="flex justify-end text-ghost">
                <ChevronRight size={13} />
              </div>
            </div>
          );
        })}

        {/* footer note */}
        <div className="border-t border-border-faint px-4 py-3 text-[11.5px] text-faint">
          <span className="font-mono" style={{ color: '#f5a623' }}>
            illustrative
          </span>{' '}
          · 7 mock hunts shown — real hunts will populate here once the hunting agent is deployed.
          Findings promote into the existing investigation loop unchanged.
        </div>
      </div>
    </div>
  );
}
