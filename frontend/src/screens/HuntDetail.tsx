import { ChevronLeft, Crosshair, FlaskConical } from 'lucide-react';
import { Link } from 'react-router-dom';

// ---------------------------------------------------------------------------
// The hunting agent has no backend yet, so there are no real hunts to detail.
// This used to render fabricated per-hunt data (mock attacker IPs, fake
// findings, a synthetic attack-sequence ribbon) which read as real — replaced
// with the same honest "coming soon" empty state as the Hunts list.
// ---------------------------------------------------------------------------

export function HuntDetail() {
  return (
    <div className="px-[22px] pb-[60px] pt-[18px]">
      {/* breadcrumb row */}
      <div className="mb-3.5 flex flex-wrap items-center gap-3">
        <Link to="/hunts" className="flex items-center gap-1.5 text-[12.5px] text-dim hover:text-text">
          <ChevronLeft size={13} /> Hunts
        </Link>
        <span className="text-ghost">/</span>
        <div className="text-[15px] font-semibold">Hunt detail</div>
      </div>

      {/* ---- honest empty state ---- */}
      <div
        className="flex flex-col items-center rounded-card border px-6 py-[72px] text-center"
        style={{
          background: 'rgba(245,166,35,.05)',
          borderColor: 'rgba(245,166,35,.3)',
        }}
      >
        <span
          className="mb-4 flex h-12 w-12 items-center justify-center rounded-full border"
          style={{
            color: '#f5a623',
            borderColor: 'rgba(245,166,35,.4)',
            background: 'rgba(245,166,35,.1)',
          }}
        >
          <FlaskConical size={22} />
        </span>
        <div className="flex items-center gap-2">
          <Crosshair size={16} style={{ color: '#f5a623' }} />
          <span className="text-[16px] font-semibold">Coming soon</span>
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
        <div className="mt-2.5 max-w-[460px] text-[13px] leading-[1.6] text-dim">
          The autonomous hunting agent isn&apos;t wired up yet, so there are no hunts to display.
          When it ships, hunt findings and the reconstructed attack sequence will appear here.
        </div>
      </div>
    </div>
  );
}
