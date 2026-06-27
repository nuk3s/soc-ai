import { Crosshair, FlaskConical } from 'lucide-react';

// ---------------------------------------------------------------------------
// The autonomous Hunting Agent isn't wired up yet. Rather than ship convincing
// fabricated hunts (mock attacker IPs, fake findings) that read as real, this
// page is an honest "coming soon" placeholder behind the nav's DEV badge.
// ---------------------------------------------------------------------------

export function Hunts() {
  return (
    <div className="px-[22px] pb-[60px] pt-5">
      {/* page header */}
      <div className="mb-5 flex items-end gap-3">
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
          The autonomous hunting agent isn&apos;t wired up yet. When it ships, this page will run
          real scheduled and ad-hoc threat hunts, surface findings, and promote them into the
          existing investigation loop.
        </div>
      </div>
    </div>
  );
}
