import { AlertTriangle, RotateCw } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';

/** Spinner — the 2px ring with a transparent top, as used throughout. */
export function Spinner({ size = 15, color = '#4b8bf5' }: { size?: number; color?: string }) {
  return (
    <span
      className="inline-block flex-none animate-spin rounded-full"
      style={{
        width: size,
        height: size,
        border: `2px solid ${color}`,
        borderTopColor: 'transparent',
      }}
      aria-label="loading"
      role="status"
    />
  );
}

/** Shared Suspense fallback for lazily-loaded route screens. */
export function RouteFallback() {
  return (
    <div className="flex min-h-[50vh] items-center justify-center">
      <Spinner size={20} />
    </div>
  );
}

export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 px-1 py-10 text-[13px] text-dim">
      <Spinner />
      {label}
    </div>
  );
}

export function ErrorState({
  error,
  onRetry,
  label = 'this view',
}: {
  error: Error;
  onRetry?: () => void;
  label?: string;
}) {
  return (
    <div className="flex flex-col items-center gap-2 rounded-card border border-[rgba(240,68,56,.3)] bg-[rgba(240,68,56,.05)] px-4 py-8 text-center">
      <span className="text-danger">
        <AlertTriangle size={20} />
      </span>
      <div className="text-[13.5px] font-semibold text-text">Couldn't load {label}</div>
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-1 rounded-control border border-border-strong bg-surface-3 px-3 py-1.5 text-[12px] font-semibold text-text hover:border-accent"
        >
          Retry
        </button>
      )}
      {/* Raw exception behind a disclosure — available, not shouted, per the
          design's failed-load spec. */}
      <details className="mt-1 max-w-[520px] text-left">
        <summary className="cursor-pointer text-[11px] text-faint">Details</summary>
        <div className="mt-1 break-words font-mono text-[11px] text-faint">{error.message}</div>
      </details>
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return (
    <div className="px-4 py-10 text-center text-[13px] text-faint">{children}</div>
  );
}

function agoLabel(at: number): string {
  const s = Math.max(0, Math.round((Date.now() - at) / 1000));
  if (s < 5) return 'just now';
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
}

/**
 * "updated Xs ago" marker for a polled surface. Re-renders on a 10s tick so the
 * label stays honest without a prop change. Renders nothing until the first
 * successful load. Answers "is what I'm looking at live?" — the gap the app had
 * across ~15 polling surfaces.
 */
export function Freshness({ at, className = '' }: { at: number | null; className?: string }) {
  const [, tick] = useState(0);
  useEffect(() => {
    // 15s cadence — enough to keep an "Xs ago" label honest, and deliberately
    // NOT a poll interval (10s/8s/5s/3s) so it never collides with a screen's
    // setInterval in tests that key on the poll period.
    const t = setInterval(() => tick((n) => n + 1), 15000);
    return () => clearInterval(t);
  }, []);
  if (!at) return null;
  return (
    <span
      className={`font-mono text-[11px] text-faint ${className}`}
      title={`Last updated ${new Date(at).toLocaleTimeString()}`}
    >
      updated {agoLabel(at)}
    </span>
  );
}

/**
 * Degraded marker shown when a surface's background polls have failed enough to
 * be stale (failCount >= 2). The last-good data stays on screen; this says so,
 * with the time it's from and a manual retry.
 */
export function StaleNotice({
  since,
  onRefresh,
  className = '',
}: {
  since: number | null;
  onRefresh: () => void;
  className?: string;
}) {
  const t = since ? new Date(since).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—';
  return (
    <div
      role="status"
      className={`flex items-center gap-2 rounded-control border-l-2 border-warn bg-[rgba(245,166,35,.08)] px-3 py-1.5 text-[12px] text-warn ${className}`}
    >
      <AlertTriangle size={13} className="flex-none" />
      <span>Showing data from {t} — retrying</span>
      <button
        onClick={onRefresh}
        className="ml-auto flex items-center gap-1 rounded-control border border-[rgba(245,166,35,.4)] px-2 py-0.5 text-[11px] font-semibold hover:bg-[rgba(245,166,35,.15)]"
      >
        <RotateCw size={11} /> Refresh
      </button>
    </div>
  );
}
