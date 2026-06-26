import { AlertTriangle } from 'lucide-react';
import type { ReactNode } from 'react';

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

export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 px-1 py-10 text-[13px] text-dim">
      <Spinner />
      {label}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: Error; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center gap-2 rounded-card border border-[rgba(240,68,56,.3)] bg-[rgba(240,68,56,.05)] px-4 py-8 text-center">
      <span className="text-danger">
        <AlertTriangle size={20} />
      </span>
      <div className="text-[13.5px] font-semibold text-text">Couldn't load this view</div>
      <div className="font-mono text-[11.5px] text-faint">{error.message}</div>
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-1 rounded-control border border-border-strong bg-surface-3 px-3 py-1.5 text-[12px] font-semibold text-text hover:border-accent"
        >
          Retry
        </button>
      )}
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return (
    <div className="px-4 py-10 text-center text-[13px] text-faint">{children}</div>
  );
}
