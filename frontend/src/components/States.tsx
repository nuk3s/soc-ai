import { AlertTriangle, ArrowLeft, RotateCw, SearchX } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';

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

/**
 * A surface the read-only demo deliberately refuses — policy, not an incident.
 *
 * Same reasoning as NotFoundState below: the demo's admin-read lock (403
 * `demo_mode`, a security fix — the public demo used to answer the full user
 * table and which secrets are set) rendered as the alarm-red "Couldn't load
 * this view" card, so a visitor's first look at Config read as breakage. No
 * Retry: retrying a policy answers the same policy.
 */
export function DemoDisabledState({ what }: { what: string }) {
  return (
    <div className="flex flex-col items-center gap-2 rounded-card border border-border bg-surface-1 px-4 py-8 text-center">
      <span className="text-faint">
        <SearchX size={20} />
      </span>
      <div className="text-[13.5px] font-semibold text-text-2">Read-only demo</div>
      <div className="max-w-[460px] text-[12.5px] leading-[1.6] text-faint">
        {what} is switched off here: this hosted demo replays recorded investigations, and its
        settings, users and secrets are neither editable nor visible. Run your own soc-ai to see
        this screen live.
      </div>
    </div>
  );
}

/**
 * The id asked for isn't there — a calm answer, not an incident.
 *
 * Deliberately NOT the ErrorState: an unknown investigation/hunt/host id used
 * to render the same alarm-red "Couldn't load this view" card as a real outage,
 * so the analyst could not tell "this run doesn't exist" from "the grid is
 * down" (dogfood B3, 2026-08-11). Neutral chrome, and no Retry — retrying a
 * 404 just fails again. The way out is the list it came from.
 */
export function NotFoundState({
  what,
  id,
  backTo,
  backLabel,
}: {
  what: string;
  id?: string;
  backTo: string;
  backLabel: string;
}) {
  return (
    <div className="flex flex-col items-center gap-2 rounded-card border border-border bg-surface-1 px-4 py-8 text-center">
      <span className="text-faint">
        <SearchX size={20} />
      </span>
      <div className="text-[13.5px] font-semibold text-text-2">No such {what}</div>
      <div className="max-w-[460px] text-[12.5px] leading-[1.6] text-faint">
        {id ? (
          <>
            Nothing here answers to <span className="font-mono text-dim">{id}</span>. It may have
            been deleted, or the link may be mistyped.
          </>
        ) : (
          <>It may have been deleted, or the link may be mistyped.</>
        )}
      </div>
      <Link
        to={backTo}
        className="mt-1 flex items-center gap-1.5 rounded-control border border-border-strong bg-surface-3 px-3 py-1.5 text-[12px] font-semibold text-text-2 hover:border-accent hover:text-text"
      >
        <ArrowLeft size={12} /> {backLabel}
      </Link>
    </div>
  );
}

/**
 * Nothing to show — said in the shape that gets the operator somewhere.
 *
 * `title` is the headline, the children are the explainer, `action` is the one
 * thing to do next. Hosts and Hunts had built that shape by hand; Investigations
 * had a bare "No investigations yet." and no way forward, which is the same
 * screen telling a new operator nothing (dogfood B1). All three now pass the
 * parts and get one look. A caller that passes only children still renders
 * exactly the plain centred line it always did.
 */
export function EmptyState({
  title,
  action,
  children,
}: {
  title?: ReactNode;
  action?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className="px-4 py-10 text-center text-[13px] text-faint">
      <div className="mx-auto max-w-[520px]">
        {title && <div className="text-[13.5px] font-semibold text-text-2">{title}</div>}
        {children && (
          <div className={'leading-[1.6]' + (title ? ' mt-1.5 text-dim' : '')}>{children}</div>
        )}
        {action && <div className="mt-3 flex justify-center">{action}</div>}
      </div>
    </div>
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
 * Degraded marker for a surface still showing its last-good data, in the two
 * ways that happens.
 *
 * `reason="stale"` (the default) is the background case: polls have failed
 * enough times to count (failCount >= 2) and the next one is already coming, so
 * the copy says "retrying".
 *
 * `reason="refresh-failed"` is the FOREGROUND case — the analyst asked for
 * fresh data, or a route param changed, and the request failed. The detail
 * screens keep their content through that (deliberately: an error arriving
 * after the report is on screen must not take it away), which left nothing at
 * all on screen to say the refresh had failed, so the analyst read stale data
 * believing it current.
 *
 * `retrying` is a fact about the surface, not about which of the two cases this
 * is: a screen that polls on an interval goes on polling right through a failed
 * click, and the next tick will heal the page with nobody doing anything. Copy
 * that dropped the retry promise there would send the analyst off to fix
 * something that is already fixing itself; copy that kept it on a screen with
 * no poll (a finished investigation, a host page) would promise a retry that is
 * never coming. The callers know which they are, so they say.
 *
 * One component for all of it because they are one message to the reader ("what
 * you are looking at is from earlier") and a second banner shape would just be
 * a second thing to learn.
 */
export function StaleNotice({
  since,
  onRefresh,
  className = '',
  reason = 'stale',
  retrying = false,
}: {
  since: number | null;
  onRefresh: () => void;
  className?: string;
  reason?: 'stale' | 'refresh-failed';
  /** Is something still polling underneath? Only read for `refresh-failed`;
   *  the background case is a failing poll loop, which by definition is. */
  retrying?: boolean;
}) {
  const t = since ? new Date(since).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—';
  return (
    <div
      role="status"
      className={`flex items-center gap-2 rounded-control border-l-2 border-warn bg-[rgba(245,166,35,.08)] px-3 py-1.5 text-[12px] text-warn ${className}`}
    >
      <AlertTriangle size={13} className="flex-none" />
      <span>
        {reason === 'refresh-failed'
          ? `Refresh failed — still showing data from ${t}${retrying ? ' — retrying' : ''}`
          : `Showing data from ${t} — retrying`}
      </span>
      <button
        onClick={onRefresh}
        className="ml-auto flex items-center gap-1 rounded-control border border-[rgba(245,166,35,.4)] px-2 py-0.5 text-[11px] font-semibold hover:bg-[rgba(245,166,35,.15)]"
      >
        <RotateCw size={11} /> Refresh
      </button>
    </div>
  );
}
