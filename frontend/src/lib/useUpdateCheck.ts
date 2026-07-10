import { useEffect, useState } from 'react';

// The entry bundle URL as baked into index.html by Vite (content-hashed).
const ENTRY_RE = /\/assets\/index-[^"']+\.js/;

/** The entry script this tab is actually running (absolute /app/... URL). */
function runningEntry(): string | null {
  return (
    document
      .querySelector('script[type=module][src*="/assets/index-"]')
      ?.getAttribute('src') ?? null
  );
}

export interface UpdateCheck {
  /** True when the server's build no longer matches this tab (and not dismissed). */
  stale: boolean;
  /** Hide the banner until the served entry changes AGAIN (a newer deploy). */
  dismiss: () => void;
}

/**
 * Detects a deploy under an open tab: every 60s (and on window focus) fetch
 * the served index.html and compare its entry-script hash against the one
 * this tab booted from. A mismatch means hashed chunks this tab may still
 * lazy-import have been replaced — surface a "reload for the latest" banner
 * before a navigation trips the chunk-404 auto-heal.
 *
 * Fail-soft by design: any fetch/parse problem (offline, backend restarting,
 * dev server without a hashed entry) just means "no banner" — this hook must
 * never generate noise of its own.
 */
export function useUpdateCheck(intervalMs = 60_000): UpdateCheck {
  // The mismatching served entry (null = in sync), and the one the operator
  // dismissed. Keeping the dismissed *value* (not a boolean) re-arms the
  // banner automatically when yet another deploy changes the entry again.
  const [servedEntry, setServedEntry] = useState<string | null>(null);
  const [dismissedEntry, setDismissedEntry] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;

    const check = async () => {
      try {
        const running = runningEntry();
        if (!running) return; // dev server / unexpected DOM — nothing to compare
        const res = await fetch('/app/index.html', { cache: 'no-store' });
        if (!res.ok) return;
        const served = (await res.text()).match(ENTRY_RE)?.[0];
        if (!alive || !served) return;
        // Suffix-compare: the DOM src is absolute under /app/, the regex match
        // may start at /assets — a base-path difference must not false-alarm.
        setServedEntry(running.endsWith(served) ? null : served);
      } catch {
        // fail-soft: a transient fetch/parse error never raises the banner
      }
    };

    void check();
    const timer = setInterval(() => {
      if (!document.hidden) void check(); // don't poll a backgrounded tab
    }, intervalMs);
    const onFocus = () => void check();
    window.addEventListener('focus', onFocus);
    return () => {
      alive = false;
      clearInterval(timer);
      window.removeEventListener('focus', onFocus);
    };
  }, [intervalMs]);

  return {
    stale: servedEntry !== null && servedEntry !== dismissedEntry,
    dismiss: () => setDismissedEntry(servedEntry),
  };
}
