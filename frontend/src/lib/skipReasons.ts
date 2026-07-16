/** Human labels for the auto-triage skip-reason codes (soc_ai/webui/autotriage.py). */
const LABEL: Record<string, string> = {
  already_triaged: 'already triaged',
  inherited: 'verdict inherited',
  running: 'already running',
  no_ip: 'no IP to investigate',
};

/**
 * "80 already triaged · 10 verdict inherited" from the skipped_reasons map —
 * the bare "91 skipped" count told the analyst nothing about why. Unknown
 * codes pass through with underscores humanized so a new backend reason is
 * never silently swallowed. Null when there is nothing to explain.
 */
export function formatSkipReasons(
  reasons: Record<string, number> | undefined | null,
): string | null {
  if (!reasons) return null;
  const parts = Object.entries(reasons)
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1])
    .map(([code, n]) => `${n} ${LABEL[code] ?? code.replace(/_/g, ' ')}`);
  return parts.length ? parts.join(' · ') : null;
}
