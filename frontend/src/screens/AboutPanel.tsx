import { useState } from 'react';
import { ExternalLink } from 'lucide-react';
import { checkForUpdates, getAbout } from '../lib/api';
import type { AboutInfo, UpdateCheckResult } from '../lib/types';
import { CollapseChevron } from '../components/Panel';
import { ErrorState, LoadingState } from '../components/States';
import { Wordmark } from '../components/Logo';
import { useAsync } from '../lib/useAsync';

/**
 * About — the running version, project links, and (only when an admin has opted
 * in) a manual "check for updates" button. The check is the panel's only
 * outbound call: it is off by default and compares the version LOCALLY, so
 * nothing about the deployment is sent. See soc_ai/webui/updates.py.
 */
export function AboutPanel({
  collapsed = false,
  onToggleCollapse,
  refreshKey = 0,
}: {
  collapsed?: boolean;
  onToggleCollapse?: () => void;
  /** Bump to refetch /about — e.g. after the hot `update_check_enabled` toggle is
   * applied, so the button appears/disappears live instead of after a remount. */
  refreshKey?: number;
} = {}) {
  const { data, loading, error } = useAsync<AboutInfo>(getAbout, [refreshKey]);
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState<UpdateCheckResult | null>(null);

  const runCheck = () => {
    setChecking(true);
    setResult(null);
    checkForUpdates()
      .then(setResult)
      .catch((e: unknown) =>
        setResult({
          enabled: true,
          ok: false,
          current_version: data?.version ?? '',
          latest_version: null,
          update_available: false,
          detail: e instanceof Error ? e.message : 'Update check failed',
        }),
      )
      .finally(() => setChecking(false));
  };

  // Colour the result like the Diagnostics probes: red on failure, amber when an
  // update is waiting, green when up to date.
  const resultTone = (r: UpdateCheckResult): string =>
    !r.ok ? 'text-danger' : r.update_available ? 'text-warn' : 'text-success';

  return (
    <div id="about" className="mb-[22px] scroll-mt-6">
      <div className="mb-1 flex items-center gap-2">
        <div className="text-[15px] font-semibold">About</div>
        {onToggleCollapse && (
          <CollapseChevron collapsed={collapsed} onToggle={onToggleCollapse} label="Toggle About" />
        )}
      </div>
      {!collapsed && (
        <>
          {loading && !data && <LoadingState />}
          {error && (
            <div className="mb-3">
              <ErrorState error={error} />
            </div>
          )}
          {data && (
            <div className="rounded-card border border-border bg-surface-1 px-4 py-3.5">
              <div className="flex items-center gap-2.5">
                <Wordmark size={16} />
                <span className="rounded-chip border border-border bg-surface-2 px-2 py-0.5 font-mono text-[12px] text-text-2">
                  v{data.version}
                </span>
              </div>
              <div className="mt-2 text-[12.5px] leading-[1.6] text-dim">
                Open, self-hosted LLM triage for Security Onion. Licensed under{' '}
                <span className="text-text-2">{data.license}</span>.
              </div>
              <div className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-[12.5px]">
                <a
                  href={data.repo_url}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="inline-flex items-center gap-1 text-accent hover:underline"
                >
                  GitHub <ExternalLink size={12} />
                </a>
                <a
                  href={`${data.repo_url}/releases`}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="inline-flex items-center gap-1 text-accent hover:underline"
                >
                  Releases <ExternalLink size={12} />
                </a>
              </div>

              <div className="mt-3.5 border-t border-border-faint pt-3">
                {data.update_check_enabled ? (
                  <div className="flex flex-wrap items-center gap-2.5">
                    <button
                      onClick={runCheck}
                      disabled={checking}
                      className="rounded-control border border-border-strong bg-surface-3 px-3 py-1.5 text-[12px] font-semibold text-text hover:border-accent disabled:opacity-60"
                    >
                      {checking ? 'Checking…' : 'Check for updates'}
                    </button>
                    {result && <span className={`text-[12px] ${resultTone(result)}`}>{result.detail}</span>}
                  </div>
                ) : (
                  <div className="text-[12px] leading-[1.5] text-faint">
                    Update checks are off — soc-ai makes no outbound calls. An admin can enable a
                    manual GitHub release check under Privacy &amp; Egress → Updates.
                  </div>
                )}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
