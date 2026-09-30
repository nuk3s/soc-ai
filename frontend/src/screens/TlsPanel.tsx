import { useState } from "react";
import type { ReactNode } from "react";
import { getTlsStatus } from "../lib/api";
import type { TlsStatus } from "../lib/api";
import { CollapseChevron } from "../components/Panel";
import { ErrorState, LoadingState } from "../components/States";
import { useAsync } from "../lib/useAsync";

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex gap-3 border-t border-border-faint px-4 py-2 text-[12.5px]">
      <dt className="w-32 flex-none text-faint">{label}</dt>
      <dd className="min-w-0 flex-1 break-all">{children}</dd>
    </div>
  );
}

function clockText(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? iso
    : `${d.toISOString().slice(11, 19)} UTC`;
}

/** The headline: the subject, or why there is none. */
function headline(data: TlsStatus): string {
  if (data.subject) return data.subject;
  return data.errors.length ? "Certificate not read" : "No subject";
}

/** ", self-signed" or ", issued by X" after the subject. */
function issuerSuffix(data: TlsStatus): string {
  if (data.self_signed) return ", self-signed";
  return data.issuer ? `, issued by ${data.issuer}` : "";
}

/** "(expired)", "(today)", "(1 day)" or "(N days)" after the expiry date. */
function daysSuffix(data: TlsStatus): string {
  if (data.expired) return " (expired)";
  if (data.days_left === null) return "";
  if (data.days_left === 0) return " (today)";
  if (data.days_left === 1) return " (1 day)";
  return ` (${data.days_left} days)`;
}

/** "N certificates", "1 certificate" or "none", then ", out of order" when the chain is wrong. */
function chainText(data: TlsStatus): string {
  const count =
    data.chain_length === 0
      ? "none"
      : `${data.chain_length} certificate${data.chain_length === 1 ? "" : "s"}`;
  return data.chain_ok ? count : `${count}, out of order`;
}

function keyText(data: TlsStatus): string {
  if (data.key_matches === null) return "not checked";
  return data.key_matches ? "matches" : "does not match";
}

/** "YYYY-MM-DD HH:MM UTC", or "unknown" when the time is missing or unreadable. */
function loadedText(loadedAt: string | null): string {
  if (!loadedAt) return "unknown";
  const t = new Date(loadedAt);
  if (Number.isNaN(t.getTime())) return "unknown";
  return `${t.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

export function TlsPanel({
  collapsed = false,
  onToggleCollapse,
}: { collapsed?: boolean; onToggleCollapse?: () => void } = {}) {
  const { data, loading, error, refetch } = useAsync(getTlsStatus, [], {
    refetchInterval: 60_000,
  });
  const [checkedAt, setCheckedAt] = useState<string | null>(null);
  return (
    <div id="tls" className="mb-[22px] scroll-mt-6">
      <div className="mb-2 flex items-center gap-2">
        <h2 className="text-[15px] font-semibold">TLS</h2>
        {onToggleCollapse && (
          <CollapseChevron
            collapsed={collapsed}
            onToggle={onToggleCollapse}
            label="Toggle TLS"
          />
        )}
      </div>
      {!collapsed && (
        <div className="rounded-card border border-border bg-surface-1">
          {loading && !data && <LoadingState label="Reading the certificate" />}
          {error && !data && (
            <ErrorState
              error={error}
              onRetry={refetch}
              label="the TLS status"
            />
          )}
          {data && data.mode === "off" && (
            <div className="px-4 py-3 text-[12.5px]">
              TLS is off. soc-ai serves plain HTTP. Put a proxy in front of it,
              or set the certificate paths. See docs/DOCKER.md, TLS.
            </div>
          )}
          {data && data.mode === "direct" && (
            <>
              <div className="px-4 py-3 text-[12.5px]">
                <span className="font-semibold">{headline(data)}</span>
                {issuerSuffix(data)}
              </div>
              {data.errors.map((e) => (
                <div
                  key={e}
                  className="border-t border-border-faint px-4 py-2 text-[12.5px] text-danger"
                >
                  <strong>Error: </strong>
                  {e}
                </div>
              ))}
              {data.warnings.map((w) => (
                <div
                  key={w}
                  className="border-t border-border-faint px-4 py-2 text-[12.5px] text-warn"
                >
                  <strong>Warning: </strong>
                  {w}
                </div>
              ))}
              {data.restart_required && (
                <div className="border-t border-border-faint px-4 py-2 text-[12.5px] text-warn">
                  The files on disk differ from the files loaded at start.
                  Restart soc-ai to load them. Docker:{" "}
                  <code>docker compose restart soc-ai</code>. systemd:{" "}
                  <code>sudo systemctl restart soc-ai</code>.
                </div>
              )}
              <dl>
                <Row label="Expires">
                  {data.not_after ? data.not_after.slice(0, 10) : "unknown"}
                  {daysSuffix(data)}
                </Row>
                <Row label="Names">
                  {data.sans.length
                    ? data.sans.map((s) => <div key={s}>{s}</div>)
                    : "none"}
                </Row>
                <Row label="Chain">{chainText(data)}</Row>
                <Row label="Key">{keyText(data)}</Row>
                <Row label="Files">
                  <div>{data.cert_path}</div>
                  <div>{data.key_path}</div>
                </Row>
                <Row label="Fingerprint">
                  {data.fingerprint_sha256 ?? "unknown"}
                </Row>
                <Row label="Loaded">{loadedText(data.loaded_at)}</Row>
              </dl>
            </>
          )}
          <div className="flex items-center gap-2 border-t border-border-faint px-4 py-3">
            <button
              type="button"
              className="rounded border border-border bg-surface-2 px-2 py-0.5 text-[11px] font-medium hover:bg-surface-3 transition-colors"
              onClick={() => {
                void Promise.resolve(refetch()).then(() =>
                  setCheckedAt(new Date().toISOString()),
                );
              }}
            >
              Check again
            </button>
            <span className="text-[11px] text-faint">
              Reads the files on disk now.
              {checkedAt ? ` Checked at ${clockText(checkedAt)}.` : ""}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
