import { Copy, Download, FileCode2 } from 'lucide-react';
import { type ReactNode, useEffect, useState } from 'react';
import type { SigmaDraft } from '../lib/types';
import { Spinner } from './States';

interface DraftDetectionPaneProps {
  /** Fetches the drafted, validated rule — `draftFindingDetection` (Hunt
   *  Console FindingCard) or `draftInvestigationDetection` (Investigation
   *  screen). The caller owns eligibility (flag + hunt-kind + TP + complete);
   *  this component only renders once mounted, so it never has to re-derive
   *  those rules itself. */
  onDraft: () => Promise<SigmaDraft>;
  /** Extra provenance shown under the drafted rule — e.g. the Investigation
   *  screen's link back to the source hunt. Omitted where the caller's own
   *  page already IS that provenance (a hunt finding's own card). */
  provenance?: ReactNode;
  /**
   * When true, the pane fires `onDraft` immediately on mount and skips its
   * own trigger bar — for a caller (the Hunt Console's compact per-finding
   * badge button) that owns the trigger itself and only mounts this pane
   * once the analyst has already clicked it. Investigation.tsx leaves this
   * false: its trigger bar IS this pane's own "Draft detection" button.
   */
  autoRun?: boolean;
}

/**
 * The Draft-detection trigger + review pane (1.3 slice 3, "the detection
 * bridge"). Turns a confirmed hunt finding into a Sigma rule the analyst
 * reviews, edits, and EXPORTS — copy to clipboard or download a `.yml`.
 * There is deliberately no deploy/apply button: soc-ai never writes a
 * detection to Security Onion (see the plan's "why export-only" note); the
 * analyst pastes the exported rule into the Detections module themselves.
 *
 * Shared between the Investigation screen (a promoted finding's own page)
 * and the Hunt Console's per-finding card — both gate MOUNTING this
 * component on `sigma_authoring_enabled` + the finding's own state, so this
 * component's only job is the draft → review → export loop.
 */
export function DraftDetectionPane({ onDraft, provenance, autoRun = false }: DraftDetectionPaneProps) {
  // `attempted` (not `!!draft`) gates the review panel so a failed first
  // click still opens the panel to show the error — a silently-dead button
  // is worse than an honest failure.
  const [attempted, setAttempted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState<SigmaDraft | null>(null);
  // Local-only edits (v1 — no re-validation round trip, per the plan). Seeded
  // from the drafted rule; both Copy and Download export THIS (what the analyst
  // is looking at in the textarea), so an edit made "before export" is never
  // silently dropped on the Copy path.
  const [yamlEdit, setYamlEdit] = useState('');
  const [copied, setCopied] = useState(false);

  // Undefined in an insecure (plain-http) context — hide Copy rather than
  // render a button that silently does nothing (mirrors QualityCard's
  // EvidencePath copy affordance).
  const canCopy = typeof navigator !== 'undefined' && !!navigator.clipboard;

  const run = () => {
    if (loading) return;
    setAttempted(true);
    setLoading(true);
    setError(null);
    onDraft()
      .then((d) => {
        setDraft(d);
        setYamlEdit(d.sigma_yaml);
      })
      .catch((e: unknown) => setError(e instanceof Error ? e.message : 'Could not draft a detection.'))
      .finally(() => setLoading(false));
  };

  // autoRun callers (the Hunt Console's compact button) mount this pane
  // already-triggered — fire once, on mount only, never again on a re-render
  // (a fresh onDraft closure identity each render must not restart the draft).
  useEffect(() => {
    if (autoRun) run();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const copyRule = () => {
    if (!draft || !canCopy) return;
    navigator.clipboard
      .writeText(yamlEdit)
      .then(() => {
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1500);
      })
      .catch(() => {});
  };

  const downloadYaml = () => {
    const blob = new Blob([yamlEdit], { type: 'application/x-yaml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const slug =
      (draft?.title ?? 'detection')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/(^-|-$)/g, '') || 'detection';
    a.download = `${slug}.yml`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const dry = draft?.dry_run ?? null;
  // Local edits go stale against the server's validation (F4, dogfood 1.3):
  // the structure check and dry run described the ORIGINAL draft, while Copy/
  // Download export the textarea. Once they differ, stop asserting validity of
  // text nobody checked.
  const edited = draft !== null && yamlEdit !== draft.sigma_yaml;

  return (
    <div className="flex flex-col gap-2.5">
      {/* The explainer renders on BOTH surfaces (F20, dogfood 1.3): an autoRun
          caller (the Hunt Console's one-click badge) fires the draft with no
          other context, so the "review, edit, export — nothing is written to
          Security Onion" reassurance must not be exclusive to the surface that
          owns its own trigger bar. autoRun only drops the button. */}
      <div
        className="flex flex-wrap items-center gap-2.5 rounded-card border px-3.5 py-3"
        style={{ borderColor: 'rgba(75,139,245,.3)', background: 'rgba(75,139,245,.05)' }}
      >
        <div className="min-w-0 flex-1">
          <div className="text-[13px] font-semibold text-text">Draft a Sigma detection</div>
          <p className="mt-1 text-[12px] leading-[1.5] text-dim">
            The draft uses the evidence in this finding. Review it, edit it, and export it. soc-ai
            writes nothing to Security Onion.
          </p>
        </div>
        {!autoRun && (
          <button
            type="button"
            onClick={run}
            disabled={loading}
            className="flex items-center gap-1.5 rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold text-[#cfe0ff] disabled:opacity-60"
            style={{ background: 'rgba(75,139,245,.14)', borderColor: 'rgba(75,139,245,.4)' }}
          >
            {loading ? <Spinner size={13} /> : <FileCode2 size={13} />}
            {loading ? 'Drafting…' : 'Draft detection'}
          </button>
        )}
      </div>

      {attempted && (
        <div className="overflow-hidden rounded-panel border border-border bg-surface-1">
          <div className="border-b border-border px-[15px] py-3">
            <div className="text-[13px] font-semibold uppercase tracking-[.05em] text-text-2">
              Detection review
            </div>
          </div>
          <div className="flex flex-col gap-3 px-[15px] py-3.5">
            {error && (
              <div
                role="alert"
                className="rounded-card border px-3.5 py-2.5 text-[12.5px] text-danger"
                style={{ borderColor: 'rgba(240,68,56,.35)', background: 'rgba(240,68,56,.08)' }}
              >
                {error}
              </div>
            )}
            {loading && !draft && (
              <div className="flex items-center gap-2 text-[12.5px] text-dim">
                <Spinner size={13} /> Drafting a detection…
              </div>
            )}
            {draft && (
              <>
                <div>
                  <div className="text-[13.5px] font-semibold text-text">{draft.title}</div>
                  <p className="mt-1 text-[12.5px] leading-[1.5] text-text-2">{draft.rationale}</p>
                </div>

                {/* Both validator verdicts hide once the analyst has edited the
                    YAML — they describe the original draft, and a green badge
                    over text nobody checked is a false assurance (F4). The
                    label says "structure" on purpose: the check is parse +
                    required keys + recognized fields, not proof Security Onion
                    will load the rule (F6). */}
                {draft.schema_ok === true && !edited && (
                  <div
                    className="text-[12px] font-semibold text-success"
                    title="The rule parses, has the required keys, and uses recognized fields. soc-ai has not loaded it into Security Onion."
                  >
                    Rule structure valid
                  </div>
                )}
                {draft.schema_ok === false && !edited && (
                  <div className="text-[12px] font-semibold text-danger">
                    {draft.validator_note ?? 'The rule structure check failed.'}
                  </div>
                )}
                {edited && (
                  <div className="text-[12px] text-warn">
                    The check and the dry run describe the original draft. soc-ai has not checked
                    your edits.
                  </div>
                )}

                {dry && (
                  <div
                    className="text-[12.5px] text-text-2"
                    style={edited ? { opacity: 0.55 } : undefined}
                  >
                    {dry.ran === false ? (
                      <span className="text-danger">
                        The dry run did not run: {dry.error ?? 'unknown error'}
                      </span>
                    ) : dry.hit_count === 0 ? (
                      <span>Dry run: 0 matches in {dry.window_days}d</span>
                    ) : (
                      <>
                        <span>
                          Would have fired {dry.hit_count}× in {dry.window_days}d
                          {dry.total_is_lower_bound ? ', a lower bound' : ''}
                        </span>
                        {dry.sample_ids.length > 0 && (
                          <div className="mt-1.5 flex flex-wrap gap-1.5 font-mono text-[10.5px]">
                            {dry.sample_ids.map((id) => (
                              <span
                                key={id}
                                className="rounded-chip bg-surface-3 px-1.5 py-px text-accent"
                              >
                                {id}
                              </span>
                            ))}
                          </div>
                        )}
                      </>
                    )}
                    {dry.ran !== false && (
                      <p className="mt-1 text-[11px] leading-[1.5] text-faint">
                        The would-have-fired count comes from an equivalent OQL query against your
                        telemetry. soc-ai did not load the Sigma rule into Security Onion.
                      </p>
                    )}
                  </div>
                )}

                {/* The query the dry run actually measured (2026-08-25 security
                    audit, FIX 3): without it the analyst cannot see whether the
                    would-have-fired count and the exported Sigma describe the
                    same logic. Read-only by design — edits belong in the YAML. */}
                {draft.oql && (
                  <div className="flex flex-col gap-1.5">
                    <span className="text-[11.5px] font-semibold uppercase tracking-[.05em] text-faint">
                      Measured by this read-only OQL query
                    </span>
                    <code className="block w-full overflow-x-auto whitespace-pre-wrap break-all rounded-card border border-border bg-surface-2 px-2.5 py-2 font-mono text-[11.5px] leading-[1.5] text-text-2">
                      {draft.oql}
                    </code>
                  </div>
                )}

                <label className="flex flex-col gap-1.5">
                  <span className="text-[11.5px] font-semibold uppercase tracking-[.05em] text-faint">
                    Sigma rule YAML. Edit before export.
                  </span>
                  <textarea
                    value={yamlEdit}
                    onChange={(e) => setYamlEdit(e.target.value)}
                    rows={14}
                    spellCheck={false}
                    className="w-full resize-y rounded-card border border-border-input bg-surface-2 px-2.5 py-2 font-mono text-[12px] leading-[1.5] text-text-2 outline-none focus:border-accent"
                  />
                </label>

                {provenance}

                <div className="flex flex-wrap items-center gap-2">
                  {canCopy && (
                    <button
                      type="button"
                      onClick={copyRule}
                      className="flex items-center gap-1.5 rounded-control border border-border-strong bg-surface-3 px-[11px] py-1.5 text-[12px] font-semibold text-dim hover:border-accent hover:text-text"
                    >
                      <Copy size={13} />
                      {copied ? 'Copied' : 'Copy rule'}
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={downloadYaml}
                    className="flex items-center gap-1.5 rounded-control border border-border-strong bg-surface-3 px-[11px] py-1.5 text-[12px] font-semibold text-dim hover:border-accent hover:text-text"
                  >
                    <Download size={13} />
                    Download .yml
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
