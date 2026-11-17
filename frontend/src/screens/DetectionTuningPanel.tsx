import { useState } from 'react';
import {
  clearRulePrior,
  type DetectionNomination,
  type DetectionOverride,
  getDetectionTuning,
  muteRule,
  unmuteRule,
} from '../lib/api';
import { CollapseChevron } from '../components/Panel';
import { OracleShadowTally } from './OracleShadowTally';
import { ErrorState, LoadingState } from '../components/States';
import {
  RULE_PRIOR_COLUMN,
  RULE_PRIOR_INTERNAL,
  RULE_PRIOR_KNOWN_EXTERNAL,
  RULE_PRIOR_REASON,
  RULE_PRIOR_SUSPENDED,
  RULE_PRIOR_UNCHECKED,
} from '../lib/tooltips';
import { useAsync } from '../lib/useAsync';

// The nominations grid. One template for the header and the rows, so the
// columns cannot drift apart.
const NOMINATION_COLS = 'grid-cols-[1fr_80px_150px_170px_110px_90px]';

/** One line of the split of the covered alerts: the covers and the disagreements. */
function PriorSplitLine({
  label,
  covered,
  disagree,
  tip,
  testId,
}: {
  label: string;
  covered: number;
  disagree: number;
  tip: string;
  testId: string;
}) {
  return (
    <div data-testid={testId} title={tip} className="font-mono text-faint">
      {label}: covered {covered} · disagree{' '}
      <span className={disagree > 0 ? 'text-danger' : undefined}>{disagree}</span>
    </div>
  );
}

/**
 * The Rule prior cell: what the rule prior did on this rule. Covered alerts
 * and the real verdicts beside them, split into two internal addresses and a
 * known external address; a suspension with its Clear button; or, when it
 * covered nothing, why it held back on the newest alert.
 */
function RulePriorCell({
  n,
  busy,
  onClear,
}: {
  n: DetectionNomination;
  busy: boolean;
  onClear: () => void;
}) {
  const covered = n.prior_covered ?? 0;
  const agree = n.prior_agreements ?? 0;
  const disagree = n.prior_disagreements ?? 0;
  const unchecked = n.prior_unchecked ?? 0;
  const reason = n.prior_last_reason ? RULE_PRIOR_REASON[n.prior_last_reason] : undefined;
  // An older backend sends no split. The cell then shows the totals only.
  const split =
    n.prior_covered_internal !== undefined || n.prior_covered_known_external !== undefined;
  return (
    <div data-testid={`rule-prior-${n.rule_name}`} className="min-w-0 text-[11px] leading-[1.45]">
      {covered > 0 ? (
        <>
          <div className="font-mono text-dim">
            covered {covered} · agree {agree} · disagree{' '}
            <span className={disagree > 0 ? 'text-danger' : undefined}>{disagree}</span>
            {unchecked > 0 && (
              <span title={RULE_PRIOR_UNCHECKED} className="text-faint">
                {' '}
                · {unchecked} unchecked
              </span>
            )}
          </div>
          {split && (
            <>
              <PriorSplitLine
                label="internal"
                covered={n.prior_covered_internal ?? 0}
                disagree={n.prior_disagreements_internal ?? 0}
                tip={RULE_PRIOR_INTERNAL}
                testId={`rule-prior-internal-${n.rule_name}`}
              />
              <PriorSplitLine
                label="known external"
                covered={n.prior_covered_known_external ?? 0}
                disagree={n.prior_disagreements_known_external ?? 0}
                tip={RULE_PRIOR_KNOWN_EXTERNAL}
                testId={`rule-prior-external-${n.rule_name}`}
              />
            </>
          )}
        </>
      ) : (
        <div className="text-faint" title={reason}>
          {reason ? `not covered: ${reason}` : 'not covered'}
        </div>
      )}
      {n.prior_suspended && (
        <div className="mt-1 flex items-center gap-1.5">
          <span
            title={RULE_PRIOR_SUSPENDED}
            className="rounded-chip border px-1.5 py-px text-[9.5px] font-semibold uppercase tracking-[.04em]"
            style={{ color: '#f04438', borderColor: 'rgba(240,68,56,.35)', background: 'rgba(240,68,56,.08)' }}
          >
            Suspended
          </span>
          <button
            onClick={onClear}
            disabled={busy}
            className="rounded-[7px] border border-border-strong bg-surface-3 px-[8px] py-[2px] text-[11px] font-semibold text-text hover:border-accent disabled:cursor-not-allowed disabled:opacity-40"
          >
            Clear
          </button>
        </div>
      )}
    </div>
  );
}

/** Color + label for a tuning recommendation. A mute suggestion is routine
 *  housekeeping: red marks a confirmed threat or a failed write only (review
 *  2026-11-12), so the suggestion wears the accent. */
function recBadge(rec: DetectionNomination['recommendation']): { color: string; label: string } {
  if (rec === 'mute') return { color: '#4b8bf5', label: 'Mute' };
  if (rec === 'monitor') return { color: '#f5a623', label: 'Monitor' };
  return { color: '#8b949e', label: 'None' };
}

/** The rules the next step mutes: a mute suggestion, not muted yet, and no
 *  true positive. */
export function muteCandidates(nominations: DetectionNomination[]): DetectionNomination[] {
  return nominations.filter((n) => n.recommendation === 'mute' && !n.already_muted && n.tp === 0);
}

/** The window words: "7d" reads "the last 7 days". */
function windowWords(window: string | undefined): string {
  const m = (window ?? '7d').match(/^(\d+)([dh])$/);
  if (!m) return 'this window';
  const n = Number(m[1]);
  const unit = m[2] === 'd' ? 'day' : 'hour';
  return n === 1 ? `the last ${unit}` : `the last ${n} ${unit}s`;
}

/** The one next step of the panel: "25 rules produce 62% of the alert events
 *  of the last 7 days and no true positive." Null when no rule waits. */
export function nextStepSentence(
  nominations: DetectionNomination[],
  alertTotal: number | null | undefined,
  window: string | undefined,
): string | null {
  const rules = muteCandidates(nominations);
  if (rules.length === 0) return null;
  const events = rules.reduce((sum, n) => sum + n.alert_count, 0);
  const who = rules.length === 1 ? '1 rule produces' : `${rules.length} rules produce`;
  const when = windowWords(window);
  if (alertTotal && alertTotal > 0) {
    const share = Math.min(100, Math.round((events / alertTotal) * 100));
    return `${who} ${share}% of the alert events of ${when} and no true positive.`;
  }
  return `${who} ${events.toLocaleString()} alert events of ${when} and no true positive.`;
}

/**
 * The analyst-feedback signal for a nomination — the human corrections that drove
 * (or strengthened) it. Returns '' when the analyst has not touched the rule, so
 * the caller can skip rendering the line entirely.
 */
function analystSignal(n: DetectionNomination): string {
  const parts: string[] = [];
  if (n.override_fp > 0) {
    parts.push(`${n.override_fp} analyst FP-override${n.override_fp === 1 ? '' : 's'}`);
  }
  const resolved = n.chat_resolved + n.manual_resolved;
  if (resolved > 0) {
    parts.push(`${resolved} analyst-resolved`);
    if (n.chat_resolved > 0) parts.push(`${n.chat_resolved} in chat`);
    if (n.manual_resolved > 0) parts.push(`${n.manual_resolved} manual`);
  }
  return parts.join(' · ');
}

/** "39 · 29 mute suggestions": every nominated rule, then the pending mutes
 *  among them. The Dashboard nudge counts pending mutes the same way. */
function nominationCountLine(nominations: DetectionNomination[]): string {
  const pending = nominations.filter((n) => n.recommendation === 'mute' && !n.already_muted).length;
  return `${nominations.length} · ${pending} mute suggestion${pending === 1 ? '' : 's'}`;
}

export function DetectionTuningPanel({
  collapsed = false,
  onToggleCollapse,
}: {
  collapsed?: boolean;
  onToggleCollapse?: () => void;
} = {}) {
  // A nonce drives an optimistic refetch after every mute / un-mute.
  const [nonce, setNonce] = useState(0);
  const { data, loading, error } = useAsync(getDetectionTuning, [nonce]);
  const [actionError, setActionError] = useState('');
  const [busy, setBusy] = useState(false);
  const [confirmAll, setConfirmAll] = useState(false);

  const nominations = data?.nominations ?? [];
  const overrides = data?.overrides ?? [];
  // Both halves of this panel are fed by the one call, so when it fails the
  // muted-rules COUNT is unknown — and `?? []` renders unknown as zero. On a
  // grid outage that printed "MUTED RULES (0)" over a bare table: a team that
  // relies on mutes reads "nothing is suppressed" at exactly the moment nobody
  // can check. Zero is a finding; this is the absence of one, and the header
  // has to be able to say so. A genuinely empty list on a healthy grid keeps
  // its 0 and its explanatory caption.
  //
  // The predicate is "did a load ever land", not "is there an error right now":
  // useAsync keeps the last good data through a failed REFETCH, and a count of
  // "—" over rows the panel is still showing would be its own small lie.
  const overridesKnown = !!data;

  // Wrap a mutation so any error surfaces inline and the lists refetch on success.
  const mutate = (p: Promise<unknown>) => {
    setActionError('');
    setBusy(true);
    p.then(() => setNonce((n) => n + 1))
      .catch((e: unknown) =>
        setActionError(e instanceof Error ? e.message : 'The action failed.'),
      )
      .finally(() => setBusy(false));
  };

  return (
    <div id="detection-tuning" className="mb-[22px] scroll-mt-6">
      <div className="mb-1 flex items-center gap-2">
        <div className="text-[15px] font-semibold">Detection tuning</div>
        {onToggleCollapse && (
          <CollapseChevron collapsed={collapsed} onToggle={onToggleCollapse} label="Toggle Detection tuning" />
        )}
      </div>
      {!collapsed && (
      <>
      <div className="mb-3 text-[12.5px] leading-[1.5] text-dim">
        soc-ai nominates a rule that fires often and returns a false positive each time. A mute
        hides the alerts of that rule from the default feed. A mute is reversible. A mute{' '}
        <strong>never changes Security Onion</strong>. soc-ai never nominates a rule that caught a
        true positive.
      </div>

      {actionError && (
        <div className="mb-2 text-[12px] text-danger">{actionError}</div>
      )}

      {/* L3: one next step above the table. The panel showed "37 · 25 MUTE
          SUGGESTIONS" and one Mute for each row, and no line said what the
          25 cost or how to act on them (review 2026-11-12). */}
      {overridesKnown && nextStepSentence(nominations, data?.alert_total, data?.window) && (
        <div
          data-testid="tuning-next-step"
          className="mb-3 flex flex-wrap items-center gap-x-3 gap-y-2 rounded-card border border-border bg-surface-1 px-3.5 py-2.5 text-[12.5px] text-text-2"
        >
          <span className="min-w-0 flex-1">
            {nextStepSentence(nominations, data?.alert_total, data?.window)}
          </span>
          {confirmAll ? (
            <span className="flex flex-wrap items-center gap-2" data-testid="tuning-mute-confirm">
              <span className="text-dim">
                {`Mute ${muteCandidates(nominations).length} rules? A mute hides their alerts from the default feed. It never changes Security Onion.`}
              </span>
              <button
                type="button"
                data-testid="tuning-mute-all-confirm"
                disabled={busy}
                onClick={() => {
                  const rules = muteCandidates(nominations);
                  setConfirmAll(false);
                  // One request for each rule, in order. A failed request
                  // stops the run and names itself.
                  mutate(
                    rules.reduce<Promise<unknown>>(
                      (chain, n) => chain.then(() => muteRule(n.rule_name, n.reason)),
                      Promise.resolve(),
                    ),
                  );
                }}
                className="flex-none rounded-[7px] border border-accent bg-[rgba(75,139,245,.14)] px-[11px] py-[5px] text-[11.5px] font-semibold text-text hover:bg-[rgba(75,139,245,.22)] disabled:opacity-40"
              >
                {`Mute ${muteCandidates(nominations).length} rules`}
              </button>
              <button
                type="button"
                onClick={() => setConfirmAll(false)}
                className="flex-none rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-[5px] text-[11.5px] font-semibold text-text-2 hover:text-text"
              >
                Cancel
              </button>
            </span>
          ) : (
            <button
              type="button"
              data-testid="tuning-mute-all"
              disabled={busy}
              onClick={() => setConfirmAll(true)}
              className="flex-none rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-[5px] text-[11.5px] font-semibold text-text hover:border-accent disabled:opacity-40"
            >
              {muteCandidates(nominations).length === 1 ? 'Mute this rule' : `Mute these ${muteCandidates(nominations).length} rules`}
            </button>
          )}
        </div>
      )}

      {/* ── Nominations ──────────────────────────────────────────────────── */}
      {/* The count matches the Dashboard nudge, which names both numbers
          (D10). Unknown until a load lands, for the reason given above. */}
      <div
        data-testid="nominated-count"
        className="mb-1.5 text-[11px] font-semibold uppercase tracking-[.06em] text-faint"
      >
        Nominated rules ({overridesKnown ? nominationCountLine(nominations) : '—'})
      </div>
      <div className="mb-4 overflow-hidden rounded-card border border-border bg-surface-1">
        <div className={`grid ${NOMINATION_COLS} gap-2 border-b border-border bg-surface-2 px-3.5 py-2 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint`}>
          <div>Rule</div>
          <div title="The alert events of the rule in the window of the panel.">{`Alerts · ${data?.window ?? '7d'}`}</div>
          <div title="False positive, true positive and needs more info verdicts on the rule.">
            FP / TP / Needs more info
          </div>
          <div title={RULE_PRIOR_COLUMN}>Rule prior</div>
          <div>Recommend</div>
          <div />
        </div>
        {loading && <LoadingState />}
        {error && (
          <div className="p-3">
            <ErrorState error={error} />
          </div>
        )}
        {!loading && !error && nominations.length === 0 && (
          <div className="px-3.5 py-4 text-[12.5px] text-faint">
            No rule is nominated. No rule reached the nomination thresholds.
          </div>
        )}
        {!loading &&
          !error &&
          nominations.map((n) => {
            const rb = recBadge(n.recommendation);
            return (
              <div
                key={n.rule_name}
                className={`grid ${NOMINATION_COLS} items-center gap-2 border-b border-border-faint px-3.5 py-3 last:border-b-0`}
              >
                <div className="min-w-0">
                  <div className="break-words text-[13px] font-medium" title={n.rule_name}>
                    {n.rule_name}
                  </div>
                  <div className="mt-0.5 text-[11px] leading-[1.4] text-faint">{n.reason}</div>
                  {analystSignal(n) && (
                    <div
                      className="mt-0.5 text-[11px] leading-[1.4] text-accent"
                      title="This line counts the analyst corrections on this rule. The counts drive the nomination."
                    >
                      {analystSignal(n)}
                    </div>
                  )}
                </div>
                <div className="font-mono text-[12px] text-dim">{n.alert_count.toLocaleString()}</div>
                <div className="font-mono text-[11.5px] text-dim">
                  {n.fp} / {n.tp} / {n.nmi}
                </div>
                <RulePriorCell n={n} busy={busy} onClear={() => mutate(clearRulePrior(n.rule_name))} />
                <div>
                  <span
                    className="inline-flex items-center gap-1.5 text-[11.5px]"
                    style={{ color: rb.color }}
                  >
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: rb.color }} />
                    {rb.label}
                  </span>
                </div>
                <div className="text-right">
                  {n.already_muted ? (
                    <span className="text-[11px] text-faint">muted</span>
                  ) : (
                    <button
                      onClick={() => mutate(muteRule(n.rule_name, n.reason))}
                      disabled={busy}
                      className="flex-none rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-[5px] text-[11.5px] font-semibold text-text hover:border-accent disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      Mute
                    </button>
                  )}
                </div>
              </div>
            );
          })}
      </div>

      {/* ── Active overrides ─────────────────────────────────────────────── */}
      <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-[.06em] text-faint">
        Muted rules ({overridesKnown ? overrides.length : '—'})
      </div>
      <div className="overflow-hidden rounded-card border border-border bg-surface-1">
        <div className="grid grid-cols-[1fr_140px_90px] gap-2 border-b border-border bg-surface-2 px-3.5 py-2 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint">
          <div>Rule</div>
          <div>Muted by</div>
          <div />
        </div>
        {!loading && !error && overrides.length === 0 && (
          <div className="px-3.5 py-4 text-[12.5px] text-faint">
            No muted rules. Mute a nominated rule above to suppress it from the default feed.
          </div>
        )}
        {/* Without this the failed load leaves a bare column header — the same
            shape as an empty table, which is the reading to avoid. The card
            above already carries the error and the retry; this one only has to
            refuse to claim the list is empty. Not shown when a previous load
            left rows on screen: they are stale, not absent. */}
        {error && !data && (
          <div className="px-3.5 py-4 text-[12.5px] text-faint">
            soc-ai could not load the muted rules. This is not a claim that none are muted.
          </div>
        )}
        {overrides.map((o: DetectionOverride) => (
          <div
            key={o.id}
            className="grid grid-cols-[1fr_140px_90px] items-center gap-2 border-b border-border-faint px-3.5 py-3 last:border-b-0"
          >
            <div className="min-w-0">
              <div className="break-words text-[13px] font-medium" title={o.rule_name}>
                {o.rule_name}
              </div>
              {o.reason && (
                <div className="mt-0.5 text-[11px] leading-[1.4] text-faint">{o.reason}</div>
              )}
            </div>
            <div className="break-words text-[11.5px] text-dim" title={o.created_by}>
              {o.created_by}
            </div>
            <div className="text-right">
              <button
                onClick={() => mutate(unmuteRule(o.id))}
                disabled={busy}
                className="flex-none rounded-[7px] border border-border-strong bg-surface-3 px-[11px] py-[5px] text-[11.5px] font-semibold text-text hover:border-accent disabled:cursor-not-allowed disabled:opacity-40"
              >
                Un-mute
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* ── Oracle rule shadow ───────────────────────────────────────────── */}
      <OracleShadowTally />
      </>
      )}
    </div>
  );
}
