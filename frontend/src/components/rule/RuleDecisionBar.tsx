import { useEffect, useId, useState } from 'react';
import { CalendarClock, CheckCircle2, ShieldOff, XCircle } from 'lucide-react';
import {
  endRuleDecision,
  emitNeedsYouChanged,
  postRuleDecision,
  type RuleDecisionChoice,
  type RuleDecisionDetail,
  type RuleDecisionRecord,
} from '../../lib/api';
import { demoBlocked, useDemo } from '../../lib/demo';
import {
  END_STANDING_LABEL,
  END_STANDING_WRITES,
  INCLUDE_TRUE_POSITIVE_PAIRS_HINT,
  INCLUDE_WEAK_HINT,
  NOTE_HINT,
  NOTE_LABEL,
  STANDING_LABEL,
  acknowledgeLabel,
  acknowledgeWrites,
  historyWords,
  includeTruePositivePairsLabel,
  includeWeakLabel,
  planFor,
  progressWords,
  resultWords,
  standingInForceWords,
  standingRefusedWords,
  standingWrites,
} from '../../lib/ruleDecision';
import { Spinner } from '../States';

/** How often the bar reads the rule again while soc-ai writes. */
export const PROGRESS_POLL_MS = 1500;

const PRIMARY =
  'flex flex-none items-center gap-1.5 rounded-control border border-accent bg-[rgba(75,139,245,.14)] px-3 py-1.5 text-left text-[12.5px] font-semibold text-accent hover:bg-[rgba(75,139,245,.22)] disabled:cursor-not-allowed disabled:opacity-60';
const SECONDARY =
  'flex flex-none items-center gap-1.5 rounded-control border border-border-strong bg-surface-3 px-3 py-1.5 text-left text-[12.5px] font-semibold text-text hover:border-accent hover:text-accent disabled:cursor-not-allowed disabled:opacity-60';
const WRITES = 'mt-1 break-words text-[12px] leading-[1.5] text-dim';

function errorText(err: unknown): string {
  return err instanceof Error && err.message ? err.message : 'soc-ai did not store the decision. Try again.';
}

/**
 * The decision on a rule (round 3, RC3). The main button acknowledges the
 * false positives with checked evidence. A check box adds the ones with weak evidence,
 * off by default, and absent when the rule holds none. The second choice also
 * lets soc-ai acknowledge each later false positive of the rule for 30 days;
 * the console hides it with the reason when the server refuses it. Each
 * button states what it writes before the press, and no button asks again:
 * the owner rule for an acknowledge.
 *
 * After the press the bar states the progress, reads the rule again until the
 * record is done, and then states the result. A failed result states the
 * failure and keeps the buttons. A standing decision in force shows its end
 * date, its count and "End the standing decision".
 */
export function RuleDecisionBar({
  detail: d,
  onRefresh,
}: {
  detail: RuleDecisionDetail;
  /** Read the rule again. */
  onRefresh: () => void;
}) {
  const demo = useDemo();
  const noteId = useId();
  const [includeWeak, setIncludeWeak] = useState(false);
  const [includeTp, setIncludeTp] = useState(false);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState<RuleDecisionChoice | 'end' | null>(null);
  const [error, setError] = useState<string | null>(null);
  // The record of the press in this tab. The history of the server holds the
  // newer state of the same record. With no press here, a decision that soc-ai
  // still writes, from another tab or before a reload, shows its progress.
  const [pressed, setPressed] = useState<RuleDecisionRecord | null>(null);
  const record = pressed
    ? (d.history.find((h) => String(h.id) === String(pressed.id)) ?? pressed)
    : (d.history.find((h) => h.state === 'acknowledging') ?? null);
  const writing = record?.state === 'acknowledging';

  // Read the rule again while soc-ai writes. Each new read starts the next wait.
  useEffect(() => {
    if (!writing) return;
    const t = window.setTimeout(onRefresh, PROGRESS_POLL_MS);
    return () => window.clearTimeout(t);
  }, [writing, d, onRefresh]);

  // The end of the write moves the needs-you count.
  const done = record !== null && record.state !== 'acknowledging';
  useEffect(() => {
    if (done) emitNeedsYouChanged();
  }, [done]);

  // The false positives on the machines of a true positive are a third
  // choice, off by default: the main button leaves them out (F4).
  const tpConfident = Math.min(d.confident.count, d.truePositivePairs?.confident ?? 0);
  const tpWeak = Math.min(d.weak.count, d.truePositivePairs?.weak ?? 0);
  const confident = d.confident.count - tpConfident;
  const weak = d.weak.count - tpWeak;
  // A rule with none that has checked evidence offers the group with weak
  // evidence on the main button, and the check box goes.
  const weakOnly = confident === 0 && weak > 0;
  const withWeak = weakOnly || (includeWeak && weak > 0);
  const tpN = tpConfident + (withWeak ? tpWeak : 0);
  const withTp = includeTp && tpN > 0;
  const n = confident + (withWeak ? weak : 0) + (withTp ? tpN : 0);
  const plan = planFor(d.plans, withWeak, withTp);
  const locked = busy !== null || writing;
  const offerStanding = d.canStanding && !d.standing;

  const decide = (decision: RuleDecisionChoice) => {
    const blocked = demoBlocked(demo);
    if (blocked) {
      setError(blocked);
      return;
    }
    setBusy(decision);
    setError(null);
    postRuleDecision(d.ruleKey, {
      decision,
      includeWeak: withWeak,
      note: note.trim(),
      ...(withTp ? { includeTruePositivePairs: true } : {}),
    })
      .then((answer) => {
        setPressed(answer);
        setNote('');
        onRefresh();
      })
      .catch((err: unknown) => setError(errorText(err)))
      .finally(() => setBusy(null));
  };

  const end = () => {
    const blocked = demoBlocked(demo);
    if (blocked) {
      setError(blocked);
      return;
    }
    setBusy('end');
    setError(null);
    endRuleDecision(d.ruleKey)
      .then(() => onRefresh())
      .catch((err: unknown) => setError(errorText(err)))
      .finally(() => setBusy(null));
  };

  return (
    <section
      aria-label="The decision on the rule"
      data-testid="rule-decision-bar"
      className="mt-3 rounded-card border border-warn/40 bg-warn/[.07] px-3 py-2.5"
    >
      {d.standing && (
        <div data-testid="rule-standing" className="mb-2.5 rounded-[7px] border border-border-strong bg-surface-2 px-3 py-2">
          <div className="flex items-start gap-2 text-[12.5px] leading-[1.5] text-text">
            <CalendarClock size={14} aria-hidden className="mt-[3px] flex-none text-accent" />
            <span className="min-w-0 break-words">{standingInForceWords(d.standing)}</span>
          </div>
          <div className="mt-2 pl-[22px]">
            <button type="button" className={SECONDARY} disabled={locked} onClick={end}>
              {busy === 'end' && <Spinner size={13} />}
              {END_STANDING_LABEL}
            </button>
            <div data-testid="rule-end-writes" className={WRITES}>
              {END_STANDING_WRITES}
            </div>
          </div>
        </div>
      )}

      {record && (
        <div data-testid="rule-decision-result" data-state={record.state} className="mb-2.5 text-[13px] leading-[1.5]">
          {record.state === 'acknowledging' ? (
            <span className="flex items-center gap-2 text-text">
              <Spinner size={13} /> {progressWords(record.alerts)}
            </span>
          ) : record.state === 'failed' ? (
            <span role="alert" className="flex items-start gap-2 font-semibold text-danger">
              <XCircle size={14} aria-hidden className="mt-[3px] flex-none" />
              <span className="min-w-0 break-words">{resultWords(record)}</span>
            </span>
          ) : (
            <span className="flex items-start gap-2 font-semibold text-success">
              <CheckCircle2 size={14} aria-hidden className="mt-[3px] flex-none" />
              <span className="min-w-0 break-words">{resultWords(record)}</span>
            </span>
          )}
        </div>
      )}

      {d.confident.count + d.weak.count === 0 ? (
        <p data-testid="rule-nothing-open" className="break-words text-[12.5px] text-text-2">
          No open false positive of this rule waits on you.
        </p>
      ) : (
        <>
          <div>
            <button
              type="button"
              data-testid="rule-acknowledge"
              className={PRIMARY}
              disabled={locked || n === 0}
              onClick={() => decide('acknowledge')}
            >
              {busy === 'acknowledge' && <Spinner size={13} />}
              {acknowledgeLabel(
                confident + (withTp ? tpConfident : 0),
                weak + (withTp && withWeak ? tpWeak : 0),
                withWeak,
              )}
            </button>
            {weakOnly && (
              <div data-testid="rule-weak-first" className="mt-1 break-words text-[12px] font-semibold text-warn">
                {INCLUDE_WEAK_HINT}
              </div>
            )}
            <div data-testid="rule-acknowledge-writes" className={WRITES}>
              {acknowledgeWrites(n, plan, { known: d.planKnown, scanMax: d.scanMax })}
            </div>
          </div>

          {weak > 0 && !weakOnly && (
            <label className="mt-2 flex cursor-pointer items-start gap-2 text-[12.5px] text-text">
              <input
                type="checkbox"
                data-testid="rule-include-weak"
                className="mt-[3px]"
                checked={includeWeak}
                disabled={locked}
                onChange={(e) => setIncludeWeak(e.target.checked)}
              />
              <span className="min-w-0 break-words">
                {includeWeakLabel(weak)}
                <span className="block text-[12px] text-dim">{INCLUDE_WEAK_HINT}</span>
              </span>
            </label>
          )}

          {tpN > 0 && (
            <label className="mt-2 flex cursor-pointer items-start gap-2 text-[12.5px] text-text">
              <input
                type="checkbox"
                data-testid="rule-include-true-positive-pairs"
                className="mt-[3px]"
                checked={includeTp}
                disabled={locked}
                onChange={(e) => setIncludeTp(e.target.checked)}
              />
              <span className="min-w-0 break-words">
                {includeTruePositivePairsLabel(tpN)}
                <span className="block text-[12px] text-danger">{INCLUDE_TRUE_POSITIVE_PAIRS_HINT}</span>
              </span>
            </label>
          )}

          {offerStanding ? (
            <div className="mt-2.5">
              <button
                type="button"
                data-testid="rule-standing-choice"
                className={SECONDARY}
                disabled={locked || n === 0}
                onClick={() => decide('standing')}
              >
                {busy === 'standing' && <Spinner size={13} />}
                {STANDING_LABEL}
              </button>
              <div data-testid="rule-standing-writes" className={WRITES}>
                {standingWrites(n)}
              </div>
            </div>
          ) : (
            !d.standing && (
              <p data-testid="rule-standing-refused" className="mt-2.5 flex items-start gap-2 break-words text-[12px] text-dim">
                <ShieldOff size={13} aria-hidden className="mt-[2px] flex-none" />
                <span className="min-w-0">{standingRefusedWords(d.canStandingWhy)}</span>
              </p>
            )
          )}

          <div className="mt-2.5">
            <label htmlFor={noteId} className="mb-1 block text-[12px] font-semibold text-dim">
              {NOTE_LABEL}
            </label>
            <textarea
              id={noteId}
              data-testid="rule-note"
              value={note}
              maxLength={2000}
              rows={2}
              disabled={locked}
              onChange={(e) => setNote(e.target.value)}
              className="w-full max-w-[640px] rounded-control border border-border-input bg-bg px-3 py-2 text-[13px] text-text outline-none focus:border-accent"
            />
            <div className="mt-0.5 text-[11.5px] text-faint">{NOTE_HINT}</div>
          </div>
        </>
      )}

      {error && (
        <div role="alert" data-testid="rule-decision-error" className="mt-2 break-words text-[12.5px] text-danger">
          {error}
        </div>
      )}

      {d.history.length > 0 && (
        <div className="mt-2.5 border-t border-border pt-2">
          <div className="text-[11px] font-semibold uppercase tracking-[.06em] text-dim">Decisions on this rule</div>
          <ul data-testid="rule-history" className="mt-1 flex flex-col gap-0.5">
            {d.history.map((h) => (
              <li key={String(h.id)} className="break-words text-[12px] leading-[1.5] text-text-2">
                {historyWords(h)}
                {h.note && <span className="text-dim"> Note: {h.note}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
