import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ChevronDown, ChevronRight, ShieldCheck } from 'lucide-react';

import {
  getAuthorizedActivity,
  onNeedsYouChanged,
  revokeAuthorizedActivity,
  type AuthorizedActivity,
} from '../lib/api';
import {
  AUTHORIZED_MARK,
  AUTHORIZED_STATE,
  expiryWords,
  machineWords,
  recordTimeSentence,
  ruleCountWords,
  runCountWords,
  scopeWords,
} from '../lib/authorizedActivity';
import { demoBlocked, useDemo } from '../lib/demo';
import { plural } from '../lib/plural';
import { useToast } from '../lib/toast';
import { agoWords } from '../lib/timeRange';
import { DEFINE_AUTHORIZED_ACTIVITY } from '../lib/tooltips';
import { Spinner } from './States';

// ---------------------------------------------------------------------------
// The cards of authorized activity: one card for each record, full width.
//
// A run inside an authorized scope raises no notification of its own, so the
// card is where the analyst sees it: the label, the scope, the expiry and the
// count of the runs that matched since the decision, on one row. The count
// links to the runs. The rule names, the note and who recorded the record sit
// behind a toggle. Revoke asks for a reason and returns the runs to normal
// handling.
//
// The strip renders nothing when no record is active or ended in the last 7
// days.
// ---------------------------------------------------------------------------

const POLL_MS = 60_000;

const STATE_TONE: Record<AuthorizedActivity['state'], string> = {
  active: 'border-accent text-accent',
  expired: 'border-border-2 text-dim',
  revoked: 'border-border-2 text-faint',
};

function errorText(err: unknown, fallback: string): string {
  return err instanceof Error && err.message ? err.message : fallback;
}

function Card({
  record,
  onRevoked,
}: {
  record: AuthorizedActivity;
  /** The count of the runs that went back to normal handling. */
  onRevoked: (returned: number) => void;
}) {
  const demo = useDemo();
  const [asking, setAsking] = useState(false);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showRules, setShowRules] = useState(false);

  const revoke = () => {
    const blocked = demoBlocked(demo);
    if (blocked) {
      setError(blocked);
      return;
    }
    setBusy(true);
    setError(null);
    revokeAuthorizedActivity(record.id, reason.trim())
      .then((answer) => {
        setAsking(false);
        setReason('');
        onRevoked(answer.runs_returned ?? answer.runs_total);
      })
      .catch((err: unknown) => setError(errorText(err, 'The revoke failed. Try again.')))
      .finally(() => setBusy(false));
  };

  const rulesId = `authorized-rules-${record.id}`;
  return (
    <article
      data-testid={`authorized-card-${record.id}`}
      className="rounded-card border border-border-2 bg-surface-2 px-3.5 py-2.5 text-[12.5px] leading-[1.55] text-text-2"
    >
      {/* One row: the label, the state, the scope, the expiry, the runs and
          Revoke. The card listed every rule name and took about 400 px at
          the top of Investigations and the Hunt Console (polish review
          2026-11-13). The rules sit behind a toggle, closed by default. */}
      <div data-testid="authorized-row" className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="text-[13px] font-semibold text-text">{record.label}</span>
        <span
          data-testid="authorized-state"
          className={`rounded-badge border px-[6px] py-[1px] text-[10.5px] font-semibold ${STATE_TONE[record.state]}`}
        >
          {AUTHORIZED_STATE[record.state]}
        </span>
        <span
          data-testid="authorized-scope"
          title={`Sources: ${record.sources.map((source) => machineWords(source)).join(', ')}. Target: ${machineWords(record.target)}.`}
        >
          {scopeWords(record)}
        </span>
        <span data-testid="authorized-expiry" title={recordTimeSentence(record)} className="text-dim">
          {expiryWords(record)}
        </span>
        <Link
          to={record.runs_href}
          data-testid="authorized-runs-link"
          title={record.last_match_at ? `The last match was ${agoWords(record.last_match_at)}.` : undefined}
          className="font-semibold text-accent underline hover:opacity-80"
        >
          {runCountWords(record)}
        </Link>
        <span className="flex-1" />
        <button
          type="button"
          data-testid="authorized-rules-toggle"
          aria-expanded={showRules}
          aria-controls={rulesId}
          onClick={() => setShowRules((open) => !open)}
          className="inline-flex items-center gap-1 text-[12px] font-semibold text-dim hover:text-text"
        >
          {showRules ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
          {showRules ? 'Hide the rules' : `Show the ${plural(record.rule_names.length, 'rule')}`}
        </button>
        {record.state !== 'revoked' && !asking && (
          <button
            type="button"
            onClick={() => {
              setAsking(true);
              setError(null);
            }}
            className="rounded-control border border-border-strong bg-surface-3 px-[10px] py-0.5 text-[12px] font-semibold text-dim hover:border-warn hover:text-text"
          >
            Revoke
          </button>
        )}
      </div>
      {showRules && (
        <div id={rulesId} data-testid="authorized-rules" className="mt-1.5 border-t border-border-faint pt-1.5">
          <div>{recordTimeSentence(record)}</div>
          {record.note && <div className="text-dim">Note: {record.note}</div>}
          {ruleCountWords(record)}:
          <ul className="list-disc pl-5">
            {record.rule_names.map((name) => (
              <li key={name} className="font-mono text-[11.5px] text-text">
                {name}
              </li>
            ))}
          </ul>
        </div>
      )}
      {asking && (
        <div data-testid="authorized-revoke-form" className="mt-2 flex flex-col gap-1.5">
          <label htmlFor={`revoke-reason-${record.id}`} className="text-[12px] font-semibold text-dim">
            Reason for the revoke
          </label>
          <input
            id={`revoke-reason-${record.id}`}
            value={reason}
            maxLength={512}
            onChange={(e) => setReason(e.target.value)}
            className="w-full rounded-control border border-border-input bg-bg px-3 py-1.5 text-[12.5px] text-text outline-none focus:border-accent"
          />
          <div className="text-dim">
            A revoke ends the record now. Its investigations get normal handling again: each case request
            waits for you.
          </div>
          {error && (
            <div role="alert" className="text-danger">
              {error}
            </div>
          )}
          <div className="flex gap-2">
            <button
              type="button"
              disabled={busy || !reason.trim()}
              onClick={revoke}
              className="flex items-center gap-1.5 rounded-control border border-warn bg-[rgba(245,166,35,.12)] px-3 py-1 text-[12px] font-semibold text-warn hover:bg-[rgba(245,166,35,.2)] disabled:opacity-60"
            >
              {busy && <Spinner size={12} />}
              Confirm revoke
            </button>
            <button
              type="button"
              onClick={() => setAsking(false)}
              className="rounded-control border border-border-strong bg-surface-3 px-3 py-1 text-[12px] font-semibold text-text-2 hover:text-text"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </article>
  );
}

export function AuthorizedActivityCards({ className = '' }: { className?: string }) {
  const { toast } = useToast();
  const [rows, setRows] = useState<AuthorizedActivity[] | null>(null);
  const [failed, setFailed] = useState(false);

  const load = useCallback(() => {
    getAuthorizedActivity()
      .then((answer) => {
        setRows(answer.rows);
        setFailed(false);
      })
      .catch(() => setFailed(true));
  }, []);

  useEffect(() => {
    load();
    const stop = onNeedsYouChanged(load);
    const timer = window.setInterval(load, POLL_MS);
    return () => {
      stop();
      window.clearInterval(timer);
    };
  }, [load]);

  if (failed && rows === null) {
    return (
      <div role="status" data-testid="authorized-cards-error" className={`text-[12.5px] text-dim ${className}`}>
        soc-ai could not read the authorized activity.
      </div>
    );
  }
  if (!rows || rows.length === 0) return null;

  return (
    <section data-testid="authorized-cards" aria-label={AUTHORIZED_MARK} className={className}>
      <h2
        title={DEFINE_AUTHORIZED_ACTIVITY}
        className="mb-2 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[.06em] text-faint"
      >
        <ShieldCheck size={13} />
        {AUTHORIZED_MARK}
      </h2>
      <div className="flex flex-col gap-2">
        {rows.map((record) => (
          <Card
            key={record.id}
            record={record}
            onRevoked={(returned) => {
              toast({
                tone: 'success',
                message: `soc-ai revoked "${record.label}". ${plural(returned, 'investigation')} went back to normal handling.`,
              });
              load();
            }}
          />
        ))}
      </div>
    </section>
  );
}
