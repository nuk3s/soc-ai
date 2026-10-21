import { Link2Off, Loader2 } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router-dom';

import { checkEscalationClaim, getStrandedEscalations, type StrandedClaim } from '../lib/api';
import { absTime, agoWords } from '../lib/timeRange';
import { tint } from '../lib/tokens';
import { useAsync } from '../lib/useAsync';
import { Panel, PanelHeader } from './Panel';
import { EmptyState, Freshness, LoadingState } from './States';

// ---------------------------------------------------------------------------
// Escalation ledger — the claims that never came back with a case id.
//
// soc-ai claims an alert BEFORE opening its case, because the unique index on
// alert_id is what makes a repeated press safe. The claim is filled in a
// moment later with the case Security Onion opened, or dropped when the grid
// proves no case was opened. A row that gets neither is an escalate whose
// outcome nobody knows: the request may have created a case and failed on the
// attach, or failed before anything was written, and this deployment cannot
// tell which.
//
// Those rows do not heal. Reconciliation is lazy and press-scoped — it happens
// only when somebody presses escalate on a group that still contains the same
// alert, and only when the grid answers. If the alert ages out of the queue,
// or the case index cannot be read, the claim is permanent, and it keeps
// refusing every future escalate of that alert. Until this panel the only way
// to see one was to open the database: every reader in the store is keyed by
// an explicit list of alert ids, which is what the press path needs and no use
// at all for "what is stuck".
//
// Reads GET /escalations/stranded on a 5-minute cadence, matching the hunt
// catalog beside it. There is no "release" button: it would drop a claim on
// somebody's opinion rather than on evidence, and a request can fail after
// Security Onion has already created the case.
//
// Each row links to its alert, and each row has "Check Security Onion now"
// (R5-I5). The check asks POST /escalations/check to compare that one claim
// with Security Onion. The server settles the claim only on evidence: a case
// link settles it with the case, and a complete read with no link releases
// it. One check runs at a time, and the panel states its result in one
// sentence.
// ---------------------------------------------------------------------------

// Amber, the same "true story, but not the one you think" tone the catalog's
// blind and undecided markers wear. A stranded claim is not a failure of the
// alert or of the analyst; it is a fact about the ledger that reads as nothing
// at all until something says it.
const AMBER = '#f5a623';

const DAY_MS = 86_400_000;

/** A datetime-local value in the browser zone, the shape the Alerts custom
 *  window reads: "2026-10-01T11:37". */
function localInput(ms: number): string {
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

/**
 * The Alerts list on this claim's alert, or null when no link can name it.
 *
 * There is no alert detail page. The Alerts list takes an OQL clause, and
 * `_id` is a whitelisted field, so `_id:"<id>"` narrows the list to the one
 * alert. Acknowledged alerts stay in: an escalated alert can be acked.
 *
 * The window is absolute and sits around the claim. A preset such as 30d
 * counts back from now, and a claim never settles on its own, so a preset
 * loses the alert once the claim is a month old. The window starts 31 days
 * before the claim, because the Alerts list reaches back at most 30 days and a
 * zone offset can cost one more. It ends a day after the claim, for the same
 * offset. An id with a quote or a backslash cannot sit in the quoted clause, so
 * that row gets no link.
 */
export function alertHref(claim: StrandedClaim): string | null {
  const at = Date.parse(claim.claimed_at);
  if (!Number.isFinite(at) || !/^[^"\\\s]+$/.test(claim.alert_id)) return null;
  const p = new URLSearchParams();
  p.set('range', 'custom');
  p.set('from', localInput(at - 31 * DAY_MS));
  p.set('to', localInput(at + DAY_MS));
  p.set('hide_acked', 'false');
  p.set('q', `_id:"${claim.alert_id}"`);
  return `/alerts?${p}`;
}

interface CheckState {
  /** The claim whose check is in flight, or null. */
  running: string | null;
  onCheck: (claim: StrandedClaim) => void;
}

function ClaimRow({ claim, check }: { claim: StrandedClaim; check: CheckState }) {
  const href = alertHref(claim);
  const mine = check.running === claim.alert_id;
  // The rule and the host, then the sentence. The row was a raw alert id with
  // "claimed 5d ago" beside it, which names nothing an operator can act on
  // (dogfood 2026-10-06). The id stays in the tooltip for a search.
  return (
    <li data-testid="stranded-claim" className="flex items-start gap-2.5 px-[15px] py-2.5 text-[13px]">
      <div className="min-w-0 flex-1" title={`Alert ${claim.alert_id}`}>
        <div className="break-words text-text-2">
          {claim.rule_name ? (
            <>
              <span className="font-semibold">{claim.rule_name}</span>
              {claim.host && <span className="text-dim"> on {claim.host}</span>}
            </>
          ) : (
            <span className="text-dim">
              An alert with no investigation, <span className="font-mono text-[11.5px]">{claim.alert_id}</span>
            </span>
          )}
        </div>
        {/* The age is the fact: four minutes is a request in flight, and five
            days is an alert nobody can escalate. */}
        <div className="mt-0.5 text-[12px] text-dim" title={absTime(claim.claimed_at)}>
          Escalation sent {agoWords(claim.claimed_at)}. Security Onion has not confirmed a case.
        </div>
      </div>
      <span className="flex flex-none flex-col items-end gap-0.5 text-[12px]">
        <span className="text-dim">{claim.escalated_by}</span>
        {href && (
          <Link
            to={href}
            aria-label={`Open alert ${claim.alert_id} in Alerts`}
            className="text-accent hover:underline"
          >
            Open alert
          </Link>
        )}
        <button
          type="button"
          onClick={() => check.onCheck(claim)}
          disabled={check.running !== null}
          title={
            check.running !== null && !mine ? 'A check is running. Wait for its result.' : undefined
          }
          className="mt-0.5 flex items-center gap-1 rounded-control border border-border-strong px-2 py-0.5 text-[11.5px] font-semibold text-dim hover:text-text disabled:cursor-not-allowed disabled:opacity-60"
        >
          {mine && <Loader2 size={11} className="animate-spin" />}
          {mine ? 'Checking Security Onion' : 'Check Security Onion now'}
        </button>
      </span>
    </li>
  );
}

/** The count line. `total` is the server's count over the whole set and
 *  `claims.length` is what fitted, so the two disagreeing is itself the news:
 *  a panel that showed its rows and called that the total would under-report
 *  in exactly the way the panel exists to stop. */
function CountLine({ total, shown }: { total: number; shown: number }) {
  const cut = total > shown;
  return (
    <span
      className="inline-flex flex-none items-center gap-1 whitespace-nowrap rounded-chip border px-1.5 py-px text-[9.5px] font-semibold tracking-[.02em]"
      style={{
        color: AMBER,
        borderColor: tint(AMBER, 0.4),
        background: tint(AMBER, 0.09),
      }}
      title={
        cut
          ? `${total} claims are open. The panel lists the ${shown} oldest. Each open claim blocks a new escalation of its alert.`
          : 'Each open claim blocks a new escalation of its alert. A group escalation that covers the alert compares the claim with Security Onion.'
      }
    >
      {total} unsettled{cut ? ` · ${shown} oldest shown` : ''}
    </span>
  );
}

/** The last check and its one-sentence result. */
interface CheckOutcome {
  /** The rule of the claim. Null when the message names the alert itself. */
  label: string | null;
  message: string;
  tone: 'settled' | 'open' | 'error';
  /** The case the check found, and its page in Security Onion. */
  caseId?: string | null;
  caseUrl?: string | null;
}

/** The message with its case id as a link to the case page. */
function MessageWithCase({ outcome }: { outcome: CheckOutcome }) {
  const { message, caseId, caseUrl } = outcome;
  const at = caseId ? message.indexOf(caseId) : -1;
  if (!caseId || !caseUrl || at < 0) return <>{message}</>;
  return (
    <>
      {message.slice(0, at)}
      <a
        href={caseUrl}
        target="_blank"
        rel="noopener noreferrer"
        className="font-mono text-accent hover:underline"
      >
        {caseId}
      </a>
      {message.slice(at + caseId.length)}
    </>
  );
}

const OUTCOME_COLOR: Record<CheckOutcome['tone'], string> = {
  settled: 'text-text-2',
  open: 'text-warn',
  error: 'text-danger',
};

export function EscalationLedgerPanel() {
  const ledger = useAsync(getStrandedEscalations, [], {
    refetchInterval: 300_000,
  });
  const data = ledger.data;
  // One check at a time. Each check is a read of Security Onion, and two
  // presses on one claim must not race to settle it.
  const [running, setRunning] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<CheckOutcome | null>(null);
  const onCheck = (claim: StrandedClaim) => {
    if (running !== null) return;
    const label = claim.rule_name || `Alert ${claim.alert_id}`;
    setRunning(claim.alert_id);
    setOutcome(null);
    checkEscalationClaim(claim.alert_id)
      .then((r) => {
        // A found case reads "soc-ai found case X for alert Y. The claim is
        // settled." The sentence names the alert, and the case is a link.
        setOutcome({
          label: r.result === 'case_found' ? null : label,
          message: r.message,
          tone: r.settled ? 'settled' : 'open',
          caseId: r.case_id,
          caseUrl: r.case_url ?? null,
        });
        // A settled claim leaves the list. Read the ledger again to show it.
        if (r.settled) ledger.refetch();
      })
      .catch((e: unknown) =>
        setOutcome({
          label,
          message: e instanceof Error ? e.message : 'The check did not run. Try again.',
          tone: 'error',
        }),
      )
      .finally(() => setRunning(null));
  };
  return (
    <Panel className="md:col-span-2">
      <PanelHeader
        icon={<Link2Off size={16} />}
        title="Escalations awaiting an answer"
        right={
          <span className="flex items-center gap-2">
            {data && data.total > 0 && <CountLine total={data.total} shown={data.claims.length} />}
            <Freshness at={ledger.lastUpdated} />
          </span>
        }
      />
      {outcome && (
        <div
          data-testid="escalation-check-result"
          role="status"
          className={`border-b border-border px-[15px] py-2 text-[12px] ${OUTCOME_COLOR[outcome.tone]}`}
        >
          {outcome.label && <span className="font-semibold">{outcome.label}. </span>}
          <MessageWithCase outcome={outcome} />
        </div>
      )}
      {!data ? (
        ledger.error ? (
          // "Could not tell", not "nothing is stuck". An empty list and a
          // failed read render the same on a panel that treats both as no
          // rows, and here the difference is the whole point: this surface
          // exists because an absence was being read as an all-clear.
          <div className="px-[15px] py-3 text-[13px] text-dim">
            Could not read the escalation ledger.
          </div>
        ) : (
          <LoadingState label="Reading the escalation ledger" />
        )
      ) : data.claims.length === 0 ? (
        <EmptyState title="Nothing is waiting.">
          {/* Two sentences, and the second is the whole point: the panel is
              about claims that never came back, so "nothing here" has to say
              what it means rather than trail off into the settling window. */}
          All escalations have an answer.
        </EmptyState>
      ) : (
        <>
          <ul className="divide-y divide-border">
            {data.claims.map((claim) => (
              <ClaimRow key={claim.alert_id} claim={claim} check={{ running, onCheck }} />
            ))}
          </ul>
          {/* What the rows MEAN and what clears them. A list of alert ids with
              no sentence attached is a list an operator scrolls past; the
              actionable part is that each row is an alert that cannot be
              escalated, and that the fix is a press rather than a repair. */}
          <div className="border-t border-border px-[15px] py-2.5 text-[11.5px] leading-[1.55] text-faint">
            soc-ai claimed each of these alerts for an escalation. soc-ai does not know if
            Security Onion opened a case. soc-ai refuses a new escalation of each alert until
            Security Onion confirms the outcome. The next group escalation that covers an alert
            compares the claim with the case links in Security Onion. Select Check Security Onion
            now to compare one claim with Security Onion. The check also settles a claim whose
            alert has left the queue.
          </div>
        </>
      )}
    </Panel>
  );
}
