import { Link2Off } from 'lucide-react';

import { getStrandedEscalations, type StrandedClaim } from '../lib/api';
import { absTime, ago } from '../lib/timeRange';
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
// catalog beside it. Nothing here writes: a "release" button would drop a
// claim on somebody's opinion rather than on evidence, and a request can fail
// after Security Onion has already created the case.
// ---------------------------------------------------------------------------

// Amber, the same "true story, but not the one you think" tone the catalog's
// blind and undecided markers wear. A stranded claim is not a failure of the
// alert or of the analyst; it is a fact about the ledger that reads as nothing
// at all until something says it.
const AMBER = '#f5a623';

function ClaimRow({ claim }: { claim: StrandedClaim }) {
  return (
    <li className="flex items-center gap-2.5 px-[15px] py-2.5 text-[13px]">
      <span
        className="min-w-0 flex-1 truncate font-mono text-[11.5px] text-text-2"
        title={claim.alert_id}
      >
        {claim.alert_id}
      </span>
      <span className="flex-none text-[12px] text-dim">{claim.escalated_by}</span>
      {/* The age, not the timestamp: "claimed 4m ago" is a request that may
          still be in flight and "claimed 6d ago" is an alert nobody can
          escalate, and those need different reactions from the same row. */}
      <span className="flex-none text-[12px] text-dim" title={absTime(claim.claimed_at)}>
        claimed {ago(claim.claimed_at)}
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
          ? `${total} claims are open. The panel lists the ${shown} oldest. Each one holds its alert against every future escalate.`
          : 'Each open claim holds its alert against every future escalate. A group press that covers the alert reconciles it against Security Onion.'
      }
    >
      {total} unsettled{cut ? ` · ${shown} oldest shown` : ''}
    </span>
  );
}

export function EscalationLedgerPanel() {
  const ledger = useAsync(getStrandedEscalations, [], {
    refetchInterval: 300_000,
  });
  const data = ledger.data;
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
      {!data ? (
        ledger.error ? (
          // "Could not tell", not "nothing is stuck". An empty list and a
          // failed read render the same on a panel that treats both as no
          // rows, and here the difference is the whole point: this surface
          // exists because an absence was being read as an all-clear.
          <div className="px-[15px] py-3 text-[13px] text-dim">
            Couldn't read the escalation ledger.
          </div>
        ) : (
          <LoadingState label="Reading the escalation ledger…" />
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
              <ClaimRow key={claim.alert_id} claim={claim} />
            ))}
          </ul>
          {/* What the rows MEAN and what clears them. A list of alert ids with
              no sentence attached is a list an operator scrolls past; the
              actionable part is that each row is an alert that cannot be
              escalated, and that the fix is a press rather than a repair. */}
          <div className="border-t border-border px-[15px] py-2.5 text-[11.5px] leading-[1.55] text-faint">
            soc-ai claimed each of these alerts. It never learned whether Security Onion opened a
            case. Each alert is refused by every escalate until it settles. The next group escalate
            that covers the alert reconciles it against Security Onion's own case links. A claim
            whose alert has left the queue will not settle on its own.
          </div>
        </>
      )}
    </Panel>
  );
}
