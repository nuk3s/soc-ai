import type { CampaignPairEvents, CampaignParty, CampaignRuleEvents } from '../../lib/api';
import { NOT_JUDGED } from '../../lib/campaignWords';
import { plural } from '../../lib/plural';
import { utcStamp } from '../../lib/timeRange';
import { VerdictPill } from '../Badges';
import { selectionHoldsPair, type CampaignSelection } from './selection';
import { PartyLink } from './shared';

const TH = 'px-2.5 py-2 text-left font-semibold';

/** One row of the Alerts table: one rule between two machines. */
export interface AlertRow {
  key: string;
  pair: CampaignPairEvents;
  rule: CampaignRuleEvents;
}

/** The rules of each pair, the confirmed rules first, then the most alerts. */
export function alertRows(pairs: readonly CampaignPairEvents[]): AlertRow[] {
  const rows: AlertRow[] = [];
  for (const pair of pairs) {
    for (const rule of pair.rules ?? []) {
      rows.push({ key: `${pair.source}|${pair.target}|${rule.name}`, pair, rule });
    }
  }
  const confirmed = (r: AlertRow) => (r.rule.verdict === 'true_positive' ? 0 : 1);
  return rows.sort(
    (a, b) =>
      confirmed(a) - confirmed(b) ||
      b.rule.alerts - a.rule.alerts ||
      a.rule.name.localeCompare(b.rule.name) ||
      a.key.localeCompare(b.key),
  );
}

/** The distinct rule names over all pairs: the count of the Alerts fold. */
export function distinctRules(pairs: readonly CampaignPairEvents[]): number {
  return new Set(pairs.flatMap((p) => (p.rules ?? []).map((r) => r.name))).size;
}

/** The alert events between the machines of the campaign, one row for each
 *  rule of each pair: the rules that soc-ai confirmed, then the rules that it
 *  judged otherwise or did not judge. The verdict cell states which.
 *
 *  A machine or an arrow picked on the attack graph shows only its rows,
 *  under a line that names it and a button that clears it. A mark of the
 *  timeline filters the Investigations table, and this table shows all rows. */
export function CampaignAlerts({
  pairs,
  parties,
  selection = null,
  onClearSelection,
}: {
  pairs: CampaignPairEvents[];
  parties: CampaignParty[];
  selection?: CampaignSelection | null;
  onClearSelection?: () => void;
}) {
  const rows = alertRows(pairs);
  if (rows.length === 0) return null;
  const filter = selection && selection.kind !== 'runs' ? selection : null;
  const shown = filter ? rows.filter((r) => selectionHoldsPair(filter, r.pair)) : rows;
  const sum = (list: AlertRow[]) => list.reduce((n, r) => n + r.rule.alerts, 0);
  const partyOf = new Map(parties.map((p) => [p.machineKey, p]));

  const machine = (key: string) => {
    const p = partyOf.get(key);
    return p ? <PartyLink party={p} /> : <span className="break-words font-mono text-[11.5px]">{key}</span>;
  };

  return (
    <>
      {filter && (
        <div
          data-testid="alerts-selection"
          className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-border-faint bg-accent/5 px-[15px] py-2 text-[12.5px] text-text-2"
        >
          <span className="break-words">
            {`Showing ${sum(shown).toLocaleString()} of ${plural(sum(rows), 'alert')}: ${filter.label}.`}
          </span>
          {onClearSelection && (
            <button
              type="button"
              onClick={onClearSelection}
              className="rounded-control border border-border-strong bg-surface-2 px-2 py-0.5 text-[11.5px] text-text-2 hover:border-accent"
            >
              Show all alerts
            </button>
          )}
        </div>
      )}
      <div className="overflow-x-auto">
        <table data-testid="campaign-alerts" className="w-full text-[12.5px]">
          <thead className="border-b border-border bg-surface-2 text-[10.5px] uppercase tracking-[.06em] text-faint">
            <tr>
              <th scope="col" className="px-[15px] py-2 text-left font-semibold">
                Rule
              </th>
              <th scope="col" className="px-2.5 py-2 text-right font-semibold">
                Alerts
              </th>
              <th scope="col" className={TH}>
                From
              </th>
              <th scope="col" className={TH}>
                To
              </th>
              <th scope="col" className={TH}>
                First
              </th>
              <th scope="col" className={TH}>
                Last
              </th>
              <th scope="col" className="px-[15px] py-2 text-left font-semibold">
                soc-ai verdict
              </th>
            </tr>
          </thead>
          <tbody>
            {shown.map((r) => (
              <tr
                key={r.key}
                data-testid="alert-row"
                data-rule={r.rule.name}
                data-verdict={r.rule.verdict}
                className="border-b border-border-faint align-top last:border-b-0"
              >
                <td className="min-w-[14rem] break-words px-[15px] py-2.5 text-text">{r.rule.name}</td>
                <td className="px-2.5 py-2.5 text-right font-mono tabular-nums text-text-2">
                  {r.rule.alerts.toLocaleString()}
                </td>
                <td className="px-2.5 py-2.5">{machine(r.pair.source)}</td>
                <td className="px-2.5 py-2.5">{machine(r.pair.target)}</td>
                <td className="whitespace-nowrap px-2.5 py-2.5 font-mono text-[11.5px] text-text-2">
                  {utcStamp(r.rule.firstAt)}
                </td>
                <td className="whitespace-nowrap px-2.5 py-2.5 font-mono text-[11.5px] text-text-2">
                  {utcStamp(r.rule.lastAt)}
                </td>
                <td data-testid="alert-verdict" className="px-[15px] py-2.5">
                  <RuleVerdict verdict={r.rule.verdict} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

/** The verdict of a rule: the pill of the three verdicts, or the dim words of
 *  a rule that no investigation judged. */
function RuleVerdict({ verdict }: { verdict: CampaignRuleEvents['verdict'] }) {
  if (verdict === 'true_positive' || verdict === 'false_positive' || verdict === 'needs_more_info') {
    return <VerdictPill verdict={verdict} showConf={false} />;
  }
  return <span className="text-dim">{NOT_JUDGED}</span>;
}

