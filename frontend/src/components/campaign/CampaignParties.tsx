import type { CampaignParty } from '../../lib/api';
import { BEYOND_MARK, coverageSentence, joinLabel, roleLabel } from '../../lib/campaignWords';
import { utcStamp } from '../../lib/timeRange';
import { UNKNOWN, UNKNOWN_TONE } from '../Kpi';
import { Panel, PanelHeader } from '../Panel';
import { PartyLink } from './shared';

const TH = 'px-2.5 py-2 text-left font-semibold';

/** The actors and the targets, actors first, each with its addresses, the
 *  record that ties the addresses to the machine, and what soc-ai can read on
 *  it. A machine with no agent states that soc-ai cannot read processes or
 *  files on it. `embedded` drops the panel and the title: a fold of the page
 *  holds them. */
export function CampaignParties({ parties, embedded = false }: { parties: CampaignParty[]; embedded?: boolean }) {
  if (parties.length === 0) return null;
  const ordered = [
    ...parties.filter((p) => p.role === 'actor'),
    ...parties.filter((p) => p.role !== 'actor'),
  ];
  const body = (
    <div className="overflow-x-auto">
      <table data-testid="campaign-parties" className="w-full text-[12.5px]">
        <thead className="border-b border-border bg-surface-2 text-[10.5px] uppercase tracking-[.06em] text-faint">
          <tr>
            <th scope="col" className="px-[15px] py-2 text-left font-semibold">
              Name
            </th>
            <th scope="col" className={TH}>
              Role
            </th>
            <th scope="col" className={TH}>
              Addresses
            </th>
            <th scope="col" className={TH}>
              Address source
            </th>
            <th scope="col" className={TH}>
              Coverage
            </th>
            <th scope="col" className={TH}>
              First event
            </th>
            <th scope="col" className={TH}>
              Last event
            </th>
            <th scope="col" className="px-[15px] py-2 text-right font-semibold">
              Investigations
            </th>
          </tr>
        </thead>
        <tbody>
          {ordered.map((p) => (
            <PartyRow key={p.machineKey} p={p} />
          ))}
        </tbody>
      </table>
    </div>
  );
  if (embedded) return body;
  return (
    <Panel>
      <PanelHeader title="Machines" />
      {body}
    </Panel>
  );
}

function PartyRow({ p }: { p: CampaignParty }) {
  const time = (iso: string | null) =>
    iso ? utcStamp(iso) : <span className={UNKNOWN_TONE}>{UNKNOWN}</span>;
  return (
    <tr
      data-testid={`party-${p.machineKey}`}
      className="border-b border-border-faint align-top last:border-b-0"
    >
      <td className="px-[15px] py-2.5">
        <PartyLink party={p} className="font-semibold" />
        {p.role === 'target' && p.beyond && (
          <span
            data-testid="party-beyond"
            className="ml-2 inline-flex whitespace-nowrap rounded-chip border border-warn/40 bg-warn/10 px-1.5 py-px text-[10.5px] text-warn"
          >
            {BEYOND_MARK}
          </span>
        )}
      </td>
      <td className="px-2.5 py-2.5 text-text-2">{roleLabel(p.role)}</td>
      <td className="px-2.5 py-2.5 font-mono text-[11.5px] text-text-2">
        {p.addresses.length > 0 ? (
          p.addresses.map((a) => (
            // An IPv4 address stays on one line. Only an IPv6 address is long
            // enough to need a break.
            <div key={a} className={a.includes(':') ? 'break-all' : 'whitespace-nowrap'}>
              {a}
            </div>
          ))
        ) : (
          <span className={UNKNOWN_TONE}>{UNKNOWN}</span>
        )}
      </td>
      <td className="px-2.5 py-2.5 text-text-2">
        {p.join ? joinLabel(p.join) : <span className={UNKNOWN_TONE}>{UNKNOWN}</span>}
      </td>
      <td data-testid="party-coverage" className="min-w-[14rem] px-2.5 py-2.5 text-text-2">
        {coverageSentence(p)}
      </td>
      <td className="px-2.5 py-2.5 font-mono text-[11.5px] text-text-2">{time(p.firstEvent)}</td>
      <td className="px-2.5 py-2.5 font-mono text-[11.5px] text-text-2">{time(p.lastEvent)}</td>
      <td className="px-[15px] py-2.5 text-right font-mono">{p.memberRuns.toLocaleString()}</td>
    </tr>
  );
}
