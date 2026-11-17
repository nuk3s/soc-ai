import { RotateCw, ShieldAlert } from 'lucide-react';
import { Link } from 'react-router-dom';
import { listInvestigations } from '../lib/api';
import { plural } from '../lib/plural';
import { absTime } from '../lib/timeRange';
import type { InvestigationRow } from '../lib/types';
import { useAsync } from '../lib/useAsync';
import { VerdictPill } from './Badges';
import { Panel, PanelHeader } from './Panel';
import { LoadingState } from './States';

// ---------------------------------------------------------------------------
// The investigations of one machine, on its host page.
//
// The host page of a domain controller with 7 investigations, 6 of them true
// positives, showed no investigation count, list or link. Its Alerts card
// read "0 nothing fired" for the last 7 days. A search for the host name
// found 1 of the 7 runs (dogfood 2026-10-19, R4-D3 and R4-I1). The server
// filter reads every address and name of the machine, all time, so the
// count here and the filtered list agree.
// ---------------------------------------------------------------------------

/** The runs the block lists. The list link holds the rest. */
export const HOST_INVESTIGATIONS_SHOWN = 3;

// The worst verdict first. The page of an attacked host with 42 true
// positives listed its three newest runs, three false positives (review
// 2026-11-12, ui-hunt 7).
const VERDICT_RANK: Record<string, number> = {
  true_positive: 0,
  needs_more_info: 1,
  inconclusive: 2,
  untriaged: 3,
  false_positive: 4,
};
const rankOf = (v: string): number => VERDICT_RANK[v] ?? 5;

/** The rows to show: the newest true positives first when the newest runs
 *  hold fewer of them than the block can show, then the newest of the rest,
 *  worst verdict first. The sort is stable, so newer runs stay above older
 *  ones of the same verdict. */
export function worstFirst(newest: InvestigationRow[], truePositives: InvestigationRow[] = []): InvestigationRow[] {
  const seen = new Set<string>();
  const merged: InvestigationRow[] = [];
  for (const r of [...truePositives.filter((r) => r.verdict === 'true_positive'), ...newest]) {
    if (seen.has(r.id)) continue;
    seen.add(r.id);
    merged.push(r);
  }
  return merged
    .map((r, i) => ({ r, i }))
    .sort((a, b) => rankOf(a.r.verdict) - rankOf(b.r.verdict) || a.i - b.i)
    .map(({ r }) => r)
    .slice(0, HOST_INVESTIGATIONS_SHOWN);
}

/** The Investigations list, filtered on the machine, over all time. */
export function investigationsHref(entityKey: string, label?: string | null): string {
  const p = new URLSearchParams();
  p.set('entity', entityKey);
  if (label?.trim()) p.set('entity_label', label.trim());
  p.set('range', 'all');
  return `/investigations?${p.toString()}`;
}

/** "7 investigations name this host. 6 reached a true-positive verdict." */
export function investigationsCountLine(total: number, truePositives: number): string {
  if (total === 0) return 'No investigation names this host.';
  const head = `${plural(total, 'investigation')} ${total === 1 ? 'names' : 'name'} this host.`;
  if (truePositives === 0) return `${head} None reached a true-positive verdict.`;
  return `${head} ${truePositives.toLocaleString()} reached a true-positive verdict.`;
}

/** The read behind the block, for the block and the hero line. Each answer
 *  carries the key it answers for: useAsync keeps the last answer while the
 *  next one loads. */
export function useHostInvestigations(entityKey: string) {
  return useAsync(
    async () => {
      if (!entityKey) return null;
      const list = await listInvestigations({ entity: entityKey, limit: HOST_INVESTIGATIONS_SHOWN });
      // A second read only when true positives exist that the newest runs
      // do not show. The count and the total stay those of the first read.
      const shownTp = list.rows.filter((r) => r.verdict === 'true_positive').length;
      const wantTp = Math.min(list.truePositives, HOST_INVESTIGATIONS_SHOWN);
      const tps =
        shownTp < wantTp
          ? (
              await listInvestigations({
                entity: entityKey,
                verdict: ['true_positive'],
                limit: HOST_INVESTIGATIONS_SHOWN,
              }).catch(() => null)
            )?.rows ?? []
          : [];
      return { key: entityKey, list: { ...list, rows: worstFirst(list.rows, tps) } };
    },
    [entityKey],
    { refetchInterval: 300_000 },
  );
}

export type HostInvestigationsRead = ReturnType<typeof useHostInvestigations>;

export function HostInvestigations({
  entityKey,
  label,
  read,
  className = 'mb-3',
}: {
  /** Any key of the machine: its machine key, an address or a name. */
  entityKey: string;
  /** The name of the machine, for the filter chip on the list. */
  label?: string | null;
  read: HostInvestigationsRead;
  className?: string;
}) {
  const data = read.data && read.data.key === entityKey ? read.data.list : null;
  return (
    <Panel className={className}>
      <PanelHeader
        icon={<ShieldAlert size={15} />}
        title={
          <span data-testid="host-investigations-title">
            {`Investigations on this host · all time${data ? ` · ${data.total.toLocaleString()}` : ''}`}
          </span>
        }
        right={
          data && data.total > 0 ? (
            <Link
              data-testid="host-investigations-all"
              to={investigationsHref(entityKey, label)}
              className="text-[11.5px] font-semibold text-accent hover:underline"
            >
              {data.total === 1 ? 'Open the investigation' : `Open the ${data.total.toLocaleString()} investigations`}
            </Link>
          ) : undefined
        }
      />
      {!data ? (
        read.error && !read.loading ? (
          <div
            data-testid="host-investigations-error"
            className="flex flex-wrap items-center gap-3 px-[15px] py-3 text-[12.5px] text-dim"
          >
            <span>This page could not read the investigations of this host.</span>
            <button
              type="button"
              onClick={read.refetch}
              className="flex items-center gap-1.5 rounded-control border border-border-strong px-2.5 py-1 text-[11.5px] font-semibold text-text-2 hover:border-accent"
            >
              <RotateCw size={11} /> Retry
            </button>
          </div>
        ) : (
          <LoadingState label="Reading the investigations" />
        )
      ) : (
        <>
          <div
            data-testid="host-investigations-count"
            className={`px-[15px] pt-3 text-[12.5px] ${data.truePositives > 0 ? 'text-danger' : 'text-text-2'} ${data.rows.length ? '' : 'pb-3'}`}
          >
            {investigationsCountLine(data.total, data.truePositives)}
          </div>
          {data.rows.length > 0 && (
            <ul className="flex flex-col gap-1.5 px-[15px] pb-3 pt-2">
              {data.rows.map((inv) => (
                <li key={inv.id}>
                  <Link
                    data-testid="host-investigation-row"
                    to={`/investigation/${encodeURIComponent(inv.id)}`}
                    className="flex items-center gap-3 rounded-card border border-border bg-surface-2 px-3 py-2 hover:border-accent"
                  >
                    <span className="min-w-0 flex-1 break-words text-[12.5px] text-text">
                      {inv.name || 'Investigation'}
                    </span>
                    <span className="flex-none font-mono text-[10.5px] text-faint">
                      {inv.ts ? absTime(inv.ts) : inv.when}
                    </span>
                    <VerdictPill verdict={inv.verdict} conf={inv.conf} />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </Panel>
  );
}
