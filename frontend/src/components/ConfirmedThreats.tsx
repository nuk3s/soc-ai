import { AlertTriangle, ArrowUpRight, RotateCw, ShieldAlert } from 'lucide-react';
import { Fragment, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  type AuthorizedThreatGroup,
  type ThreatCampaign,
  type ThreatImpact,
  type ThreatList,
  type ThreatQuery,
  type ThreatRow,
  type ThreatTarget,
  getThreats,
} from '../lib/api';
import { moreWords } from '../lib/campaignWords';
import { stageColor } from '../lib/campaignViz';
import { plural } from '../lib/plural';
import { timeLabel, utcStamp, utcWindow } from '../lib/timeRange';
import {
  CHIP_IMPACT,
  DEFINE_CONFIRMED_THREATS,
  THREAT_ACTIONS_WAIT,
  THREAT_AUTHORIZED,
  THREAT_CAMPAIGN_AUTHORIZED,
  THREAT_OPEN,
} from '../lib/tooltips';
import { useAsync } from '../lib/useAsync';
import { CampaignBeyondChip, CampaignDecisionChip, CampaignStatusChip, PartyLinks } from './campaign/shared';
import { StageMeter } from './campaign/StageMeter';
import { Panel, PanelHeader } from './Panel';
import { LoadingInline, StaleNotice } from './States';

// ---------------------------------------------------------------------------
// Confirmed threats: is anything bad happening, on which host, how bad, and
// what waits on the analyst.
//
// The review of 2026-11-12 (ui-core 3, ui-hunt 1 and 7) found the answer in
// three wrong places. The Dashboard said "True positives 3" in a tile and
// "True positive 0" in a card for the same window, and named no host. The Hunt
// Console put its one confirmed exploit chain 10,900 px down the page. The
// page of the attacked host listed three false positives first.
//
// One route answers all three surfaces, so the tile, the panel and the host
// strip state one count. The server merges the true positives by target host
// and orders the rows worst first. This file keeps that order.
//
// The campaign is the unit of work (owner, 2026-11-14). The server sends the
// campaigns of the window, worst stage first, and the rows then hold only the
// investigations in no campaign. The campaigns lead the panel.
// ---------------------------------------------------------------------------

/** The rows the panel shows before "Show N more hosts". The panel is the
 *  first block of two pages, and a long list would push the rest of the
 *  first screen down. The worst rows come first, so the cut hides the least. */
export const THREAT_ROWS_SHOWN = 5;

/** One answer, tagged with the window or the host it answers for. useAsync
 *  keeps the last answer while the next one loads, and a window change must
 *  not show the rows of the old window. */
export interface ThreatsAnswer {
  key: string;
  list: ThreatList;
}

/** The read behind a panel or a strip. `query` runs on every poll, so a
 *  preset window moves with the clock. A null query reads nothing. */
export function useThreats(key: string, query: () => ThreatQuery | null, refetchInterval = 60_000) {
  return useAsync<ThreatsAnswer | null>(
    () => {
      const q = query();
      return q ? getThreats(q).then((list) => ({ key, list })) : Promise.resolve(null);
    },
    [key],
    { refetchInterval },
  );
}

export type ThreatsRead = ReturnType<typeof useThreats>;

/** The answer for this key, or null while the read for the key runs. */
export function threatsFor(read: ThreatsRead, key: string): ThreatList | null {
  return read.data && read.data.key === key ? read.data.list : null;
}

/** A stored time may carry no offset. It is UTC, and `new Date` would read it
 *  in the browser zone. */
function asUtc(iso: string): string {
  return /T\d{2}:\d{2}/.test(iso) && !/(?:[zZ]|[+-]\d{2}:?\d{2})$/.test(iso) ? `${iso}Z` : iso;
}

/** The server writes in-app paths. Drop the mount prefix if one comes along,
 *  so the router does not add it twice. */
function appPath(href: string): string {
  return href.replace(/^\/app(?=\/)/, '');
}

/** "web01 (web server)" with the address beside it, or the address alone. */
export function threatTargetWords(t: ThreatTarget): { main: string; address: string | null } {
  const name = t.name?.trim();
  const role = t.role?.trim();
  if (name) return { main: role ? `${name} (${role})` : name, address: t.address };
  return { main: role ? `${t.address} (${role})` : t.address, address: null };
}

/** "mainsrv, 10.40.50.7 +2": each source by its name, or by its address. */
export function sourcesWords(sources: ThreatRow['sources'], more: number): string {
  const names = sources.map((s) => s.name?.trim() || s.address);
  if (!names.length) return more > 0 ? plural(more, 'source') : '';
  return `${names.join(', ')}${more > 0 ? ` +${more.toLocaleString()}` : ''}`;
}

/** "12 investigations: 9 alerts, 3 findings". */
export function runsWords(row: Pick<ThreatRow, 'runs' | 'alertRuns' | 'findingRuns'>): string {
  const parts: string[] = [];
  if (row.alertRuns > 0) parts.push(plural(row.alertRuns, 'alert'));
  if (row.findingRuns > 0) parts.push(plural(row.findingRuns, 'finding'));
  const head = plural(row.runs, 'investigation');
  return parts.length ? `${head}: ${parts.join(', ')}` : head;
}

/** The one link of a row: the actions that wait, or the investigations. */
export function primaryLink(row: ThreatRow): { to: string; label: string; title: string; waiting: boolean } {
  if (row.waitingActions > 0 && row.newestInvestigationId) {
    return {
      to: `/investigation/${encodeURIComponent(row.newestInvestigationId)}`,
      label: `${plural(row.waitingActions, 'action')} ${row.waitingActions === 1 ? 'waits' : 'wait'}`,
      title: THREAT_ACTIONS_WAIT,
      waiting: true,
    };
  }
  return { to: appPath(row.investigationsHref), label: 'Open', title: THREAT_OPEN, waiting: false };
}

/** "Authorized activity: Red team test. 4 investigations on web01. Expires 2026-11-20 09:00 UTC." */
export function authorizedLine(g: AuthorizedThreatGroup): string {
  const target = g.target.name?.trim() || g.target.address;
  const when = utcStamp(asUtc(g.authorization.expiresAt));
  const expiry = g.authorization.state === 'expired' ? `Expired ${when}.` : `Expires ${when}.`;
  return `Authorized activity: ${g.authorization.label}. ${plural(g.runs, 'investigation')} on ${target}. ${expiry}`;
}

/** The count of a campaign row: its alert events, or its true positive
 *  investigations when the campaign holds no stored events. */
export function campaignCountWords(c: Pick<ThreatCampaign, 'alerts' | 'investigations'>): string {
  return typeof c.alerts === 'number'
    ? plural(c.alerts, 'alert')
    : plural(c.investigations, 'true positive investigation');
}

/** The plain label over the rows that are in no campaign. */
export const OTHERS_LABEL = 'Not in a campaign';

// Only Succeeded and Attempted wear a color: the danger and the warning
// tokens. Unknown and none read neutral, so red keeps one meaning.
const IMPACT_CLASS: Record<ThreatImpact, string> = {
  succeeded: 'border-danger/40 bg-danger/10 text-danger',
  attempted: 'border-warn/40 bg-warn/10 text-warn',
  unknown: 'border-border-strong bg-surface-3 text-dim',
  none: 'border-border-strong bg-surface-3 text-dim',
};

export function ImpactChip({ impact }: { impact: ThreatImpact }) {
  // An impact off the union reads as its own word in the neutral chip.
  const meta = CHIP_IMPACT[impact] ?? { label: String(impact), title: '' };
  return (
    <span
      data-testid="impact-chip"
      data-impact={impact}
      title={meta.title || undefined}
      className={
        'inline-flex flex-none items-center whitespace-nowrap rounded-pill border px-[9px] py-[2.5px] ' +
        `text-[11.5px] font-semibold ${IMPACT_CLASS[impact] ?? IMPACT_CLASS.unknown}`
      }
    >
      {meta.label}
    </span>
  );
}

function ThreatRowLink({ row }: { row: ThreatRow }) {
  const target = threatTargetWords(row.target);
  const link = primaryLink(row);
  const sources = sourcesWords(row.sources, row.sourcesMore);
  const newest = timeLabel(asUtc(row.lastSeen));
  return (
    <Link
      data-testid="threat-row"
      to={link.to}
      title={link.title}
      className="flex flex-wrap items-center gap-x-3 gap-y-1.5 rounded-card border border-border bg-surface-2 px-3 py-2.5 hover:border-accent"
    >
      <span className="min-w-0 flex-[1_1_24rem]">
        <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <ImpactChip impact={row.impact} />
          <span data-testid="threat-target" className="break-words text-[13px] font-semibold text-text">
            {target.main}
          </span>
          {target.address && (
            <span className="font-mono text-[11.5px] text-dim">{target.address}</span>
          )}
        </span>
        {row.headline && (
          <span data-testid="threat-headline" className="mt-1 block break-words text-[12.5px] leading-[1.5] text-text-2">
            {row.headline}
          </span>
        )}
        <span data-testid="threat-meta" className="mt-1 block break-words text-[11.5px] text-faint">
          {sources && <>{row.direction === 'outbound' ? 'To' : 'From'} {sources} · </>}
          {runsWords(row)} · Newest event <span title={newest.title}>{newest.text}</span>
        </span>
      </span>
      <span
        data-testid="threat-primary"
        className={`flex flex-none items-center gap-1 text-[12px] font-semibold ${link.waiting ? 'text-warn' : 'text-accent'}`}
      >
        {link.label}
        <ArrowUpRight size={13} />
      </span>
    </Link>
  );
}

/**
 * One quiet line under a row that holds authorized runs: "9 of 22 runs are
 * authorized activity: <label>." Each label links to its runs. The row read
 * "22 runs: 9 alerts, 13 findings" and nothing said that 9 of them sit inside
 * an authorized activity record (polish review 2026-11-13). The line sits
 * outside the row link, so a link is never inside a link.
 */
function AuthorizedRunsLine({ row }: { row: ThreatRow }) {
  const count = row.authorizedRuns ?? 0;
  const records = row.authorizations ?? [];
  if (count <= 0 || records.length === 0) return null;
  return (
    <p data-testid="threat-authorized-runs" title={THREAT_AUTHORIZED} className="mt-1 px-3 text-[11.5px] text-faint">
      {count} of {plural(row.runs, 'investigation')} {count === 1 ? 'is' : 'are'} authorized activity:{' '}
      {records.map((record, i) => (
        <Fragment key={record.id}>
          {i > 0 && ', '}
          <Link to={appPath(record.runsHref)} className="text-text-2 underline hover:text-accent">
            {record.label}
          </Link>
        </Fragment>
      ))}
      .
    </p>
  );
}

/**
 * One campaign of the window: the stage meter, the title as the link to the
 * campaign, Open or Ended, its decision state, the actors and the targets,
 * the alerts, the period,
 * and the investigations that wait on a decision or that an authorization
 * holds. The machine names are links of their own, so the row is no link.
 */
export function ThreatCampaignRow({ c }: { c: ThreatCampaign }) {
  const more = moreWords(c.targetsMore);
  return (
    <div
      data-testid="threat-campaign"
      data-campaign={c.id}
      className="flex flex-wrap items-center gap-x-3 gap-y-1.5 rounded-card border border-l-[3px] border-border bg-surface-2 px-3 py-2.5"
      style={{ borderLeftColor: stageColor(c.stage) }}
    >
      <span className="min-w-0 flex-[1_1_24rem]">
        <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <StageMeter stage={c.stage} />
          <Link
            data-testid="threat-campaign-title"
            to={`/campaigns/${c.id}`}
            className="min-w-0 break-words text-[13px] font-semibold text-text hover:text-accent hover:underline"
          >
            {c.title}
          </Link>
          <CampaignStatusChip status={c.status} />
          <CampaignDecisionChip campaign={c} />
          <CampaignBeyondChip beyond={c.beyond} />
        </span>
        <span data-testid="threat-campaign-parties" className="mt-1 block break-words text-[12.5px] text-text-2">
          From <PartyLinks parties={c.actors} /> to <PartyLinks parties={c.targets} />
          {more && ` ${more}`}
        </span>
        <span data-testid="threat-campaign-meta" className="mt-1 block break-words text-[11.5px] text-faint">
          {campaignCountWords(c)} · {utcWindow(c.firstEvent, c.lastEvent)}
        </span>
      </span>
      {/* The campaign waits, and its investigations do not: the decision
          chip states it. The count of the investigations that wait can no
          longer show, because the server counts none for an investigation
          that a campaign holds. */}
      {c.authorized > 0 && (
        <span className="flex flex-none flex-col items-end gap-0.5 text-[12px]">
          <span data-testid="threat-campaign-authorized" title={THREAT_CAMPAIGN_AUTHORIZED} className="text-faint">
            {c.authorized.toLocaleString()} authorized
          </span>
        </span>
      )}
    </div>
  );
}

/** The line of a failed read. It must not read as "no threat". */
function ThreatsReadFailed({ onRetry, what }: { onRetry: () => void; what: string }) {
  return (
    <div
      data-testid="confirmed-threats-error"
      className="flex flex-wrap items-center gap-x-3 gap-y-1.5 px-[15px] py-3 text-[12.5px] text-warn"
    >
      <AlertTriangle size={14} className="flex-none" />
      <span>Could not read {what}. This is not an all-clear.</span>
      <button
        type="button"
        onClick={onRetry}
        className="flex items-center gap-1.5 rounded-control border border-border-strong px-2.5 py-1 text-[11.5px] font-semibold text-text-2 hover:border-accent"
      >
        <RotateCw size={11} /> Retry
      </button>
    </div>
  );
}

/**
 * The panel of the Dashboard and of the Hunt Console. `windowLabel` is the
 * window in words, "last 24 hours", and the panel title and the empty line
 * both state it.
 */
export function ConfirmedThreats({
  read,
  readKey,
  windowLabel,
  className = 'mb-4',
}: {
  read: ThreatsRead;
  readKey: string;
  windowLabel: string;
  className?: string;
}) {
  const list = threatsFor(read, readKey);
  const campaigns = list?.campaigns ?? [];
  const failed = !!read.error && !read.loading;
  const [showAll, setShowAll] = useState(false);
  return (
    <section data-testid="confirmed-threats" aria-label="Confirmed threats" className={className}>
      <Panel>
        <PanelHeader
          icon={<ShieldAlert size={15} />}
          title={
            <span data-testid="confirmed-threats-title" title={DEFINE_CONFIRMED_THREATS}>
              Confirmed threats · {windowLabel}
            </span>
          }
          right={
            list ? (
              <span data-testid="confirmed-threats-total" className="text-[11.5px] text-faint">
                {plural(list.total, 'true positive')}
              </span>
            ) : undefined
          }
        />
        {!list ? (
          failed ? (
            <ThreatsReadFailed onRetry={read.refetch} what="the confirmed threats" />
          ) : (
            <div className="px-[15px] py-3 text-[12.5px] text-dim">
              <LoadingInline>Reading the confirmed threats</LoadingInline>
            </div>
          )
        ) : (
          <>
            {/* The rows stay on screen when a later read fails, with the
                time they are from. */}
            {failed ? (
              <StaleNotice since={read.lastUpdated} onRefresh={read.refetch} reason="refresh-failed" retrying className="mx-[15px] mt-3" />
            ) : read.failCount >= 2 ? (
              <StaleNotice since={read.lastUpdated} onRefresh={read.refetch} className="mx-[15px] mt-3" />
            ) : null}
            {campaigns.length > 0 && (
              <ul data-testid="threat-campaigns" className={`flex flex-col gap-1.5 px-[15px] pt-3 ${list.rows.length ? 'pb-1' : 'pb-3'}`}>
                {campaigns.map((c) => (
                  <li key={c.id}>
                    <ThreatCampaignRow c={c} />
                  </li>
                ))}
              </ul>
            )}
            {campaigns.length > 0 && list.rows.length > 0 && (
              <div
                data-testid="threat-others-label"
                className="px-[15px] pt-2 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint"
              >
                {OTHERS_LABEL}
              </div>
            )}
            {list.rows.length === 0 ? (
              campaigns.length > 0 ? null : (
              <div data-testid="confirmed-threats-empty" className="px-[15px] py-3 text-[12.5px] text-dim">
                {list.authorized.length > 0
                  ? `No confirmed threat outside authorized activity in the ${windowLabel}.`
                  : `No confirmed threat in the ${windowLabel}.`}
              </div>
              )
            ) : (
              <ul className={`flex flex-col gap-1.5 px-[15px] ${campaigns.length ? 'pb-3 pt-1.5' : 'py-3'}`}>
                {(showAll ? list.rows : list.rows.slice(0, THREAT_ROWS_SHOWN)).map((row) => (
                  <li key={row.target.machineKey ?? row.target.address}>
                    <ThreatRowLink row={row} />
                    <AuthorizedRunsLine row={row} />
                  </li>
                ))}
                {list.rows.length > THREAT_ROWS_SHOWN && (
                  <li>
                    <button
                      type="button"
                      data-testid="confirmed-threats-more"
                      aria-expanded={showAll}
                      onClick={() => setShowAll((v) => !v)}
                      className="text-[12px] font-semibold text-accent hover:underline"
                    >
                      {showAll
                        ? 'Show fewer hosts'
                        : `Show ${plural(list.rows.length - THREAT_ROWS_SHOWN, 'more host', 'more hosts')}`}
                    </button>
                  </li>
                )}
              </ul>
            )}
            {list.authorized.length > 0 && (
              <ul className={`flex flex-col gap-1 px-[15px] pb-3 ${list.rows.length ? '' : '-mt-1'}`}>
                {list.authorized.map((g) => (
                  <li key={`${g.authorization.id}-${g.target.machineKey ?? g.target.address}`}>
                    <Link
                      data-testid="threat-authorized"
                      to={appPath(g.runsHref)}
                      title={THREAT_AUTHORIZED}
                      className="text-[12px] text-faint hover:text-text-2 hover:underline"
                    >
                      {authorizedLine(g)}
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </Panel>
    </section>
  );
}

/** The panel with its own read of the last `days` days, for a page with no
 *  window of its own to lend it. The Hunt Console uses 7 days. */
export function RecentConfirmedThreats({ days, className }: { days: number; className?: string }) {
  const key = `recent|${days}`;
  const read = useThreats(key, () => ({ since: new Date(Date.now() - days * 86_400_000).toISOString() }));
  return (
    <ConfirmedThreats
      read={read}
      readKey={key}
      windowLabel={`last ${days === 1 ? 'day' : `${days} days`}`}
      className={className}
    />
  );
}

/**
 * The strip under the header of a host page. It states the host's group and
 * its one next step. It shows nothing when the host has no confirmed threat,
 * and a failed read says so.
 */
export function HostThreatStrip({
  read,
  readKey,
  windowLabel = 'last 30 days',
  className = 'mb-3',
}: {
  read: ThreatsRead;
  readKey: string;
  windowLabel?: string;
  className?: string;
}) {
  const list = threatsFor(read, readKey);
  if (!list) {
    if (!readKey || !read.error || read.loading) return null;
    return (
      <div className={`rounded-card border border-border bg-surface-1 ${className}`}>
        <ThreatsReadFailed onRetry={read.refetch} what="the confirmed threats of this host" />
      </div>
    );
  }
  const worst = list.rows[0];
  if (!worst) return null;
  // A machine with two addresses can hold two rows. The sentence counts
  // them all, and the worst row gives the impact, the headline and the link.
  const sum = (pick: (r: ThreatRow) => number) => list.rows.reduce((n, r) => n + pick(r), 0);
  const runs = sum((r) => r.runs);
  const split = [
    ...(sum((r) => r.alertRuns) > 0 ? [plural(sum((r) => r.alertRuns), 'alert')] : []),
    ...(sum((r) => r.findingRuns) > 0 ? [plural(sum((r) => r.findingRuns), 'finding')] : []),
  ];
  const link = primaryLink(worst);
  const newest = timeLabel(asUtc(worst.lastSeen));
  return (
    <section
      data-testid="host-threats"
      aria-label="Confirmed threats on this host"
      className={`flex flex-wrap items-center gap-x-3 gap-y-1.5 rounded-card border border-border bg-surface-1 px-3.5 py-2.5 ${className}`}
    >
      <span className="min-w-0 flex-[1_1_24rem]">
        <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <ImpactChip impact={worst.impact} />
          <span data-testid="host-threats-count" className="text-[13px] font-semibold text-text" title={DEFINE_CONFIRMED_THREATS}>
            This host has {plural(runs, 'true positive investigation')}
            {list.campaigns?.length ? ' outside a campaign' : ''} in the {windowLabel}.
          </span>
        </span>
        {worst.headline && (
          <span className="mt-1 block break-words text-[12.5px] leading-[1.5] text-text-2">{worst.headline}</span>
        )}
        <span className="mt-1 block text-[11.5px] text-faint">
          {split.length > 0 && <>{split.join(', ')} · </>}
          Newest event <span title={newest.title}>{newest.text}</span>
        </span>
      </span>
      <Link
        data-testid="host-threats-primary"
        to={link.to}
        title={link.title}
        className={`flex flex-none items-center gap-1 text-[12px] font-semibold hover:underline ${link.waiting ? 'text-warn' : 'text-accent'}`}
      >
        {link.label}
        <ArrowUpRight size={13} />
      </Link>
    </section>
  );
}
