import { ChevronLeft, Crosshair, Globe, Server, ShieldAlert, User } from 'lucide-react';
import { Link, Navigate, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { SeverityTag, VerdictPill } from '../components/Badges';
import { HostObservations } from '../components/HostObservations';
import { LeadsStrip } from '../components/LeadsStrip';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { getEntity, isNotFound, resolveMachine } from '../lib/api';
import {
  ENTITY_TYPE_LABEL,
  entityType,
  identityLine,
  machineKeysLine,
  machineKeysShown,
  nothingKnown,
  nothingKnownLine,
  worryLines,
} from '../lib/entityIdentity';
import { relativeAge } from '../lib/hostDossier';
import { machineHref } from '../lib/hostsList';
import { isIpKey } from '../lib/ip';
import { plural } from '../lib/plural';
import { absTime } from '../lib/timeRange';
import { ENTITY_ADDRESS, ENTITY_NAME } from '../lib/tooltips';
import type { EntityDetail, EntityTimelineItem, EntityType, Severity, Verdict } from '../lib/types';
import { useAsync } from '../lib/useAsync';

// The narrow frontend severity union the pill understands; a hunt finding can
// carry "info" (or an odd value) — coerce so the chip never sees an off-union sev.
// An unrecognized or absent severity lands on 'unknown', not 'low': the SPA-side
// twin of the backend's _sev, and for the same reason. Calling something Low is
// a claim about it; this is the absence of one.
// 'info' is on the list because a hunt finding that says "info" told us
// something; relabelling it would be the same invention one rung down.
const FE_SEV: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
function feSev(sev?: string | null): Severity {
  const v = (sev ?? '').toLowerCase() as Severity;
  return FE_SEV.includes(v) ? v : 'unknown';
}

/** One card in the entity timeline — an investigation or a hunt finding — a link
 *  to its source run, with the verdict / severity chip for its kind. */
function TimelineCard({ item }: { item: EntityTimelineItem }) {
  const isInv = item.kind === 'investigation';
  return (
    <Link
      to={item.link.replace(/^\/app/, '')}
      className="group flex items-start gap-3 rounded-card border border-border bg-surface-2 px-3.5 py-3 transition-colors hover:border-accent"
    >
      <span
        className="mt-0.5 flex-none"
        style={{ color: isInv ? '#4b8bf5' : '#f0883e' }}
        title={isInv ? 'Investigation' : 'Hunt finding'}
      >
        {isInv ? <ShieldAlert size={15} /> : <Crosshair size={15} />}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="rounded-chip border border-border-input bg-surface-3 px-1.5 py-px font-mono text-[9.5px] font-semibold uppercase tracking-[.04em] text-dim">
            {isInv ? 'Investigation' : 'Hunt finding'}
          </span>
          <span className="font-mono text-[10.5px] text-faint">{absTime(item.ts)}</span>
        </div>
        <div className="mt-1 break-words text-[13px] font-medium text-text group-hover:text-white">
          {item.title || (isInv ? 'Investigation' : 'Hunt finding')}
        </div>
      </div>
      <div className="flex-none self-center">
        {isInv ? (
          <VerdictPill verdict={(item.verdict ?? 'untriaged') as Verdict} conf={item.confidence} />
        ) : (
          <SeverityTag sev={feSev(item.severity)} />
        )}
      </div>
    </Link>
  );
}

/** The icon of each type. A user page wore the server icon of a host
 *  (dogfood 2026-10-19, R4-D23). */
function TypeIcon({ type }: { type: EntityType }) {
  const chrome = type === 'user' ? 'user' : type === 'domain' || type === 'external_address' ? 'globe' : 'host';
  return (
    <span data-testid="entity-icon" data-type={chrome} className="text-dim">
      {chrome === 'user' ? <User size={18} /> : chrome === 'globe' ? <Globe size={18} /> : <Server size={18} />}
    </span>
  );
}

/** The machine read: a key, "no machine", or a read that failed. Each answer
 *  carries the value it answers for, because useAsync keeps the last answer
 *  while the next one loads. */
interface MachineRead {
  value: string;
  key: string | null;
  primaryIp: string | null;
}

/**
 * Entity page: "who is this, and should I worry" for one address, host name,
 * user or domain (dogfood 2026-10-06, S1, S2, S5).
 *
 * Every entity link in the console opens this route. A value a machine holds
 * moves on to the machine page: that page is the answer for a machine. An
 * address no machine holds, an external address, a user and a domain stay
 * here. `?view=entity` keeps a machine's value on this page, for its timeline.
 * `?type=user` or `?type=domain` says what the value is, so an account that
 * shares a name with a machine never opens the machine.
 */

export function Entity() {
  const { value = '' } = useParams();
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const hint = params.get('type');
  const stay = params.get('view') === 'entity';
  const notMachine = hint === 'user' || hint === 'domain';
  const trimmed = value.trim();

  // The machine this name or address belongs to. A value that names no
  // machine is a 404. A failed read keeps the entity page.
  const machineRead = useAsync<MachineRead>(
    () =>
      notMachine || !trimmed
        ? Promise.resolve({ value, key: null, primaryIp: null })
        : resolveMachine(trimmed).then(
            (r) => ({ value, key: r.key, primaryIp: r.primary_ip }),
            (err: unknown) => {
              if (isNotFound(err)) return { value, key: null, primaryIp: null };
              throw err;
            },
          ),
    [value, notMachine],
  );
  const machine = machineRead.data?.value === value ? machineRead.data : null;
  const machineSettled = !!machine || (!!machineRead.error && !machineRead.loading);
  const { data, loading, error, refetch } = useAsync(
    () => getEntity(value, notMachine ? hint : null),
    [value, hint],
  );

  // A machine holds the value: its page is the answer.
  if (machine?.key && !stay) {
    const address = isIpKey(trimmed) ? `?address=${encodeURIComponent(trimmed)}` : '';
    return <Navigate to={`${machineHref(machine.key)}${address}`} replace />;
  }

  const hostLink = machine?.key ? { to: machineHref(machine.key), ip: machine.primaryIp ?? '' } : null;

  return (
    <div className="px-[22px] pb-[60px] pt-[18px] font-sans text-text">
      <div className="mb-3.5 flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={() => navigate(-1)}
          className="flex items-center gap-1.5 text-[12.5px] text-dim hover:text-text"
        >
          <ChevronLeft size={13} /> Back
        </button>
        <span className="text-ghost">/</span>
        {/* The crumb names the entity. "Alerts / Entity" named the screen. */}
        <div data-testid="entity-crumb" className="font-mono text-[15px] font-semibold">
          {value}
        </div>
      </div>

      <div className="mx-auto max-w-workstation">
        {!machineSettled || (loading && !data) ? (
          <LoadingState label="Loading entity" />
        ) : error ? (
          <ErrorState error={error} onRetry={refetch} label="this entity" />
        ) : !data ? (
          <ErrorState error={new Error('Entity not found')} />
        ) : (
          <EntityBody data={data} hostLink={hostLink} />
        )}
      </div>
    </div>
  );
}

function EntityBody({
  data,
  hostLink,
}: {
  data: EntityDetail;
  hostLink: { to: string; ip: string } | null;
}) {
  const type = entityType(data);
  const empty = nothingKnown(data);
  const worry = worryLines(data);
  const keys = machineKeysShown(data);
  const s = data.summary;
  return (
    <>
      {/* Header: the value, what it is, and the answer to "should I worry". */}
      <div
        data-testid="entity-header"
        className="mb-4 rounded-panel-lg border border-border bg-surface-2 px-5 py-4"
      >
        <div className="flex flex-wrap items-center gap-3">
          <TypeIcon type={type} />
          <span className="font-mono text-[17px] font-semibold text-white">{data.value}</span>
          <span
            data-testid="entity-type"
            title={type === 'address' || type === 'external_address' ? ENTITY_ADDRESS : ENTITY_NAME}
            className="rounded-chip border border-border-input bg-surface-3 px-1.5 py-0.5 font-mono text-[9.5px] font-semibold uppercase tracking-[.04em] text-dim"
          >
            {ENTITY_TYPE_LABEL[type]}
          </span>
          {hostLink && (
            <Link
              data-testid="entity-host-link"
              to={hostLink.to}
              title="This entity belongs to a machine. The machine page holds its addresses, profile, observations and leads."
              className="rounded-chip border border-accent/40 bg-accent/10 px-2 py-0.5 text-[11.5px] font-semibold text-accent hover:bg-accent/20"
            >
              machine {hostLink.ip} →
            </Link>
          )}
        </div>
        <p data-testid="entity-identity" className="mt-2.5 text-[14px] leading-[1.6] text-text-2">
          {identityLine(data)}
        </p>
        {empty ? (
          <p data-testid="entity-nothing-known" className="mt-1 text-[13px] leading-[1.6] text-dim">
            {nothingKnownLine(data.value)}
          </p>
        ) : (
          <ul data-testid="entity-worry" className="mt-1 text-[13px] leading-[1.6] text-text-2">
            {worry.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        )}
        <div
          data-testid="entity-seen"
          className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[11px] text-faint"
        >
          {/* The source of each time is named: soc-ai records here, grid
              events on the host page. Both said "last seen" (dogfood round 2,
              V2-7). */}
          {data.first_seen || data.last_seen ? (
            <>
              <span title={data.first_seen ? absTime(data.first_seen) : undefined}>
                first soc-ai record {data.first_seen ? relativeAge(data.first_seen) : 'never'}
              </span>
              <span title={data.last_seen ? absTime(data.last_seen) : undefined}>
                last soc-ai record {data.last_seen ? relativeAge(data.last_seen) : 'never'}
              </span>
            </>
          ) : (
            <span>no soc-ai record</span>
          )}
          <span>{plural(s.investigationCount, 'investigation')}</span>
          <span>{plural(s.huntFindingCount, 'hunt finding')}</span>
          <span>{plural(s.leadCount ?? 0, 'lead')}</span>
          <span title="Observations in the last 30 days, from every source.">
            {plural(s.observationCount ?? 0, 'observation')}
          </span>
          {s.latestVerdict && (
            <span className="flex items-center gap-1.5 font-sans">
              latest verdict
              <VerdictPill verdict={s.latestVerdict as Verdict} showConf={false} />
            </span>
          )}
        </div>
        {/* The counts read every key of the machine. The address and the
            name of one machine gave two sets of counts (dogfood
            2026-10-19, R4-D2). */}
        {keys.length > 0 && (
          <p data-testid="entity-keys" className="mt-1 break-words text-[11.5px] leading-[1.5] text-faint">
            {machineKeysLine(keys)}
          </p>
        )}
      </div>

      {/* The leads and the observations that name the entity come first:
          they are the open work. The timeline is the history. */}
      <div data-testid="entity-hunting">
        <LeadsStrip entityKey={data.value} status="all" noun="entity" className="mb-4" />
        <HostObservations entityKey={data.value} noun="entity" />
      </div>

      <div className="mt-4">
        {data.timeline.length === 0 ? (
          <EmptyState>
            No investigation or hunt finding names{' '}
            <span className="font-mono text-dim">{data.value}</span>.
            {hostLink && (
              <>
                {' '}
                <Link to={hostLink.to} className="text-accent hover:underline">
                  Open the machine page for {hostLink.ip}.
                </Link>
              </>
            )}
          </EmptyState>
        ) : (
          <div className="flex flex-col gap-2">
            {data.timeline.map((item, i) => (
              <TimelineCard key={`${item.kind}-${item.link}-${i}`} item={item} />
            ))}
          </div>
        )}
      </div>
    </>
  );
}
