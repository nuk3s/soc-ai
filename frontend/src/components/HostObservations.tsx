import { Link } from 'react-router-dom';

import { getObservations, type EntityObservation } from '../lib/api';
import { kindLabel, sourceLabel, sourceTitle } from '../lib/kinds';
import { plural } from '../lib/plural';
import { absTime, ago } from '../lib/timeRange';
import {
  CHIP_IN_LEAD,
  CHIP_NO_LEAD,
  CHIP_SEEN,
  CHIP_TYPE,
  COUNT_OBSERVATIONS,
  UNREAD_DOT,
} from '../lib/tooltips';
import { useAsync } from '../lib/useAsync';
import { Panel, PanelHeader } from './Panel';
import { LoadingState } from './States';

// ---------------------------------------------------------------------------
// Observations on one host, from every source.
//
// The profile layer, the catalog, the alert layer and hunt findings each wrote
// to their own table before the spine. One host then had three partial stories
// and no list. One table holds all observations now, and this panel is where a
// repeated single signal is visible before it forms a lead.
// ---------------------------------------------------------------------------

const DAYS = 7;

const WEIGHT_TITLE =
  'The weight of this observation now. Observations decay with a 48 h half-life, so an old one is worth less than its birth weight.';

function Row({ observation }: { observation: EntityObservation }) {
  return (
    <li
      data-testid={`observation-${observation.id}`}
      className="flex flex-wrap items-center gap-x-2.5 gap-y-1 px-[15px] py-2.5 text-[12.5px]"
    >
      <span
        className="font-mono text-[11px] text-dim"
        title={observation.born_at ? absTime(observation.born_at) : undefined}
      >
        {ago(observation.born_at)}
      </span>
      {/* One chip, one word. A shadow row read "shadow" beside "candidate",
          and "candidate" is a status that writes nothing. */}
      <span
        className={
          observation.shadow
            ? 'rounded-chip border px-1.5 py-px text-[10.5px]'
            : 'rounded-chip border border-border-faint px-1 py-px text-[10px] text-faint'
        }
        style={
          observation.shadow
            ? { color: '#d29922', borderColor: 'rgba(210,153,34,.35)' }
            : undefined
        }
        title={sourceTitle(observation.source, observation.shadow)}
      >
        {sourceLabel(observation.source, observation.shadow)}
      </span>
      <span
        className="rounded-chip border border-border-strong bg-surface-2 px-1.5 py-px text-[10.5px] text-text-2"
        title={CHIP_TYPE}
      >
        {kindLabel(observation.kind, observation.kind_label)}
      </span>
      <span className="min-w-0 flex-1 text-text-2">{observation.summary ?? ''}</span>
      {observation.occurrences > 1 && (
        <span className="text-[11px] text-dim" title={CHIP_SEEN}>
          seen {plural(observation.occurrences, 'time')}
        </span>
      )}
      <span className="font-mono text-[11px] text-dim" title={WEIGHT_TITLE}>
        weight {observation.weight_now.toFixed(2)}
      </span>
      {observation.shadow && !observation.read && (
        <span className="text-[11px]" style={{ color: '#d29922' }} title={UNREAD_DOT}>
          shadow hit · unread
        </span>
      )}
      {observation.lead_id !== null ? (
        <Link
          to={`/leads/${observation.lead_id}`}
          title={CHIP_IN_LEAD}
          className="text-[11.5px] text-accent hover:underline"
        >
          in lead {observation.lead_id}
        </Link>
      ) : (
        <span className="text-[11.5px] text-faint" title={CHIP_NO_LEAD}>
          not yet in a lead
        </span>
      )}
    </li>
  );
}

export function HostObservations({
  entityKey,
  noun = 'host',
}: {
  entityKey: string;
  /** The word for the thing the panel is mounted on. A user account is not a
   *  host, and the heading said host on both. */
  noun?: string;
}) {
  const data = useAsync(() => getObservations(entityKey, DAYS), [entityKey], {
    refetchInterval: 300_000,
  });
  const rows = data.data?.observations ?? [];
  return (
    <Panel className="mt-4" >
      <PanelHeader
        title={
          <span title={COUNT_OBSERVATIONS}>
            {`Observations on this ${noun} · last ${DAYS} days · ${rows.length}`}
          </span>
        }
        right={
          <span className="text-[11px] text-dim" title={WEIGHT_TITLE}>
            all sources · live weight decays with a 48 h half-life
          </span>
        }
      />
      {!data.data ? (
        data.error ? (
          <div className="px-[15px] py-3 text-[12.5px] text-dim">
            Could not read the observations.
          </div>
        ) : (
          <LoadingState label="Reading the observations…" />
        )
      ) : rows.length === 0 ? (
        <div className="px-[15px] py-3 text-[12.5px] text-dim">
          No observations on this {noun} in the last {DAYS} days. Operate shows the analytics
          that could not score it.
        </div>
      ) : (
        <ul className="divide-y divide-border-faint">
          {rows.map((observation) => (
            <Row key={observation.id} observation={observation} />
          ))}
        </ul>
      )}
    </Panel>
  );
}
