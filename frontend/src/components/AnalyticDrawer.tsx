import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

import {
  getAnalytic,
  setAnalyticStatus,
  startHuntConsole,
  type AnalyticDetail,
  type AnalyticRow,
} from '../lib/api';
import { entityPath } from '../lib/entityPath';
import { plural } from '../lib/plural';
import { absTime, ago } from '../lib/timeRange';
import {
  CHIP_CANDIDATE,
  CHIP_IN_LEAD,
  CHIP_LIVE,
  CHIP_LOCAL,
  CHIP_NO_BENIGN_BASELINE,
  CHIP_RETIRED,
  CHIP_SEEN,
  CHIP_SHADOW,
  CHIP_SHIPPED,
  CHIP_VERSION,
  LEDGER_DISMISSED,
  LEDGER_HUNTED_PROMOTED,
  LEDGER_LEADS,
  LEDGER_OBSERVATIONS,
  LEDGER_VERSION,
} from '../lib/tooltips';
import { useAsync } from '../lib/useAsync';
import { Definition } from './Definition';
import { Drawer } from './Drawer';

// ---------------------------------------------------------------------------
// One analytic, its history and what it earned.
//
// An analytic earns its place if it feeds confirmed leads at a cost the grid
// can afford. The ledger is the evidence for that judgement, so the drawer
// puts it beside the version history: a retirement is taken here, and it is
// taken on both.
//
// The ledger is computed on read and never stored. A stored figure is correct
// on the night the job ran and wrong every night the job is missed, and a
// retirement taken on a stale number retires the wrong analytic.
// ---------------------------------------------------------------------------

/** One sentence for coverage, wherever coverage is read. The drawer said
 *  "prior run" and "plane", and the tab beside it said "profile run" and
 *  "telemetry", for the same two numbers. */
export const COVERAGE_TITLE =
  'The newest profile run, in entity evaluations. measured means soc-ai scored the entity ' +
  'against a real baseline. blind means no baseline, no confident role, or no telemetry on ' +
  'the grid that can answer.';

export const STATUS_COLOR: Record<string, string> = {
  live: '#3fb950',
  shadow: '#d29922',
  candidate: '#4b8bf5',
  retired: '#8b949e',
};

/** One sentence per status, from the tooltip copy. The drawer, the Analytics
 *  tab and the hit card read the same words for one status. */
export const STATUS_TITLE: Record<string, string> = {
  live: CHIP_LIVE,
  shadow: CHIP_SHADOW,
  candidate: CHIP_CANDIDATE,
  retired: CHIP_RETIRED,
};

export function StatusDot({ status }: { status: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap" title={STATUS_TITLE[status]}>
      <span
        className="h-[7px] w-[7px] flex-none rounded-full"
        style={{ background: STATUS_COLOR[status] ?? '#8b949e' }}
      />
      {status}
    </span>
  );
}

const REASON_PLACEHOLDER: Record<string, string> = {
  live: 'Why it goes live',
  retired: 'Why it is retired',
  shadow: 'Why it runs in shadow',
};

/** The analyst actions on one analytic. Shared by the Analytics tab and this
 *  drawer, so one analytic offers one set of actions wherever it is read.
 *
 *  A transition that changes what runs asks for a reason first. The sharpening
 *  loop reads the reason later, and a retirement with no reason is an analytic
 *  that disappeared. */
export function AnalyticActions({
  analytic,
  onChanged,
  compact,
}: {
  analytic: AnalyticRow;
  onChanged?: () => void;
  compact?: boolean;
}) {
  const navigate = useNavigate();
  const [asking, setAsking] = useState<string | null>(null);
  const [why, setWhy] = useState('');
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);

  const move = async (to: string, reason?: string) => {
    setBusy(true);
    setFailed(null);
    try {
      await setAnalyticStatus(analytic.id, to, reason);
      setAsking(null);
      setWhy('');
      onChanged?.();
    } catch (e) {
      setFailed(e instanceof Error ? e.message : 'The status did not change.');
    } finally {
      setBusy(false);
    }
  };

  const hunt = async () => {
    setBusy(true);
    setFailed(null);
    try {
      // The id, because that is what `t_run_analytic` takes. A title is
      // prose the agent has to guess an id from.
      const started = await startHuntConsole(
        `Run the analytic ${analytic.id} over the last 30 days with t_run_analytic and ` +
          'investigate every entity it returns.',
      );
      navigate(`/hunts/${started.hunt_id}`);
    } catch {
      setFailed('The hunt did not start. Try again.');
    } finally {
      setBusy(false);
    }
  };

  // `whitespace-nowrap`: "Run in shadow" wrapped to two lines in the Actions
  // column and pushed the row to twice its height.
  const btn = `whitespace-nowrap rounded-control border border-border-strong px-2.5 py-1 text-[11.5px] font-semibold hover:bg-surface-2 disabled:opacity-50`;

  return (
    <div className={compact ? 'flex flex-wrap items-center gap-1.5' : 'flex flex-col gap-2'}>
      <div className="flex flex-wrap items-center gap-1.5">
        {analytic.status === 'candidate' && (
          <button type="button" disabled={busy} className={btn} onClick={() => move('shadow')}>
            Run in shadow
          </button>
        )}
        {analytic.status === 'shadow' && (
          <>
            <button type="button" disabled={busy} className={btn} onClick={() => setAsking('live')}>
              Approve
            </button>
            <button
              type="button"
              disabled={busy}
              className={btn}
              onClick={() => setAsking('retired')}
            >
              Reject
            </button>
          </>
        )}
        {analytic.status === 'live' && (
          <>
            <button type="button" disabled={busy} className={btn} onClick={hunt}>
              Hunt with this
            </button>
            <button
              type="button"
              disabled={busy}
              className={btn}
              onClick={() => setAsking('retired')}
            >
              Retire
            </button>
          </>
        )}
        {analytic.status === 'retired' && (
          <button type="button" disabled={busy} className={btn} onClick={() => setAsking('shadow')}>
            Reinstate
          </button>
        )}
      </div>
      {asking && (
        <div className="flex flex-wrap items-center gap-2 text-[12px]">
          <input
            value={why}
            onChange={(e) => setWhy(e.target.value)}
            placeholder={REASON_PLACEHOLDER[asking] ?? 'Why'}
            className="min-w-[220px] flex-1 rounded-control border border-border bg-surface-2 px-2 py-1"
          />
          <button
            type="button"
            disabled={!why || busy}
            onClick={() => move(asking, why)}
            className="rounded-control bg-accent px-3 py-1 font-semibold text-white disabled:opacity-50"
          >
            Confirm
          </button>
          <button
            type="button"
            onClick={() => {
              setAsking(null);
              setWhy('');
            }}
            className="text-dim"
          >
            Cancel
          </button>
        </div>
      )}
      {failed && <div className="text-[11.5px] text-warn">{failed}</div>}
    </div>
  );
}

function Cell({
  label,
  value,
  sub,
  title,
}: {
  label: string;
  value: string;
  sub?: string;
  title?: string;
}) {
  return (
    <div
      data-testid={`ledger-${label.toLowerCase().replace(/[^a-z]+/g, '-').replace(/^-|-$/g, '')}`}
      className="rounded-panel border border-border bg-surface-2/40 px-3 py-2"
      title={title}
    >
      <div className="text-[10.5px] font-semibold uppercase tracking-[.05em] text-faint">
        {label}
      </div>
      <div className="mt-1 text-[17px] font-semibold leading-none tabular-nums">{value}</div>
      {sub && <div className="mt-1 text-[11px] text-dim">{sub}</div>}
    </div>
  );
}

/** Did a lead this analytic fed reach a hunt or an investigation? "yes" is
 *  evidence against a retirement. "no data" is an analytic that observed
 *  nothing, which is a different case from one that observed and led nowhere. */
function fedAHuntedLead(detail: AnalyticDetail): string {
  if (detail.ledger.promoted >= 1 || detail.ledger.hunted >= 1) return 'yes';
  if (detail.ledger.observations > 0) return 'not yet';
  return 'no data';
}

function dismissedLine(dismissed: Record<string, number>): string {
  const parts = Object.entries(dismissed).map(([reason, n]) => `${reason.replace(/_/g, ' ')} ×${n}`);
  return parts.length ? parts.join(' · ') : 'none';
}

function coverageLine(coverage: Record<string, number>): string {
  if (!Object.keys(coverage).length) return '—';
  return `${coverage.measured ?? 0} measured · ${coverage.blind ?? 0} blind`;
}

function runtimeLine(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

/** The versions, newest first, each carrying the number it was created with.
 *
 *  The server writes the trail in creation order and the drawer listed it in
 *  that order while it numbered the rows backwards. The first transition of
 *  an analytic read v2 and sat above the one that read v1. */
function numberedVersions(
  versions: AnalyticDetail['versions'],
): Array<{ version: AnalyticDetail['versions'][number]; number: number }> {
  return versions
    .map((version, i) => ({ version, number: i + 1 }))
    .reverse();
}

function Body({ detail, onChanged }: { detail: AnalyticDetail; onChanged?: () => void }) {
  const [specOpen, setSpecOpen] = useState(false);
  const ledger = detail.ledger;
  return (
    <div className="flex flex-col gap-4 p-4">
      <div>
        <div className="text-[12px] text-dim">
          <span title={detail.tier === 'local' ? CHIP_LOCAL : CHIP_SHIPPED}>{detail.tier}</span> ·{' '}
          <span title={STATUS_TITLE[detail.status]}>{detail.status}</span> · {detail.evaluator}{' '}
          analytic · {detail.level} · scope: {detail.scope_kind}
        </div>
        <div className="mt-1.5 text-[13px] text-text-2">{detail.description}</div>
        {detail.no_benign_baseline && (
          <div className="mt-1.5 text-[11.5px] text-dim" title={CHIP_NO_BENIGN_BASELINE}>
            no benign baseline
          </div>
        )}
        {detail.reason && (
          <div className="mt-1.5 text-[11.5px] text-dim">Reason on record: {detail.reason}</div>
        )}
      </div>

      <AnalyticActions analytic={detail} onChanged={onChanged} compact />

      <div>
        <button
          type="button"
          onClick={() => setSpecOpen((v) => !v)}
          className="text-[11.5px] font-semibold text-accent hover:underline"
        >
          {specOpen ? 'Hide definition' : 'Show definition'}
        </button>
        {specOpen && (
          <pre className="mt-1.5 max-h-[280px] overflow-auto rounded-panel border border-border bg-surface-2/40 p-2.5 font-mono text-[11px] leading-[1.5] text-text-2">
            {detail.spec_text}
          </pre>
        )}
      </div>

      <div>
        <div className="mb-2 text-[13px] font-semibold">Outcome ledger · last 30 days</div>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Cell
            label="Observations"
            value={String(ledger.observations)}
            sub={plural(ledger.entities, 'entity', 'entities')}
            title={LEDGER_OBSERVATIONS}
          />
          <Cell label="Leads" value={String(ledger.leads)} sub="this analytic fed" title={LEDGER_LEADS} />
          <Cell
            label="Hunted · promoted"
            value={`${ledger.hunted} · ${ledger.promoted}`}
            sub="of those leads"
            title={LEDGER_HUNTED_PROMOTED}
          />
          <Cell
            label="Dismissed"
            value={String(Object.values(ledger.dismissed).reduce((a, b) => a + b, 0))}
            sub={dismissedLine(ledger.dismissed)}
            title={LEDGER_DISMISSED}
          />
          <Cell
            label="Cost"
            value={ledger.docs_scanned.toLocaleString()}
            sub={`documents · ${runtimeLine(ledger.runtime_ms)} · ${ledger.sweeps} sweeps`}
            title="Documents scanned and time spent over the window. The sweep trail is the source."
          />
          <Cell
            label="Coverage"
            value={coverageLine(ledger.coverage)}
            sub="entities the newest run could score"
            title={COVERAGE_TITLE}
          />
          <Cell
            label="Version"
            value={String(detail.versions.length)}
            sub="status changes on record"
            title={LEDGER_VERSION}
          />
          <Cell
            label="Fed a hunted lead"
            value={fedAHuntedLead(detail)}
            sub="a lead it fed was hunted or promoted"
            title="Yes if a lead this analytic fed was hunted or promoted. Retire an analytic that observes and never contributes."
          />
        </div>
      </div>

      <div>
        {/* An analytic scoped to user accounts linked every account to the
            host dossier, which is keyed on an address and cannot hold one. */}
        <div className="mb-1.5 text-[13px] font-semibold">Recent observations · by entity</div>
        {detail.recent.length === 0 ? (
          <div className="text-[12px] text-dim">
            This analytic has observed nothing. It has not run, or it found nothing.
          </div>
        ) : (
          <ul className="divide-y divide-border-faint">
            {detail.recent.map((r) => (
              <li key={r.entity} className="flex flex-wrap items-center gap-2 py-1.5 text-[12.5px]">
                <Link
                  to={entityPath(detail.scope_kind, r.entity)}
                  className="font-mono text-[12px] font-semibold text-accent hover:underline"
                >
                  {r.entity}
                </Link>
                <span className="text-[11.5px] text-dim" title={CHIP_SEEN}>
                  seen {plural(r.count, 'time')}
                </span>
                <span className="text-[11.5px] text-dim" title={absTime(r.last)}>
                  · {ago(r.last)}
                </span>
                {r.lead_id !== null && (
                  <Link
                    to={`/leads/${r.lead_id}`}
                    title={CHIP_IN_LEAD}
                    className="rounded-chip border border-border-strong px-1.5 py-px text-[10.5px] text-accent hover:underline"
                  >
                    in lead {r.lead_id}
                  </Link>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div>
        <div className="mb-1.5 text-[13px] font-semibold">Versions</div>
        {detail.versions.length === 0 ? (
          <div className="text-[12px] text-dim">
            This analytic has no status change on record. It has always been {detail.status}.
          </div>
        ) : (
          <ul data-testid="analytic-versions" className="divide-y divide-border-faint">
            {numberedVersions(detail.versions).map(({ version: v, number }, i) => (
              <li key={`${v.at}-${i}`} className="flex flex-wrap items-center gap-2 py-1.5 text-[12px]">
                <span className="font-mono text-[11.5px] text-dim" title={absTime(v.at)}>
                  {ago(v.at)}
                </span>
                <span className="font-mono text-[11.5px] text-faint" title={CHIP_VERSION}>
                  v{number}
                </span>
                <span className="text-text-2">
                  {v.from_status ?? 'new'} → {v.to_status}
                </span>
                <span className="text-[11.5px] text-dim">{v.who}</span>
                {v.why && <span className="text-[11.5px] text-dim">"{v.why}"</span>}
                {v.has_receipts && (
                  <span
                    className="rounded-chip border border-border-strong px-1.5 py-px text-[10.5px] text-dim"
                    title="The evidence this decision was taken on is stored on this row."
                  >
                    evidence
                  </span>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

export function AnalyticDrawer({
  analyticId,
  onClose,
  onChanged,
}: {
  analyticId: string | null;
  onClose: () => void;
  onChanged?: () => void;
}) {
  const [reload, setReload] = useState(0);
  const detail = useAsync(
    () => (analyticId ? getAnalytic(analyticId) : Promise.resolve(null)),
    [analyticId, reload],
  );
  const data = detail.data;
  const changed = () => {
    setReload((n) => n + 1);
    onChanged?.();
  };
  return (
    <Drawer
      open={analyticId !== null}
      onClose={onClose}
      header={
        <div className="flex min-w-0 flex-1 items-center gap-2.5">
          {/* The id under the title: two analytics on one subject read the
              same from the title alone, and the id is what an objective and a
              CLI call take. */}
          <span className="min-w-0 flex-1">
            <span className="block truncate text-[13.5px] font-semibold">
              {data?.title ?? analyticId ?? ''}
            </span>
            <span data-testid="analytic-id" className="block truncate font-mono text-[11px] text-faint">
              {analyticId ?? ''}
            </span>
          </span>
          {data && <StatusDot status={data.status} />}
        </div>
      }
    >
      {/* What an analytic is, under the title. The drawer is where an analytic
          is judged, and it never said what one was. */}
      <Definition of="analytic" className="border-b border-border px-4 py-2.5" />
      {!data ? (
        <div className="p-4 text-[12.5px] text-dim">
          {detail.error ? 'Could not read the analytic.' : 'Reading the analytic…'}
        </div>
      ) : (
        <Body detail={data} onChanged={changed} />
      )}
    </Drawer>
  );
}
