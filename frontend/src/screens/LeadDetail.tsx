import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import {
  LEAD_ACTION as ACTIONS,
  INVESTIGATION_GONE_LABEL,
  LEFT_TO_YOU_LABEL,
  LeadStatePill,
  huntQueued,
  leadState,
  leftToYou,
} from '../components/LeadsStrip';
import { Definition } from '../components/Definition';
import { LeadTimeline } from '../components/LeadTimeline';
import { DismissLeadForm, HUNT_CLOSED_ACTOR, REASON_LABEL, closedByHunt } from '../components/LeadsStrip';
import { Panel, PanelHeader } from '../components/Panel';
import { EmptyState, LoadingState } from '../components/States';
import {
  getHunts,
  getLead,
  getNeedsYou,
  huntLead,
  promoteLead,
  reopenLead,
  type LeadDetail as LeadDetailT,
  type RelatedLead as RelatedLeadT,
} from '../lib/api';
import { entityPath } from '../lib/entityPath';
import { kindLabel } from '../lib/kinds';
import { plural } from '../lib/plural';
import { HUNT_STATUS } from '../lib/statusMeta';
import { ago } from '../lib/timeRange';
import {
  ACTION_HUNT_NOW,
  ACTION_REOPEN,
  CHIP_CLOSED_BY_HUNT,
  CHIP_DISMISS_REASON,
  CHIP_LEFT_TO_YOU,
  CHIP_ONE_SIGNAL,
  CHIP_SHADOW_LEAD,
  CHIP_TYPE,
  COUNT_THREAT_FINDINGS,
  INVESTIGATION_GONE,
  LEAD_LEGEND,
  LEGEND_AUTO_HUNT,
  PROMOTE_NEEDS_HUNT,
  RELATED_REASON,
  WEIGHT_AT_FORMATION,
  WEIGHT_BY_TYPE,
  WEIGHT_NOW,
  huntStatusTitle,
} from '../lib/tooltips';
import type { HuntRow, HuntStatus } from '../lib/types';
import { useAsync } from '../lib/useAsync';

// ---------------------------------------------------------------------------
// Lead detail — one lead, its timeline and its actions.
//
// The page answers one question: is this worth an hour? So it states the
// weight now beside the weight at formation. A lead that has gone quiet reads
// the same as a fresh one without both numbers.
//
// An evidence id is a document id, and it is the proof the analytic matched
// the right thing. It opens the document in a drawer. An id that looked like a
// link and opened nothing was the earlier defect here.
// ---------------------------------------------------------------------------

/** The outcome label that makes a benign repeat the right reason to dismiss. */
const NO_THREAT = 'No threat observed';

/** The hunts this lead started, newest first. The page named one hunt, from
 *  `hunt_id`, so a lead hunted twice showed the first hunt forever. */
function huntsOnLead(rows: HuntRow[] | null, lead: LeadDetailT): HuntRow[] {
  const mine = (rows ?? []).filter((h) => h.leadId === lead.id);
  // The lead's own `hunt_id` may sit outside the window the list answered.
  if (lead.hunt_id && !mine.some((h) => h.id === lead.hunt_id)) {
    mine.push({
      id: lead.hunt_id,
      objective: '',
      kind: 'lead',
      status: 'complete',
      findingCount: 0,
      affectedHosts: 0,
      confidence: null,
      startedBy: '',
      when: '',
      ts: '',
    });
  }
  return mine;
}

export function LeadDetail() {
  const { id = '' } = useParams();
  const leadId = Number(id);
  const navigate = useNavigate();
  const [dismissing, setDismissing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [confirmAgain, setConfirmAgain] = useState(false);
  // The investigation the promotion started. The click left no mark on the
  // page: the record held the promotion and the running investigation, and
  // the page still read Hunted with Promote live.
  const [promoted, setPromoted] = useState('');
  const lead = useAsync<LeadDetailT>(() => getLead(leadId), [leadId]);
  // Every hunt on this lead, not only the newest. `kind=lead` is the whole
  // class; the lead id narrows it to this one.
  const leadHunts = useAsync(() => getHunts({ kind: 'lead' }), [leadId]);
  // The server states whether the loop runs. The legend is a taxonomy of the
  // deployment, not of this one lead, and the page read the lead's own queued
  // hunt: every hunted, promoted and reopened lead then read the legend
  // without the sentence the strip carries. The read is best-effort, because
  // the counts are not what the page is for.
  const needsYou = useAsync(() => getNeedsYou().catch(() => null), [leadId]);

  if (lead.loading && !lead.data) return <LoadingState label="Reading the lead" />;
  if (lead.error || !lead.data) return <EmptyState>This lead does not exist.</EmptyState>;
  const d = lead.data;
  // The state the strip shows, derived once. The page said "Hunting" over a
  // hunt that had already finished, and the strip said "Hunted".
  const state = leadState(d);
  const closed = state === 'dismissed' || state === 'promoted';
  const hunted = state === 'hunted';
  // The loop owns this lead's next move. The page reads the strip's words for
  // it: the same pill, the same secondary Hunt, the same legend sentence.
  const queued = huntQueued(d);
  // A server that sends no setting leaves the page with this lead's own
  // queued hunt, which proves the loop runs and never disproves it.
  const autoHunt =
    typeof needsYou.data?.lead_auto_hunt === 'boolean' ? needsYou.data.lead_auto_hunt : queued;
  const benignRepeat = hunted && d.hunt_outcome_label === NO_THREAT;
  // A closed lead states the weight it formed at. The live weight of a lead
  // nobody works any more is a number that moves and means nothing.
  const liveWeight = !closed;
  const hunts = huntsOnLead(leadHunts.data, d);
  const attached = hunts[0] ?? null;
  // The hunt the actions point at. A link goes to the hunt page, so the
  // address is written once.
  const huntHref = attached ? `/hunts/${attached.id}` : d.hunt_id ? `/hunts/${d.hunt_id}` : null;
  const linkClass = 'text-[12px] font-semibold text-accent hover:underline';
  const buttonClass =
    'rounded-control border border-border-strong px-3 py-1.5 text-[12px] font-semibold disabled:opacity-50';

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError('');
    try {
      await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'The action failed.');
    } finally {
      setBusy(false);
    }
  };

  // The two acts that leave the page, written once. The New block and the
  // Hunted block both offer them, and two copies drifted the moment one of
  // them grew a rule.
  const startHunt = async () => {
    const r = await huntLead(d.id);
    navigate(`/hunts/${r.hunt_id}`);
  };
  const startPromotion = async () => {
    const r = await promoteLead(d.id);
    setPromoted(r.investigation_id);
    lead.refetch();
  };

  return (
    <div className="p-5">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-[19px] font-semibold">
          Lead {d.id} ·{' '}
          {d.entities.map((e, i) => (
            <span key={e[1]}>
              {/* The dot carries a space on each side. A margin is not a
                  space: the two names ran together under one dot. */}
              {i > 0 && <span className="text-dim">{' · '}</span>}
              <Link to={entityPath(e[0], e[1])} className="font-mono text-accent hover:underline">
                {e[1]}
              </Link>
            </span>
          ))}
        </h1>
        {/* The pill the strip wears. The page and the strip read one word for
            one state, and the outcome of a finished hunt rides in the pill. */}
        <LeadStatePill lead={d} />
        {/* The loop starts a hunt on every new lead but three: a shadow lead,
            a reopened lead and a lead with no documents. This is one of the
            three, and without the chip the analyst waits for a hunt that
            never comes. */}
        {leftToYou(d, autoHunt) && (
          <span
            data-testid="lead-left-to-you"
            className="rounded-chip border border-border-faint px-1.5 py-px text-[10.5px] text-faint"
            title={CHIP_LEFT_TO_YOU}
          >
            {LEFT_TO_YOU_LABEL}
          </span>
        )}
        {/* A closed lead states why it was closed beside its status. The
            reason sat on the timeline alone, below every observation. The word
            is the strip's word: one dismissal read "reason:" there and
            "Closed:" here, which is two names for one fact. */}
        {closedByHunt(d) ? (
          <span
            data-testid="lead-closed-reason"
            className="text-[11.5px] text-dim"
            title={CHIP_CLOSED_BY_HUNT}
          >
            closed by {HUNT_CLOSED_ACTOR}
          </span>
        ) : (
          closed &&
          d.dismissed_reason && (
            <span
              data-testid="lead-closed-reason"
              className="text-[11.5px] text-dim"
              title={CHIP_DISMISS_REASON}
            >
              reason: {REASON_LABEL[d.dismissed_reason] ?? d.dismissed_reason}
            </span>
          )
        )}
        {d.kinds.map((k, i) => (
          <span
            key={k}
            className="rounded-chip border border-border-strong bg-surface-2 px-1.5 py-px text-[10.5px] text-text-2"
            title={CHIP_TYPE}
          >
            {kindLabel(k, d.kind_labels?.[i])}
          </span>
        ))}
        {d.single_signal && (
          <span
            className="rounded-chip border border-border-strong px-1.5 py-px text-[10.5px] text-dim"
            title={CHIP_ONE_SIGNAL}
          >
            one signal, repeated
          </span>
        )}
        {d.shadow && (
          <span
            className="rounded-chip border px-1.5 py-px text-[10.5px]"
            style={{ color: '#d29922', borderColor: 'rgba(210,153,34,.35)' }}
            title={CHIP_SHADOW_LEAD}
          >
            shadow
          </span>
        )}
        {/* One set of actions per state, in the words of the strip. A closed
            lead offers one act: every other act answers 409 from the server. A
            lead under a running hunt offers one act: follow the hunt. */}
        <span className="ml-auto flex flex-wrap items-center gap-2.5">
          {state === 'new' && (
            <>
              {/* A queued lead already has a hunt coming, so the word on the
                  button is the word for jumping the queue. */}
              {!queued && (
                <button
                  type="button"
                  disabled={busy}
                  className="rounded-control bg-accent px-3 py-1.5 text-[12px] font-semibold text-white disabled:opacity-50"
                  onClick={() => run(startHunt)}
                >
                  {ACTIONS.hunt}
                </button>
              )}
              <button
                type="button"
                disabled={busy}
                className={`${buttonClass} text-dim`}
                onClick={() => setDismissing((v) => !v)}
              >
                {ACTIONS.dismiss}
              </button>
              <button
                type="button"
                disabled={busy || !hunted}
                title={hunted ? undefined : PROMOTE_NEEDS_HUNT}
                className={
                  queued
                    ? 'rounded-control bg-accent px-3 py-1.5 text-[12px] font-semibold text-white disabled:opacity-50'
                    : buttonClass
                }
                onClick={() => run(startPromotion)}
              >
                {ACTIONS.promote}
              </button>
              {queued && (
                <button
                  type="button"
                  disabled={busy}
                  title={ACTION_HUNT_NOW}
                  className={buttonClass}
                  onClick={() => run(startHunt)}
                >
                  {ACTIONS.huntNow}
                </button>
              )}
            </>
          )}
          {state === 'in_progress' && huntHref && (
            <Link to={huntHref} className={linkClass}>
              {ACTIONS.viewHunt}
            </Link>
          )}
          {state === 'hunted' && (
            <>
              {huntHref && (
                <Link to={huntHref} className={linkClass}>
                  {ACTIONS.readHunt}
                </Link>
              )}
              <button
                type="button"
                disabled={busy}
                className="rounded-control bg-accent px-3 py-1.5 text-[12px] font-semibold text-white disabled:opacity-50"
                onClick={() => run(startPromotion)}
              >
                {ACTIONS.promote}
              </button>
              <button
                type="button"
                disabled={busy}
                className={`${buttonClass} text-dim`}
                onClick={() => setDismissing((v) => !v)}
              >
                {ACTIONS.dismiss}
              </button>
              <button
                type="button"
                disabled={busy}
                className={buttonClass}
                onClick={() => setConfirmAgain(true)}
              >
                {ACTIONS.huntAgain}
              </button>
            </>
          )}
          {closed && (
            <button
              type="button"
              disabled={busy}
              className={buttonClass}
              title={ACTION_REOPEN}
              onClick={() =>
                run(async () => {
                  await reopenLead(d.id);
                  lead.refetch();
                })
              }
            >
              {ACTIONS.reopen}
            </button>
          )}
          {/* A link goes to a page. This lead kept the id of an investigation
              the store no longer holds, so the link promised a page and landed
              on "No such investigation". */}
          {state === 'promoted' &&
            d.investigation_id &&
            (d.investigation_exists === false ? (
              <span className="text-[12px] text-dim" title={INVESTIGATION_GONE}>
                {INVESTIGATION_GONE_LABEL}
              </span>
            ) : (
              <Link
                to={`/investigation/${encodeURIComponent(d.investigation_id)}`}
                className={linkClass}
              >
                {ACTIONS.openInvestigation}
              </Link>
            ))}
        </span>
      </div>
      {/* What a lead is, under the title. An analyst who lands here from a link
          never saw the line the Hunts page carries. */}
      <Definition of="lead" className="mt-1" />
      {/* The four states, once, under the actions. The strip carries the same
          line, so a state means one thing on both. */}
      <div data-testid="lead-legend" className="mt-1 text-[11px] text-faint">
        {autoHunt ? `${LEAD_LEGEND} ${LEGEND_AUTO_HUNT}` : LEAD_LEGEND}
      </div>
      {/* Two weights, two sentences. One decays and one is the record of a
          moment, and the line carried the decay sentence over both. */}
      <div data-testid="lead-meta" className="mt-1 text-[12.5px] text-dim">
        formed {ago(d.formed_at)} ·{' '}
        {liveWeight && (
          <>
            <b className="text-text-2" title={WEIGHT_NOW}>
              weight now {d.weight_now.toFixed(2)}
            </b>{' '}
            ·{' '}
          </>
        )}
        <span title={WEIGHT_AT_FORMATION}>
          at formation {d.weight_at_formation.toFixed(2)}
        </span>{' '}
        {/* One line per type, each against the cap one type can reach. A
            lead read "weight now 25.00" over one type repeated, and 25 ranked
            nothing. "1.70 of 1.70, saturated" says what the number is. */}
        {liveWeight &&
          (d.weight_by_kind ?? []).map((k) => (
            <span
              key={k.kind}
              className="ml-1 font-mono text-[11px]"
              title={WEIGHT_BY_TYPE}
              data-testid={`weight-kind-${k.kind}`}
            >
              {kindLabel(k.kind, k.kind_label)} {k.weight.toFixed(2)} of {k.cap.toFixed(2)}
              {k.saturated ? ', saturated' : ''}
            </span>
          ))}{' '}
        · {plural(d.kinds.length, 'type')} ·{' '}
        {plural(d.entities.length, 'entity', 'entities')} named · {d.scope_count} with observations
      </div>
      {/* A second hunt on one lead is a real thing to want and a common
          mis-click. The confirm names the hunt that already exists. */}
      {confirmAgain && (
        <div className="mt-3 flex flex-wrap items-center gap-2 rounded-panel border border-border bg-surface-1 p-3 text-[12.5px]">
          <span>
            A hunt on this lead already exists. Open {attached?.id} before you start another.
          </span>
          <button
            type="button"
            disabled={busy}
            className="rounded-control bg-accent px-3 py-1 font-semibold text-white disabled:opacity-50"
            onClick={() =>
              run(async () => {
                const r = await huntLead(d.id);
                setConfirmAgain(false);
                navigate(`/hunts/${r.hunt_id}`);
              })
            }
          >
            Start another hunt
          </button>
          <button type="button" className="text-dim" onClick={() => setConfirmAgain(false)}>
            Cancel
          </button>
        </div>
      )}
      {/* The same form the leads strip mounts, so one dismissal reads the same
          wherever an analyst takes it. */}
      {dismissing && !closed && (
        <div className="mt-3 rounded-panel border border-border bg-surface-1 p-3">
          <DismissLeadForm
            leadId={d.id}
            reasons={d.dismiss_reasons}
            initialReason={benignRepeat ? 'benign_repeat' : undefined}
            onDone={() => {
              setDismissing(false);
              lead.refetch();
            }}
          />
        </div>
      )}
      {error && <div className="mt-2 text-[12px] text-danger">{error}</div>}
      {/* The act landed, and the investigation is already running. The page
          reads the lead again behind this line, so the pill and the actions
          catch up with the record. */}
      {promoted && (
        <div
          data-testid="lead-promoted"
          className="mt-2 flex flex-wrap items-center gap-2 text-[12.5px] text-text-2"
        >
          <span>Promoted. The investigation is running.</span>
          <Link to={`/investigation/${encodeURIComponent(promoted)}`} className={linkClass}>
            {ACTIONS.openInvestigation}
          </Link>
        </div>
      )}

      {/* Every hunt this lead started. The page named one, from `hunt_id`, so a
          lead hunted twice showed the first hunt forever. */}
      {hunts.length > 0 && (
        <Panel className="mt-4">
          <PanelHeader title={`Hunts on this lead · ${hunts.length}`} />
          <ul data-testid="lead-hunts" className="divide-y divide-border-faint">
            {hunts.map((h) => (
              <li key={h.id} className="flex flex-wrap items-center gap-2.5 px-[15px] py-2.5 text-[12.5px]">
                <Link to={`/hunts/${h.id}`} className="font-mono text-accent hover:underline">
                  {h.id}
                </Link>
                {/* The screen word, with the sentence that states it. The row
                    printed the raw API word and explained nothing. */}
                <span className="text-dim" title={huntStatusTitle(h.status, 'row')}>
                  {HUNT_STATUS[h.status as HuntStatus]?.label ?? h.status}
                </span>
                {h.when && <span className="text-[11.5px] text-faint">started {h.when}</span>}
                {h.status === 'complete' && (
                  <span className="text-[11.5px] text-dim" title={COUNT_THREAT_FINDINGS}>
                    {plural(h.threatFindingCount ?? h.findingCount, 'threat finding')}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </Panel>
      )}

      {/* One entity is one lead. A coordinated attack across entities is
          several leads, and no single one of them reads as a campaign. The
          panel is the only place that joins them, and it joins them on read:
          nothing here is stored. */}
      <RelatedLeadsPanel related={d.related} />

      {/* The dismissal stays on the record, and the timeline names the
          reopen. The hunt page renders the same component, so the entry
          reads one way on both. */}
      <LeadTimeline lead={d} />
    </div>
  );
}

/**
 * The open leads that relate to this one.
 *
 * A related lead shares an analytic within 24 hours, an external address, or a
 * technique, and it formed in the last 7 days. The reason rides on the row,
 * because "related" without a reason is an assertion the analyst cannot check.
 *
 * `undefined` means the API sent nothing, and the panel does not render. An
 * empty panel there would read as "nothing relates", which is an answer no
 * deployment gave.
 */
function RelatedLeadsPanel({ related }: { related?: RelatedLeadT[] }) {
  if (!related) return null;
  return (
    <Panel className="mt-4">
      <PanelHeader title={`Related leads · ${related.length}`} />
      {related.length === 0 ? (
        <div data-testid="lead-related" className="px-[15px] py-2.5 text-[12.5px] text-dim">
          No related lead in the last 7 days.
        </div>
      ) : (
        <ul data-testid="lead-related" className="divide-y divide-border-faint">
          {related.map((r) => {
            const primary = r.entities[0];
            return (
              <li
                key={r.lead_id}
                data-testid={`related-lead-${r.lead_id}`}
                className="flex flex-wrap items-center gap-2.5 px-[15px] py-2.5 text-[12.5px]"
              >
                {primary && (
                  <Link
                    to={entityPath(primary[0], primary[1])}
                    className="font-mono text-accent hover:underline"
                  >
                    {primary[1]}
                  </Link>
                )}
                <Link to={`/leads/${r.lead_id}`} className="text-accent hover:underline">
                  Lead {r.lead_id}
                </Link>
                {/* The whole row, not the stored status alone. The pill reads
                    the hunt status and the outcome, and a row built from
                    `status` on its own could not tell a running hunt from a
                    finished one. */}
                <LeadStatePill lead={r} />
                <span className="text-dim" title={RELATED_REASON}>
                  {r.reason}
                </span>
                {r.formed_at && (
                  <span className="text-[11.5px] text-faint">formed {ago(r.formed_at)}</span>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}
