import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import {
  LEAD_ACTION as ACTIONS,
  FormedFromBacktestChip,
  INVESTIGATION_GONE_LABEL,
  LEFT_TO_YOU_LABEL,
  LeadStatePill,
  huntQueued,
  leadState,
  leftToYou,
} from '../components/LeadsStrip';
import { Definition } from '../components/Definition';
import { FlowStrip } from '../components/FlowStrip';
import { LeadTimeline } from '../components/LeadTimeline';
import {
  DismissLeadForm,
  HUNT_CLOSED_ACTOR,
  REASON_LABEL,
  closedByHunt,
  dismissEffect,
} from '../components/LeadsStrip';
import { Panel, PanelHeader } from '../components/Panel';
import { ErrorState, LoadingState, NotFoundState, StaleNotice } from '../components/States';
import {
  ApiError,
  closeLeadAsPromoted,
  getHunt,
  getLead,
  getMachine,
  keepLeadOpen,
  getNeedsYou,
  huntLead,
  isNotFound,
  reopenLead,
  resolveMachine,
  type LeadDetail as LeadDetailT,
  type LeadHunt as LeadHuntT,
  type RelatedLead as RelatedLeadT,
} from '../lib/api';
import { entityPath } from '../lib/entityPath';
import { type FlowHunt, leadFlow } from '../lib/flowSteps';
import { isIpKey } from '../lib/ip';
import { kindLabel } from '../lib/kinds';
import { formedFromBacktest, holdSentence, type LeadDecisionFields } from '../lib/leadDecisions';
import {
  entityCountWords,
  huntRecordSentence,
  leadHuntLabel,
  leadWhySentence,
  staleHuntSentence,
  verdictToDecide,
  verdictWords,
} from '../lib/leadWords';
import { plural } from '../lib/plural';
import { chipProps, huntOutcome, outcomeLabel, outcomeMeta, statusLabel } from '../lib/labels';
import { absTime, ago } from '../lib/timeRange';
import {
  ACTION_HUNT,
  ACTION_HUNT_NOW,
  ACTION_REOPEN,
  CHIP_CLOSED_BY_HUNT,
  CHIP_DISMISS_REASON,
  CHIP_LEFT_TO_YOU,
  CHIP_ONE_SIGNAL,
  CHIP_SHADOW_LEAD,
  CHIP_TYPE,
  INVESTIGATION_GONE,
  LEAD_ACTIONS_LINE,
  LEAD_LEGEND,
  LEGEND_AUTO_HUNT,
  RELATED_REASON,
  WEIGHT_AT_FORMATION,
  WEIGHT_BY_TYPE,
  WEIGHT_NOW,
  huntStatusTitle,
} from '../lib/tooltips';
import { useAsync } from '../lib/useAsync';
import { useChatScope } from '../lib/chatScope';

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

/** One hunt on the lead. A row the server named carries its answer. A row
 *  built from the lead's own `hunt_id` carries only what the lead record
 *  states about the hunt, and `fromLead` says so. */
type LeadHuntRow = LeadHuntT & { fromLead?: boolean };

/** The hunts on this lead, newest first, each with its answer. The page named
 *  one hunt, from `hunt_id`, so a lead hunted twice showed the first hunt
 *  forever. The server now sends every hunt on the lead.
 *
 *  A server that sends no list leaves the hunt the lead record names. That row
 *  reads the status the record states. It stated "complete" whatever the hunt
 *  was doing, so a running hunt read as finished and an errored one read as
 *  clean, against the pill on the same page. */
function huntsOnLead(lead: LeadDetailT): LeadHuntRow[] {
  if (lead.hunts) return lead.hunts;
  if (!lead.hunt_id) return [];
  return [
    {
      id: lead.hunt_id,
      status: lead.hunt_status ?? 'complete',
      outcome: '',
      outcome_label: lead.hunt_outcome_label ?? '',
      threat_findings: 0,
      steps: 0,
      elapsed_sec: 0,
      started_at: null,
      started_by: '',
      answer: '',
      not_checked: [],
      fromLead: true,
    },
  ];
}

/** The outcome key of one hunt row, or null. A row the server never named
 *  carries no count. It states the outcome the lead record holds, and "0
 *  threat findings" over a hunt that found some was the earlier defect. An
 *  older server sends the label alone, and the row then states no outcome. */
function rowOutcome(h: LeadHuntRow, lead: LeadDetailT): string | null {
  if (h.status === 'running' || h.status === 'queued') return null;
  return huntOutcome({ status: h.status, outcome: h.fromLead ? lead.hunt_outcome : h.outcome });
}

/** The outcome words of one hunt row. The server's label carries the counts
 *  of a hunt that investigated its findings, "2 of 2 findings are threats".
 *  The client word stands in for an older server. */
function rowOutcomeLabel(h: LeadHuntRow, lead: LeadDetailT): string {
  const outcome = rowOutcome(h, lead);
  if (!outcome) return '';
  const server = h.fromLead ? lead.hunt_outcome_label : h.outcome_label;
  return COUNTED_OUTCOMES.has(outcome) && server ? server : outcomeLabel(outcome);
}

/** The outcomes whose label carries a count the client cannot compute. */
const COUNTED_OUTCOMES: ReadonlySet<string> = new Set([
  'investigating',
  'threats_confirmed',
  'no_threat_confirmed',
]);

/** The words that name one hunt in a sentence or a link. */
function huntName(h: LeadHuntRow): string {
  return h.fromLead ? 'Lead hunt' : leadHuntLabel(h);
}

export function LeadDetail() {
  const { id = '' } = useParams();
  const leadId = Number(id);
  const navigate = useNavigate();
  const [dismissing, setDismissing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [confirmAgain, setConfirmAgain] = useState(false);
  // C2: the weights and the z scores sit behind this toggle.
  const [scoring, setScoring] = useState(false);
  // A lead id is an integer. Anything else in the address is a wrong link,
  // not a read to retry: `Number('01BOGUS')` is NaN, the request went out as
  // /leads/NaN, and the 422 rendered an error card whose Retry could never
  // succeed. A 404 here takes the not-found branch below without a request.
  const validId = Number.isInteger(leadId) && leadId > 0;
  const lead = useAsync<LeadDetailT & LeadDecisionFields>(
    () => (validId ? getLead(leadId) : Promise.reject(new ApiError(`Lead ${id} not found`, 404))),
    [leadId],
  );
  // The server states whether the loop runs. The legend is a taxonomy of the
  // deployment, not of this one lead, and the page read the lead's own queued
  // hunt: every hunted, promoted and reopened lead then read the legend
  // without the sentence the strip carries. The read is best-effort, because
  // the counts are not what the page is for.
  const needsYou = useAsync(() => getNeedsYou().catch(() => null), [leadId]);
  // W7: the machine behind the lead's first address, read from the hosts
  // resolve route. The title named the address alone, so the analyst opened
  // the host page to learn that 10.1.10.254 is the router. Best-effort: a
  // value no machine holds keeps the title it has.
  const firstEntity = lead.data?.entities[0];
  const machineKey =
    firstEntity && firstEntity[0] === 'host' && isIpKey(String(firstEntity[1]))
      ? String(firstEntity[1])
      : '';
  const machine = useAsync(
    () =>
      machineKey
        ? resolveMachine(machineKey)
            .then((r) => getMachine(r.key))
            .catch(() => null)
        : Promise.resolve(null),
    [machineKey],
  );
  // The Ask soc-ai panel's lead scope, once the lead is read.
  const leadRead = lead.data ? lead.data.id : null;
  useChatScope(
    leadRead != null ? { scope: { kind: 'lead', id: String(leadRead), name: `Lead ${leadRead}` } } : null,
  );
  // The hunt the lead points at, for the flow strip: its findings and their
  // investigations. Best-effort. A failed read leaves the strip with what the
  // lead record states, and the page stays as it is.
  const attachedHuntId = lead.data?.hunt_id ?? null;
  const flowHunt = useAsync<FlowHunt | null>(
    () =>
      attachedHuntId
        ? getHunt(attachedHuntId)
            .then((h) => h as FlowHunt)
            .catch(() => null)
        : Promise.resolve(null),
    [attachedHuntId, lead.data?.hunt_status],
  );

  if (lead.loading && !lead.data) return <LoadingState label="Reading the lead" />;
  // A 404 is an answer, and retrying one fails again. Any other failure keeps
  // the error card and its Retry: the page answered every failure with "does
  // not exist", so a grid outage read as a deleted record. Both branches wait
  // on `!data`, the way the hunt and host pages do: the re-read behind
  // Reopen and Dismiss keeps the lead on screen when it fails.
  if (lead.error && !lead.data) {
    return isNotFound(lead.error) ? (
      <NotFoundState what="lead" id={id} backTo="/hunts#leads" backLabel="Back to leads" />
    ) : (
      <ErrorState error={lead.error} onRetry={lead.refetch} label="this lead" />
    );
  }
  if (!lead.data) return null;
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
  // A closed lead states the weight it formed at. The live weight of a lead
  // nobody works any more is a number that moves and means nothing.
  const liveWeight = !closed;
  const hunts = huntsOnLead(d);
  // The name and the role of the machine, when the resolve route found one.
  // A role the server holds back as a guess is not stated.
  const resolved = machine.data ?? null;
  const machineName = resolved?.name && resolved.name !== machineKey ? resolved.name : null;
  const machineRole =
    resolved && (resolved.role.state === 'declared' || resolved.role.state === 'inferred')
      ? (resolved.role.label ?? resolved.role.value)
      : null;
  // The verdict of a promoted finding the analyst has not answered yet.
  const ask = verdictToDecide(d);
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

  // The act that leaves the page, written once. The New block offers it
  // twice, and two copies drifted the moment one of them grew a rule.
  //
  // A lead offers no "Open an investigation" (owner, 2026-10-07). The hunt
  // investigates what it finds and brings back the verdicts, and the manual
  // control sits on a finding with no investigation, on the hunt page.
  const startHunt = async () => {
    const r = await huntLead(d.id);
    navigate(`/hunts/${r.hunt_id}`);
  };

  return (
    <div className="p-5">
      {/* The re-read failed and the page still shows the record it read
          before. Nothing polls underneath, so the line offers the refresh. */}
      {lead.error && (
        <StaleNotice
          since={lead.lastUpdated}
          reason="refresh-failed"
          onRefresh={lead.refetch}
          className="mb-3"
        />
      )}
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-[19px] font-semibold">
          Lead {d.id} ·{' '}
          {/* W7: the machine name first, then the address, then the role. */}
          {machineName && (
            <span data-testid="lead-machine-name">
              <Link to={entityPath(d.entities[0][0], d.entities[0][1])} className="text-accent hover:underline">
                {machineName}
              </Link>
              <span className="text-dim">{' · '}</span>
            </span>
          )}
          {d.entities.map((e, i) => (
            <span key={e[1]}>
              {/* The dot carries a space on each side. A margin is not a
                  space: the two names ran together under one dot. */}
              {i > 0 && <span className="text-dim">{' · '}</span>}
              <Link to={entityPath(e[0], e[1])} className="font-mono text-accent hover:underline">
                {e[1]}
              </Link>
              {i === 0 && machineRole && (
                <span data-testid="lead-machine-role" className="font-normal text-text-2">
                  {' · '}
                  {machineRole}
                </span>
              )}
            </span>
          ))}
        </h1>
        {/* The pill the strip wears. The page and the strip read one word for
            one state, and the outcome of a finished hunt rides in the pill. */}
        <LeadStatePill lead={d} />
        {formedFromBacktest(d) && <FormedFromBacktestChip />}
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
                  title={ACTION_HUNT}
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
                {ACTIONS.viewInvestigation}
              </Link>
            ))}
        </span>
      </div>
      {/* C8: what the hunt does, and the meaning of "left to you", in plain
          view. Both lived in a hover title alone. The owner asked what a hunt
          is for (2026-10-07), so an open lead states it under its actions. */}
      {(!closed || leftToYou(d, autoHunt)) && (
        <div data-testid="lead-action-notes" className="mt-1.5 text-[12px] text-dim">
          {!closed && <div data-testid="lead-actions-line">{LEAD_ACTIONS_LINE}</div>}
          {leftToYou(d, autoHunt) && (
            <div data-testid="lead-left-to-you-reason">{CHIP_LEFT_TO_YOU}</div>
          )}
        </div>
      )}
      {/* The flow, under the header (owner, 2026-10-07): Hit, Lead, Hunt,
          Investigations, Verdicts, Actions. The lead is the current step. */}
      <FlowStrip steps={leadFlow(d, flowHunt.data ?? null)} className="mt-2" />
      {/* S2: a finding of this lead's hunt has an investigation, and the
          investigation reached a verdict. The lead stayed in Needs you, so a
          second analyst could start a second investigation of the same
          evidence. The strip asks once per investigation. */}
      {ask && (
        <div
          data-testid="lead-verdict-strip"
          className="mt-2 flex flex-wrap items-center gap-2.5 rounded-panel border px-3 py-2 text-[12.5px]"
          style={{ borderColor: 'rgba(163,113,247,.45)', background: 'rgba(163,113,247,.08)' }}
        >
          <span className="text-text-2">
            {`An investigation holds this lead's evidence. Verdict: ${verdictWords(
              ask.verdict,
              ask.confidence,
            )}. Close the lead on this investigation?`}
          </span>
          <Link
            to={`/investigation/${encodeURIComponent(ask.investigation_id)}`}
            className={linkClass}
            title={`Investigation ${ask.investigation_id}`}
          >
            {ACTIONS.viewInvestigation}
          </Link>
          <button
            type="button"
            disabled={busy}
            className="rounded-control bg-accent px-3 py-1 text-[12px] font-semibold text-white disabled:opacity-50"
            onClick={() =>
              run(async () => {
                await closeLeadAsPromoted(d.id, ask.investigation_id);
                lead.refetch();
              })
            }
          >
            Close the lead
          </button>
          <button
            type="button"
            disabled={busy}
            className={buttonClass}
            onClick={() =>
              run(async () => {
                await keepLeadOpen(d.id, ask.investigation_id);
                lead.refetch();
              })
            }
          >
            Keep open
          </button>
        </div>
      )}
      {/* What a lead is, under the title. An analyst who lands here from a link
          never saw the line the Hunts page carries. */}
      <Definition of="lead" className="mt-1" />
      {/* The four states, once, under the actions. The strip carries the same
          line, so a state means one thing on both. */}
      <div data-testid="lead-legend" className="mt-1 text-[11px] text-faint">
        {autoHunt ? `${LEAD_LEGEND} ${LEGEND_AUTO_HUNT}` : LEAD_LEGEND}
      </div>
      {/* C2: why this is a lead, in one sentence. The header read the
          numbers of the scoring, and the analyst asked what happened. */}
      <div data-testid="lead-why" className="mt-1.5 text-[13px] text-text-2">
        {leadWhySentence(d)}
      </div>
      <div className="mt-0.5 flex flex-wrap items-center gap-2 text-[12px] text-dim">
        <span title={absTime(d.formed_at)}>formed {ago(d.formed_at)}</span>
        <span className="text-faint">·</span>
        <button
          type="button"
          aria-expanded={scoring}
          aria-controls="lead-scoring"
          onClick={() => setScoring((v) => !v)}
          className="text-accent hover:underline"
          title="Show the weights and the statistics that formed this lead."
        >
          {scoring ? 'Hide scoring' : 'Scoring'}
        </button>
      </div>
      {/* Two weights, two sentences. One decays and one is the record of a
          moment, and the line carried the decay sentence over both. The
          weights are the numbers of the scoring, so they sit behind it. */}
      {scoring && (
      <div id="lead-scoring" data-testid="lead-meta" className="mt-1 text-[12.5px] text-dim">
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
        · {plural(d.kinds.length, 'type')} · {entityCountWords(d.entities)}
      </div>
      )}
      {/* What the dismissal does next. The page said nothing, so an analyst
          could not tell whether the same observations form a lead tomorrow. */}
      {state === 'dismissed' && !closedByHunt(d) && (
        <div data-testid="lead-dismiss-effect" className="mt-2 text-[12.5px] text-text-2">
          {`Dismissed. ${dismissEffect(d.entities[0]?.[1] ?? null)}`}
        </div>
      )}
      {/* S3: the record of every hunt, beside the newest answer. The pill read
          the newest hunt alone and the timeline read "found no threat" over
          three earlier hunts that found one. */}
      {huntRecordSentence(d.hunts ?? []) && (
        <div data-testid="lead-hunt-record" className="mt-2 text-[12.5px] text-text-2">
          {huntRecordSentence(d.hunts ?? [])}
        </div>
      )}
      {/* W5: the newest hunt ran before some of the evidence arrived. The
          hold banner said the hunt could not read all evidence and did not
          say why. A closed lead offers no hunt, so it carries no line. */}
      {!closed && staleHuntSentence(d.hunts?.[0], d.observations) && (
        <div
          data-testid="lead-stale-hunt"
          className="mt-2 rounded-panel border px-3 py-2 text-[12.5px] text-warn"
          style={{ borderColor: 'rgba(210,153,34,.35)', background: 'rgba(210,153,34,.06)' }}
        >
          {staleHuntSentence(d.hunts?.[0], d.observations)}
        </div>
      )}
      {/* RH1: a hunt that answered clean and did not close the lead. The
          range closed a lead as clean after a re-hunt that could not read the
          alert documents, over two earlier hunts that found a threat. The
          lead now waits, and this line says why. */}
      {hunted && holdSentence(d) && (
        <div
          data-testid="lead-hold-reason"
          className="mt-2 rounded-panel border px-3 py-2 text-[12.5px] text-warn"
          style={{ borderColor: 'rgba(210,153,34,.35)', background: 'rgba(210,153,34,.06)' }}
        >
          {`The hunt did not close this lead. ${holdSentence(d)} Decide on the lead.`}
        </div>
      )}
      {/* A second hunt on one lead is a real thing to want and a common
          mis-click. The confirm names the hunt that already exists. */}
      {confirmAgain && (
        <div className="mt-3 flex flex-wrap items-center gap-2 rounded-panel border border-border bg-surface-1 p-3 text-[12.5px]">
          <span>
            A hunt on this lead already exists.{' '}
            {attached ? (
              <>
                Read{' '}
                <Link
                  to={`/hunts/${attached.id}`}
                  className="text-accent hover:underline"
                  title={`Hunt ${attached.id}`}
                >
                  {huntName(attached)}
                </Link>{' '}
                before you start another.
              </>
            ) : (
              'Read it before you start another.'
            )}
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
            onDone={() => {
              setDismissing(false);
              lead.refetch();
            }}
          />
        </div>
      )}
      {error && <div className="mt-2 text-[12px] text-danger">{error}</div>}

      {/* Every hunt this lead started. The page named one, from `hunt_id`, so a
          lead hunted twice showed the first hunt forever. */}
      {hunts.length > 0 && (
        <Panel className="mt-4">
          <PanelHeader title={`Hunts on this lead · ${hunts.length}`} />
          <ul data-testid="lead-hunts" className="divide-y divide-border-faint">
            {hunts.map((h) => (
              <li
                key={h.id}
                data-testid={`lead-hunt-${h.id}`}
                className="px-[15px] py-2.5 text-[12.5px]"
              >
                <div className="flex flex-wrap items-center gap-2.5">
                  {/* K5: the label states the type, the steps, the run time
                      and the threat findings. The id alone said nothing an
                      analyst can use, so it moves to the hover. */}
                  <Link
                    to={`/hunts/${h.id}`}
                    className="text-accent hover:underline"
                    title={`Open hunt ${h.id}.`}
                  >
                    {huntName(h)}
                  </Link>
                  {/* The screen word, with the sentence that states it. The
                      row printed the raw API word and explained nothing. */}
                  <span className="text-dim" title={huntStatusTitle(h.status, 'row')}>
                    {statusLabel(h.status)}
                  </span>
                  {/* The outcome, in the words and the colour of the one
                      label map. A threat is never green. */}
                  {rowOutcome(h, d) && (
                    <span
                      data-testid={`lead-hunt-outcome-${h.id}`}
                      {...chipProps(outcomeMeta(rowOutcome(h, d)))}
                    >
                      {rowOutcomeLabel(h, d)}
                    </span>
                  )}
                  {h.started_at && (
                    <span className="text-[11.5px] text-faint" title={absTime(h.started_at)}>
                      started {ago(h.started_at)}
                    </span>
                  )}
                </div>
                {/* W3: the hunt's answer, and what it could not check. The
                    analyst read a long narrative on the hunt page to decide. */}
                {h.answer && (
                  <div data-testid={`lead-hunt-answer-${h.id}`} className="mt-1 text-text-2">
                    <span className="font-semibold">Answer: </span>
                    {h.answer}
                  </div>
                )}
                {h.not_checked.length > 0 && (
                  <div data-testid={`lead-hunt-gaps-${h.id}`} className="mt-0.5 text-dim">
                    <span className="font-semibold">Not checked: </span>
                    {h.not_checked.join(' ')}
                  </div>
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
      <LeadTimeline lead={d} scoring={scoring} />
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
