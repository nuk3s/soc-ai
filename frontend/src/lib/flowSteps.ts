// ---------------------------------------------------------------------------
// The steps of the flow strip, from the real data of one object.
//
// The owner asked "What is the user flow?" (2026-10-07). Each detail page now
// carries one line that names where the object sits in the flow:
//
//   alert drawer, investigation page:  Alert → Investigation → Verdict → Action in Security Onion
//   lead page, lead hunt:              Hit → Lead → Hunt → Investigations → Verdicts → Actions
//   manual hunt:                       Objective → Hunt → Investigations → Verdicts → Actions
//
// A step is done, current, next or not yet. The current step is the object
// the page shows. A done step links to its object when the object has a page.
// The next step names the control that moves the flow to it, or names none
// when soc-ai does the work.
//
// Every rule reads stored fields. A step the data cannot prove is never done.
// ---------------------------------------------------------------------------

import { ACTION_VERB } from '../components/ActionCard';
import type { LeadDetail } from './api';
import { VERDICT_LABELS, type VerdictKey } from './labels';
import type { HuntDetailData, HuntFinding, Investigation } from './types';

export type FlowStepState = 'done' | 'current' | 'next' | 'not_yet';

/** One step of the flow strip. */
export interface FlowStep {
  /** A stable key: "alert", "hunt", "verdict". */
  key: string;
  /** A short noun: "Hunt", "Verdict". */
  label: string;
  state: FlowStepState;
  /** The page of the object. A done or current step links to it. */
  to?: string;
  /** On the next step: the control that moves the flow to this step. */
  control?: string;
  /** A short count or state after the noun: "2 of 3 done", "running". */
  note?: string;
  /** The hover sentence. */
  title?: string;
}

// ── The fields of the hunt investigation phase ─────────────────────────────
//
// A hunt investigates what it finds (owner, 2026-10-07). The server states the
// count on the hunt and the investigation on each finding. The fields ride
// beside the types and not inside them, the way lib/leadDecisions.ts carries
// the decision fields. An older server sends none of them, and the strip then
// reads the `investigation` block a finding already carries.

/** The fields the investigation phase adds to a hunt. */
export interface HuntInvestigationFields {
  findingsInvestigated?: number | null;
  findingsTotal?: number | null;
}

/** The fields the investigation phase adds to a finding. */
export interface FindingInvestigationFields {
  investigationId?: string | null;
  verdict?: string | null;
  investigationStatus?: string | null;
  pendingActions?: number | null;
}

export type FlowFinding = HuntFinding & FindingInvestigationFields;
export type FlowHunt = Omit<HuntDetailData, 'findings'> &
  HuntInvestigationFields & { findings: FlowFinding[] };

/** The investigation of one finding, in one shape. */
export interface FindingInvestigation {
  id: string;
  /** running, complete, error, cancelled or interrupted. */
  status: string;
  verdict: string | null;
  /** Recommended actions that wait for the analyst. Null when the server
   *  does not say. */
  pendingActions: number | null;
}

/** The status words of an investigation in flight. The hunt route says
 *  "running", the investigation route says "investigating". */
const IN_FLIGHT = new Set(['running', 'investigating', 'queued']);

/** The investigation of a finding, from the new fields or from the older
 *  `investigation` block. Null when the finding has none. */
export function findingInvestigation(f: FlowFinding): FindingInvestigation | null {
  const legacy = f.investigation ?? null;
  const id = f.investigationId ?? legacy?.id ?? null;
  if (!id) return null;
  const verdict = f.verdict ?? legacy?.verdict ?? null;
  const raw = f.investigationStatus ?? legacy?.status ?? (verdict ? 'complete' : 'running');
  return {
    id,
    status: IN_FLIGHT.has(raw) ? 'running' : raw,
    verdict,
    pendingActions: typeof f.pendingActions === 'number' ? f.pendingActions : null,
  };
}

/** The verdict in screen words: "true positive". */
function verdictNote(verdict: string): string {
  return (VERDICT_LABELS[verdict as VerdictKey]?.label ?? verdict.replace(/_/g, ' ')).toLowerCase();
}

/** The two verdicts the model committed to. */
const SETTLED = new Set(['true_positive', 'false_positive']);

/** The words of each write, "Acknowledge or Escalate to case", in the order the
 *  card lists them. */
function controlWords(tags: string[]): string {
  const verbs = [...new Set(tags.map((t) => ACTION_VERB[t as keyof typeof ACTION_VERB] ?? t))];
  return verbs.join(' or ');
}

/** The control of the settled bar, on a run that recommended no write. */
const SETTLED_BAR_CONTROL = controlWords(['ack', 'escalate']);

/** One next step at most. The first step a builder marked next keeps the
 *  mark, and a later one reads not yet, with no control: two next steps
 *  would name two controls for one move. */
function settle(steps: FlowStep[]): FlowStep[] {
  let nextSeen = false;
  return steps.map((s) => {
    if (s.state !== 'next') return s;
    if (!nextSeen) {
      nextSeen = true;
      return s;
    }
    return { key: s.key, label: s.label, state: 'not_yet', to: s.to, note: s.note };
  });
}

// ── The investigation ───────────────────────────────────────────────────────

export interface InvestigationFlowOptions {
  /** The run reached a terminal state with no verdict, or the client gave up
   *  on it. The page computes this, so the strip and the page agree. */
  failed?: boolean;
  /** An action of this run was executed in this tab, before the next read. */
  actedHere?: boolean;
  /** The run writes nothing: a backtest replay. */
  noWrites?: boolean;
}

/** The flow of one investigation, for the alert drawer and the page. */
export function investigationFlow(
  inv: Pick<
    Investigation,
    | 'kind'
    | 'status'
    | 'verdict'
    | 'actions'
    | 'alertAcked'
    | 'huntId'
    | 'subject'
    | 'supersededBy'
    | 'fallback'
    | 'id'
    | 'failure'
  >,
  opts: InvestigationFlowOptions = {},
): FlowStep[] {
  const fromHunt = inv.kind === 'hunt' || inv.subject?.type === 'hunt';
  const steps: FlowStep[] = [];
  if (fromHunt) {
    const leadId = inv.subject?.lead_id ?? null;
    if (leadId != null) {
      steps.push({ key: 'lead', label: 'Lead', state: 'done', to: `/leads/${leadId}` });
    }
    const huntId = inv.huntId ?? inv.subject?.hunt_id ?? null;
    steps.push({
      key: 'hunt',
      label: 'Hunt',
      state: 'done',
      to: huntId ? `/hunts/${encodeURIComponent(huntId)}` : undefined,
      title: 'The hunt that found the evidence of this investigation.',
    });
  } else {
    steps.push({
      key: 'alert',
      label: 'Alert',
      state: 'done',
      title: 'The alert that Security Onion raised.',
    });
  }

  const running = inv.status === 'investigating' && !opts.failed;
  const failed =
    !!opts.failed ||
    inv.status === 'error' ||
    inv.status === 'cancelled' ||
    inv.status === 'interrupted' ||
    !!inv.fallback ||
    (inv.status === 'complete' && inv.verdict === 'untriaged');
  steps.push({
    key: 'investigation',
    label: 'Investigation',
    state: 'current',
    note: running ? 'running' : failed ? 'no verdict' : undefined,
    title: 'This investigation. It ends in a verdict, recommended actions and an audit record.',
  });

  // The control that starts the run again. A hunt finding runs again from
  // its hunt: this page refuses a re-run of it.
  const again = fromHunt ? 'Open an investigation' : 'Re-run investigation';
  let verdict: FlowStep;
  if (running) {
    verdict = { key: 'verdict', label: 'Verdict', state: 'next', title: 'soc-ai reaches the verdict.' };
  } else if (failed) {
    verdict = inv.supersededBy
      ? { key: 'verdict', label: 'Verdict', state: 'next', title: 'A newer run replaced this one.' }
      : inv.status === 'error' && inv.failure?.permanent
        ? // The failure panel says no re-run can help, so the strip names no
          // Re-run either (R2-D4).
          {
            key: 'verdict',
            label: 'Verdict',
            state: 'next',
            title: 'A re-run cannot change the recorded cause.',
          }
        : { key: 'verdict', label: 'Verdict', state: 'next', control: again };
  } else if (!SETTLED.has(inv.verdict)) {
    verdict = inv.supersededBy
      ? // A newer run answered or replaced this one, and every action here is
        // off. The strip offered Request more info next to "Its actions are
        // off" (V1-A7).
        {
          key: 'verdict',
          label: 'Verdict',
          state: 'next',
          note: verdictNote(inv.verdict),
          title: 'A newer run replaced this one. Its actions are off.',
        }
      : {
          key: 'verdict',
          label: 'Verdict',
          state: 'next',
          note: verdictNote(inv.verdict),
          control: fromHunt ? again : 'Request more info',
        };
  } else {
    verdict = { key: 'verdict', label: 'Verdict', state: 'done', note: verdictNote(inv.verdict) };
  }
  steps.push(verdict);

  const action: FlowStep = { key: 'action', label: 'Action in Security Onion', state: 'not_yet' };
  if (verdict.state === 'done') {
    const pending = inv.actions.filter((a) => a.applied !== true && a.dismissed !== true);
    const applied =
      opts.actedHere || inv.actions.some((a) => a.applied === true) || inv.alertAcked === true;
    // A write other than the ack still waits. An acknowledged alert does not
    // settle an escalate: after an override to true positive the strip read
    // the old auto-ack as the action (R2-D22).
    const waiting = pending.filter((a) => a.tag !== 'ack');
    if (!opts.actedHere && !inv.supersededBy && waiting.length > 0) {
      action.state = 'next';
      action.control = controlWords(waiting.map((a) => a.tag));
    } else if (applied) {
      action.state = 'done';
    } else if (inv.supersededBy) {
      action.title = 'A newer run replaced this one. Its actions are off.';
    } else if (pending.length > 0) {
      action.state = 'next';
      action.control = controlWords(pending.map((a) => a.tag));
    } else if (inv.actions.length > 0) {
      // Every recommendation was dismissed. The decision is made, and
      // nothing went to Security Onion.
      action.state = 'done';
      action.note = 'none taken';
    } else if (!fromHunt && !opts.noWrites) {
      action.state = 'next';
      action.control = SETTLED_BAR_CONTROL;
    } else {
      action.note = 'none recommended';
    }
  }
  steps.push(action);
  return settle(steps);
}

// ── The hunt tail: Investigations, Verdicts, Actions ───────────────────────

/** The subject findings of a hunt: the threat findings. A run failure and a
 *  visibility gap name no evidence to investigate. */
function subjectFindings(findings: FlowFinding[]): FlowFinding[] {
  return findings.filter((f) => (f.category ?? 'threat') === 'threat');
}

const HUNT_STOPPED = new Set(['error', 'cancelled', 'interrupted']);

/** The finding the catalog composer writes for a query that failed. */
function isRunFailureFinding(f: FlowFinding): boolean {
  return f.category === 'visibility_gap' && (f.title ?? '').endsWith(': could not run');
}

/** A hunt that ended with no result: the server says could_not_run, or every
 *  finding records a failed query. Its stepper must not read as a clean hunt. */
function couldNotRun(hunt: FlowHunt): boolean {
  if (hunt.outcome === 'could_not_run') return true;
  const findings = hunt.findings ?? [];
  return findings.length > 0 && findings.every(isRunFailureFinding);
}

/** "1 of 2 findings": the subject findings whose investigation ended. The
 *  step counts findings, the way the hunt label does. Two findings can share
 *  one investigation, so the count of runs can be lower (R3-D4). */
function findingsNote(investigated: number, total: number): string {
  return `${investigated} of ${total === 1 ? '1 finding' : `${total} findings`}`;
}

/** The hover sentence when findings share an investigation, or undefined.
 *  "2 findings share 1 investigation." */
function sharedRunsTitle(findings: number, runs: number): string | undefined {
  if (runs <= 0 || runs >= findings) return undefined;
  return `${findings} findings share ${runs === 1 ? '1 investigation' : `${runs} investigations`}.`;
}

/** The step sentence when no open threat finding can start an investigation:
 *  each one cites no event. The card turns its control off for that reason,
 *  and the step offered the control the card refused (V1-H1). */
const NO_EVENT_TO_INVESTIGATE =
  'No threat finding without an investigation cites an event. An investigation needs at least one event.';

/** The investigations of a list of findings, once each. Two findings can
 *  share one investigation, and its actions wait once. */
function distinctRuns(invs: FindingInvestigation[]): FindingInvestigation[] {
  const seen = new Set<string>();
  return invs.filter((i) => {
    if (seen.has(i.id)) return false;
    seen.add(i.id);
    return true;
  });
}

/** The three steps after a finished hunt, from its findings. */
function huntTail(hunt: FlowHunt | null, retry: string): FlowStep[] {
  const investigations: FlowStep = { key: 'investigations', label: 'Investigations', state: 'not_yet' };
  const verdicts: FlowStep = { key: 'verdicts', label: 'Verdicts', state: 'not_yet' };
  const actions: FlowStep = { key: 'actions', label: 'Actions', state: 'not_yet' };
  if (!hunt) return [investigations, verdicts, actions];
  if (HUNT_STOPPED.has(hunt.status) || (hunt.status === 'complete' && couldNotRun(hunt))) {
    investigations.state = 'next';
    investigations.control = retry;
    return [investigations, verdicts, actions];
  }
  if (hunt.status === 'running') {
    // The server sends a plan count of 0 on a hunt that has not ended. The
    // findings arrive with the report.
    investigations.state = 'next';
    investigations.title = 'soc-ai investigates the findings when the hunt ends.';
    return [investigations, verdicts, actions];
  }
  const subject = subjectFindings(hunt.findings);
  const invs = subject.map(findingInvestigation);
  // A plan count of 0 beside threat findings is a hunt the server did not
  // plan: a hunt from before the phase, or one with the switch off. The
  // analyst opens each investigation by hand.
  const phase =
    typeof hunt.findingsTotal === 'number' && (hunt.findingsTotal > 0 || subject.length === 0);
  const total = phase ? (hunt.findingsTotal as number) : subject.length;
  const investigated =
    phase && typeof hunt.findingsInvestigated === 'number'
      ? hunt.findingsInvestigated
      : invs.filter((i) => i?.status === 'complete').length;
  if (total === 0) {
    // A finding that names no threat, an observation or a visibility gap,
    // gives the hunt nothing to investigate. The note says which case it is.
    const any = (hunt.findings ?? []).length > 0;
    investigations.note = any ? 'no threat finding' : 'no findings';
    investigations.title = any
      ? 'The hunt reported findings, and none names a threat to investigate.'
      : 'The hunt reported no findings.';
    return [investigations, verdicts, actions];
  }
  const done = invs.filter((i): i is FindingInvestigation => i?.status === 'complete');
  investigations.note = findingsNote(Math.min(investigated, total), total);
  if (investigated < total) {
    // The hunt investigates its findings. An older server does not, and the
    // analyst opens each investigation by hand.
    if (phase) {
      investigations.state = 'next';
      investigations.title = 'soc-ai investigates each threat finding.';
    } else if (subject.some((f) => !findingInvestigation(f) && (f.citations ?? []).length > 0)) {
      investigations.state = 'next';
      investigations.control = 'Open an investigation';
    } else {
      // Every open threat finding cites no event, and its card turns the
      // control off. The step names the reason and offers no control.
      investigations.title = NO_EVENT_TO_INVESTIGATE;
    }
    return [investigations, verdicts, actions];
  }
  investigations.state = 'done';
  const runs = distinctRuns(done);
  investigations.title = sharedRunsTitle(done.length, runs.length);
  if (runs.length === 1) investigations.to = `/investigation/${encodeURIComponent(runs[0].id)}`;
  verdicts.state = 'done';
  const threats = done.filter((i) => i.verdict === 'true_positive').length;
  verdicts.note = threats > 0 ? `${threats} of ${total} threats` : 'no threat confirmed';
  const known = runs.filter((i) => i.pendingActions !== null);
  const waiting = known.reduce((n, i) => n + (i.pendingActions ?? 0), 0);
  if (waiting > 0) {
    actions.state = 'next';
    actions.note = `${waiting} wait for you`;
    actions.control = SETTLED_BAR_CONTROL;
  } else if (known.length > 0 && known.length === runs.length) {
    actions.state = 'done';
    actions.note = 'none waiting';
  } else {
    actions.state = 'next';
    actions.control = 'View investigation';
    actions.title = 'Open each investigation to act on its verdict.';
  }
  return [investigations, verdicts, actions];
}

// ── The lead ────────────────────────────────────────────────────────────────

/** The flow of one lead, for the lead page. `hunt` is the newest hunt on the
 *  lead when the page could read it. */
export function leadFlow(
  lead: Pick<
    LeadDetail,
    'status' | 'hunt_id' | 'hunt_status' | 'hunt_queued' | 'investigation_id' | 'dismissed_reason'
  >,
  hunt: FlowHunt | null,
): FlowStep[] {
  const closedByHunt = lead.status === 'dismissed' && lead.dismissed_reason === 'hunt_clean';
  const dismissed = lead.status === 'dismissed' && !closedByHunt;
  const promoted = lead.status === 'promoted';
  const steps: FlowStep[] = [
    { key: 'hit', label: 'Hit', state: 'done', title: 'The hits and observations that formed this lead.' },
    {
      key: 'lead',
      label: 'Lead',
      state: 'current',
      note: dismissed ? 'dismissed' : closedByHunt || promoted ? 'closed' : undefined,
    },
  ];
  const huntTo = lead.hunt_id ? `/hunts/${encodeURIComponent(lead.hunt_id)}` : undefined;
  // An older server names the hunt and not its status. The lead status then
  // says whether it still runs.
  const status =
    lead.hunt_status ??
    (lead.status === 'hunting' ? 'running' : lead.hunt_id ? 'complete' : null);
  const huntStep: FlowStep = { key: 'hunt', label: 'Hunt', state: 'not_yet', to: huntTo };
  if (!lead.hunt_id) {
    huntStep.to = undefined;
    if (lead.hunt_queued) {
      huntStep.state = 'next';
      huntStep.note = 'queued';
      huntStep.title = "The lead's hunt starts within a minute.";
    } else if (!dismissed && !closedByHunt && !promoted) {
      huntStep.state = 'next';
      huntStep.control = 'Hunt this lead';
    }
  } else if (status === 'running') {
    huntStep.state = 'next';
    huntStep.note = 'running';
  } else if (status && HUNT_STOPPED.has(status)) {
    huntStep.state = 'next';
    huntStep.note = 'stopped';
    huntStep.control = 'Hunt again';
  } else {
    huntStep.state = 'done';
  }
  steps.push(huntStep);

  let tail: FlowStep[];
  const huntInvestigated = !!hunt && typeof hunt.findingsTotal === 'number' && hunt.findingsTotal > 0;
  if (promoted && huntInvestigated) {
    // The hunt investigated its findings and their verdicts closed the lead.
    // The hunt states each verdict and the actions that wait.
    tail = huntTail(hunt, 'Hunt again');
  } else if (promoted && lead.investigation_id) {
    // An analyst opened one investigation on the lead's hunt. The lead record
    // names it and not its verdict.
    tail = [
      {
        key: 'investigations',
        label: 'Investigations',
        state: 'done',
        to: `/investigation/${encodeURIComponent(lead.investigation_id)}`,
      },
      {
        key: 'verdicts',
        label: 'Verdicts',
        state: 'next',
        control: 'View investigation',
        title: 'Open the investigation to read its verdict.',
      },
      { key: 'actions', label: 'Actions', state: 'not_yet' },
    ];
  } else if (huntStep.state === 'done') {
    tail = hunt
      ? huntTail(hunt, 'Hunt again')
      : [
          {
            key: 'investigations',
            label: 'Investigations',
            state: 'next',
            control: 'Read hunt',
            title: 'Read the hunt to see the investigations of its findings.',
          },
          { key: 'verdicts', label: 'Verdicts', state: 'not_yet' },
          { key: 'actions', label: 'Actions', state: 'not_yet' },
        ];
  } else {
    tail = huntTail(null, 'Hunt again');
  }
  const chain = [...steps, ...tail];
  if (!dismissed) return settle(chain);
  // A dismissed lead moves again only after Reopen. The first step after the
  // lead that is not done is next, and it names Reopen. The steps after it
  // wait.
  const at = chain.findIndex((s, i) => i > 1 && s.state !== 'done');
  return chain.map((s, i) => {
    if (at < 0 || i < at) return s;
    if (i === at) return { key: s.key, label: s.label, state: 'next', control: 'Reopen' };
    return { key: s.key, label: s.label, state: 'not_yet' };
  });
}

// ── The hunt ────────────────────────────────────────────────────────────────

/** The first step of a hunt: what started it. */
function huntOrigin(hunt: Pick<FlowHunt, 'kind' | 'starter'>, leadId: number | null): FlowStep[] {
  if (leadId != null || hunt.kind === 'lead' || hunt.starter === 'lead') {
    return [
      { key: 'hit', label: 'Hit', state: 'done', title: 'The hits and observations that formed the lead.' },
      { key: 'lead', label: 'Lead', state: 'done', to: leadId != null ? `/leads/${leadId}` : undefined },
    ];
  }
  if (hunt.kind === 'scheduled' || hunt.starter === 'schedule') {
    return [{ key: 'schedule', label: 'Schedule', state: 'done' }];
  }
  if (hunt.kind === 'triggered' || hunt.starter === 'catalog') {
    return [{ key: 'analytic', label: 'Analytic', state: 'done' }];
  }
  return [{ key: 'objective', label: 'Objective', state: 'done', title: 'The objective an analyst typed.' }];
}

/** The flow of one hunt, for the hunt page. */
export function huntFlow(hunt: FlowHunt, leadId: number | null = null): FlowStep[] {
  const stopped = HUNT_STOPPED.has(hunt.status);
  const noRun = !stopped && hunt.status === 'complete' && couldNotRun(hunt);
  const phase = typeof hunt.findingsTotal === 'number';
  const investigating =
    hunt.status === 'investigating' ||
    (phase && hunt.status !== 'running' && !stopped &&
      (hunt.findingsInvestigated ?? 0) < (hunt.findingsTotal as number));
  const huntStep: FlowStep = {
    key: 'hunt',
    label: 'Hunt',
    state: 'current',
    note:
      hunt.status === 'running'
        ? 'running'
        : stopped
          ? 'stopped'
          : noRun
            ? 'could not run'
            : investigating
              ? 'investigating'
              : undefined,
    title: 'This hunt. It returns findings. soc-ai investigates each threat finding when the hunt ends.',
  };
  return settle([...huntOrigin(hunt, leadId), huntStep, ...huntTail(hunt, 'Re-hunt')]);
}
