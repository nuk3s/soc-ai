import { AlertTriangle, ChevronDown, ChevronRight, GitBranch, History, X } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';

import {
  ApiError,
  bulkDismissLeads,
  bulkDismissLeadsAgain,
  bulkHuntLeads,
  bulkReopenLeads,
  dismissLead,
  getLeadBulkHuntPlan,
  getLeadCount,
  getLeads,
  getNeedsYou,
  huntLead,
  reopenLead,
  type Lead,
  type LeadBulkHuntPlan,
  type LeadBulkPress,
  type LeadBulkResult,
  type LeadStatusFilter,
} from '../lib/api';
import { demoBlocked, useDemo } from '../lib/demo';
import { entityPath } from '../lib/entityPath';
import { kindLabel, sourceLabel, sourceTitle } from '../lib/kinds';
import { huntOutcome, outcomeLabel, outcomeMeta } from '../lib/labels';
import { formedFromBacktest } from '../lib/leadDecisions';
import { HUNT_AGAIN_CLOSE, moreEntityWords } from '../lib/leadWords';
import { plural } from '../lib/plural';
import { absTime, ago } from '../lib/timeRange';
import {
  ACTION_HUNT,
  ACTION_HUNT_NOW,
  ACTION_REOPEN,
  CHIP_ANALYTIC_MATCH,
  CHIP_CLOSED_BY_HUNT,
  CHIP_CLOSED_ON_VERDICTS,
  CHIP_DISMISS_REASON,
  CHIP_LEFT_TO_YOU,
  CHIP_NO_BENIGN_BASELINE,
  CHIP_ONE_SIGNAL_REPEATED,
  CHIP_RELATED,
  CHIP_SWEEPS,
  CLOSE_RULE,
  INVESTIGATION_GONE,
  LEADS_NOTE_AUTO_HUNT,
  LEGEND_AUTO_HUNT,
  PILL_CLOSED_BY_HUNT,
  PILL_CLOSED_ON_VERDICTS,
  LEAD_LEGEND,
  PILL_DISMISSED,
  PILL_HUNTED,
  PILL_HUNT_QUEUED,
  PILL_IN_PROGRESS,
  PILL_NEW,
  PILL_PROMOTED,
  TAB_ALL,
  TAB_CLOSED,
  TAB_IN_PROGRESS,
  TAB_NEEDS_DECISION,
  WEIGHT_AT_FORMATION,
} from '../lib/tooltips';
import { useAsync } from '../lib/useAsync';
import { useListSelection } from '../lib/useListSelection';
import { Checkbox } from './Controls';
import { Definition } from './Definition';
import { SelectionStrip } from './ListToolbar';
import { CollapseChevron } from './Panel';
import { LoadingInline } from './States';

// ---------------------------------------------------------------------------
// Leads — several observations that together are worth looking at.
//
// A lead is a hunt the system is proposing. The tabs read by what the analyst
// must do, not by what the record holds: Needs decision, In progress, Closed,
// All. The tab is a filter. The pill is the state. The actions follow the
// state. The lead page wears the same pill and the same action names, so it
// imports both from here.
//
// Shadow leads are shown with their flag rather than hidden: the design does
// not let anything here trigger a playbook before a shadow week has been read,
// and a week nobody can read is not a shadow week.
// ---------------------------------------------------------------------------

/** The block the chevron folds. The anchor `leads` stays on the strip, so a
 *  link still reaches the header of a folded section. */
const LEADS_BODY_ID = 'leads-body';

/** The live weight at which a lead forms (soc_ai/hunting/weight.py,
 *  DEFAULT_LEAD_THRESHOLD). The card states it beside the weight at formation,
 *  so the number has a scale (dogfood 2026-10-06). */
export const LEAD_FORMS_AT = 0.85;

/** One label per dismissal reason. The lead page reads the same map, so one
 *  reason reads the same word wherever an analyst meets it. */
export const REASON_LABEL: Record<string, string> = {
  expected_for_role: 'Expected for this role',
  known_change: 'A known change',
  benign_repeat: 'A benign repeat',
  bad_baseline: 'The baseline is wrong',
  authorized_test: 'Authorized test or scan',
  duplicate: 'Duplicate of another lead or investigation',
  bad_analytic_logic: 'The analytic logic is wrong',
  lab_host: 'Lab or test host',
  other: 'Other',
};

/** What a dismissal by an analyst does to the observations, in one line.
 *
 *  The store consumes the observations of a closed lead, and a repeat of one
 *  refreshes the same row, so the repeats stay on the closed lead. A new
 *  observation is a new row, and it can form a new lead at once. No time
 *  window applies. `entity` names the host or the account. */
export function dismissEffect(entity: string | null): string {
  const on = entity ? ` on ${entity}` : '';
  return (
    'The observations on this lead and their repeats form no new lead. ' +
    `A new observation${on} can form a new lead. Select Reopen to undo.`
  );
}

/** The reasons the server accepts. The strip has no lead detail to read them
 *  from, so it carries the list the route validates against. */
export const DISMISS_REASONS = Object.keys(REASON_LABEL);

/** The reason the grid-gap review writes on each hit it marks benign. No form
 *  offers it, and no lead takes it. The note names the gap and its hours. */
export const GRID_GAP_REASON = 'grid_gap';

/** The line on a hit or an observation that somebody marked benign: "Marked
 *  benign by jordan: A known change. It counts toward no lead." A mark of the
 *  grid-gap review states its note: "Grid gap from ... to ...". */
export function benignLine(mark: {
  dismissed_by?: string | null;
  dismissed_reason?: string | null;
  dismissed_note?: string | null;
}): string {
  const by = mark.dismissed_by ? ` by ${mark.dismissed_by}` : '';
  const reason =
    mark.dismissed_reason === GRID_GAP_REASON
      ? mark.dismissed_note || 'A grid gap'
      : (REASON_LABEL[mark.dismissed_reason ?? ''] ?? mark.dismissed_reason);
  return `Marked benign${by}: ${reason}. It counts toward no lead.`;
}

/** The reason the server writes when the settle rule closes a lead after a
 *  clean hunt. It is not in REASON_LABEL: the form never offers it, and the
 *  pill reads the sentence below instead of a reason. */
export const HUNT_CLEAN_REASON = 'hunt_clean';
/** The settle rule closes a lead on a clean hunt only, so the closure names
 *  that outcome in the words of lib/labels.ts. */
export const HUNT_CLOSED_OUTCOME = `${outcomeLabel('no_threat')}.`;
export const HUNT_CLOSED_LABEL = `Closed. ${HUNT_CLOSED_OUTCOME}`;
/** The hand the server signs that closure with reads as the product on screen. */
export const HUNT_CLOSED_ACTOR = 'soc-ai';

export function closedByHunt(lead: { status: string; dismissed_reason?: string | null }): boolean {
  return lead.status === 'dismissed' && lead.dismissed_reason === HUNT_CLEAN_REASON;
}

/** True when soc-ai closed the lead because every finding of its hunt has a
 *  verdict (R3-D5). The server sends the flag. A lead page with the history
 *  reads it from the newest close when the flag is absent. */
export function closedOnVerdicts(lead: {
  status: string;
  closed_by_hunt_verdicts?: boolean;
  decisions?: { action: string; by?: string | null; reason?: string | null }[];
}): boolean {
  if (lead.status !== 'promoted') return false;
  if (typeof lead.closed_by_hunt_verdicts === 'boolean') return lead.closed_by_hunt_verdicts;
  const close = [...(lead.decisions ?? [])].reverse().find((d) => d.action === 'promoted');
  return close?.by === SYSTEM_HUNT_ACTOR && close?.reason === 'finding_verdict';
}

/** The hand the server signs a close on the hunt's verdicts with. */
const SYSTEM_HUNT_ACTOR = 'system:hunt';

/** The pill words of a close on the hunt's verdicts: the verdict count when
 *  the server sends it. */
export function closedOnVerdictsLabel(label: string | null | undefined): string {
  const words = (label ?? '').trim().replace(/\.$/, '');
  return words ? `Closed. ${words}.` : `Closed. ${CLOSE_RULE}`;
}

/** The word each lead status wears on screen. The API values do not change:
 *  they stay open, hunting, dismissed and promoted. */
export const LEAD_STATUS_LABEL: Record<string, string> = {
  open: 'New',
  hunting: 'Hunting',
  dismissed: 'Closed',
  promoted: 'Closed',
};

/** The screen word for one lead status. An unknown status reads as itself. */
export function leadStatusLabel(status: string): string {
  return LEAD_STATUS_LABEL[status] ?? status.replace(/_/g, ' ');
}

/** A hunt that is still going. Any other status is a hunt that has stopped,
 *  and the lead is no longer waiting on it. This is the server's rule for
 *  `needs_decision` too, so the pill and the tab agree: a set of finished
 *  statuses drifted from it, and a cancelled or interrupted hunt sat on the
 *  Needs decision tab while the pill read "In progress" and hid every act. */
const HUNT_RUNNING = new Set(['running', 'queued']);

/** The five states of a lead. The state is what the pill says and what the
 *  actions follow. */
export type LeadState = 'new' | 'in_progress' | 'hunted' | 'dismissed' | 'promoted';

/** The state of one lead, from the record. A finished hunt reads Hunted:
 *  "Hunting" said the hunt was still running, so a lead that had already been
 *  answered sat in the strip and nobody read the answer. */
export function leadState(lead: {
  status: string;
  hunt_status?: string | null;
  hunt_id?: string | null;
}): LeadState {
  if (lead.status === 'dismissed') return 'dismissed';
  if (lead.status === 'promoted') return 'promoted';
  if (lead.hunt_status && !HUNT_RUNNING.has(lead.hunt_status)) return 'hunted';
  if (lead.status === 'hunting' || lead.hunt_status) return 'in_progress';
  return 'new';
}

/** The word on the pill. The outcome of a finished hunt rides beside Hunted,
 *  because "Hunted" alone left an analyst to open the hunt to learn whether it
 *  found anything. */
export const LEAD_STATE_LABEL: Record<LeadState, string> = {
  new: 'New',
  in_progress: 'In progress',
  hunted: 'Hunted',
  dismissed: 'Dismissed',
  promoted: 'Promoted',
};

const LEAD_STATE_TITLE: Record<LeadState, string> = {
  new: PILL_NEW,
  in_progress: PILL_IN_PROGRESS,
  hunted: PILL_HUNTED,
  dismissed: PILL_DISMISSED,
  promoted: PILL_PROMOTED,
};

const LEAD_STATE_STYLE: Record<LeadState, { color: string; border: string; background: string }> = {
  new: { color: '#4b8bf5', border: 'rgba(75,139,245,.45)', background: 'rgba(75,139,245,.10)' },
  in_progress: {
    color: '#4b8bf5',
    border: 'rgba(75,139,245,.45)',
    background: 'rgba(75,139,245,.10)',
  },
  // The colour of a lead whose hunt outcome is not on record. A known outcome
  // reads its colour from lib/labels.ts, so a threat is never green.
  hunted: { color: '#3fb950', border: 'rgba(63,185,80,.45)', background: 'rgba(63,185,80,.10)' },
  dismissed: { color: '#8b949e', border: 'rgba(139,148,158,.45)', background: 'rgba(139,148,158,.10)' },
  promoted: { color: '#a371f7', border: 'rgba(163,113,247,.45)', background: 'rgba(163,113,247,.10)' },
};

/** True when the loop owns this lead's next move. Auto-hunt is on, the lead
 *  has never been hunted, and the hunt starts within a minute. Nothing waits
 *  on the analyst, and a bare New pill said the opposite. */
export function huntQueued(lead: { status: string; hunt_queued?: boolean; hunt_status?: string | null; hunt_id?: string | null }): boolean {
  return lead.hunt_queued === true && leadState(lead) === 'new';
}

/** The word beside the pill on a lead the loop leaves to the analyst. */
export const LEFT_TO_YOU_LABEL = 'left to you';

/** True when the loop starts no hunt on this lead while the setting is on.
 *
 *  The loop takes every new lead but three: a shadow lead, a reopened lead and
 *  a lead with no documents. The server states which by sending `hunt_queued`
 *  false on a lead it will not take, so the rule reads the flag rather than
 *  working the three exclusions out again on the screen.
 *
 *  With the setting off the loop leaves every lead, and a chip on all of them
 *  says nothing about any one of them. */
export function leftToYou(
  lead: { status: string; hunt_queued?: boolean; hunt_id?: string | null },
  autoHunt: boolean,
): boolean {
  return autoHunt && lead.hunt_queued === false && lead.status === 'open' && !lead.hunt_id;
}

/** The words the pill states for a lead whose newest hunt found no threat
 *  while an earlier hunt on the same lead found one. */
export const EARLIER_THREAT_LABEL = 'An earlier hunt found a threat';

/** True when an earlier hunt on the lead found a threat and the newest did not.
 *  The pill read the newest hunt alone, so a lead that held a true-positive
 *  exploit read "No threat observed" in green. The worst outcome on record
 *  wins. */
export function earlierThreat(lead: {
  hunt_threat_count?: number;
  hunt_outcome?: string | null;
}): boolean {
  return (
    (lead.hunt_threat_count ?? 0) > 0 && huntOutcome({ outcome: lead.hunt_outcome }) !== 'threat_found'
  );
}

/** The state pill of one lead. The strip and the lead page render this one
 *  component, so a lead never wears two different words. */
export function LeadStatePill({
  lead,
}: {
  lead: {
    status: string;
    hunt_status?: string | null;
    hunt_id?: string | null;
    hunt_outcome_label?: string | null;
    hunt_outcome?: string | null;
    hunt_threat_count?: number;
    hunt_queued?: boolean;
    dismissed_reason?: string | null;
    closed_by_hunt_verdicts?: boolean;
    decisions?: { action: string; by?: string | null; reason?: string | null }[];
  };
}) {
  const state = leadState(lead);
  const queued = huntQueued(lead);
  const byHunt = closedByHunt(lead);
  const onVerdicts = closedOnVerdicts(lead);
  // The outcome of the attached hunt, in the words and the colour of the one
  // label map. An earlier threat on record outranks a newer clean answer.
  const key = huntOutcome({ status: lead.hunt_status, outcome: lead.hunt_outcome });
  const worst = state === 'hunted' && earlierThreat(lead);
  const toned =
    (state === 'hunted' || onVerdicts) && (worst || key)
      ? outcomeMeta(worst ? 'threat_found' : key)
      : null;
  const style = toned
    ? { color: toned.color, border: toned.border, background: toned.bg }
    : LEAD_STATE_STYLE[state];
  // The tail of the pill names who holds the lead next. A finished hunt names
  // the worst outcome on record. A queued hunt names the loop. A closure by
  // the rule is one sentence, with no tail. An older server sends the label
  // alone, and the pill then prints it.
  const outcomeWords = worst
    ? EARLIER_THREAT_LABEL
    : key
      ? outcomeLabel(key)
      : lead.hunt_outcome_label;
  const outcome = state === 'hunted' && outcomeWords ? ` · ${outcomeWords}` : '';
  const tail = byHunt || onVerdicts ? '' : queued ? ' · hunt queued' : outcome;
  const title = byHunt
    ? PILL_CLOSED_BY_HUNT
    : onVerdicts
      ? PILL_CLOSED_ON_VERDICTS
      : queued
        ? PILL_HUNT_QUEUED
        : LEAD_STATE_TITLE[state];
  return (
    <span
      data-testid="lead-status"
      data-lead-state={state}
      title={title}
      className="inline-flex flex-none items-center gap-1.5 rounded-chip border px-1.5 py-px text-[10.5px] font-medium"
      style={{ color: style.color, borderColor: style.border, background: style.background }}
    >
      <span className="h-[5px] w-[5px] rounded-full" style={{ background: style.color }} />
      {byHunt
        ? HUNT_CLOSED_LABEL
        : onVerdicts
          ? closedOnVerdictsLabel(lead.hunt_outcome_label)
          : LEAD_STATE_LABEL[state]}
      {tail}
    </span>
  );
}

/** The hover of the backtest chip, in the words of the mark the server stores. */
export const CHIP_FORMED_FROM_BACKTEST =
  'This lead formed from a backtest replay. A backtest replay is a measurement on an alert ' +
  'an analyst already closed. It is not live evidence.';

/** A grey chip on a lead that formed from backtest replays only. The strip and
 *  the lead page render this one chip. */
export function FormedFromBacktestChip({ testId }: { testId?: string }) {
  return (
    <span
      data-testid={testId ?? 'lead-backtest-chip'}
      title={CHIP_FORMED_FROM_BACKTEST}
      className="inline-flex flex-none items-center gap-1 whitespace-nowrap rounded-chip border border-border-strong bg-surface-2 px-1.5 py-px text-[10.5px] font-medium text-dim"
    >
      <History size={10} strokeWidth={2.5} />
      Formed from a backtest replay
    </span>
  );
}

/** The name of each action on a lead. The strip and the lead page read the
 *  same words: "Start a hunt" here and "Hunt this lead" there taught an analyst
 *  that the two screens did different things.
 *
 *  A lead offers no "Open an investigation". The hunt investigates what it
 *  finds, so the one manual control of that name sits on a finding with no
 *  investigation (owner, 2026-10-07). "Promote" beside "Hunt" read as two
 *  words for one act. */
export const LEAD_ACTION = {
  hunt: 'Hunt this lead',
  /** The same act on a lead whose hunt the loop already owns. The word is
   *  different because the act is: it does not wait for the loop. */
  huntNow: 'Hunt now',
  dismiss: 'Dismiss',
  viewHunt: 'View hunt',
  readHunt: 'Read hunt',
  huntAgain: 'Hunt again',
  reopen: 'Reopen',
  /** A link to an investigation that exists. "Open investigation" sat one
   *  article away from the control that starts one. */
  viewInvestigation: 'View investigation',
} as const;

/** What a promoted lead reads in place of the View investigation link when the
 *  investigation it names has gone. A label, not a sentence, so it sits with
 *  the other action words; its sentence is `INVESTIGATION_GONE`. */
export const INVESTIGATION_GONE_LABEL = 'The investigation no longer exists';

/** The actions a New lead offers while its hunt sits in the loop's queue.
 *  Hunt drops to a secondary act under its own word, because the hunt is
 *  already coming and this button only makes it come sooner. */
export const LEAD_QUEUED_ACTIONS: string[] = [LEAD_ACTION.dismiss, LEAD_ACTION.huntNow];

/** The actions each state offers, in the order they are read. */
export const LEAD_STATE_ACTIONS: Record<LeadState, string[]> = {
  new: [LEAD_ACTION.hunt, LEAD_ACTION.dismiss],
  in_progress: [LEAD_ACTION.viewHunt],
  hunted: [LEAD_ACTION.readHunt, LEAD_ACTION.dismiss, LEAD_ACTION.huntAgain],
  dismissed: [LEAD_ACTION.reopen],
  promoted: [LEAD_ACTION.reopen, LEAD_ACTION.viewInvestigation],
};

/** The four tabs, in the order an analyst reads them: what waits on a
 *  decision, what is being worked, what is finished, everything. */
export type LeadTab = 'needs_decision' | 'in_progress' | 'closed' | 'all';

export const LEAD_TABS: { id: LeadTab; label: string; title: string }[] = [
  { id: 'needs_decision', label: 'Needs decision', title: TAB_NEEDS_DECISION },
  { id: 'in_progress', label: 'In progress', title: TAB_IN_PROGRESS },
  { id: 'closed', label: 'Closed', title: TAB_CLOSED },
  { id: 'all', label: 'All', title: TAB_ALL },
];

const isLeadTab = (v: unknown): v is LeadTab => LEAD_TABS.some((t) => t.id === v);

/** One line under the tabs. The four words are a taxonomy, and a taxonomy
 *  nobody can read is a filter an analyst guesses at. */
export const STATUS_LEGEND = LEAD_LEGEND;

/** The legend, with the sentence auto-hunt adds. With the loop on, New no
 *  longer means "hunt it": it means the hunt is coming. */
export function statusLegend(autoHunt: boolean): string {
  return autoHunt ? `${STATUS_LEGEND} ${LEGEND_AUTO_HUNT}` : STATUS_LEGEND;
}

/**
 * Whether the auto-hunt loop is running, read from the leads themselves.
 *
 * `GET /config` carries the `lead_auto_hunt` setting, and it is an admin-only
 * route: an analyst's Hunts page would spend a guaranteed 403 on every load to
 * learn one boolean. So the strip reads the leads it already has. A lead that
 * carries `hunt_queued` is a lead the loop has taken, which only happens while
 * the setting is on.
 *
 * The derivation is one-way on purpose. A queued lead proves the loop runs. No
 * queued lead proves nothing, because the loop may simply have caught up, so
 * the legend keeps its standing words rather than claiming the setting is off.
 */
export function autoHuntOn(leads: readonly { hunt_queued?: boolean }[]): boolean {
  return leads.some((l) => l.hunt_queued === true);
}

/** The older status word, kept for the surfaces that have not moved to the
 *  pill yet. A new surface renders `LeadStatePill` instead: the pill states the
 *  state, the outcome and the sentence that explains both. */
export function leadRowStatus(lead: { status: string; hunt_status?: string | null }): string {
  if (lead.hunt_status && !HUNT_RUNNING.has(lead.hunt_status)) return 'Hunted';
  return leadStatusLabel(lead.status);
}

const EMPTY_STATE: Record<LeadTab, string> = {
  needs_decision:
    'No lead waits on a decision. Every lead is under a hunt, or closed, or none has formed.',
  in_progress: 'No hunt is running on a lead.',
  closed: 'No closed leads. No analyst closed a lead, and soc-ai closed none.',
  all: 'No leads. No entity has observations of two types, a finding, or a repeated single type.',
};

/** The scope of each tab, in visible words. The Hunts page and the host page
 *  both have a time filter, and the leads follow neither: a backlog keeps its
 *  full scope. The two tabs of open work say "all open". The two tabs that
 *  hold closed leads say "all time". */
export const TAB_SCOPE: Record<LeadTab, string> = {
  needs_decision: 'all open',
  in_progress: 'all open',
  closed: 'all time',
  all: 'all time',
};

/** The count beside the heading, in the tab's own word. */
function countText(tab: LeadTab, n: number): string {
  if (tab === 'needs_decision') return `${n} ${n === 1 ? 'needs' : 'need'} a decision`;
  if (tab === 'in_progress') return `${n} in progress`;
  if (tab === 'closed') return plural(n, 'closed lead');
  return plural(n, 'lead');
}

const HEADING_TITLE =
  'A lead forms in three cases. Two or more types reach a live weight of 0.85. One finding ' +
  'has no benign baseline. One type repeats to a stacked weight of 1.5, and the lead is marked ' +
  'one signal, repeated.';

/** The sentence for one observation kind that Frame 7 names. */
const KIND_TITLE: Record<string, string> = {
  catalog_match: CHIP_ANALYTIC_MATCH,
  prior_no_baseline: CHIP_NO_BENIGN_BASELINE,
};

/**
 * The reason form for a dismissal, in place.
 *
 * The strip sent the analyst to the lead page for this. Clearing three benign
 * leads then meant leaving the strip three times and coming back to it three
 * times. The lead page mounts the same form.
 */
/** A threat the lead's hunt found, for the Dismiss form. `titles` names the
 *  open threat findings when the page holds the hunt. The strip holds only
 *  the outcome, so its list is empty. */
export interface DismissThreat {
  huntId: string | null;
  titles: string[];
}

/** The warning above a dismissal of a lead whose hunt found a threat
 *  (R3-I4). Dismiss does not close the finding. */
export function dismissThreatText(threat: DismissThreat): string {
  const [first, ...rest] = threat.titles;
  const named = first
    ? `The hunt of this lead found a threat: ${first.replace(/\.$/, '')}.${
        rest.length ? ` It found ${plural(rest.length, 'more threat finding')}.` : ''
      }`
    : 'The hunt of this lead found a threat.';
  return `${named} Dismiss closes the lead. The threat finding stays open on the hunt.`;
}

/** The titles of the open threat findings of a hunt: a threat finding whose
 *  investigation did not clear it as a false positive. */
export function openThreatTitles(
  findings: readonly {
    title: string;
    category?: string;
    verdict?: string | null;
    investigation?: { verdict?: string | null } | null;
  }[],
): string[] {
  return findings
    .filter((f) => (f.category ?? 'threat') === 'threat')
    .filter((f) => (f.verdict ?? f.investigation?.verdict ?? null) !== 'false_positive')
    .map((f) => f.title);
}

/** True when a hunt on the lead found a threat: the attached hunt, or an
 *  earlier one. */
export function leadFoundThreat(lead: {
  hunt_outcome?: string | null;
  hunt_threat_count?: number;
}): boolean {
  if ((lead.hunt_threat_count ?? 0) > 0) return true;
  const key = huntOutcome({ outcome: lead.hunt_outcome });
  return key === 'threat_found' || key === 'threats_confirmed';
}

export function DismissLeadForm({
  leadId,
  reasons,
  onDone,
  onCancel,
  threat,
}: {
  leadId: number;
  reasons: string[];
  onDone: () => void;
  /** Escape closes the form (R3-D14). */
  onCancel?: () => void;
  /** The threat the lead's hunt found. The form names it before the
   *  analyst confirms. */
  threat?: DismissThreat | null;
}) {
  // No reason is chosen when the form opens. The form chose "A benign repeat"
  // after a clean hunt, and one click then dismissed a lead with a reason the
  // analyst had not read.
  const [reason, setReason] = useState('');
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);
  const selectId = `dismiss-reason-${leadId}`;

  const confirm = async () => {
    setBusy(true);
    setFailed(null);
    try {
      await dismissLead(leadId, reason, note || undefined);
      onDone();
    } catch (e) {
      setFailed(e instanceof Error ? e.message : 'The lead was not dismissed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="flex flex-wrap items-center gap-2 text-[12.5px]"
      onKeyDown={(e) => {
        if (e.key === 'Escape' && onCancel) {
          e.stopPropagation();
          onCancel();
        }
      }}
    >
      {threat && (
        <div data-testid="dismiss-threat-warning" className="basis-full text-[12px] text-warn">
          {dismissThreatText(threat)}{' '}
          {threat.huntId && (
            <Link to={`/hunts/${encodeURIComponent(threat.huntId)}`} className="font-semibold text-accent hover:underline">
              Open the hunt
            </Link>
          )}
        </div>
      )}
      <label htmlFor={selectId}>Reason</label>
      <select
        id={selectId}
        // The form opens on a click, and the keyboard lands in it, so Escape
        // closes it at once.
        autoFocus
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        className="rounded-control border border-border bg-surface-2 px-2 py-1"
      >
        <option value="">Choose a reason</option>
        {reasons.map((r) => (
          <option key={r} value={r}>
            {REASON_LABEL[r] ?? r}
          </option>
        ))}
      </select>
      <input
        value={note}
        onChange={(e) => setNote(e.target.value)}
        placeholder="Note, optional"
        className="min-w-[200px] flex-1 rounded-control border border-border bg-surface-2 px-2 py-1"
      />
      <button
        type="button"
        disabled={!reason || busy}
        onClick={confirm}
        className="rounded-control bg-accent px-3 py-1 font-semibold text-white disabled:opacity-50"
      >
        Confirm dismiss
      </button>
      {onCancel && (
        <button type="button" onClick={onCancel} className="text-dim hover:text-text">
          Cancel
        </button>
      )}
      {failed && <span className="text-[11.5px] text-danger">{failed}</span>}
    </div>
  );
}

const ACTION_CLASS =
  'rounded-control border border-border-strong px-2 py-1 text-[11.5px] font-semibold hover:bg-surface-2 disabled:opacity-50';
const PRIMARY_CLASS =
  'rounded-control bg-accent px-2 py-1 text-[11.5px] font-semibold text-white disabled:opacity-50';
const LINK_CLASS = 'text-[11.5px] font-semibold text-accent underline hover:opacity-80';

function LeadRow({
  lead,
  autoHunt,
  onChanged,
  selectable = false,
  selected = false,
  onToggleSelect,
}: {
  lead: Lead;
  /** Whether the loop runs. A lead the loop leaves says so beside its pill,
   *  and only a deployment whose loop runs has such a lead. */
  autoHunt: boolean;
  onChanged: () => void;
  /** The Hunts page selects leads for a bulk press. A host page does not. */
  selectable?: boolean;
  selected?: boolean;
  onToggleSelect?: () => void;
}) {
  const primary = lead.entities[0];
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [dismissing, setDismissing] = useState(false);
  const [confirmAgain, setConfirmAgain] = useState(false);
  // Escape closes the confirm, and the focus goes back to Hunt again
  // (V1-H4). The Dismiss form beside it closed on Escape already.
  const huntAgainRef = useRef<HTMLButtonElement>(null);
  const closeConfirm = () => {
    setConfirmAgain(false);
    huntAgainRef.current?.focus();
  };
  const [failed, setFailed] = useState<string | null>(null);
  const state = leadState(lead);
  const queued = huntQueued(lead);
  const huntPath = lead.hunt_id ? `/hunts/${lead.hunt_id}` : `/leads/${lead.id}`;

  const run = async (work: () => Promise<void>, message: string) => {
    setBusy(true);
    setFailed(null);
    try {
      await work();
    } catch (e) {
      // The house refusal shape is {reason, hint}, and the hint is the
      // sentence written for the analyst. The row printed its own "Try again."
      // over it, which told the analyst to repeat the act the server had just
      // refused and named the reason for.
      setFailed(e instanceof ApiError && e.reason ? e.message : message);
    } finally {
      setBusy(false);
    }
  };

  // The strip starts the hunt and opens it.
  const hunt = () =>
    run(async () => {
      const r = await huntLead(lead.id);
      navigate(`/hunts/${r.hunt_id}`);
    }, 'The hunt did not start. Try again.');

  const reopen = () =>
    run(async () => {
      await reopenLead(lead.id);
      onChanged();
    }, 'The lead was not reopened. Try again.');

  // The words the type chips on this card already say.
  const typeChipWords = new Set(lead.kinds.map((k, i) => kindLabel(k, lead.kind_labels?.[i])));

  return (
    <li
      className="flex flex-wrap items-center gap-x-3 gap-y-1 px-[15px] py-2.5 text-[13px]"
      data-testid={`lead-${lead.id}`}
    >
      {/* The checkbox of the bulk press. A button with the checkbox role, as
          on the other lists: Tab reaches it and space toggles it. */}
      {selectable && (
        <Checkbox
          checked={selected}
          onChange={() => onToggleSelect?.()}
          aria-label={`Select lead ${lead.id}`}
          title="Select this lead for a bulk action."
        />
      )}
      {primary && (
        <Link
          to={entityPath(primary[0], primary[1])}
          className="font-mono text-[12.5px] font-semibold text-accent hover:underline"
        >
          {primary[1]}
        </Link>
      )}
      <Link to={`/leads/${lead.id}`} className="text-[11.5px] text-accent hover:underline">
        Lead {lead.id}
      </Link>
      {/* The pill is the state. The tab is a filter. */}
      <LeadStatePill lead={lead} />
      {/* A replay is a measurement on an alert an analyst already closed. A
          lead it formed reads as live work without the mark. */}
      {formedFromBacktest(lead) && <FormedFromBacktestChip testId={`lead-backtest-chip-${lead.id}`} />}
      {/* The note above says the loop starts a hunt on every new lead but
          three. This is the row that carries one of the three, and without it
          the analyst waits for a hunt that never comes. */}
      {leftToYou(lead, autoHunt) && (
        <span
          data-testid={`lead-left-to-you-${lead.id}`}
          className="rounded-chip border border-border-faint px-1.5 py-px text-[10.5px] text-faint"
          title={CHIP_LEFT_TO_YOU}
        >
          {LEFT_TO_YOU_LABEL}
        </span>
      )}
      {closedByHunt(lead) || closedOnVerdicts(lead) ? (
        <span
          className="rounded-chip border border-border-faint px-1.5 py-px text-[10.5px] text-faint"
          title={closedByHunt(lead) ? CHIP_CLOSED_BY_HUNT : CHIP_CLOSED_ON_VERDICTS}
        >
          closed by {HUNT_CLOSED_ACTOR}
        </span>
      ) : (
        lead.status === 'dismissed' &&
        lead.dismissed_reason && (
          <span
            className="rounded-chip border border-border-faint px-1.5 py-px text-[10.5px] text-faint"
            title={CHIP_DISMISS_REASON}
          >
            reason: {REASON_LABEL[lead.dismissed_reason] ?? lead.dismissed_reason}
          </span>
        )
      )}
      {lead.entities.length > 1 && (
        <span className="text-[11.5px] text-dim">
          {/* K6: counted by what they are. "entity" is the data model. */}
          and {moreEntityWords(lead.entities.slice(1))}
        </span>
      )}
      {/* One entity is one lead, and a coordinated attack is several leads. The
          chip is the only place on the strip that says so, and it links to the
          page that names each one. */}
      {(lead.related_count ?? 0) > 0 && (
        <Link
          data-testid={`lead-related-${lead.id}`}
          to={`/leads/${lead.id}`}
          title={CHIP_RELATED}
          className="rounded-chip border border-border-strong bg-surface-2 px-1.5 py-px text-[10.5px] text-accent hover:underline"
        >
          +{lead.related_count} related
        </Link>
      )}
      <span className="flex flex-wrap gap-1">
        {lead.kinds.map((k, i) => (
          <span
            key={k}
            title={KIND_TITLE[k]}
            className="rounded-chip border border-border-strong bg-surface-2 px-1.5 py-px text-[10.5px] text-text-2"
          >
            {kindLabel(k, lead.kind_labels?.[i])}
          </span>
        ))}
      </span>
      {lead.single_signal && (
        <span
          className="rounded-chip border border-border-strong bg-surface-2 px-1.5 py-px text-[10.5px] text-dim"
          title={CHIP_ONE_SIGNAL_REPEATED}
        >
          one signal, repeated
        </span>
      )}
      <span className="font-mono text-[11px] text-dim" title={WEIGHT_AT_FORMATION}>
        weight at formation {lead.weight_at_formation.toFixed(2)} · a lead forms at{' '}
        {LEAD_FORMS_AT.toFixed(2)}
      </span>
      <span
        className="text-[11.5px] text-dim"
        title={lead.formed_at ? absTime(lead.formed_at) : undefined}
      >
        formed {ago(lead.formed_at)}
      </span>
      {lead.shadow && (
        <span
          className="rounded-chip border px-1.5 py-px text-[10.5px] font-medium"
          style={{
            color: '#d29922',
            borderColor: 'rgba(210,153,34,.35)',
            background: 'rgba(210,153,34,.09)',
          }}
          title="Recorded in shadow. No hunt starts from this lead by itself."
        >
          shadow
        </span>
      )}

      {/* The actions follow the state. A lead already under a hunt offered
          "Hunt this lead", which starts a second one. A closed lead offered
          actions the server answers 409 to. */}
      <span className="ml-auto flex items-center gap-2">
        {/* A queued lead is one the loop has taken. The analyst closes it,
            and Hunt drops to a secondary act under its own word for the case
            where the loop is behind. */}
        {state === 'new' && queued && (
          <>
            <button
              type="button"
              disabled={busy}
              onClick={() => setDismissing((v) => !v)}
              className={ACTION_CLASS}
            >
              {LEAD_ACTION.dismiss}
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={hunt}
              title={ACTION_HUNT_NOW}
              className={ACTION_CLASS}
            >
              {LEAD_ACTION.huntNow}
            </button>
          </>
        )}
        {state === 'new' && !queued && (
          <>
            <button
              type="button"
              disabled={busy}
              onClick={hunt}
              title={ACTION_HUNT}
              className={PRIMARY_CLASS}
            >
              {LEAD_ACTION.hunt}
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() => setDismissing((v) => !v)}
              className={ACTION_CLASS}
            >
              {LEAD_ACTION.dismiss}
            </button>
          </>
        )}
        {state === 'in_progress' && (
          <Link to={huntPath} className={LINK_CLASS}>
            {LEAD_ACTION.viewHunt}
          </Link>
        )}
        {state === 'hunted' && (
          <>
            <Link to={huntPath} className={LINK_CLASS}>
              {LEAD_ACTION.readHunt}
            </Link>
            <button
              type="button"
              disabled={busy}
              onClick={() => setDismissing((v) => !v)}
              className={ACTION_CLASS}
            >
              {LEAD_ACTION.dismiss}
            </button>
            <button
              ref={huntAgainRef}
              type="button"
              disabled={busy}
              onClick={() => setConfirmAgain(true)}
              className={ACTION_CLASS}
            >
              {LEAD_ACTION.huntAgain}
            </button>
          </>
        )}
        {(state === 'dismissed' || state === 'promoted') && (
          <button
            type="button"
            disabled={busy}
            onClick={reopen}
            title={ACTION_REOPEN}
            className={ACTION_CLASS}
          >
            {LEAD_ACTION.reopen}
          </button>
        )}
        {/* A link goes to a page. This lead kept the id of an investigation the
            store no longer holds, so the link promised a page and landed on
            "No such investigation". Where there is no page there is no link. */}
        {state === 'promoted' &&
          lead.investigation_id &&
          (lead.investigation_exists === false ? (
            <span className="text-[11.5px] text-dim" title={INVESTIGATION_GONE}>
              {INVESTIGATION_GONE_LABEL}
            </span>
          ) : (
            <Link
              to={`/investigation/${encodeURIComponent(lead.investigation_id)}`}
              className={LINK_CLASS}
            >
              {LEAD_ACTION.viewInvestigation}
            </Link>
          ))}
      </span>
      {failed && <span className="basis-full text-[11.5px] text-danger">{failed}</span>}
      {/* A second hunt on one lead is a real thing to want and a common
          mis-click. The confirm names the hunt that already exists. */}
      {confirmAgain && (
        <div
          className="basis-full pt-1.5 text-[12.5px]"
          onKeyDown={(e) => {
            if (e.key !== 'Escape') return;
            e.stopPropagation();
            closeConfirm();
          }}
        >
          <span className="mr-2" data-testid={`lead-hunt-again-confirm-${lead.id}`}>
            This lead has a hunt. Read{' '}
            <Link to={huntPath} className="text-accent hover:underline">
              that hunt
            </Link>{' '}
            first. {HUNT_AGAIN_CLOSE}
          </span>
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              setConfirmAgain(false);
              void hunt();
            }}
            className={PRIMARY_CLASS}
          >
            Start another hunt
          </button>
          {/* The keyboard lands on Cancel, so Enter starts nothing and
              Escape closes the confirm. */}
          <button type="button" autoFocus className="ml-2 text-dim" onClick={closeConfirm}>
            Cancel
          </button>
        </div>
      )}
      {dismissing && (
        <div className="basis-full pt-1.5">
          <DismissLeadForm
            leadId={lead.id}
            reasons={DISMISS_REASONS}
            threat={leadFoundThreat(lead) ? { huntId: lead.hunt_id ?? null, titles: [] } : null}
            onCancel={() => setDismissing(false)}
            onDone={() => {
              setDismissing(false);
              onChanged();
            }}
          />
        </div>
      )}
      {lead.observations.length > 0 && (
        <ul className="basis-full pl-1 text-[11.5px] leading-[1.6] text-dim">
          {lead.observations.slice(0, 4).map((o, i) => (
            <li
              key={i}
              className="break-words"
              title={
                o.occurrences > 1
                  ? `${o.summary ?? ''} ${CHIP_SWEEPS}`.trim()
                  : (o.summary ?? undefined)
              }
            >
              ·{' '}
              {/* The source chip, unless the card already wears the word as a
                  type chip. "alert" read twice, one line apart (dogfood
                  2026-10-06). */}
              {!typeChipWords.has(sourceLabel(o.source, o.shadow)) && (
                <span
                  data-testid="lead-observation-source"
                  className="mr-1 rounded-chip border border-border-faint px-1 text-[10px] text-faint"
                  title={sourceTitle(o.source, o.shadow)}
                >
                  {sourceLabel(o.source, o.shadow)}
                </span>
              )}
              {/* The summary ends in a stop. The sweep count follows it with a
                  comma, so drop the stop and the line does not read "days., seen". */}
              {o.occurrences > 1 && o.summary
                ? o.summary.replace(/\.\s*$/, '')
                : (o.summary ?? kindLabel(o.kind, o.kind_label))}
              {o.occurrences > 1 &&
                `, seen on ${plural(o.occurrences, 'sweep')}${
                  o.first_seen_at ? `, first seen ${ago(o.first_seen_at)}` : ''
                }`}
            </li>
          ))}
          {lead.observations.length > 4 && (
            <li className="text-faint">
              · and {plural(lead.observations.length - 4, 'more observation')} on this lead
            </li>
          )}
        </ul>
      )}
    </li>
  );
}

// ---------------------------------------------------------------------------
// Bulk decisions on the leads list (owner, 2026-10-20).
//
// Every lead decision was one lead at a time, so ten noise leads on one host
// cost about thirty clicks. The Hunts page selects leads the way the Alerts,
// Investigations and Hosts lists select rows: a checkbox on each row, one box
// for every row on the list, and the shared selection strip, sticky at the top
// of the strip. A press opens a confirm that states what it does, with counts.
// The result line names the outcome of each lead and offers Undo while the
// press can be undone. The server decides each lead again: the plan here
// states what the rows on screen say.
// ---------------------------------------------------------------------------

/** The three bulk acts. There is no bulk promotion: an investigation is one
 *  decision per case. */
export type LeadBulkAction = 'dismiss' | 'hunt' | 'reopen';

/** The hunts one press starts at most, when the server cannot be read. The
 *  server states its own cap (routes_lead_bulk.py, LEAD_BULK_HUNT_CAP). */
export const LEAD_BULK_HUNT_CAP = 3;

/** How long Undo stays on the result line after a press. */
export const LEAD_UNDO_WINDOW_MS = 120_000;
const UNDO_WINDOW_WORDS = '2 minutes';

/** The word on each bulk button. The single row uses the same words. */
export const LEAD_BULK_LABEL: Record<LeadBulkAction, string> = {
  dismiss: LEAD_ACTION.dismiss,
  hunt: 'Hunt',
  reopen: LEAD_ACTION.reopen,
};

/** The bulk acts each tab offers. A lead under a running hunt takes no
 *  decision, so In progress offers none. */
export const LEAD_BULK_ACTIONS: Record<LeadTab, LeadBulkAction[]> = {
  needs_decision: ['dismiss', 'hunt'],
  in_progress: [],
  closed: ['reopen'],
  all: ['dismiss', 'hunt', 'reopen'],
};

const BULK_TITLE: Record<LeadBulkAction, string> = {
  dismiss: 'Dismiss the selected leads with one reason. The confirm states the count.',
  hunt: `Start one hunt for each selected lead. One press starts at most ${LEAD_BULK_HUNT_CAP} hunts.`,
  reopen: 'Reopen the selected dismissed leads. Each lead goes back to Needs decision.',
};

const BULK_NONE_TITLE: Record<LeadBulkAction, string> = {
  dismiss:
    'No selected lead takes a dismissal. A closed lead, a shadow lead and a lead under a running hunt take none.',
  hunt: 'No selected lead takes a hunt. A closed lead, a shadow lead and a lead under a running hunt take none.',
  reopen: 'No selected lead takes a reopen. Only a dismissed lead reopens in bulk. A shadow lead does not.',
};

/** True while the lead's hunt runs. An investigating hunt still runs: it
 *  investigates its findings. */
function huntInFlight(lead: Lead): boolean {
  return (
    leadState(lead) === 'in_progress' ||
    (lead.hunt_status as string | null | undefined) === 'investigating'
  );
}

/** What a press does with the selected leads, from the rows on screen. */
export interface LeadBulkPlan {
  action: LeadBulkAction;
  /** The leads the press acts on, in list order. */
  act: Lead[];
  /** The leads the press skips, each with the code the server uses. */
  skip: { lead: Lead; code: string }[];
}

function skipCode(action: LeadBulkAction, lead: Lead): string | null {
  if (lead.shadow) return 'shadow';
  const state = leadState(lead);
  const closed = state === 'dismissed' || state === 'promoted';
  if (action === 'reopen') {
    if (!closed) return 'not_closed';
    return state === 'promoted' ? 'promoted' : null;
  }
  if (closed) return 'already_closed';
  return huntInFlight(lead) ? 'hunt_running' : null;
}

export function leadBulkPlan(action: LeadBulkAction, leads: readonly Lead[]): LeadBulkPlan {
  const act: Lead[] = [];
  const skip: { lead: Lead; code: string }[] = [];
  for (const lead of leads) {
    const code = skipCode(action, lead);
    if (code) skip.push({ lead, code });
    else act.push(lead);
  }
  return { action, act, skip };
}

/** "a", "a and b", "a, b and c". */
export function joinWords(parts: readonly string[]): string {
  if (parts.length <= 1) return parts[0] ?? '';
  return `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}`;
}

/** The count of each code, in the order the codes first appear. */
function countCodes(codes: readonly string[]): [string, number][] {
  const out = new Map<string, number>();
  for (const code of codes) out.set(code, (out.get(code) ?? 0) + 1);
  return [...out.entries()];
}

/** The words for `n` leads that one skip code names. */
export function skipWords(code: string, n: number, cap: number = LEAD_BULK_HUNT_CAP): string {
  const leads = plural(n, 'lead');
  switch (code) {
    case 'shadow':
      return plural(n, 'shadow lead');
    case 'already_closed':
      return plural(n, 'closed lead');
    case 'not_closed':
      return plural(n, 'open lead');
    case 'hunt_running':
      return `${leads} with a hunt in progress`;
    case 'over_cap':
      return `${leads} over the cap of ${cap}`;
    case 'promoted':
      return `${leads} closed by an investigation`;
    case 'changed':
      return `${leads} that changed after the page loaded`;
    case 'not_found':
      return `${leads} not found`;
    case 'no_dismissal':
      return `${leads} with no dismissal to restore`;
    default:
      return `${leads} with the reason ${code}`;
  }
}

/** Why a skip code holds, for the codes whose words do not say it. */
const SKIP_WHY: Record<string, string> = {
  shadow: 'Decide on a shadow lead from its own row.',
  promoted: 'To reopen a lead that an investigation closed, use the row of that lead.',
};

function skipSentence(plan: LeadBulkPlan): string | null {
  if (!plan.skip.length) return null;
  const groups = countCodes(plan.skip.map((s) => s.code));
  const why = groups.map(([code]) => SKIP_WHY[code]).filter(Boolean);
  return [`The press skips ${joinWords(groups.map(([code, n]) => skipWords(code, n)))}.`, ...why].join(' ');
}

function offListSentence(offList: number): string | null {
  if (offList <= 0) return null;
  return offList === 1
    ? '1 selected lead left this list after a refresh. The press includes it.'
    : `${offList.toLocaleString()} selected leads left this list after a refresh. The press includes them.`;
}

function leadIdWords(leads: readonly Lead[]): string {
  return `${leads.length === 1 ? 'lead' : 'leads'} ${joinWords(leads.map((l) => String(l.id)))}`;
}

/** The sentences of the Dismiss confirm. */
export function dismissConfirmText(plan: LeadBulkPlan, offList = 0): string[] {
  const n = plan.act.length;
  const out: string[] = [`Dismiss ${plural(n, 'lead')}. Each lead gets the reason and the note below.`];
  const skip = skipSentence(plan);
  if (skip) out.push(skip);
  const off = offListSentence(offList);
  if (off) out.push(off);
  // Name each lead whose hunt found a threat. A count named no lead, and the
  // analyst could not tell which lead to keep (verify 2026-10-20).
  const threats = plan.act.filter(leadFoundThreat);
  if (threats.length === 1) {
    out.push(
      `An earlier hunt of lead ${threats[0].id} found a threat. ` +
        'Dismiss closes the lead. The threat finding stays open on the hunt.',
    );
  } else if (threats.length > 1) {
    out.push(
      `Earlier hunts of ${leadIdWords(threats)} found a threat. ` +
        'Dismiss closes each lead. Each threat finding stays open on its hunt.',
    );
  }
  out.push(
    'The observations on these leads and their repeats form no new lead. A new observation can form a new lead.',
  );
  out.push(`You can undo the dismissal from the result line for ${UNDO_WINDOW_WORDS}.`);
  return out;
}

/** What the Hunt confirm knows about hunt time: the server's plan, a read in
 *  progress, or a failed read. */
export type HuntPlanState = LeadBulkHuntPlan | 'loading' | 'failed';

export function huntCap(plan: HuntPlanState): number {
  return typeof plan === 'object' ? plan.cap : LEAD_BULK_HUNT_CAP;
}

/** The sentences of the Hunt confirm. */
export function huntConfirmText(plan: LeadBulkPlan, huntPlan: HuntPlanState, offList = 0): string[] {
  const cap = huntCap(huntPlan);
  const starts = plan.act.slice(0, cap);
  const rest = plan.act.length - starts.length;
  const out: string[] = [`Start ${plural(starts.length, 'hunt')} on ${leadIdWords(starts)}.`];
  out.push(`Each hunt is a model run. One press starts at most ${cap} hunts.`);
  if (huntPlan === 'loading') out.push('Reading the hunt time of this grid.');
  else if (huntPlan === 'failed') out.push('The console could not read the hunt time of this grid.');
  else if (huntPlan.typical_run == null) out.push('soc-ai has too few finished hunts to state a hunt time.');
  else {
    const t = huntPlan.typical_run;
    const span = t.lowMin === t.highMin ? `about ${t.lowMin}` : `${t.lowMin} to ${t.highMin}`;
    out.push(
      `Hunts on this grid take ${span} minutes. The time comes from the last ${plural(t.samples, 'finished hunt')}.`,
    );
  }
  if (rest > 0) out.push(`Press Hunt again for the other ${plural(rest, 'lead')}.`);
  const again = starts.filter((l) => leadState(l) === 'hunted').length;
  if (again > 0) {
    out.push(
      `${again.toLocaleString()} of these leads ${again === 1 ? 'has' : 'have'} a finished hunt. The press starts another hunt on each.`,
    );
  }
  const skip = skipSentence(plan);
  if (skip) out.push(skip);
  const off = offListSentence(offList);
  if (off) out.push(off);
  out.push('A hunt start has no Undo. You can cancel a hunt on its page.');
  return out;
}

/** The sentences of the Reopen confirm. */
export function reopenConfirmText(plan: LeadBulkPlan, offList = 0): string[] {
  const n = plan.act.length;
  const out: string[] = [
    `Reopen ${plural(n, 'lead')}. Each lead goes back to Needs decision.`,
    'The history of each lead keeps the dismissal.',
  ];
  const skip = skipSentence(plan);
  if (skip) out.push(skip);
  const off = offListSentence(offList);
  if (off) out.push(off);
  out.push(
    `You can undo the reopen from the result line for ${UNDO_WINDOW_WORDS}. ` +
      'Undo dismisses each lead again with its last reason.',
  );
  const byHunt = plan.act.filter(closedByHunt).length;
  if (byHunt > 0) {
    out.push(`Undo leaves open ${plural(byHunt, 'lead')} that soc-ai closed after a clean hunt.`);
  }
  return out;
}

/** The Undo a press offers: the write that reverses it, for the leads it
 *  wrote, with their change tokens. */
interface LeadBulkUndo {
  kind: 'reopen' | 'dismiss_again';
  ids: number[];
  seen: Record<string, string | null>;
  until: number;
}

/** One line in the sticky bar: a press, the Undo of a press, or a refusal. */
export interface LeadBulkEntry {
  result?: LeadBulkResult;
  /** How many leads the press sent. */
  sent: number;
  /** The dismissal reason of a Dismiss press. */
  reason?: string;
  /** Set on the answer of an Undo: the act it reversed. */
  undoOf?: 'dismiss' | 'reopen';
  /** A refusal of the whole press, or a failed Undo. */
  error?: string;
  undo?: LeadBulkUndo | null;
}

function undoFor(result: LeadBulkResult, now: number): LeadBulkUndo | null {
  const tokens = (rows: { id: number; updated_at?: string | null }[]) =>
    Object.fromEntries(rows.map((d) => [String(d.id), d.updated_at ?? null]));
  if (result.action === 'dismiss' && result.done.length) {
    return {
      kind: 'reopen',
      ids: result.done.map((d) => d.id),
      seen: tokens(result.done),
      until: now + LEAD_UNDO_WINDOW_MS,
    };
  }
  if (result.action === 'reopen') {
    // A close by the settle rule carries the rule's reason, and no analyst
    // dismissal can restore it.
    const back = result.done.filter((d) => DISMISS_REASONS.includes(d.previous_reason ?? ''));
    if (!back.length) return null;
    return {
      kind: 'dismiss_again',
      ids: back.map((d) => d.id),
      seen: tokens(back),
      until: now + LEAD_UNDO_WINDOW_MS,
    };
  }
  return null;
}

/** The sentence of the result line. */
export function bulkResultText(entry: LeadBulkEntry): string {
  if (!entry.result) return entry.error ?? '';
  const r = entry.result;
  const done = r.done.length;
  const of =
    done === entry.sent ? plural(done, 'lead') : `${done.toLocaleString()} of ${plural(entry.sent, 'lead')}`;
  const parts: string[] = [];
  if (r.action === 'dismiss') {
    const label = REASON_LABEL[entry.reason ?? ''] ?? entry.reason ?? '';
    parts.push(`Dismissed ${of} as "${label}".`);
  } else if (r.action === 'reopen') {
    parts.push(entry.undoOf === 'dismiss' ? `Undid the dismissal of ${of}.` : `Reopened ${of}.`);
  } else if (r.action === 'dismiss_again') {
    parts.push(`Undid the reopen of ${of}. Each lead has its last reason again.`);
  } else {
    parts.push(`Started ${plural(done, 'hunt')}.`);
  }
  if (r.skipped.length) {
    const cap = r.cap ?? LEAD_BULK_HUNT_CAP;
    const groups = countCodes(r.skipped.map((s) => s.reason));
    parts.push(`Skipped ${joinWords(groups.map(([code, n]) => skipWords(code, n, cap)))}.`);
  }
  if (r.failed.length) {
    parts.push(
      r.failed.length === 1
        ? '1 failed. It stays selected. Try it again.'
        : `${r.failed.length.toLocaleString()} failed. They stay selected. Try them again.`,
    );
  }
  if (entry.error) parts.push(entry.error);
  return parts.join(' ');
}

const CONFIRM_TITLE: Record<LeadBulkAction, string> = {
  dismiss: 'Dismiss leads',
  hunt: 'Hunt leads',
  reopen: 'Reopen leads',
};

/** The confirm of a bulk press. Escape and Cancel close it. A Dismiss takes
 *  one reason and one optional note for every lead. */
function LeadBulkConfirm({
  action,
  plan,
  offList,
  busy,
  onCancel,
  onConfirm,
}: {
  action: LeadBulkAction;
  plan: LeadBulkPlan;
  offList: number;
  busy: boolean;
  onCancel: () => void;
  onConfirm: (reason?: string, note?: string) => void;
}) {
  const [reason, setReason] = useState('');
  const [note, setNote] = useState('');
  const [huntPlan, setHuntPlan] = useState<HuntPlanState>('loading');
  useEffect(() => {
    if (action !== 'hunt') return;
    let alive = true;
    getLeadBulkHuntPlan()
      .then((p) => alive && setHuntPlan(p))
      .catch(() => alive && setHuntPlan('failed'));
    return () => {
      alive = false;
    };
  }, [action]);
  // Esc cancels. Capture phase, so a drawer behind the confirm stays open.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      e.stopPropagation();
      onCancel();
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [onCancel]);

  const sentences =
    action === 'dismiss'
      ? dismissConfirmText(plan, offList)
      : action === 'hunt'
        ? huntConfirmText(plan, huntPlan, offList)
        : reopenConfirmText(plan, offList);
  const count = action === 'hunt' ? Math.min(plan.act.length, huntCap(huntPlan)) : plan.act.length;
  const goLabel =
    action === 'hunt'
      ? `Start ${plural(count, 'hunt')}`
      : `${LEAD_BULK_LABEL[action]} ${plural(count, 'lead')}`;
  const ready = count > 0 && !busy && (action !== 'dismiss' || !!reason);
  const reasonId = 'lead-bulk-reason';
  return (
    <div
      className="fixed inset-0 z-[70] flex items-center justify-center"
      style={{ background: 'rgba(0,0,0,.65)' }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onCancel();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label={CONFIRM_TITLE[action]}
        data-testid="lead-bulk-confirm"
        className="relative w-[500px] max-w-[calc(100vw-32px)] rounded-panel-lg border p-6"
        style={{ background: '#0e1117', borderColor: '#1c232e' }}
      >
        <div className="mb-4 text-[14px] font-semibold">{CONFIRM_TITLE[action]}</div>
        <div
          className="mb-4 flex items-start gap-2 rounded-[7px] border px-3 py-2.5 text-[12.5px] leading-[1.5]"
          style={
            action === 'hunt'
              ? { borderColor: 'rgba(210,153,34,.4)', background: 'rgba(210,153,34,.08)', color: '#e3b341' }
              : { borderColor: 'rgba(148,163,184,.32)', background: 'rgba(148,163,184,.08)', color: '#cbd5e1' }
          }
        >
          <AlertTriangle size={13} className="mt-px flex-none" />
          <div data-testid="lead-bulk-confirm-text" className="space-y-1.5">
            {sentences.map((line) => (
              <p key={line}>{line}</p>
            ))}
          </div>
        </div>
        {action === 'dismiss' && (
          <div className="mb-5 flex flex-wrap items-center gap-2 text-[12.5px]">
            <label htmlFor={reasonId}>Reason</label>
            <select
              id={reasonId}
              // The keyboard lands on the reason. No reason is chosen when the
              // confirm opens, so one key press dismisses nothing.
              autoFocus
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="rounded-control border border-border bg-surface-2 px-2 py-1"
            >
              <option value="">Choose a reason</option>
              {DISMISS_REASONS.map((r) => (
                <option key={r} value={r}>
                  {REASON_LABEL[r] ?? r}
                </option>
              ))}
            </select>
            <input
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Note, optional"
              aria-label="Note, optional"
              className="min-w-[200px] flex-1 rounded-control border border-border bg-surface-2 px-2 py-1"
            />
          </div>
        )}
        <div className="flex justify-end gap-2.5">
          <button
            type="button"
            // The keyboard lands on Cancel when there is no reason to choose,
            // so Enter starts nothing.
            autoFocus={action !== 'dismiss'}
            onClick={onCancel}
            className="rounded-control border border-border-strong bg-surface-3 px-4 py-2 text-[13px] font-semibold text-text-2 hover:text-text"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={!ready}
            onClick={() => onConfirm(reason || undefined, note.trim() || undefined)}
            className="rounded-control border border-accent bg-accent/15 px-4 py-2 text-[13px] font-semibold text-[#cfe0ff] hover:bg-accent/25 disabled:opacity-50"
          >
            {busy ? 'Working' : goLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

/** The result line of the last press, in the sticky bar. It stays until the
 *  analyst closes it or a new press replaces it. Undo stays for the window. */
function LeadBulkResultLine({
  entry,
  undoBusy,
  onUndo,
  onClose,
}: {
  entry: LeadBulkEntry;
  undoBusy: boolean;
  onUndo: () => void;
  onClose: () => void;
}) {
  const [open, setOpen] = useState(false);
  const r = entry.result;
  const detail = r
    ? [
        ...(r.action === 'hunt'
          ? r.done.map((d) => ({ id: d.id, text: 'The hunt started.', hunt: d.hunt_id ?? null }))
          : []),
        ...r.skipped.map((s) => ({ id: s.id, text: s.hint, hunt: null as string | null })),
        ...r.failed.map((f) => ({ id: f.id, text: f.hint, hunt: null as string | null })),
      ]
    : [];
  const undo = entry.undo;
  return (
    <div
      data-testid="leads-bulk-result"
      role="status"
      className="mb-2 rounded-card border border-accent-deep bg-[#0d1726] px-[11px] py-[7px] text-[12.5px] text-text-2"
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="min-w-0 flex-1 break-words">{bulkResultText(entry)}</span>
        {detail.length > 0 && (
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            className="flex items-center gap-1 text-[11.5px] font-semibold text-accent hover:underline"
          >
            {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
            {open ? 'Hide detail' : 'Show detail'}
          </button>
        )}
        {undo && (
          <button
            type="button"
            onClick={onUndo}
            disabled={undoBusy}
            title={
              undo.kind === 'reopen'
                ? 'Reopen the leads this press dismissed. A lead that changed after the press stays dismissed.'
                : 'Dismiss the reopened leads again with their last reason. A lead that changed after the press stays open.'
            }
            className="flex items-center gap-1.5 rounded-[7px] border border-warn/40 px-[11px] py-1.5 text-[12.5px] font-semibold text-warn hover:bg-warn/10 disabled:opacity-60"
          >
            {undoBusy ? 'Undoing' : `Undo (${undo.ids.length})`}
          </button>
        )}
        <button
          type="button"
          onClick={onClose}
          disabled={undoBusy}
          aria-label="Close the bulk result"
          title={undo ? 'Close this result. After you close it, you cannot undo the press from this page.' : 'Close this result.'}
          className="flex flex-none items-center rounded-control p-1 text-faint hover:text-text disabled:opacity-60"
        >
          <X size={13} />
        </button>
      </div>
      {open && detail.length > 0 && (
        <ul className="mt-1.5 space-y-0.5 text-[11.5px] text-dim">
          {detail.map((d) => (
            <li key={`${d.id}-${d.text}`}>
              <Link to={`/leads/${d.id}`} className="text-accent hover:underline">
                Lead {d.id}
              </Link>
              : {d.text}
              {d.hunt && (
                <>
                  {' '}
                  <Link
                    to={`/hunts/${encodeURIComponent(d.hunt)}`}
                    aria-label={`Open the hunt of lead ${d.id}`}
                    className="font-semibold text-accent hover:underline"
                  >
                    Open the hunt
                  </Link>
                </>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** The Hunts page with the leads of one host, on the All tab. "all leads"
 *  on a host page opened every lead of the estate (dogfood 2026-10-19,
 *  R4-I2). */
export function leadsHref(entityKey: string, label?: string | null): string {
  const p = new URLSearchParams();
  p.set(LEAD_ENTITY_PARAM, entityKey);
  if (label?.trim()) p.set(LEAD_ENTITY_LABEL_PARAM, label.trim());
  p.set('leads', 'all');
  return `/hunts?${p.toString()}#leads`;
}

/** The Hunts page parameters of the host filter. */
export const LEAD_ENTITY_PARAM = 'lead_entity';
export const LEAD_ENTITY_LABEL_PARAM = 'lead_entity_label';

export function LeadsStrip({
  entityKey: hostKey,
  entityLabel,
  className,
  status: firstTab = 'needs_decision',
  noun = 'host',
  paramBound = false,
  onRows,
  collapsed = false,
  onToggleCollapsed,
}: {
  /** The entity the strip is mounted on. The server keeps the leads that name
   *  it, under every key of its machine: a lead on the host name belongs on
   *  the address's page too. */
  entityKey?: string;
  /** The name of the host, for the filter chip on the Hunts page. */
  entityLabel?: string | null;
  className?: string;
  /** The tab the strip opens on. A host page opens on All, because a lead
   *  under a hunt and a lead already closed both belong to the host. */
  status?: LeadTab;
  /** The word for the thing the strip is mounted on. A user account is not a
   *  host, and the heading said host on both. */
  noun?: string;
  /** On the Hunts page the tab lives in the address, so a reload keeps it and
   *  the Needs-you strip can jump straight to it. On a host page the strip
   *  holds its own tab: the address there describes the host. */
  paramBound?: boolean;
  /** The rows on screen, for a block below that has to say something about
   *  them. The hunt list uses it to name the leads that reach a hunt older
   *  than its window. One fetch, read twice. */
  onRows?: (rows: Lead[]) => void;
  /** The fold of the section. The page holds it, because a Needs-you link has
   *  to open this block before it scrolls to it. */
  collapsed?: boolean;
  /** When the page passes this, the header carries the chevron. */
  onToggleCollapsed?: () => void;
} = {}) {
  const [params, setParams] = useSearchParams();
  // On the Hunts page a host page link names one host. The strip keeps the
  // leads that name it until the analyst clears the chip.
  const paramEntity = paramBound ? (params.get(LEAD_ENTITY_PARAM) ?? '').trim() : '';
  const paramEntityLabel = (params.get(LEAD_ENTITY_LABEL_PARAM) ?? '').trim() || paramEntity;
  const entityKey = hostKey || paramEntity || undefined;
  const clearEntity = () => {
    const search = new URLSearchParams(params);
    search.delete(LEAD_ENTITY_PARAM);
    search.delete(LEAD_ENTITY_LABEL_PARAM);
    setParams(search, { replace: true });
  };
  const [localTab, setLocalTab] = useState<LeadTab>(firstTab);
  const wanted = params.get('leads');
  const tab: LeadTab = paramBound
    ? isLeadTab(wanted)
      ? wanted
      : 'needs_decision'
    : localTab;
  const setTab = (next: LeadTab) => {
    if (!paramBound) {
      setLocalTab(next);
      return;
    }
    const search = new URLSearchParams(params);
    if (next === 'needs_decision') search.delete('leads');
    else search.set('leads', next);
    setParams(search, { replace: true });
  };

  const [reload, setReload] = useState(0);
  // 60 s, the cadence the hits block runs at. A lead forms on the profile sweep
  // and on every triage verdict, so 5 minutes was long enough for the strip to
  // disagree with the block beside it.
  //
  // On a host page the server keeps the leads that touch this host. The strip
  // read the newest 50 leads of the estate and filtered them here, so a host
  // lead older than those 50 never showed (2026-10-14).
  const leads = useAsync(
    () =>
      entityKey
        ? getLeads(tab as LeadStatusFilter, { entity: entityKey })
        : getLeads(tab as LeadStatusFilter),
    [tab, reload, entityKey],
    { refetchInterval: 60_000 },
  );
  // The true total of the tab. The rows stop at the server's limit, and the
  // heading counted the rows, so it never said more than 50. A failed count
  // leaves the heading on the rows. `async` turns a throw into a rejection.
  const total = useAsync(
    async () =>
      entityKey
        ? getLeadCount(tab as LeadStatusFilter, { entity: entityKey })
        : getLeadCount(tab as LeadStatusFilter),
    [tab, reload, entityKey],
    { refetchInterval: 60_000 },
  );
  // The caller's callback, held in a ref so an inline arrow function in the
  // parent does not re-fire the effect below on every render.
  const onRowsRef = useRef(onRows);
  onRowsRef.current = onRows;
  const rows = leads.data ?? [];
  const totalCount =
    total.data && total.data.status === tab ? Math.max(total.data.total, rows.length) : rows.length;
  // The rows, to the block that asked for them. The effect keys on the loaded
  // list, so a render the poll did not change does not re-announce it.
  const loaded = leads.data;
  useEffect(() => {
    if (loaded) onRowsRef.current?.(rows);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loaded]);
  const onHost = Boolean(hostKey);
  // The server states the setting. A queued lead is the fallback for an
  // older server: reading the rule off the queue said "off" the moment the
  // queue was empty, and the note under the header then said the opposite of
  // what the deployment does.
  const needsYou = useAsync(() => getNeedsYou().catch(() => null), [reload]);
  const autoHunt =
    typeof needsYou.data?.lead_auto_hunt === 'boolean'
      ? needsYou.data.lead_auto_hunt
      : autoHuntOn(leads.data ?? []);

  // ---- bulk decisions ------------------------------------------------------
  // The Hunts page only. A host page links to the Hunts page with the host
  // filter, and the bulk press runs there.
  const selectable = paramBound;
  const demo = useDemo();
  const sel = useListSelection(rows.map((r) => String(r.id)));
  // The last row read for each lead. A selected lead that left the list after
  // a refresh keeps its row here, so the press still sends its change token
  // and the strip counts it as not on this page.
  const known = useRef(new Map<string, Lead>());
  for (const r of rows) known.current.set(String(r.id), r);
  const selectedLeads = sel.ids
    .map((id) => known.current.get(id))
    .filter((l): l is Lead => l !== undefined);
  // A new tab or a new host filter is a new list. The selection does not
  // follow it: a press acts on the list the analyst is reading.
  const clearSelection = sel.clear;
  useEffect(() => {
    clearSelection();
  }, [tab, entityKey, clearSelection]);
  const [confirm, setConfirm] = useState<{ action: LeadBulkAction; leads: Lead[]; offList: number } | null>(
    null,
  );
  const opener = useRef<HTMLElement | null>(null);
  const [bulk, setBulk] = useState<LeadBulkEntry | null>(null);
  const [bulkBusy, setBulkBusy] = useState(false);
  const [undoBusy, setUndoBusy] = useState(false);
  // Undo ends with its window. The line stays until the analyst closes it.
  const undoUntil = bulk?.undo?.until;
  useEffect(() => {
    if (!undoUntil) return;
    const t = window.setTimeout(
      () => setBulk((b) => (b?.undo?.until === undoUntil ? { ...b, undo: null } : b)),
      Math.max(0, undoUntil - Date.now()),
    );
    return () => window.clearTimeout(t);
  }, [undoUntil]);

  const closeConfirm = () => {
    setConfirm(null);
    opener.current?.focus();
  };
  const openConfirm = (action: LeadBulkAction, el: HTMLElement) => {
    opener.current = el;
    setConfirm({ action, leads: selectedLeads, offList: sel.offPageCount });
  };
  const failedMessage = (e: unknown) =>
    e instanceof ApiError && e.reason
      ? e.message
      : 'The console got no answer. Read the list again to see what changed.';
  const undoFailedMessage = (e: unknown) =>
    e instanceof ApiError && e.reason
      ? `The undo did not complete. ${e.message} The list below shows the state of each lead now.`
      : 'The undo did not complete. The console got no answer. The list below shows the state of each lead now.';

  const runPress = async (reason?: string, note?: string) => {
    if (!confirm) return;
    const blocked = demoBlocked(demo);
    if (blocked) {
      setBulk({ sent: 0, error: blocked });
      closeConfirm();
      return;
    }
    const press: LeadBulkPress = {
      ids: confirm.leads.map((l) => l.id),
      expected: confirm.leads.length,
      seen: Object.fromEntries(confirm.leads.map((l) => [String(l.id), l.updated_at])),
    };
    setBulkBusy(true);
    try {
      const result =
        confirm.action === 'dismiss'
          ? await bulkDismissLeads(press, reason ?? '', note)
          : confirm.action === 'reopen'
            ? await bulkReopenLeads(press)
            : await bulkHuntLeads(press);
      // The leads that did not land stay selected, so "try them again" is
      // one press.
      const failed = result.failed.map((f) => String(f.id));
      if (failed.length) sel.select(failed);
      else sel.clear();
      setBulk({ result, sent: press.ids.length, reason, undo: undoFor(result, Date.now()) });
    } catch (e) {
      setBulk({ sent: press.ids.length, error: failedMessage(e) });
    } finally {
      setBulkBusy(false);
      setConfirm(null);
      setReload((n) => n + 1);
    }
  };

  const runUndo = async () => {
    const entry = bulk;
    const undo = entry?.undo;
    if (!entry?.result || !undo) return;
    const blocked = demoBlocked(demo);
    if (blocked) {
      setBulk({ ...entry, error: blocked });
      return;
    }
    setUndoBusy(true);
    try {
      const press: LeadBulkPress = { ids: undo.ids, expected: undo.ids.length, seen: undo.seen };
      const result =
        undo.kind === 'reopen' ? await bulkReopenLeads(press) : await bulkDismissLeadsAgain(press);
      setBulk({
        result,
        sent: undo.ids.length,
        undoOf: entry.result.action === 'dismiss' ? 'dismiss' : 'reopen',
        undo: null,
      });
    } catch (e) {
      // The line says that the undo failed, and offers it no more. The list
      // reads the leads again below, so it shows the state of each lead
      // (verify 2026-10-20, V3-N8).
      setBulk({ ...entry, undo: null, error: undoFailedMessage(e) });
    } finally {
      setUndoBusy(false);
      setReload((n) => n + 1);
    }
  };

  const selecting = selectable && sel.count > 0;
  const bulkActions = LEAD_BULK_ACTIONS[tab];

  if (onHost && leads.data && rows.length === 0) return null;
  return (
    <div
      id={paramBound ? 'leads' : undefined}
      className={`${className ?? 'mb-4'} rounded-panel border border-border bg-surface-1`}
      data-testid="leads-strip"
    >
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border-faint px-[15px] py-2">
        <span className="inline-flex items-center gap-2.5">
          {onToggleCollapsed && (
            <CollapseChevron
              collapsed={collapsed}
              onToggle={onToggleCollapsed}
              section="Leads"
              controls={LEADS_BODY_ID}
            />
          )}
          <span
            data-testid="leads-heading"
            className="inline-flex items-center gap-1.5 whitespace-nowrap text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint"
            title={HEADING_TITLE}
          >
            <GitBranch size={12} />
            {onHost ? `Leads on this ${noun}` : 'Leads'}
            {leads.data && (
              <span className="font-mono normal-case tracking-normal">
                · {countText(tab, totalCount)} ·{' '}
                <span data-testid="leads-scope">{TAB_SCOPE[tab]}</span>
              </span>
            )}
          </span>
          {/* The strip showed open leads and nothing else. A lead an analyst
              dismissed yesterday was unreachable from the screen that had
              listed it, and a lead under a hunt left the strip the moment the
              hunt started.

              The tabs filter a list. A folded section has none, so they go with
              it and the count in the heading keeps the tab's own word. */}
          {!collapsed && (
          <span className="inline-flex flex-wrap items-center gap-x-1 gap-y-0.5">
            <span className="inline-flex items-center gap-1">
              {LEAD_TABS.map((t) => (
                <button
                  key={t.id}
                  type="button"
                  aria-pressed={tab === t.id}
                  onClick={() => setTab(t.id)}
                  title={t.title}
                  className={`rounded-chip border px-1.5 py-px text-[10.5px] ${
                    tab === t.id
                      ? 'border-accent text-accent'
                      : 'border-border-faint text-dim hover:text-text-2'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </span>
            {/* The four words are a taxonomy. A taxonomy nobody can read is a
                filter an analyst guesses at. */}
            <span
              data-testid="leads-legend"
              className="basis-full text-[10.5px] font-normal normal-case tracking-normal text-faint"
            >
              {statusLegend(autoHunt)}
            </span>
          </span>
          )}
        </span>
        <span className="flex items-center gap-2.5">
          {/* The one thing an analyst must know before reading the list: who
              acts on a lead. The 1.5.0 dogfood read the strip as a queue the
              system was already working, and with the loop on it is exactly
              that, so the note says which of the two this deployment is. */}
          <span
            data-testid="leads-note"
            className="text-[11px] text-dim"
            title={
              autoHunt
                ? LEADS_NOTE_AUTO_HUNT
                : 'soc-ai records leads. It does not start a hunt from a lead by itself. An analyst starts every hunt from a lead in this release.'
            }
          >
            {autoHunt
              ? LEADS_NOTE_AUTO_HUNT
              : 'soc-ai records leads. It does not start a hunt from a lead by itself.'}
          </span>
          {paramEntity && (
            <span
              data-testid="leads-entity-filter"
              className="flex items-center gap-1.5 rounded-chip border border-accent/40 bg-accent/10 px-2 py-0.5 text-[11px] font-semibold text-accent"
            >
              Host: {paramEntityLabel}
              <button
                type="button"
                aria-label="Clear the host filter"
                onClick={clearEntity}
                className="rounded px-0.5 text-accent hover:bg-accent/20"
              >
                ×
              </button>
            </span>
          )}
          {onHost && hostKey && (
            <Link
              data-testid="leads-host-link"
              to={leadsHref(hostKey, entityLabel)}
              className="whitespace-nowrap text-[11px] text-accent hover:underline"
            >
              open in Hunts
            </Link>
          )}
        </span>
      </div>
      {/* What a lead is, before the leads. The definition stays while the
          section is folded: a folded block still says what it holds. */}
      <Definition of="lead" className="px-[15px] pt-2" />
      {collapsed ? (
        <div id={LEADS_BODY_ID} className="pb-2" />
      ) : (
        <div id={LEADS_BODY_ID}>
          {/* The selection strip and the result line of the last press, held
              at the top of the strip while the analyst scrolls the list. The
              strip is the one the other lists render. */}
          {selectable && (selecting || bulk) && (
            <div
              data-testid="leads-bulk-bar"
              className="sticky top-0 z-20 border-b border-border-faint bg-surface-1 px-[15px] pt-2 shadow-[0_1px_0_rgba(0,0,0,.4)]"
            >
              {selecting && (
                <SelectionStrip
                  className="mb-2"
                  selection={{
                    count: sel.count,
                    noun: sel.count === 1 ? 'lead selected' : 'leads selected',
                    offPageCount: sel.offPageCount,
                    onClearOffPage: sel.clearOffPage,
                    onClear: sel.clear,
                    actions:
                      bulkActions.length === 0 ? (
                        <span className="text-[12px] text-dim">
                          A lead under a running hunt takes no bulk decision.
                        </span>
                      ) : (
                        <>
                          {bulkActions.map((action) => {
                            const n = leadBulkPlan(action, selectedLeads).act.length;
                            return (
                              <button
                                key={action}
                                type="button"
                                disabled={bulkBusy || n === 0}
                                onClick={(e) => openConfirm(action, e.currentTarget)}
                                title={n === 0 ? BULK_NONE_TITLE[action] : BULK_TITLE[action]}
                                className="flex items-center gap-1.5 rounded-[7px] border px-[11px] py-1.5 text-[12.5px] font-semibold text-[#cfe0ff] disabled:opacity-50"
                                style={{ background: 'rgba(75,139,245,.14)', borderColor: 'rgba(75,139,245,.4)' }}
                              >
                                {`${LEAD_BULK_LABEL[action]} (${n})`}
                              </button>
                            );
                          })}
                        </>
                      ),
                  }}
                />
              )}
              {bulk && (
                <LeadBulkResultLine
                  entry={bulk}
                  undoBusy={undoBusy}
                  onUndo={() => {
                    void runUndo();
                  }}
                  onClose={() => setBulk(null)}
                />
              )}
            </div>
          )}
          {confirm && (
            <LeadBulkConfirm
              action={confirm.action}
              plan={leadBulkPlan(confirm.action, confirm.leads)}
              offList={confirm.offList}
              busy={bulkBusy}
              onCancel={closeConfirm}
              onConfirm={(reason, note) => {
                void runPress(reason, note);
              }}
            />
          )}
          {!leads.data ? (
            <div className="px-[15px] py-2.5 text-[12.5px] text-dim">
              {leads.error ? 'Could not read the leads.' : <LoadingInline>Reading the leads</LoadingInline>}
            </div>
          ) : rows.length === 0 ? (
            // Absence is stated, with the reason it is not an all-clear.
            <div className="px-[15px] py-2.5 text-[12.5px] text-dim">{EMPTY_STATE[tab]}</div>
          ) : (
            <>
              {selectable && (
                <div
                  data-testid="leads-select-all"
                  className="flex items-center gap-2 border-b border-border-faint px-[15px] py-1.5 text-[11.5px] text-dim"
                >
                  <Checkbox
                    checked={sel.allVisibleSelected}
                    indeterminate={!sel.allVisibleSelected && sel.someVisibleSelected}
                    onChange={sel.toggleAll}
                    aria-label={`Select the ${plural(rows.length, 'lead')} on this list`}
                    title="Select every lead on this list. A bulk action takes the selected leads."
                  />
                  <span aria-hidden="true">Select the {plural(rows.length, 'lead')} on this list</span>
                </div>
              )}
              <ul className="divide-y divide-border-faint">
                {rows.map((lead) => (
                  <LeadRow
                    key={lead.id}
                    lead={lead}
                    autoHunt={autoHunt}
                    onChanged={() => setReload((n) => n + 1)}
                    selectable={selectable}
                    selected={sel.isSelected(String(lead.id))}
                    onToggleSelect={() => sel.toggle(String(lead.id))}
                  />
                ))}
              </ul>
              {totalCount > rows.length && (
                <div
                  data-testid="leads-capped"
                  className="border-t border-border-faint px-[15px] py-2 text-[11.5px] text-faint"
                >
                  The list shows the newest {rows.length} of {plural(totalCount, 'lead')}.
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
