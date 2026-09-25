import { GitBranch } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';

import {
  ApiError,
  dismissLead,
  getLeads,
  getNeedsYou,
  huntLead,
  promoteLead,
  reopenLead,
  type Lead,
  type LeadStatusFilter,
} from '../lib/api';
import { entityPath } from '../lib/entityPath';
import { kindLabel, sourceLabel, sourceTitle } from '../lib/kinds';
import { plural } from '../lib/plural';
import { absTime, ago } from '../lib/timeRange';
import {
  ACTION_HUNT_NOW,
  ACTION_REOPEN,
  CHIP_ANALYTIC_MATCH,
  CHIP_CLOSED_BY_HUNT,
  CHIP_DISMISS_REASON,
  CHIP_LEFT_TO_YOU,
  CHIP_NO_BENIGN_BASELINE,
  CHIP_ONE_SIGNAL_REPEATED,
  CHIP_RELATED,
  INVESTIGATION_GONE,
  LEADS_NOTE_AUTO_HUNT,
  LEGEND_AUTO_HUNT,
  PILL_CLOSED_BY_HUNT,
  PILL_DISMISSED,
  PILL_HUNTED,
  PILL_HUNT_QUEUED,
  PILL_IN_PROGRESS,
  PILL_NEW,
  PILL_PROMOTED,
  PROMOTE_NEEDS_HUNT,
  TAB_ALL,
  TAB_CLOSED,
  TAB_IN_PROGRESS,
  TAB_NEEDS_DECISION,
  WEIGHT_AT_FORMATION,
} from '../lib/tooltips';
import { useAsync } from '../lib/useAsync';
import { Definition } from './Definition';
import { CollapseChevron } from './Panel';

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

/** One label per dismissal reason. The lead page reads the same map, so one
 *  reason reads the same word wherever an analyst meets it. */
export const REASON_LABEL: Record<string, string> = {
  expected_for_role: 'Expected for this role',
  known_change: 'A known change',
  benign_repeat: 'A benign repeat',
  bad_baseline: 'The baseline is wrong',
  other: 'Other',
};

/** The reasons the server accepts. The strip has no lead detail to read them
 *  from, so it carries the list the route validates against. */
export const DISMISS_REASONS = Object.keys(REASON_LABEL);

/** The reason the server writes when the settle rule closes a lead after a
 *  clean hunt. It is not in REASON_LABEL: the form never offers it, and the
 *  pill reads the sentence below instead of a reason. */
export const HUNT_CLEAN_REASON = 'hunt_clean';
export const HUNT_CLOSED_LABEL = 'Closed. The hunt found no threat.';
/** The hand the server signs that closure with reads as the product on screen. */
export const HUNT_CLOSED_ACTOR = 'soc-ai';

export function closedByHunt(lead: { status: string; dismissed_reason?: string | null }): boolean {
  return lead.status === 'dismissed' && lead.dismissed_reason === HUNT_CLEAN_REASON;
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

/** A hunt that has stopped. The lead is no longer waiting on it. This is the
 *  server's rule for `needs_decision` too, so the pill and the tab agree. */
const HUNT_DONE = new Set(['complete', 'error', 'cancelled', 'interrupted']);

/** The outcome label that makes a benign repeat the right reason to dismiss. */
const NO_THREAT = 'No threat observed';

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
  if (lead.hunt_status && HUNT_DONE.has(lead.hunt_status)) return 'hunted';
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
    hunt_queued?: boolean;
    dismissed_reason?: string | null;
  };
}) {
  const state = leadState(lead);
  const style = LEAD_STATE_STYLE[state];
  const queued = huntQueued(lead);
  const byHunt = closedByHunt(lead);
  // The tail of the pill names who holds the lead next. A finished hunt names
  // its outcome. A queued hunt names the loop. A closure by the rule is one
  // sentence, with no tail.
  const outcome = state === 'hunted' && lead.hunt_outcome_label ? ` · ${lead.hunt_outcome_label}` : '';
  const tail = byHunt ? '' : queued ? ' · hunt queued' : outcome;
  const title = byHunt ? PILL_CLOSED_BY_HUNT : queued ? PILL_HUNT_QUEUED : LEAD_STATE_TITLE[state];
  return (
    <span
      data-testid="lead-status"
      data-lead-state={state}
      title={title}
      className="inline-flex flex-none items-center gap-1.5 rounded-chip border px-1.5 py-px text-[10.5px] font-medium"
      style={{ color: style.color, borderColor: style.border, background: style.background }}
    >
      <span className="h-[5px] w-[5px] rounded-full" style={{ background: style.color }} />
      {byHunt ? HUNT_CLOSED_LABEL : LEAD_STATE_LABEL[state]}
      {tail}
    </span>
  );
}

/** The name of each action on a lead. The strip and the lead page read the
 *  same words: "Start a hunt" here and "Hunt this lead" there taught an analyst
 *  that the two screens did different things. */
export const LEAD_ACTION = {
  hunt: 'Hunt',
  /** The same act on a lead whose hunt the loop already owns. The word is
   *  different because the act is: it does not wait for the loop. */
  huntNow: 'Hunt now',
  dismiss: 'Dismiss',
  promote: 'Promote',
  viewHunt: 'View hunt',
  readHunt: 'Read hunt',
  huntAgain: 'Hunt again',
  reopen: 'Reopen',
  openInvestigation: 'Open investigation',
} as const;

/** What a promoted lead reads in place of the Open investigation link when the
 *  investigation it names has gone. A label, not a sentence, so it sits with
 *  the other action words; its sentence is `INVESTIGATION_GONE`. */
export const INVESTIGATION_GONE_LABEL = 'The investigation no longer exists';

/** The actions a New lead offers while its hunt sits in the loop's queue.
 *  Hunt drops to a secondary act under its own word, because the hunt is
 *  already coming and this button only makes it come sooner. */
export const LEAD_QUEUED_ACTIONS: string[] = [
  LEAD_ACTION.dismiss,
  LEAD_ACTION.promote,
  LEAD_ACTION.huntNow,
];

/** The actions each state offers, in the order they are read. */
export const LEAD_STATE_ACTIONS: Record<LeadState, string[]> = {
  new: [LEAD_ACTION.hunt, LEAD_ACTION.dismiss, LEAD_ACTION.promote],
  in_progress: [LEAD_ACTION.viewHunt],
  hunted: [
    LEAD_ACTION.readHunt,
    LEAD_ACTION.promote,
    LEAD_ACTION.dismiss,
    LEAD_ACTION.huntAgain,
  ],
  dismissed: [LEAD_ACTION.reopen],
  promoted: [LEAD_ACTION.reopen, LEAD_ACTION.openInvestigation],
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
export const STATUS_LEGEND =
  'New: nobody has acted. In progress: a hunt is running. ' +
  'Hunted: the hunt finished, decide. Closed: dismissed or promoted.';

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
  if (lead.hunt_status && HUNT_DONE.has(lead.hunt_status)) return 'Hunted';
  return leadStatusLabel(lead.status);
}

const EMPTY_STATE: Record<LeadTab, string> = {
  needs_decision:
    'No lead waits on a decision. Every lead is under a hunt, or closed, or none has formed.',
  in_progress: 'No hunt is running on a lead. No analyst has started a hunt from a lead.',
  closed: 'No closed leads. No analyst has dismissed or promoted a lead.',
  all: 'No leads. No entity has observations of two types, a finding, or a repeated single type.',
};

/** The count beside the heading, in the tab's own word. */
function countText(tab: LeadTab, n: number): string {
  if (tab === 'needs_decision') return `${n} ${n === 1 ? 'needs' : 'need'} a decision`;
  if (tab === 'in_progress') return `${n} in progress`;
  if (tab === 'closed') return plural(n, 'closed lead');
  return plural(n, 'lead');
}

const HEADING_TITLE =
  'A lead forms at a live weight of 0.85 across two or more types. ' +
  'A finding with no benign baseline forms alone. ' +
  'One type that repeats until its stacked weight reaches 1.5 forms alone and is marked one signal, repeated.';

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
export function DismissLeadForm({
  leadId,
  reasons,
  onDone,
  initialReason,
}: {
  leadId: number;
  reasons: string[];
  onDone: () => void;
  /** The reason the form opens on. A hunt that observed no threat makes the
   *  lead a benign repeat, and the analyst had to pick that reason again. */
  initialReason?: string;
}) {
  const [reason, setReason] = useState(initialReason ?? '');
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
    <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
      <label htmlFor={selectId}>Reason</label>
      <select
        id={selectId}
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
}: {
  lead: Lead;
  /** Whether the loop runs. A lead the loop leaves says so beside its pill,
   *  and only a deployment whose loop runs has such a lead. */
  autoHunt: boolean;
  onChanged: () => void;
}) {
  const primary = lead.entities[0];
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [dismissing, setDismissing] = useState(false);
  const [confirmAgain, setConfirmAgain] = useState(false);
  const [failed, setFailed] = useState<string | null>(null);
  const state = leadState(lead);
  const queued = huntQueued(lead);
  const benignRepeat = state === 'hunted' && lead.hunt_outcome_label === NO_THREAT;
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

  const promote = () =>
    run(async () => {
      const r = await promoteLead(lead.id);
      navigate(`/investigation/${encodeURIComponent(r.investigation_id)}`);
    }, 'The lead was not promoted. Try again.');

  const reopen = () =>
    run(async () => {
      await reopenLead(lead.id);
      onChanged();
    }, 'The lead was not reopened. Try again.');

  return (
    <li
      className="flex flex-wrap items-center gap-x-3 gap-y-1 px-[15px] py-2.5 text-[13px]"
      data-testid={`lead-${lead.id}`}
    >
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
      {closedByHunt(lead) ? (
        <span
          className="rounded-chip border border-border-faint px-1.5 py-px text-[10.5px] text-faint"
          title={CHIP_CLOSED_BY_HUNT}
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
          +{plural(lead.entities.length - 1, 'more entity', 'more entities')}
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
        weight at formation {lead.weight_at_formation.toFixed(2)}
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
        {/* A queued lead is one the loop has taken. The analyst closes it or
            takes it further, and Hunt drops to a secondary act under its own
            word for the case where the loop is behind. */}
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
            {/* An investigation of a lead reads the hunt's findings, so the
                server refuses a promotion before a hunt has run. The lead
                page disabled the button and said why; the row let the analyst
                click and read the refusal in red. */}
            <button
              type="button"
              disabled
              title={PROMOTE_NEEDS_HUNT}
              className={PRIMARY_CLASS}
            >
              {LEAD_ACTION.promote}
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
            <button type="button" disabled={busy} onClick={hunt} className={PRIMARY_CLASS}>
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
            <button
              type="button"
              disabled
              title={PROMOTE_NEEDS_HUNT}
              className={ACTION_CLASS}
            >
              {LEAD_ACTION.promote}
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
            <button type="button" disabled={busy} onClick={promote} className={PRIMARY_CLASS}>
              {LEAD_ACTION.promote}
            </button>
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
              {LEAD_ACTION.openInvestigation}
            </Link>
          ))}
      </span>
      {failed && <span className="basis-full text-[11.5px] text-danger">{failed}</span>}
      {/* A second hunt on one lead is a real thing to want and a common
          mis-click. The confirm names the hunt that already exists. */}
      {confirmAgain && (
        <div className="basis-full pt-1.5 text-[12.5px]">
          <span className="mr-2">
            A hunt on this lead already finished. Read it before you start another.
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
          <button type="button" className="ml-2 text-dim" onClick={() => setConfirmAgain(false)}>
            Cancel
          </button>
        </div>
      )}
      {dismissing && (
        <div className="basis-full pt-1.5">
          <DismissLeadForm
            leadId={lead.id}
            reasons={DISMISS_REASONS}
            initialReason={benignRepeat ? 'benign_repeat' : undefined}
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
            <li key={i} className="truncate" title={o.summary ?? undefined}>
              ·{' '}
              <span
                className="mr-1 rounded-chip border border-border-faint px-1 text-[10px] text-faint"
                title={sourceTitle(o.source, o.shadow)}
              >
                {sourceLabel(o.source, o.shadow)}
              </span>
              {o.summary ?? kindLabel(o.kind, o.kind_label)}
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

export function LeadsStrip({
  entityKey,
  className,
  status: firstTab = 'needs_decision',
  noun = 'host',
  paramBound = false,
  onRows,
  collapsed = false,
  onToggleCollapsed,
}: {
  entityKey?: string;
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
  const leads = useAsync(() => getLeads(tab as LeadStatusFilter), [tab, reload], {
    refetchInterval: 60_000,
  });
  // The caller's callback, held in a ref so an inline arrow function in the
  // parent does not re-fire the effect below on every render.
  const onRowsRef = useRef(onRows);
  onRowsRef.current = onRows;
  // On a host page the strip shows only the leads that touch this host: the
  // lead points at the host, and the host page pointed at nothing.
  const rows = (leads.data ?? []).filter(
    (lead) => !entityKey || lead.entities.some((e) => e[1] === entityKey),
  );
  // The rows, to the block that asked for them. The effect keys on the loaded
  // list, so a render the poll did not change does not re-announce it.
  const loaded = leads.data;
  useEffect(() => {
    if (loaded) onRowsRef.current?.(rows);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loaded]);
  const onHost = Boolean(entityKey);
  // The server states the setting. A queued lead is the fallback for an
  // older server: reading the rule off the queue said "off" the moment the
  // queue was empty, and the note under the header then said the opposite of
  // what the deployment does.
  const needsYou = useAsync(() => getNeedsYou().catch(() => null), [reload]);
  const autoHunt =
    typeof needsYou.data?.lead_auto_hunt === 'boolean'
      ? needsYou.data.lead_auto_hunt
      : autoHuntOn(leads.data ?? []);
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
            className="inline-flex items-center gap-1.5 text-[10.5px] font-semibold uppercase tracking-[.06em] text-faint"
            title={HEADING_TITLE}
          >
            <GitBranch size={12} />
            {onHost ? `Leads on this ${noun}` : 'Leads'}
            {leads.data && (
              <span className="font-mono normal-case tracking-normal">
                · {countText(tab, rows.length)}
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
          {onHost && (
            <Link to="/hunts" className="text-[11px] text-accent hover:underline">
              all leads
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
          {!leads.data ? (
            <div className="px-[15px] py-2.5 text-[12.5px] text-dim">
              {leads.error ? 'Could not read the leads.' : 'Reading the leads…'}
            </div>
          ) : rows.length === 0 ? (
            // Absence is stated, with the reason it is not an all-clear.
            <div className="px-[15px] py-2.5 text-[12.5px] text-dim">{EMPTY_STATE[tab]}</div>
          ) : (
            <ul className="divide-y divide-border-faint">
              {rows.map((lead) => (
                <LeadRow
                  key={lead.id}
                  lead={lead}
                  autoHunt={autoHunt}
                  onChanged={() => setReload((n) => n + 1)}
                />
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
