import { useState } from 'react';
import { Link } from 'react-router-dom';

import { DocumentChip } from './DocumentDrawer';
import { HUNT_CLOSED_ACTOR, HUNT_CLOSED_OUTCOME, REASON_LABEL, closedByHunt } from './LeadsStrip';
import { Panel, PanelHeader } from './Panel';
import type { LeadDetail, LeadObservationDetail, LeadPromotedFinding } from '../lib/api';
import { kindLabel, sourceLabel, sourceTitle } from '../lib/kinds';
import {
  eventWindowText,
  observationSortTime,
  promotedFindingSentence,
  utcStamp,
  withStop,
} from '../lib/leadWords';
import {
  DECISION_WORD,
  HOLD_SENTENCE,
  actorOf,
  decisionsOf,
  type LeadDecision,
  type LeadDecisionFields,
} from '../lib/leadDecisions';
import { plural } from '../lib/plural';
import {
  dimensionMeasure,
  isZScore,
  rateMultipleSentence,
  rerunHref,
  statisticSentence,
} from '../lib/statistics';
import { ago } from '../lib/timeRange';
import {
  CHIP_DISMISSED_EVENT,
  CHIP_SWEEPS,
  CHIP_TYPE,
  COUNT_OBSERVATIONS,
  OBSERVATION_NO_ANALYTIC,
  OBSERVATION_RERUN,
  OBSERVATION_STATISTIC,
  SIGHTING_HALF_WEIGHT,
  WEIGHT_NOW,
} from '../lib/tooltips';

/** The hover text of an observation's time: the event time and the record
 *  time, or the record time alone when the row has no document time. Both in
 *  UTC, with the label, the zone the whole timeline reads. */
export function observationTimeTitle(o: {
  observed_at?: string | null;
  born_at: string | null;
}): string {
  return o.observed_at
    ? `Event time ${utcStamp(o.observed_at)}. Recorded ${utcStamp(o.born_at)}.`
    : `Recorded ${utcStamp(o.born_at)}. No document time is on record.`;
}

// ---------------------------------------------------------------------------
// The timeline of one lead: every observation that formed it, every decision
// on it, and every finding of its hunts that an analyst promoted.
//
// The lead page holds it, and the hunt page started from that lead holds it
// too. The hunt page named the lead and showed nothing of it, so an analyst
// reading the hunt had to leave it to learn what the hunt was about.
//
// One order, newest first. The decisions read oldest first above the
// observations, which read newest first, so lead 1 read 18d, 8d, now, now,
// now, 8d, 8d, 19d. Every row now sorts on one clock.
//
// An evidence id is a document id, and it is the proof the analytic matched
// the right thing. It opens the document in a drawer.
// ---------------------------------------------------------------------------

/** The document ids an observation cites, deduplicated and capped. */
export function evidenceIds(ev: Record<string, unknown> | null): string[] {
  if (!ev) return [];
  const out: string[] = [];
  for (const key of ['anchor_id', 'alert_id']) if (typeof ev[key] === 'string') out.push(ev[key] as string);
  for (const key of ['sample_ids', 'citations']) {
    const v = ev[key];
    if (Array.isArray(v)) out.push(...v.filter((x): x is string => typeof x === 'string'));
  }
  return Array.from(new Set(out)).slice(0, 10);
}

/** The documents a row cites: the column first, then the evidence. A row
 *  written before the column existed holds its ids in the evidence alone. */
export function observationIds(o: {
  document_ids?: string[];
  evidence: Record<string, unknown> | null;
}): string[] {
  return Array.from(new Set([...(o.document_ids ?? []), ...evidenceIds(o.evidence)])).slice(0, 10);
}

/** True when an analyst put a dismissed lead back in the queue. The dismissal
 *  stays on the record, and the reopen is the next decision on it.
 *
 *  The rule lives here, with the line it writes. The lead page derived it and
 *  passed it in, and the hunt page rendered the same timeline without it, so
 *  one entry read two ways on two screens. */
export function leadReopened(lead: {
  status: string;
  dismissed_at?: string | null;
}): boolean {
  return Boolean(lead.dismissed_at) && (lead.status === 'open' || lead.status === 'hunting');
}

/** The reopen of a lead, in a sentence that names who and why. A row written
 *  before the history named the hand reads as an unknown hand: the record
 *  does not say, and the timeline does not guess. */
const REOPEN_UNKNOWN = 'Reopened. The record does not name who reopened it.';

/** One decision on the lead, in one sentence. */
export function decisionSentence(d: LeadDecision): string {
  const by = actorOf(d.by, HUNT_CLOSED_ACTOR);
  switch (d.action) {
    case 'dismissed': {
      const reason = REASON_LABEL[d.reason ?? ''] ?? d.reason ?? 'Other';
      // One stop at the end. A note that ends in a stop read "shipping..".
      return withStop(`Dismissed${by ? ` by ${by}` : ''}: ${reason}${d.note ? `. ${d.note}` : ''}`);
    }
    case 'reopened':
      // C3: the row names the hand and the cause. "Reopened." named neither.
      if (d.reason === 'new_type')
        return `Reopened by ${HUNT_CLOSED_ACTOR}. A new observation arrived, of a type the lead did not hold.`;
      if (by === HUNT_CLOSED_ACTOR) return `Reopened by ${HUNT_CLOSED_ACTOR}. A new observation arrived.`;
      return by ? `Reopened by ${by}. The analyst put the lead back to decide again.` : REOPEN_UNKNOWN;
    case 'promoted':
      // The store keeps the word `promoted`. The row names the act by its
      // control, so it reads "opened an investigation" (owner, 2026-10-07).
      // S2: the analyst closed the lead on the verdict of a finding's
      // investigation.
      if (d.reason === 'finding_verdict')
        return `${by || 'An analyst'} closed the lead on the investigation of a hunt finding.`;
      return `${by || 'An analyst'} opened an investigation on this lead.`;
    case 'kept_open':
      return `Kept open${by ? ` by ${by}` : ''}. The investigation of a hunt finding reached a verdict.`;
    case 'closed_by_hunt':
      return `Closed by ${HUNT_CLOSED_ACTOR}. ${HUNT_CLOSED_OUTCOME}`;
    case 'held':
      return `Left open by ${HUNT_CLOSED_ACTOR}. ${
        HOLD_SENTENCE[d.reason ?? ''] ?? 'The hunt did not settle the lead.'
      }`;
    case 'formed_from_backtest':
      // The server stores the sentence with the mark. The raw code was the
      // only text on the row.
      return d.note ?? 'This lead formed from a backtest replay.';
    default:
      return d.action;
  }
}

const CHIP_CLASS =
  'rounded-chip border border-border-strong bg-surface-2 px-1.5 py-px text-[10.5px] text-text-2';

/** The relative time of a row, with the UTC time in the hover. */
function When({ at }: { at: string | null }) {
  if (!at) return null;
  return (
    <span className="font-mono text-[11px] text-dim" title={utcStamp(at)}>
      {ago(at)}
    </span>
  );
}

/** One decision on the lead. */
function DecisionRow({ d }: { d: LeadDecision }) {
  return (
    <li data-testid="lead-decision" className="px-[15px] py-2.5 text-[13px]">
      <div className="flex flex-wrap items-center gap-2">
        <When at={d.at} />
        <span className={CHIP_CLASS} title={CHIP_DISMISSED_EVENT}>
          {DECISION_WORD[d.action] ?? d.action}
        </span>
      </div>
      <div className="mt-0.5 font-medium">
        {decisionSentence(d)}
        {(d.action === 'promoted' || d.action === 'kept_open') && d.investigation_id && (
          <>
            {' '}
            <Link
              to={`/investigation/${encodeURIComponent(d.investigation_id)}`}
              className="font-mono text-[12px] text-accent hover:underline"
            >
              {d.investigation_id}
            </Link>
          </>
        )}
        {/* K5: the link names the act. The hunt id said nothing an analyst
            can use, so it moves to the hover. */}
        {(d.action === 'closed_by_hunt' || d.action === 'held') && d.hunt_id && (
          <>
            {' '}
            <Link
              to={`/hunts/${encodeURIComponent(d.hunt_id)}`}
              className="text-[12px] text-accent hover:underline"
              title={`Open hunt ${d.hunt_id}.`}
            >
              Read the hunt
            </Link>
          </>
        )}
      </div>
    </li>
  );
}

/** The one dismissal a server with no history sends. The line names the
 *  reopen, because the record holds no reopen of its own. */
function LegacyDismissalRow({ lead }: { lead: LeadDetail }) {
  const at = lead.dismissed_at ?? null;
  return (
    <li data-testid="lead-dismissal" className="px-[15px] py-2.5 text-[13px]">
      <div className="flex flex-wrap items-center gap-2">
        <When at={at} />
        <span className={CHIP_CLASS} title={CHIP_DISMISSED_EVENT}>
          {closedByHunt(lead) ? 'closed' : 'dismissed'}
        </span>
      </div>
      <div className="mt-0.5 font-medium">
        {closedByHunt(lead)
          ? `Closed ${ago(at)} by ${HUNT_CLOSED_ACTOR}. ${HUNT_CLOSED_OUTCOME}`
          : withStop(
              `Dismissed ${ago(at)} by ${lead.dismissed_by}: ${
                REASON_LABEL[lead.dismissed_reason ?? ''] ?? lead.dismissed_reason
              }${lead.dismissed_note ? `. ${lead.dismissed_note}` : ''}`,
            )}
        {leadReopened(lead) ? ` ${REOPEN_UNKNOWN}` : ''}
      </div>
    </li>
  );
}

/** S2: a finding promoted from a hunt on this lead, and the verdict its
 *  investigation reached. The lead page said nothing of it. */
function FindingRow({ p }: { p: LeadPromotedFinding }) {
  return (
    <li data-testid="lead-promoted-finding" className="px-[15px] py-2.5 text-[13px]">
      <div className="flex flex-wrap items-center gap-2">
        <When at={p.promoted_at} />
        <span className={CHIP_CLASS}>investigation opened</span>
      </div>
      <div className="mt-0.5 font-medium">
        {promotedFindingSentence(p)}{' '}
        <Link
          to={`/investigation/${encodeURIComponent(p.investigation_id)}`}
          className="text-[12px] text-accent hover:underline"
          title={`Investigation ${p.investigation_id}${p.finding_title ? `: ${p.finding_title}` : ''}`}
        >
          View investigation
        </Link>
      </div>
    </li>
  );
}

/** The dimension and the member of a departure, from the baseline block the
 *  profile sweep writes into the evidence. The hunt objective names them. */
function departureOf(evidence: Record<string, unknown> | null): {
  dimension: string | null;
  member: string | null;
} {
  const block = evidence?.baseline;
  if (!block || typeof block !== 'object') return { dimension: null, member: null };
  const b = block as Record<string, unknown>;
  return {
    dimension: typeof b.dimension === 'string' ? b.dimension : null,
    member: typeof b.member === 'string' ? b.member : null,
  };
}

/** Copy one query to the clipboard, and say whether the copy landed. */
function CopyQuery({ query }: { query: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(query);
      setState('copied');
    } catch {
      setState('failed');
    }
  };
  return (
    <button
      type="button"
      onClick={() => void copy()}
      className="text-accent hover:underline"
      title="Copy the query. Paste it into Security Onion Hunt to read the events."
    >
      {state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed. Select the query.' : 'Copy query'}
    </button>
  );
}

/** The count in the hour that departed, from the baseline block the profile
 *  sweep writes into the evidence. */
function observedCount(evidence: Record<string, unknown> | null): number | null {
  const block = evidence?.baseline;
  if (!block || typeof block !== 'object') return null;
  const n = (block as Record<string, unknown>).observed_count;
  return typeof n === 'number' ? n : null;
}

/** One observation on the lead. `scoring` shows the weights and the z score:
 *  C2 moved them behind the lead page's Scoring toggle. */
function ObservationRow({
  o,
  lead,
  scoring,
}: {
  o: LeadObservationDetail;
  lead: LeadDetail;
  scoring: boolean;
}) {
  const raw = statisticSentence(o.statistic, o.statistic_value, o.baseline_value);
  const multiple = rateMultipleSentence(o.statistic, observedCount(o.evidence), o.baseline_value);
  // A z score reads as a multiple of the expected rate. The z itself is a
  // number of the scoring, and it shows with the weights.
  const plain = multiple || (isZScore(o.statistic) ? '' : raw);
  return (
    <li className="px-[15px] py-2.5 text-[13px]" data-testid={`observation-${o.id}`}>
      <div className="flex flex-wrap items-center gap-2">
        {/* The event time when the row has one. The record time read an
            event a day old as new on the sweep that found it. */}
        <span
          className="font-mono text-[11px] text-dim"
          title={observationTimeTitle(o)}
          data-testid={`observation-time-${o.id}`}
        >
          {ago(o.observed_at ?? o.born_at)}
        </span>
        <span className={CHIP_CLASS} title={CHIP_TYPE}>
          {kindLabel(o.kind, o.kind_label)}
        </span>
        {/* One chip, one word. A shadow row read "shadow" beside "candidate",
            and "candidate" is a status that writes nothing. C8: a row whose
            analytic an analyst retired kept its shadow chip. It now says the
            analytic is retired, and on which day. */}
        {o.analytic_retired_at ? (
          <span
            className="rounded-chip border border-border-faint px-1 text-[10px] text-faint"
            data-testid={`observation-retired-${o.id}`}
            title="An analyst retired the analytic that wrote this observation. It no longer runs."
          >
            analytic retired on {o.analytic_retired_at.slice(0, 10)}
          </span>
        ) : (
          <span
            className="rounded-chip border border-border-faint px-1 text-[10px]"
            style={o.shadow ? { color: '#d29922', borderColor: 'rgba(210,153,34,.35)' } : undefined}
            title={sourceTitle(o.source, o.shadow)}
          >
            {sourceLabel(o.source, o.shadow)}
          </span>
        )}
        {scoring && (
          <span
            className="font-mono text-[11px] text-dim"
            title={WEIGHT_NOW}
            data-testid={`observation-weight-${o.id}`}
          >
            weight {o.birth_weight.toFixed(2)} at first sighting, {o.weight_now.toFixed(2)} now
          </span>
        )}
        {o.occurrences > 1 && (
          <span className="text-[11px] text-dim" title={CHIP_SWEEPS}>
            seen on {plural(o.occurrences, 'sweep')}
            {o.first_seen_at ? `, first seen ${ago(o.first_seen_at)}` : ''}
          </span>
        )}
      </div>
      <div className="mt-0.5 font-medium">{o.summary ?? kindLabel(o.kind, o.kind_label)}</div>
      {/* C3: the row is dated by the events it describes, in UTC. */}
      <div className="mt-0.5 text-[11.5px] text-dim" data-testid={`observation-window-${o.id}`}>
        {eventWindowText(o)}
      </div>
      <div className="mt-0.5 flex flex-wrap items-center gap-1 text-[11.5px] text-dim">
        {/* The id opens the analytic. It was plain text, so a lead named its
            analytic and gave no way to read it.

            An alert verdict writes an observation, and an alert has no
            analytic. The row linked every id, so `?open=alert` opened a
            drawer titled "alert / alert" that read "Could not read the
            analytic". A link goes to a page, so an id with nothing to open is
            text. */}
        {o.spec_id ? (
          o.analytic_exists === false ? (
            <span className="font-mono" title={OBSERVATION_NO_ANALYTIC}>
              {o.spec_id}
            </span>
          ) : (
            <Link
              to={`/hunts?tab=analytics&open=${encodeURIComponent(o.spec_id)}`}
              className="font-mono hover:underline"
              title="Open the analytic that wrote this observation."
            >
              {o.spec_id}
            </Link>
          )
        ) : null}
        {observationIds(o).length > 0 && (
          <>
            <span>· evidence</span>
            {/* The id opens the document. A dashed chip that did nothing was
                the first state here, and a link into the investigations
                search was the second. */}
            {observationIds(o).map((eid) => (
              <DocumentChip key={eid} id={eid} />
            ))}
          </>
        )}
      </div>
      {/* The statistic and the query the observation carries. The numbers
          lived in the summary sentence, and the hunt searched the grid for the
          departure again. */}
      {plain && (
        <div
          className="mt-0.5 text-[11.5px] text-text-2"
          data-testid={`observation-statistic-${o.id}`}
          title={OBSERVATION_STATISTIC}
        >
          {plain}
        </div>
      )}
      {/* W7: the count the departure measures. The analyst could not tell
          which count spiked on a host that serves DNS. */}
      {dimensionMeasure(departureOf(o.evidence).dimension) && (
        <div className="mt-0.5 text-[11.5px] text-dim" data-testid={`observation-measures-${o.id}`}>
          {dimensionMeasure(departureOf(o.evidence).dimension)}
        </div>
      )}
      {scoring && isZScore(o.statistic) && raw && (
        <div className="mt-0.5 font-mono text-[11px] text-dim" data-testid={`observation-score-${o.id}`}>
          {raw}
        </div>
      )}
      {o.rerun_query && (
        <div
          className="mt-0.5 flex flex-wrap items-center gap-2 text-[11.5px] text-dim"
          data-testid={`observation-query-${o.id}`}
        >
          <code className="break-all font-mono text-[11px] text-text-2">{o.rerun_query}</code>
          {/* W6: "Run this query" started a hunt and ran no query. The two
              acts now carry their own names. */}
          <CopyQuery query={o.rerun_query} />
          <Link
            to={rerunHref(o.rerun_query, lead.entities[0]?.[1] ?? 'the entity', departureOf(o.evidence))}
            className="text-accent hover:underline"
            title={OBSERVATION_RERUN}
          >
            Hunt with this query
          </Link>
        </div>
      )}
    </li>
  );
}

/** One row of the timeline and the time it sorts on. */
type Entry =
  | { type: 'decision'; at: string | null; key: string; d: LeadDecision }
  | { type: 'dismissal'; at: string | null; key: string }
  | { type: 'finding'; at: string | null; key: string; p: LeadPromotedFinding }
  | { type: 'observation'; at: string | null; key: string; o: LeadObservationDetail };

/** Newest first. A row with no time goes last, in the order it came. */
function newestFirst(a: Entry, b: Entry): number {
  const ta = a.at ? Date.parse(a.at) : Number.NaN;
  const tb = b.at ? Date.parse(b.at) : Number.NaN;
  if (Number.isNaN(ta) && Number.isNaN(tb)) return 0;
  if (Number.isNaN(ta)) return 1;
  if (Number.isNaN(tb)) return -1;
  return tb - ta;
}

/** Every row of the timeline, newest first. */
export function timelineEntries(lead: LeadDetail & LeadDecisionFields): Entry[] {
  const decisions = decisionsOf(lead);
  const entries: Entry[] = [];
  (decisions ?? []).forEach((d, i) =>
    entries.push({ type: 'decision', at: d.at, key: `decision-${i}`, d }),
  );
  // The dismissal is a decision on the record, so it stays on the timeline
  // whatever the lead's status is now. A server with no history sends it in
  // the dismissal columns alone.
  if (!decisions && lead.dismissed_at) {
    entries.push({ type: 'dismissal', at: lead.dismissed_at, key: 'dismissal' });
  }
  for (const p of lead.promoted_findings ?? []) {
    entries.push({ type: 'finding', at: p.promoted_at, key: `finding-${p.investigation_id}`, p });
  }
  for (const o of lead.observations) {
    entries.push({ type: 'observation', at: observationSortTime(o), key: `observation-${o.id}`, o });
  }
  return entries.sort(newestFirst);
}

/** The count in the header: every kind of row the timeline holds. The header
 *  said "4 observations" over seven rows. */
function headerCount(lead: LeadDetail & LeadDecisionFields): string {
  const decisions = decisionsOf(lead)?.length ?? (lead.dismissed_at ? 1 : 0);
  const findings = lead.promoted_findings?.length ?? 0;
  const parts = [plural(lead.observations.length, 'observation')];
  if (decisions > 0) parts.push(plural(decisions, 'decision'));
  if (findings > 0) parts.push(plural(findings, 'investigated finding'));
  return parts.join(' · ');
}

/** One lead's timeline: observations, decisions and promoted findings in one
 *  order, newest first, with every time in UTC. */
export function LeadTimeline({
  lead,
  title,
  className,
  scoring = false,
}: {
  lead: LeadDetail & LeadDecisionFields;
  title?: string;
  className?: string;
  /** Show the weights and the z scores. The lead page holds the toggle. */
  scoring?: boolean;
}) {
  const entries = timelineEntries(lead);
  return (
    <Panel className={className ?? 'mt-4'}>
      <PanelHeader
        title={<span title={COUNT_OBSERVATIONS}>{title ?? `Timeline · ${headerCount(lead)}`}</span>}
        right={
          <span className="text-[11px] text-dim">
            <span data-testid="lead-timeline-note">Newest first. Times in UTC.</span>
            {scoring && (
              <span title={WEIGHT_NOW}> {SIGHTING_HALF_WEIGHT}</span>
            )}
          </span>
        }
      />
      <ul className="divide-y divide-border-faint">
        {entries.map((e) =>
          e.type === 'decision' ? (
            <DecisionRow key={e.key} d={e.d} />
          ) : e.type === 'dismissal' ? (
            <LegacyDismissalRow key={e.key} lead={lead} />
          ) : e.type === 'finding' ? (
            <FindingRow key={e.key} p={e.p} />
          ) : (
            <ObservationRow key={e.key} o={e.o} lead={lead} scoring={scoring} />
          ),
        )}
        {/* F10: a lead whose observations aged out or were removed read
            "0 observations" under a header that counted one. The kinds that
            formed it are on the record, so the empty list says them. */}
        {lead.observations.length === 0 && (
          <li data-testid="lead-no-observations" className="px-[15px] py-2.5 text-[12.5px] text-dim">
            {`No observation remains on this lead. It formed from ${
              lead.kinds.map((k, i) => kindLabel(k, lead.kind_labels?.[i])).join(' and ') ||
              'observations that are gone'
            }.`}
          </li>
        )}
      </ul>
    </Panel>
  );
}
