import { Link } from 'react-router-dom';

import { DocumentChip } from './DocumentDrawer';
import { HUNT_CLOSED_ACTOR, REASON_LABEL, closedByHunt } from './LeadsStrip';
import { Panel, PanelHeader } from './Panel';
import type { LeadDetail } from '../lib/api';
import { kindLabel, sourceLabel, sourceTitle } from '../lib/kinds';
import {
  DECISION_WORD,
  HOLD_SENTENCE,
  actorOf,
  decisionsOf,
  type LeadDecision,
  type LeadDecisionFields,
} from '../lib/leadDecisions';
import { plural } from '../lib/plural';
import { rerunHref, statisticSentence } from '../lib/statistics';
import { absTime, ago } from '../lib/timeRange';
import {
  CHIP_DISMISSED_EVENT,
  CHIP_SWEEPS,
  CHIP_TYPE,
  COUNT_OBSERVATIONS,
  OBSERVATION_NO_ANALYTIC,
  OBSERVATION_RERUN,
  OBSERVATION_STATISTIC,
  WEIGHT_NOW,
} from '../lib/tooltips';

/** The hover text of an observation's time: the event time and the record
 *  time, or the record time alone when the row has no document time. */
export function observationTimeTitle(o: {
  observed_at?: string | null;
  born_at: string | null;
}): string {
  return o.observed_at
    ? `Event time ${absTime(o.observed_at)}. Recorded ${absTime(o.born_at)}.`
    : `Recorded ${absTime(o.born_at)}. No document time is on record.`;
}

// ---------------------------------------------------------------------------
// The timeline of one lead: every observation that formed it, and the
// dismissal if an analyst has taken one.
//
// The lead page holds it, and the hunt page started from that lead holds it
// too. The hunt page named the lead and showed nothing of it, so an analyst
// reading the hunt had to leave it to learn what the hunt was about.
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

/** One decision on the lead, in one sentence. */
export function decisionSentence(d: LeadDecision): string {
  const by = actorOf(d.by, HUNT_CLOSED_ACTOR);
  switch (d.action) {
    case 'dismissed': {
      const reason = REASON_LABEL[d.reason ?? ''] ?? d.reason ?? 'Other';
      return `Dismissed${by ? ` by ${by}` : ''}: ${reason}${d.note ? `. ${d.note}` : ''}.`;
    }
    case 'reopened':
      if (d.reason === 'new_type')
        return `Reopened by ${HUNT_CLOSED_ACTOR}. An observation of a new type joined the lead.`;
      return by ? `Reopened by ${by}.` : 'Reopened.';
    case 'promoted':
      return `Promoted${by ? ` by ${by}` : ''} to an investigation.`;
    case 'closed_by_hunt':
      return `Closed by ${HUNT_CLOSED_ACTOR}. The hunt found no threat.`;
    case 'held':
      return `Left open by ${HUNT_CLOSED_ACTOR}. ${
        HOLD_SENTENCE[d.reason ?? ''] ?? 'The hunt did not settle the lead.'
      }`;
    default:
      return d.action;
  }
}

/** Every decision on the lead, oldest first. */
function DecisionRows({ decisions }: { decisions: LeadDecision[] }) {
  return (
    <>
      {decisions.map((d, i) => (
        <li
          key={`${d.action}-${d.at ?? ''}-${i}`}
          data-testid="lead-decision"
          className="px-[15px] py-2.5 text-[13px]"
        >
          <div className="flex flex-wrap items-center gap-2">
            {d.at && (
              <span className="font-mono text-[11px] text-dim" title={absTime(d.at)}>
                {ago(d.at)}
              </span>
            )}
            <span
              className="rounded-chip border border-border-strong bg-surface-2 px-1.5 py-px text-[10.5px] text-text-2"
              title={CHIP_DISMISSED_EVENT}
            >
              {DECISION_WORD[d.action] ?? d.action}
            </span>
          </div>
          <div className="mt-0.5 font-medium">
            {decisionSentence(d)}
            {d.action === 'promoted' && d.investigation_id && (
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
            {(d.action === 'closed_by_hunt' || d.action === 'held') && d.hunt_id && (
              <>
                {' '}
                <Link
                  to={`/hunts/${encodeURIComponent(d.hunt_id)}`}
                  className="font-mono text-[12px] text-accent hover:underline"
                >
                  {d.hunt_id}
                </Link>
              </>
            )}
          </div>
        </li>
      ))}
    </>
  );
}

/** One lead's observations, newest first, under every decision on the record.
 *
 *  The decisions read oldest first, so a dismiss, a reopen and a promotion
 *  read in the order they happened. A server that sends no history gets the
 *  single dismissal line, and that line names the reopen. */
export function LeadTimeline({
  lead,
  title,
  className,
}: {
  lead: LeadDetail & LeadDecisionFields;
  title?: string;
  className?: string;
}) {
  const reopened = leadReopened(lead);
  const decisions = decisionsOf(lead);
  return (
    <Panel className={className ?? 'mt-4'}>
      <PanelHeader
        title={
          <span title={COUNT_OBSERVATIONS}>
            {title ?? `Timeline · ${plural(lead.observations.length, 'observation')}`}
          </span>
        }
        right={
          <span className="text-[11px] text-dim" title={WEIGHT_NOW}>
            live weight decays with a 48 h half-life
          </span>
        }
      />
      <ul className="divide-y divide-border-faint">
        {/* The dismissal is a decision on the record, so it stays on the
            timeline whatever the lead's status is now. */}
        {decisions && decisions.length > 0 && <DecisionRows decisions={decisions} />}
        {!decisions && lead.dismissed_at && (
          <li data-testid="lead-dismissal" className="px-[15px] py-2.5 text-[13px]">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-[11px] text-dim" title={absTime(lead.dismissed_at)}>
                {ago(lead.dismissed_at)}
              </span>
              <span
                className="rounded-chip border border-border-strong bg-surface-2 px-1.5 py-px text-[10.5px] text-text-2"
                title={CHIP_DISMISSED_EVENT}
              >
                {closedByHunt(lead) ? 'closed' : 'dismissed'}
              </span>
            </div>
            <div className="mt-0.5 font-medium">
              {closedByHunt(lead)
                ? `Closed ${ago(lead.dismissed_at)} by ${HUNT_CLOSED_ACTOR}. The hunt found no threat.`
                : `Dismissed ${ago(lead.dismissed_at)} by ${lead.dismissed_by}: ${
                    REASON_LABEL[lead.dismissed_reason ?? ''] ?? lead.dismissed_reason
                  }${lead.dismissed_note ? `. ${lead.dismissed_note}` : ''}`}
              {reopened ? '. Reopened.' : ''}
            </div>
          </li>
        )}
        {/* F10: a lead whose observations aged out or were removed read
            "0 observations" under a header that counted one. The kinds
            that formed it are on the record, so the empty list says them. */}
        {lead.observations.length === 0 && (
          <li data-testid="lead-no-observations" className="px-[15px] py-2.5 text-[12.5px] text-dim">
            {`No observation remains on this lead. It formed from ${
              lead.kinds.map((k, i) => kindLabel(k, lead.kind_labels?.[i])).join(' and ') ||
              'observations that are gone'
            }.`}
          </li>
        )}
        {lead.observations.map((o) => (
          <li key={o.id} className="px-[15px] py-2.5 text-[13px]" data-testid={`observation-${o.id}`}>
            <div className="flex flex-wrap items-center gap-2">
              {/* The event time when the row has one. The record time
                  read an event a day old as new on the sweep that found it. */}
              <span
                className="font-mono text-[11px] text-dim"
                title={observationTimeTitle(o)}
                data-testid={`observation-time-${o.id}`}
              >
                {ago(o.observed_at ?? o.born_at)}
              </span>
              <span
                className="rounded-chip border border-border-strong bg-surface-2 px-1.5 py-px text-[10.5px] text-text-2"
                title={CHIP_TYPE}
              >
                {kindLabel(o.kind, o.kind_label)}
              </span>
              {/* One chip, one word. A shadow row read "shadow" beside
                  "candidate", and "candidate" is a status that writes
                  nothing. */}
              <span
                className="rounded-chip border border-border-faint px-1 text-[10px]"
                style={o.shadow ? { color: '#d29922', borderColor: 'rgba(210,153,34,.35)' } : undefined}
                title={sourceTitle(o.source, o.shadow)}
              >
                {sourceLabel(o.source, o.shadow)}
              </span>
              <span className="font-mono text-[11px] text-dim" title={WEIGHT_NOW}>
                {o.birth_weight.toFixed(2)} → {o.weight_now.toFixed(2)} now
              </span>
              {o.occurrences > 1 && (
                <span className="text-[11px] text-dim" title={CHIP_SWEEPS}>
                  seen on {plural(o.occurrences, 'sweep')}
                  {o.first_seen_at ? `, first seen ${ago(o.first_seen_at)}` : ''}
                </span>
              )}
            </div>
            <div className="mt-0.5 font-medium">{o.summary ?? kindLabel(o.kind, o.kind_label)}</div>
            <div className="mt-0.5 flex flex-wrap items-center gap-1 text-[11.5px] text-dim">
              {/* The id opens the analytic. It was plain text, so a lead named
                  its analytic and gave no way to read it.

                  An alert verdict writes an observation, and an alert has no
                  analytic. The row linked every id, so `?open=alert` opened a
                  drawer titled "alert / alert" that read "Could not read the
                  analytic". A link goes to a page, so an id with nothing to
                  open is text. */}
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
                  {/* The id opens the document. A dashed chip that did nothing
                      was the first state here, and a link into the
                      investigations search was the second. */}
                  {observationIds(o).map((eid) => (
                    <DocumentChip key={eid} id={eid} />
                  ))}
                </>
              )}
            </div>
            {/* The statistic and the query the observation carries. The
                numbers lived in the summary sentence, and the hunt searched
                the grid for the departure again. */}
            {statisticSentence(o.statistic, o.statistic_value, o.baseline_value) && (
              <div
                className="mt-0.5 text-[11.5px] text-text-2"
                data-testid={`observation-statistic-${o.id}`}
                title={OBSERVATION_STATISTIC}
              >
                {statisticSentence(o.statistic, o.statistic_value, o.baseline_value)}
              </div>
            )}
            {o.rerun_query && (
              <div
                className="mt-0.5 flex flex-wrap items-center gap-2 text-[11.5px] text-dim"
                data-testid={`observation-query-${o.id}`}
              >
                <code className="break-all font-mono text-[11px] text-text-2">{o.rerun_query}</code>
                <Link
                  to={rerunHref(o.rerun_query, lead.entities[0]?.[1] ?? 'the entity')}
                  className="text-accent hover:underline"
                  title={OBSERVATION_RERUN}
                >
                  Run this query
                </Link>
              </div>
            )}
          </li>
        ))}
      </ul>
    </Panel>
  );
}
