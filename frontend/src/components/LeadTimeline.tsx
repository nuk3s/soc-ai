import { Link } from 'react-router-dom';

import { DocumentChip } from './DocumentDrawer';
import { REASON_LABEL } from './LeadsStrip';
import { Panel, PanelHeader } from './Panel';
import type { LeadDetail } from '../lib/api';
import { kindLabel, sourceLabel, sourceTitle } from '../lib/kinds';
import { plural } from '../lib/plural';
import { absTime, ago } from '../lib/timeRange';
import {
  CHIP_DISMISSED_EVENT,
  CHIP_SEEN,
  CHIP_TYPE,
  COUNT_OBSERVATIONS,
  OBSERVATION_NO_ANALYTIC,
  WEIGHT_NOW,
} from '../lib/tooltips';

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
  return Array.from(new Set(out)).slice(0, 8);
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

/** One lead's observations, newest first, with the dismissal on the record.
 *
 *  The dismissal line names the reopen. A lead an analyst put back in the
 *  queue read as a lead that had been dismissed and left. */
export function LeadTimeline({
  lead,
  title,
  className,
}: {
  lead: LeadDetail;
  title?: string;
  className?: string;
}) {
  const reopened = leadReopened(lead);
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
        {lead.dismissed_at && (
          <li data-testid="lead-dismissal" className="px-[15px] py-2.5 text-[13px]">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-[11px] text-dim" title={absTime(lead.dismissed_at)}>
                {ago(lead.dismissed_at)}
              </span>
              <span
                className="rounded-chip border border-border-strong bg-surface-2 px-1.5 py-px text-[10.5px] text-text-2"
                title={CHIP_DISMISSED_EVENT}
              >
                dismissed
              </span>
            </div>
            <div className="mt-0.5 font-medium">
              Dismissed {ago(lead.dismissed_at)} by {lead.dismissed_by}:{' '}
              {REASON_LABEL[lead.dismissed_reason ?? ''] ?? lead.dismissed_reason}
              {lead.dismissed_note ? `. ${lead.dismissed_note}` : ''}
              {reopened ? '. Reopened.' : ''}
            </div>
          </li>
        )}
        {lead.observations.map((o) => (
          <li key={o.id} className="px-[15px] py-2.5 text-[13px]" data-testid={`observation-${o.id}`}>
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-[11px] text-dim" title={absTime(o.born_at)}>
                {ago(o.born_at)}
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
                <span className="text-[11px] text-dim" title={CHIP_SEEN}>
                  seen {plural(o.occurrences, 'time')}
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
              {evidenceIds(o.evidence).length > 0 && (
                <>
                  <span>· evidence</span>
                  {/* The id opens the document. A dashed chip that did nothing
                      was the first state here, and a link into the
                      investigations search was the second. */}
                  {evidenceIds(o.evidence).map((eid) => (
                    <DocumentChip key={eid} id={eid} />
                  ))}
                </>
              )}
            </div>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
