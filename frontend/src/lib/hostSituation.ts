import type { EntityObservation, Lead } from './api';
import { plural } from './plural';

// ---------------------------------------------------------------------------
// The first lines of the host page: what waits on this host, and what the
// verdicts of the last seven days found (dogfood 2026-10-06, hosts S3 and
// architecture change 4).
//
// The range attacker's page opened on "has appeared on the network. Nothing
// else is known about it yet." and "ALERTS 7D 0 · nothing fired". Lower on
// the page sat six alert verdicts, five of them true positives, and a lead
// whose hunt found threats. The page held the facts and led with the one
// sentence that said there were none. These rules build the first screen
// from the facts the page holds: open leads first, then the verdicts, then
// identity.
// ---------------------------------------------------------------------------

/** One sentence, with the in-app link that proves it when it has one. */
export interface SituationLine {
  text: string;
  to?: string;
  /** `alarm` for a threat or a true positive, else `info`. */
  tone: 'alarm' | 'info';
  /** The scope of the line, in visible words. The page has a 24h and a 7d
   *  button, and these lines follow neither, so each line says what it
   *  covers. A hover title is not a label. */
  scope?: string;
}

/** The scope words of the lead lines. A backlog keeps its full scope. */
export const SCOPE_OPEN_LEADS = 'all open leads';
/** The scope words of the verdict lines. The observations read is 7 days,
 *  the window of the Alerts card. */
export const VERDICT_DAYS = 7;
export const SCOPE_VERDICTS = `last ${VERDICT_DAYS} days`;

/** The lead statuses that still wait on soc-ai or on the analyst. */
const OPEN = new Set(['open', 'hunting']);
const HUNT_RUNNING = new Set(['running', 'queued']);

type OpenState = 'decision' | 'new' | 'queued' | 'hunting';

function openState(lead: Lead): OpenState {
  if (lead.hunt_status && !HUNT_RUNNING.has(lead.hunt_status)) return 'decision';
  if (lead.status === 'hunting' || lead.hunt_status) return 'hunting';
  if (lead.hunt_queued) return 'queued';
  return 'new';
}

/** The order an analyst reads open leads in: what waits on a decision, what
 *  nobody has touched, what soc-ai is about to hunt, what a hunt holds now. */
const URGENCY: Record<OpenState, number> = { decision: 0, new: 1, queued: 2, hunting: 3 };

/** The rank of a finished hunt's outcome among the leads that wait on a
 *  decision: a threat first, then a hunt that could not read part of the
 *  data, then a hunt that could not run, then a clean hunt. The hero
 *  headlined a clean lead above a lead whose hunt found a threat (dogfood
 *  2026-10-19, R4-D7). */
function outcomeRank(lead: Lead): number {
  if (openState(lead) !== 'decision') return 0;
  const code = (lead.hunt_outcome ?? '').toLowerCase();
  const label = (lead.hunt_outcome_label ?? '').trim().toLowerCase();
  if (code === 'threats' || (lead.hunt_threat_count ?? 0) > 0 || label.startsWith('threat')) return 0;
  if (code === 'gap' || label.includes('visibility gap')) return 1;
  if (code === 'failed' || label.startsWith('could not run')) return 2;
  return 3;
}

/** The sentence for the outcome of a finished hunt. */
export function huntOutcomeSentence(label: string | null | undefined): string {
  const text = (label ?? '').trim();
  const folded = text.toLowerCase();
  if (!text) return 'Its hunt finished.';
  if (folded.startsWith('threat')) return 'Its hunt found threats.';
  if (folded.includes('visibility gap')) return 'Its hunt found no threat. Part of the data could not be read.';
  if (folded.startsWith('no threat')) return 'Its hunt found no threat.';
  if (folded.startsWith('could not run')) return 'Its hunt could not run.';
  return `Its hunt finished: ${text}.`;
}

/** The sentence for one open lead. */
export function leadLine(lead: Lead): SituationLine {
  const to = `/leads/${lead.id}`;
  switch (openState(lead)) {
    case 'decision': {
      const outcome = huntOutcomeSentence(lead.hunt_outcome_label);
      return {
        text: `Lead ${lead.id} waits on a decision. ${outcome}`,
        to,
        tone: outcome.includes('found threats') ? 'alarm' : 'info',
      };
    }
    case 'queued':
      return { text: `Lead ${lead.id} is new. soc-ai starts its hunt within a minute.`, to, tone: 'info' };
    case 'hunting':
      return { text: `Lead ${lead.id} is under a hunt now.`, to, tone: 'info' };
    default:
      return { text: `Lead ${lead.id} is new. It waits on a hunt or a decision.`, to, tone: 'info' };
  }
}

/** The open leads on the host, the most urgent first. */
export function openLeads(leads: readonly Lead[]): Lead[] {
  return leads
    .filter((l) => OPEN.has(l.status))
    .sort(
      (a, b) =>
        URGENCY[openState(a)] - URGENCY[openState(b)] || outcomeRank(a) - outcomeRank(b) || b.id - a.id,
    );
}

/** The lead lines: the most urgent lead in full, then a count of the rest.
 *
 *  `total` is the server's count of the open leads on the host. The rows
 *  stop at a limit, and the count does not. Without it the rows count. */
export function leadLines(leads: readonly Lead[], total?: number | null): SituationLine[] {
  const open = openLeads(leads);
  if (open.length === 0) return [];
  const lines = [{ ...leadLine(open[0]), scope: SCOPE_OPEN_LEADS }];
  const all = typeof total === 'number' ? Math.max(total, open.length) : open.length;
  if (all > 1) {
    const rest = all - 1;
    lines.push({
      text: `${plural(rest, 'more open lead')} ${rest === 1 ? 'names' : 'name'} this host.`,
      tone: 'info',
      scope: SCOPE_OPEN_LEADS,
    });
  }
  return lines;
}

/** The scope words of the investigation line. The count covers every
 *  investigation of the machine. */
export const SCOPE_INVESTIGATIONS = 'all time';

/** The investigation line: the true positives of the machine, over all
 *  time, with the filtered list as its proof. No line without a true
 *  positive: the Investigations block below the hero holds the count. */
export function investigationLines(total: number, truePositives: number, to: string): SituationLine[] {
  if (total <= 0 || truePositives <= 0) return [];
  return [
    {
      text: `${plural(truePositives, 'investigation')} of this host reached a true-positive verdict.`,
      to,
      tone: 'alarm',
      scope: SCOPE_INVESTIGATIONS,
    },
  ];
}

/** "today", "1 day ago", "5 days ago". */
export function daysAgo(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return 'at an unknown time';
  const ms = now - new Date(iso).getTime();
  if (!Number.isFinite(ms)) return 'at an unknown time';
  const days = Math.floor(ms / 86_400_000);
  if (days <= 0) return 'today';
  return days === 1 ? '1 day ago' : `${days} days ago`;
}

/** The alert verdicts the observations hold, one per alert. */
export function alertVerdicts(observations: readonly EntityObservation[]): EntityObservation[] {
  return observations.filter((o) => o.source === 'alert' && !!o.verdict);
}

/** When a set of verdicts happened: "5 days ago" when all fall on one day,
 *  else "the newest 2 days ago". */
function whenPhrase(rows: readonly EntityObservation[], now: number): string {
  const days = new Set(rows.map((o) => daysAgo(o.born_at, now)));
  const newest = rows.reduce<string | null>(
    (best, o) => (o.born_at && (!best || o.born_at > best) ? o.born_at : best),
    null,
  );
  return days.size <= 1 ? daysAgo(newest, now) : `the newest ${daysAgo(newest, now)}`;
}

/** The verdict lines: the true positives first, then the verdicts that need
 *  more information. "5 true-positive alerts, 5 days ago." */
export function verdictLines(
  observations: readonly EntityObservation[],
  now = Date.now(),
): SituationLine[] {
  const verdicts = alertVerdicts(observations);
  const lines: SituationLine[] = [];
  const tp = verdicts.filter((o) => o.verdict === 'true_positive');
  if (tp.length > 0) {
    lines.push({
      text: `${plural(tp.length, 'true-positive alert')}, ${whenPhrase(tp, now)}.`,
      tone: 'alarm',
      scope: SCOPE_VERDICTS,
    });
  }
  const nmi = verdicts.filter((o) => o.verdict === 'needs_more_info');
  if (nmi.length > 0) {
    lines.push({
      text: `${plural(nmi.length, 'alert')} ${nmi.length === 1 ? 'needs' : 'need'} more information, ${whenPhrase(nmi, now)}.`,
      tone: 'info',
      scope: SCOPE_VERDICTS,
    });
  }
  return lines;
}
