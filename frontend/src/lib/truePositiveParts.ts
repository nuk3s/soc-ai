// ---------------------------------------------------------------------------
// The parts of a set of true positives (round "decide once", DC3 and DC5).
//
// The Dashboard at 7 days read "12 true positives on 0 hosts", and its link
// opened 14 rows. Each of the 12 was in a campaign that the analyst had
// closed, and 2 of the 14 were superseded. The server splits the true
// positives by one rule (`truePositiveParts` of the Investigations list), and
// the true positives view and the host page state the parts.
// ---------------------------------------------------------------------------

import { plural } from './plural';
import { utcStamp } from './timeRange';
import type { TruePositiveParts } from './types';

export type PartKey = 'waiting' | 'decided' | 'authorized' | 'handled' | 'superseded' | 'other' | 'earlier';

const DECISION_NOUN: Record<string, string> = { closed: 'close', authorized: 'authorization', case: 'case' };

/** The true positives that the earlier decision of a reopened campaign
 *  covered, in two sentences (round 3 part 2, W2): "28 are in a campaign
 *  that opened again. The close of 2026-11-15 covered them." The Dashboard
 *  tile, the Confirmed threats panel, the true positives view and the host
 *  page read this one function. */
export function earlierPartWords(
  e: {
    investigations: number;
    campaigns: number;
    decision?: string | null;
    decidedAt?: string | null;
  },
  /** The subject of the first sentence. The count alone by default. */
  subject: string = e.investigations.toLocaleString(),
): string {
  const n = e.investigations;
  const where =
    e.campaigns > 1
      ? `in ${e.campaigns.toLocaleString()} campaigns that opened again`
      : 'in a campaign that opened again';
  const them = n === 1 ? 'it' : 'them';
  const noun = e.decision ? DECISION_NOUN[e.decision] : undefined;
  const on = e.decidedAt ? ` of ${utcStamp(e.decidedAt).split(' ')[0]}` : '';
  const who =
    e.campaigns > 1 ? 'The earlier decision of each campaign' : noun ? `The ${noun}${on}` : 'The earlier decision';
  return `${subject} ${n === 1 ? 'is' : 'are'} ${where}. ${who} covered ${them}.`;
}

export interface PartPhrase {
  key: PartKey;
  n: number;
  /** "12 are in a decided campaign." */
  text: string;
}

const be = (n: number) => (n === 1 ? 'is' : 'are');

/** One sentence for each part: the part that waits always, each other part
 *  with a count above 0. */
export function partPhrases(p: TruePositiveParts): PartPhrase[] {
  const n = (v: number) => v.toLocaleString();
  const out: PartPhrase[] = [
    { key: 'waiting', n: p.waiting, text: `${n(p.waiting)} ${p.waiting === 1 ? 'waits' : 'wait'}.` },
  ];
  if (p.decided > 0) {
    out.push({ key: 'decided', n: p.decided, text: `${n(p.decided)} ${be(p.decided)} in a decided campaign.` });
  }
  // The earlier decision of a reopened campaign covered them (W2).
  const earlier = p.earlier ?? 0;
  if (earlier > 0) {
    const cs = p.earlierCampaigns ?? [];
    const [only] = cs;
    out.push({
      key: 'earlier',
      n: earlier,
      text: earlierPartWords({
        investigations: earlier,
        campaigns: Math.max(1, cs.length),
        decision: cs.length === 1 && only ? only.decision : null,
        decidedAt: cs.length === 1 && only ? only.decidedAt : null,
      }),
    });
  }
  if (p.authorized > 0) {
    out.push({ key: 'authorized', n: p.authorized, text: `${n(p.authorized)} ${be(p.authorized)} authorized activity.` });
  }
  // The analyst decided on the investigation itself (round "decide once"
  // part 2, OW2): nothing of it waits.
  const handled = p.handled ?? 0;
  if (handled > 0) {
    out.push({ key: 'handled', n: handled, text: `${n(handled)} ${be(handled)} handled by the analyst.` });
  }
  if (p.superseded > 0) {
    out.push({ key: 'superseded', n: p.superseded, text: `${n(p.superseded)} ${be(p.superseded)} superseded.` });
  }
  if (p.other > 0) {
    out.push({ key: 'other', n: p.other, text: `${n(p.other)} ${be(p.other)} not complete or synthetic.` });
  }
  return out;
}

/** "14 true positives. 0 wait. 12 are in a decided campaign. 2 are superseded." */
export function partsSentence(p: TruePositiveParts): string {
  return [`${plural(p.total, 'true positive')}.`, ...partPhrases(p).map((x) => x.text)].join(' ');
}

/** The tone class of a part: the part that waits wears the danger color when
 *  it holds a count, and each other part reads neutral. */
export function partTone(part: PartPhrase): string {
  return part.key === 'waiting' && part.n > 0 ? 'font-semibold text-danger' : 'text-text-2';
}
