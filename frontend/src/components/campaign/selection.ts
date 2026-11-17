import type { CampaignMember, CampaignPairEvents } from '../../lib/api';

/** What the analyst picked on a chart. A machine or an arrow filters the
 *  Alerts table and the Investigations table. A mark of the timeline filters
 *  the Investigations table to the investigations inside its span. */
export type CampaignSelection =
  | { kind: 'machine'; key: string; label: string }
  | { kind: 'edge'; source: string; target: string; label: string }
  | {
      kind: 'runs';
      runIds: string[];
      label: string;
      /** The lane and the time span of the mark, so the timeline can mark it after a zoom. */
      span?: { lane: string; from: number; to: number };
    };

/** True when the two machines of a selection are the two ends. An arrow holds
 *  both directions: an alert on the answer of a server has the server as its
 *  source. */
function holdsEnds(selection: CampaignSelection, source: string | null, target: string | null): boolean {
  if (selection.kind === 'machine') return source === selection.key || target === selection.key;
  if (selection.kind === 'edge') {
    return (
      (source === selection.source && target === selection.target) ||
      (source === selection.target && target === selection.source)
    );
  }
  return true;
}

/** True when the investigation is part of the selection. */
export function selectionHolds(selection: CampaignSelection | null, m: CampaignMember): boolean {
  if (!selection) return true;
  if (selection.kind === 'runs') return selection.runIds.includes(m.runId);
  return holdsEnds(selection, m.sourceKey, m.targetKey);
}

/** True when the events of the pair are part of the selection. A mark of the
 *  timeline selects no pair, so it holds every pair. */
export function selectionHoldsPair(
  selection: CampaignSelection | null,
  pair: Pick<CampaignPairEvents, 'source' | 'target'>,
): boolean {
  if (!selection) return true;
  return holdsEnds(selection, pair.source, pair.target);
}

export function sameSelection(a: CampaignSelection | null, b: CampaignSelection | null): boolean {
  if (!a || !b) return a === b;
  if (a.kind !== b.kind) return false;
  if (a.kind === 'machine' && b.kind === 'machine') return a.key === b.key;
  if (a.kind === 'edge' && b.kind === 'edge') return a.source === b.source && a.target === b.target;
  if (a.kind === 'runs' && b.kind === 'runs') {
    // Two marks with no investigation select the same empty list. The label
    // names the machine and the span, so it tells them apart.
    return a.label === b.label && a.runIds.join('|') === b.runIds.join('|');
  }
  return false;
}
