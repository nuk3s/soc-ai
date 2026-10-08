import { plural } from './plural';
import type { EntityDetail, EntityType } from './types';

// ---------------------------------------------------------------------------
// The first lines of the entity page: who is this, and should I worry.
//
// The page held a timeline and two counts. A user named in a live lead, an
// external address in a confirmed true positive and a domain all opened on
// the same shape, and none of them said what the value was (dogfood
// 2026-10-06, S5).
// ---------------------------------------------------------------------------

/** The chip word for each type. */
export const ENTITY_TYPE_LABEL: Record<EntityType, string> = {
  address: 'address',
  external_address: 'external address',
  host: 'host',
  user: 'user',
  domain: 'domain',
  name: 'name',
};

/** The type the page states. An older server sends `kind` alone. */
export function entityType(data: Pick<EntityDetail, 'kind' | 'type'>): EntityType {
  if (data.type) return data.type;
  return data.kind === 'ip' ? 'address' : 'name';
}

/** One sentence: what the value is. */
export function identityLine(data: EntityDetail): string {
  const v = data.value;
  switch (entityType(data)) {
    case 'external_address':
      return `${v} is an external address. It is outside the internal ranges.`;
    case 'address':
      return `${v} is an internal address. No machine in the census holds it.`;
    case 'host':
      return `${v} is a host name.`;
    case 'user':
      return `${v} is a user account.`;
    case 'domain': {
      const n = data.domain_machines ?? 0;
      return n > 0
        ? `${v} is a domain. ${plural(n, 'address', 'addresses')} ${n === 1 ? 'is' : 'are'} joined to it.`
        : `${v} is a domain.`;
    }
    default:
      return `${v} is a name. soc-ai does not know what it names.`;
  }
}

/** True when nothing soc-ai holds names the value. */
export function nothingKnown(data: EntityDetail): boolean {
  const s = data.summary;
  return (
    s.investigationCount === 0 &&
    s.huntFindingCount === 0 &&
    (s.leadCount ?? 0) === 0 &&
    (s.observationCount ?? 0) === 0
  );
}

/** The sentences that answer "should I worry", strongest first. Empty when
 *  nothing is known: the page says that in its own line. */
export function worryLines(data: EntityDetail): string[] {
  if (nothingKnown(data)) return [];
  const s = data.summary;
  const lines: string[] = [];
  const tp = s.truePositiveCount ?? 0;
  const open = s.openLeadCount ?? 0;
  if (open > 0) {
    lines.push(`${plural(open, 'open lead')} ${open === 1 ? 'names' : 'name'} it. A lead waits on a hunt or a decision.`);
  }
  if (tp > 0) {
    lines.push(`${plural(tp, 'investigation')} reached a true-positive verdict.`);
  }
  if (lines.length === 0) {
    lines.push('No open lead names it. No investigation reached a true-positive verdict.');
  }
  return lines;
}

/** The line for a value soc-ai holds nothing on. */
export function nothingKnownLine(value: string): string {
  return `soc-ai knows nothing about ${value} yet. No investigation, hunt finding, lead or observation names it.`;
}
