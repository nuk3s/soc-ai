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
    case 'address': {
      if (!data.host_key) return `${v} is an internal address. No machine holds it.`;
      const name = (data.host_name ?? '').trim();
      return name ? `${v} is an internal address of the machine ${name}.` : `${v} is an internal address of a machine.`;
    }
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

/** The keys of the machine the counts read, for the line under the counts.
 *  Empty when no machine holds the value: the counts then read the value
 *  alone. The machine key is an internal id and stays off the line. */
export function machineKeysShown(data: EntityDetail): string[] {
  if (!data.host_key) return [];
  const keys = (data.machine_keys ?? []).filter((k) => k && k !== data.host_key);
  return keys.length > 1 ? keys : [];
}

/** "The counts cover every key of the machine: a, b and c." */
export function machineKeysLine(keys: readonly string[]): string {
  const list = keys.length > 1 ? `${keys.slice(0, -1).join(', ')} and ${keys[keys.length - 1]}` : keys.join('');
  return `The counts cover every key of the machine: ${list}.`;
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
