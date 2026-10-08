import { machineRoleView, nameSourceLabel } from './hostDossier';
import { VERDICT } from './tokens';
import type { AlertGroup, EntitySearchHit, InvestigationRow, MachineRow } from './types';

/**
 * One machine hit in the palette: "<name> · <primary address> · <role>".
 * A machine with no name leads with its address. An unknown role says
 * nothing, because "unknown" on every row is noise.
 */
export function machineHitLabel(row: MachineRow): string {
  const role = machineRoleView(row.role);
  const parts = [row.name?.trim() || null, row.primary_ip, role.state === 'unknown' ? null : role.text];
  return parts.filter((p): p is string => !!p).join(' · ');
}

/** The second line of a machine hit: the key soc-ai holds it under, and
 *  where its name came from. Two machines with the same name and address
 *  read apart on this line. */
export function machineHitDetail(row: MachineRow): string {
  const source = nameSourceLabel(row.name_source);
  return [`Machine ${row.key}`, source ? `name from ${source}` : null]
    .filter((p): p is string => !!p)
    .join(' · ');
}

/** One entity result for the ⌘K palette: an investigation or an alert group
 * matched by rule-name fragment or IP. `detail` is the second line. Two hits
 * with the same label read apart on it (dogfood 2026-10-06, 7.3). */
export interface EntityHit {
  group: 'Investigations' | 'Alerts';
  label: string;
  detail: string;
  to: string;
}

/** The endpoint pair of a flow, for a second line. */
function endpoints(src: string | null | undefined, dst: string | null | undefined): string | null {
  const a = (src ?? '').trim();
  const b = (dst ?? '').trim();
  if (a && b && a !== '\u2014' && b !== '\u2014') return `${a} → ${b}`;
  if (a && a !== '\u2014') return a;
  if (b && b !== '\u2014') return b;
  return null;
}

const CAP = 8;
const MIN_QUERY = 2;

/**
 * Case-insensitive substring search over investigations (name, src/dst IP, id)
 * and alert groups (name, src/dst IP). The palette's static commands cover
 * screens/actions; this covers "the thing I'm looking at" — typing a rule
 * fragment or an IP must find it (dogfood 2026-07-15: "teardrop" → No matches
 * while the rule was on screen). Investigations rank first: they carry a
 * permalink; a group hit lands on the Alerts queue.
 */
export function searchEntities(
  q: string,
  invs: InvestigationRow[],
  groups: AlertGroup[],
): EntityHit[] {
  const query = q.trim().toLowerCase();
  if (query.length < MIN_QUERY) return [];

  const hits: EntityHit[] = [];
  for (const r of invs) {
    if (hits.length >= CAP) break;
    const hay = `${r.name} ${r.host} ${r.dst ?? ''} ${r.id}`.toLowerCase();
    if (!hay.includes(query)) continue;
    const conf = r.conf != null ? ` ${r.conf.toFixed(2)}` : '';
    hits.push({
      group: 'Investigations',
      // The palette renders a plain-text label, so the synth-eval marker rides
      // it as the badge's exact wording — a planted run surfaced by ⌘K must
      // never read as real activity.
      // The verdict is the label the badge shows, never the raw enum.
      label: `${r.name} · ${VERDICT[r.verdict]?.label ?? r.verdict}${conf} · ${r.when}${r.isSynthEval ? ' · Synthetic evaluation data' : ''}`,
      detail: [endpoints(r.host, r.dst), `Investigation ${r.id}`].filter(Boolean).join(' · '),
      to: `/investigation/${r.id}`,
    });
  }
  for (const g of groups) {
    if (hits.length >= CAP) break;
    const hay = `${g.name} ${g.src ?? ''} ${g.dst ?? ''}`.toLowerCase();
    if (!hay.includes(query)) continue;
    hits.push({
      group: 'Alerts',
      label: `${g.name} · ×${g.count} · ${g.sev}`,
      detail: endpoints(g.src, g.dst) ?? 'Alert group',
      to: '/alerts',
    });
  }
  return hits;
}

/** The palette group each server hit sits in. */
export const SERVER_HIT_GROUP: Record<EntitySearchHit['type'], 'Users' | 'Domains' | 'Addresses' | 'Hunts'> = {
  user: 'Users',
  domain: 'Domains',
  address: 'Addresses',
  external_address: 'Addresses',
  hunt: 'Hunts',
};

/**
 * A result set that belongs to one query. The palette shows a set only while
 * the box still holds the query it answers. A set from the previous query
 * stayed pinned above "No matches" on the next keystroke (dogfood 2026-10-06,
 * 7.5).
 */
export interface QueryResult<T> {
  q: string;
  rows: T[];
}

/** The rows of a result set when it answers the query in the box, else none. */
export function rowsFor<T>(result: QueryResult<T>, q: string): T[] {
  return result.q === q.trim() ? result.rows : [];
}
