import { machineRoleView } from './hostDossier';
import { VERDICT } from './tokens';
import type { AlertGroup, InvestigationRow, MachineRow } from './types';

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

/** One entity result for the ⌘K palette: an investigation or an alert group
 * matched by rule-name fragment or IP. */
export interface EntityHit {
  group: 'Investigations' | 'Alerts';
  label: string;
  to: string;
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
      to: '/alerts',
    });
  }
  return hits;
}
