import type { AlertGroup, InvestigationRow } from './types';

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
      label: `${r.name} — ${r.verdict}${conf} · ${r.when}`,
      to: `/investigation/${r.id}`,
    });
  }
  for (const g of groups) {
    if (hits.length >= CAP) break;
    const hay = `${g.name} ${g.src ?? ''} ${g.dst ?? ''}`.toLowerCase();
    if (!hay.includes(query)) continue;
    hits.push({
      group: 'Alerts',
      label: `${g.name} — ×${g.count} · ${g.sev}`,
      to: '/alerts',
    });
  }
  return hits;
}
