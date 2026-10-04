// The generalization pins of a drafted analytic, and the entity count of its
// dry run. An analytic drafted from one finding can name the host, the user
// or the domain of that one case, and then it fires on that case only. The
// server's check names each such clause. The confirm dialog and the drawer
// show the same list.

import type { AnalyticDryRun } from '../lib/api';

export function AnalyticPins({
  pins,
  label,
  testId,
}: {
  pins: string[] | null | undefined;
  label: string;
  testId?: string;
}) {
  if (!pins || pins.length === 0) return null;
  return (
    <div
      data-testid={testId}
      role="alert"
      className="mt-1.5 rounded-control border px-2.5 py-1.5 text-[11.5px] text-warn"
      style={{ borderColor: 'rgba(245,166,35,.35)', background: 'rgba(245,166,35,.06)' }}
    >
      <div className="font-semibold">{label}</div>
      <ul className="mt-0.5 list-disc pl-4">
        {pins.map((p) => (
          <li key={p}>{p}</li>
        ))}
      </ul>
    </div>
  );
}

const NOUNS: Record<string, [string, string]> = {
  host: ['host', 'hosts'],
  user: ['user', 'users'],
  ip: ['address', 'addresses'],
};

/** "1 host matched in 30 days." One entity on a clause that reads as a
 *  behaviour is the analyst's cue that the analytic still describes one case.
 *  Empty when the dry run did not run or the server sent no count. */
export function entityLine(dry: AnalyticDryRun): string {
  if (!dry.ran || dry.entity_count == null) return '';
  const [one, many] = NOUNS[dry.scope_kind ?? ''] ?? ['entity', 'entities'];
  const n = dry.entity_count;
  const prefix = dry.entity_count_is_lower_bound ? 'At least ' : '';
  return `${prefix}${n} ${n === 1 ? one : many} matched in ${dry.window_days} days.`;
}
