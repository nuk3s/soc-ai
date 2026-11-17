// The mark of a hunt that completed in a degraded state.
//
// Prod, 2026-11-03, hunt 01M6HB9Y7JDA71ZEYME4N2MSF2: the model returned no
// reasoning trace on 36 responses, the hunt wrote 3 false threat findings, and
// no surface said that the run was weaker than the runs before it. The server
// sets `degraded` to a reason code and `degradedNote` to the sentence. The
// Hunts list and the hunt page show this one chip, so the word is the same on
// both.
import { AlertTriangle } from 'lucide-react';

/** The sentence for a server that sends a reason and no note. */
export const DEGRADED_FALLBACK_NOTE =
  'This hunt ran in a degraded state. Check each finding against its evidence.';

export function HuntDegradedChip({ note, testId }: { note?: string | null; testId?: string }) {
  return (
    <span
      data-testid={testId ?? 'hunt-degraded'}
      className="inline-flex flex-none items-center gap-1 whitespace-nowrap rounded-chip border px-1.5 py-px text-[9.5px] font-semibold tracking-[.02em]"
      style={{ color: '#f5a623', borderColor: 'rgba(245,166,35,.4)', background: 'rgba(245,166,35,.09)' }}
      title={note || DEGRADED_FALLBACK_NOTE}
    >
      <AlertTriangle size={9} strokeWidth={2.5} />
      Degraded
    </span>
  );
}
