import { huntOutcomeChip } from '../lib/notifications';
import { tint } from '../lib/tokens';

/**
 * How a hunt ended, on a bell row and a Notifications row.
 *
 * The chip reads the row's `outcome` field and never its title. The bell said
 * "Hunt finished: no threat observed" for analytic runs that could not reach
 * their data source, and a reader cannot tell those two apart from the words.
 */
export function HuntOutcomeChip({ outcome }: { outcome: string | null | undefined }) {
  const chip = huntOutcomeChip(outcome);
  if (!chip) return null;
  return (
    <span
      data-testid="hunt-outcome"
      className="inline-flex flex-none items-center whitespace-nowrap rounded-chip border px-1.5 py-px text-[10px] font-semibold"
      style={{ color: chip.color, borderColor: tint(chip.color, 0.4), background: tint(chip.color, 0.1) }}
    >
      {chip.label}
    </span>
  );
}
