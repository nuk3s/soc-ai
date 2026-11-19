import { ListChecks } from 'lucide-react';
import type { NeedsYouItem } from '../../lib/api';
import { ruleCountWords, ruleSpanWords } from '../../lib/needsYouItems';

/** The icon of a rule item. */
export const RULE_ICON = ListChecks;

/** The two groups of the open false positives of a rule, in the colors of
 *  the rule page: the confident ones calm, the weak ones in the warning tone. */
export const CONFIDENT_COLOR = 'rgb(var(--text-2))';
export const WEAK_COLOR = 'rgb(var(--warn))';

/** The width of the split bar of a row, in pixels. */
const SPLIT_W = 120;

/**
 * The facts of a rule item of Needs you: one bar that splits the open false
 * positives into the two groups, the count in words and the span of the
 * events. The verdict, the severity, the machines, why it waits and the
 * action are the facts of every row.
 */
export function RuleRowFacts({ item }: { item: NeedsYouItem }) {
  const count = item.count ?? 0;
  const confident = item.confident ?? 0;
  const weak = item.weak ?? 0;
  const words = ruleCountWords(item);
  const span = ruleSpanWords(item.since, item.eventAt);
  const whole = Math.max(1, confident + weak);
  const confidentW = Math.round((confident / whole) * SPLIT_W);
  return (
    <span data-testid="needs-you-rule-facts" className="flex flex-col gap-1">
      <span className="flex flex-wrap items-center gap-2">
        {count > 0 && (
          <svg
            data-testid="needs-you-rule-split"
            width={SPLIT_W}
            height={8}
            role="img"
            aria-label={words}
            className="flex-none"
          >
            <rect x={0} y={0} width={confidentW} height={8} rx={2} fill={CONFIDENT_COLOR} opacity={0.75} />
            {weak > 0 && (
              <rect x={confidentW} y={0} width={SPLIT_W - confidentW} height={8} rx={2} fill={WEAK_COLOR} />
            )}
          </svg>
        )}
        <span data-testid="needs-you-rule-count" className="break-words text-[12.5px] text-text">
          {words}
        </span>
      </span>
      {span && (
        <span data-testid="needs-you-rule-span" className="break-words text-[12px] text-dim">
          {span}
        </span>
      )}
    </span>
  );
}
